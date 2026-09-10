// agent-runtime is a real worker that executes tools (read_file, write_file,
// delete_file) but never runs one without first clearing it through the
// Agent Governance Layer gateway. This is the wiring pattern: governance
// check happens before execution, not alongside it or after it.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------- governance client ----------

type governanceClient struct {
	baseURL string
	agentID string
	http    *http.Client
}

func newGovernanceClient(baseURL, agentID string) *governanceClient {
	return &governanceClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		agentID: agentID,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

// registerSelf declares this agent's identity and permission scope to the
// gateway. Must run once at startup before any action is submitted.
func (g *governanceClient) registerSelf(name string, allowedActions []string, riskThreshold float64) error {
	body, _ := json.Marshal(map[string]interface{}{
		"id":              g.agentID,
		"name":            name,
		"allowed_actions": allowedActions,
		"risk_threshold":  riskThreshold,
	})
	resp, err := g.http.Post(g.baseURL+"/agents", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("governance unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io_ReadAll(resp)
		return fmt.Errorf("registration failed (%d): %s", resp.StatusCode, string(b))
	}
	return nil
}

type actionSubmission struct {
	Status     string `json:"status"`
	AuditLogID int64  `json:"audit_log_id"`
	ApprovalID *int64 `json:"approval_id,omitempty"`
	Hash       string `json:"hash"`
}

// submitAction is the gate. Every tool call goes through here first.
// Returns the final resolved status: "executed", "denied", or "rejected".
// For "pending_approval" it blocks and polls until a human resolves it.
func (g *governanceClient) submitAction(action string, payload interface{}, riskScore float64) (actionSubmission, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return actionSubmission{}, err
	}
	reqBody, _ := json.Marshal(map[string]interface{}{
		"action":     action,
		"payload":    json.RawMessage(payloadBytes),
		"risk_score": riskScore,
	})

	resp, err := g.http.Post(
		fmt.Sprintf("%s/agent/%s/action", g.baseURL, g.agentID),
		"application/json", bytes.NewReader(reqBody),
	)
	if err != nil {
		return actionSubmission{}, fmt.Errorf("governance unreachable: %w", err)
	}
	defer resp.Body.Close()

	var sub actionSubmission
	if err := json.NewDecoder(resp.Body).Decode(&sub); err != nil {
		return actionSubmission{}, fmt.Errorf("bad governance response: %w", err)
	}

	if sub.Status != "pending_approval" {
		return sub, nil // executed or denied — final, no waiting
	}

	log.Printf("[governance] action %q (audit_log %d) awaiting human approval — polling...", action, sub.AuditLogID)
	return g.pollUntilResolved(sub)
}

// pollUntilResolved blocks until a pending_approval action is approved or
// rejected by a human, checked against the audit trail (source of truth,
// not the approvals queue, since that's what actually gates execution).
func (g *governanceClient) pollUntilResolved(sub actionSubmission) (actionSubmission, error) {
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)

		resp, err := g.http.Get(fmt.Sprintf("%s/agent/%s/audit", g.baseURL, g.agentID))
		if err != nil {
			continue
		}
		var entries []struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, e := range entries {
			if e.ID == sub.AuditLogID {
				if e.Status == "executed" || e.Status == "rejected" {
					sub.Status = e.Status
					return sub, nil
				}
				break // still pending, keep polling
			}
		}
	}
	return sub, errors.New("approval wait timed out after 5 minutes")
}

func io_ReadAll(resp *http.Response) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

// ---------- tools (the actual work an agent does) ----------

// sandboxRoot scopes all file tools so the agent can't touch anything
// outside its working directory regardless of what governance clears.
var sandboxRoot string

func resolveSafe(rel string) (string, error) {
	clean := filepath.Clean(rel)
	full := filepath.Join(sandboxRoot, clean)
	if !strings.HasPrefix(full, sandboxRoot) {
		return "", fmt.Errorf("path %q escapes sandbox", rel)
	}
	return full, nil
}

func toolReadFile(payload map[string]interface{}) (interface{}, error) {
	path, _ := payload["path"].(string)
	if path == "" {
		return nil, errors.New("path required")
	}
	full, err := resolveSafe(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	return map[string]string{"content": string(data)}, nil
}

func toolWriteFile(payload map[string]interface{}) (interface{}, error) {
	path, _ := payload["path"].(string)
	content, _ := payload["content"].(string)
	if path == "" {
		return nil, errors.New("path required")
	}
	full, err := resolveSafe(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		return nil, err
	}
	return map[string]string{"wrote": full}, nil
}

func toolDeleteFile(payload map[string]interface{}) (interface{}, error) {
	path, _ := payload["path"].(string)
	if path == "" {
		return nil, errors.New("path required")
	}
	full, err := resolveSafe(path)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(full); err != nil {
		return nil, err
	}
	return map[string]string{"deleted": full}, nil
}

type toolFunc func(payload map[string]interface{}) (interface{}, error)

var tools = map[string]toolFunc{
	"read_file":   toolReadFile,
	"write_file":  toolWriteFile,
	"delete_file": toolDeleteFile,
}

// ---------- runtime ----------

type runtime struct {
	gov *governanceClient
}

// execute is the single entry point for running any tool. Nothing in this
// binary calls a tool function directly — everything routes through here.
func (rt *runtime) execute(action string, payload map[string]interface{}, riskScore float64) (interface{}, error) {
	sub, err := rt.gov.submitAction(action, payload, riskScore)
	if err != nil {
		return nil, fmt.Errorf("governance check failed: %w", err)
	}

	switch sub.Status {
	case "denied":
		return nil, fmt.Errorf("governance denied action %q (audit_log %d) — outside permission scope", action, sub.AuditLogID)
	case "rejected":
		return nil, fmt.Errorf("governance rejected action %q (audit_log %d) — human declined approval", action, sub.AuditLogID)
	case "executed":
		fn, ok := tools[action]
		if !ok {
			return nil, fmt.Errorf("governance approved %q but no local tool implements it", action)
		}
		log.Printf("[runtime] governance cleared %q (audit_log %d, hash %s) — executing locally", action, sub.AuditLogID, sub.Hash[:12])
		return fn(payload)
	default:
		return nil, fmt.Errorf("unexpected governance status %q", sub.Status)
	}
}

// ---------- HTTP surface for triggering the demo ----------

type runRequest struct {
	Action    string                 `json:"action"`
	Payload   map[string]interface{} `json:"payload"`
	RiskScore float64                `json:"risk_score"`
}

func (rt *runtime) handleRun(w http.ResponseWriter, r *http.Request) {
	var req runRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid json"})
		return
	}

	result, err := rt.execute(req.Action, req.Payload, req.RiskScore)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"result": result})
}

func main() {
	agentID := envOr("AGENT_ID", "agent-runtime-1")
	governanceURL := envOr("GOVERNANCE_URL", "http://localhost:8090")
	sandboxRoot = envOr("SANDBOX_ROOT", "/tmp/agent-sandbox")
	listenAddr := envOr("LISTEN_ADDR", ":8091")
	riskThreshold := 0.7
	if v := os.Getenv("RISK_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			riskThreshold = f
		}
	}

	if err := os.MkdirAll(sandboxRoot, 0o755); err != nil {
		log.Fatalf("failed to create sandbox root: %v", err)
	}
	var err error
	sandboxRoot, err = filepath.Abs(sandboxRoot)
	if err != nil {
		log.Fatalf("failed to resolve sandbox root: %v", err)
	}

	gov := newGovernanceClient(governanceURL, agentID)

	allowedActions := []string{"read_file", "write_file"} // delete_file deliberately excluded
	if err := gov.registerSelf("Agent Runtime 1", allowedActions, riskThreshold); err != nil {
		log.Fatalf("failed to register with governance: %v", err)
	}
	log.Printf("registered agent %q with governance at %s (allowed: %v, threshold: %.2f)",
		agentID, governanceURL, allowedActions, riskThreshold)
	log.Printf("sandbox root: %s", sandboxRoot)

	rt := &runtime{gov: gov}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", rt.handleRun)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "agent_id": agentID})
	})

	log.Printf("agent-runtime %q listening on %s", agentID, listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
