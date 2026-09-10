// Agent Governance Layer gateway.
//
// Every agent action must pass through this service. It:
//  1. Rejects actions outside the agent's declared permission scope.
//  2. Writes every decision to a SHA-256 hash-chained audit log (tamper-evident).
//  3. Routes high-risk actions to a human approval queue instead of executing them.
//
// No JVM, no external message broker required for this layer — stdlib net/http
// (Go 1.22 method+pattern routing) and pgx against Postgres.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type server struct {
	db *pgxpool.Pool
}

// ---------- request/response types ----------

type registerAgentReq struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	AllowedActions []string `json:"allowed_actions"`
	RiskThreshold  float64  `json:"risk_threshold"`
}

type submitActionReq struct {
	Action    string          `json:"action"`
	Payload   json.RawMessage `json:"payload"`
	RiskScore float64         `json:"risk_score"`
}

type submitActionResp struct {
	Status     string `json:"status"`
	AuditLogID int64  `json:"audit_log_id"`
	ApprovalID *int64 `json:"approval_id,omitempty"`
	Hash       string `json:"hash"`
}

type auditEntry struct {
	ID        int64           `json:"id"`
	AgentID   string          `json:"agent_id"`
	Action    string          `json:"action"`
	Payload   json.RawMessage `json:"payload"`
	RiskScore float64         `json:"risk_score"`
	Status    string          `json:"status"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
	CreatedAt time.Time       `json:"created_at"`
}

type approvalRow struct {
	ID          int64           `json:"id"`
	AuditLogID  int64           `json:"audit_log_id"`
	Status      string          `json:"status"`
	Resolver    *string         `json:"resolver,omitempty"`
	RequestedAt time.Time       `json:"requested_at"`
	ResolvedAt  *time.Time      `json:"resolved_at,omitempty"`
	Action      string          `json:"action"`
	AgentID     string          `json:"agent_id"`
	Payload     json.RawMessage `json:"payload"`
	RiskScore   float64         `json:"risk_score"`
}

// ---------- hashing ----------

// canonicalize produces a deterministic byte representation of arbitrary JSON
// by re-marshaling through a sorted-key map. Needed so the same payload always
// hashes the same way regardless of client-side key ordering.
func canonicalize(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("{}"), nil
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return canonicalMarshal(v)
}

func canonicalMarshal(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := []byte("{")
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kb, _ := json.Marshal(k)
			buf = append(buf, kb...)
			buf = append(buf, ':')
			vb, err := canonicalMarshal(t[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, vb...)
		}
		buf = append(buf, '}')
		return buf, nil
	case []interface{}:
		buf := []byte("[")
		for i, e := range t {
			if i > 0 {
				buf = append(buf, ',')
			}
			eb, err := canonicalMarshal(e)
			if err != nil {
				return nil, err
			}
			buf = append(buf, eb...)
		}
		buf = append(buf, ']')
		return buf, nil
	default:
		return json.Marshal(t)
	}
}

func computeHash(prevHash, agentID, action string, payload json.RawMessage, riskScore float64, ts time.Time) (string, error) {
	canon, err := canonicalize(payload)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte("|"))
	h.Write([]byte(agentID))
	h.Write([]byte("|"))
	h.Write([]byte(action))
	h.Write([]byte("|"))
	h.Write(canon)
	h.Write([]byte("|"))
	h.Write([]byte(fmt.Sprintf("%f", riskScore)))
	h.Write([]byte("|"))
	h.Write([]byte(strconv.FormatInt(ts.UnixNano(), 10)))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func genesisHash(agentID string) string {
	h := sha256.Sum256([]byte("genesis:" + agentID))
	return hex.EncodeToString(h[:])
}

// ---------- handlers ----------

func (s *server) registerAgent(w http.ResponseWriter, r *http.Request) {
	var req registerAgentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.ID == "" || req.Name == "" {
		httpError(w, http.StatusBadRequest, "id and name are required")
		return
	}
	if req.RiskThreshold == 0 {
		req.RiskThreshold = 0.7
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	tx, err := s.db.Begin(ctx)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO agents (id, name, allowed_actions, risk_threshold)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE
		SET name = $2, allowed_actions = $3, risk_threshold = $4`,
		req.ID, req.Name, req.AllowedActions, req.RiskThreshold,
	)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "failed to register agent: "+err.Error())
		return
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO chain_genesis (agent_id, genesis)
		VALUES ($1, $2)
		ON CONFLICT (agent_id) DO NOTHING`,
		req.ID, genesisHash(req.ID),
	)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "failed to init chain: "+err.Error())
		return
	}

	if err := tx.Commit(ctx); err != nil {
		httpError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered", "id": req.ID})
}

func (s *server) submitAction(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		httpError(w, http.StatusBadRequest, "agent id required in path")
		return
	}

	var req submitActionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Action == "" {
		httpError(w, http.StatusBadRequest, "action is required")
		return
	}
	if req.Payload == nil {
		req.Payload = json.RawMessage("{}")
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// 1. Load agent + permission scope
	var allowed []string
	var riskThreshold float64
	err := s.db.QueryRow(ctx, `SELECT allowed_actions, risk_threshold FROM agents WHERE id = $1`, agentID).
		Scan(&allowed, &riskThreshold)
	if err != nil {
		httpError(w, http.StatusNotFound, "agent not registered")
		return
	}

	permitted := false
	for _, a := range allowed {
		if a == req.Action || a == "*" {
			permitted = true
			break
		}
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback(ctx)

	prevHash, err := lastHash(ctx, tx, agentID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "chain read failed: "+err.Error())
		return
	}

	// Truncate to microsecond precision to match what Postgres TIMESTAMPTZ
	// actually stores — otherwise the hash computed pre-insert (nanosecond
	// precision) won't match the hash recomputed from the read-back row
	// during chain verification.
	now := time.Now().UTC().Truncate(time.Microsecond)

	if !permitted {
		hash, herr := computeHash(prevHash, agentID, req.Action, req.Payload, req.RiskScore, now)
		if herr != nil {
			httpError(w, http.StatusInternalServerError, "hash error")
			return
		}
		var auditID int64
		err = tx.QueryRow(ctx, `
			INSERT INTO audit_log (agent_id, action, payload, risk_score, status, prev_hash, hash, created_at)
			VALUES ($1,$2,$3,$4,'denied',$5,$6,$7) RETURNING id`,
			agentID, req.Action, req.Payload, req.RiskScore, prevHash, hash, now,
		).Scan(&auditID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "audit write failed: "+err.Error())
			return
		}
		if err := tx.Commit(ctx); err != nil {
			httpError(w, http.StatusInternalServerError, "commit failed")
			return
		}
		writeJSON(w, http.StatusForbidden, submitActionResp{Status: "denied", AuditLogID: auditID, Hash: hash})
		return
	}

	status := "executed"
	if req.RiskScore >= riskThreshold {
		status = "pending_approval"
	}

	hash, herr := computeHash(prevHash, agentID, req.Action, req.Payload, req.RiskScore, now)
	if herr != nil {
		httpError(w, http.StatusInternalServerError, "hash error")
		return
	}

	var auditID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO audit_log (agent_id, action, payload, risk_score, status, prev_hash, hash, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		agentID, req.Action, req.Payload, req.RiskScore, status, prevHash, hash, now,
	).Scan(&auditID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "audit write failed: "+err.Error())
		return
	}

	resp := submitActionResp{Status: status, AuditLogID: auditID, Hash: hash}

	if status == "pending_approval" {
		var approvalID int64
		err = tx.QueryRow(ctx, `
			INSERT INTO approvals (audit_log_id, status) VALUES ($1, 'pending') RETURNING id`,
			auditID,
		).Scan(&approvalID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "approval write failed: "+err.Error())
			return
		}
		resp.ApprovalID = &approvalID
	}

	if err := tx.Commit(ctx); err != nil {
		httpError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	code := http.StatusOK
	if status == "pending_approval" {
		code = http.StatusAccepted
	}
	writeJSON(w, code, resp)
}

// lastHash returns the hash of the most recent audit_log entry for this agent,
// or the agent's genesis hash if no entries exist yet. This is what the next
// entry's prev_hash must equal to keep the chain unbroken.
func lastHash(ctx context.Context, tx pgx.Tx, agentID string) (string, error) {
	var hash string
	err := tx.QueryRow(ctx, `SELECT hash FROM audit_log WHERE agent_id=$1 ORDER BY id DESC LIMIT 1`, agentID).Scan(&hash)
	if err == nil {
		return hash, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	var genesis string
	if err := tx.QueryRow(ctx, `SELECT genesis FROM chain_genesis WHERE agent_id=$1`, agentID).Scan(&genesis); err != nil {
		return "", fmt.Errorf("no genesis found for agent %s: %w", agentID, err)
	}
	return genesis, nil
}

func (s *server) listPendingApprovals(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT a.id, a.audit_log_id, a.status, a.resolver, a.requested_at, a.resolved_at,
		       l.action, l.agent_id, l.payload, l.risk_score
		FROM approvals a
		JOIN audit_log l ON l.id = a.audit_log_id
		WHERE a.status = 'pending'
		ORDER BY a.requested_at ASC`)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "query failed: "+err.Error())
		return
	}
	defer rows.Close()

	var out []approvalRow
	for rows.Next() {
		var ar approvalRow
		if err := rows.Scan(&ar.ID, &ar.AuditLogID, &ar.Status, &ar.Resolver, &ar.RequestedAt, &ar.ResolvedAt,
			&ar.Action, &ar.AgentID, &ar.Payload, &ar.RiskScore); err != nil {
			httpError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
			return
		}
		out = append(out, ar)
	}
	if out == nil {
		out = []approvalRow{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) resolveApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "invalid approval id")
		return
	}

	var resolver struct {
		Resolver string `json:"resolver"`
	}
	_ = json.NewDecoder(r.Body).Decode(&resolver) // optional field, empty ok
	if resolver.Resolver == "" {
		resolver.Resolver = "unspecified"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	newApprovalStatus := "rejected"
	newAuditStatus := "rejected"
	if approve {
		newApprovalStatus = "approved"
		newAuditStatus = "executed"
	}

	now := time.Now().UTC()

	tx, err := s.db.Begin(ctx)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback(ctx)

	var auditLogID int64
	err = tx.QueryRow(ctx, `
		UPDATE approvals SET status=$1, resolver=$2, resolved_at=$3
		WHERE id=$4 AND status='pending' RETURNING audit_log_id`,
		newApprovalStatus, resolver.Resolver, now, id,
	).Scan(&auditLogID)
	if err != nil {
		httpError(w, http.StatusNotFound, "approval not found or already resolved")
		return
	}

	_, err = tx.Exec(ctx, `UPDATE audit_log SET status=$1 WHERE id=$2`, newAuditStatus, auditLogID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "audit update failed: "+err.Error())
		return
	}

	if err := tx.Commit(ctx); err != nil {
		httpError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"approval_id":  id,
		"audit_log_id": auditLogID,
		"status":       newApprovalStatus,
	})
}

func (s *server) getAuditTrail(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT id, agent_id, action, payload, risk_score, status, prev_hash, hash, created_at
		FROM audit_log WHERE agent_id = $1 ORDER BY id ASC`, agentID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "query failed: "+err.Error())
		return
	}
	defer rows.Close()

	var out []auditEntry
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.ID, &e.AgentID, &e.Action, &e.Payload, &e.RiskScore, &e.Status, &e.PrevHash, &e.Hash, &e.CreatedAt); err != nil {
			httpError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
			return
		}
		out = append(out, e)
	}
	if out == nil {
		out = []auditEntry{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) verifyChain(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var expected string
	err := s.db.QueryRow(ctx, `SELECT genesis FROM chain_genesis WHERE agent_id=$1`, agentID).Scan(&expected)
	if err != nil {
		httpError(w, http.StatusNotFound, "unknown agent or no genesis")
		return
	}

	rows, err := s.db.Query(ctx, `
		SELECT id, action, payload, risk_score, prev_hash, hash, created_at
		FROM audit_log WHERE agent_id = $1 ORDER BY id ASC`, agentID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "query failed: "+err.Error())
		return
	}
	defer rows.Close()

	checked := 0
	for rows.Next() {
		var id int64
		var action, prevHash, hash string
		var payload json.RawMessage
		var riskScore float64
		var createdAt time.Time
		if err := rows.Scan(&id, &action, &payload, &riskScore, &prevHash, &hash, &createdAt); err != nil {
			httpError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
			return
		}
		if prevHash != expected {
			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"valid": false, "broken_at_id": id, "reason": "prev_hash mismatch",
			})
			return
		}
		recomputed, err := computeHash(prevHash, agentID, action, payload, riskScore, createdAt)
		if err != nil || recomputed != hash {
			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"valid": false, "broken_at_id": id, "reason": "hash mismatch — record tampered",
			})
			return
		}
		expected = hash
		checked++
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"valid": true, "entries_checked": checked})
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// ---------- main ----------

func main() {
	dsn := os.Getenv("PG_URL")
	if dsn == "" {
		dsn = "postgres://titan:titan@localhost:5432/agent_governance?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("failed to connect to postgres: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("postgres ping failed: %v", err)
	}

	s := &server{db: pool}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /agents", s.registerAgent)
	mux.HandleFunc("POST /agent/{id}/action", s.submitAction)
	mux.HandleFunc("GET /agent/{id}/audit", s.getAuditTrail)
	mux.HandleFunc("GET /agent/{id}/audit/verify", s.verifyChain)
	mux.HandleFunc("GET /approvals/pending", s.listPendingApprovals)
	mux.HandleFunc("POST /approvals/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		s.resolveApproval(w, r, true)
	})
	mux.HandleFunc("POST /approvals/{id}/reject", func(w http.ResponseWriter, r *http.Request) {
		s.resolveApproval(w, r, false)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8090"
	}

	log.Printf("agent-governance gateway listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
