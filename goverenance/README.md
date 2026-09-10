# Agent Governance Layer

Standalone gateway that sits in front of any agent-runtime. Solves the bottleneck
Google itself has named publicly: agents can now act faster than humans can
review, audit, or trust them. This gives you the three controls that gap requires:

1. **Permission scoping** — an agent can only take actions declared in its allowlist.
   Anything else is rejected and logged, not silently attempted.
2. **Tamper-evident audit log** — every decision (executed, denied, pending,
   rejected) is written to Postgres as a SHA-256 hash-chained record. Any edit
   to a past row breaks the chain and `verify` will catch it.
3. **Human approval gate** — actions above an agent's configured risk threshold
   pause and wait for a human to approve or reject before they execute.

No Kafka, no JVM, no vector DB. One Go binary, one Postgres instance.

## Run it

```bash
docker compose up -d
```

Gateway listens on `:8090`. Postgres on `:5433` (host-mapped to avoid clashing
with any other Postgres instance you're running).

## API

### Register an agent
```bash
curl -X POST localhost:8090/agents \
  -H 'content-type: application/json' \
  -d '{"id":"agent-1","name":"Research Agent","allowed_actions":["read_file","web_search"],"risk_threshold":0.7}'
```

### Submit an action
```bash
curl -X POST localhost:8090/agent/agent-1/action \
  -H 'content-type: application/json' \
  -d '{"action":"read_file","payload":{"path":"/data/report.pdf"},"risk_score":0.2}'
```
Returns `200` with `status: "executed"` if under threshold and permitted.
Returns `202` with `status: "pending_approval"` and an `approval_id` if over threshold.
Returns `403` with `status: "denied"` if the action isn't in the agent's allowlist.

### List pending approvals
```bash
curl localhost:8090/approvals/pending
```

### Approve / reject
```bash
curl -X POST localhost:8090/approvals/1/approve -d '{"resolver":"ju"}'
curl -X POST localhost:8090/approvals/1/reject  -d '{"resolver":"ju"}'
```

### Read an agent's full audit trail
```bash
curl localhost:8090/agent/agent-1/audit
```

### Verify the chain hasn't been tampered with
```bash
curl localhost:8090/agent/agent-1/audit/verify
# {"valid":true,"entries_checked":4}
```
If any row was edited or deleted out of band, this returns `409` with the
exact record where the chain breaks.

## Build without Docker

```bash
go mod tidy   # needs unrestricted network — pulls golang.org/x, gopkg.in transitively
go build -o gateway ./cmd/gateway
PG_URL=postgres://titan:titan@localhost:5432/agent_governance?sslmode=disable ./gateway
```

## Wiring into an existing agent-runtime

This gateway doesn't replace your agent's message bus or memory store — it sits
*in front of* the action, not in place of your existing Kafka/Chroma stack.
The pattern: before an agent executes a tool call, it calls
`POST /agent/{id}/action` first. If it gets `200`, proceed. If `202`, wait/poll
`GET /agent/{id}/audit` for the entry's status to flip to `executed`. If `403`,
don't proceed — the action was out of scope.
