-- Agent Governance Layer schema
-- Sits in front of any agent-runtime. Enforces declared permission scopes,
-- writes a tamper-evident hash-chained audit log, and gates risky actions
-- behind human approval before execution.

CREATE TABLE IF NOT EXISTS agents (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    allowed_actions TEXT[] NOT NULL DEFAULT '{}',
    risk_threshold  DOUBLE PRECISION NOT NULL DEFAULT 0.7,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES agents(id),
    action      TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_score  DOUBLE PRECISION NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'executed', -- executed | pending_approval | rejected | denied
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_agent ON audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_status ON audit_log(status);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS approvals (
    id           BIGSERIAL PRIMARY KEY,
    audit_log_id BIGINT NOT NULL REFERENCES audit_log(id),
    status       TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
    resolver     TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

-- Genesis row so every agent's first audit entry has a real prev_hash to chain from.
CREATE TABLE IF NOT EXISTS chain_genesis (
    agent_id  TEXT PRIMARY KEY,
    genesis   TEXT NOT NULL
);
