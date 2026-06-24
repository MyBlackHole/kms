pub const INIT_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS keys (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keys_name ON keys(name);
CREATE INDEX IF NOT EXISTS idx_keys_created_at ON keys(created_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL UNIQUE,
    timestamp   INTEGER NOT NULL,
    data        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_id ON audit_log(event_id);

CREATE TABLE IF NOT EXISTS key_material (
    id              TEXT PRIMARY KEY,
    key_id          TEXT NOT NULL,
    version_number  INTEGER NOT NULL,
    encrypted_key   BLOB NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'SM4-GCM',
    created_at      TEXT NOT NULL,
    FOREIGN KEY (key_id) REFERENCES keys(id)
);

CREATE INDEX IF NOT EXISTS idx_key_material_key_id ON key_material(key_id);

CREATE TABLE IF NOT EXISTS hsm_state (
    id          TEXT PRIMARY KEY,
    provider    TEXT NOT NULL,
    state_data  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- 等保三级：结构化审计事件表（追加写入，不支持 UPDATE/DELETE）
CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE,
    timestamp       INTEGER NOT NULL,
    event_type      TEXT NOT NULL,
    subject         TEXT NOT NULL,
    admin_role      TEXT,
    action          TEXT NOT NULL,
    resource        TEXT NOT NULL,
    source_ip       TEXT,
    request_id      TEXT,
    result          TEXT NOT NULL,
    detail          TEXT,
    previous_hash   TEXT,
    hash            TEXT NOT NULL,
    signature       TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_id ON audit_events(event_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_subject ON audit_events(subject);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);

CREATE INDEX IF NOT EXISTS idx_audit_events_result ON audit_events(result);
-- 恢复码表（用于双因子失效后的后备认证）
CREATE TABLE IF NOT EXISTS recovery_codes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(username, code_hash)
);


-- 用户 TOTP 密钥存储表
CREATE TABLE IF NOT EXISTS user_totp_secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE,
    secret      TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 安全标记表
CREATE TABLE IF NOT EXISTS security_labels (
    id          TEXT PRIMARY KEY,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    level       TEXT NOT NULL DEFAULT 'Public',
    categories  TEXT DEFAULT '[]',
    compartments TEXT DEFAULT '[]',
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(resource_type, resource_id)
);

-- 密钥依赖索引表
CREATE TABLE IF NOT EXISTS key_dependencies (
    id              TEXT PRIMARY KEY,
    key_id          TEXT NOT NULL,
    version_number  INTEGER NOT NULL DEFAULT 1,
    dependent_key_id TEXT NOT NULL,
    description     TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_key_deps_key_id ON key_dependencies(key_id);

-- 双人复核：审批请求表
CREATE TABLE IF NOT EXISTS key_dependencies (
    id              VARCHAR(64) PRIMARY KEY,
    key_id          VARCHAR(64) NOT NULL,
    version_number  INTEGER NOT NULL DEFAULT 1,
    dependent_key_id VARCHAR(64) NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_key_deps_key_id ON key_dependencies(key_id);

CREATE TABLE IF NOT EXISTS approval_requests (
    id          TEXT PRIMARY KEY,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    subject     TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'Pending',
    reviewed_by TEXT,
    created_at  TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    token_hint  TEXT NOT NULL,
    role        TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    last_used   INTEGER,
    disabled    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);

-- 等保四级：抗抵赖证据表
CREATE TABLE IF NOT EXISTS non_repudiation_evidence (
    id          TEXT PRIMARY KEY,
    operation   TEXT NOT NULL,
    key_id      TEXT NOT NULL DEFAULT '',
    subject     TEXT NOT NULL,
    signature   TEXT NOT NULL,
    timestamp   INTEGER NOT NULL,
    data_hash   TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_non_repudiation_op ON non_repudiation_evidence(operation);
CREATE INDEX IF NOT EXISTS idx_non_repudiation_key ON non_repudiation_evidence(key_id);
CREATE INDEX IF NOT EXISTS idx_non_repudiation_ts ON non_repudiation_evidence(timestamp);
"#;

pub async fn run_migrations(pool: &sqlx::SqlitePool) -> crate::Result<()> {
    sqlx::raw_sql(INIT_SQL).execute(pool).await?;
    Ok(())
}

pub fn get_postgres_migration() -> &'static str {
    r#"
CREATE TABLE IF NOT EXISTS keys (
    id          VARCHAR(64) PRIMARY KEY,
    name        VARCHAR(256) NOT NULL,
    data        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keys_name ON keys(name);
CREATE INDEX IF NOT EXISTS idx_keys_created_at ON keys(created_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    event_id    VARCHAR(64) NOT NULL UNIQUE,
    timestamp   BIGINT NOT NULL,
    data        JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

CREATE TABLE IF NOT EXISTS key_material (
    id              VARCHAR(64) PRIMARY KEY,
    key_id          VARCHAR(64) NOT NULL,
    version_number  INTEGER NOT NULL,
    encrypted_key   BYTEA NOT NULL,
    algorithm       VARCHAR(32) NOT NULL DEFAULT 'SM4-GCM',
    created_at      TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (key_id) REFERENCES keys(id)
);

CREATE TABLE IF NOT EXISTS hsm_state (
    id          VARCHAR(64) PRIMARY KEY,
    provider    VARCHAR(64) NOT NULL,
    state_data  JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id              SERIAL PRIMARY KEY,
    event_id        VARCHAR(64) NOT NULL UNIQUE,
    timestamp       BIGINT NOT NULL,
    event_type      VARCHAR(64) NOT NULL,
    subject         VARCHAR(256) NOT NULL,
    admin_role      VARCHAR(64),
    action          VARCHAR(256) NOT NULL,
    resource        VARCHAR(256) NOT NULL,
    source_ip       VARCHAR(64),
    request_id      VARCHAR(64),
    result          VARCHAR(32) NOT NULL,
    detail          TEXT,
    previous_hash   VARCHAR(128),
    hash            VARCHAR(128) NOT NULL,
    signature       VARCHAR(256),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_subject ON audit_events(subject);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(256) NOT NULL,
    code_hash   VARCHAR(128) NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(username, code_hash)
);

CREATE TABLE IF NOT EXISTS key_dependencies (
    id              VARCHAR(64) PRIMARY KEY,
    key_id          VARCHAR(64) NOT NULL,
    version_number  INTEGER NOT NULL DEFAULT 1,
    dependent_key_id VARCHAR(64) NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_key_deps_key_id ON key_dependencies(key_id);

CREATE TABLE IF NOT EXISTS approval_requests (
    id          VARCHAR(64) PRIMARY KEY,
    action      VARCHAR(256) NOT NULL,
    resource    VARCHAR(256) NOT NULL,
    subject     VARCHAR(256) NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    status      VARCHAR(32) NOT NULL DEFAULT 'Pending',
    reviewed_by VARCHAR(256),
    created_at  TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS non_repudiation_evidence (
    id          VARCHAR(64) PRIMARY KEY,
    operation   VARCHAR(256) NOT NULL,
    key_id      VARCHAR(64) NOT NULL DEFAULT '',
    subject     VARCHAR(256) NOT NULL,
    signature   TEXT NOT NULL,
    timestamp   BIGINT NOT NULL,
    data_hash   VARCHAR(128) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_non_repudiation_op ON non_repudiation_evidence(operation);
CREATE INDEX IF NOT EXISTS idx_non_repudiation_key ON non_repudiation_evidence(key_id);
"#
}
