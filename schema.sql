-- JWP SaaS — D1 Schema (synced from remote, 2026-04-05)
-- Apply locally:  npm run db:migrate:local  (from worker/)
-- Apply remotely: npm run db:migrate:remote (from worker/)

CREATE TABLE IF NOT EXISTS users (
  id                   TEXT    PRIMARY KEY,          -- nanoid
  email                TEXT    UNIQUE NOT NULL,
  password_hash        TEXT    NOT NULL,             -- PBKDF2-SHA256 via Web Crypto
  created_at           INTEGER NOT NULL,             -- Unix ms
  last_login           INTEGER,
  is_verified          INTEGER NOT NULL DEFAULT 0,
  is_active            INTEGER NOT NULL DEFAULT 1,
  notification_prefs   TEXT,
  updated_at           INTEGER,
  tos_accepted_at      INTEGER,
  tos_version          TEXT    DEFAULT '2026-04-01',
  verify_token         TEXT,
  verify_token_expires INTEGER,
  full_name            TEXT
);

CREATE TABLE IF NOT EXISTS scans (
  id                          TEXT    PRIMARY KEY,  -- nanoid
  user_id                     TEXT    NOT NULL REFERENCES users(id),
  target                      TEXT    NOT NULL,
  status                      TEXT    NOT NULL DEFAULT 'queued', -- queued|running|completed|failed
  modules_selected            TEXT,                -- JSON array of module IDs; NULL = all
  created_at                  INTEGER NOT NULL,
  started_at                  INTEGER,
  completed_at                INTEGER,
  findings_count              INTEGER NOT NULL DEFAULT 0,
  critical_count              INTEGER NOT NULL DEFAULT 0,
  high_count                  INTEGER NOT NULL DEFAULT 0,
  medium_count                INTEGER NOT NULL DEFAULT 0,
  low_count                   INTEGER NOT NULL DEFAULT 0,
  info_count                  INTEGER NOT NULL DEFAULT 0,
  report_key                  TEXT,                -- R2 object key for full JSON report
  error_message               TEXT,
  tags                        TEXT,
  is_public                   INTEGER NOT NULL DEFAULT 0,
  public_token                TEXT,
  authorization_confirmed_at  INTEGER,
  authorization_ip            TEXT
);

CREATE TABLE IF NOT EXISTS usage (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    TEXT    NOT NULL REFERENCES users(id),
  action     TEXT    NOT NULL DEFAULT 'scan',
  scan_id    TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  id           TEXT    PRIMARY KEY,         -- nanoid
  user_id      TEXT    NOT NULL REFERENCES users(id),
  key_hash     TEXT    NOT NULL,
  name         TEXT,
  last_used    INTEGER,
  created_at   INTEGER NOT NULL,
  is_active    INTEGER NOT NULL DEFAULT 1,
  key_prefix   TEXT    DEFAULT '',
  enabled      INTEGER DEFAULT 1,
  last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS scheduled_scans (
  id            TEXT    PRIMARY KEY,
  user_id       TEXT    NOT NULL,
  url           TEXT    NOT NULL,
  schedule_cron TEXT    NOT NULL,
  next_run_at   INTEGER NOT NULL,
  last_run_at   INTEGER,
  enabled       INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS webhooks (
  id         TEXT    PRIMARY KEY,
  user_id    TEXT    NOT NULL,
  url        TEXT    NOT NULL,
  secret     TEXT    NOT NULL,
  events     TEXT    NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS false_positive_reports (
  id               TEXT    PRIMARY KEY,
  scan_id          TEXT    NOT NULL,
  user_id          TEXT    NOT NULL,
  finding_type     TEXT    NOT NULL,
  finding_url      TEXT    NOT NULL,
  finding_severity TEXT    NOT NULL,
  reason           TEXT,
  status           TEXT    NOT NULL DEFAULT 'pending',
  created_at       INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS system_config (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at INTEGER DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_scans_user_created
  ON scans(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_usage_user_created
  ON usage(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_usage_user_action_date
  ON usage(user_id, action, created_at DESC);
