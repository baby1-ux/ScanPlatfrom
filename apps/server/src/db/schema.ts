/**
 * 建表 DDL —— 由 docs/01-需求与开发文档.md 第 10.2 节的 MySQL DDL 翻译而来。
 *
 * 方言差异说明（SQLite 适配层）：
 *  - MySQL `ENUM(...)`      → TEXT + CHECK 约束，枚举值来自 @vuln/shared 常量
 *  - MySQL `TINYINT`        → INTEGER
 *  - MySQL `DECIMAL(4,3)`   → REAL
 *  - `BIGINT UNSIGNED`      → INTEGER（SQLite 主键自增；JS 安全整数范围内足够）
 *  - `DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE ...` → 由应用层显式写入 ISO8601 UTC 字符串
 *    时间统一以 `YYYY-MM-DDTHH:mm:ss.sssZ` 存储，字符串字典序 == 时间序，可直接用于范围比较与排序。
 */

export const SCHEMA_SQL = `
PRAGMA foreign_keys = ON;

-- ---------- 用户 ----------
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      VARCHAR(64)  NOT NULL,
  password_hash VARCHAR(100) NOT NULL,
  display_name  VARCHAR(64),
  email         VARCHAR(128),
  role          TEXT NOT NULL DEFAULT 'auditor' CHECK (role IN ('admin','auditor','viewer')),
  status        INTEGER NOT NULL DEFAULT 1,
  last_login_at TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_users_username ON users(username);

-- ---------- API Key ----------
CREATE TABLE IF NOT EXISTS api_keys (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         VARCHAR(64) NOT NULL,
  key_prefix   VARCHAR(16) NOT NULL,
  key_hash     CHAR(64)    NOT NULL,
  scopes       VARCHAR(255) NOT NULL DEFAULT 'ingest',
  repo_scope   TEXT,
  expires_at   TEXT,
  last_used_at TEXT,
  status       INTEGER NOT NULL DEFAULT 1,
  created_by   INTEGER,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status);

-- ---------- 项目 / 代码仓库 ----------
CREATE TABLE IF NOT EXISTS projects (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  name           VARCHAR(128) NOT NULL,
  repo_type      TEXT NOT NULL DEFAULT 'other'
                 CHECK (repo_type IN ('github','gitlab','gitee','bitbucket','other')),
  repo_url       VARCHAR(512) NOT NULL,
  repo_full_name VARCHAR(255),
  default_branch VARCHAR(128),
  owner          VARCHAR(64),
  description    VARCHAR(512),
  status         INTEGER NOT NULL DEFAULT 1,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_projects_repo ON projects(repo_type, repo_url);
CREATE INDEX IF NOT EXISTS idx_projects_name ON projects(name);

-- ---------- 扫描批次 ----------
CREATE TABLE IF NOT EXISTS scan_tasks (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_no         VARCHAR(128) NOT NULL,
  project_id      INTEGER NOT NULL REFERENCES projects(id),
  scanner_name    VARCHAR(64),
  scanner_version VARCHAR(32),
  trigger_type    TEXT NOT NULL DEFAULT 'push'
                  CHECK (trigger_type IN ('push','merge_request','manual','schedule','webhook')),
  branch          VARCHAR(128),
  commit_id       VARCHAR(64),
  commit_message  VARCHAR(512),
  commit_author   VARCHAR(64),
  commit_time     TEXT,
  started_at      TEXT,
  finished_at     TEXT,
  status          TEXT NOT NULL DEFAULT 'running'
                  CHECK (status IN ('running','success','failed','partial')),
  total_files     INTEGER NOT NULL DEFAULT 0,
  scanned_files   INTEGER NOT NULL DEFAULT 0,
  vuln_count      INTEGER NOT NULL DEFAULT 0,
  sample_count    INTEGER NOT NULL DEFAULT 0,
  positive_count  INTEGER NOT NULL DEFAULT 0,
  negative_count  INTEGER NOT NULL DEFAULT 0,
  error_message   VARCHAR(1024),
  raw_report      TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_scan_tasks_scan_no ON scan_tasks(scan_no);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_project_time ON scan_tasks(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status);

-- ---------- 漏洞 ----------
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  vuln_no          VARCHAR(32) NOT NULL,
  fingerprint      CHAR(64)    NOT NULL,
  scan_id          INTEGER NOT NULL REFERENCES scan_tasks(id),
  project_id       INTEGER NOT NULL REFERENCES projects(id),
  external_vuln_id VARCHAR(64),
  rule_id          VARCHAR(128),
  rule_name        VARCHAR(255),
  title            VARCHAR(512) NOT NULL,
  severity         TEXT NOT NULL
                   CHECK (severity IN ('critical','high','medium','low','info')),
  category         VARCHAR(64),
  cwe              VARCHAR(32),
  cve              VARCHAR(64),
  language         VARCHAR(32),
  file_path        VARCHAR(512) NOT NULL,
  line_start       INTEGER,
  line_end         INTEGER,
  code_snippet     TEXT,
  description      TEXT,
  suggestion       TEXT,
  confidence       REAL,
  status           TEXT NOT NULL DEFAULT 'open'
                   CHECK (status IN ('open','confirmed','fixing','fixed','ignored','false_positive')),
  assignee         INTEGER REFERENCES users(id),
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  first_found_at   TEXT NOT NULL,
  last_found_at    TEXT NOT NULL,
  fixed_at         TEXT,
  remark           VARCHAR(512),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_vuln_fingerprint ON vulnerabilities(fingerprint);
CREATE UNIQUE INDEX IF NOT EXISTS uk_vuln_no ON vulnerabilities(vuln_no);
CREATE INDEX IF NOT EXISTS idx_vuln_project_sev_status ON vulnerabilities(project_id, severity, status);
CREATE INDEX IF NOT EXISTS idx_vuln_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vuln_status_time ON vulnerabilities(status, last_found_at);
CREATE INDEX IF NOT EXISTS idx_vuln_file ON vulnerabilities(project_id, file_path);
CREATE INDEX IF NOT EXISTS idx_vuln_rule ON vulnerabilities(rule_id);

-- ---------- 正负样本 ----------
CREATE TABLE IF NOT EXISTS samples (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id            INTEGER NOT NULL REFERENCES scan_tasks(id),
  project_id         INTEGER NOT NULL REFERENCES projects(id),
  external_sample_id VARCHAR(64),
  label              TEXT NOT NULL CHECK (label IN ('positive','negative')),
  rule_id            VARCHAR(128),
  vuln_id            INTEGER REFERENCES vulnerabilities(id),
  file_path          VARCHAR(512) NOT NULL,
  language           VARCHAR(32),
  line_start         INTEGER,
  line_end           INTEGER,
  snippet            TEXT,
  snippet_hash       CHAR(64) NOT NULL,
  file_hash          CHAR(64),
  created_at         TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uk_samples ON samples(scan_id, file_path, snippet_hash);
CREATE INDEX IF NOT EXISTS idx_samples_project_label ON samples(project_id, label);
CREATE INDEX IF NOT EXISTS idx_samples_rule ON samples(rule_id);
CREATE INDEX IF NOT EXISTS idx_samples_label_time ON samples(label, created_at);
CREATE INDEX IF NOT EXISTS idx_samples_vuln ON samples(vuln_id);

-- ---------- 漏洞操作时间线 ----------
CREATE TABLE IF NOT EXISTS vuln_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  vuln_id       INTEGER NOT NULL REFERENCES vulnerabilities(id),
  action        VARCHAR(32) NOT NULL,
  from_value    VARCHAR(64),
  to_value      VARCHAR(64),
  operator_id   INTEGER,
  operator_name VARCHAR(64),
  comment       VARCHAR(512),
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vuln_events_vuln ON vuln_events(vuln_id, created_at);

-- ---------- 审计日志 ----------
CREATE TABLE IF NOT EXISTS audit_logs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER,
  username    VARCHAR(64),
  method      VARCHAR(8),
  path        VARCHAR(255),
  ip          VARCHAR(64),
  status_code INTEGER,
  cost_ms     INTEGER,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_logs(user_id, created_at);

-- ---------- 键值元数据（如：种子数据是否已灌入） ----------
CREATE TABLE IF NOT EXISTS meta (
  k          VARCHAR(64) PRIMARY KEY,
  v          TEXT,
  updated_at TEXT NOT NULL
);
`;

/** 记录用过的表名，供 reset 脚本按依赖顺序清理 */
export const TABLE_NAMES = [
  'audit_logs',
  'vuln_events',
  'samples',
  'vulnerabilities',
  'scan_tasks',
  'projects',
  'api_keys',
  'users',
  'meta',
] as const;
