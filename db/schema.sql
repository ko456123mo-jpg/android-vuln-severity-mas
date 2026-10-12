-- =====================================================================
-- Android Vulnerability Severity MAS — Database Schema (v1)
-- SQLite — 14 جدولاً / tables — OWASP MASVS aligned
-- مصدر الحقيقة للـ DDL / Single source of truth for DDL
-- =====================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- ---------------------------------------------------------------------
-- 1) users — المستخدمون والأدوار (admin / analyst / reviewer)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER      PRIMARY KEY AUTOINCREMENT,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(20)  NOT NULL CHECK (role IN ('admin', 'analyst', 'reviewer')),
    email         VARCHAR(255) UNIQUE,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login    TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 2) projects — تجميع تنظيمي للتطبيقات
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER      PRIMARY KEY AUTOINCREMENT,
    name        VARCHAR(120) NOT NULL,
    description TEXT,
    owner_id    INTEGER      REFERENCES users(id),
    status      VARCHAR(20)  NOT NULL DEFAULT 'active',
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 3) applications — بيانات الـ APK
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS applications (
    id            INTEGER      PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER      NOT NULL REFERENCES projects(id),
    name          VARCHAR(120) NOT NULL,
    package_name  VARCHAR(255),
    version       VARCHAR(50),
    sha256        CHAR(64)     NOT NULL UNIQUE,
    file_path     TEXT         NOT NULL,
    file_size     INTEGER,
    app_category  VARCHAR(50),
    uploaded_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 4) app_context — السياق التجاري (مدخل context_score) — علاقة 1:1
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_context (
    id                      INTEGER     PRIMARY KEY AUTOINCREMENT,
    application_id          INTEGER     NOT NULL UNIQUE REFERENCES applications(id),
    data_sensitivity        VARCHAR(10) CHECK (data_sensitivity IN ('LOW', 'MEDIUM', 'HIGH')),
    industry                VARCHAR(20) CHECK (industry IN ('banking', 'health', 'commerce', 'game', 'utility')),
    user_base_size          VARCHAR(10) CHECK (user_base_size IN ('small', 'medium', 'large')),
    internet_facing         BOOLEAN,
    business_criticality    VARCHAR(10) CHECK (business_criticality IN ('LOW', 'MEDIUM', 'HIGH')),
    compliance_requirements TEXT,
    context_score           FLOAT,
    updated_at              TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 5) tools — سجل أدوات التحليل عبر MCP
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tools (
    id                INTEGER      PRIMARY KEY AUTOINCREMENT,
    name              VARCHAR(50)  NOT NULL UNIQUE,
    version           VARCHAR(30),
    category          VARCHAR(10)  CHECK (category IN ('static', 'dynamic')),
    mcp_endpoint      TEXT,
    capabilities      TEXT,                -- JSON array
    reliability_score FLOAT,
    enabled           BOOLEAN      NOT NULL DEFAULT 1,
    last_healthcheck  TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 6) scans — جلسات الفحص
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id                INTEGER     PRIMARY KEY AUTOINCREMENT,
    application_id    INTEGER     NOT NULL REFERENCES applications(id),
    status            VARCHAR(20) NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'running', 'success', 'failed', 'partial')),
    tools_used        TEXT,                -- JSON array
    rule_version      VARCHAR(20),
    started_at        TIMESTAMP,
    finished_at       TIMESTAMP,
    error_message     TEXT,
    total_tokens      INTEGER     DEFAULT 0,
    total_duration_ms INTEGER     DEFAULT 0
);

-- ---------------------------------------------------------------------
-- 7) vulnerabilities — الثغرة الموحّدة بعد الدمج (dedup)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                 INTEGER      PRIMARY KEY AUTOINCREMENT,
    application_id     INTEGER      NOT NULL REFERENCES applications(id),
    title              VARCHAR(255) NOT NULL,
    description        TEXT,
    masvs_category     VARCHAR(50),
    cwe_id             VARCHAR(20),
    dedup_fingerprint  VARCHAR(128) NOT NULL UNIQUE,
    status             VARCHAR(20)  NOT NULL DEFAULT 'open'
                       CHECK (status IN ('open', 'confirmed', 'fixed', 'false_positive')),
    discovered_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 8) vulnerability_findings — الأدلة الخام لكل أداة
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerability_findings (
    id               INTEGER     PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER     NOT NULL REFERENCES vulnerabilities(id),
    scan_id          INTEGER     NOT NULL REFERENCES scans(id),
    tool_id          INTEGER     NOT NULL REFERENCES tools(id),
    location         TEXT,
    evidence_type    VARCHAR(10) CHECK (evidence_type IN ('static', 'dynamic')),
    artifact_ref     TEXT,
    created_at       TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 9) severity_rules — قواعد التقييم (versioned) — صف نشط واحد
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS severity_rules (
    id             INTEGER     PRIMARY KEY AUTOINCREMENT,
    version        VARCHAR(20) NOT NULL UNIQUE,
    weights        TEXT        NOT NULL,     -- JSON: {base, context, evidence}
    context_params TEXT        NOT NULL,     -- JSON: معاملات السياق
    thresholds     TEXT        NOT NULL,     -- JSON: العتبات + الثقة
    active         BOOLEAN     NOT NULL DEFAULT 0,
    created_at     TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 10) assessments — نتائج التقييم الموزون (تقييم واحد لكل ثغرة)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assessments (
    id                INTEGER     PRIMARY KEY AUTOINCREMENT,
    vulnerability_id  INTEGER     NOT NULL UNIQUE REFERENCES vulnerabilities(id),
    base_score        FLOAT,
    context_score     FLOAT,
    evidence_score    FLOAT,
    confidence_factor FLOAT,
    final_score       FLOAT,
    severity          VARCHAR(10) CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    rationale         TEXT,
    rule_version      VARCHAR(20) REFERENCES severity_rules(version),
    assessed_by       VARCHAR(10) CHECK (assessed_by IN ('agent', 'reviewer', 'human')),
    assessed_at       TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_by       INTEGER,
    review_status     VARCHAR(10) DEFAULT 'pending'
                      CHECK (review_status IN ('pending', 'approved', 'rejected')),
    review_notes      TEXT
);

-- ---------------------------------------------------------------------
-- 11) corrections — التصحيحات البشرية (HITL)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS corrections (
    id                 INTEGER     PRIMARY KEY AUTOINCREMENT,
    assessment_id      INTEGER     NOT NULL REFERENCES assessments(id),
    reviewer_id        INTEGER     NOT NULL REFERENCES users(id),
    original_severity  VARCHAR(10),
    corrected_severity VARCHAR(10),
    original_score     FLOAT,
    corrected_score    FLOAT,
    reason             TEXT        NOT NULL,
    corrected_at       TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 12) feedback_examples — أمثلة few-shot مشتقة من التصحيحات
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS feedback_examples (
    id             INTEGER     PRIMARY KEY AUTOINCREMENT,
    correction_id  INTEGER     NOT NULL REFERENCES corrections(id),
    example_type   VARCHAR(30),
    prompt_payload TEXT,               -- JSON
    embedding      BLOB,
    active         BOOLEAN     NOT NULL DEFAULT 1,
    created_at     TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 13) agent_logs — تدقيق شامل للوكلاء (تكلفة/زمن/أخطاء)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_logs (
    id            INTEGER     PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER     REFERENCES scans(id),
    agent_name    VARCHAR(30),
    action        VARCHAR(100),
    llm_model     VARCHAR(100),
    tokens_in     INTEGER,
    tokens_out    INTEGER,
    latency_ms    INTEGER,
    status        VARCHAR(10) CHECK (status IN ('success', 'failed')),
    error_message TEXT,
    reasoning     TEXT,
    created_at    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 14) knowledge_base — معرفة RAG (MASVS / CWE / OWASP)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge_base (
    id             INTEGER      PRIMARY KEY AUTOINCREMENT,
    source         VARCHAR(10)  CHECK (source IN ('MASVS', 'CWE', 'OWASP')),
    ref_id         VARCHAR(40),
    title          VARCHAR(255),
    content        TEXT         NOT NULL,
    cwe_id         VARCHAR(20),
    masvs_category VARCHAR(50),
    embedding      BLOB,
    version        VARCHAR(20),
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- الفهارس / Indexes
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_apps_project       ON applications(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_app          ON scans(application_id);
CREATE INDEX IF NOT EXISTS idx_vulns_app          ON vulnerabilities(application_id);
CREATE INDEX IF NOT EXISTS idx_vulns_fingerprint  ON vulnerabilities(dedup_fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_vuln      ON vulnerability_findings(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan      ON vulnerability_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_assessments_vuln   ON assessments(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_assessments_severity ON assessments(severity);
CREATE INDEX IF NOT EXISTS idx_logs_scan          ON agent_logs(scan_id);
CREATE INDEX IF NOT EXISTS idx_kb_masvs           ON knowledge_base(masvs_category);
