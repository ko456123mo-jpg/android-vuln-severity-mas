"""نماذج ORM — SQLAlchemy 2.0 declarative models للجداول الـ14.

متوافقة 1:1 مع db/schema.sql (مصدر الحقيقة للـ DDL).
Reuse / Usage:
    from db.models import User, Project, Application, ...
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """قاعدة كل النماذج / Declarative base for all models."""


# ---------------------------------------------------------------------
# 1) users
# ---------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('admin','analyst','reviewer')", name="ck_users_role"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime)

    projects: Mapped[list[Project]] = relationship(back_populates="owner")
    corrections: Mapped[list[Correction]] = relationship(back_populates="reviewer")


# ---------------------------------------------------------------------
# 2) projects
# ---------------------------------------------------------------------
class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    owner: Mapped[User | None] = relationship(back_populates="projects")
    applications: Mapped[list[Application]] = relationship(back_populates="project")


# ---------------------------------------------------------------------
# 3) applications
# ---------------------------------------------------------------------
class Application(Base):
    __tablename__ = "applications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    package_name: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(50))
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_size: Mapped[int | None] = mapped_column(Integer)
    app_category: Mapped[str | None] = mapped_column(String(50))
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    project: Mapped[Project] = relationship(back_populates="applications")
    context: Mapped[AppContext | None] = relationship(back_populates="application")
    scans: Mapped[list[Scan]] = relationship(back_populates="application")
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(back_populates="application")


# ---------------------------------------------------------------------
# 4) app_context  (1:1 مع applications — مدخل context_score)
# ---------------------------------------------------------------------
class AppContext(Base):
    __tablename__ = "app_context"
    __table_args__ = (
        CheckConstraint(
            "data_sensitivity IN ('LOW','MEDIUM','HIGH')", name="ck_ctx_sensitivity"
        ),
        CheckConstraint(
            "industry IN ('banking','health','commerce','game','utility')", name="ck_ctx_industry"
        ),
        CheckConstraint("user_base_size IN ('small','medium','large')", name="ck_ctx_userbase"),
        CheckConstraint(
            "business_criticality IN ('LOW','MEDIUM','HIGH')", name="ck_ctx_criticality"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id"), nullable=False, unique=True
    )
    data_sensitivity: Mapped[str | None] = mapped_column(String(10))
    industry: Mapped[str | None] = mapped_column(String(20))
    user_base_size: Mapped[str | None] = mapped_column(String(10))
    internet_facing: Mapped[bool | None] = mapped_column(Boolean)
    business_criticality: Mapped[str | None] = mapped_column(String(10))
    compliance_requirements: Mapped[str | None] = mapped_column(Text)
    context_score: Mapped[float | None] = mapped_column(Float)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )

    application: Mapped[Application] = relationship(back_populates="context")


# ---------------------------------------------------------------------
# 5) tools — أدوات MCP
# ---------------------------------------------------------------------
class Tool(Base):
    __tablename__ = "tools"
    __table_args__ = (
        CheckConstraint("category IN ('static','dynamic')", name="ck_tools_category"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    version: Mapped[str | None] = mapped_column(String(30))
    category: Mapped[str | None] = mapped_column(String(10))
    mcp_endpoint: Mapped[str | None] = mapped_column(Text)
    capabilities: Mapped[list[str] | None] = mapped_column(JSON)
    reliability_score: Mapped[float | None] = mapped_column(Float)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_healthcheck: Mapped[datetime | None] = mapped_column(DateTime)

    findings: Mapped[list[VulnerabilityFinding]] = relationship(back_populates="tool")


# ---------------------------------------------------------------------
# 6) scans
# ---------------------------------------------------------------------
class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','running','success','failed','partial')", name="ck_scans_status"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("applications.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    tools_used: Mapped[list[str] | None] = mapped_column(JSON)
    rule_version: Mapped[str | None] = mapped_column(String(20))
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    error_message: Mapped[str | None] = mapped_column(Text)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    application: Mapped[Application] = relationship(back_populates="scans")
    findings: Mapped[list[VulnerabilityFinding]] = relationship(back_populates="scan")
    logs: Mapped[list[AgentLog]] = relationship(back_populates="scan")


# ---------------------------------------------------------------------
# 7) vulnerabilities
# ---------------------------------------------------------------------
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open','confirmed','fixed','false_positive')", name="ck_vulns_status"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("applications.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    masvs_category: Mapped[str | None] = mapped_column(String(50))
    cwe_id: Mapped[str | None] = mapped_column(String(20))
    dedup_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    application: Mapped[Application] = relationship(back_populates="vulnerabilities")
    findings: Mapped[list[VulnerabilityFinding]] = relationship(back_populates="vulnerability")
    assessment: Mapped[Assessment | None] = relationship(back_populates="vulnerability")


# ---------------------------------------------------------------------
# 8) vulnerability_findings
# ---------------------------------------------------------------------
class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        CheckConstraint(
            "evidence_type IN ('static','dynamic')", name="ck_findings_evidence"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id"), nullable=False
    )
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    tool_id: Mapped[int] = mapped_column(ForeignKey("tools.id"), nullable=False)
    location: Mapped[str | None] = mapped_column(Text)
    evidence_type: Mapped[str | None] = mapped_column(String(10))
    artifact_ref: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="findings")
    scan: Mapped[Scan] = relationship(back_populates="findings")
    tool: Mapped[Tool] = relationship(back_populates="findings")


# ---------------------------------------------------------------------
# 9) severity_rules — versioned (صف active واحد)
# ---------------------------------------------------------------------
class SeverityRule(Base):
    __tablename__ = "severity_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    weights: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    context_params: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    thresholds: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    assessments: Mapped[list[Assessment]] = relationship(back_populates="rule")


# ---------------------------------------------------------------------
# 10) assessments — تقييم واحد لكل ثغرة
# ---------------------------------------------------------------------
class Assessment(Base):
    __tablename__ = "assessments"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('Critical','High','Medium','Low')", name="ck_assess_severity"
        ),
        CheckConstraint(
            "assessed_by IN ('agent','reviewer','human')", name="ck_assess_by"
        ),
        CheckConstraint(
            "review_status IN ('pending','approved','rejected')", name="ck_assess_review"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id"), nullable=False, unique=True
    )
    base_score: Mapped[float | None] = mapped_column(Float)
    context_score: Mapped[float | None] = mapped_column(Float)
    evidence_score: Mapped[float | None] = mapped_column(Float)
    confidence_factor: Mapped[float | None] = mapped_column(Float)
    final_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(10))
    rationale: Mapped[str | None] = mapped_column(Text)
    rule_version: Mapped[str | None] = mapped_column(ForeignKey("severity_rules.version"))
    assessed_by: Mapped[str | None] = mapped_column(String(10))
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    reviewed_by: Mapped[int | None] = mapped_column(Integer)
    review_status: Mapped[str | None] = mapped_column(String(10), default="pending")
    review_notes: Mapped[str | None] = mapped_column(Text)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="assessment")
    rule: Mapped[SeverityRule | None] = relationship(back_populates="assessments")
    corrections: Mapped[list[Correction]] = relationship(back_populates="assessment")


# ---------------------------------------------------------------------
# 11) corrections — HITL
# ---------------------------------------------------------------------
class Correction(Base):
    __tablename__ = "corrections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id"), nullable=False)
    reviewer_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    original_severity: Mapped[str | None] = mapped_column(String(10))
    corrected_severity: Mapped[str | None] = mapped_column(String(10))
    original_score: Mapped[float | None] = mapped_column(Float)
    corrected_score: Mapped[float | None] = mapped_column(Float)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    corrected_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    assessment: Mapped[Assessment] = relationship(back_populates="corrections")
    reviewer: Mapped[User] = relationship(back_populates="corrections")
    feedback_examples: Mapped[list[FeedbackExample]] = relationship(back_populates="correction")


# ---------------------------------------------------------------------
# 12) feedback_examples
# ---------------------------------------------------------------------
class FeedbackExample(Base):
    __tablename__ = "feedback_examples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    correction_id: Mapped[int] = mapped_column(ForeignKey("corrections.id"), nullable=False)
    example_type: Mapped[str | None] = mapped_column(String(30))
    prompt_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    embedding: Mapped[bytes | None] = mapped_column(LargeBinary)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    correction: Mapped[Correction] = relationship(back_populates="feedback_examples")


# ---------------------------------------------------------------------
# 13) agent_logs
# ---------------------------------------------------------------------
class AgentLog(Base):
    __tablename__ = "agent_logs"
    __table_args__ = (
        CheckConstraint("status IN ('success','failed')", name="ck_logs_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"))
    agent_name: Mapped[str | None] = mapped_column(String(30))
    action: Mapped[str | None] = mapped_column(String(100))
    llm_model: Mapped[str | None] = mapped_column(String(100))
    tokens_in: Mapped[int | None] = mapped_column(Integer)
    tokens_out: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str | None] = mapped_column(String(10))
    error_message: Mapped[str | None] = mapped_column(Text)
    reasoning: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    scan: Mapped[Scan | None] = relationship(back_populates="logs")


# ---------------------------------------------------------------------
# 14) knowledge_base
# ---------------------------------------------------------------------
class KnowledgeBase(Base):
    __tablename__ = "knowledge_base"
    __table_args__ = (
        CheckConstraint("source IN ('MASVS','CWE','OWASP')", name="ck_kb_source"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str | None] = mapped_column(String(10))
    ref_id: Mapped[str | None] = mapped_column(String(40))
    title: Mapped[str | None] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(Text, nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(20))
    masvs_category: Mapped[str | None] = mapped_column(String(50))
    embedding: Mapped[bytes | None] = mapped_column(LargeBinary)
    version: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
