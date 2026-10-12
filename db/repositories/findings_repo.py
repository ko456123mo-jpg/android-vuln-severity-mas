"""CRUD الثغرات والأدلة / Vulnerabilities + findings repository."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from db.connection import get_session
from db.models import Vulnerability, VulnerabilityFinding
from db.repositories import row_to_dict


# ---------------------------------------------------------------------
# vulnerabilities — السجل الموحّد (dedup_fingerprint UNIQUE)
# ---------------------------------------------------------------------
def create_vulnerability(
    application_id: int,
    title: str,
    description: str | None = None,
    masvs_category: str | None = None,
    cwe_id: str | None = None,
    dedup_fingerprint: str = "",
    status: str = "open",
) -> dict[str, Any] | None:
    """إنشاء ثغرة موحّدة — get-or-create بالبصمة (idempotent عبر الفحوص)."""
    if not dedup_fingerprint:
        return None
    with get_session() as session:
        existing = session.scalar(
            select(Vulnerability).where(
                Vulnerability.dedup_fingerprint == dedup_fingerprint
            )
        )
        if existing:
            return row_to_dict(existing)
        vuln = Vulnerability(
            application_id=application_id,
            title=title,
            description=description,
            masvs_category=masvs_category,
            cwe_id=cwe_id,
            dedup_fingerprint=dedup_fingerprint,
            status=status,
        )
        session.add(vuln)
        session.flush()
        session.refresh(vuln)
        return row_to_dict(vuln)


def list_vulns_by_app(application_id: int) -> list[dict[str, Any]]:
    """سرد ثغرات تطبيق (الأحدث أولاً)."""
    with get_session() as session:
        vulns = session.scalars(
            select(Vulnerability)
            .where(Vulnerability.application_id == application_id)
            .order_by(Vulnerability.id)
        ).all()
        return [row_to_dict(v) for v in vulns]


# ---------------------------------------------------------------------
# vulnerability_findings — الأدلة لكل أداة
# ---------------------------------------------------------------------
def create(
    vulnerability_id: int,
    scan_id: int,
    tool_id: int,
    location: str | None = None,
    evidence_type: str | None = None,
    artifact_ref: str | None = None,
) -> dict[str, Any]:
    """تسجيل دليل جديد مرتبط بثغرة + فحص + أداة.

    Idempotent على ثلاثيّة (vulnerability_id, scan_id, tool_id): التكرار
    يعيد السجل القائم — يسمح بحفظ الأدلة مبكراً (قبل التقارير) ثم في
    finalize دون أي مضاعفة (قرار المرحلة 5، موثق).
    """
    with get_session() as session:
        existing = session.scalar(
            select(VulnerabilityFinding).where(
                VulnerabilityFinding.vulnerability_id == vulnerability_id,
                VulnerabilityFinding.scan_id == scan_id,
                VulnerabilityFinding.tool_id == tool_id,
            )
        )
        if existing:
            return row_to_dict(existing)
        finding = VulnerabilityFinding(
            vulnerability_id=vulnerability_id,
            scan_id=scan_id,
            tool_id=tool_id,
            location=location,
            evidence_type=evidence_type,
            artifact_ref=artifact_ref,
        )
        session.add(finding)
        session.flush()
        session.refresh(finding)
        return row_to_dict(finding)


# اسم بديل متوافق مع مواصفات الوكلاء / alias per agent spec (Phase 3)
def create_finding(**kwargs: Any) -> dict[str, Any]:
    """Alias of create() — التسمية المعتمدة في المرحلة 3."""
    return create(**kwargs)


def list_by_vuln(vulnerability_id: int) -> list[dict[str, Any]]:
    """كل الأدلة المرتبطة بثغرة (تغذي evidence_score)."""
    with get_session() as session:
        findings = session.scalars(
            select(VulnerabilityFinding)
            .where(VulnerabilityFinding.vulnerability_id == vulnerability_id)
            .order_by(VulnerabilityFinding.id)
        ).all()
        return [row_to_dict(f) for f in findings]


def list_by_scan(scan_id: int) -> list[dict[str, Any]]:
    """كل الأدلة الناتجة عن جلسة فحص."""
    with get_session() as session:
        findings = session.scalars(
            select(VulnerabilityFinding)
            .where(VulnerabilityFinding.scan_id == scan_id)
            .order_by(VulnerabilityFinding.id)
        ).all()
        return [row_to_dict(f) for f in findings]


def get_vulnerability(vulnerability_id: int) -> dict[str, Any] | None:
    """جلب ثغرة بالمعرّف (إضافة المرحلة 6 للواجهة)."""
    with get_session() as session:
        vuln = session.get(Vulnerability, vulnerability_id)
        return row_to_dict(vuln) if vuln else None
