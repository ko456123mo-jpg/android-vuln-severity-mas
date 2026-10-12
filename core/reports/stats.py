"""إحصائيات الفحص — Scan statistics aggregator (المرحلة 5).

تجميع حتمي من قاعدة البيانات فقط — لا حسابات LLM هنا.
المصدر: vulnerabilities × assessments × findings × scans لفحص معيّن.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select

from db.connection import get_session
from db.models import Assessment, Scan, Tool, Vulnerability, VulnerabilityFinding

_SEVERITIES = ("Critical", "High", "Medium", "Low")


def _ensure_list(value: Any) -> list[Any]:
    """تطبيع أعمدة JSON النصية (scans.tools_used مخزَّن TEXT)."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        import json

        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except ValueError:
            return []
    return []


def compute_scan_statistics(scan_id: int) -> dict[str, Any]:
    """حساب إحصائيات فحص واحد.

    Returns:
        {
          "scan_id", "total", "by_severity" {Critical: n, ...},
          "by_masvs" {MASVS-X: n, ...}, "confirmed_dynamic",
          "avg_final_score", "max_final_score", "min_final_score",
          "tools_used" [names], "tool_counts" {tool: findings},
          "pending_reviews", "approved_reviews",
          "total_duration_ms", "status"
        }
    """
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"scan غير موجود / scan_id={scan_id}")

        # ثغرات التطبيق المفحوص (assessments على مستوى التطبيق — النتيجة تراكمية)
        vulns = session.scalars(
            select(Vulnerability).where(Vulnerability.application_id == scan.application_id)
        ).all()
        vuln_ids = [v.id for v in vulns]

        assessments: list[Assessment] = []
        if vuln_ids:
            assessments = list(
                session.scalars(
                    select(Assessment).where(Assessment.vulnerability_id.in_(vuln_ids))
                ).all()
            )

        by_severity = {sev: 0 for sev in _SEVERITIES}
        by_masvs: dict[str, int] = {}
        for vuln in vulns:
            record = next((a for a in assessments if a.vulnerability_id == vuln.id), None)
            severity = record.severity if record and record.severity else "Unscored"
            by_severity[severity] = by_severity.get(severity, 0) + 1
            category = vuln.masvs_category or "Unknown"
            by_masvs[category] = by_masvs.get(category, 0) + 1

        # الأدلة المؤكدة ديناميكياً لهذا الفحص / dynamic-confirmed evidence
        findings = session.scalars(
            select(VulnerabilityFinding).where(VulnerabilityFinding.scan_id == scan_id)
        ).all()
        confirmed_vulns = {f.vulnerability_id for f in findings if f.evidence_type == "dynamic"}

        # توزيع الأدوات / per-tool findings
        tool_ids = {f.tool_id for f in findings}
        tool_names = {
            t.id: t.name
            for t in session.scalars(select(Tool).where(Tool.id.in_(tool_ids))).all()
        } if tool_ids else {}
        tool_counts: dict[str, int] = {}
        for finding in findings:
            name = tool_names.get(finding.tool_id, f"tool#{finding.tool_id}")
            tool_counts[name] = tool_counts.get(name, 0) + 1

        scores = [a.final_score for a in assessments if a.final_score is not None]
        tools_used = _ensure_list(scan.tools_used) if scan.tools_used else []

    return {
        "scan_id": scan_id,
        "status": scan.status,
        "total": len(vulns),
        "by_severity": by_severity,
        "by_masvs": by_masvs,
        "confirmed_dynamic": len(confirmed_vulns),
        "avg_final_score": round(sum(scores) / len(scores), 4) if scores else 0.0,
        "max_final_score": max(scores) if scores else 0.0,
        "min_final_score": min(scores) if scores else 0.0,
        "tools_used": tools_used,
        "tool_counts": tool_counts,
        "pending_reviews": sum(
            1 for a in assessments if a.review_status == "pending"
        ),
        "approved_reviews": sum(
            1 for a in assessments if a.review_status == "approved"
        ),
        "total_duration_ms": scan.total_duration_ms or 0,
        "total_findings": len(findings),
    }
