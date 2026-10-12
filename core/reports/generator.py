"""ReportGenerator — توليد تقارير الفحص (فني EN + تنفيذي AR) بثلاث صيغ.

قرارات موثقة (docs/hitl_and_reports.md):
    • بيانات التقارير مصدرها قاعدة البيانات فقط (assessments/vulnerabilities/
      findings/scans) — لا يُخترع أي رقم؛ الملخصات التنفيذية العربية تأتي من
      LLM عبر ReporterAgent أو من بديل حتمي عند التعذر.
    • عمود "Recommendation" محتوى إرشادي مشتق من خريطة ثابتة CWE→نص
      (RECOMMENDATIONS أدناه) — ليس حقلاً في قاعدة البيانات.
    • executive HTML/PDF يُلف بفئة report-rtl لدعم الاتجاه العربي.
    • WeasyPrint يُستورد كسولاً داخل export_pdf حتى تبقى باقي الصيغ صالحة
      في بيئات بلا مكتبات نظام.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select

from agents.llm_client import PROMPTS_DIR
from core.reports.stats import compute_scan_statistics
from db.connection import get_session
from db.models import (
    Application,
    Assessment,
    Scan,
    SeverityRule,
    Tool,
    Vulnerability,
    VulnerabilityFinding,
)

TEMPLATES_DIR = PROMPTS_DIR.parent / "templates"
_jinja = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(disabled_extensions=("j2",)),
)

# إرشادات إصلاح ثابتة لكل CWE (محتوى مشتق موثق — لا يُقرأ من القاعدة)
RECOMMENDATIONS: dict[str, str] = {
    "CWE-321": "Remove hardcoded credentials from the binary; load keys from Android Keystore or a remote KMS and rotate exposed keys immediately.",
    "CWE-327": "Replace broken/legacy algorithms (DES/3DES/MD5/SHA1) with AES-GCM-256 and SHA-256+ via a vetted crypto library (Tink/BouncyCastle).",
    "CWE-312": "Stop persisting secrets in plaintext (SharedPreferences/files); encrypt at rest using Android Keystore-backed keys.",
    "CWE-295": "Enforce proper certificate validation; do not override checkServerTrusted/HostnameVerifier; add certificate pinning.",
    "CWE-319": "Move all cleartext HTTP endpoints to HTTPS and set usesCleartextTraffic=false in the Network Security Config.",
    "CWE-287": "Implement proper authentication/session checks on the affected endpoint; never trust client-side auth flags.",
    "CWE-926": "Set android:exported=false for internal components or gate them with signature-level permissions.",
    "CWE-919": "Move business logic validation server-side; never rely on client-enforced rules.",
    "CWE-532": "Remove sensitive data from Log calls; strip logs in release builds with ProGuard/R8 rules.",
    "CWE-20": "Validate and sanitize all input from intents/extras/IPC boundaries before use.",
}
_DEFAULT_RECOMMENDATION = (
    "Review the finding against its MASVS category guidance and remediate "
    "according to OWASP MAS best practices."
)


class ReportGenerator:
    """مولّد تقارير فحص واحد (Technical EN + Executive AR)."""

    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id

    # ------------------------------------------------------------------
    # جمع البيانات / Data collection (DB only)
    # ------------------------------------------------------------------
    def collect_data(self) -> dict[str, Any]:
        """تجميع كل بيانات الفحص في بنية واحدة جاهزة للقوالب."""
        stats = compute_scan_statistics(self.scan_id)
        with get_session() as session:
            scan = session.get(Scan, self.scan_id)
            if scan is None:
                raise ValueError(f"scan غير موجود / scan_id={self.scan_id}")
            app = session.get(Application, scan.application_id)
            rule = session.scalar(select(SeverityRule).where(SeverityRule.active.is_(True)))

            vulns = session.scalars(
                select(Vulnerability).where(Vulnerability.application_id == app.id)
            ).all()
            tool_names = {
                t.id: t.name for t in session.scalars(select(Tool)).all()
            }
            report_vulns: list[dict[str, Any]] = []
            for vuln in vulns:
                assessment = session.scalar(
                    select(Assessment).where(Assessment.vulnerability_id == vuln.id)
                )
                findings = session.scalars(
                    select(VulnerabilityFinding).where(
                        VulnerabilityFinding.vulnerability_id == vuln.id
                    )
                ).all()
                discovered_by = sorted(
                    {tool_names.get(f.tool_id, f"tool#{f.tool_id}") for f in findings}
                )
                is_confirmed = any(f.evidence_type == "dynamic" for f in findings)
                evidence_text = "; ".join(
                    (f.location or "")[:180] for f in findings[:3] if f.location
                ) or (vuln.description or "—")[:240]

                report_vulns.append(
                    {
                        "id": vuln.id,
                        "title": vuln.title,
                        "masvs_category": vuln.masvs_category or "Unknown",
                        "cwe_id": vuln.cwe_id or "—",
                        "final_score": assessment.final_score if assessment else None,
                        "severity": assessment.severity if assessment else "Unscored",
                        "is_confirmed": is_confirmed,
                        "evidence": evidence_text,
                        "discovered_by": discovered_by,
                        "rationale": (assessment.rationale if assessment else "") or "",
                        "recommendation": RECOMMENDATIONS.get(
                            vuln.cwe_id or "", _DEFAULT_RECOMMENDATION
                        ),
                        "review_status": (assessment.review_status if assessment else "—"),
                    }
                )
            report_vulns.sort(
                key=lambda v: v["final_score"] if v["final_score"] is not None else -1.0,
                reverse=True,
            )
            scan_date = (
                scan.finished_at
                or scan.started_at
                or datetime.now(timezone.utc).replace(tzinfo=None)
            ).strftime("%Y-%m-%d %H:%M")
            application_meta = {
                "application_name": app.name,
                "package_name": app.package_name or "",
                "version": app.version or "",
            }
        return {
            "application": application_meta,
            "scan_date": scan_date,
            "scan_status": stats["status"],
            "rule_version": rule.version if rule else "v1.1",
            "stats": stats,
            "vulnerabilities": report_vulns,
        }

    # ------------------------------------------------------------------
    # التوليد / Rendering
    # ------------------------------------------------------------------
    def generate_technical_report(self, data: dict[str, Any] | None = None) -> dict[str, Any]:
        """يولّد التقرير الفني (EN) — يعيد {markdown, data}."""
        data = data or self.collect_data()
        stats, app = data["stats"], data["application"]
        markdown_text = _jinja.get_template("technical_report.md.j2").render(
            application_name=app["application_name"],
            package_name=app["package_name"],
            version=app["version"],
            scan_date=data["scan_date"],
            rule_version=data["rule_version"],
            total=stats["total"],
            critical_count=stats["by_severity"]["Critical"],
            high_count=stats["by_severity"]["High"],
            medium_count=stats["by_severity"]["Medium"],
            low_count=stats["by_severity"]["Low"],
            confirmed_dynamic=stats["confirmed_dynamic"],
            avg_final_score=stats["avg_final_score"],
            vulnerabilities=data["vulnerabilities"],
            tools_used=stats["tools_used"],
        )
        return {"markdown": markdown_text.strip() + "\n", "data": data}

    def generate_executive_report(
        self,
        summaries: list[dict[str, Any]],
        overall_risk: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """يولّد التقرير التنفيذي (AR) — يعيد {markdown, data}."""
        data = data or self.collect_data()
        stats, app = data["stats"], data["application"]
        markdown_text = _jinja.get_template("executive_report.md.j2").render(
            application_name=app["application_name"],
            scan_date=data["scan_date"],
            overall_risk=overall_risk,
            total=stats["total"],
            critical_count=stats["by_severity"]["Critical"],
            high_count=stats["by_severity"]["High"],
            critical_vulns=summaries,
        )
        return {"markdown": markdown_text.strip() + "\n", "data": data}

    # ------------------------------------------------------------------
    # التصدير / Export
    # ------------------------------------------------------------------
    @staticmethod
    def export_markdown(report_md: str, output_path: str | Path) -> str:
        """كتابة Markdown — يعيد المسار المطلق كنص."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report_md, encoding="utf-8")
        return str(path)

    @staticmethod
    def export_html(report_md: str, output_path: str | Path, rtl: bool = False) -> str:
        """Markdown → HTML مكتمل (styles مضمّنة + اتجاه حسب اللغة)."""
        import markdown as md_lib

        body = md_lib.markdown(report_md, extensions=["tables", "fenced_code"])
        css = (TEMPLATES_DIR / "report_styles.css").read_text(encoding="utf-8")
        direction_class = "report-rtl" if rtl else "report-ltr"
        lang = "ar" if rtl else "en"
        html = (
            f'<!DOCTYPE html><html lang="{lang}"><head><meta charset="utf-8">'
            f"<title>Security Report</title><style>{css}</style></head>"
            f'<body class="{direction_class}">{body}</body></html>'
        )
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
        return str(path)

    @staticmethod
    def export_pdf(html_path: str | Path, output_path: str | Path) -> str:
        """HTML → PDF عبر WeasyPrint (استيراد كسول — انظر الترويسة)."""
        from weasyprint import HTML

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        HTML(filename=str(html_path)).write_pdf(str(path))
        return str(path)

    def export_all(
        self,
        output_dir: str | Path,
        executive_summaries: list[dict[str, Any]] | None = None,
        overall_risk: str = "متوسط",
    ) -> dict[str, str]:
        """توليد كل الصيغ (6 ملفات) داخل output_dir وإرجاع خريطة المسارات."""
        output = Path(output_dir)
        data = self.collect_data()

        tech = self.generate_technical_report(data)
        execu = self.generate_executive_report(executive_summaries or [], overall_risk, data)

        paths: dict[str, str] = {}
        paths["technical_md"] = self.export_markdown(
            tech["markdown"], output / "technical_report.md"
        )
        paths["executive_md"] = self.export_markdown(
            execu["markdown"], output / "executive_report.md"
        )
        paths["technical_html"] = self.export_html(
            tech["markdown"], output / "technical_report.html", rtl=False
        )
        paths["executive_html"] = self.export_html(
            execu["markdown"], output / "executive_report.html", rtl=True
        )
        paths["technical_pdf"] = self.export_pdf(
            paths["technical_html"], output / "technical_report.pdf"
        )
        paths["executive_pdf"] = self.export_pdf(
            paths["executive_html"], output / "executive_report.pdf"
        )
        return paths
