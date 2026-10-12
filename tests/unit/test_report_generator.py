"""اختبارات وحدة محرك التقارير — core/reports (المرحلة 5).

يجهّز فحصاً Mock كاملاً عبر المستودعات (بلا pipeline) ثم يتحقق من:
    • الإحصائيات الحتمية (compute_scan_statistics)
    • التقرير الفني: الجدول مرتب بـ final_score تنازلياً + كل الحقول
    • التنفيذي: RTL + ملخصات عربية + بلا أي ذكر لـ CWE/MASVS في الملخصات
    • التصدير: markdown + html + pdf (WeasyPrint) مع مضمون صالح
"""
from __future__ import annotations

import uuid

import pytest

from core.reports.generator import RECOMMENDATIONS, ReportGenerator
from core.reports.stats import compute_scan_statistics
from db.repositories import (
    applications_repo,
    assessments_repo,
    findings_repo,
    projects_repo,
    scans_repo,
)
from db.connection import get_session
from db.models import Tool, Vulnerability
from sqlalchemy import select


def _make_fixture_scan() -> dict:
    """تطبيق + 3 ثغرات بتقييمات (C/H/M) + أدلة findings لفحص واحد."""
    project = projects_repo.create(name=f"report-{uuid.uuid4().hex[:6]}")
    app = applications_repo.create(
        project_id=project["id"],
        name="FixtureBank",
        sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        file_path="/data/apks/fixture.apk",
        package_name="com.fixture.bank",
        version="1.0.0",
    )
    scan = scans_repo.create_scan(application_id=app["id"])
    scans_repo.update_tools_used(scan["id"], ["mobsf", "frida"])

    with get_session() as session:
        tools = {t.name: t.id for t in session.scalars(select(Tool)).all()}

    cases = [
        # (cwe, masvs, score, severity, dynamic?)
        ("CWE-321", "MASVS-CRYPTO", 9.1, "Critical", False),
        ("CWE-312", "MASVS-STORAGE", 8.2, "High", True),
        ("CWE-532", "MASVS-CODE", 5.0, "Medium", False),
    ]
    created = []
    for index, (cwe, masvs, score, severity, dynamic) in enumerate(cases):
        record = findings_repo.create_vulnerability(
            application_id=app["id"],
            title=f"Fixture {cwe} issue",
            description="fixture",
            masvs_category=masvs,
            cwe_id=cwe,
            dedup_fingerprint=f"fixture-{uuid.uuid4().hex[:12]}",
        )
        assessments_repo.upsert_by_vuln(
            vulnerability_id=record["id"],
            base_score=7.0,
            context_score=10.0,
            evidence_score=8.0,
            confidence_factor=0.8,
            final_score=score,
            severity=severity,
            rationale=f"1) base=7 ... 5) final={score} → {severity}.",
            rule_version="v1.1",
            assessed_by="agent",
        )
        with get_session() as session:
            vuln_pk = session.scalar(
                select(Vulnerability.id).where(Vulnerability.dedup_fingerprint == record["dedup_fingerprint"])
            )
        findings_repo.create_finding(
            vulnerability_id=vuln_pk,
            scan_id=scan["id"],
            tool_id=tools["frida" if dynamic else "mobsf"],
            location=f"src/com/fixture/File{index}.java:{(index+1)*10}",
            evidence_type="dynamic" if dynamic else "static",
        )
        created.append({"cwe": cwe, "severity": severity, "vuln_id": vuln_pk})
    return {"app": app, "scan": scan, "cases": created}


class TestScanStatistics:
    def test_statistics_exact(self):
        fixture = _make_fixture_scan()
        stats = compute_scan_statistics(fixture["scan"]["id"])
        assert stats["total"] == 3
        assert stats["by_severity"] == {"Critical": 1, "High": 1, "Medium": 1, "Low": 0}
        assert stats["by_masvs"] == {
            "MASVS-CRYPTO": 1, "MASVS-STORAGE": 1, "MASVS-CODE": 1
        }
        assert stats["confirmed_dynamic"] == 1
        assert stats["max_final_score"] == 9.1
        assert stats["min_final_score"] == 5.0
        assert stats["tools_used"] == ["mobsf", "frida"]
        assert stats["tool_counts"] == {"mobsf": 2, "frida": 1}
        assert stats["total_findings"] == 3

    def test_unknown_scan_raises(self):
        with pytest.raises(ValueError):
            compute_scan_statistics(999_999_999)


class TestTechnicalReport:
    def test_content_and_ordering(self):
        fixture = _make_fixture_scan()
        report = ReportGenerator(fixture["scan"]["id"]).generate_technical_report()
        md = report["markdown"]
        assert "# Technical Security Report — FixtureBank" in md
        assert "**Package**: com.fixture.bank" in md
        assert "Critical: 1 | High: 1 | Medium: 1 | Low: 0" in md
        # ترتيب تنازلي بالدرجة: 9.1 ثم 8.2 ثم 5.0 (صفوف جدول الثغرات تحديداً)
        rows = [l for l in md.splitlines() if l.startswith("| ") and " | CWE-" in l]
        assert len(rows) == 3
        assert "| 9.1 |" in rows[0] and "| 8.2 |" in rows[1] and "| 5.0 |" in rows[2]
        # الأدلة والتوصيات موجودة
        assert "**Evidence**: src/com/fixture/File" in md
        assert "Android Keystore" in md  # توصية CWE-321 الثابتة
        assert "## Tools Used" in md and "- mobsf" in md and "- frida" in md

    def test_recommendation_map_complete_for_fixture(self):
        for cwe in ("CWE-321", "CWE-312", "CWE-532"):
            assert RECOMMENDATIONS[cwe].strip()


class TestExecutiveReport:
    def test_arabic_summary_rendering(self):
        fixture = _make_fixture_scan()
        generator = ReportGenerator(fixture["scan"]["id"])
        summaries = [
            {
                "vulnerability_id": fixture["cases"][0]["vuln_id"],
                "title_ar": "مفتاح تشفير مكشوف داخل التطبيق",
                "impact_ar": "قد يسمح بالوصول غير المصرّح لبيانات العملاء.",
                "action_ar": "سحب المفتاح فوراً وتدويره.",
                "timeline_ar": "24-48 ساعة",
            }
        ]
        report = generator.generate_executive_report(summaries, "حرج")
        md = report["markdown"]
        assert "# الملخص التنفيذي — FixtureBank" in md
        assert "**مستوى الخطر العام**: حرج" in md
        assert "منها 1 حرجة و 1 عالية الخطورة" in md
        assert "مفتاح تشفير مكشوف داخل التطبيق" in md
        assert "24-48 ساعة" in md

    def test_no_technical_tokens_in_summary(self):
        """القاعدة: الملخص التنفيذي لا يذكر CWE/MASVS (فحص المحتوى العربي المُدخل)."""
        fixture = _make_fixture_scan()
        generator = ReportGenerator(fixture["scan"]["id"])
        bad_summary = [
            {"vulnerability_id": fixture["cases"][0]["vuln_id"],
             "title_ar": "ثغرة في التشفير", "impact_ar": "تأثير", "action_ar": "إجراء",
             "timeline_ar": "أسبوع"}
        ]
        md = generator.generate_executive_report(bad_summary, "حرج")["markdown"]
        executive_section = md.split("## أهم الثغرات الحرجة")[1].split("## التوصيات")[0]
        assert "CWE" not in executive_section and "MASVS" not in executive_section


class TestExports:
    def test_markdown_html_pdf_pipeline(self, tmp_path):
        fixture = _make_fixture_scan()
        generator = ReportGenerator(fixture["scan"]["id"])
        out = tmp_path / str(fixture["scan"]["id"])

        tech = generator.generate_technical_report()
        md_path = generator.export_markdown(tech["markdown"], out / "technical_report.md")
        html_path = generator.export_html(tech["markdown"], out / "technical_report.html")
        pdf_path = generator.export_pdf(html_path, out / "technical_report.pdf")

        from pathlib import Path

        assert Path(md_path).read_text(encoding="utf-8").startswith("# Technical")
        html_text = Path(html_path).read_text(encoding="utf-8")
        assert "report-ltr" in html_text and "<table>" in html_text
        pdf_bytes = Path(pdf_path).read_bytes()
        assert pdf_bytes.startswith(b"%PDF") and len(pdf_bytes) > 2_000

    def test_executive_html_rtl(self, tmp_path):
        fixture = _make_fixture_scan()
        generator = ReportGenerator(fixture["scan"]["id"])
        report = generator.generate_executive_report([], "متوسط")
        html_path = generator.export_html(
            report["markdown"], tmp_path / "executive_report.html", rtl=True
        )
        from pathlib import Path

        html_text = Path(html_path).read_text(encoding="utf-8")
        assert "report-rtl" in html_text and 'lang="ar"' in html_text

    def test_export_all_six_files(self, tmp_path):
        fixture = _make_fixture_scan()
        paths = ReportGenerator(fixture["scan"]["id"]).export_all(
            tmp_path, executive_summaries=[], overall_risk="حرج"
        )
        from pathlib import Path

        assert set(paths) == {
            "technical_md", "executive_md", "technical_html",
            "executive_html", "technical_pdf", "executive_pdf",
        }
        for path in paths.values():
            assert Path(path).exists() and Path(path).stat().st_size > 100
