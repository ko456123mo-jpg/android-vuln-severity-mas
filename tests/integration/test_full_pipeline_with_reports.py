"""اختبار تكامل المرحلة 5 — Pipeline الكامل مع التقارير + حلقة HITL.

المسار: orchestrator → tools → extractor → scorer → reviewer → **reporter** → finalize
ثم حلقة بشرية كاملة: pending → correction → corrections + feedback_examples.
"""
from __future__ import annotations

import os

os.environ["MCP_MOCK_MODE"] = "1"
os.environ["LLM_MOCK_MODE"] = "1"

import asyncio  # noqa: E402
import uuid  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from agents.graph import ainvoke_pipeline, build_scan_graph  # noqa: E402
from agents.state import ScanState  # noqa: E402
from core.feedback import CorrectionManager  # noqa: E402
from core.feedback.feedback_extractor import select_fewshot_examples  # noqa: E402
from db.connection import get_session  # noqa: E402
from db.models import AppContext, Correction, FeedbackExample  # noqa: E402
from db.repositories import (  # noqa: E402
    applications_repo,
    logs_repo,
    projects_repo,
    scans_repo,
)
from sqlalchemy import select  # noqa: E402


def _make_entities() -> dict:
    project = projects_repo.create(name=f"p5-{uuid.uuid4().hex[:6]}")
    app = applications_repo.create(
        project_id=project["id"],
        name="InsecureBank",
        sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        file_path="/data/apks/insecurebank.apk",
        package_name="com.insecurebank.app",
        version="2.1.0",
        app_category="banking",
    )
    with get_session() as session:
        session.add(
            AppContext(
                application_id=app["id"], data_sensitivity="HIGH", industry="banking",
                user_base_size="large", internet_facing=True, business_criticality="HIGH",
            )
        )
    scan = scans_repo.create_scan(application_id=app["id"])
    return {"project": project, "app": app, "scan": scan}


def _make_state(entities: dict) -> ScanState:
    return ScanState(
        scan_id=f"scan_{entities['scan']['id']:03d}_{uuid.uuid4().hex[:4]}",
        application_id=entities["app"]["id"],
        apk_path="/data/apks/insecurebank.apk",
        package_name="com.insecurebank.app",
        app_category="banking",
        db_scan_id=entities["scan"]["id"],
    )


async def _run_full_pipeline(state: ScanState, checkpoints: str) -> dict:
    """بناء الرسم داخل حلقة الأحداث — AsyncSqliteSaver يتطلب running loop."""
    graph = build_scan_graph(checkpoints_path=checkpoints)
    return await ainvoke_pipeline(graph, state)


class TestPipelineWithReports:
    def test_full_pipeline_generates_reports(self, tmp_path):
        entities = _make_entities()
        result = asyncio.run(
            _run_full_pipeline(_make_state(entities), str(tmp_path / "cp5.db"))
        )

        # ① الحالة النهائية — المرحلة 5 تكتمل دون أخطاء
        assert result["current_stage"] == "done"
        assert result["reports_generated"] is True
        assert len(result["assessments"]) == 9
        assert result["pending_reviews_count"] == 6  # كما حُسب يدوياً في المرحلة 4

        # ② ملفات التقارير الستة موجودة حقاً على القرص
        tech_md = Path(result["technical_report_path"])
        exec_md = Path(result["executive_report_path"])
        report_dir = tech_md.parent
        expected_files = {
            "technical_report.md", "technical_report.html", "technical_report.pdf",
            "executive_report.md", "executive_report.html", "executive_report.pdf",
        }
        assert {p.name for p in report_dir.iterdir()} == expected_files
        assert (report_dir / "technical_report.pdf").read_bytes().startswith(b"%PDF")
        assert (report_dir / "executive_report.pdf").stat().st_size > 2_000

        # ③ محتوى التقريرين
        tech = tech_md.read_text(encoding="utf-8")
        assert "# Technical Security Report — InsecureBank" in tech
        assert "Critical: 2 | High: 5 | Medium: 2 | Low: 0" in tech
        assert "| 9.3626" in tech or "9.3626" in tech  # قمة الجدول CWE-327
        executive = exec_md.read_text(encoding="utf-8")
        assert "# الملخص التنفيذي — InsecureBank" in executive
        assert "**مستوى الخطر العام**: حرج" in executive
        # mock يكتب سطراً تنفيذياً لكل Critical/High (7 ثغرات)
        assert executive.count("### ") == 7
        assert "CWE-" not in executive.split("## أهم الثغرات الحرجة")[1].split("## التوصيات")[0]

        # ④ تدقيق reporter في سجلات الوكلاء
        logs = logs_repo.list_by_scan(entities["scan"]["id"])
        names = {l["agent_name"] for l in logs}
        assert "reporter" in names
        assert any(
            l["agent_name"] == "reporter" and l["action"] == "llm_call" for l in logs
        )
        assert all(l["status"] == "success" for l in logs)

    def test_hitl_roundtrip(self, tmp_path):
        """فحص → pending → تصحيح بشري → corrections + feedback_examples."""
        entities = _make_entities()
        asyncio.run(
            _run_full_pipeline(_make_state(entities), str(tmp_path / "cp_hitl.db"))
        )
        manager = CorrectionManager()
        pending_before = manager.list_pending_reviews()
        stats_before = manager.get_review_queue_stats()
        assert stats_before["pending"] >= 6

        target = pending_before[0]  # الأعلى خطورة (CWE-327 في هذه البيانات)
        correction_id = manager.submit_correction(
            assessment_id=target["id"],
            reviewer_id=1,
            corrected_severity="Critical",
            corrected_score=9.5,
            reason="ثغرة التشفير الضعيف مؤكدة ديناميكياً وتمنح فك كامل للجلسات.",
        )
        assert correction_id >= 1

        # التقييم بعد التصحيح: معتمد + final_score محفوظ قيمة المحرك
        details = manager.get_assessment_details(target["id"])
        assert details["review_status"] == "approved"
        assert details["severity"] == "Critical"
        assert details["final_score"] == pytest.approx(target["final_score"])

        # سجل التصحيح و مثال Few-Shot في القاعدة
        with get_session() as session:
            correction = session.get(Correction, correction_id)
            assert correction.original_severity == target["severity"]
            example = session.scalar(
                select(FeedbackExample).where(
                    FeedbackExample.correction_id == correction_id
                )
            )
            assert example is not None
            assert example.prompt_payload["corrected_score"] == 9.5

        # القائمة تقلصت بواحد
        stats_after = manager.get_review_queue_stats()
        assert stats_after["pending"] == stats_before["pending"] - 1
        assert stats_after["feedback_examples_total"] >= 1

        # المثال قابل للاختيار لفئة الثغرة (CRYPTO هنا)
        examples = select_fewshot_examples("MASVS-CRYPTO", limit=5)
        assert any(
            e["prompt_payload"]["corrected_score"] == 9.5 for e in examples
        )
