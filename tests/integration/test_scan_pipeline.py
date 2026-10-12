"""اختبار تكامل pipeline الفحص — Mock IPC + Mock LLM + قاعدة اختبار معزولة.

يغطي (شامل وstatic):
    1. إنشاء project + application + scan في قاعدة الاختبار
    2. تشغيل المخطط الكامل مع checkpointing (SqliteSaver بملف مؤقت)
    3. التحقق من state النهائية (stage/tools/vulnerabilities)
    4. التحقق من القاعدة: vulnerabilities(9) + findings(17) + scans(success) + logs
    5. idempotency: إعادة الفحص لا تضاعف vulnerabilities (dedup بالبصمة)
"""
from __future__ import annotations

import os

os.environ["MCP_MOCK_MODE"] = "1"
os.environ["LLM_MOCK_MODE"] = "1"

import asyncio  # noqa: E402
import uuid  # noqa: E402

import pytest  # noqa: E402

from agents.graph import ainvoke_pipeline, build_scan_graph  # noqa: E402
from agents.state import ScanState  # noqa: E402
from db.repositories import (  # noqa: E402
    applications_repo,
    findings_repo,
    logs_repo,
    projects_repo,
    scans_repo,
)

EXPECTED_COMPREHENSIVE = {
    "vulns": 9,      # 8 MASVS + CWE-319 (dedup: 4 jadx↔mobsf، frida↔mobsf 327)
    "findings": 17,  # 8 mobsf + 4 jadx + 2 frida + 3 objection
    "tools": {"jadx", "mobsf", "frida", "objection"},
}
EXPECTED_STATIC = {"vulns": 8, "findings": 12, "tools": {"jadx", "mobsf"}}


# =====================================================================
# تركيب الكيانات / Setup entities
# =====================================================================
def _make_entities() -> dict:
    """مشروع + تطبيق + فحص جديدان في قاعدة الاختبار المعزولة."""
    project = projects_repo.create(name=f"pipeline-{uuid.uuid4().hex[:6]}")
    app = applications_repo.create(
        project_id=project["id"],
        name="InsecureBank",
        sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        file_path="/data/apks/insecurebank.apk",
        package_name="com.insecurebank.app",
        version="2.1.0",
        app_category="banking",
    )
    scan = scans_repo.create_scan(application_id=app["id"])
    return {"project": project, "app": app, "scan": scan}


def _make_state(entities: dict, user_request: str = "") -> ScanState:
    return ScanState(
        scan_id=f"scan_{entities['scan']['id']:03d}_{uuid.uuid4().hex[:4]}",
        application_id=entities["app"]["id"],
        apk_path="/data/apks/insecurebank.apk",
        package_name="com.insecurebank.app",
        app_category="banking",
        user_request=user_request,
        db_scan_id=entities["scan"]["id"],
    )


async def _run_pipeline(state: ScanState, checkpoints: str) -> dict:
    graph = build_scan_graph(checkpoints_path=checkpoints)
    return await ainvoke_pipeline(graph, state)


# =====================================================================
# الاختبار الشامل / Comprehensive pipeline
# =====================================================================
class TestComprehensivePipeline:
    def test_full_pipeline_end_to_end(self, tmp_path):
        entities = _make_entities()
        state = _make_state(entities)
        result = asyncio.run(_run_pipeline(state, str(tmp_path / "cp.db")))

        # 1) الحالة النهائية / Final state
        assert result["current_stage"] == "done"
        assert set(result["tools_executed"]) == EXPECTED_COMPREHENSIVE["tools"]
        assert result["scan_type"] == "comprehensive"
        assert result["finished_at"] is not None

        # 2) الثغرات بعد الدمج / Deduped vulnerabilities
        assert len(result["vulnerabilities"]) == EXPECTED_COMPREHENSIVE["vulns"]
        fps = [v["dedup_fingerprint"] for v in result["vulnerabilities"]]
        assert len(set(fps)) == len(fps)

        # تأكيد متعدد الأدوات / multi-tool confirmations
        weak_crypto = next(v for v in result["vulnerabilities"] if v["cwe_id"] == "CWE-327")
        assert sorted(weak_crypto["discovered_by"]) == ["frida", "jadx", "mobsf"]
        assert weak_crypto["is_confirmed"] is True

        # 3) قاعدة البيانات / DB persistence
        app_id = entities["app"]["id"]
        stored = findings_repo.list_vulns_by_app(app_id)
        assert len(stored) == EXPECTED_COMPREHENSIVE["vulns"]

        findings = findings_repo.list_by_scan(entities["scan"]["id"])
        assert len(findings) == EXPECTED_COMPREHENSIVE["findings"]
        assert {f["evidence_type"] for f in findings} == {"static", "dynamic"}

        scan_row = scans_repo.get_by_id(entities["scan"]["id"])
        assert scan_row["status"] == "success"
        assert set(scan_row["tools_used"]) == EXPECTED_COMPREHENSIVE["tools"]
        assert scan_row["total_duration_ms"] >= 0

        # 4) تدقيق الوكلاء / Agent audit logs
        logs = logs_repo.list_by_scan(entities["scan"]["id"])
        assert len(logs) > 0
        assert {l["agent_name"] for l in logs} >= {"orchestrator", "extractor"}
        assert any(l["action"] == "llm_call" for l in logs)
        assert all(l["status"] == "success" for l in logs)

    def test_rerun_is_idempotent_at_vulnerability_level(self, tmp_path):
        """فحص ثانٍ على نفس التطبيق لا يضاعف vulnerabilities (بصمة UNIQUE)."""
        entities = _make_entities()
        app_id = entities["app"]["id"]
        state1 = _make_state(entities)
        asyncio.run(_run_pipeline(state1, str(tmp_path / "cp1.db")))

        scan2 = scans_repo.create_scan(application_id=app_id)
        state2 = _make_state({**entities, "scan": scan2})
        result2 = asyncio.run(_run_pipeline(state2, str(tmp_path / "cp2.db")))

        assert result2["current_stage"] == "done"
        assert len(findings_repo.list_vulns_by_app(app_id)) == EXPECTED_COMPREHENSIVE["vulns"]
        # لكن الأدلة تتراكم لكل فحص / findings accumulate per scan
        assert len(findings_repo.list_by_scan(scan2["id"])) == EXPECTED_COMPREHENSIVE["findings"]


# =====================================================================
# فحص ساكن فقط / Static-only pipeline
# =====================================================================
class TestStaticOnlyPipeline:
    def test_static_pipeline_skips_dynamic(self, tmp_path):
        entities = _make_entities()
        state = _make_state(entities, user_request="فحص ساكن فقط — بدون تشغيل")
        result = asyncio.run(_run_pipeline(state, str(tmp_path / "cp.db")))

        assert result["current_stage"] == "done"
        assert result["scan_type"] == "static"
        assert set(result["tools_executed"]) == EXPECTED_STATIC["tools"]
        assert len(result["vulnerabilities"]) == EXPECTED_STATIC["vulns"]
        findings = findings_repo.list_by_scan(entities["scan"]["id"])
        assert len(findings) == EXPECTED_STATIC["findings"]
        assert {f["evidence_type"] for f in findings} == {"static"}
