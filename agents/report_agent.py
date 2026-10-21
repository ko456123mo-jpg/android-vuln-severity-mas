"""ReporterAgent — وكيل التقارير (المرحلة 5).

التدفق / Flow:
    ① ReportGenerator(scan_id) يجمع تقييمات الفحص من القاعدة
    ② LLM يكتب الملخصات التنفيذية العربية للثغرات Critical/High فقط
       (بديل حتمي عند تعذّر LLM — عناوين ومؤثرات مشتقة من قاعدة البيانات)
    ③ توليد Technical (EN) + Executive (AR) بثلاث صيغ MD/HTML/PDF
       داخل data/reports/<scan_id>/

عقود صارمة: لا أرقام جديدة — كل الأرقام من assessments؛ الملخصات لا تذكر
CWE/MASVS؛ أي فشل في إنتاج PDF تُسجَّل بقية الصيغ بدلاً من إسقاط الفحص.
"""
from __future__ import annotations

import json
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agents.base_agent import BaseAgent
from agents.llm_client import PROMPTS_DIR
from agents.state import ScanState
from core.guardrails.output_validator import ReportOutput
from core.reports.generator import ReportGenerator
from mcp_servers.common import PROJECT_ROOT

_jinja = Environment(
    loader=FileSystemLoader(PROMPTS_DIR), autoescape=select_autoescape(disabled_extensions=("j2",))
)


class ReporterAgent(BaseAgent):
    """يولّد تقارير الفحص ويحدّث state بمساراتها."""

    def __init__(self, llm: Any = None, **kwargs: Any) -> None:
        super().__init__(name="reporter", llm=llm, **kwargs)

    # ------------------------------------------------------------------
    async def run(self, state: ScanState) -> dict[str, Any]:
        if state.db_scan_id is None:
            # فحص بلا سجل DB (اختبارات عقدية) — لا تقارير
            return {"current_stage": "report", "reports_generated": False}

        generator = ReportGenerator(state.db_scan_id)
        try:
            data = generator.collect_data()
            critical_high = [
                v
                for v in data["vulnerabilities"]
                if v["severity"] in ("Critical", "High")
            ]
            summaries, overall_risk = await self._executive_summaries(
                critical_high, scan_id=state.db_scan_id
            )

            reports_dir = PROJECT_ROOT / "data" / "reports" / str(state.db_scan_id)
            paths = generator.export_all(
                reports_dir, executive_summaries=summaries, overall_risk=overall_risk
            )
            stats = data["stats"]
            return {
                "current_stage": "report",
                "reports_generated": True,
                "technical_report_path": paths["technical_md"],
                "executive_report_path": paths["executive_md"],
                "pending_reviews_count": stats["pending_reviews"],
            }
        except Exception as exc:
            # فشل إنتاج تقرير لا يجب أن يسقط الفحص — يُسجَّل ويُعتم جزئياً
            self.log_action(
                action="report_generation_failed",
                details={"reasoning": str(exc)[:400]},
                tokens_in=0,
                tokens_out=0,
                duration_ms=0,
                status="failed",
                scan_id=state.db_scan_id,
            )
            return {
                "current_stage": "report",
                "reports_generated": False,
                "errors": list(state.errors) + [f"report generation failed: {exc}"],
            }

    # ------------------------------------------------------------------
    # الملخصات التنفيذية / Executive summaries
    # ------------------------------------------------------------------
    async def _executive_summaries(
        self, critical_high: list[dict[str, Any]], scan_id: int | None
    ) -> tuple[list[dict[str, Any]], str]:
        """ملخصات LLM مع بديل حتمي — يعيد (summaries, overall_risk)."""
        if not critical_high:
            return [], "منخفض"

        vulns_payload = [
            {
                "vulnerability_id": v["id"],
                "title": v["title"],
                "final_score": v["final_score"],
                "severity": v["severity"],
                "dynamically_confirmed": v["is_confirmed"],
            }
            for v in critical_high
        ]
        prompt = _jinja.get_template("report_agent.j2").render(
            critical_high_vulns_json=json.dumps(vulns_payload, ensure_ascii=False, indent=2)
        )
        try:
            output = await self.call_llm_structured(
                prompt, ReportOutput, scan_id=scan_id, max_retries=1
            )
            # سلامة: لا نثق إلا بمعرفات الثغرات التي أرسلناها فعلاً
            valid_ids = {v["vulnerability_id"] for v in vulns_payload}
            summaries = [
                s.model_dump()
                for s in output.executive_summaries
                if s.vulnerability_id in valid_ids
            ]
            if summaries:
                return summaries, output.overall_risk
        except Exception:
            pass
        return self._deterministic_summaries(critical_high)

    @staticmethod
    def _deterministic_summaries(
        critical_high: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], str]:
        """بديل حتمي — يفوَّض إلى المولّد حتى يتشارك المساران نفس القاعدة."""
        return (
            ReportGenerator.deterministic_summaries(critical_high),
            ReportGenerator.overall_risk_from(critical_high),
        )
