"""ScorerAgent — وكيل التقييم: يحسب الأرقام عبر ScoringEngine فقط.

عقد صارم (موثق في docs/scoring_logic.md):
    ★ الأرقام (base/context/confidence/evidence/final/severity) تصدر حصراً من
      ScoringEngine الحتمي — الـ LLM يولّد النص التفسيري (reasoning) فقط،
      ولا تُخزَّن أي قيمة رقمية منه أبداً.
    ★ القاعدة النشطة تُقرأ من severity_rules (active=1) — لا أوزان مخترعة.
    ★ سياق التطبيق من جدول app_context (وإلا DEFAULT_APP_CONTEXT).
    ★ موثوقية الأدوات من عمود tools.reliability_score.
    ★ كل تقييم يُسجَّل في agent_logs (التدقيق الإجباري عبر BaseAgent).
"""
from __future__ import annotations

import json
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select

from agents.base_agent import BaseAgent
from agents.llm_client import PROMPTS_DIR
from agents.state import ScanState
from core.guardrails.output_validator import ScorerOutput
from core.performance.caching import cached
from core.scoring.base_score import DEFAULT_MASVS_WEIGHTS
from core.scoring.context_score import DEFAULT_APP_CONTEXT
from core.scoring.engine import ScoringEngine
from db.connection import get_session
from db.models import AppContext, SeverityRule, Tool

_jinja = Environment(
    loader=FileSystemLoader(PROMPTS_DIR), autoescape=select_autoescape(disabled_extensions=("j2",))
)

@cached(ttl=300)
def load_active_rule_cached() -> dict[str, Any]:
    """قراءة قاعدة severity_rule النشطة (TTL=300s)؛ والاحتياطي v1.1 المدمجة."""
    try:
        with get_session() as session:
            rule = session.scalar(select(SeverityRule).where(SeverityRule.active.is_(True)))
            if rule is not None:
                return {
                    "version": rule.version,
                    "weights": rule.weights or {},
                    "context_params": rule.context_params or {},
                    "thresholds": rule.thresholds or {},
                    "masvs_weights": (rule.context_params or {}).get(
                        "masvs_weights", DEFAULT_MASVS_WEIGHTS
                    ),
                }
    except Exception:
        pass
    # fallback (قواعد v1.1 مدمجة — تُستخدم في بيئات بلا قاعدة)
    return {
        "version": "v1.1-fallback",
        "weights": {"base": 0.6, "context": 0.2, "evidence": 0.2},
        "context_params": {},
        "thresholds": {"critical": 9.0, "high": 7.0, "medium": 4.0},
        "masvs_weights": DEFAULT_MASVS_WEIGHTS,
    }


# خريطة احتياطية لموثوقية الأدوات عند غياب الصف في جدول tools
_FALLBACK_TOOL_RELIABILITY: dict[str, float] = {
    "jadx": 0.85,
    "mobsf": 0.80,
    "frida": 0.90,
    "objection": 0.75,
}


class ScorerAgent(BaseAgent):
    """يقيّم كل ثغرة في state.vulnerabilities ويضيف state.assessments."""

    def __init__(self, llm: Any = None, **kwargs: Any) -> None:
        super().__init__(name="scorer", llm=llm, **kwargs)

    # ------------------------------------------------------------------
    # المنطق الرئيسي / Main logic
    # ------------------------------------------------------------------
    async def run(self, state: ScanState) -> dict[str, Any]:
        rule = self._load_active_rule()
        engine = ScoringEngine(rule)
        app_context = self._load_app_context(state.application_id)
        reliabilities = self._load_tool_reliabilities()

        assessments: list[dict[str, Any]] = []
        errors: list[str] = []
        scan_db_id = state.db_scan_id

        for vuln in state.vulnerabilities:
            fp = vuln.get("dedup_fingerprint") or ""
            try:
                result = engine.score(vuln, app_context, reliabilities)
            except Exception as exc:  # لا نسقط الفحص كله بسبب ثغرة واحدة
                errors.append(f"scoring failed for {fp[:12]}: {exc}")
                continue

            # الـ LLM يولّد الشرح فقط — الأرقام كلها من المحرك (authoritative)
            # Few-Shot (المرحلة 7): أمثلة من تصحيحات بشرية سابقة لنفس فئة MASVS
            fewshot_examples = self._fewshot_block(vuln.get("masvs_category"), state)
            reasoning = await self._llm_reasoning(
                vuln=vuln,
                engine_result=result,
                app_context=app_context,
                rule=rule,
                reliabilities=reliabilities,
                scan_id=scan_db_id,
                fewshot_examples=fewshot_examples,
            )

            assessments.append(
                {
                    "dedup_fingerprint": fp,
                    "vulnerability_title": vuln.get("title", ""),
                    "masvs_category": vuln.get("masvs_category"),
                    "cwe_id": vuln.get("cwe_id"),
                    "rule_version": rule.get("version", "v1.1"),
                    "base_score": result["base_score"],
                    "context_score": result["context_score"],
                    "evidence_score": result["evidence_score"],
                    "confidence_factor": result["confidence_factor"],
                    "confidence_breakdown": result["confidence_breakdown"],
                    "final_score": result["final_score"],
                    "severity": result["severity"],
                    "rationale": result["rationale"],
                    "reasoning": reasoning,
                    "app_context_used": app_context,
                    "assessed_by": "agent",
                }
            )

        return {
            "assessments": assessments,
            "current_stage": "scoring",
            "errors": list(state.errors) + errors if errors else state.errors,
        }

    # ------------------------------------------------------------------
    # توليد الشرح بواسطة LLM / LLM-authored reasoning (numbers locked)
    # ------------------------------------------------------------------
    async def _llm_reasoning(
        self,
        vuln: dict[str, Any],
        engine_result: dict[str, Any],
        app_context: dict[str, Any],
        rule: dict[str, Any],
        reliabilities: dict[str, float],
        scan_id: int | None,
        fewshot_examples: str = "(لا أمثلة)",
    ) -> str:
        """برومبت scorer.j2 + التحقق — أرقام المحرك تُغرس في <engine_result>.

        حتى لو خالف الـ LLM المخطط أو اخترع أرقاماً، لن تُستخدم إطلاقاً:
        نأخذ فقط حقل reasoning المفصول، ونتحقق منه عبر ScorerOutput لضمان
        صحة الشكل (لا المصدر الرقمي).
        """
        prompt = _jinja.get_template("scorer.j2").render(
            fewshot_examples=fewshot_examples,
            vulnerability_json=json.dumps(vuln, ensure_ascii=False, indent=2)[:3000],
            app_context_json=json.dumps(app_context, ensure_ascii=False),
            severity_rule_json=json.dumps(
                {"version": rule.get("version"), "weights": rule.get("weights"),
                 "thresholds": rule.get("thresholds")},
                ensure_ascii=False,
            ),
            tool_reliabilities_json=json.dumps(reliabilities, ensure_ascii=False),
            engine_result_json=json.dumps(engine_result, ensure_ascii=False, indent=2),
        )
        try:
            output = await self.call_llm_structured(
                prompt, ScorerOutput, scan_id=scan_id, max_retries=1
            )
            return output.reasoning or engine_result["rationale"]
        except Exception:
            # سقوط آمن: الشرح الحتمي للمحرك دائماً صالح للتدقيق
            return engine_result["rationale"]

    # ------------------------------------------------------------------
    # Few-Shot (المرحلة 7) / من تصحيحات HITL السابقة
    # ------------------------------------------------------------------
    @staticmethod
    def _fewshot_block(masvs_category: str | None, state: ScanState) -> str:
        """كتلة أمثلة Few-Shot من feedback_examples لنفس فئة MASVS.

        المصدر حصرياً محلات الحلقة البشرية (select_fewshot_examples — المرحلة 5):
        لم تُسجَّل تصحيحات بعد في فئة ما ⇒ كتلة صريحة فارغة (لا اختلاق أمثلة).
        disable_feedback=True (وضع التجربة) ⇒ تجاوز كامل.
        """
        if getattr(state, "disable_feedback", False) or not masvs_category:
            return "(لا أمثلة Few-Shot — الوضع التجريبي بلا تغذية راجعة)"
        try:
            from core.feedback.feedback_extractor import select_fewshot_examples

            examples = select_fewshot_examples(masvs_category, limit=5)
        except Exception:
            examples = []
        if not examples:
            return "(لا أمثلة بعد — لم تُسجَّل تصحيحات بشرية لهذه الفئة)"
        lines: list[str] = []
        for index, example in enumerate(examples, 1):
            payload = example.get("prompt_payload") or {}
            lines.append(
                f"مثال {index}: {payload.get('vuln_pattern', '—')} → "
                f"{payload.get('corrected_severity', '—')} "
                f"(السبب: {payload.get('reason', '—')})"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # محمّلات البيانات / Data loaders
    # ------------------------------------------------------------------
    @staticmethod
    def _load_active_rule() -> dict[str, Any]:
        """قراءة قاعدة severity_rule النشطة — عبر تخزين مؤقت TTL=300 (المرحلة 8).

        القاعدة تتغير يدوياً مرة كل إصدار؛ إعادة قراءتها لكل ثغرة كانت تكلفة
        قاعدة بيانات بلا داعٍ. أي تغيير إداري يُفرَّغ بـ
        ``load_active_rule_cached.cache_clear()`` (وتُصفَّر تلقائياً بعد 300 ثانية).
        """
        return load_active_rule_cached()

    @staticmethod
    def _load_app_context(application_id: int) -> dict[str, Any]:
        """قراءة سياق التطبيق؛ غياب السجل ⇒ DEFAULT_APP_CONTEXT."""
        try:
            with get_session() as session:
                ctx = session.scalar(
                    select(AppContext).where(AppContext.application_id == application_id)
                )
                if ctx is None:
                    return dict(DEFAULT_APP_CONTEXT)
                return {
                    "data_sensitivity": ctx.data_sensitivity or "MEDIUM",
                    "industry": ctx.industry or "utility",
                    "user_base_size": ctx.user_base_size or "medium",
                    "internet_facing": bool(ctx.internet_facing)
                    if ctx.internet_facing is not None
                    else True,
                    "business_criticality": ctx.business_criticality or "MEDIUM",
                }
        except Exception:
            return dict(DEFAULT_APP_CONTEXT)

    @staticmethod
    def _load_tool_reliabilities() -> dict[str, float]:
        """موثوقية الأدوات من جدول tools؛ الاحتياطي لكل أداة معروفة."""
        reliabilities = dict(_FALLBACK_TOOL_RELIABILITY)
        try:
            with get_session() as session:
                tools = session.scalars(select(Tool)).all()
                for tool in tools:
                    if tool.reliability_score is not None:
                        reliabilities[tool.name] = float(tool.reliability_score)
        except Exception:
            pass
        return reliabilities
