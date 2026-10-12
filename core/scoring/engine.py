"""engine.py — محرك التقييم الموحّد / ScoringEngine.

final_score = (base × w_base) + (context × w_context) + (evidence × w_evidence)
الأوزان من severity_rules.weights (v1.x: 0.6/0.2/0.2) — لا قيم مخترعة.

ScoringEngine حتمي بالكامل (deterministic): نفس المدخلات ⇒ نفس المخرجات.
الـ LLM يُستخدم لتوليد الشرح (reasoning) فقط — أبداً للأرقام.
"""
from __future__ import annotations

from typing import Any

from core.scoring.bands import classify_severity
from core.scoring.base_score import calculate_base_score
from core.scoring.confidence import (
    assess_evidence_quality,
    assess_reproducibility,
    calculate_confidence_factor,
)
from core.scoring.context_score import calculate_context_score
from core.scoring.evidence_score import calculate_evidence_score


class ScoringEngine:
    """محرك حساب التقييم الكامل لثغرة واحدة."""

    def __init__(self, rule: dict[str, Any]) -> None:
        self.rule = rule or {}
        weights = (self.rule.get("weights") or {}) if isinstance(self.rule, dict) else {}
        self.w_base = float(weights.get("base", 0.6))
        self.w_context = float(weights.get("context", 0.2))
        self.w_evidence = float(weights.get("evidence", 0.2))

    # ------------------------------------------------------------------
    def score(
        self,
        vulnerability: dict[str, Any],
        app_context: dict[str, Any] | None = None,
        tool_reliabilities: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        """حساب التقييم الكامل — يعيد كل المكونات + rationale حتمي."""
        base = calculate_base_score(
            vulnerability.get("masvs_category"),
            vulnerability.get("sub_category", ""),
            self.rule,
        )
        context = calculate_context_score(app_context, self.rule.get("context_params"))

        tools = vulnerability.get("discovered_by") or []
        reliabilities = tool_reliabilities or {}
        reliability_avg = (
            sum(float(reliabilities.get(t, 0.5)) for t in tools) / len(tools) if tools else 0.0
        )
        quality_label = assess_evidence_quality(vulnerability)
        repro_label = assess_reproducibility(vulnerability)
        confidence = calculate_confidence_factor(
            tool_count=len(tools),
            evidence_quality=quality_label,
            tool_reliability_avg=reliability_avg,
            reproducibility=repro_label,
        )
        evidence = calculate_evidence_score(confidence)

        final = round(
            base * self.w_base + context * self.w_context + evidence * self.w_evidence, 4
        )
        severity = classify_severity(final)

        breakdown = {
            "tool_count_score": round(
                (0.0 if len(tools) == 0 else 0.4 if len(tools) == 1 else 0.7 if len(tools) == 2 else 1.0), 4
            ),
            "evidence_quality_score": quality_label,
            "tool_reliability_avg": round(reliability_avg, 4),
            "reproducibility_score": repro_label,
        }
        rationale = self._build_rationale(
            vulnerability=vulnerability,
            base=base,
            context=context,
            evidence=evidence,
            confidence=confidence,
            breakdown=breakdown,
            final=final,
            severity=severity,
        )
        return {
            "base_score": round(base, 4),
            "context_score": round(context, 4),
            "evidence_score": round(evidence, 4),
            "confidence_factor": round(confidence, 4),
            "confidence_breakdown": breakdown,
            "final_score": final,
            "severity": severity,
            "rationale": rationale,
        }

    # ------------------------------------------------------------------
    def _build_rationale(self, **kw: Any) -> str:
        """شرح حتمي قابل للتدقيق لكل خطوة في المعادلة (بأرقام المحرك نفسها)."""
        vuln = kw["vulnerability"]
        b = kw["breakdown"]
        tools = vuln.get("discovered_by") or []
        lines = [
            f"الثغرة: {vuln.get('title', '؟')} [{vuln.get('masvs_category', '?')} / {vuln.get('cwe_id', '?')}]",
            f"1) base_score = {kw['base']:.2f} ← وزن الفئة "
            f"{vuln.get('masvs_category', '?')} من جدول MASVS (severity_rules).",
            f"2) context_score = {kw['context']:.2f} ← 5.0 + معاملات سياق التطبيق الموزونة (0.4/0.2/0.2/0.2).",
            f"3) confidence = {kw['confidence']:.2f} ← "
            f"أدوات({len(tools)})={b['tool_count_score']}×0.4 + "
            f"جودة الدليل({b['evidence_quality_score']})×0.3 + "
            f"موثوقية الأدوات({b['tool_reliability_avg']})×0.2 + "
            f"إعادة الإنتاج({b['reproducibility_score']})×0.1.",
            f"4) evidence_score = 3.0 + {kw['confidence']:.2f}×7.0 = {kw['evidence']:.2f}.",
            f"5) final = {kw['base']:.2f}×{self.w_base} + {kw['context']:.2f}×{self.w_context} "
            f"+ {kw['evidence']:.2f}×{self.w_evidence} = {kw['final']:.2f} → {kw['severity']}.",
            f"الأدوات: {', '.join(tools) if tools else '—'} | مؤكد ديناميكياً: "
            f"{'نعم' if vuln.get('is_confirmed') else 'لا'}.",
        ]
        return "\n".join(lines)
