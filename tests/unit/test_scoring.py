"""اختبارات وحدة منظومة التقييم — core/scoring + قواعد Reviewer (المرحلة 4).

التغطية:
    • bands: حدود الفئات + المسافة لأقرب حافة
    • base_score: جدول MASVS من severity_rules + الافتراضي + المجهول
    • context_score: المعادلة الموزونة + الكبح (clamp) + الجداول المخصصة
    • confidence: المعادلة الوارية (tc×0.4 + eq×0.3 + rel×0.2 + repro×0.1)
    • evidence_score: 3 + 7×conf
    • engine: سيناريو محسوب يدوياً بالكامل + حتمية + أوزان مخصصة
    • reviewer: جدول قرار 12 سيناريو + معايير التصعيد البشري الثلاثة

القيم الحرجة في هذا الملف محسوبة يدوياً (hand-verified) وتطابق
docs/scoring_logic.md سطراً بسطر.
"""
from __future__ import annotations

import pytest

from agents.reviewer import (
    REVIEW_RULES,
    apply_review_rules,
    needs_human_review,
)
from core.scoring.bands import classify_severity, distance_to_band_edge
from core.scoring.base_score import DEFAULT_MASVS_WEIGHTS, calculate_base_score
from core.scoring.confidence import (
    assess_evidence_quality,
    assess_reproducibility,
    calculate_confidence_factor,
    tool_count_score,
)
from core.scoring.context_score import (
    DEFAULT_APP_CONTEXT,
    calculate_context_score,
)
from core.scoring.engine import ScoringEngine
from core.scoring.evidence_score import calculate_evidence_score

# قاعدة v1.1 كما هي مزروعة في db/seed.py (مرجع واحد للاختبارات)
RULE_V11 = {
    "version": "v1.1",
    "weights": {"base": 0.6, "context": 0.2, "evidence": 0.2},
    "context_params": {
        "data_sensitivity": {"LOW": 3, "MEDIUM": 6, "HIGH": 10},
        "industry": {"banking": 10, "health": 10, "commerce": 7, "game": 5, "utility": 6},
        "user_base_size": {"small": 4, "medium": 6, "large": 9},
        "internet_facing": {"true": 10, "false": 4},
        "business_criticality": {"LOW": 3, "MEDIUM": 6, "HIGH": 10},
        "masvs_weights": dict(DEFAULT_MASVS_WEIGHTS),
    },
    "thresholds": {
        "critical": 9.0, "high": 7.0, "medium": 4.0,
        "confidence": {"review": 0.75, "critical_min": 0.90},
    },
}

BANKING_CTX = {
    "data_sensitivity": "HIGH",
    "user_base_size": "large",
    "internet_facing": True,
    "business_criticality": "HIGH",
}
# التوقع: 5 + 10×.4 + 9×.2 + 10×.2 + 10×.2 = 12.8 → كبح 10.0
TOOL_RELIABILITIES = {"jadx": 0.70, "mobsf": 0.90, "frida": 1.00, "objection": 0.85}


# =====================================================================
# 1) bands
# =====================================================================
class TestBands:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (10.0, "Critical"), (9.0, "Critical"), (9.5, "Critical"),
            (8.99, "High"), (7.0, "High"), (8.0, "High"),
            (6.99, "Medium"), (4.0, "Medium"), (5.5, "Medium"),
            (3.99, "Low"), (1.0, "Low"),
        ],
    )
    def test_classify_boundaries(self, score, expected):
        assert classify_severity(score) == expected

    def test_classify_out_of_range_clamped(self):
        assert classify_severity(-3.0) == "Low"
        assert classify_severity(12.5) == "Critical"

    def test_distance_to_edge(self):
        assert distance_to_band_edge(8.6) == pytest.approx(0.4)   # |8.6-9|
        assert distance_to_band_edge(9.36) == pytest.approx(0.36)  # |9.36-9|
        assert distance_to_band_edge(5.5) == pytest.approx(1.5)   # |5.5-4|
        # الحواف {0,4,7,9,10}: score=2.0 يبعد 2.0 عن 0 و 2.0 عن 4
        assert distance_to_band_edge(2.0) == pytest.approx(2.0)
        assert distance_to_band_edge(9.0) == pytest.approx(0.0)


# =====================================================================
# 2) base_score
# =====================================================================
class TestBaseScore:
    def test_all_categories_from_rule(self):
        params = RULE_V11["context_params"]
        for cat, expected in DEFAULT_MASVS_WEIGHTS.items():
            assert calculate_base_score(cat, rule={"context_params": params}) == expected

    def test_category_case_insensitive(self):
        assert calculate_base_score("masvs-crypto", rule=RULE_V11) == 9.0
        assert calculate_base_score("Masvs-Storage", rule=RULE_V11) == 8.0

    def test_unknown_category_neutral_5(self):
        assert calculate_base_score("MASVS-UNKNOWN") == 5.0
        assert calculate_base_score(None) == 5.0
        assert calculate_base_score("") == 5.0

    def test_rule_overrides_default_weights(self):
        custom = {"context_params": {"masvs_weights": {"MASVS-CRYPTO": 7.5}}}
        assert calculate_base_score("MASVS-CRYPTO", rule=custom) == 7.5
        # الفئات غير المُعرَّفة تبقى من الجدول الافتراضي
        assert calculate_base_score("MASVS-CODE", rule=custom) == 4.0

    def test_sub_category_reserved_no_invented_weights(self):
        score_plain = calculate_base_score("MASVS-CRYPTO", rule=RULE_V11)
        score_with_sub = calculate_base_score(
            "MASVS-CRYPTO", "hardcoded_key", rule=RULE_V11
        )
        assert score_with_sub == score_plain


# =====================================================================
# 3) context_score
# =====================================================================
class TestContextScore:
    def test_banking_maximum_clamped_to_10(self):
        # 5 + 10×.4 + 9×.2 + 10×.2 + 10×.2 = 12.8 → كبح علوي 10.0
        assert calculate_context_score(BANKING_CTX, RULE_V11["context_params"]) == 10.0

    def test_minimum_exact_not_clamped(self):
        # 5 + 3×.4 + 4×.2 + 4×.2 + 3×.2 = 5 + 1.2+0.8+0.8+0.6 = 8.4
        ctx = {
            "data_sensitivity": "LOW",
            "user_base_size": "small",
            "internet_facing": False,
            "business_criticality": "LOW",
        }
        assert calculate_context_score(ctx, RULE_V11["context_params"]) == 8.4

    def test_custom_tables_respected(self):
        params = {
            "data_sensitivity": {"LOW": 1, "HIGH": 5},
            "user_base_size": {"small": 1},
            "internet_facing": {"false": 1},
            "business_criticality": {"LOW": 1},
        }
        ctx = {
            "data_sensitivity": "LOW", "user_base_size": "small",
            "internet_facing": False, "business_criticality": "LOW",
        }
        # 5 + 1×(.4+.2+.2+.2) = 6.0
        assert calculate_context_score(ctx, params) == 6.0

    def test_missing_key_falls_to_min_table_value(self):
        # "ULTRA" غير موجودة ⇒ أدنى قيمة (3) بدلاً من رفع الدرجة
        ctx = {
            "data_sensitivity": "ULTRA",
            "user_base_size": "small",
            "internet_facing": False,
            "business_criticality": "LOW",
        }
        assert calculate_context_score(ctx, RULE_V11["context_params"]) == 8.4

    def test_default_context_used_when_none(self):
        # DEFAULT (MEDIUM/medium/True/MEDIUM): 5 + 2.4 + 1.2 + 2 + 1.2 = 11.8 → 10
        assert calculate_context_score(None) == 10.0
        assert DEFAULT_APP_CONTEXT["internet_facing"] is True

    def test_clamp_floor_at_1(self):
        params = {k: {kk: -20 for kk in v} for k, v in RULE_V11["context_params"].items() if k != "masvs_weights"}
        assert calculate_context_score(BANKING_CTX, params) == 1.0


# =====================================================================
# 4) confidence
# =====================================================================
class TestConfidence:
    @pytest.mark.parametrize(
        "count,expected", [(0, 0.0), (1, 0.4), (2, 0.7), (3, 1.0), (9, 1.0)]
    )
    def test_tool_count_map(self, count, expected):
        assert tool_count_score(count) == expected

    def test_formula_exact_components(self):
        # 0.7×0.4 + 0.9×0.3 + 0.8×0.2 + 0.6×0.1 = 0.28+0.27+0.16+0.06 = 0.77
        factor = calculate_confidence_factor(
            tool_count=2,
            evidence_quality="specific",
            tool_reliability_avg=0.8,
            reproducibility="once",
        )
        assert factor == 0.77

    def test_evidence_quality_levels(self):
        assert assess_evidence_quality({}) == "none"
        assert assess_evidence_quality({"discovered_by": ["mobsf"]}) == "general"
        assert assess_evidence_quality(
            {"evidence_by_tool": {"mobsf": "weak crypto detected in app"}}
        ) == "raw"
        assert assess_evidence_quality(
            {"evidence_by_tool": {"jadx": 'String K = "abc";'}, "is_confirmed": False}
        ) == "specific"
        assert assess_evidence_quality(
            {"evidence_by_tool": {"frida": "Cipher.getInstance(\"DES\")"}, "is_confirmed": True}
        ) == "code_and_repro"

    def test_reproducibility_levels(self):
        assert assess_reproducibility({"is_confirmed": True}) == "twice"
        assert assess_reproducibility({"discovered_by": ["jadx", "mobsf"]}) == "once"
        assert assess_reproducibility({"discovered_by": ["mobsf"]}) == "not_tested"
        assert assess_reproducibility({}) == "not_tested"


# =====================================================================
# 5) evidence_score
# =====================================================================
class TestEvidenceScore:
    @pytest.mark.parametrize(
        "conf,expected", [(0.0, 3.0), (1.0, 10.0), (0.5, 6.5), (0.77, 8.39)]
    )
    def test_linear_transform(self, conf, expected):
        assert calculate_evidence_score(conf) == pytest.approx(expected)


# =====================================================================
# 6) ScoringEngine — سيناريو محسوب يدوياً بالكامل
# =====================================================================
class TestScoringEngine:
    def test_cwe321_hand_calculated_scenario(self):
        """CWE-321 (CRYPTO، أداتان، غير مؤكد) — مطابق للحساب اليدوي في التوثيق.

        base=9 (CRYPTO) · context=10 (كبح) · conf=0.7×.4+0.9×.3+0.8×.2+0×.1=0.77
        evidence=3+7×0.77=8.39 · final=9×.6+10×.2+8.39×.2=9.078 → Critical
        """
        engine = ScoringEngine(RULE_V11)
        vuln = {
            "title": "Hardcoded Key",
            "masvs_category": "MASVS-CRYPTO", "cwe_id": "CWE-321",
            "is_confirmed": False, "discovered_by": ["jadx", "mobsf"],
            "evidence_by_tool": {
                "jadx": 'String KEY = "hardcoded_secret_123";',
                "mobsf": "hardcoded key in code",
            },
        }
        result = engine.score(vuln, BANKING_CTX, TOOL_RELIABILITIES)
        assert result["base_score"] == 9.0
        assert result["context_score"] == 10.0
        assert result["confidence_factor"] == 0.77
        assert result["evidence_score"] == 8.39
        assert result["final_score"] == 9.078
        assert result["severity"] == "Critical"
        # سلامة المعادلة على الناتج نفسه
        recomputed = (
            result["base_score"] * 0.6
            + result["context_score"] * 0.2
            + result["evidence_score"] * 0.2
        )
        assert abs(recomputed - result["final_score"]) < 0.01

    def test_deterministic_same_inputs_same_outputs(self):
        engine = ScoringEngine(RULE_V11)
        vuln = {
            "title": "X", "masvs_category": "MASVS-STORAGE",
            "discovered_by": ["mobsf"], "is_confirmed": False,
            "evidence_by_tool": {"mobsf": "world readable file"},
        }
        assert engine.score(vuln, BANKING_CTX, TOOL_RELIABILITIES) == engine.score(
            vuln, BANKING_CTX, TOOL_RELIABILITIES
        )

    def test_custom_weights_from_rule_respected(self):
        rule = {**RULE_V11, "weights": {"base": 0.5, "context": 0.3, "evidence": 0.2}}
        engine = ScoringEngine(rule)
        vuln = {"masvs_category": "MASVS-CODE", "discovered_by": []}
        result = engine.score(vuln, None, {})
        # base=4.0 · context=10 (default ctx) · conf=0 → evidence=3.0
        # final = 4×0.5 + 10×0.3 + 3×0.2 = 2.0+3.0+0.6 = 5.6
        assert result["base_score"] == 4.0
        assert result["evidence_score"] == 3.0
        assert result["final_score"] == 5.6

    def test_rationale_contains_equation_steps(self):
        engine = ScoringEngine(RULE_V11)
        vuln = {"title": "Y", "masvs_category": "MASVS-NETWORK", "discovered_by": ["mobsf"]}
        result = engine.score(vuln, BANKING_CTX, TOOL_RELIABILITIES)
        rationale = result["rationale"]
        assert "base_score" in rationale and "final" in rationale
        assert "0.6" in rationale and "×" in rationale


# =====================================================================
# 7) Reviewer — جدول القرار (12 سيناريو)
# =====================================================================
def _assessment(**over) -> dict:
    """تقييم افتراضي محايد (لا تُطلق أي قاعدة) ما لم تُعدَّل القيم."""
    base = {
        "final_score": 5.0, "severity": "Medium",
        "base_score": 6.0, "context_score": 5.0, "evidence_score": 5.0,
        "confidence_factor": 0.80, "masvs_category": "MASVS-STORAGE",
    }
    base.update(over)
    return base


class TestReviewDecisionTable:
    def test_R1_weak_evidence_critical(self):
        r = apply_review_rules(_assessment(
            final_score=9.2, severity="Critical", evidence_score=4.0, confidence_factor=0.95
        ))
        assert [a["rule_id"] for a in r["adjustments"]] == ["R1-weak-evidence-critical"]
        assert r["reviewed_score"] == 7.7
        assert r["final_severity"] == "High"

    def test_R2_strong_evidence_low(self):
        r = apply_review_rules(_assessment(
            final_score=2.5, severity="Low", evidence_score=9.0, context_score=5.0, confidence_factor=0.5
        ))
        assert [a["rule_id"] for a in r["adjustments"]] == ["R2-strong-evidence-low"]
        assert r["reviewed_score"] == 4.0
        assert r["final_severity"] == "Medium"

    def test_R3_high_context_low(self):
        r = apply_review_rules(_assessment(
            final_score=3.0, severity="Low", context_score=9.0, evidence_score=5.0, confidence_factor=0.5
        ))
        assert [a["rule_id"] for a in r["adjustments"]] == ["R3-high-context-low"]
        assert r["reviewed_score"] == 4.0

    def test_R4_low_context_critical(self):
        r = apply_review_rules(_assessment(
            final_score=9.1, severity="Critical", context_score=3.0, evidence_score=6.0, confidence_factor=0.85
        ))
        assert [a["rule_id"] for a in r["adjustments"]] == ["R4-low-context-critical"]
        assert r["reviewed_score"] == 8.1

    def test_R5_crypto_medium_floor(self):
        r = apply_review_rules(_assessment(
            final_score=5.0, severity="Medium", masvs_category="MASVS-CRYPTO", confidence_factor=0.8
        ))
        assert [a["rule_id"] for a in r["adjustments"]] == ["R5-crypto-medium-floor"]
        assert r["reviewed_score"] == 6.0

    def test_R6_code_quality_critical_cap(self):
        r = apply_review_rules(_assessment(
            final_score=9.0, severity="Critical", masvs_category="MASVS-CODE",
            evidence_score=6.0, confidence_factor=0.8, context_score=6.0
        ))
        assert [a["rule_id"] for a in r["adjustments"]] == ["R6-code-quality-critical-cap"]
        assert r["reviewed_score"] == 8.0
        assert r["final_severity"] == "High"

    def test_R7_low_confidence_critical(self):
        r = apply_review_rules(_assessment(
            final_score=9.4, severity="Critical", confidence_factor=0.3,
            evidence_score=6.0, context_score=6.0
        ))
        assert [a["rule_id"] for a in r["adjustments"]] == ["R7-low-confidence-critical"]
        assert r["reviewed_score"] == 8.4

    def test_R8_high_confidence_low(self):
        r = apply_review_rules(_assessment(
            final_score=2.0, severity="Low", confidence_factor=0.95,
            evidence_score=5.0, context_score=3.0
        ))
        assert [a["rule_id"] for a in r["adjustments"]] == ["R8-high-confidence-low"]
        assert r["reviewed_score"] == 2.5

    def test_no_rules_fired_unchanged(self):
        a = _assessment()
        r = apply_review_rules(a)
        assert r["adjustments"] == []
        assert r["reviewed_score"] == a["final_score"]
        assert r["final_severity"] == a["severity"]

    def test_multiple_rules_stack(self):
        # Low + evidence 9 + conf 0.95 + ctx 9 → R2(+1.5) + R3(+1.0) + R8(+0.5) = +3.0
        r = apply_review_rules(_assessment(
            final_score=3.0, severity="Low", evidence_score=9.0,
            confidence_factor=0.95, context_score=9.0
        ))
        assert {a["rule_id"] for a in r["adjustments"]} == {
            "R2-strong-evidence-low", "R3-high-context-low", "R8-high-confidence-low"
        }
        assert r["reviewed_score"] == 6.0

    def test_clamped_to_10(self):
        # Low بدرجة 9.9 مع التراكيب الثلاثة (+3.0) ⇒ كبح علوي 10.0
        r = apply_review_rules(_assessment(
            final_score=9.9, severity="Low", evidence_score=9.0,
            confidence_factor=0.95, context_score=9.0
        ))
        assert r["reviewed_score"] == 10.0
        assert r["final_severity"] == "Critical"

    def test_clamped_to_1(self):
        # Critical عند 2.4 مع R1(-1.5) ⇒ خام 0.9 ⇒ كبح أدنى 1.0
        r = apply_review_rules(_assessment(
            final_score=2.4, severity="Critical", evidence_score=4.0, confidence_factor=0.95,
            masvs_category="MASVS-STORAGE", context_score=6.0
        ))
        assert r["original_score"] == 2.4
        assert r["reviewed_score"] == 1.0
        assert r["final_severity"] == "Low"

    def test_eight_rules_registered_with_reasons(self):
        assert len(REVIEW_RULES) == 8
        for rule in REVIEW_RULES:
            assert rule["id"].startswith("R")
            assert rule["adjustment"] != 0
            assert rule["reason"].strip()  # سبب مكتوب إلزامي لكل قاعدة


class TestHumanReviewCriteria:
    def test_criterion1_confidence_below_review_threshold(self):
        flag, reasons = needs_human_review(
            _assessment(confidence_factor=0.74, final_score=5.0, severity="Medium"), 0.75, 0.9
        )
        assert flag is True
        assert any("الثقة" in r for r in reasons)

    def test_criterion2_boundary_zone(self):
        flag, reasons = needs_human_review(
            _assessment(final_score=7.3, confidence_factor=0.9, severity="High"), 0.75, 0.9
        )
        assert flag is True
        assert any("حدّية" in r for r in reasons)

    def test_criterion3_critical_with_conf_below_09(self):
        flag, reasons = needs_human_review(
            _assessment(
                final_score=9.5, confidence_factor=0.85, severity="Critical"
            ), 0.75, 0.9
        )
        assert flag is True
        assert any("Critical" in r for r in reasons)

    def test_negative_case_no_flag(self):
        flag, reasons = needs_human_review(
            _assessment(final_score=7.8, confidence_factor=0.85, severity="High"), 0.75, 0.9
        )
        assert flag is False
        assert reasons == []

    def test_exact_boundary_edge_inclusive(self):
        # المسافة 0.5 بالضبط ⇒ ضمن المنطقة الحدّية (≤)
        flag, _ = needs_human_review(
            _assessment(final_score=7.5, confidence_factor=0.9, severity="High"), 0.75, 0.9
        )
        assert flag is True
