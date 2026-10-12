"""base_score.py — النقاط الأساسية حسب فئة MASVS.

الجدول الرسمي (قرار المرحلة 4) — يُقرأ من
severity_rules.context_params.masvs_weights ويُزرع في القاعدة كإصدار v1.1.
الجداول الافتراضية أدناه = نفس جدول v1.1 حرفياً (احتياط عند غياب القاعدة).
"""
from __future__ import annotations

from typing import Any

# جدول MASVS الرسمي (v1.1) — القيم معتمدة في مواصفات المرحلة 4
DEFAULT_MASVS_WEIGHTS: dict[str, float] = {
    "MASVS-CRYPTO": 9.0,
    "MASVS-STORAGE": 8.0,
    "MASVS-NETWORK": 7.5,
    "MASVS-AUTH": 7.0,
    "MASVS-PLATFORM": 6.0,
    "MASVS-RESILIENCE": 5.0,
    "MASVS-CODE": 4.0,
}

# فئة افتراضية عند غياب/جهالة التصنيف (نقطة المنتصف — موثقة، لا تخمين مضلل)
UNKNOWN_CATEGORY_SCORE = 5.0


def calculate_base_score(
    masvs_category: str | None,
    sub_category: str = "",
    rule: dict[str, Any] | None = None,
) -> float:
    """حساب base_score من فئة MASVS وفق جدول قاعدة التقييم النشطة.

    Args:
        masvs_category: مثل "MASVS-CRYPTO" — غير معروف ⇒ 5.0.
        sub_category: محجوز للإصدارات القادمة (لا يغيّر النتيجة حالياً —
                      لا أوزان دقيقة معتمدة له بعد، فلا نخترعها).
        rule: صف severity_rules كـ dict: {"weights": ..., "context_params": ..., "thresholds": ...}
              إن غاب masvs_weights نستخدم جدول v1.1 الافتراضي أعلاه.

    Returns:
        درجة بين 0 و 10.
    """
    weights_table = DEFAULT_MASVS_WEIGHTS
    if rule:
        params = rule.get("context_params") or {}
        candidate = params.get("masvs_weights")
        if isinstance(candidate, dict) and candidate:
            weights_table = {**DEFAULT_MASVS_WEIGHTS, **candidate}

    category = (masvs_category or "").strip().upper()
    score = weights_table.get(category)
    if score is None:
        return UNKNOWN_CATEGORY_SCORE
    return max(0.0, min(10.0, float(score)))
