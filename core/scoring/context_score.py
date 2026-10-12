"""context_score.py — نقاط سياق التطبيق التجاري.

المعادلة المعتمدة (المرحلة 4 — تُقرأ معاملاتها من severity_rules.context_params):

    context_score = 5.0 (أساسي)
        + data_sensitivity   × 0.4   # {LOW:3, MEDIUM:6, HIGH:10}
        + user_base_size     × 0.2   # {small:4, medium:6, large:9}
        + internet_facing    × 0.2   # {True:10, False:4}
        + business_criticality × 0.2 # {LOW:3, MEDIUM:6, HIGH:10}
    ومقيّدة إلى [1.0, 10.0].

ملاحظة تحليلية (توثّق في论文): بما أن الأساس 5.0 ثابت، فالمجال الفعلي
8.4–15 ⇒ بعد القيود 8.4–10.0. تصميم قادم v2 قد يطببّع على الأقصى (÷1.5).
"""
from __future__ import annotations

from typing import Any

BASE_VALUE = 5.0

_W_SENSITIVITY = 0.4
_W_USERBASE = 0.2
_W_INTERNET = 0.2
_W_CRITICALITY = 0.2

# قيم افتراضية محايدة عند غياب app_context (موثقة — لا فشل للفحص)
DEFAULT_APP_CONTEXT: dict[str, Any] = {
    "data_sensitivity": "MEDIUM",
    "user_base_size": "medium",
    "internet_facing": True,
    "business_criticality": "MEDIUM",
}

# معاملات احتياط = صفوف قاعدة v1.0/v1.1 (مطابقة للسيد)
_FALLBACK_PARAMS: dict[str, dict[str, float]] = {
    "data_sensitivity": {"LOW": 3, "MEDIUM": 6, "HIGH": 10},
    "user_base_size": {"small": 4, "medium": 6, "large": 9},
    "internet_facing": {"true": 10, "false": 4},
    "business_criticality": {"LOW": 3, "MEDIUM": 6, "HIGH": 10},
}


def _lookup(table: dict[str, float], key: str, factor: str) -> float:
    """قراءة معامل من جدول القاعدة — مفتاح مفقود ⇒ أدنى قيمة (تحفّظ موثّق)."""
    if isinstance(key, bool):
        key = "true" if key else "false"
    key_norm = str(key).strip()
    if key_norm in table:
        return float(table[key_norm])
    # محاولة بمطابقة حالة الأحرف (INTERNET_FACING json يستخدم true/false صغيرة)
    for candidate, value in table.items():
        if candidate.lower() == key_norm.lower():
            return float(value)
    return float(min(table.values()))  # أدنى قيمة = لا تضخيم


def calculate_context_score(
    app_context: dict[str, Any] | None, params: dict[str, Any] | None = None
) -> float:
    """حساب context_score وفق المعادلة المعتمدة — مقيّدة إلى [1.0, 10.0].

    Args:
        app_context: {data_sensitivity, user_base_size, internet_facing, business_criticality}
        params: severity_rules.context_params (إن غاب ⇒ جداول v1.1 الاحتياطية).
    """
    ctx = {**DEFAULT_APP_CONTEXT, **(app_context or {})}
    tables = {key: (params or {}).get(key) or fallback for key, fallback in _FALLBACK_PARAMS.items()}

    score = (
        BASE_VALUE
        + _lookup(tables["data_sensitivity"], ctx["data_sensitivity"], "data_sensitivity") * _W_SENSITIVITY
        + _lookup(tables["user_base_size"], ctx["user_base_size"], "user_base_size") * _W_USERBASE
        + _lookup(tables["internet_facing"], ctx["internet_facing"], "internet_facing") * _W_INTERNET
        + _lookup(tables["business_criticality"], ctx["business_criticality"], "business_criticality") * _W_CRITICALITY
    )
    return round(max(1.0, min(10.0, score)), 4)
