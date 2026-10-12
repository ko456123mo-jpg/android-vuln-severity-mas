"""عرض الفرق بين تقييم النظام والتصحيح البشري (side-by-side) — المرحلة 6.

final_score لا يُمَس عند التصحيح (قرار المرحلة 5): يُعرض هنا النظام (original)
مقابل المراجع البشري (corrected) مع فرق الدرجة والخطورة بلا أي تعديل على القاعدة.
"""
from __future__ import annotations

from typing import Any

import streamlit as st

from i18n import t

_SEVERITY_COLOR = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}


def _fmt_score(value: Any) -> str:
    """عرض آمن للدرجة."""
    return "—" if value is None else f"{float(value):.2f}"


def render_correction_diff(corrections: list[dict[str, Any]]) -> None:
    """مقارنة كل تصحيح: النظام (original) مقابل المراجع (corrected)."""
    if not corrections:
        st.caption(t("no_data"))
        return
    for correction in corrections:
        original_sev = correction.get("original_severity") or "—"
        corrected_sev = correction.get("corrected_severity") or "—"
        original_score = correction.get("original_score")
        corrected_score = correction.get("corrected_score")
        delta = (
            float(corrected_score) - float(original_score)
            if corrected_score is not None and original_score is not None
            else None
        )
        with st.container(border=True):
            st.caption(
                f"#{correction.get('id')} · {correction.get('reviewer_username') or correction.get('reviewer_id')}"
                f" · {correction.get('corrected_at')}"
            )
            left, right = st.columns(2)
            with left:
                st.markdown(f"**{t('system_vs_human')} — النظام**")
                st.markdown(f"{_SEVERITY_COLOR.get(original_sev, '⚪')} {original_sev}")
                st.markdown(f"{t('final_score')}: **{_fmt_score(original_score)}**")
            with right:
                st.markdown(f"**{t('system_vs_human')} — المراجع البشري**")
                st.markdown(f"{_SEVERITY_COLOR.get(corrected_sev, '⚪')} {corrected_sev}")
                st.markdown(f"{t('correction_score')}: **{_fmt_score(corrected_score)}**")
            if delta is not None:
                st.metric(
                    "Δ",
                    f"{delta:+.2f}",
                    delta_color="inverse" if delta > 0 else "normal",
                )
            st.markdown(f"**{t('correction_reason')}:** {correction.get('reason')}")
