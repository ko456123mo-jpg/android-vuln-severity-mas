"""رسم تفكيك معادلة الدرجة (Waterfall) + شرائح المكوّنات (المرحلة 6).

الأوزان ثابتة بمواصفة محرك التقييم (المرحلة 4): base 0.6 + context 0.2 +
evidence 0.2 = final. تُعرض مع كل مكوّن قيمته الفعلية وناتج ضربه بالوزن.
"""
from __future__ import annotations

from typing import Any

import plotly.graph_objects as go
import streamlit as st

from i18n import t

WEIGHTS = {"base": 0.6, "context": 0.2, "evidence": 0.2}


def render_score_metrics(assessment: dict[str, Any]) -> None:
    """شرائح المكوّنات: base × 0.6 · context × 0.2 · evidence × 0.2 → final."""
    base = float(assessment.get("base_score") or 0.0)
    context = float(assessment.get("context_score") or 0.0)
    evidence = float(assessment.get("evidence_score") or 0.0)
    final = float(assessment.get("final_score") or 0.0)
    confidence = float(assessment.get("confidence_factor") or 0.0)

    cols = st.columns(5)
    cols[0].metric(f"{t('base_score')} × {WEIGHTS['base']}", f"{base:.2f}", f"→ {base * WEIGHTS['base']:.2f}")
    cols[1].metric(f"{t('context_score')} × {WEIGHTS['context']}", f"{context:.2f}", f"→ {context * WEIGHTS['context']:.2f}")
    cols[2].metric(f"{t('evidence_score')} × {WEIGHTS['evidence']}", f"{evidence:.2f}", f"→ {evidence * WEIGHTS['evidence']:.2f}")
    cols[3].metric(t("final_score"), f"{final:.4f}")
    cols[4].metric("Confidence", f"{confidence:.2f}")


def render_score_waterfall(assessment: dict[str, Any]) -> None:
    """Waterfall: مساهمات base/context/evidence ثم الدرجة النهائية."""
    base = float(assessment.get("base_score") or 0.0)
    context = float(assessment.get("context_score") or 0.0)
    evidence = float(assessment.get("evidence_score") or 0.0)
    final = float(assessment.get("final_score") or 0.0)

    labels = [
        f"{t('base_score')} × 0.6",
        f"{t('context_score')} × 0.2",
        f"{t('evidence_score')} × 0.2",
        t("final_score"),
    ]
    values = [
        round(base * WEIGHTS["base"], 4),
        round(context * WEIGHTS["context"], 4),
        round(evidence * WEIGHTS["evidence"], 4),
        round(final, 4),
    ]
    fig = go.Figure(
        go.Waterfall(
            orientation="v",
            measure=["absolute", "relative", "relative", "total"],
            x=labels,
            y=values,
            connector={"line": {"color": "rgba(120,120,120,0.5)"}},
            increasing={"marker": {"color": "#d32f2f"}},
            decreasing={"marker": {"color": "#388e3c"}},
            totals={"marker": {"color": "#1976d2"}},
            text=[f"{v:.2f}" for v in values],
            textposition="outside",
        )
    )
    fig.update_layout(
        height=380,
        margin=dict(l=10, r=10, t=30, b=10),
        showlegend=False,
        yaxis_title=t("final_score"),
    )
    st.plotly_chart(fig, use_container_width=True)
