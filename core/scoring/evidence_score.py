"""evidence_score.py — نقاط الأدلة المشتقة من عامل الثقة.

المعادلة المعتمدة (المرحلة 4): evidence_score = 3.0 + (confidence × 7.0)
النطاق: [3.0, 10.0] — أدنى قيمة 3.0 لأن وجود finding أصلاً يشي بدليل ما.
"""
from __future__ import annotations


def calculate_evidence_score(confidence_factor: float) -> float:
    """تحويل الثقة (∈[0,1]) إلى نقاط أدلة (∈[3,10])."""
    factor = max(0.0, min(1.0, float(confidence_factor)))
    return round(3.0 + factor * 7.0, 4)
