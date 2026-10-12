"""scoring — محرك التقييم الموزون / Weighted severity scoring engine.

final_score = (base_score × 0.6) + (context_score × 0.2) + (evidence_score × 0.2)
الأوزان والمعاملات تُقرأ من severity_rules النشطة — لا قيم مخترعة هنا.
"""
from core.scoring.bands import SEVERITY_BANDS, classify_severity
from core.scoring.base_score import calculate_base_score
from core.scoring.confidence import (
    assess_evidence_quality,
    assess_reproducibility,
    calculate_confidence_factor,
)
from core.scoring.context_score import calculate_context_score
from core.scoring.engine import ScoringEngine
from core.scoring.evidence_score import calculate_evidence_score

__all__ = [
    "SEVERITY_BANDS",
    "assess_evidence_quality",
    "assess_reproducibility",
    "calculate_base_score",
    "calculate_confidence_factor",
    "calculate_context_score",
    "calculate_evidence_score",
    "classify_severity",
    "ScoringEngine",
]
