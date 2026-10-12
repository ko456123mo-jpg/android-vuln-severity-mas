"""bands.py — فئات الخطورة / Severity bands (CVSS-compatible)."""
from __future__ import annotations

SEVERITY_BANDS: dict[str, tuple[float, float]] = {
    "Critical": (9.0, 10.0),
    "High": (7.0, 8.9),
    "Medium": (4.0, 6.9),
    "Low": (0.0, 3.9),
}

# عتبات مرتّبة تنازلياً — تُستخدم للتصنيف والقياس من حدود الفئات
_BAND_THRESHOLDS: tuple[tuple[str, float], ...] = (
    ("Critical", 9.0),
    ("High", 7.0),
    ("Medium", 4.0),
)


def classify_severity(final_score: float) -> str:
    """تصنيف النتيجة النهائية إلى فئة خطورة.

    - score ≥ 9.0 → Critical
    - score ≥ 7.0 → High
    - score ≥ 4.0 → Medium
    - score < 4.0 → Low
    """
    score = max(0.0, min(10.0, float(final_score)))
    for severity, threshold in _BAND_THRESHOLDS:
        if score >= threshold:
            return severity
    return "Low"


def distance_to_band_edge(final_score: float) -> float:
    """المسافة الحسابية لأقرب حد بين فئتين (يستخدمها Reviewer).

    مثال: score=8.6 → min(|8.6-9|, |8.6-7|) = 0.4
    """
    thresholds = {t for _sev, t in _BAND_THRESHOLDS} | {10.0}
    score = max(0.0, min(10.0, float(final_score)))
    prev_edges = [t for t in sorted(thresholds)]
    return min(abs(score - edge) for edge in prev_edges if edge <= 10.0)
