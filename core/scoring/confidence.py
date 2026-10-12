"""confidence.py — عامل الثقة (Confidence Factor) ∈ [0, 1].

المعادلة المعتمدة (المرحلة 4):
    confidence = tool_count_score×0.4 + evidence_quality_score×0.3
               + tool_reliability_avg×0.2 + reproducibility_score×0.1

جداول القراءة:
    tool_count_score        : 0→0.0, 1→0.4, 2→0.7, 3+→1.0
    evidence_quality_score  : none→0.0, general→0.3, raw→0.6, specific→0.9, code+repro→1.0
    reproducibility_score   : not_tested→0.0, once→0.6, twice→1.0
"""
from __future__ import annotations

import re
from typing import Any

TOOL_COUNT_MAP = {0: 0.0, 1: 0.4, 2: 0.7}
REPRODUCIBILITY_MAP = {"not_tested": 0.0, "once": 0.6, "twice": 1.0}
EVIDENCE_QUALITY_MAP = {
    "none": 0.0,
    "general": 0.3,
    "raw": 0.6,
    "specific": 0.9,
    "code_and_repro": 1.0,
}

# علامات "دليل مشخّص": أسناد/استدعاءات/ملفات/خصائص أندرويد
_CODE_HINT = re.compile(r"[=;{}()]|\"[^\"]+\"|\.java\b|android:[a-z]|\b[A-Z][A-Za-z]+\.\w+\(")


def tool_count_score(tool_count: int) -> float:
    """0→0.0, 1→0.4, 2→0.7, 3+→1.0"""
    if tool_count >= 3:
        return 1.0
    return TOOL_COUNT_MAP.get(max(0, tool_count), 0.0)


def assess_evidence_quality(vulnerability: dict[str, Any]) -> str:
    """تصنيف جودة الدليل للثغرة (محدّد حتمي — لا LLM هنا).

    - code_and_repro : دليل مشخّص (كود/قيم) + تأكيد ديناميكي (is_confirmed)
    - specific       : دليل مشخّص بدون تأكيد ديناميكي
    - raw            : دليل نصي خام موجود لكن غير مشخّص
    - general        : وصف عام فقط / بلا نص دليل
    - none           : لا دليل إطلاقاً (لا discovered_by ولا أدلة)
    """
    confirmed = bool(vulnerability.get("is_confirmed"))
    texts: list[str] = [
        str(t) for t in (vulnerability.get("evidence_by_tool") or {}).values() if t
    ]
    if not texts and vulnerability.get("evidence"):
        texts = [str(vulnerability["evidence"])]
    if not texts and not vulnerability.get("discovered_by"):
        return "none"

    looks_code = any(_CODE_HINT.search(t) for t in texts)
    if looks_code and confirmed:
        return "code_and_repro"
    if looks_code:
        return "specific"
    if texts:
        return "raw"
    return "general"


def assess_reproducibility(vulnerability: dict[str, Any]) -> str:
    """قابلية إعادة الإنتاج:

    - twice     : مؤكدة ديناميكياً (Frida/Objection PoC)
    - once      : ثابتة لكن أكثر من أداة مستقلة رصدتها
    - not_tested: أداة واحدة ثابتة فقط
    """
    if vulnerability.get("is_confirmed"):
        return "twice"
    if len(vulnerability.get("discovered_by") or []) >= 2:
        return "once"
    return "not_tested"


def calculate_confidence_factor(
    tool_count: int,
    evidence_quality: str,
    tool_reliability_avg: float,
    reproducibility: str,
) -> float:
    """المعادلة الموزونة — تعيد عاملاً ∈ [0, 1] (مدوَّر 4 خانات)."""
    quality_score = EVIDENCE_QUALITY_MAP.get(evidence_quality, EVIDENCE_QUALITY_MAP["general"])
    repro_score = REPRODUCIBILITY_MAP.get(reproducibility, 0.0)
    reliability = max(0.0, min(1.0, float(tool_reliability_avg)))

    factor = (
        tool_count_score(tool_count) * 0.4
        + quality_score * 0.3
        + reliability * 0.2
        + repro_score * 0.1
    )
    return round(max(0.0, min(1.0, factor)), 4)
