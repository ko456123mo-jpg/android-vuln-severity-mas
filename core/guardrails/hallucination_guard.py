"""Hallucination Guard — فحص وجود الأدلة في مخرجات الأدوات الأصلية.

مجرد أن LLM قد يخترع دليلاً غير موجود، تُقارن كلمات الدليل المفتاحية
(كلاسات، دوال، أسطر كود، سلاسل نصية) مع نصوص المصادر التي أنتجتها الأدوات،
وتُحسب تغطية (coverage): نسبة الكلمات الموجودة فعلاً.

القواعد (موثقة في docs/scoring_logic.md):
    coverage ≥ 0.8 → accept  (الدليل موثوق — مقبول كما هو)
    coverage ≥ 0.4 → flag    (قبول مشروط — يُعلَّم للمراجعة البشرية)
    coverage <  0.4 → reject (مرفوض — استبعاد محتمل)
"""
from __future__ import annotations

import re
from typing import Any

# ============================== أنماط استخراج الكلمات المفتاحية ==============================
_PATTERNS = [
    re.compile(r"\bcom\.[a-zA-Z][\w$]*(?:\.[\w$]+)+\b"),          # اسم فئة Java الكامل
    re.compile(r"\b[A-Z][A-Za-z0-9]+\.[a-zA-Z]\w*\(\)"),          # استدعاء دالة Class.method()
    re.compile(r'"([^"]{4,60})"'),                                # سلاسل مقتبسة
    re.compile(r"\b[\w./-]+\.(?:java|kt|xml|so|dex|jar)\b"),     # مسارات/ملفات
    re.compile(r"\bhttps?://[^\s\"'<>]+"),                        # روابط
    re.compile(r"\bandroid:[\w:.-]{4,}\b"),                       # عناصر XML خاصة بأندرويد
    re.compile(r"\b(?:class|function|method)\s+[A-Za-z_]\w+\b"), # تعريفات صريحة
]

_MIN_KEYWORD_LEN = 4


def extract_evidence_keywords(evidence: str) -> list[str]:
    """استخراج كلمات مفتاحية تميّز الدليل (كلاس/دالة/سلسلة/مسار/رابط...)."""
    found: list[str] = []
    text = evidence or ""
    for pattern in _PATTERNS:
        for match in pattern.finditer(text):
            token = match.group(1) if match.groups() else match.group(0)
            token = token.strip().strip('`"\'')
            if len(token) >= _MIN_KEYWORD_LEN and token not in found:
                found.append(token)
    return found


def _text_contains(source_text: str, token: str) -> bool:
    """بحث شبه حرفي (case-insensitive) عن التوكن في نص المصدر."""
    if not source_text:
        return False
    return token.lower() in source_text.lower()


def calculate_coverage(evidence: str, sources: list[str]) -> float:
    """حساب نسبة تغطية الدليل في نصوص المصادر (أعلى تطابق لكل توكن).

    لكل كلمة مفتاحية، تُعتبر «موجودة» إذا ظهرت في أي مصدر من المصادر.
    لا توجد كلمات مفتاحية ⇒ تغطية 0.0 (لا يمكن التحقق ⇒ معاملة افتراضية حذرة).
    """
    keywords = extract_evidence_keywords(evidence)
    if not keywords:
        return 0.0
    present = sum(1 for kw in keywords if any(_text_contains(s, kw) for s in sources))
    return present / len(keywords)


def verify_evidence_in_sources(
    vulnerability: dict[str, Any],
    source_texts: dict[str, str],
) -> dict[str, Any]:
    """التحقق من أن أدلة الثغرة موجودة فعلاً في مخرجات الأدوات الأصلية.

    Args:
        vulnerability: {"evidence_by_tool": {"jadx": "...", "frida": "...", ...}}
        source_texts: {"jadx": "<نص مخرجات jadx>", "frida": "...", ...}
                      أو خريطة tool→مخرجات نصية جاهزة (قد تكون فارغة).

    Returns:
        {"verified": bool, "coverage": 0..1, "action": accept|flag|reject,
         "found_in": [tools], "missing": [keywords]}
    """
    evidence_by_tool: dict[str, str] = vulnerability.get("evidence_by_tool") or {}
    all_sources = list(source_texts.values())
    all_keywords: list[str] = []
    found_in: list[str] = []
    missing: list[str] = []

    for tool_name, evidence in evidence_by_tool.items():
        kws = extract_evidence_keywords(str(evidence))
        all_keywords.extend(kws)
        # تفضيل نص المصدر الخاص بالأداة نفسها ثم بقية المصادر كاحتياط.
        searched = [source_texts.get(tool_name, "")] + [
            v for k, v in source_texts.items() if k != tool_name
        ]
        per_kw_presence = {
            kw: any(_text_contains(s, kw) for s in searched) for kw in kws
        }
        if kws and any(per_kw_presence.values()):
            found_in.append(tool_name)
        missing.extend(kw for kw, ok in per_kw_presence.items() if not ok)

    if not all_keywords:
        coverage = 0.0
    else:
        coverage = 1.0 - (len(missing) / len(all_keywords)) if all_keywords else 0.0

    if coverage >= 0.8:
        action = "accept"
    elif coverage >= 0.4:
        action = "flag"
    else:
        action = "reject"

    return {
        "verified": coverage >= 0.8,
        "coverage": round(coverage, 4),
        "action": action,
        "found_in": sorted(set(found_in)),
        "missing": missing,
    }
