"""Fingerprints — بصمات دمج الثغرات (Dedup).

الفكرة: نفس الثغرة قد تظهر من عدة أدوات (jadx + mobsf + frida) —
يجب أن تنتهي في سجل vulnerabilities واحد مع أدلة متعددة.

البصمة = SHA256(package_name + cwe_id + canonical_sink)[:32]

قاعدة canonical_sink:
    - ثغرات ذات نطاق عام للتطبيق (SSL pinning، root، تخزين، cleartext) لها
      مفاتيح ثابتة بصرف النظر عن تنسيق الموقع المُبلَّغ من كل أداة
      (APP_WIDE_CWE) — لأن "AndroidManifest.xml" ≠ "runtime:ssl_pinning"
      رغم أنهما نفس الثغرة.
    - ثغرات الكود تشتق من اسم الفئة المطبع (com.x.Y بعد إزالة .java و:line).
    - بدون فئة: توقيع الموقع بعد إزالة رقم السطر والتطبيع.
"""
from __future__ import annotations

import hashlib
import re

# ثغرات نطاقها التطبيق كاملاً — مفتاح ثابت لكل CWE/تطبيق عبر كل الأدوات
APP_WIDE_CWE: dict[str, str] = {
    "CWE-295": "app-wide:network.tls",        # SSL Pinning / شهادات
    "CWE-919": "app-wide:resilience.root",    # كشف الروت
    "CWE-312": "app-wide:storage.plaintext",  # تخزين بيانات حساسة نصّياً
    "CWE-319": "app-wide:network.cleartext",  # HTTP نص صريح
}

_CLASS_RE = re.compile(r"(com(?:\.[A-Za-z_$][\w$]*)+)")
_LINE_SUFFIX = re.compile(r":\d+(?::\d+)?$")


def _canon(value: str | None, default: str = "") -> str:
    return (value or "").strip() or default


def _normalize_class(location: str) -> str:
    """استخراج اسم الفئة المؤهل من مواقع بصيغ مختلفة.

    com/x/Y.java:9  و  com.x.Y.java  و  com.x.Y.method  كلها → com.x.Y
    (نُسقط المقاطع النهائية ذات الحرف الصغير: method/java/pkg آمنة لأن
    أسماء فئات جافا تبدأ بحرف كبير، فتبقى آخر فئة ClassName).
    """
    normalized = location.replace("/", ".")
    match = _CLASS_RE.search(normalized)
    if not match:
        return ""
    parts = match.group(1).split(".")
    while len(parts) > 1 and parts[-1] and parts[-1][0].islower():
        parts.pop()
    return ".".join(parts)


def _canonical_sink(cwe_id: str, location: str) -> str:
    """المفتاح القانوني للـ sink حسب CWE والموقع."""
    fixed = APP_WIDE_CWE.get(cwe_id)
    if fixed:
        return fixed
    cls = _normalize_class(location)
    if cls:
        return f"class:{cls}"
    # بدون فئة — توقيع الموقع بعد إزالة رقم السطر
    cleaned = _LINE_SUFFIX.sub("", _canon(location)).lower()
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return f"loc:{cleaned}" if cleaned else "unknown-sink"


def compute_vuln_fingerprint(vuln: dict) -> str:
    """حساب بصمة الثغرة — ثابتة لنفس الثغرة عبر الأدوات المختلفة.

    Args:
        vuln: dict يحوي package_name (أو package)، cwe_id، location،
              واختيارياً fingerprint_scope لحصر الدمج في نطاق تطبيق معيّن
              (مثلاً "app:42") — يمنع تصادم تطبيقين منفصلين بنفس الـ package
              على عمود dedup_fingerprint الفريد عموماً.
    Returns:
        بصمة hex بطول 32 (تناسب VARCHAR(128)).
    """
    package = _canon(vuln.get("package_name") or vuln.get("package"), "unknown.package")
    cwe = _canon(vuln.get("cwe_id"), "CWE-UNKNOWN").upper()
    location = _canon(vuln.get("location"))
    scope = _canon(vuln.get("fingerprint_scope"))
    sink = _canonical_sink(cwe, location)
    raw = f"{scope}|{package}|{cwe}|{sink}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
