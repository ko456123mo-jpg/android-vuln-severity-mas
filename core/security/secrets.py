"""تحقق الأسرار / Secrets validation (المرحلة 8).

يُستدعى عند **بدء التطبيق** (lifespan في ``api/main.py``) ليمنع الإنتاج من
الإقلاع بأخطاء إعداد صارخة، وليلتقط أخطاء التطوير مبكراً بدون تعطيله.

الفحوص (كلٌّ بدرجته):

| الفحص | الدرجة | الشرط |
|---|---|---|
| ``MAS_SECRET_KEY`` موجود وطوله ≥ 32 | خطأ في الإنتاج / تحذير في التطوير | توقيع JWT |
| ``MAS_SECRET_KEY`` ليس قيمة معروفة/ضعيفة | خطأ في الإنتاج | «mas-dev-secret-…», «changeme», «secret»… |
| ``GROQ_API_KEY`` بصيغة ``gsk_…`` إن وُجد | خطأ | مفتاح مكتوب خطأً |
| ``OPENAI/GOOGLE/ANTHROPIC`` بادئة معقولة إن وُجدت | تحذير | صيغة غير متوقعة |
| كلمة مرور المدير الافتراضية ``admin123`` في الإنتاج | خطأ | حساب افتراضي مكشوف |
| ``DATABASE_PATH`` داخل مجلد عام/مؤقّت في الإنتاج | تحذير | تسريب قاعدة بيانات |
| ``CORS`` مفتوح (لا ``MAS_CORS_ORIGINS``) في الإنتاج | تحذير | تعرّض متصفحي |

الاستخدام:
    from core.security.secrets import validate_secrets
    report = validate_secrets()
    report.ok        # False عند وجود خطأ
    report.summary()  # نص عربي جاهز للسجل/التقرير
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

MIN_SECRET_LENGTH = 32
KNOWN_WEAK_SECRETS = {
    "mas-dev-secret-key-change-in-production",
    "changeme",
    "change-me",
    "secret",
    "admin",
    "password",
    "test",
    "your-secret-key",
}
WEAK_ADMIN_PASSWORDS = {"admin123", "admin", "password", "12345678", "changeme"}


@dataclass
class SecretsReport:
    """نتيجة التحقق: أخطاء (تمنع الإنتاج) + تحذيرات (لا تمنع)."""

    env: str = "development"
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """لا أخطاء ⇒ صالح للإقلاع (التحذيرات تبقى مسموحة)."""
        return not self.errors

    def summary(self) -> str:
        """ملخص نصي عربي موحّد للسجل."""
        lines = [f"تحقق الأسرار — البيئة: {self.env} | فُحص: {len(self.checked)} مفتاحاً"]
        for item in self.errors:
            lines.append(f"  ✗ خطأ: {item}")
        for item in self.warnings:
            lines.append(f"  ⚠ تحذير: {item}")
        if self.ok and not self.warnings:
            lines.append("  ✓ لا ملاحظات — الإعداد آمن للإنتاج")
        return "\n".join(lines)


def _is_production(env: str | None = None) -> bool:
    """هل البيئة إنتاج؟"""
    resolved = (env or os.getenv("MAS_ENV", "development")).strip().lower()
    return resolved == "production"


def validate_secrets(env: str | None = None) -> SecretsReport:
    """يفحص الأسرار ويعيد تقريراً (لا يرفع استثناءً بنفسه — القرار للمستدعي)."""
    report = SecretsReport(env=(env or os.getenv("MAS_ENV", "development")))
    production = _is_production(env)

    # ── 1) مفتاح JWT ─────────────────────────────────────────────────
    secret = os.getenv("MAS_SECRET_KEY")
    report.checked.append("MAS_SECRET_KEY")
    if not secret:
        message = "MAS_SECRET_KEY غير مضبوط (يُستخدم المفتاح التطويري من settings.yaml)"
        (report.errors if production else report.warnings).append(message)
    else:
        if len(secret) < MIN_SECRET_LENGTH:
            report.errors.append(
                f"MAS_SECRET_KEY قصير ({len(secret)} < {MIN_SECRET_LENGTH} حرفاً) — "
                "ولّد مفتاحاً بـ: python -c \"import secrets;print(secrets.token_urlsafe(48))\""
            )
        if secret.strip().lower() in KNOWN_WEAK_SECRETS:
            (report.errors if production else report.warnings).append(
                "MAS_SECRET_KEY قيمة معروفة/ضعيفة — استبدلها في أي بيئة مشتركة"
            )

    # ── 2) مفاتيح مزوّدي النماذج ────────────────────────────────────
    groq = os.getenv("GROQ_API_KEY")
    report.checked.append("GROQ_API_KEY")
    if groq and not groq.startswith("gsk_"):
        report.errors.append("GROQ_API_KEY لا تبدأ بـ «gsk_» — تحقق من نسخ المفتاح")

    for name, prefix in (
        ("OPENAI_API_KEY", "sk-"),
        ("GOOGLE_API_KEY", "AIza"),
        ("ANTHROPIC_API_KEY", "sk-ant-"),
    ):
        value = os.getenv(name)
        report.checked.append(name)
        if value and not value.startswith(prefix):
            report.warnings.append(f"{name} لا تبدأ بـ «{prefix}» — تحقق من الصيغة")

    # ── 3) حساب المدير الافتراضي ────────────────────────────────────
    admin_password = os.getenv("MAS_ADMIN_PASSWORD")
    report.checked.append("MAS_ADMIN_PASSWORD/ADMIN_PASSWORD")
    effective = admin_password or os.getenv("ADMIN_PASSWORD")
    if production and (effective or "admin123").strip().lower() in WEAK_ADMIN_PASSWORDS:
        report.errors.append(
            "كلمة مرور المدير الافتراضية (admin123) في بيئة إنتاج — "
            "اضبط MAS_ADMIN_PASSWORD بكلمة مرور قوية"
        )

    # ── 4) موقع قاعدة البيانات ─────────────────────────────────────
    db_path = os.getenv("DATABASE_PATH", "./data/app.db")
    report.checked.append("DATABASE_PATH")
    if production and ("/tmp" in db_path or db_path.startswith("/var/www") is False and "data" not in db_path):
        report.warnings.append(
            f"DATABASE_PATH='{db_path}' غير معتاد للإنتاج — تأكد أنه على قرص دائم ومحمي"
        )

    # ── 5) CORS في الإنتاج ─────────────────────────────────────────
    report.checked.append("MAS_CORS_ORIGINS")
    if production and not os.getenv("MAS_CORS_ORIGINS"):
        report.warnings.append(
            "MAS_CORS_ORIGINS غير مضبوط — التطبيق يبقي CORS مفتوحاً (مناسب للتطوير فقط)"
        )

    return report


def assert_secrets_or_exit(report: SecretsReport | None = None) -> SecretsReport:
    """يُستدعى عند بدء التطبيق: يطبع الملخص، ويُسقط الإنتاج عند خطأ.

    في التطوير: يكتفي بالتحذير حتى لا يعيق العمل المحلي (سلوك موثق).
    """
    report = report or validate_secrets()
    stream = sys.stderr if report.errors else sys.stdout
    print(report.summary(), file=stream)
    if report.errors and _is_production(report.env):
        raise RuntimeError(
            "أسرار غير آمنة في بيئة إنتاج — أوقف الإقلاع: " + " | ".join(report.errors)
        )
    return report


def load_dotenv_if_present(path: str | Path = ".env") -> bool:
    """تحميل ``.env`` إن وُجد (بلا كسر إن غاب أو غابت python-dotenv)."""
    try:
        from dotenv import load_dotenv  # type: ignore

        return bool(load_dotenv(dotenv_path=path, override=False))
    except Exception:
        return False
