"""بذر البيانات الأولية — Database seeding (idempotent).

يدرج / Seeds:
    1. مستخدم admin (كلمة مرور مشفّرة بـ bcrypt)
    2. الأدوات الخمس (tools) — jadx / mobsf / frida / objection / apktool
    3. قاعدة severity_rules النشطة (version="v1.0")
    4. ثمانية أنماط في knowledge_base (MASVS)

Safe to run multiple times: يتخطى السجلات الموجودة.
"""
from __future__ import annotations

import bcrypt
from sqlalchemy import func, select

from db.connection import get_session
from db.models import KnowledgeBase, SeverityRule, Tool, User

# ---------------------------------------------------------------------
# 1) المستخدم الافتراضي / Default admin user
# ---------------------------------------------------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
ADMIN_ROLE = "admin"

# ---------------------------------------------------------------------
# 2) الأدوات الخمس / The five security tools
# ---------------------------------------------------------------------
TOOLS: list[dict] = [
    {
        "name": "jadx",
        "version": "1.5.0",
        "category": "static",
        "reliability_score": 0.70,
        "mcp_endpoint": "stdio://jadx",
        "capabilities": ["decompile", "get_manifest", "search_code", "get_class"],
    },
    {
        "name": "mobsf",
        "version": "4.5.1",
        "category": "static",
        "reliability_score": 0.90,
        "mcp_endpoint": "http://localhost:8000",
        "capabilities": ["upload", "start_scan", "get_report", "get_findings"],
    },
    {
        "name": "frida",
        "version": "17.0.0",
        "category": "dynamic",
        "reliability_score": 1.00,
        "mcp_endpoint": "stdio://frida",
        "capabilities": ["spawn_app", "run_hook", "capture_crypto", "capture_network"],
    },
    {
        "name": "objection",
        "version": "1.11.0",
        "category": "dynamic",
        "reliability_score": 0.85,
        "mcp_endpoint": "stdio://objection",
        "capabilities": ["explore_storage", "dump_keystore", "bypass_pinning", "root_bypass"],
    },
    {
        "name": "apktool",
        "version": "2.9.0",
        "category": "static",
        "reliability_score": 0.60,
        "mcp_endpoint": "stdio://apktool",
        "capabilities": ["decode", "build", "extract_manifest"],
    },
]

# ---------------------------------------------------------------------
# 3) قواعد التقييم بنسختين / Severity rules (versioned)
#    ملاحظة: كتلة "confidence" تُخزَّن داخل عمود thresholds (JSON موحّد)
#    لأن المخطط يحتوي ثلاثة أعمدة JSON فقط (weights/context_params/thresholds).
#
#    v1.0: الأوزان + معاملات السياق + العتبات (بلا masvs_weights).
#    v1.1: تضيف جدول masvs_weights صراحةً داخل context_params (مصدر أوزان
#          base_score في core/scoring/base_score.py) — تُفعَّل وحدها.
#    القاعدة الذهبية: لا يُعدَّل إصدار قديم أبداً؛ الإصلاحات = إصدار جديد.
# ---------------------------------------------------------------------
_MASVS_WEIGHTS: dict = {
    "MASVS-CRYPTO": 9.0,
    "MASVS-STORAGE": 8.0,
    "MASVS-NETWORK": 7.5,
    "MASVS-AUTH": 7.0,
    "MASVS-PLATFORM": 6.0,
    "MASVS-RESILIENCE": 5.0,
    "MASVS-CODE": 4.0,
}

_CONTEXT_PARAMS: dict = {
    "data_sensitivity": {"LOW": 3, "MEDIUM": 6, "HIGH": 10},
    "industry": {"banking": 10, "health": 10, "commerce": 7, "game": 5, "utility": 6},
    "user_base_size": {"small": 4, "medium": 6, "large": 9},
    "internet_facing": {"true": 10, "false": 4},
    "business_criticality": {"LOW": 3, "MEDIUM": 6, "HIGH": 10},
}

SEVERITY_RULE_VERSION = "v1.0"  # الإصدار الأولي — يبقى مسجلاً لأغراض التدقيق
SEVERITY_RULE_PAYLOAD: dict = {
    "weights": {"base": 0.6, "context": 0.2, "evidence": 0.2},
    "context_params": dict(_CONTEXT_PARAMS),
    "thresholds": {
        "critical": 9.0,
        "high": 7.0,
        "medium": 4.0,
        "confidence": {"review_threshold": 0.75, "critical_min": 0.90},
    },
}

# القاعدة النشطة الحالية (تتضمن جدول MASVS الصريح)
SEVERITY_RULE_V11_PAYLOAD: dict = {
    "weights": {"base": 0.6, "context": 0.2, "evidence": 0.2},
    "context_params": {**_CONTEXT_PARAMS, "masvs_weights": dict(_MASVS_WEIGHTS)},
    "thresholds": {
        "critical": 9.0,
        "high": 7.0,
        "medium": 4.0,
        "confidence": {
            "review": 0.75,
            "review_threshold": 0.75,  # توافقية مع مفتاح v1.0
            "critical_min": 0.90,
        },
    },
}

# (version, payload, active) — النشطة واحدة فقط
SEVERITY_RULE_VERSIONS: list[tuple[str, dict, bool]] = [
    ("v1.0", SEVERITY_RULE_PAYLOAD, False),
    ("v1.1", SEVERITY_RULE_V11_PAYLOAD, True),
]

# ---------------------------------------------------------------------
# 4) أنماط knowledge_base (MASVS)
# ---------------------------------------------------------------------
KB_PATTERNS: list[dict] = [
    {
        "ref_id": "MSTG-NETWORK-3",
        "title": "SSL Pinning Missing",
        "cwe_id": "CWE-295",
        "masvs_category": "MASVS-NETWORK",
        "content": "التطبيق لا يطبق SSL Pinning — قناة TLS معرضة لهجمات MITM.",
    },
    {
        "ref_id": "MSTG-CRYPTO-1",
        "title": "Hardcoded Encryption Key",
        "cwe_id": "CWE-321",
        "masvs_category": "MASVS-CRYPTO",
        "content": "مفتاح تشفير مضمّن في الكود — يمكن استخراجه بتحليل ساكن.",
    },
    {
        "ref_id": "MSTG-STORAGE-1",
        "title": "Insecure Data Storage",
        "cwe_id": "CWE-312",
        "masvs_category": "MASVS-STORAGE",
        "content": "تخزين بيانات حساسة كنص صريح في SharedPreferences أو قواعد محلية.",
    },
    {
        "ref_id": "MSTG-RESILIENCE-1",
        "title": "Root Detection Absent",
        "cwe_id": "CWE-919",
        "masvs_category": "MASVS-RESILIENCE",
        "content": "غياب كشف الروت — التطبيق يعمل على أجهزة مخترقة دون حماية.",
    },
    {
        "ref_id": "MSTG-CRYPTO-4",
        "title": "Weak Cryptography",
        "cwe_id": "CWE-327",
        "masvs_category": "MASVS-CRYPTO",
        "content": "استخدام خوارزميات ضعيفة (MD5, DES) — يجب استبدالها بمعايير حديثة.",
    },
    {
        "ref_id": "MSTG-CODE-3",
        "title": "Insecure Logging",
        "cwe_id": "CWE-532",
        "masvs_category": "MASVS-CODE",
        "content": "تسريب بيانات حساسة في السجلات (Logcat) — يجب إزالتها من الإصدار النهائي.",
    },
    {
        "ref_id": "MSTG-PLATFORM-1",
        "title": "Exported Components",
        "cwe_id": "CWE-926",
        "masvs_category": "MASVS-PLATFORM",
        "content": "مكونات مُصدَّرة (Activities/Services/Receivers) بدون حماية بأذونات.",
    },
    {
        "ref_id": "MSTG-AUTH-1",
        "title": "Weak Authentication",
        "cwe_id": "CWE-287",
        "masvs_category": "MASVS-AUTH",
        "content": "ضعف في المصادقة — آليات تحقق غير كافية يمكن تجاوزها.",
    },
]
KB_SOURCE = "MASVS"
KB_VERSION = "v1.0"


def _hash_password(password: str) -> str:
    """تشفير كلمة المرور بـ bcrypt (آمن، مع salt عشوائي)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


# ---------------------------------------------------------------------
# باذرات منفصلة — Idempotent seeders
# ---------------------------------------------------------------------
def seed_users() -> dict[str, int]:
    """إدراج مستخدم admin إن لم يكن موجوداً."""
    with get_session() as session:
        exists = session.scalar(select(User).where(User.username == ADMIN_USERNAME))
        if exists:
            return {"inserted": 0, "skipped": 1}
        session.add(
            User(
                username=ADMIN_USERNAME,
                password_hash=_hash_password(ADMIN_PASSWORD),
                role=ADMIN_ROLE,
            )
        )
        return {"inserted": 1, "skipped": 0}


def seed_tools() -> dict[str, int]:
    """إدراج الأدوات الخمس (تخطّي الموجود بالاسم)."""
    inserted = skipped = 0
    with get_session() as session:
        existing = set(session.scalars(select(Tool.name)).all())
        for tool in TOOLS:
            if tool["name"] in existing:
                skipped += 1
                continue
            session.add(Tool(**tool, enabled=True))
            inserted += 1
    return {"inserted": inserted, "skipped": skipped}


def seed_severity_rules() -> dict[str, int]:
    """إدراج إصدارات severity_rules (v1.0 + v1.1) مع صف نشط واحد فقط.

    Idempotent: الإصدارات الموجودة تُتخطَّى بلا تعديل؛ وأعلام التنشيط
    تُضبط دائماً وفق SEVERITY_RULE_VERSIONS (v1.1 نشطة وحدها حالياً).
    """
    inserted = skipped = activated = 0
    with get_session() as session:
        for version, payload, active in SEVERITY_RULE_VERSIONS:
            rule = session.scalar(
                select(SeverityRule).where(SeverityRule.version == version)
            )
            if rule is None:
                session.add(
                    SeverityRule(
                        version=version,
                        weights=payload["weights"],
                        context_params=payload["context_params"],
                        thresholds=payload["thresholds"],
                        active=active,
                    )
                )
                inserted += 1
            else:
                skipped += 1
                if rule.active != active:
                    rule.active = active
                    activated += 1
        session.flush()
    return {"inserted": inserted, "skipped": skipped, "re_activated": activated}


def seed_knowledge_base() -> dict[str, int]:
    """إدراج الأنماط الثمانية (تخطّي الموجود بـ ref_id)."""
    inserted = skipped = 0
    with get_session() as session:
        existing = set(session.scalars(select(KnowledgeBase.ref_id)).all())
        for pattern in KB_PATTERNS:
            if pattern["ref_id"] in existing:
                skipped += 1
                continue
            session.add(KnowledgeBase(source=KB_SOURCE, version=KB_VERSION, **pattern))
            inserted += 1
    return {"inserted": inserted, "skipped": skipped}


# ---------------------------------------------------------------------
# نقطة التشغيل الرئيسية / Main entry
# ---------------------------------------------------------------------
def run_seed() -> dict[str, dict[str, int]]:
    """تشغيل كل الباذرات وإرجاع ملخص لكل جدول."""
    summary = {
        "users": seed_users(),
        "tools": seed_tools(),
        "severity_rules": seed_severity_rules(),
        "knowledge_base": seed_knowledge_base(),
    }
    return summary


def table_counts() -> dict[str, int]:
    """عدد الصفوف الحالي في الجداول المبذورة."""
    with get_session() as session:
        return {
            "users": session.scalar(select(func.count(User.id))) or 0,
            "tools": session.scalar(select(func.count(Tool.id))) or 0,
            "severity_rules": session.scalar(select(func.count(SeverityRule.id))) or 0,
            "knowledge_base": session.scalar(select(func.count(KnowledgeBase.id))) or 0,
        }


def main() -> None:
    print("=" * 60)
    print("🌱 بذر البيانات الأولية / Seeding initial data")
    print("=" * 60)
    summary = run_seed()
    for table, result in summary.items():
        print(
            f"  • {table:<15} أُدرج/inserted={result['inserted']}"
            f"، موجود/s skipped={result['skipped']}"
        )
    counts = table_counts()
    print("-" * 60)
    print("📊 عدد الصفوف الحالي / Current row counts:")
    for table, count in counts.items():
        print(f"  • {table:<15} = {count}")
    print("✅ اكتمل البذر / Seeding done.")


if __name__ == "__main__":
    main()
