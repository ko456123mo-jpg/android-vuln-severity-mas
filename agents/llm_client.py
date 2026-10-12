"""عميل LLM موحّد — Hybrid providers (Ollama / Groq / Gemini) + Fallback Chain.

يقرأ التوزيع المعتمد من config/settings.yaml:
    orchestrator → llama3.2:3b            (Ollama محلي)
    extractor    → qwen2.5:14b            (Ollama محلي)
    scorer       → llama-3.3-70b-versatile (Groq API)
    reviewer     → llama-3.3-70b-versatile (Groq API)
    report       → qwen2.5:14b            (Ollama محلي)

الجديد في المرحلة 3: MockLLM — عند LLM_MOCK_MODE=1 تُعاد نماذج وهمية
تنتج JSON واقعياً مطابقاً لمخططات الوكلاء (بلا أي مزوّد خارجي).
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

logger = logging.getLogger("mas.llm")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SETTINGS_PATH = PROJECT_ROOT / "config" / "settings.yaml"

# النموذج الافتراضي لكل مزوّد عند استخدامه كبديل (fallback)
PROVIDER_DEFAULT_MODELS: dict[str, str] = {
    "ollama": "llama3.2:3b",
    "groq": "llama-3.3-70b-versatile",
    "gemini": "gemini-1.5-flash",
}

SUPPORTED_PROVIDERS = tuple(PROVIDER_DEFAULT_MODELS.keys())

PROMPTS_DIR = PROJECT_ROOT / "agents" / "prompts"


def is_llm_mock_mode() -> bool:
    """تفعيل Mock LLM عبر LLM_MOCK_MODE=1 (للاختبارات والـ sandbox)."""
    return os.getenv("LLM_MOCK_MODE", "0") == "1"


# =====================================================================
# MockLLM — نموذج وهمي يعيد JSON واقعياً حسب نوع البرومبت
# =====================================================================
class MockResponse:
    """رد وهمي متوافق مع AIMessage (يملك .content)."""

    def __init__(self, content: str) -> None:
        self.content = content

    def __str__(self) -> str:  # بعض المستهلكين يستخدمون str(resp)
        return self.content


# ثغرات Mock لكل أداة — متسقة مع mock_data الخاص بالمرحلة 2 وقاعدة المعرفة.
# تكرار مقصود بين الأدوات لاختبار الدمج (dedup_fingerprint).
_MOCK_EXTRACTED: dict[str, list[dict[str, Any]]] = {
    "mobsf": [
        {
            "title": "Hardcoded Encryption Key",
            "description": "مفتاح تشفير مضمّن في الكود (CryptoUtil.SECRET_KEY).",
            "evidence": 'private static final String SECRET_KEY = "mysecretkey12345";',
            "masvs_category": "MASVS-CRYPTO",
            "cwe_id": "CWE-321",
            "sub_category": "key_management",
            "discovered_by": "mobsf",
            "is_confirmed": False,
            "confidence": 0.9,
            "location": "com/insecurebank/app/crypto/CryptoUtil.java:9",
        },
        {
            "title": "Weak Cryptography",
            "description": "AES/ECB و MD5 — خوارزميات/أوضاع ضعيفة.",
            "evidence": 'Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");',
            "masvs_category": "MASVS-CRYPTO",
            "cwe_id": "CWE-327",
            "sub_category": "weak_algorithm",
            "discovered_by": "mobsf",
            "is_confirmed": False,
            "confidence": 0.85,
            "location": "com/insecurebank/app/crypto/CryptoUtil.java:14",
        },
        {
            "title": "Insecure Data Storage",
            "description": "auth_token مخزّن كنص صريح في SharedPreferences.",
            "evidence": "editor.putString(\"auth_token\", token);",
            "masvs_category": "MASVS-STORAGE",
            "cwe_id": "CWE-312",
            "sub_category": "shared_prefs",
            "discovered_by": "mobsf",
            "is_confirmed": False,
            "confidence": 0.85,
            "location": "com/insecurebank/app/storage/PrefsManager.java:18",
        },
        {
            "title": "SSL Pinning Missing",
            "description": "لا يوجد Certificate Pinning + cleartext مسموح.",
            "evidence": 'android:usesCleartextTraffic="true"',
            "masvs_category": "MASVS-NETWORK",
            "cwe_id": "CWE-295",
            "sub_category": "tls",
            "discovered_by": "mobsf",
            "is_confirmed": False,
            "confidence": 0.8,
            "location": "AndroidManifest.xml",
        },
        {
            "title": "Exported Components",
            "description": "مكونات exported بدون حماية بأذونات.",
            "evidence": 'activity android:exported="true" LoginActivity + SyncService + SmsReceiver',
            "masvs_category": "MASVS-PLATFORM",
            "cwe_id": "CWE-926",
            "sub_category": "ipc",
            "discovered_by": "mobsf",
            "is_confirmed": False,
            "confidence": 0.8,
            "location": "AndroidManifest.xml",
        },
        {
            "title": "Insecure Logging",
            "description": "Log.d يطبع كلمة مرور المستخدم.",
            "evidence": 'Log.d(TAG, "login attempt user=" + user + " password=" + password);',
            "masvs_category": "MASVS-CODE",
            "cwe_id": "CWE-532",
            "sub_category": "logging",
            "discovered_by": "mobsf",
            "is_confirmed": False,
            "confidence": 0.9,
            "location": "com/insecurebank/app/crypto/CryptoUtil.java:21",
        },
        {
            "title": "Root Detection Absent",
            "description": "لا توجد فحوصات كشف روت.",
            "evidence": "no root checks found in decompiled sources",
            "masvs_category": "MASVS-RESILIENCE",
            "cwe_id": "CWE-919",
            "sub_category": "anti_tamper",
            "discovered_by": "mobsf",
            "is_confirmed": False,
            "confidence": 0.6,
            "location": "global",
        },
        {
            "title": "Weak Authentication",
            "description": "مصادقة محلية بلا قفل حساب أو MFA.",
            "evidence": "onLoginClick: if (password.equals(storedPassword)) grantAccess();",
            "masvs_category": "MASVS-AUTH",
            "cwe_id": "CWE-287",
            "sub_category": "local_auth",
            "discovered_by": "mobsf",
            "is_confirmed": False,
            "confidence": 0.7,
            "location": "com/insecurebank/app/LoginActivity.java:52",
        },
    ],
    "jadx": [
        {
            "title": "Hardcoded Encryption Key",
            "description": "ثابت SECRET_KEY مضمّن داخل CryptoUtil.",
            "evidence": 'private static final String SECRET_KEY = "mysecretkey12345";',
            "masvs_category": "MASVS-CRYPTO",
            "cwe_id": "CWE-321",
            "sub_category": "key_management",
            "discovered_by": "jadx",
            "is_confirmed": False,
            "confidence": 0.75,
            "location": "com/insecurebank/app/crypto/CryptoUtil.java:9",
        },
        {
            "title": "Weak Cryptography",
            "description": "وضع ECB يكشف أنماط النص الصريح.",
            "evidence": 'Cipher.getInstance("AES/ECB/PKCS5Padding")',
            "masvs_category": "MASVS-CRYPTO",
            "cwe_id": "CWE-327",
            "sub_category": "weak_mode",
            "discovered_by": "jadx",
            "is_confirmed": False,
            "confidence": 0.7,
            "location": "com/insecurebank/app/crypto/CryptoUtil.java:14",
        },
        {
            "title": "Insecure Logging",
            "description": "تسجيل كلمة المرور في Logcat.",
            "evidence": 'Log.d(TAG, "login attempt user=" + user + " password=" + password);',
            "masvs_category": "MASVS-CODE",
            "cwe_id": "CWE-532",
            "sub_category": "logging",
            "discovered_by": "jadx",
            "is_confirmed": False,
            "confidence": 0.7,
            "location": "com/insecurebank/app/crypto/CryptoUtil.java:21",
        },
        {
            "title": "Exported Components",
            "description": "LoginActivity/SyncService/SmsReceiver مُصدَّرة بلا أذونات.",
            "evidence": 'Manifest: android:exported="true" ×4 components',
            "masvs_category": "MASVS-PLATFORM",
            "cwe_id": "CWE-926",
            "sub_category": "ipc",
            "discovered_by": "jadx",
            "is_confirmed": False,
            "confidence": 0.7,
            "location": "AndroidManifest.xml",
        },
    ],
    "frida": [
        {
            "title": "Weak Cryptography",
            "description": "رصد Cipher.getInstance(AES/ECB) ومفتاح ثابت أثناء التشغيل.",
            "evidence": "Cipher.getInstance algorithm=AES/ECB/PKCS5Padding (weak: ECB); SecretKeySpec key_hex=6d79736563726574..",
            "masvs_category": "MASVS-CRYPTO",
            "cwe_id": "CWE-327",
            "sub_category": "runtime_confirmation",
            "discovered_by": "frida",
            "is_confirmed": True,
            "confidence": 0.95,
            "location": "com/insecurebank/app/crypto/CryptoUtil.encrypt",
        },
        {
            "title": "Cleartext HTTP Traffic",
            "description": "رصد طلب POST عبر http:// (نص صريح) لـ /login.",
            "evidence": "openConnection POST http://api.insecurebank.com/login (cleartext HTTP) code=200",
            "masvs_category": "MASVS-NETWORK",
            "cwe_id": "CWE-319",
            "sub_category": "cleartext",
            "discovered_by": "frida",
            "is_confirmed": True,
            "confidence": 0.9,
            "location": "runtime:network",
        },
    ],
    "objection": [
        {
            "title": "Insecure Data Storage",
            "description": "auth_token كنص صريح في user_prefs.xml أثناء التشغيل.",
            "evidence": 'user_prefs.xml: auth_token="PLAIN_12345_TOKEN"',
            "masvs_category": "MASVS-STORAGE",
            "cwe_id": "CWE-312",
            "sub_category": "runtime_confirmation",
            "discovered_by": "objection",
            "is_confirmed": True,
            "confidence": 0.95,
            "location": "runtime:shared_prefs",
        },
        {
            "title": "Root Detection Absent",
            "description": "نجح android root disable — كشف الروت غير فعّال.",
            "evidence": "objection> android root disable → (agent) disabled root checks",
            "masvs_category": "MASVS-RESILIENCE",
            "cwe_id": "CWE-919",
            "sub_category": "runtime_confirmation",
            "discovered_by": "objection",
            "is_confirmed": True,
            "confidence": 0.9,
            "location": "runtime:root_detection",
        },
        {
            "title": "SSL Pinning Missing",
            "description": "نجح android sslpinning disable — لا يوجد Pinning فعّال.",
            "evidence": "objection> android sslpinning disable → (agent) pinning disabled",
            "masvs_category": "MASVS-NETWORK",
            "cwe_id": "CWE-295",
            "sub_category": "runtime_confirmation",
            "discovered_by": "objection",
            "is_confirmed": True,
            "confidence": 0.95,
            "location": "runtime:ssl_pinning",
        },
    ],
}


class MockLLM:
    """نموذج وهمي: يعيد JSON واقعياً حسب الوكيل المُميَّز في البرومبت.

    يُفعَّل عبر LLM_MOCK_MODE=1 — يتيح الاختبار الكامل بلا مزوّد خارجي.
    يميّز البرومبت بعلامات Jinja الثابتة في agents/prompts/*.j2.
    """

    def __init__(self, model: str = "mock-llm", temperature: float = 0.0) -> None:
        self.model = model
        self.temperature = temperature

    async def ainvoke(self, prompt: Any, **_kwargs: Any) -> MockResponse:
        return MockResponse(self._respond(str(prompt)))

    def invoke(self, prompt: Any, **_kwargs: Any) -> MockResponse:
        return MockResponse(self._respond(str(prompt)))

    @staticmethod
    def _respond(prompt: str) -> str:
        import json
        import re

        # 1) Orchestrator — برومبت التنسيق يبدأ بـ «أنت وكيل منسق»
        if "أنت وكيل منسق" in prompt:
            lowered = prompt.lower()
            if "فحص ساكن" in prompt or "static scan" in lowered:
                scan_type = "static"
            elif "فحص ديناميكي" in prompt or "dynamic scan" in lowered:
                scan_type = "dynamic"
            else:
                scan_type = "comprehensive"
            sequences = {
                "static": ["jadx", "mobsf"],
                "dynamic": ["frida", "objection"],
                "comprehensive": ["jadx", "mobsf", "frida", "objection"],
            }
            tools_sequence = [
                {"tool": t, "action": "auto", "params": {}}
                for t in sequences[scan_type]
            ]
            return json.dumps(
                {
                    "scan_type": scan_type,
                    "tools_sequence": tools_sequence,
                    "reasoning": (
                        f"mock plan: {scan_type} — static أولاً ثم dynamic "
                        "وفق النوع المطلوب والأدوات المتاحة."
                    ),
                },
                ensure_ascii=False,
            )

        # 2) Extractor — برومبت الاستخراج يبدأ بـ «أنت وكيل استخراج» ويحوي <data tool="X">
        if "أنت وكيل استخراج" in prompt:
            match = re.search(r'tool="(\w+)"', prompt)
            tool = match.group(1) if match else "mobsf"
            vulns = _MOCK_EXTRACTED.get(tool, _MOCK_EXTRACTED["mobsf"])
            return json.dumps(
                {"vulnerabilities": vulns, "injection_attempts_detected": []},
                ensure_ascii=False,
            )

        # 3) Scorer — «أنت وكيل تقييم خطورة»: نعيد أرقام المحرك من <engine_result>
        if "أنت وكيل تقييم خطورة" in prompt:
            match = re.search(r"<engine_result>\s*(\{.*?\})\s*</engine_result>", prompt, re.DOTALL)
            engine: dict[str, Any] = json.loads(match.group(1)) if match else {}
            return json.dumps(
                {
                    "base_score": engine.get("base_score", 0.0),
                    "context_score": engine.get("context_score", 0.0),
                    "confidence_factor": engine.get("confidence_factor", 0.0),
                    "evidence_score": engine.get("evidence_score", 0.0),
                    "final_score": engine.get("final_score", 0.0),
                    "severity": engine.get("severity", "Medium"),
                    "confidence_breakdown": engine.get(
                        "confidence_breakdown",
                        {
                            "tool_count_score": 0.0,
                            "evidence_quality_score": "general",
                            "tool_reliability_avg": 0.0,
                            "reproducibility_score": "not_tested",
                        },
                    ),
                    "reasoning": (
                        "mock: تفسير Scorer — الأرقام محسوبة حتمياً من ScoringEngine؛ "
                        f"الفئة {engine.get('severity', '?')} ناتجة عن الدمج الموزون "
                        "0.6/0.2/0.2 للمكونات الثلاثة وفق severity_rules."
                    ),
                },
                ensure_ascii=False,
            )

        # 4) Reviewer — «أنت وكيل مراجعة لتقييمات»: نعيد القرار من <computed_review>
        if "أنت وكيل مراجعة لتقييمات" in prompt:
            match = re.search(r"<computed_review>\s*(\{.*?\})\s*</computed_review>", prompt, re.DOTALL)
            review: dict[str, Any] = json.loads(match.group(1)) if match else {}
            adjustments = review.get("adjustments", [])
            flag = bool(review.get("requires_human_review", False))
            return json.dumps(
                {
                    "original_score": review.get("original_score", 0.0),
                    "reviewed_score": review.get("reviewed_score", 0.0),
                    "original_severity": review.get("original_severity", "Medium"),
                    "final_severity": review.get("final_severity", "Medium"),
                    "adjustments": [
                        {k: adj[k] for k in ("type", "amount", "reason") if k in adj}
                        for adj in adjustments
                    ],
                    "review_notes": (
                        "mock: ملاحظات Reviewer — "
                        + (
                            f"طُبّق {len(adjustments)} تعديلاً حسب REVIEW_RULES الثابتة. "
                            if adjustments
                            else "لا تعديلات (لم تنطبق أي قاعدة). "
                        )
                        + ("يتطلب مراجعة بشرية." if flag else "لا يتطلب مراجعة بشرية.")
                    ),
                    "requires_human_review": flag,
                },
                ensure_ascii=False,
            )

        # 5) Reporter — «أنت وكيل تقارير»: ملخصات تنفيذية + خطر عام
        if "أنت وكيل تقارير" in prompt:
            match = re.search(r"<vulnerabilities>\s*(\[.*?\])\s*</vulnerabilities>", prompt, re.DOTALL)
            vulns: list[dict[str, Any]] = json.loads(match.group(1)) if match else []
            summaries = []
            for vuln in vulns:
                severity = str(vuln.get("severity", "Medium"))
                timeline = "24-48 ساعة" if severity == "Critical" else "أسبوع"
                summaries.append(
                    {
                        "vulnerability_id": vuln.get("vulnerability_id"),
                        "title_ar": f"ثغرة أمنية بحاجة إلى معالجة عاجلة: {vuln.get('title', '؟')}",
                        "impact_ar": (
                            "mock: احتمال تسريب بيانات المستخدمين أو الإخلال بالامتثال "
                            "والإضرار بسمعة العلامة التجارية."
                        ),
                        "action_ar": (
                            "mock: عزل المكوّن المتأثر وتعطيل مسار الاستغلال فوراً ثم "
                            "إصدار إصلاح."
                            if severity == "Critical"
                            else "mock: جدولة إصلاح عالي الأولوية واختبار التحقق بعده."
                        ),
                        "timeline_ar": timeline,
                    }
                )
            severity_set = {str(v.get("severity", "")) for v in vulns}
            if "Critical" in severity_set:
                risk = "حرج"
            elif "High" in severity_set:
                risk = "مرتفع"
            elif "Medium" in severity_set:
                risk = "متوسط"
            else:
                risk = "منخفض"
            return json.dumps(
                {"executive_summaries": summaries, "overall_risk": risk},
                ensure_ascii=False,
            )

        # 6) Injection detector (اختياري — للمرحلة 5)
        if "كشف حقن" in prompt:
            return json.dumps(
                {"is_injection": False, "patterns_found": [], "reason": "mock"},
                ensure_ascii=False,
            )

        return json.dumps({"status": "ok", "note": "mock-llm"}, ensure_ascii=False)


# =====================================================================
# LLMClient — الواجهة الموحدة
# =====================================================================
class LLMClient:
    """عميل موحّد لبناء نماذج المحادثة حسب الوكيل والمزوّد."""

    def __init__(self, settings_path: str | Path | None = None, load_env: bool = True) -> None:
        if load_env:
            load_dotenv(PROJECT_ROOT / ".env")
        path = Path(settings_path) if settings_path else SETTINGS_PATH
        with open(path, encoding="utf-8") as fh:
            self.settings: dict[str, Any] = yaml.safe_load(fh) or {}
        self.llm_cfg: dict[str, Any] = self.settings.get("llm", {})
        self.ollama_base_url: str = (
            os.getenv("OLLAMA_BASE_URL")
            or (self.settings.get("ollama") or {}).get("base_url")
            or "http://localhost:11434"
        )

    # ------------------------------------------------------------------
    # أدوات مساعدة داخلية / Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _require_key(env_var: str, provider: str) -> str:
        key = os.getenv(env_var)
        if not key:
            raise RuntimeError(
                f"مفتاح API مفقود للمزوّد '{provider}': عيّن المتغير {env_var} في .env"
            )
        return key

    def _build_llm(self, provider: str, model: str, temperature: float) -> Any:
        """بناء نموذج محادثة LangChain لمزوّد معيّن (استيراد كسول)."""
        if provider == "ollama":
            from langchain_ollama import ChatOllama

            return ChatOllama(
                model=model, base_url=self.ollama_base_url, temperature=temperature
            )
        if provider == "groq":
            from langchain_groq import ChatGroq

            return ChatGroq(
                model=model,
                temperature=temperature,
                api_key=self._require_key("GROQ_API_KEY", provider),
            )
        if provider == "gemini":
            from langchain_google_genai import ChatGoogleGenerativeAI

            return ChatGoogleGenerativeAI(
                model=model,
                temperature=temperature,
                google_api_key=self._require_key("GOOGLE_API_KEY", provider),
            )
        raise ValueError(f"مزوّد غير مدعوم / Unsupported provider: {provider}")

    # ------------------------------------------------------------------
    # الواجهة العامة / Public API
    # ------------------------------------------------------------------
    def get_agent_config(self, agent_name: str) -> dict[str, Any]:
        """إعدادات نموذج وكيل معيّن من settings.yaml."""
        cfg = self.llm_cfg.get(agent_name)
        if not cfg:
            raise KeyError(f"لا يوجد إعداد LLM للوكيل '{agent_name}' في settings.yaml")
        return cfg

    def get_llm(self, agent_name: str) -> Any:
        """إرجاع النموذج الأساسي لوكيل معيّن (MockLLM عند LLM_MOCK_MODE=1)."""
        cfg = self.get_agent_config(agent_name)
        if is_llm_mock_mode():
            return MockLLM(model=f"mock:{agent_name}", temperature=float(cfg.get("temperature", 0.0)))
        return self._build_llm(
            provider=cfg["provider"],
            model=cfg["model"],
            temperature=float(cfg.get("temperature", 0.0)),
        )

    def get_llm_with_fallback(self, agent_name: str) -> Any:
        """إرجاع نموذج الوكيل مع سلسلة بدائل (Groq ← Gemini ← Ollama).

        السلوك (مُصلَّب في المرحلة 8 — تحصين ضد انقطاع المزوّد):

        1. عند ``LLM_MOCK_MODE=1`` ⇒ ``MockLLM`` مباشرة (بلا شبكة).
        2. تُجرَّب مزوّدو السلسلة بالترتيب: الأساسي ثم ``fallback_chain``.
           أول مزوّد **يُبنى بنجاح** يصبح الأساسي الحالي، والباقي يُلحَق به
           عبر ``with_fallbacks`` (يتحمّل انقطاعاً زمن التشغيل أيضاً).
        3. إن فشل بناء المزوّد الأساسي (مفتاح/حزمة مفقودة) يُرقّى أول بديل متاح
           إلى الأساسي مع تسجيل السبب في ``self.last_provider_selection`` —
           فلا ينهار النظام لغياب مفتاح واحد.
        4. إن فشلت كل السلسلة ⇒ ``RuntimeError`` برسالة واضحة تسرد المحاولات
           (لا فشل صامت).

        ``self.last_provider_selection`` يُقرأ في اختبارات الفوضى/المرونة والقياس.
        """
        cfg = self.get_agent_config(agent_name)
        temperature = float(cfg.get("temperature", 0.0))
        primary_provider, primary_model = cfg["provider"], cfg["model"]

        if is_llm_mock_mode():
            self.last_provider_selection = {
                "agent": agent_name,
                "selected": "mock",
                "attempts": ["mock: ok"],
                "degraded": False,
            }
            return MockLLM(model=f"mock:{agent_name}", temperature=temperature)

        chain: list[tuple[str, str]] = [(primary_provider, primary_model)]
        for provider in self.llm_cfg.get("fallback_chain", []):
            if provider != primary_provider and provider in PROVIDER_DEFAULT_MODELS:
                chain.append((provider, PROVIDER_DEFAULT_MODELS[provider]))

        attempts: list[str] = []
        built: list[tuple[str, Any]] = []
        for provider, model in chain:
            try:
                built.append(
                    (provider, self._build_llm(provider=provider, model=model, temperature=temperature))
                )
                attempts.append(f"{provider}: ok")
            except Exception as exc:  # مفتاح/حزمة مفقودة — نتخطاه ونسجّل السبب
                attempts.append(f"{provider}: {type(exc).__name__}")
                logger.warning("تعذّر بناء مزوّد %s لوكيل %s: %s", provider, agent_name, exc)

        if not built:
            self.last_provider_selection = {
                "agent": agent_name,
                "selected": None,
                "attempts": attempts,
                "degraded": True,
            }
            raise RuntimeError(
                f"لا مزوّد نماذج متاح للوكيل '{agent_name}' — المحاولات: {attempts}. "
                "اضبط مفتاح مزوّد (GROQ_API_KEY…) أو شغّل LLM_MOCK_MODE=1."
            )

        selected_provider, primary = built[0]
        degraded = selected_provider != primary_provider
        fallbacks = [llm for _provider, llm in built[1:]]
        self.last_provider_selection = {
            "agent": agent_name,
            "selected": selected_provider,
            "requested": primary_provider,
            "attempts": attempts,
            "degraded": degraded,
        }
        if degraded:
            logger.warning(
                "وكيل %s: المزوّد المطلوب %s غير متاح ⇒ العمل بمزوّد البديل %s",
                agent_name, primary_provider, selected_provider,
            )
        if not fallbacks:
            return primary
        return primary.with_fallbacks(fallbacks)

    @property
    def last_provider_selection(self) -> dict[str, Any]:
        """حالة آخر انتقاء مزوّد (تدقيق/اختبارات المرونة) — الافتراضي فارغ."""
        return getattr(self, "_last_provider_selection", {})

    @last_provider_selection.setter
    def last_provider_selection(self, value: dict[str, Any]) -> None:
        """تخزين نتيجة انتقاء المزوّد."""
        self._last_provider_selection = value

    def test_connection(self, provider: str, model: str | None = None) -> dict[str, Any]:
        """اختبار الاتصال بمزوّد (ping رسالة قصيرة) وإرجاع تقرير dict.

        لا يرمي استثناءات أبداً — يعيد ok=False مع وصف الخطأ، ليصلح
        للاستخدام في سكربت الفحص دون إيقاف الباقي.
        """
        model = model or PROVIDER_DEFAULT_MODELS.get(provider, "unknown")
        report: dict[str, Any] = {
            "provider": provider,
            "model": model,
            "ok": False,
            "latency_ms": None,
            "error": None,
        }
        if provider not in SUPPORTED_PROVIDERS:
            report["error"] = f"مزوّد غير مدعوم: {provider}"
            return report
        try:
            llm = self._build_llm(provider=provider, model=model, temperature=0.0)
        except Exception as exc:  # حزمة أو مفتاح مفقود
            report["error"] = f"setup: {exc}"
            return report
        try:
            started = time.perf_counter()
            response = llm.invoke("Reply with exactly: OK")
            report["latency_ms"] = round((time.perf_counter() - started) * 1000)
            report["ok"] = True
            report["response_preview"] = str(getattr(response, "content", response))[:60]
        except Exception as exc:  # فشل الشبكة/الخدمة
            report["error"] = f"invoke: {exc}"
        return report
