"""بيانات Mock واقعية — تُستخدم عند MCP_MOCK_MODE=1.

الهدف: اختبار الخوادم طرف-لطرف في بيئات لا تحتوي الأدوات الحقيقية
(sandbox/CI). البيانات تحاكي تطبيقاً متعمد الثغرات (شبيه DIVA/InsecureBank)
وتتسق مع أنماط knowledge_base المبذورة في المرحلة 1.
"""
from __future__ import annotations

from typing import Any

# =====================================================================
# JADX
# =====================================================================
JADX_PACKAGE = "com.insecurebank.app"

JADX_CLASSES_COUNT = 1240

JADX_SAMPLE_CLASSES = [
    "com/insecurebank/app/LoginActivity.java",
    "com/insecurebank/app/crypto/CryptoUtil.java",
    "com/insecurebank/app/network/ApiClient.java",
    "com/insecurebank/app/storage/PrefsManager.java",
    "com/insecurebank/app/BuildConfig.java",
]

JADX_PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.SEND_SMS",
]

JADX_MANIFEST: dict[str, Any] = {
    "package": JADX_PACKAGE,
    "version_name": "2.1.0",
    "version_code": "21",
    "min_sdk": "23",
    "target_sdk": "30",
    "permissions": JADX_PERMISSIONS,
    "application": {
        "debuggable": True,
        "allow_backup": True,
        "uses_cleartext_traffic": True,
    },
    "exported_components": [
        {"type": "activity", "name": f"{JADX_PACKAGE}.LoginActivity", "exported": True},
        {"type": "activity", "name": f"{JADX_PACKAGE}.SettingsActivity", "exported": True},
        {"type": "service", "name": f"{JADX_PACKAGE}.sync.SyncService", "exported": True},
        {"type": "receiver", "name": f"{JADX_PACKAGE}.receivers.SmsReceiver", "exported": True},
    ],
}

JADX_CLASS_SOURCE = '''package com.insecurebank.app.crypto;

import android.util.Log;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtil {
    // MASVS-CRYPTO: hardcoded key + weak algorithm (mock fixture)
    private static final String SECRET_KEY = "mysecretkey12345";
    private static final String TAG = "CryptoUtil";

    public static String encrypt(String plainText) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // ECB = weak mode
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return android.util.Base64.encodeToString(encrypted, 0);
    }

    public static void login(String user, String password) {
        Log.d(TAG, "login attempt user=" + user + " password=" + password);  // MASVS-CODE
    }
}
'''

JADX_SEARCH_MATCHES: list[dict[str, Any]] = [
    {
        "file": "com/insecurebank/app/crypto/CryptoUtil.java",
        "line": 9,
        "snippet": 'private static final String SECRET_KEY = "mysecretkey12345";',
    },
    {
        "file": "com/insecurebank/app/crypto/CryptoUtil.java",
        "line": 21,
        "snippet": 'Log.d(TAG, "login attempt user=" + user + " password=" + password);',
    },
    {
        "file": "com/insecurebank/app/network/ApiClient.java",
        "line": 34,
        "snippet": 'String url = "http://api.insecurebank.com/login?password=" + password;',
    },
]

# =====================================================================
# MobSF
# =====================================================================
MOBSF_REPORT: dict[str, Any] = {
    "app_name": "InsecureBank (mock)",
    "package_name": JADX_PACKAGE,
    "version_name": "2.1.0",
    "scan_type": "apk",
    "average_cvss": 6.8,
    "security_score": 42,
    "trackers": 1,
    "total_trackers": 432,
    "summary": {"high": 4, "medium": 4, "info": 2, "suppressed": 0},
}

MOBSF_FINDINGS: list[dict[str, Any]] = [
    {
        "title": "Hardcoded Encryption Key",
        "severity": "High",
        "description": "مفتاح تشفير مضمّن في الكود (CryptoUtil.SECRET_KEY).",
        "cwe_id": "CWE-321",
        "masvs_category": "MASVS-CRYPTO",
        "location": "com/insecurebank/app/crypto/CryptoUtil.java:9",
        "evidence_type": "static",
        "tool": "mobsf",
    },
    {
        "title": "Weak Cryptography",
        "severity": "High",
        "description": "AES/ECB و MessageDigest MD5 — خوارزميات/أوضاع ضعيفة.",
        "cwe_id": "CWE-327",
        "masvs_category": "MASVS-CRYPTO",
        "location": "com/insecurebank/app/crypto/CryptoUtil.java:14",
        "evidence_type": "static",
        "tool": "mobsf",
    },
    {
        "title": "Insecure Data Storage",
        "severity": "High",
        "description": "auth_token مخزّن كنص صريح في SharedPreferences.",
        "cwe_id": "CWE-312",
        "masvs_category": "MASVS-STORAGE",
        "location": "com/insecurebank/app/storage/PrefsManager.java:18",
        "evidence_type": "static",
        "tool": "mobsf",
    },
    {
        "title": "SSL Pinning Missing",
        "severity": "High",
        "description": "أحادي الاعتماد على TLS بدون Certificate Pinning + cleartext مسموح.",
        "cwe_id": "CWE-295",
        "masvs_category": "MASVS-NETWORK",
        "location": "AndroidManifest.xml",
        "evidence_type": "static",
        "tool": "mobsf",
    },
    {
        "title": "Exported Components",
        "severity": "Medium",
        "description": "4 مكونات exported بدون حماية بأذونات مخصصة.",
        "cwe_id": "CWE-926",
        "masvs_category": "MASVS-PLATFORM",
        "location": "AndroidManifest.xml",
        "evidence_type": "static",
        "tool": "mobsf",
    },
    {
        "title": "Insecure Logging",
        "severity": "Medium",
        "description": "Log.d يطبع كلمة مرور المستخدم في release.",
        "cwe_id": "CWE-532",
        "masvs_category": "MASVS-CODE",
        "location": "com/insecurebank/app/crypto/CryptoUtil.java:21",
        "evidence_type": "static",
        "tool": "mobsf",
    },
    {
        "title": "Root Detection Absent",
        "severity": "Medium",
        "description": "لا توجد فحوصات كشف روت — يعمل على أجهزة مخترقة.",
        "cwe_id": "CWE-919",
        "masvs_category": "MASVS-RESILIENCE",
        "location": "global",
        "evidence_type": "static",
        "tool": "mobsf",
    },
    {
        "title": "Weak Authentication",
        "severity": "Medium",
        "description": "مصادقة محلية بكلمة مرور بلا قفل حساب أو MFA.",
        "cwe_id": "CWE-287",
        "masvs_category": "MASVS-AUTH",
        "location": "com/insecurebank/app/LoginActivity.java:52",
        "evidence_type": "static",
        "tool": "mobsf",
    },
]

# =====================================================================
# Frida
# =====================================================================
FRIDA_DEVICES: list[dict[str, Any]] = [
    {
        "id": "emulator-5554",
        "name": "Android Emulator 5554 (Android 11, rooted)",
        "type": "usb",
        "state": "attached",
    }
]

FRIDA_CRYPTO_EVENTS: list[dict[str, Any]] = [
    {"event": "Cipher.getInstance", "detail": "algorithm=AES/ECB/PKCS5Padding (weak: ECB)"},
    {"event": "SecretKeySpec.init", "detail": "key_hex=6d797365637265746b65793132333435 (hardcoded)"},
    {"event": "MessageDigest.getInstance", "detail": "algorithm=MD5 (weak)"},
    {"event": "Cipher.doFinal", "detail": "input_len=64 output_len=88"},
]

FRIDA_NETWORK_EVENTS: list[dict[str, Any]] = [
    {"event": "openConnection", "detail": "POST http://api.insecurebank.com/login (cleartext HTTP)"},
    {"event": "Request.Builder.url", "detail": "https://api.insecurebank.com/balance"},
    {"event": "getResponseCode", "detail": "url=http://api.insecurebank.com/login code=200"},
]

FRIDA_HOOK_EVENTS: dict[str, list[dict[str, Any]]] = {
    "ssl_bypass": [
        {"event": "hook.installed", "detail": "SSLContext.init(X509TrustManager)"},
        {"event": "hook.installed", "detail": "okhttp3.CertificatePinner.check -> allowed"},
        {"event": "bypass.active", "detail": "TrustAll manager injected"},
    ],
    "root_bypass": [
        {"event": "hook.installed", "detail": "File.exists -> false for su/magisk paths"},
        {"event": "hook.installed", "detail": "Runtime.exec('su') blocked (returns false)"},
        {"event": "hook.installed", "detail": "PackageManager.getPackageInfo(superuser) hidden"},
    ],
    "crypto_trace": FRIDA_CRYPTO_EVENTS,
    "network_trace": FRIDA_NETWORK_EVENTS,
}

# =====================================================================
# Objection
# =====================================================================
OBJECTION_STORAGE: dict[str, Any] = {
    "package": JADX_PACKAGE,
    "data_dirs": {
        "files": f"/data/data/{JADX_PACKAGE}/files",
        "shared_prefs": f"/data/data/{JADX_PACKAGE}/shared_prefs",
        "databases": f"/data/data/{JADX_PACKAGE}/databases",
        "external": f"/sdcard/Android/data/{JADX_PACKAGE}/files",
    },
    "shared_prefs": {
        "user_prefs.xml": {
            "username": "admin@local",
            "auth_token": "PLAIN_12345_TOKEN",  # MASVS-STORAGE (mock evidence)
        }
    },
    "databases": [{"name": "cache.db", "size_bytes": 12288}],
    "plaintext_secrets_found": ["auth_token"],
}

OBJECTION_KEYSTORE_ITEMS: list[dict[str, Any]] = [
    {"alias": "bank_signing_key", "type": "PrivateKeyEntry", "created": "2024-01-15"},
    {"alias": "api_hmac_key", "type": "SecretKeyEntry", "created": "2024-03-02"},
]

OBJECTION_ACTIVITIES: list[str] = [
    f"{JADX_PACKAGE}.LoginActivity",
    f"{JADX_PACKAGE}.MainActivity",
    f"{JADX_PACKAGE}.SettingsActivity",
    f"{JADX_PACKAGE}.TransferActivity",
]
