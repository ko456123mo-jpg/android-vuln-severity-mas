# 🔌 تصميم خوادم MCP / MCP Servers Design (Phase 2)

أربعة خوادم FastMCP (stdio) تغلّف أدوات التحليل الأمني، مع طبقة مشتركة
(FastMCP base + process runner + Artifact Store + عقود Pydantic) ومدير موحّد.

## نظرة عامة / Overview

```
الوكيل (المرحلة 3+)
   │  MCP stdio / streamable_http
   ▼
mcp_servers/manager.py  ── MultiServerMCPClient (موحّد)
   ├── jadx_server    (static)   decompile · get_manifest · search_code · get_class · list_permissions
   ├── mobsf_server   (static)   upload_apk · start_scan · get_report · get_findings
   ├── frida_server   (dynamic)  list_devices · spawn_app · run_hook · capture_crypto · capture_network
   └── objection_server (dynamic) explore_storage · dump_keystore · bypass_pinning · root_bypass · list_activities
                            + healthcheck (تلقائية في كل خادم من BaseMCPServer)
```

## المكتبة المشتركة / Common layer

| الملف | الدور |
|------|------|
| `common/base_server.py` | BaseMCPServer: تسجيل الأدوات، healthcheck تلقائية، audit اختياري لـ agent_logs (`MCP_DB_LOGGING=1`) |
| `common/process_runner.py` | run_command: timeout يقتل مجموعة العملية (start_new_session + killpg)، retries بانتظار أسّي، يرجع `{exit_code, stdout, stderr, duration_ms, timed_out, attempts}` |
| `common/artifact_store.py` | حفظ المخرجات الضخمة كـ JSON → ref نسبي `scan_id/tool_ts_hash.json`؛ حماية من path traversal؛ list_artifacts |
| `common/schemas.py` | عقود Pydantic Input/Output لكل أداة (Output Validation قبل الوصول للوكلاء) |
| `common/mock_data.py` | بيانات Mock واقعية (تطبيق com.insecurebank.app متعمد الثغرات — متسقة مع seed KB) |

## Mock Mode

فعّله بـ `MCP_MOCK_MODE=1`. في Mock Mode لا يلزم وجود jadx/MobSF/frida/objection:
يعيد كل wrapper بيانات `mock_data` ويخزّنها فعلياً عبر ArtifactStore — أي أن
مسار ref → load حقيقي تماماً. يُقرأ عند كل استدعاء (يمكن تبديله ديناميكياً).

```bash
MCP_MOCK_MODE=1 python -m pytest tests/unit/test_mcp_servers.py -v
```

## أمثلة استدعاء / Usage examples

```python
# JADX (استيراد مباشر — أو تُستدعى عبر MCP client في المرحلة 3)
from mcp_servers.jadx_server.server import decompile, search_code
out = decompile(apk_path="/data/apks/app.apk")
# {"success": true, "artifact_ref": "apk_1a2b3c4d/jadx_....json", "classes_count": 1240}
out = search_code(apk_path="/data/apks/app.apk", keyword="password", max_results=20)

# MobSF flow
from mcp_servers.mobsf_server.server import upload_apk, start_scan, get_report, get_findings
h = upload_apk("/data/apks/app.apk")["scan_hash"]
s = start_scan(h)["scan_id"]
ref = get_report(s)["artifact_ref"]          # التقرير الضخم كمرجع
findings = get_findings(s, severity_filter="high")["findings"]

# Frida flow
from mcp_servers.frida_server.server import spawn_app, capture_crypto, run_hook
sid = spawn_app("com.example.app")["session_id"]
crypto_ref = capture_crypto(sid, duration=30)["artifact_ref"]
hook = run_hook(sid, "ssl_bypass", duration=15)

# Objection flow
from mcp_servers.objection_server.server import explore_storage, bypass_pinning
storage_ref = explore_storage("com.example.app")["artifact_ref"]
pinned = bypass_pinning("com.example.app")["bypassed"]  # False ⇒ pinning موجود فعلاً
```

## العميل الموحّد / Unified client (للمرحلة 3)

```python
from mcp_servers.manager import MCPManager
client = MCPManager().get_mcp_client()   # MultiServerMCPClient لكل الخوادم
tools = await client.get_tools()         # تُمرَّر إلى وكلاء LangChain
```

## التشغيل محلياً بالأدوات الحقيقية / Real tools setup

| الأداة | التثبيت | ملاحظات |
|--------|---------|---------|
| JADX | `brew install jadx` أو تنزيل release من GitHub (jadx-1.5.x) | المتغير `JADX_BIN` للمسار المخصص |
| MobSF | `docker compose up -d mobsf` ثم استخراج API key من واجهة http://localhost:8000 | `MOBSF_URL` + `MOBSF_API_KEY` في .env |
| Frida | `pip install frida-tools` + `frida-server` على AVD مروّت (Android 11) | يُشغَّل frida-server عبر adb مع صلاحية root |
| Objection | `pip install objection` | يحتاج frida-server نفسه (مبني فوق Frida)؛ `OBJECTION_BIN` للتخصيص |

ملاحظة: Objection يشغّل التطبيق بنفسه عبر `objection -g <pkg> explore --startup-command ...`
فلا يحتاج جلسة Frida منفصلة.

## قرارات تصميمية (Phase 2) / Design decisions

1. **artifact refs بدلاً من النص الكامل** — منع إرسال 30k سطر للـ LLM؛ الوكيل يسترجع ما يحتاجه.
2. **whitelist للسكربتات** — `run_hook` يقبل فقط ملفات `.js` الموجودة فعلياً في `frida_server/scripts/` (لا مسارات حرة).
3. **أخطاء موحّدة** — كل أداة تعيد `success=false + error` بدل رمي استثناءات عبر MCP.
4. **audit اختياري** — تسجيل الاستدعاءات في `agent_logs` معطّل افتراضياً في المرحلة 2 (`MCP_DB_LOGGING=1` لتفعيله).
5. **santization للمراجع** — ArtifactStore يرفض أي ref يخرج خارج base_dir (path traversal).
