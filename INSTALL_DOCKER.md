# دليل التثبيت والتشغيل بـ Docker — Android Vulnerability Severity MAS

**الإصدار:** 1.0.0 · **المطوّر:** المهندس محمد منير — Engineer Mohammed Moneer
**البريد:** moh123mon456@gmail.com · **GitHub:** [@ko456123mo-jpg](https://github.com/ko456123mo-jpg)

> **Installation & Operations Guide (Docker)** — every step below is numbered so it can be
> followed line by line. Commands are copy-paste ready.
> كل خطوة مرقّمة وقابلة للنسخ حرفياً. الأخطاء الشائعة في §9 (‎١٦ حالة مع الحلول).

---

## 1) المتطلبات (Requirements)

| المتطلب | الأدنى | الموصى به | كيف تتحقق |
|---|---|---|---|
| Docker Engine | **20.10** | 24+ | `docker --version` |
| Docker Compose | **2.0** (الملحق v2) | 2.20+ | `docker compose version` |
| الذاكرة RAM | 4 GB | 8 GB | `free -h` |
| المساحة | 6 GB | 12 GB | `df -h` |
| المعالج | x86_64 / arm64 | 2 vCPU+ | `uname -m` |
| المتصفح | أي حديث | Chrome/Firefox | — |
| شبكة إنترنت | لأول بناء (سحب الصور) | — | `curl -sI https://hub.docker.com` |

**ملاحظة مهمة:** النسخة التجريبية تعمل **كاملة بلا مفاتيح نماذج وبلا إنترنت بعد البناء
الأول** (وضع Mock). تحليل APK حقيقي يحتاج تفعيل MobSF + مزوّد نموذج (§7).

### تثبيت Docker إن لم يكن مثبتاً (Ubuntu/Debian)

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER     # ثم أعد تسجيل الدخول
docker --version && docker compose version
```

**Windows/macOS:** ثبّت **Docker Desktop** (يتضمن Compose v2) ثم تحقق بنفس الأمرين.
**لا تشغّل الأمر بـ sudo** بعد إضافة المستخدم لمجموعة docker.

---

## 2) الحصول على المشروع (Get the code)

```bash
# من الحزمة المضغوطة (المرفقة مع التسليم)
tar -xzf project.tar.gz
cd android-vuln-severity-mas

# أو من GitHub
git clone https://github.com/ko456123mo-jpg/android-vuln-severity-mas.git
cd android-vuln-severity-mas
```

## 3) الإعداد (Configure)

```bash
cp .env.example .env
```

**للتشغيل الأسرع (عرض/تجربة بلا إنترنت):** افتح `.env` واضبط فقط:

```ini
MAS_ENV=development                 # مطلوب للعرض: لا يوقف الإقلاع بلا مفاتيح
LLM_MOCK_MODE=1                     # نماذج لغوية حتمية مزيفة
MCP_MOCK_MODE=1                     # أدوات الفحص مزيفة (بلا JADX/Frida حقيقية)
EMBEDDING_MOCK_MODE=1               # متجهات حتمية بلا تحميل نماذج
```

**للإنتاج (بيانات حقيقية):** املأ على الأقل:

```ini
MAS_ENV=production
MAS_SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
MAS_ADMIN_PASSWORD=<كلمة-مرور-قوية-لك>
MAS_CORS_ORIGINS=https://your-frontend.example.org
GROQ_API_KEY=gsk_...                # أو ANTHROPIC_API_KEY / GOOGLE_API_KEY
MOBSF_API_KEY=<من واجهة MobSF>
```

> ⚠️ بلا `MAS_SECRET_KEY` (≥32 حرفاً) وكلمة مرور قوية، **يرفض النظام الإقلاع في
> `MAS_ENV=production`** — هذا سلوك مقصود ومُختبر (تحقق الأسرار عند البدء).

## 4) البناء (Build)

```bash
docker compose build            # بناء صورتين: mas-api:1.0.0 و mas-ui:1.0.0
# أو عبر Makefile:
make docker-build
```

مدة أول بناء ≈ 3–8 دقائق (حسب الشبكة). البناء يستخدم **multi-stage** (مرحلة بناء ثم
مرحلة تشغيل) والصور تعمل بمستخدم **غير جذري** `app`.

## 5) التشغيل (Up)

```bash
docker compose up -d            # تشغيل الخدمات في الخلفية
make docker-up                  # المكافئ عبر Makefile
```

**ما الذي يُشغَّل؟** (جدول الخدمات كما في `docker-compose.yml`):

| الخدمة | الدور | المنفذ المنشور | ملاحظات |
|---|---|---|---|
| `api` | واجهة REST/MASVS + تقييم الخطورة | **`8000:8000`** | فحص صحة كل 30s على `/health` |
| `ui` | واجهة Streamlit عربية (8 صفحات) | **`8501:8501`** | يبدأ بعد صحة الـ `api` |
| `mobsf` | تحليل APK (MobSF الرسمية) | **`expose: 8000` داخلي فقط** | متعمّد للأمان — لا منفذ للإنترنت (§9-12 لفتحه محلياً) |
| `ollama` | نماذج محلية (اختياري) | `11434:11434` بملف تعريف | `--profile ollama` |

### فتح MobSF محلياً للتصحيح فقط (اختياري)

MobSF غير منشور للإنترنت عن قصد (خدمة تحليل غير محمية). للوصول إليه محلياً:

```bash
docker compose run --rm --service-ports mobsf     # يعمل مؤقتاً على منفذك 8000؟ لا — انظر البديل
```

البديل الموصى به (منفذ منفصل 8001، ويُستخدم للحظات تصحيح):

```bash
cat > docker-compose.override.yml <<'YML'
services:
  mobsf:
    ports:
      - "8001:8000"        # LOCAL DEBUG ONLY — أزل هذا الملف قبل أي نشر
YML
docker compose up -d mobsf
# ⚠️ احذف الملف بعد الانتهاء: rm docker-compose.override.yml
```

## 6) الوصول والتحقق (Access & Verification)

| الوجهة | الرابط | الملاحظة |
|---|---|---|
| واجهة Streamlit (عربية) | http://localhost:8501 | تبدأ الصفحة بتسجيل الدخول |
| توثيق API التفاعلي (Swagger) | http://localhost:8000/docs | 42 نقطة نهاية موثّقة |
| فحص الصحة | http://localhost:8000/health | `{"status":"ok","database":"ok"}` |
| MobSF (اختياري/محلي) | http://localhost:8001 | بعد §5 أعلاه فقط |

**بيانات الدخول التجريبية:** `admin` / `admin123`
> ⚠️ **غيّرها فوراً** قبل أي استخدام غير محلي: اضبط `MAS_ADMIN_PASSWORD` في `.env`
> ثم أعد البذر: `docker compose exec api python scripts/init_db.py --reseed-admin`.

### فحص صحة يدوي (Health checks)

```bash
curl -s http://localhost:8000/health | python -m json.tool
docker compose ps                      # عمود STATUS يظهر (healthy)
docker inspect --format '{{.State.Health.Status}}' $(docker compose ps -q api)
docker compose logs --tail=50 api      # آخر السجلات
```

توقّع أن ترى في سجل الـ api عند الإقلاع:

```
تحقق الأسرار — البيئة: development | فُحص: 8 مفتاحاً
  ✓ لا ملاحظات — الإعداد آمن للإنتاج      (أو تحذيرات التطوير)
Uvicorn running on http://0.0.0.0:8000
```

## 7) تشغيل تحليل حقيقي (اختياري — Real scanning)

1. **مزوّد نموذج:** ضع مفتاحاً واحداً على الأقل (`GROQ_API_KEY` الأسرع مجاناً).
2. **MobSF:** أول تشغيل يولّد مفتاح REST — افتح http://localhost:8001 (بعد §5)
   → `API Docs` → انسخ `REST API KEY` → ضعه في `.env` كـ `MOBSF_API_KEY` ثم
   `docker compose up -d api`.
3. **ارفع APK** من الواجهة (صفحة «رفع وفحص») أو عبر API:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

PROJECT=$(curl -s -X POST http://localhost:8000/projects \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"تجربة Docker","description":"فحص أول"}' | python -c "import sys,json;print(json.load(sys.stdin)['id'])")

APP=$(curl -s -X POST http://localhost:8000/applications/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F project_id=$PROJECT -F name="Demo APK" -F file=@demo.apk | python -c "import sys,json;print(json.load(sys.stdin)['application']['id'])")

curl -s -X POST http://localhost:8000/scans/start \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"application_id\":$APP,\"scan_type\":\"comprehensive\"}" | python -m json.tool
```

4. راقب حتى الحالة النهائية:

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/scans/1/status | python -m json.tool
```

## 8) الإيقاف والتنظيف (Stop & Cleanup)

```bash
docker compose stop                 # إيقاف بلا حذف (استئناف لاحقاً)
docker compose down                 # إيقاف + حذف الحاويات والشبكة (البيانات تبقى في ./data)
docker compose down -v              # ⚠️ حذف الأحجام أيضاً (mobsf_data, ollama_models)
docker compose down --rmi local     # حذف الصور المبنية محلياً

make docker-down                    # المكافئ الأول
```

**نسخ احتياطي (موصى به قبل أي ترقية):**

```bash
docker compose stop api ui
tar czf mas-backup-$(date +%F).tgz data/ results/ .env
docker compose start api ui
```

## 9) استكشاف الأخطاء الشائعة (Troubleshooting — 16 حالة)

| # | العَرَض | السبب | الحل |
|---|---|---|---|
| 1 | `permission denied while trying to connect to the Docker daemon` | المستخدم ليس في مجموعة docker | `sudo usermod -aG docker $USER` ثم أعد الدخول (أو `newgrp docker`) |
| 2 | `port is already allocated` (8000/8501) | خدمة أخرى تستخدم المنفذ | `sudo lsof -i :8000` ثم أوقفها، أو غيّر المنفذ: `MAS_API_PORT=8010 docker compose up -d` |
| 3 | `MAS_SECRET_KEY غير مضبوط` ثم خروج الـ api | `MAS_ENV=production` بلا مفتاح | ولّد مفتاحاً (§3) أو للتجربة `MAS_ENV=development` |
| 4 | الحاوية `unhealthy` بلا سبب واضح | فحص الصحة يفشل | `docker inspect <container> \| grep -A5 Health` و`docker compose logs api` |
| 5 | الواجهة تفتح لكن تسجيل الدخول يفشل | `ui` أعلى من `api` فعلياً أو خطأ بذر | `curl localhost:8000/health` ثم `docker compose exec api python scripts/init_db.py` |
| 6 | `database is locked` | كتابة متزامنة على SQLite | طبيعي تحت الحمل العالي؛ النظام يعيد المحاولة تلقائياً (`retry_on_lock`). لا تحذف `-wal` |
| 7 | الفحوص تبقى `running` للأبد | أداة/MobSF غير متاحة | `docker compose logs api \| grep -i mobsf` — أو للتجربة `MCP_MOCK_MODE=1` |
| 8 | `429 rate_limited` أثناء الاختبار الآلي | حدّ 60/دقيقة | للتطوير فقط: `MAS_RATE_LIMIT_ENABLED=0` (لا تعطّله في الإنتاج) |
| 9 | `docker compose build` يفشل عند جلب الحزم | شبكة/مرآة | أعد المحاولة، أو `docker compose build --no-cache api` |
| 10 | الشعار/الأيقونة لا تظهر في الواجهة | نسخة قديمة من الصورة | `docker compose build ui && docker compose up -d ui` (الصورة تنسخ `assets/logo/`) |
| 11 | `no space left on device` أثناء البناء | مساحة القرص | `docker system prune -af --volumes` (احذر: يحذف ما لا يُستعمل) |
| 12 | الحاجة للوصول إلى MobSF | غير منشور عن قصد | §5 (ملف override مؤقت على 8001) |
| 13 | `x509: certificate signed by unknown authority` | وسيط شبكة/جدار ناري | أوقف اعتراض TLS أو أضف شهادة الجذر للنظام ثم أعد البناء |
| 14 | النتائج لا تُحدَّث في صفحة التقييم | قراءة من `./results` (قراءة فقط) | شغّل: `docker compose exec api python scripts/benchmark.py` |
| 15 | `pull access denied` لصورة MobSF | سحب الصور محجوب | جرّب: `docker pull opensecurity/mobile-security-framework-mobsf:latest` ثم أعد التشغيل |
| 16 | أريد البدء من قاعدة نظيفة | بيانات تجريبية قديمة | `docker compose stop api ui && rm -f data/app.db* && docker compose start api` (يعيد البذر تلقائياً) |

**أوامر تشخيصية سريعة:**

```bash
docker compose ps                     # حالة كل خدمة
docker compose logs -f --tail=100     # متابعة سجلات الكل
docker compose exec api bash          # shell داخل الحاوية (اسم المستخدم app)
docker compose exec api python -c "from db.connection import get_session; print('DB OK')"
docker stats --no-stream              # استهلاك الموارد
```

## 10) قياس الأداء داخل الحاويات (Performance)

```bash
docker compose exec api python scripts/benchmark.py     # → results/benchmark.md
docker compose exec api python scripts/reachability_report.py
docker compose exec api python scripts/final_checklist.py --skip-tests   # 13 بنداً
```

قيم مرجعية معلنة (وضع Mock، تُقرأ كحدود دنيا لا كأرقام إنتاج) في
`results/benchmark.md` و`results/load_test.md`، وحدودها موثّقة داخل التقرير نفسه.

## 11) المتقدمون: بناء يدوي بلا Compose (Advanced)

```bash
docker build -f Dockerfile.api -t mas-api:1.0.0 .
docker run -d --name mas-api -p 8000:8000 \
  --env-file .env -e DATABASE_PATH=/app/data/app.db \
  -v "$PWD/data:/app/data" -v "$PWD/results:/app/results" \
  mas-api:1.0.0
```

## 12) قائمة تحقق ما بعد التثبيت (Post-install checklist)

- [ ] `docker compose ps` → كل الخدمات `running` و`api`/`ui` `healthy`
- [ ] `curl localhost:8000/health` → `status: ok` و`database: ok`
- [ ] تسجيل الدخول `admin` في الواجهة وفتح الصفحات الثمانية
- [ ] رفع APK تجريبي → فحص → ظهور ثغرات وتقييمات
- [ ] تصحيح بشري واحد من صفحة «المراجعة» ثم التحقق من توليد مثال تغذية راجعة
- [ ] تنزيل تقرير (PDF عربي/إنجليزي) من صفحة «التقارير»
- [ ] تغيير `MAS_ADMIN_PASSWORD` و`MAS_SECRET_KEY` قبل أي استخدام حقيقي
- [ ] نسخة احتياطية أولى من `data/`
