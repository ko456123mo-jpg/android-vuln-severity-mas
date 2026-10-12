# ملاحظات النشر / Deployment Notes — v1.0.0

مرجع تشغيلي للنشر عبر Docker والمحلي، مع الأحجام والمنافذ وفحوص الصحة وسياسة
النسخ الاحتياطي. الشقّ الأمني التفصيلي في `docs/security_hardening.md`، ودليل
المستخدم في `docs/user_manual.md`.

---

## 1) نظرة على الطبولوجيا

```
                    ┌──────────────────────────┐
   المستخدم ──HTTPS─►│  عكس وكيل (nginx/…)*     │
                    └───────────┬──────────────┘
                                │ HTTP داخلي
                 ┌──────────────┴───────────────┐
                 │                              │
        ┌────────▼────────┐            ┌────────▼─────────┐
        │  api (FastAPI)  │◄───────────│ ui (Streamlit)   │
        │  :8000          │  HTTP      │ :8501            │
        └───┬─────────┬───┘            └──────────────────┘
            │         │
   ./data ──┘         └──► mobsf (شبكة داخلية فقط، بلا منفذ منشور)
   (SQLite + APK + reports)      └──► ollama (ملف تعريف اختياري)
```
\* عكس الوكيل اختياري لكنه **مستحسن** في الإنتاج: هو من يوفّر TLS وHSTS فعلياً.

---

## 2) النشر بالحاويات (الطريقة الموصى بها)

```bash
cp .env.example .env      # املأ المفاتيح (أو اتركها فارغة لوضع Mock)
make docker-build         # بناء صور api و ui (multi-stage، مستخدم غير جذري)
make docker-up            # تشغيل الخدمات في الخلفية + فحوص صحة
make docker-ps            # الحالة والصحة
make docker-logs          # متابعة السجلات
```

| الخدمة | المنفذ | ملاحظات |
|---|---|---|
| `api` | `8000:8000` | فحص صحة `/health` كل 30 ث (يفحص القاعدة أيضاً) |
| `ui` | `8501:8501` | يتحدث إلى `api` داخلياً (لا `localhost` بين الحاويات) |
| `mobsf` | **`expose` فقط** | متعمد: خدمة تحليل غير مُصدَّرة للإنترنت |
| `ollama` | `--profile ollama` | نماذج محلية؛ يحتاج حجم `ollama_models` |

الأحجام المثبّتة: `./data` (قاعدة + APK + تقارير) و`./results` (مخرجات القياس).
إيقاف وتنظيف:

```bash
make docker-down
docker compose down -v            # يحذف الأحجام (بيانات!) — بحذر
```

### متطلبات الإنتاج (يوقفها النظام إن غابت)

```bash
MAS_ENV=production
MAS_SECRET_KEY=$(python -c 'import secrets;print(secrets.token_urlsafe(48))')
MAS_ADMIN_PASSWORD=<قوية>
MAS_CORS_ORIGINS=https://console.example.org
```
`assert_secrets_or_exit()` يرفع `RuntimeError` عند أي خطأ في هذه القيم في وضع
الإنتاج (وليس تحذيراً) — الاختبارات: `TestSecretsValidation`.

---

## 3) النشر المحلي (بلا حاويات)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
make init-all              # مخطط + بذر + فهرسة RAG
make run-api               # :8000   (uvicorn)
make run-ui                # :8501   (streamlit)
```

للتشغيل بلا أي مفاتيح (عروض/اختبارات): `LLM_MOCK_MODE=1 MCP_MOCK_MODE=1
EMBEDDING_MOCK_MODE=1` (أو استخدم `make test` / `MOCK=1`).

---

## 4) الأحجام والقدرات (قياسات فعلية، وضع Mock)

من `results/benchmark.md` و`results/load_test.md` (كلاهما يصرّح بأنه حدّ أدنى):

| المقياس | القيمة |
|---|---|
| زمن إقلاع + بذر | ≈ 363 ms (seed_users هو الأثقل: bcrypt) |
| محرك التقييم | ≈ 41.5 ألف ثغرة/ث |
| خط فحص كامل (E2E Mock) | ≈ 751 ms · ≈ 37.5 ألف رمز تقديري/تشغيل |
| فهرسة RAG (8 صفوف) | ≈ 21 ms · استعلام ≈ 1.14 ms |
| API: 100 طلب / 10 متوازية | p50 48.8 · p95 89.1 · p99 102.2 ms · نجاح 1.0 |
| إنتاجية الفحص | ≈ 105 فحص/دقيقة (تسلسلياً، Mock) |

**التوسع:** uvicorn عامل واحد هو الافتراضي في الحاوية (توافق SQLite/checkpoints).
للزيادة: عاملان + قاعدة/طابور خارجي (Postgres + Celery/RQ) — خارج نطاق v1.0
(انظر `docs/thesis/limitations_and_future_work.md`).

---

## 5) مراقبة وتشخيص

| ما تراقبه | كيف |
|---|---|
| صحة الخدمة | `curl -s localhost:8000/health` (يقول `degraded` عند فشل القاعدة بلا انهيار) |
| فحوص Docker | أُضيفت `healthcheck` للخدمات؛ `make docker-ps` |
| سجلات الوكلاء | جدول `agent_logs` (كل نداء أداة/LLM: زمن + نجاح + سبب الفشل) |
| محاولات الحقن | `agent_logs.action LIKE 'injection_detected:%'` |
| حدّ المعدل | ترويسات `X-RateLimit-Limit/Remaining` على كل استجابة |
| التجارب | `results/*.json` خام + `results/*.md` مشتقة (لا يكتب التحليل فوق الخام) |

---

## 6) النسخ الاحتياطي والاستعادة

```bash
# احتياط متّسق (أوقف الكتابة أولاً)
docker compose stop api ui
tar czf mas-data-$(date +%F).tgz data/ results/
docker compose start api ui
```
الاستعادة: فكّ الأرشيف ثم `make optimize-db` ثم تحقّق `GET /health`.
القاعدة في وضع **WAL** ⇒ لا تنسخ `app.db` وحدها أثناء الكتابة (انسخ `-wal` أيضاً
أو استخدم الأمر أعلاه).

---

## 7) الترقية والتراجع

- **ترقية:** `git pull` → `make docker-build` → `make docker-up` → `make test`.
  المخطط إضافي/متوافق؛ راجع `CHANGELOG.md` لأي تغيير سلوكي (مثل سياسة تفويض
  الملكية v1.0).
- **تراجع:** الصور الموسومة بالإصدار تسمح بالرجوع: `docker compose up -d <image:v0.x>`
  — لكن **لا تراجع** إن كانت التغييرات تتضمن كتابة صفوف بصيغة جديدة دون ترحيل عكسي.
- سجل القرارات لكل تغيير: `docs/thesis/appendix_c_decision_log.md`.

---

## 8) قائمة تحقق قبل الإنتاج

- [ ] `MAS_ENV=production` + `MAS_SECRET_KEY` (≥32) + `MAS_ADMIN_PASSWORD` قوية + `MAS_CORS_ORIGINS`
- [ ] TLS على عكس الوكيل (HSTS يُرسل عند HTTPS تلقائياً)
- [ ] `python scripts/final_checklist.py` = نجاح كامل
- [ ] نسخة احتياطية أولى + جدولة دورية
- [ ] مراقبة `/health` و`results/final_checklist.md` بعد كل ترقية
- [ ] حدود الموارد (CPU/RAM) على الحاويات + أحجام مخصّصة للـ `data/`
