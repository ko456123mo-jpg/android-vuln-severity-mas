# مرجع API — Android Vuln Severity MAS v1.0.0 (المرحلة 6)

> المرجع الكامل لـ **42 نقطة نهاية** عبر 9 موجّهات + فحص الصحة.
> Swagger تفاعلي: `http://localhost:8000/docs` · ReDoc: `/redoc` · المخطط: `/openapi.json`

## التشغيل والوصول

```bash
python scripts/run_api.py --port 8000        # أو: make run-api
curl http://localhost:8000/health
```

القاعدة الافتراضية: `data/app.db` (تتجاوزها `DATABASE_PATH`)، والمستخدم المزروع
`admin / admin123`.

## المصادقة (JWT كامل — بلا مستخدم مُثبَّت)

- **الخوارزمية**: HS256 عبر `python-jose`؛ المفتاح من `config/settings.yaml → auth.secret_key`
  (يتجاوزها `MAS_SECRET_KEY` في البيئة — إلزامي في النشر).
- **كلمات المرور**: bcrypt خام — *قرار موثق*: `passlib 1.7.4` غير متوافق مع
  `bcrypt ≥ 4` (خطأ قراءة `__about__` وقيد 72 بايت)، لذا تُستخدم دوال bcrypt
  مباشرة بنفس صيغة `db/seed.py`؛ الواجهة العامة (`hash_password` /
  `verify_password`) مطابقة لعقد passlib.
- **حمل التوكن**: `sub=str(users.id)` + username + role، صلاحية 60 دقيقة
  (`auth.access_token_expire_minutes`). يُعاد قراءة المستخدم من القاعدة في كل
  طلب — تعطيل فوري للحسابات المحذوفة.
- **التمرير**: `Authorization: Bearer <token>` على كل المسارات المحمية
  (كل الموجّهات عدا `/auth/login` و`/health`).
- **الأدوار**: `admin | analyst | reviewer`؛ `/auth/register` حصراً للأدمن.

### التفويض وحدود المعدل والترويسات (المرحلة 8)

- **سلسلة الملكية**: `project ← application ← scan ← vulnerability ← assessment`.
  السياسة الكاملة في `docs/security_hardening.md §3` و`api/authz.py`:
  **admin** كل شيء · **owner** موارده · **reviewer** حلقة المراجعة · **analyst** موارده
  فقط · مورد بلا مالك ⇒ **مرفوض** لغير admin (fail-closed).
- **403** لمورد موجود لا يملكه المستخدم، و**404** لمورد غير موجود.
- **القوائم مصفّاة** لغير admin (`/projects`, `/applications`, `/scans`).
- **admin-only**: `/dashboard/*` (تجميعات نظام) و`POST /auth/register`.
- **admin/reviewer-only**: `/reviews/pending|stats`, `/assessments` (قائمة الفرز)
  و`/assessments/stats`. و`/reviews/{id}` و`POST /reviews/{id}/correct`:
  admin/reviewer، أو مالك سلسلة التقييم.
- **حدّ المعدل**: 60 طلباً/دقيقة لكل IP (`MAS_RATE_LIMIT_PER_MINUTE`)؛
  `/health` و`OPTIONS` ومسارا الوثائق معفاة؛ التجاوز ⇒ **429** + `Retry-After`
  (تعطيل صريح للاختبارات: `MAS_RATE_LIMIT_ENABLED=0`).
- **ترويسات الأمن** على كل استجابة (بما فيها 4xx/5xx/429): `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`,
  `Permissions-Policy`, `Content-Security-Policy: default-src 'none'…`;
  و`Strict-Transport-Security` في الإنتاج/HTTPS فقط.
- **الأخطاء الموحّدة**: استجابات 500 لا تحمل أي تفاصيل داخلية (SQL/traceback)،
  والتفاصيل الكاملة تُسجَّل في سجل الخادم فقط — مُختبر في `tests/security/test_security.py`.

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s http://localhost:8000/auth/me -H "Authorization: Bearer $TOKEN"
```

## صيغة الأخطاء الموحّدة

| الحالة | الشكل | المصدر |
|---|---|---|
| 401/403/404/409/413 | `{"detail": "...", "error": "http_error"}` | معالج StarletteHTTPException |
| 422 | `{"detail": [{...Pydantic...}], "error": "validation_error"}` | معالج RequestValidationError |
| 500 | `{"detail": "خطأ داخلي في الخادم", "error": "internal_error"}` | معالج عام (بلا تسريب داخلي) |

---

## 1) Auth — `/auth` (4)

| Method | Path | الوظيفة |
|---|---|---|
| POST | `/auth/login` | دخول → `{access_token, token_type, user}` |
| POST | `/auth/register` | إنشاء مستخدم (admin فقط) |
| GET | `/auth/me` | المستخدم الحالي |
| POST | `/auth/logout` | خروج منطقي (JWT stateless — العميل يحذف التوكن) |

```bash
curl -X POST http://localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'
# → {"access_token":"eyJ…","token_type":"bearer","user":{"id":1,"username":"admin","role":"admin","email":null}}

curl -X POST http://localhost:8000/auth/register -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"analyst2","password":"AnalystPass1","role":"analyst"}'
# → 201 {"id":2,…} · اسم مكرر → 409 · دور غير admin → 403 · دور غير صالح → 422
```

**مخططات**: `LoginInput{username≥3, password≥8}` · `UserOut{id,username,role,email}` ·
`TokenResponse{access_token,token_type,user}` · `RegisterInput{username,password,role∈{admin,analyst,reviewer},email?}`.

## 2) Projects — `/projects` (5)

| Method | Path | الوظيفة |
|---|---|---|
| GET | `/projects` | سرد — فلاتر: `owner_id`, `status`, `include_archived` (الافتراضي النشِطة فقط) |
| POST | `/projects` | إنشاء (المالك = المستخدم الحالي) → 201 |
| GET | `/projects/{id}` | تفاصيل + `stats{applications,scans,vulnerabilities}` |
| PUT | `/projects/{id}` | تعديل جزئي (المُمرَّر فقط) |
| DELETE | `/projects/{id}` | **حذف ناعم** → `status='archived'` |

```bash
curl -X POST http://localhost:8000/projects -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"Test Project"}'
# → 201 {"id":3,"name":"Test Project","owner_username":"admin","status":"active",
#         "stats":{"applications":0,"scans":0,"vulnerabilities":0}}
```

**سبب الحذف الناعم**: الأرشفة تحفظ سلامة FKs (تطبيقات/فحوص/ثغرات) وتُخفي المشروع من السرد الافتراضي.

## 3) Applications — `/applications` (6)

| Method | Path | الوظيفة |
|---|---|---|
| GET | `/applications` | سرد — فلتر `project_id`, `limit` |
| POST | `/applications/upload` | رفع APK (multipart): SHA-256 + تخزين + منع التكرار |
| GET | `/applications/{id}` | تفاصيل + `app_context` + `stats` |
| PUT | `/applications/{id}/context` | تحديث السياق (+ إعادة حساب `context_score`) |
| GET | `/applications/{id}/scans` | فحوص التطبيق |
| DELETE | `/applications/{id}` | حذف (ملف + صف) — **409 إن وُجدت فحوص** |

```bash
curl -X POST http://localhost:8000/applications/upload -H "Authorization: Bearer $TOKEN" \
  -F project_id=3 -F name="InsecureBank" -F package_name=com.insecurebank.app \
  -F file=@/path/app.apk
# → 201 {"created":true,"deduplicated":false,"application":{"sha256":"…64hex…", …}}
# إعادة نفس الملف → 200 {"created":false,"deduplicated":true,"application":{…existing…}}

curl -X PUT http://localhost:8000/applications/1/context -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data_sensitivity":"HIGH","industry":"banking","user_base_size":"large",
       "internet_facing":true,"business_criticality":"HIGH"}'
# → {"context_score":8.1, …}   (محسوبة بمحرك المرحلة 4: calculate_context_score)
```

- التخزين: `data/apks/<sha256>.apk`؛ سقف 300MB (413)، امتداد `.apk` إلزامي (400)، ملف فارغ (400).
- `app_context` محصور بقيم فحص القاعدة (`LOW/MEDIUM/HIGH`, `banking|health|commerce|game|utility`, `small|medium|large`).
- لا يُحلَّل APK في هذه النقطة (package_name/version اختياريان ضمن النموذج) — التحليل مهمة أدوات MCP.

## 4) Scans — `/scans` (7)

| Method | Path | الوظيفة |
|---|---|---|
| GET | `/scans` | سرد — فلاتر `application_id`, `status`, `limit` |
| POST | `/scans/start` | بدء فحص **Background Task** → 202 `{scan_id, status:"pending"}` |
| GET | `/scans/{id}` | تفاصيل + إحصاءات + آخر إجراء مسجَّل |
| GET | `/scans/{id}/status` | **polling**: الحالة + `progress_percent` + الوكيل/الإجراء الحالي |
| GET | `/scans/{id}/vulnerabilities` | ثغرات الفحص + ملخص التقييم والأدلة |
| GET | `/scans/{id}/assessments` | تقييمات ثغرات الفحص |
| DELETE | `/scans/{id}` | إلغاء (معلّق/جارٍ فقط — وإلا 409) |

```bash
curl -X POST http://localhost:8000/scans/start -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"application_id":1,"scan_type":"comprehensive"}'
# → 202 {"scan_id":5,"status":"pending","scan_type":"comprehensive","requested_by":"admin"}

curl -s "http://localhost:8000/scans/5/status" -H "Authorization: Bearer $TOKEN"
# → {"scan_id":5,"status":"running","progress_percent":46,"current_agent":"scorer",
#    "current_action":"score_batch","started_at":"…","total_tokens":0,"error_message":null}
```

**قرارات موثقة**:
- خط الأنابيب يعمل في threadpool (دالة متزامنة + `asyncio.run`) لتفريغ حلقة الأحداث فوراً —
  والنمط نفسه المعتمد في اختبارات المرحلتين 3–5 (بناء الرسم داخل حلقة التشغيل).
- `progress_percent`: pending=5 · running=10→95 (حسب ترتيب المراحل في `agent_logs`) · نهائي=100.
- **الإلغاء** = `status='failed'` + `error_message='cancelled by user'` — لأن قيد فحص القاعدة
  `ck_scans_status` لا يتضمن `'cancelled'` ولم نخترع قيمة جديدة؛ يمنع التقاط النتيجة فقط.
- فشل تحميل خط الأنابيب (بيئة بلا نماذج/أدوات) يُسجَّل `failed` مع سبب واضح — لا فشل صامت.

## 5) Findings — `/findings` (3)

| Method | Path | الوظيفة |
|---|---|---|
| GET | `/findings/{vuln_id}` | تفاصيل الثغرة + التطبيق + ملخص الأدلة + التقييم |
| GET | `/findings/{vuln_id}/evidence` | صفوف الأدلة بكل مصدر (tool/category/reliability) |
| GET | `/findings/{vuln_id}/assessment` | التقييم الكامل (المكوّنات + final_score + rationale) |

## 6) Assessments — `/assessments` (3)

| Method | Path | الوظيفة |
|---|---|---|
| GET | `/assessments` | سرد — فلاتر `severity`, `review_status`, `limit` |
| GET | `/assessments/stats` | خطورة + حالات مراجعة + متوسط/أقصى/أدنى درجة |
| GET | `/assessments/{id}` | تفاصيل + الثغرة + **تاريخ تصحيحات HITL كامل** |

```bash
curl -s "http://localhost:8000/assessments/stats" -H "Authorization: Bearer $TOKEN"
# → {"total":9,"severity_distribution":{"Critical":2,"High":5,"Medium":2,"Low":0},
#    "review_status_counts":{"pending":5,"approved":4},
#    "avg_final_score":7.9228,"max_final_score":9.3626,"min_final_score":6.07}
```

> قرار هندسي: `/assessments/stats` و`/reviews/stats` مُعلَنان **قبل** مسارات `/{id}`
> لتفادي ظلّ محوّل المسار (عولجت فعلياً — انظر «أخطاء وحلول»).

## 7) Reviews (HITL) — `/reviews` (4)

| Method | Path | الوظيفة |
|---|---|---|
| GET | `/reviews/pending` | قائمة المعلّقة — فلاتر `limit`, `severity` |
| GET | `/reviews/stats` | pending/approved/rejected + توزيع + عدّادات التصحيحات/الأمثلة |
| GET | `/reviews/{assessment_id}` | تفاصيل تقييم + سجل تصحيحات |
| POST | `/reviews/{assessment_id}/correct` | **تصحيح بشري** → إنشاء feedback_example تلقائياً |

```bash
curl -X POST http://localhost:8000/reviews/2/correct -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"corrected_severity":"Critical","corrected_score":9.7,"reason":"دليل ديناميكي مؤكد"}'
# → {"correction_id":2,"assessment_id":2,"reviewer":"admin","status":"approved"}
```

**ثوابت الحلقة** (المرحلة 5، لا تُنقض): `final_score` **لا يُمَس أبداً**؛ تُحدَّث
`severity` و`review_status='approved'` و`reviewed_by`؛ القيم المصححة تُحفظ في
`corrections`؛ ويُولَّد `feedback_examples` نشط فوراً. رفض: severity غير مدعومة /
سبب < 3 أحرف / درجة خارج [0,10] → 422؛ تقييم مجهول → 404.

## 8) Reports — `/reports` (4)

| Method | Path | الوظيفة |
|---|---|---|
| POST | `/reports/{scan_id}/generate` | توليد الملفات الستة في `data/reports/<scan_id>/` |
| GET | `/reports/{scan_id}/technical` | التقرير الفني (JSON: markdown + stats + ثغرات) |
| GET | `/reports/{scan_id}/executive` | التقرير التنفيذي العربي (JSON) |
| GET | `/reports/{scan_id}/download/{format}` | تنزيل: `technical_md|technical_html|technical_pdf|executive_md|executive_html|executive_pdf` |

```bash
curl -X POST http://localhost:8000/reports/4/generate -H "Authorization: Bearer $TOKEN"
curl -s -o /tmp/tech.pdf "http://localhost:8000/reports/4/download/technical_pdf" \
  -H "Authorization: Bearer $TOKEN" && file /tmp/tech.pdf
```

## 9) Dashboard — `/dashboard` (5)

| Method | Path | الوظيفة |
|---|---|---|
| GET | `/dashboard/summary` | KPIs: مشاريع/تطبيقات/فحوص/ثغرات/تقييمات + pending + متوسط الدرجة |
| GET | `/dashboard/severity_chart` | توزيع الخطورة (ترتيب ثابت Critical→Low، أصفار للغائب) |
| GET | `/dashboard/recent_scans` | آخر الفحوص + أسماء التطبيق/المشروع |
| GET | `/dashboard/top_vulns` | أعلى الثغرات بـ final_score |
| GET | `/dashboard/trends` | اتجاهات يومية (`days` 1–365، افتراضي 7) |

## 10) System

| Method | Path | الوظيفة |
|---|---|---|
| GET | `/health` | `{status, version, database, counts{projects,applications,scans,vulnerabilities}}` — لا يتطلب توكن؛ فشل القاعدة ⇒ `degraded` بلا انهيار |

---

## قرارات وملاحظات تشغيلية

1. **CORS**: مفتوح (`*`, بلا كوكيز — التوكن في الترويسة) لبيئة التطوير؛ يُضيَّق في
   النشر عبر `MAS_CORS_ORIGINS` (قائمة مفصولة بفواصل) — وعند ضبطها يُقيَّد فعلياً.
2. **حماية القراءة**: كل مسارات `reviews`/`reports` (بما فيها قوائم القراءة) تتطلب JWT —
   أُضيفت بعد كشف الاختبار اليدوي أنها كانت مفتوحة في المرحلة 5.
3. **الترتيب الزمني للفحص**: `orchestrator → أدوات → استخراج → تقييم → مراجعة →
   persist_scores → reporter → finalize` — كتابة النتائج قبل التقارير (قرار المرحلة 5 الموثق).
4. **الوصول للقراءة مباشرة (SELECT)**: استعلامات التجميع في لوحة المعلومات/الإحصاءات
   وبعض مسارات الدمج داخل الموجّهات؛ كل **الكتابة** تمر عبر المستودعات (`db/repositories`).
5. **قالب الاستجابة**: كل نقطة نهاية لها `response_model` Pydantic صريح (فحص آلي: OpenAPI).
6. **تفويض الملكية (المرحلة 8)**: أُضيف بعد كشف الاختبار الأمني أن كل المسارات كانت
   محميّة بالمصادقة فقط (IDOR كامل) — السلوك الحالي: كل مسارات الموارد تتحقق من
   سلسلة الملكية (`api/authz.py`)، والقوائم مصفّاة، ولوحة المعلومات وحدها admin-only.
7. **منع التكرار بالبصمة**: نفس بايتات APK في **مشروع آخر** ⇒ `409` بلا أي بيانات عن
   السجل القائم (كان يُرجع الصف كاملاً ⇒ تسريب)؛ ونفس المشروع ⇒ `200` بـ
   `deduplicated:true`. القرار مُفصَّل في `docs/security_hardening.md §8`.
