# 🗄️ مخطط قاعدة البيانات / Database Schema (14 Tables)

مصدر الحقيقة: `db/schema.sql` — ORM مرآته: `db/models.py`.
محرك: SQLite + `journal_mode=WAL` + `foreign_keys=ON`.

## خريطة العلاقات / Relationship Map

```
users 1────N projects 1────N applications 1────1 app_context ──► context_score
  │                              │
  │                              ├─1──N scans ───1──N agent_logs
  │                              │        └──N──┐
  │                              ├─1──N         │
  │                              │   vulnerabilities 1──N vulnerability_findings N──1 tools
  │                              │        │ 1
  │                              │        │ 1 (UNIQUE)
  │                              │        ▼ 1
  │                              │    assessments ───N──1 severity_rules (rule_version)
  │                              │        │ 1
  │ N◄──1 corrections ───────────┘ N
  │        │ 1
  │        ▼ N
  │   feedback_examples
  │
knowledge_base (مستقل — RAG، خزانة معرفات CWE/MASVS)
```

## الجداول / Tables

| # | الجدول | الغرض | قيود مميزة |
|---|--------|-------|------------|
| 1 | users | مستخدمون وأدوار | role ∈ admin/analyst/reviewer، username+email UNIQUE |
| 2 | projects | تجميع تنظيمي | owner_id→users، status='active' |
| 3 | applications | بيانات APK | **sha256 UNIQUE** (منع رفع مكرر) |
| 4 | app_context | السياق التجاري | application_id UNIQUE (1:1)، CHECKs للقيم المسموحة |
| 5 | tools | سجل MCP | name UNIQUE، category ∈ static/dynamic، enabled |
| 6 | scans | جلسات الفحص | status ∈ pending/running/success/failed/partial |
| 7 | vulnerabilities | الثغرة الموحدة | **dedup_fingerprint UNIQUE** (قلب الدمج) |
| 8 | vulnerability_findings | أدلة كل أداة | evidence_type ∈ static/dynamic، artifact_ref |
| 9 | severity_rules | قواعد versioned | version UNIQUE، صف active واحد |
| 10 | assessments | التقييم الموزون | vulnerability_id UNIQUE، severity ∈ 4 فئات، rule_version FK |
| 11 | corrections | HITL | reason NOT NULL |
| 12 | feedback_examples | few-shot | embedding BLOB، active |
| 13 | agent_logs | تدقيق | status ∈ success/failed، tokens/latency |
| 14 | knowledge_base | RAG | source ∈ MASVS/CWE/OWASP، embedding BLOB |

## الفهارس / Indexes

`idx_apps_project` · `idx_scans_app` · `idx_vulns_app` · `idx_vulns_fingerprint` ·
`idx_findings_vuln` · `idx_findings_scan` · `idx_assessments_vuln` ·
`idx_assessments_severity` · `idx_logs_scan` · `idx_kb_masvs`

## ملاحظات تشغيلية / Notes

- **JSON في SQLite**: أعمدة `capabilities, tools_used, weights, context_params, thresholds, prompt_payload`
  مخزنة TEXT وتُدار عبر `sqlalchemy.JSON` (تسلسل/فك تلقائي).
- **تصميم idempotent**: `init_db()` و `seed.run_seed()` آمنة للتكرار (IF NOT EXISTS + تحقق بالمفاتيح).
- **قرار تصميمي (Phase 1)**: كتلة `confidence` من بيانات seed (عتبات الثقة: `review_threshold`, `critical_min`)
  تُخزَّن داخل عمود `thresholds` كسلسلة متداخلة، لأن المخطط يحتوي ثلاثة أعمدة JSON فقط
  (weights/context_params/thresholds). البديل المستقبلي: عمود `confidence_params` منفصل
  عند أول migration فعلي (Alembic — المرحلة 3+).
- **لماذا WAL**: قراءات الواجهة والفحوص تتزامن مع كتابة الوكلاء دون قفل "database is locked".
