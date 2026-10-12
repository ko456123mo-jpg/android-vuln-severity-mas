# =====================================================================
# Makefile — أوامر المشروع الكاملة (المرحلة 8 / الإصدار v1.0.0)
#
#   make help         عرض كل الأهداف
#   make install      تثبيت الاعتماديات
#   make init-all     تهيئة القاعدة + البذر
#   make test         كل الاختبارات (وضع Mock — بلا إنترنت)
#   make run-api      تشغيل الـ API على 8000
#   make run-ui       تشغيل الواجهة على 8501
#   make docker-build docker-up docker-down docker-logs docker-shell
#   make release      حزمة إصدار v1.0.0 (أرشيف موقّع بالبصمة)
#   make final-check  الفحص النهائي الشامل
# =====================================================================
.PHONY: all help install install-dev init-db seed init-all test test-llm run-api run-ui \
        mobsf-up docker-build docker-up docker-down docker-logs docker-shell docker-ps \
        release benchmark load-test diagrams security-check optimize-db final-check clean

PY ?= python
MOCK ?= LLM_MOCK_MODE=1 MCP_MOCK_MODE=1 EMBEDDING_MOCK_MODE=1
VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0)

all: help

help:           ## عرض قائمة الأوامر
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ── التثبيت والتهيئة ────────────────────────────────────────────────
install:        ## تثبيت اعتماديات المشروع
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install .

install-dev:    ## تثبيت اعتماديات التطوير (pytest/ruff)
	$(PY) -m pip install ".[dev]"

init-db:        ## تهيئة قاعدة البيانات من schema.sql
	$(PY) scripts/init_db.py

seed:           ## بذر البيانات (admin + أدوات + قواعد + KB + RAG ingest)
	$(PY) scripts/seed_all.py
	$(PY) scripts/ingest_knowledge.py --force

init-all: init-db seed   ## تهيئة كاملة من الصفر

# ── الاختبارات والفحوص ──────────────────────────────────────────────
test:           ## كل الاختبارات (Mock كامل — بلا إنترنت)
	$(MOCK) $(PY) -m pytest -q

test-llm:       ## فحص اتصالات مزوّدي النماذج (يحتاج مفاتيح/.env)
	$(PY) scripts/test_llm_connection.py

test-e2e:       ## اختبارات e2e + الفوضى + الأمن فقط
	$(MOCK) $(PY) -m pytest tests/e2e tests/chaos tests/security -v

security-check: ## فحص التصليب الأمني (أسرار + ترويسات + حدود)
	$(MOCK) $(PY) -m pytest tests/security -q
	$(PY) -m core.security.secrets

benchmark:      ## قياس الأداء لكل مرحلة → results/benchmark.md
	$(MOCK) $(PY) scripts/benchmark.py

load-test:      ## اختبار الحمل (10 مستخدمين متوازيين) → results/load_test.md
	$(PY) scripts/load_test.py

optimize-db:    ## تحسين القاعدة (PRAGMA optimize + ANALYZE)
	$(PY) -c "from core.performance.db_optimizer import optimize_database as o; print(o())"

diagrams:       ## توليد رسوم Mermaid → SVG
	$(PY) scripts/render_diagrams.py --format svg

# ── التشغيل ────────────────────────────────────────────────────────
run-api:        ## تشغيل FastAPI على 8000
	$(PY) scripts/run_api.py --port 8000

run-ui:         ## تشغيل Streamlit على 8501
	$(PY) scripts/run_ui.py --port 8501

mobsf-up:       ## تشغيل MobSF فقط عبر Docker
	docker compose up -d mobsf

# ── Docker ─────────────────────────────────────────────────────────
docker-build:   ## بناء صور api + ui
	docker compose build

docker-up:      ## تشغيل كل الخدمات في الخلفية
	docker compose up -d

docker-down:    ## إيقاف كل الخدمات
	docker compose down

docker-ps:      ## حالة الخدمات
	docker compose ps

docker-logs:    ## متابعة السجلات (api ui mobsf)
	docker compose logs -f --tail=200

docker-shell:   ## دخول shell إلى حاوية الـ api
	docker compose exec api /bin/bash

# ── الإصدار والفحص النهائي ─────────────────────────────────────────
release:        ## حزمة إصدار v$(VERSION): أرشيف + بصمة SHA-256
	$(PY) scripts/make_release.py

final-check:    ## الفحص النهائي الشامل → results/final_checklist.md
	$(MOCK) $(PY) scripts/final_checklist.py

clean:          ## تنظيف المخلفات المؤقتة (لا يمس data/ ولا results/)
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache
