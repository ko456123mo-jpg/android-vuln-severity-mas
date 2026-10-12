#!/usr/bin/env bash
# =====================================================================
# نقطة دخول حاوية الـ API (المرحلة 8)
#   • تُهيّئ قاعدة البيانات + البذر عند أول تشغيل (idempotent — لا تكرار)
#   • تُحسّن القاعدة (PRAGMA optimize) ثم تُسلّم لـ uvicorn عبر exec
# =====================================================================
set -euo pipefail

DB_PATH="${DATABASE_PATH:-/app/data/app.db}"
echo "[api-entrypoint] قاعدة البيانات: ${DB_PATH}"

mkdir -p "$(dirname "${DB_PATH}")" /app/data/apks /app/data/artifacts /app/data/reports /app/results

if [ ! -f "${DB_PATH}" ]; then
    echo "[api-entrypoint] أول تشغيل — تهيئة المخطط والبذر"
    python scripts/init_db.py
    python scripts/seed_all.py
else
    echo "[api-entrypoint] القاعدة موجودة — تخطّي التهيئة"
fi

python - <<'PY' || echo "[api-entrypoint] تحسين القاعدة غير حرج — نتابع"
from core.performance.db_optimizer import optimize_database
print("[api-entrypoint]", optimize_database(analyze=False))
PY

echo "[api-entrypoint] تشغيل: $*"
exec "$@"
