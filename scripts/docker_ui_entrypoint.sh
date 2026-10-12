#!/usr/bin/env bash
# =====================================================================
# نقطة دخول حاوية الواجهة (المرحلة 8)
#   تتحقق من وصول الـ API ثم تُشغّل Streamlit (بلا كشف تحرير للخارج)
# =====================================================================
set -euo pipefail

API_URL="${MAS_API_URL:-http://api:8000}"
echo "[ui-entrypoint] الـ API المتوقع: ${API_URL}"

for attempt in $(seq 1 20); do
    if curl -fsS --max-time 3 "${API_URL}/health" >/dev/null 2>&1; then
        echo "[ui-entrypoint] الـ API جاهز (محاولة ${attempt})"
        break
    fi
    echo "[ui-entrypoint] انتظار الـ API… (${attempt}/20)"
    sleep 3
done

cd /app
exec streamlit run ui/streamlit_app/app.py \
    --server.address 0.0.0.0 --server.port 8501 --server.headless true \
    --browser.gatherUsageStats false
