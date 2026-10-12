"""تشغيل واجهة Streamlit (المرحلة 6).

    python scripts/run_ui.py --port 8501

ملاحظات تشغيلية (موثقة):
- CORS/XSRF مُعطَّلان ليعمل العرض خلف بروكسي/إطار مضمَّن في بيئة التطوير؛
  فعِّلهما في النشر خلف نطاق مملوك.
- يعتمد الخادم على متغير البيئة MAS_API_URL للوصول إلى الـ API
  (افتراضي http://127.0.0.1:8000 — الاتصال من خادم Streamlit لا المتصفح).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_ENTRY = PROJECT_ROOT / "ui" / "streamlit_app" / "app.py"


def main() -> None:
    """بناء أمر streamlit run وتنفيذه."""
    parser = argparse.ArgumentParser(description="تشغيل واجهة Streamlit")
    parser.add_argument("--host", default="0.0.0.0", help="عنوان الاستماع")
    parser.add_argument("--port", type=int, default=8501, help="المنفذ (افتراضي 8501)")
    parser.add_argument("--headless", action="store_true", default=True, help="بلا متصفح تلقائي")
    args = parser.parse_args()

    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(APP_ENTRY),
        f"--server.address={args.host}",
        f"--server.port={args.port}",
        "--server.headless=true",
        "--server.enableCORS=false",
        "--server.enableXsrfProtection=false",
        "--browser.gatherUsageStats=false",
    ]
    print(f"▶ الواجهة على http://{args.host}:{args.port} (API: {APP_ENTRY.parent})")
    raise SystemExit(subprocess.call(command))


if __name__ == "__main__":
    main()
