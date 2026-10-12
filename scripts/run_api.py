"""تشغيل خادم FastAPI (المرحلة 6).

    python scripts/run_api.py --port 8000
    python scripts/run_api.py --port 8000 --reload     # تطوير

Swagger UI على /docs · ReDoc على /redoc · فحص الصحة /health
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn  # noqa: E402


def main() -> None:
    """نقطة الدخول: وسائط CLI ثم uvicorn.run."""
    parser = argparse.ArgumentParser(description="تشغيل API نظام تقييم الخطورة")
    parser.add_argument("--host", default="0.0.0.0", help="عنوان الاستماع (افتراضي 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="المنفذ (افتراضي 8000)")
    parser.add_argument("--reload", action="store_true", help="إعادة التحميل التلقائي (تطوير)")
    parser.add_argument("--log-level", default="info", help="مستوى السجل")
    args = parser.parse_args()

    print(f"▶ API على http://{args.host}:{args.port}  (docs: /docs · health: /health)")
    uvicorn.run(
        "api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
