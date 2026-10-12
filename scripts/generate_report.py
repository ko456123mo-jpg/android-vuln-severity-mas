#!/usr/bin/env python3
"""CLI توليد تقارير فحص يدوياً — Technical (EN) + Executive (AR).

الاستخدام:
    python scripts/generate_report.py --scan-id 1 --format all --output ./data/reports/
    python scripts/generate_report.py --scan-id 1 --format technical
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.reports.generator import ReportGenerator  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="توليد تقارير فحص أمني")
    parser.add_argument("--scan-id", type=int, required=True, help="scans.id")
    parser.add_argument(
        "--format",
        choices=["all", "technical", "executive", "md", "html", "pdf"],
        default="all",
        help="الصيغة المطلوبة (الافتراضي all = 6 ملفات)",
    )
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "data" / "reports"),
        help="المجلد الجذر للتقارير (تُنشأ بداخله بادئة <scan_id>/)",
    )
    args = parser.parse_args()

    generator = ReportGenerator(scan_id=args.scan_id)
    output_dir = Path(args.output) / str(args.scan_id)
    fmt = args.format

    if fmt == "all":
        paths = generator.export_all(output_dir)
    else:
        data = generator.collect_data()
        paths: dict[str, str] = {}
        if fmt in ("technical", "md", "html", "pdf"):
            tech = generator.generate_technical_report(data)
            if fmt in ("technical", "md"):
                paths["technical_md"] = generator.export_markdown(
                    tech["markdown"], output_dir / "technical_report.md"
                )
            tech_html = None
            if fmt in ("technical", "html", "pdf"):
                tech_html = generator.export_html(
                    tech["markdown"], output_dir / "technical_report.html", rtl=False
                )
                paths["technical_html"] = tech_html
            if fmt in ("technical", "pdf") and tech_html:
                paths["technical_pdf"] = generator.export_pdf(
                    tech_html, output_dir / "technical_report.pdf"
                )
        if fmt in ("executive", "md", "html", "pdf"):
            execu = generator.generate_executive_report([], "متوسط", data)
            if fmt in ("executive", "md"):
                paths["executive_md"] = generator.export_markdown(
                    execu["markdown"], output_dir / "executive_report.md"
                )
            exec_html = None
            if fmt in ("executive", "html", "pdf"):
                exec_html = generator.export_html(
                    execu["markdown"], output_dir / "executive_report.html", rtl=True
                )
                paths["executive_html"] = exec_html
            if fmt in ("executive", "pdf") and exec_html:
                paths["executive_pdf"] = generator.export_pdf(
                    exec_html, output_dir / "executive_report.pdf"
                )

    print(f"✅ تم توليد تقارير الفحص {args.scan_id}:")
    for kind, path in paths.items():
        print(f"  • {kind:<16} → {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
