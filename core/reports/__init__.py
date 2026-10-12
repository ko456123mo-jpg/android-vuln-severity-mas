"""محرك التقارير — Report generation engine (المرحلة 5).

يولّد لكل فحص تقريرين:
    • Technical Report (بالإنجليزية) — تفصيلي للمهندسين
    • Executive Report (بالعربية) — ملخص للإدارة (HTML يدعم RTL)

يرجى مراجعة docs/hitl_and_reports.md لقرارات التصميم.
"""
from core.reports.generator import ReportGenerator
from core.reports.stats import compute_scan_statistics

__all__ = ["ReportGenerator", "compute_scan_statistics"]
