"""تحويل رسوم Mermaid إلى SVG/PNG — المرحلة 8.

    python scripts/render_diagrams.py --format svg
    python scripts/render_diagrams.py --format png --scale 2
    python scripts/render_diagrams.py --check          # تحقق بنيوي فقط بلا تحويل

المسار الأساسي: **mermaid-cli** (mmdc) عبر npx — يحتاج Node + Chromium.
عند تعذّر ذلك (بيئة بلا Chromium/إنترنت) لا يفشل السكربت:
    1. يتحقق بنيوياً من كل ملف (ترويسة النوع + توازن الأقواس + عدد العُقد/الحواف).
    2. ينسخ المصادر إلى ``docs/thesis/figures/preview_<name>.md`` بكتل ```mermaid````
       جاهزة للّصق المباشر في论文 (GitHub/VS Code/Typora تُصيّرها فوراً).
    3. يُخرج تقرير Markdown بحالة كل رسم + أمر التحويل اليدوي.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

FIGURES_DIR = PROJECT_ROOT / "docs" / "thesis" / "figures"
REPORT_PATH = FIGURES_DIR / "RENDER_REPORT.md"

DIAGRAMS = [
    ("architecture", "البنية المعمارية الكاملة"),
    ("dataflow", "تدفق البيانات من الرفع إلى التقرير والقياس"),
    ("state_machine", "آلة حالة الفحص/الوكلاء"),
    ("scoring_flow", "تدفق حساب الخطورة وقرارات المراجعة"),
    ("db_erd", "مخطط قاعدة البيانات (14 جدولاً)"),
]

VALID_HEADERS = ("flowchart", "graph", "stateDiagram-v2", "erDiagram", "sequenceDiagram", "classDiagram")


# ---------------------------------------------------------------------
# تحقق بنيوي
# ---------------------------------------------------------------------
def validate_mermaid(text: str) -> list[str]:
    """فحوص بنيوية خفيفة — تُرجع قائمة ملاحظات (فارغة = سليم)."""
    notes: list[str] = []
    body = [line for line in text.splitlines() if not line.strip().startswith("%%")]
    if not body:
        return ["ملف فارغ"]
    if not any(line.strip().startswith(VALID_HEADERS) for line in body):
        notes.append("لا ترويسة نوع معروفة (flowchart/graph/stateDiagram-v2/erDiagram…)")

    for opener, closer in (("{", "}"), ("[", "]"), ("(", ")"), ('"', '"')):
        if text.count(opener) % 2 != text.count(closer) % 2:
            notes.append(f"عدم توازن محتمل بين {opener} و{closer}")
    if "erDiagram" in text:
        relations = len(re.findall(r"\|\|--", text))
        if relations < 5:
            notes.append(f"علاقات ERD قليلة ({relations}) — تحقق من المخطط")
    else:
        edges = len(re.findall(r"--[->]|-->|~~~|-\.->", text))
        if edges < 5:
            notes.append(f"حواف قليلة ({edges}) — تحقق من المخطط")
    return notes


# ---------------------------------------------------------------------
# التحويل
# ---------------------------------------------------------------------
def find_mmdc() -> str | None:
    """يبحث عن mmdc أو npx لتحويل Mermaid."""
    direct = shutil.which("mmdc")
    if direct:
        return direct
    npx = shutil.which("npx")
    if npx:
        return f"{npx} --yes @mermaid-js/mermaid-cli"
    return None


def render_one(command: str, source: Path, target: Path, scale: int) -> tuple[bool, str]:
    """يستدعي mmdc لملف واحد. يُعيد (نجاح؟، رسالة)."""
    cmd = command.split() + [
        "-i", str(source), "-o", str(target),
        "-s", str(scale), "-b", "white",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return False, "انتهت المهلة (300s)"
    except OSError as exc:
        return False, f"تعذّر تشغيل mmdc: {exc}"
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()
        return False, tail[-1] if tail else f"رمز الخروج {result.returncode}"
    if not target.exists() or target.stat().st_size == 0:
        return False, "لم يُنتج الملف الهدف"
    return True, f"{target.name} ({target.stat().st_size:,} بايت)"


def write_preview(name: str, text: str, title: str) -> Path:
    """ملف Markdown بكتلة mermaid جاهزة للتصيير في المحررات/论文."""
    preview = FIGURES_DIR / f"preview_{name}.md"
    preview.write_text(
        f"# {title}\n\n"
        "> هذا الملف عرض جاهز للتصيير في VS Code / GitHub / Typora (كتلة mermaid).\n"
        f"> المصدر القابل للتحرير: `{name}.mmd`\n\n"
        "```mermaid\n" + text.rstrip() + "\n```\n",
        encoding="utf-8",
    )
    return preview


# ---------------------------------------------------------------------
# نقطة الدخول
# ---------------------------------------------------------------------
def main() -> None:
    """يولّد SVG/PNG إن أمكن، وإلا ينسخ العروض ويكتب تقرير الحالة."""
    parser = argparse.ArgumentParser(description="تحويل رسوم Mermaid إلى SVG/PNG")
    parser.add_argument("--format", choices=("svg", "png"), default="svg")
    parser.add_argument("--scale", type=int, default=2, help="معامل التكبير للـ PNG")
    parser.add_argument("--check", action="store_true", help="تحقق بنيوي فقط (بلا تحويل)")
    args = parser.parse_args()

    if not FIGURES_DIR.exists():
        raise SystemExit(f"✗ مجلد الرسوم غير موجود: {FIGURES_DIR}")

    command = None if args.check else find_mmdc()
    rows: list[dict[str, str]] = []
    svg_count = 0

    for name, title in DIAGRAMS:
        source = FIGURES_DIR / f"{name}.mmd"
        if not source.exists():
            rows.append({"diagram": name, "source": "مفقود", "status": "✗", "detail": "الملف غير موجود"})
            continue
        text = source.read_text(encoding="utf-8")
        notes = validate_mermaid(text)
        preview = write_preview(name, text, title)

        if args.check:
            rows.append(
                {
                    "diagram": name,
                    "source": f"{source.name} ({len(text.splitlines())} سطراً)",
                    "status": "✓" if not notes else "⚠",
                    "detail": "سليم بنيوياً" if not notes else " | ".join(notes),
                }
            )
            continue

        if command is None:
            rows.append(
                {
                    "diagram": name,
                    "source": source.name,
                    "status": "◐",
                    "detail": f"Mermaid CLI غير متوفر — عرض جاهز: {preview.name}",
                }
            )
            continue

        target = FIGURES_DIR / f"{name}.{args.format}"
        ok, message = render_one(command, source, target, args.scale)
        if ok:
            svg_count += 1
        rows.append(
            {
                "diagram": name,
                "source": source.name,
                "status": "✓" if ok else "✗",
                "detail": message if ok else f"فشل التحويل: {message} (العرض في {preview.name})",
            }
        )

    # ── التقرير ─────────────────────────────────────────────────────
    lines = [
        "# تقرير توليد الرسوم (Mermaid → SVG/PNG)",
        "",
        f"- الأدوات: {'mermaid-cli عبر ' + command if command else 'Mermaid CLI غير متوفر في هذه البيئة'}",
        f"- الصيغة المطلوبة: {args.format}",
        f"- المصادر: `docs/thesis/figures/*.mmd` (5 رسوم)",
        "",
        "| الرسم | المصدر | الحالة | التفصيل |",
        "|---|---|---|---|",
    ]
    for row in rows:
        lines.append(f"| {row['diagram']} | {row['source']} | {row['status']} | {row['detail']} |")
    lines += [
        "",
        "## كيف تُنتج SVG على جهازك",
        "```bash",
        "# الطريقة 1 — mermaid-cli مباشرة (يحتاج Node + Chromium)",
        "npm install -g @mermaid-js/mermaid-cli",
        "python scripts/render_diagrams.py --format svg",
        "",
        "# الطريقة 2 — npx بلا تثبيت دائم",
        "npx --yes @mermaid-js/mermaid-cli -i docs/thesis/figures/architecture.mmd \\",
        "    -o docs/thesis/figures/architecture.svg -b white",
        "",
        "# الطريقة 3 — VS Code: إضافة Markdown Preview Mermaid Support",
        "#             ثم افتح docs/thesis/figures/preview_*.md وصدّر الرسم",
        "```",
        "",
        "> الرسوم مصممة للطباعة بالأبيض والأسود: تعتمد الصناديق والنصوص "
        "(labels) لا الألوان المميزة، ويُذكر كل رقم/معادلة داخل الشكل نفسه.",
    ]
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"◉ الرسوم: {len(rows)} | تم توليد {svg_count} كـ {args.format}")
    for row in rows:
        print(f"  {row['status']} {row['diagram']:<16} {row['detail']}")
    print(f"✅ التقرير: {REPORT_PATH}")


if __name__ == "__main__":
    main()
