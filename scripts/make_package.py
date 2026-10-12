#!/usr/bin/env python
"""حزمة التوزيع للاختبار / Distribution package builder (v1.0.0).

    python scripts/make_package.py
    python scripts/make_package.py --output ~/project.tar.gz

يبني ``project.tar.gz`` جاهزاً للنسخ على أي جهاز وتشغيله بـ Docker، **بلا** بيانات
تشغيلية أو أسرار أو مخرجات مولَّدة:

    مستثنى: data/ · results/ · release/ · .git/ · .venv/ · __pycache__/
            *.db(+wal/shm) · .env · .pytest_cache/ · node_modules/ · *.log

المخرجات:
    • ``project.tar.gz`` (الحزمة)
    • ``project_files.txt`` (قائمة الملفات والحجم لكل قسم — للمراجعة والتدقيق)
وتُطبع في الطرفية: عدد الملفات، الحجم قبل/بعد الضغط، والبصمة SHA-256.
"""
from __future__ import annotations

import argparse
import hashlib
import tarfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_NAME = "android-vuln-severity-mas"

EXCLUDE_DIR_NAMES = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache",
    ".mypy_cache", "node_modules", "release", "data", "results", ".idea", ".vscode",
}
EXCLUDE_SUFFIXES = {".db", ".db-wal", ".db-shm", ".pyc", ".log", ".pyo", ".egg-info"}
EXCLUDE_GLOBS = {"*.egg-info", "*.egg-link"}
EXCLUDE_FILES = {".env", ".DS_Store"}


def should_skip(relative: Path) -> bool:
    """هل يُستثنى المسار النسبي من الحزمة؟"""
    if any(part in EXCLUDE_DIR_NAMES for part in relative.parts):
        return True
    if relative.name in EXCLUDE_FILES:
        return True
    if relative.suffix in EXCLUDE_SUFFIXES:
        return True
    # مجلدات/روابط التثبيت التطويري (تُولَّد محلياً ولا معنى لها في الحزمة)
    return any(relative.match(pattern) or any(part.endswith(".egg-info") for part in relative.parts)
               for pattern in EXCLUDE_GLOBS)


def collect() -> list[Path]:
    """كل الملفات المشمولة (نسبية من جذر المشروع)."""
    files: list[Path] = []
    for path in sorted(PROJECT_ROOT.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(PROJECT_ROOT)
        if should_skip(relative):
            continue
        files.append(relative)
    return files


def human(size_bytes: int) -> str:
    """حجم مقروء (KiB/MiB)."""
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KiB"
    return f"{size_bytes / (1024 * 1024):.2f} MiB"


def main() -> None:
    """يبني الحزمة وقائمة الملفات ويطبع التقرير."""
    parser = argparse.ArgumentParser(description="بناء حزمة التوزيع project.tar.gz")
    parser.add_argument("--output", default=str(Path.home() / "project.tar.gz"))
    args = parser.parse_args()

    files = collect()
    total = sum((PROJECT_ROOT / rel).stat().st_size for rel in files)

    archive_path = Path(args.output).expanduser()
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "w:gz") as archive:
        for relative in files:
            archive.add(PROJECT_ROOT / relative, arcname=Path(PACKAGE_NAME) / relative)

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    listing = Path(archive_path.parent) / "project_files.txt"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    by_top: dict[str, list[Path]] = {}
    for relative in files:
        by_top.setdefault(relative.parts[0], []).append(relative)

    lines = [
        f"# قائمة محتويات project.tar.gz — {generated}",
        f"# الملفات: {len(files)} · الحجم قبل الضغط: {human(total)} · بعد الضغط: {human(archive_path.stat().st_size)}",
        f"# SHA-256: {digest}",
        "",
    ]
    for top in sorted(by_top):
        section = by_top[top]
        section_bytes = sum((PROJECT_ROOT / rel).stat().st_size for rel in section)
        lines.append(f"## {top} — {len(section)} ملفاً · {human(section_bytes)}")
        for relative in section:
            lines.append(f"   {relative}")
        lines.append("")
    listing.write_text("\n".join(lines), encoding="utf-8")

    print(f"✅ الحزمة: {archive_path} ({human(archive_path.stat().st_size)})")
    print(f"✅ القائمة: {listing}")
    print(f"   الملفات: {len(files)} · قبل الضغط: {human(total)} · SHA-256: {digest[:16]}…")


if __name__ == "__main__":
    main()
