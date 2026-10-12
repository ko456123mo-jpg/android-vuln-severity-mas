#!/usr/bin/env python
"""حزمة الإصدار / Release packaging (المرحلة 8 · v1.0).

    python scripts/make_release.py
    python scripts/make_release.py --name android-vuln-severity-mas-v1.0.0

يُنفّذ خطوات مُتحقَّق منها بالترتيب:

    1) يقرأ ``VERSION`` ويشتقّ اسم الحزمة (قابل للتجاوز بـ ``--name``).
    2) **بوابة جاهزية**: يرفض بناء الحزمة إذا نقص أي ملف إلزامي (وثائق، اختبارات،
       صور Docker، قوالب، بيانات …) — لا أرشيف ناقص بصمت.
    3) ينسخ شجرة المشروع إلى ``release/<name>/`` مع استثناءات صريحة
       (``data/``, ``results/``, ``release/``, ``.venv``, ``__pycache__``, ``.git``,
       ``*.db``, ``.env`` …).
    4) يُنتج ``.tar.gz`` + ``.sha256`` + ``MANIFEST.md`` (قائمة الملفات وحجمها).

رمز الخروج: 0 عند النجاح. أي بند ناقص ⇒ رسالة صريحة وسقوط بلا أرشيف نصف جاهز.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

RELEASE_DIR = PROJECT_ROOT / "release"

# ما يُستثنى من الأرشيف (مساراً أو نمطاً)
EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache",
    ".mypy_cache", "release", "data", "results", ".idea", ".vscode", "node_modules",
}
EXCLUDE_SUFFIXES = {".db", ".db-wal", ".db-shm", ".pyc", ".log"}
EXCLUDE_FILES = {".env"}

# بوابة الجاهزية — كل مسار إلزامي في حزمة الإصدار
REQUIRED: tuple[str, ...] = (
    # وثائق الإصدار
    "README.md", "CHANGELOG.md", "VERSION", "LICENSE", "CITATION.cff",
    "pyproject.toml", "Makefile", "docker-compose.yml", ".dockerignore", ".env.example",
    "Dockerfile.api", "Dockerfile.ui",
    "docs/release_notes_v1.0.md", "docs/security_hardening.md", "docs/user_manual.md",
    "docs/api_reference.md", "docs/scoring_logic.md", "docs/mcp_design.md",
    "docs/security_guardrails.md", "docs/rag_architecture.md",
    "docs/evaluation_protocol.md", "docs/ui_guide.md", "docs/deployment_notes.md",
    "docs/phase7_deliverable.md", "docs/phase8_deliverable.md",
    # الأطروحة
    "docs/thesis/appendix_a_prompts.md", "docs/thesis/appendix_b_rules.md",
    "docs/thesis/appendix_c_decision_log.md", "docs/thesis/appendix_d_metrics.md",
    "docs/thesis/limitations_and_future_work.md",
    "docs/thesis/figures/architecture.mmd", "docs/thesis/figures/scoring_flow.mmd",
    "evaluation/protocol.md", "evaluation/metrics.py",
    # الكود الأساسي
    "api/main.py", "api/authz.py", "agents/graph.py", "agents/report_agent.py",
    "core/security/rate_limiter.py", "core/security/headers.py", "core/security/secrets.py",
    "core/performance/caching.py", "core/performance/db_optimizer.py",
    "db/schema.sql", "rag/retriever.py",
    # السكربتات
    "scripts/benchmark.py", "scripts/load_test.py", "scripts/final_checklist.py",
    "scripts/render_diagrams.py", "scripts/make_release.py", "scripts/seed_all.py",
    # الاختبارات
    "tests/conftest.py", "tests/e2e/test_full_system.py",
    "tests/chaos/test_resilience.py", "tests/security/test_security.py",
)


def read_version() -> str:
    """يقرأ VERSION (يفشل بوضوح إن غاب)."""
    path = PROJECT_ROOT / "VERSION"
    if not path.exists():
        print("✗ VERSION غير موجود — أنشئه أولاً")
        raise SystemExit(2)
    return path.read_text(encoding="utf-8").strip()


def check_readiness() -> list[str]:
    """يعيد قائمة المسارات الإلزامية الناقصة (فارغة = جاهز)."""
    return [rel for rel in REQUIRED if not (PROJECT_ROOT / rel).exists()]


def should_exclude(relative: Path) -> bool:
    """هل يُستثنى هذا المسار النسبي من الأرشيف؟"""
    if any(part in EXCLUDE_DIRS for part in relative.parts):
        return True
    if relative.name in EXCLUDE_FILES:
        return True
    if relative.suffix in EXCLUDE_SUFFIXES:
        return True
    return relative.name.endswith(".db-wal") or relative.name.endswith(".db-shm")


def collect_files() -> list[Path]:
    """كل ملفات المشروع المرشّحة للأرشيف (نسبية من الجذر)."""
    files: list[Path] = []
    for path in sorted(PROJECT_ROOT.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(PROJECT_ROOT)
        if should_exclude(relative):
            continue
        files.append(relative)
    return files


def build_archive(name: str, files: list[Path]) -> Path:
    """ينسخ الملفات إلى release/<name>/ ثم يبني tar.gz ويعيد مساره."""
    staging = RELEASE_DIR / name
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)

    for relative in files:
        destination = staging / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PROJECT_ROOT / relative, destination)

    archive_path = RELEASE_DIR / f"{name}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(staging, arcname=name)
    return archive_path


def sha256_of(path: Path) -> str:
    """بصمة SHA-256 لملف (قراءة مقطّعة)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(name: str, version: str, files: list[Path], archive: Path, digest: str) -> Path:
    """يكتب MANIFEST.md: المحتوى، الأحجام، البصمة، وتاريخ البناء."""
    total_bytes = sum((PROJECT_ROOT / rel).stat().st_size for rel in files)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    top_level: dict[str, int] = {}
    for relative in files:
        top_level[relative.parts[0]] = top_level.get(relative.parts[0], 0) + 1

    lines = [
        f"# MANIFEST — {name}",
        "",
        f"- **الإصدار:** {version}",
        f"- **تاريخ البناء:** {generated}",
        f"- **عدد الملفات:** {len(files)}",
        f"- **الحجم قبل الضغط:** {total_bytes / 1024:.1f} KiB",
        f"- **الأرشيف:** `{archive.name}` ({archive.stat().st_size / 1024:.1f} KiB)",
        f"- **SHA-256:** `{digest}`",
        "",
        "## التوزيع على المستوى الأعلى",
        "",
        "| المجلد/الملف | ملفات |",
        "|---|---|",
    ]
    for key in sorted(top_level):
        lines.append(f"| `{key}` | {top_level[key]} |")
    lines += [
        "",
        "## التحقق",
        "",
        "```bash",
        f"sha256sum -c {archive.name}.sha256        # في مجلد release/",
        f"tar -tzf {archive.name} | head -20         # قائمة المحتويات",
        "```",
        "",
        "## المستثنى عن قصد",
        "",
        "`data/` (قاعدة + APK + تقارير مولَّدة) · `results/` (مخرجات قياس بيعاد توليدها)",
        "`release/` · `.git/` · `.venv/` · `__pycache__/` · `*.db` · `*.db-wal` · `*.log` · `.env`",
        "",
    ]
    manifest = RELEASE_DIR / "MANIFEST.md"
    manifest.write_text("\n".join(lines), encoding="utf-8")
    return manifest


def main() -> None:
    """نقطة الدخول: بوابة جاهزية ← نسخ ← أرشفة ← بصمة ← بيان."""
    parser = argparse.ArgumentParser(description="بناء حزمة الإصدار")
    parser.add_argument("--name", default=None, help="اسم الحزمة (افتراضي: <repo>-v<version>)")
    args = parser.parse_args()

    version = read_version()
    name = args.name or f"android-vuln-severity-mas-v{version}"

    missing = check_readiness()
    if missing:
        print(f"✗ بوابة الجاهزية: {len(missing)} ملفاً إلزامياً ناقصاً — لا أرشيف ناقص:")
        for rel in missing:
            print(f"    - {rel}")
        raise SystemExit(1)

    files = collect_files()
    print(f"◉ الإصدار {version} — {len(files)} ملفاً")
    archive = build_archive(name, files)
    digest = sha256_of(archive)

    checksum_path = RELEASE_DIR / f"{archive.name}.sha256"
    checksum_path.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")

    manifest = write_manifest(name, version, files, archive, digest)
    print(f"✅ الأرشيف: {archive} ({archive.stat().st_size / 1024:.1f} KiB)")
    print(f"✅ البصمة:  {checksum_path}")
    print(f"✅ البيان:  {manifest}")


if __name__ == "__main__":
    main()
