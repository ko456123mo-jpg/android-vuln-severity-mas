#!/usr/bin/env bash
# =====================================================================
# نشر المستودع على GitHub — أمر واحد / One-command GitHub publish
# =====================================================================
#   bash scripts/github_publish.sh              # نشر كامل: repo + push + topics + release
#   bash scripts/github_publish.sh --dry-run    # يعرض ما سيُنفّذ بلا أي تغيير على GitHub
#
# المتطلبات:
#   1) gh CLI مثبّت (>= 2.0)   2) مصادقة: gh auth login  (أو GITHUB_TOKEN في البيئة)
#
# المالك/المستودع قابلان للتجاوز:
#   GH_OWNER=ko456123mo-jpg GH_REPO=android-vuln-severity-mas bash scripts/github_publish.sh
# =====================================================================
set -euo pipefail

OWNER="${GH_OWNER:-ko456123mo-jpg}"
REPO="${GH_REPO:-android-vuln-severity-mas}"
DESC="Multi-Agent Vulnerability Severity Assessment for Android Applications — OWASP MASVS aligned, powered by JADX, MobSF, Frida, Objection, LangGraph, FastAPI, Streamlit, and RAG."
TOPICS="android-security,owasp-masvs,multi-agent,llm,langgraph,fastapi,streamlit,mcp,rag,vulnerability-assessment,severity-scoring,thesis-project,cybersecurity,python,mobile-security,frida,mobsf"
RELEASE_TAG="v1.0.0"
RELEASE_ZIP="release/${REPO}-v1.0.0.tar.gz"
RELEASE_NOTES="docs/release_notes_v1.0.md"
DRY_RUN="${1:-}"

say()  { printf '\033[1;36m◉\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m⚠\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m✗\033[0m %s\n' "$*"; exit 1; }

run() {  # ينفّذ أو يطبع حسب --dry-run
  if [ "$DRY_RUN" = "--dry-run" ]; then printf '   [dry-run] %s\n' "$*"; else "$@"; fi
}

# ── 0) فحوص ما قبل النشر ────────────────────────────────────────────
say "فحص الجاهزية (pre-flight)"
command -v gh  >/dev/null || fail "gh غير مثبّت — ثبّته من https://cli.github.com ثم gh auth login"
command -v git >/dev/null || fail "git غير مثبّت"

if ! gh auth status >/dev/null 2>&1; then
  if [ "$DRY_RUN" = "--dry-run" ]; then
    warn "gh غير مصادَق — [dry-run] يعرض الخطوات بلا تنفيذ. للنشر الفعلي: gh auth login"
  else
    fail "gh غير مصادَق — نفّذ: gh auth login (أو صدّر GITHUB_TOKEN=... ثم أعد التشغيل)"
  fi
else
  ok "gh مصادَق: $(gh auth status 2>&1 | head -1)"
fi

[ -z "$(git status --porcelain)" ] || warn "توجد تغييرات غير مُثبَّتة (سيُدفع آخر commit فقط)"
git rev-parse --verify HEAD >/dev/null 2>&1 || fail "لا يوجد commit بعد — نفّذ git add -A && git commit"

# لا أسرار مرصودة في الشجرة المتتبَّعة
if git grep -I -nE '(gsk_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})' -- . >/dev/null 2>&1; then
  fail "أسرار محتملة في ملفات متتبَّعة — أوقف النشر وراجع: git grep -nE 'gsk_|sk-|AIza|AKIA'"
fi
ok "لا أسرار في الملفات المتتبَّعة"

# ── 1) المستودع ─────────────────────────────────────────────────────
if gh repo view "$OWNER/$REPO" >/dev/null 2>&1; then
  warn "المستودع $OWNER/$REPO موجود مسبقاً — سنضيف الريموت وندفع فقط"
else
  say "إنشاء المستودع $OWNER/$REPO (public · MIT)"
  run gh repo create "$OWNER/$REPO" --public --description "$DESC" --license MIT
fi

# ── 2) الربط والدفع ─────────────────────────────────────────────────
say "ربط الريموت والدفع إلى main"
run git remote remove origin 2>/dev/null || true
run git remote add origin "https://github.com/$OWNER/$REPO.git"
run git branch -M main
run git push -u origin main --force-with-lease

# ── 3) Topics ──────────────────────────────────────────────────────
say "إضافة Topics ($(echo "$TOPICS" | tr ',' '\n' | wc -l) موضوعاً)"
run gh repo edit "$OWNER/$REPO" --add-topic "$TOPICS"

# ── 4) الإصدار v1.0.0 ──────────────────────────────────────────────
if [ ! -f "$RELEASE_ZIP" ]; then
  warn "لا يوجد $RELEASE_ZIP — نبني الحزمة الآن: python scripts/make_release.py"
  run python scripts/make_release.py
fi
say "إنشاء Release $RELEASE_TAG برفق ملفات الإصدار"
run gh release create "$RELEASE_TAG" \
  "$RELEASE_ZIP" "${RELEASE_ZIP}.sha256" \
  --repo "$OWNER/$REPO" \
  --title "v1.0.0 — Initial Release" \
  --notes-file "$RELEASE_NOTES"

ok "انتهى — المستودع: https://github.com/$OWNER/$REPO"
ok "الإصدار: https://github.com/$OWNER/$REPO/releases/tag/$RELEASE_TAG"
