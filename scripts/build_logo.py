#!/usr/bin/env python
"""مولّد هوية المشروع البصرية / Brand asset builder.

    python scripts/build_logo.py

يُنتج **كل** ملفات الشعار في ``assets/logo/`` من مصدر واحد (هذا السكربت) بتصميم
هندسي محسوب — لا رسوم يدوية غير قابلة للتتبّع:

    logo.svg · logo-dark.svg · logo-light.svg · logo-icon.svg
    logo-horizontal.svg · logo-mono.svg
    + ملفات PNG (512 / 1024 / 64 / 128 / 1200×300) + favicon.ico

**قرارات فنية موثّقة** (تُشرح كاملة في BRAND_GUIDE.md):
    • الشعار = درع (أمن) يحتوي: حلقة مدارية بسهم دائري (الوكلاء الخمسة + حلقة
      التغذية الراجعة البشرية) + رأس أندرويد مجرّد (الهوية المستهدفة) + أربعة
      أعمدة خطورة تصاعدية (التقييم) — الحلقة تُسقط في نسخة الأيقونة الصغيرة.
    • كل النصوص تُحوَّل إلى **مسارات متجهية** (fontTools + خطوط OFL) ⇒ ملفات SVG
      مستقلة تماماً: تُعرض وتُطبع في أي بيئة بلا تثبيت خطوط.
    • التوليد حتمي (بلا عشوائية ولا طوابع زمنية داخل الأشكال) ⇒ نفس المخرجات.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOGO_DIR = PROJECT_ROOT / "assets" / "logo"
FONT_DIR = LOGO_DIR / "fonts"

# =====================================================================
# لوحة الألوان الرسمية / Official palette
# =====================================================================
PALETTE: dict[str, str] = {
    "navy": "#0A1929",        # الخلفية الأساسية (Threat-Intelligence navy)
    "navy_800": "#0E2233",    # سطح الدرع (تدرّج)
    "navy_700": "#132C42",    # سطح مرتفع / لوحات
    "navy_600": "#1E3A54",    # حدود فاصلة
    "cyan": "#00B4D8",        # اللون الرئيسي (العنصر الأول)
    "cyan_bright": "#48CAE4", # إبراز
    "cyan_deep": "#0077B6",   # تدرّج مكمّل
    "green": "#00FF88",       # فئة Low / الأمان
    "orange": "#FF6B35",      # فئة High / التنبيه
    "red": "#D62828",         # فئة Critical (جرعة صغيرة)
    "white": "#FFFFFF",
    "gray_light": "#E0E0E0",  # النص على الداكن
    "gray_mid": "#8FA3B8",    # نص ثانوي على الداكن
    "gray_dark": "#0F172A",   # نص على الفاتح
    "paper": "#F4F7FA",       # خلفية الوضع الفاتح
}

# =====================================================================
# 1) هندسة مساعدة
# =====================================================================
Point = tuple[float, float]


def polar(cx: float, cy: float, r: float, degrees: float) -> Point:
    """نقطة على دائرة (درجات، 0° = يمين، -90° = أعلى — نظام SVG حيث y للأسفل)."""
    rad = math.radians(degrees)
    return (round(cx + r * math.cos(rad), 3), round(cy + r * math.sin(rad), 3))


def arc_path(cx: float, cy: float, r: float, start_deg: float, end_deg: float) -> str:
    """قوس دائري من البداية إلى النهاية **باتجاه عقارب الساعة** (درجات متزايدة)."""
    while end_deg <= start_deg:
        end_deg += 360.0
    span = end_deg - start_deg
    x0, y0 = polar(cx, cy, r, start_deg)
    x1, y1 = polar(cx, cy, r, end_deg)
    large = 1 if span > 180 else 0
    return f"M {x0} {y0} A {r} {r} 0 {large} 1 {x1} {y1}"


def arrow_head(tip: Point, direction_deg: float, size: float = 15.0, spread: float = 30.0) -> str:
    """مثلث سهم عند ``tip`` يتجه نحو ``direction_deg`` (درجات، نظام SVG)."""
    back = direction_deg + 180.0
    left = polar(tip[0], tip[1], size, back - spread)
    right = polar(tip[0], tip[1], size, back + spread)
    return f"M {tip[0]} {tip[1]} L {left[0]} {left[1]} L {right[0]} {right[1]} Z"


def shield_path(cx: float = 256.0, top: float = 70.0, half: float = 152.0, tip: float = 468.0) -> str:
    """مسار الدرع الكلاسيكي بحواف عليا مستديرة وقاعدة مدبّبة."""
    left, right = cx - half, cx + half
    shoulder = top + 190.0          # حيث يبدأ الانحناء نحو القاعدة
    return (
        f"M {left + 34} {top} H {right - 34} "
        f"Q {right} {top} {right} {top + 34} "
        f"V {shoulder} "
        f"C {right} {shoulder + 96} {cx + 86} {tip - 46} {cx} {tip} "
        f"C {cx - 86} {tip - 46} {left} {shoulder + 96} {left} {shoulder} "
        f"V {top + 34} "
        f"Q {left} {top} {left + 34} {top} Z"
    )


def inset_shield_path() -> str:
    """درع داخلي رفيع (تفصيل تقني) — إزاحة يدوية محسوبة للشكل نفسه."""
    return shield_path(cx=256.0, top=96.0, half=126.0, tip=436.0)


# =====================================================================
# 2) عناصر الشعار (تعيد مقاطع SVG)
# =====================================================================
def defs_block(prefix: str = "lg") -> str:
    """التدرجات والمرشّحات — تُبنى مرة بأسماء مسبوقة لتفادي التعارض عند الدمج."""
    return f"""  <defs>
    <!-- تدرّج سطح الدرع: أزرق داكن سيبراني -->
    <linearGradient id="{prefix}-shield-fill" x1="0" y1="0" x2="0.6" y2="1">
      <stop offset="0%" stop-color="{PALETTE['navy_700']}"/>
      <stop offset="55%" stop-color="{PALETTE['navy_800']}"/>
      <stop offset="100%" stop-color="{PALETTE['navy']}"/>
    </linearGradient>
    <!-- تدرّج حدّ الدرع: سماوي كهربائي -->
    <linearGradient id="{prefix}-shield-stroke" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="{PALETTE['cyan_bright']}"/>
      <stop offset="55%" stop-color="{PALETTE['cyan']}"/>
      <stop offset="100%" stop-color="{PALETTE['cyan_deep']}"/>
    </linearGradient>
    <!-- تدرّج الأعمدة: سماوي → برتقالي → أحمر (شدة الخطورة) -->
    <linearGradient id="{prefix}-sev-high" x1="0" y1="1" x2="0" y2="0">
      <stop offset="0%" stop-color="{PALETTE['orange']}"/>
      <stop offset="100%" stop-color="{PALETTE['red']}"/>
    </linearGradient>
    <linearGradient id="{prefix}-bar-cool" x1="0" y1="1" x2="0" y2="0">
      <stop offset="0%" stop-color="{PALETTE['cyan_deep']}"/>
      <stop offset="100%" stop-color="{PALETTE['cyan_bright']}"/>
    </linearGradient>
    <!-- توهّج مركزي ناعم حول رأس الأندرويد (بلا مرشّحات — توافق أوسع) -->
    <radialGradient id="{prefix}-glow" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0%" stop-color="{PALETTE['cyan']}" stop-opacity="0.30"/>
      <stop offset="65%" stop-color="{PALETTE['cyan']}" stop-opacity="0.07"/>
      <stop offset="100%" stop-color="{PALETTE['cyan']}" stop-opacity="0"/>
    </radialGradient>
  </defs>"""


def shield_group(prefix: str, colors: dict[str, str], simplified: bool = False) -> str:
    """الدرع: التعبئة + الحدّ + الحدّ الداخلي الرفيع."""
    stroke_w = 11 if simplified else 8
    return f"""  <!-- الدرع: الأمن والحماية — العنصر الحاوي للهوية -->
  <g id="{prefix}-shield">
    <path d="{shield_path()}" fill="{colors['shield_fill']}" stroke="{colors['shield_stroke']}" stroke-width="{stroke_w}" stroke-linejoin="round"/>
    <path d="{inset_shield_path()}" fill="none" stroke="{colors['shield_stroke']}" stroke-width="2.4" stroke-opacity="0.28"/>
  </g>"""


def orbit_group(cx: float, cy: float, r: float, colors: dict[str, str], node_r: float, arrow: float) -> str:
    """الحلقة المدارية + السهم الدائري + الوكلاء الخمسة (نقاط متوهّجة)."""
    gap_start, gap_end = -46.0, -2.0          # فجوة السهم أسفل يمين الحلقة
    # خمس عقد بمواضع محسوبة: الأولى على القوس البادئ، والخامسة قبل فجوة السهم
    nodes = [-156.0, -84.0, 12.0, 88.0, 166.0]
    end_tip = polar(cx, cy, r, gap_start)
    parts = [
        "  <!-- الحلقة المدارية: تعاون الوكلاء الخمسة + اتجاه الدورة -->",
        f'  <g id="lg-orbit">',
        f'    <path d="{arc_path(cx, cy, r, gap_end, gap_start)}" fill="none" stroke="{colors["orbit"]}" '
        f'stroke-width="4.2" stroke-linecap="round" stroke-opacity="0.55"/>',
    ]
    for i, angle in enumerate(nodes):
        x, y = polar(cx, cy, r, angle)
        radius = node_r * (1.25 if i == 2 else 1.0)   # عقدة المركز أكبر قليلاً
        parts.append(
            f'    <!-- الوكيل {i + 1} / node {i + 1} -->\n'
            f'    <circle cx="{x}" cy="{y}" r="{radius + 4.5:.2f}" fill="{colors["node_halo"]}" opacity="0.16"/>'
            f'<circle cx="{x}" cy="{y}" r="{radius}" fill="{colors["node"]}"/>'
        )
    # رأس السهم: يلي نهاية القوس ويدلّ على استمرار الدورة (حلقة التغذية الراجعة)
    parts.append(
        f'    <path d="{arrow_head(end_tip, gap_start + 90, size=arrow, spread=32)}" fill="{colors["orbit"]}" '
        f'fill-opacity="0.9"/>'
    )
    parts.append("  </g>")
    return "\n".join(parts)


def android_head_group(cx: float, cy: float, r: float, colors: dict[str, str]) -> str:
    """رأس أندرويد مجرّد: قبة + هوائيان بنقطتين + عينان."""
    left, right = cx - r, cx + r
    eye_dy = -0.26 * r
    eye_dx = 0.42 * r
    # الهوائيان: نقطة انطلاق على القبة (±36°) وامتداد للخارج بزاوية 45°
    ax = r * math.sin(math.radians(36))
    ay = r * math.cos(math.radians(36))
    ant_len = 0.46 * r
    eye_r = max(3.2, 0.115 * r)
    ant_r = max(2.6, 0.085 * r)
    dome = (
        f"M {left} {cy} A {r} {r} 0 0 1 {right} {cy} Z"
    )
    left_ant_start = (round(cx - ax, 3), round(cy - ay, 3))
    right_ant_start = (round(cx + ax, 3), round(cy - ay, 3))
    left_ant_end = (round(left_ant_start[0] - ant_len * 0.68, 3), round(left_ant_start[1] - ant_len * 0.74, 3))
    right_ant_end = (round(right_ant_start[0] + ant_len * 0.68, 3), round(right_ant_start[1] - ant_len * 0.74, 3))
    stroke_w = max(3.0, 0.10 * r)
    return f"""  <!-- رأس أندرويد مجرّد: التطبيق المستهدف للتحليل -->
  <g id="lg-android">
    <circle cx="{cx}" cy="{cy - 0.15 * r}" r="{round(1.9 * r, 2)}" fill="{colors['glow']}"/>
    <path d="{dome}" fill="{colors['head_fill']}" stroke="{colors['head_stroke']}" stroke-width="{round(0.055 * r, 2)}" stroke-linejoin="round"/>
    <g stroke="{colors['antenna']}" stroke-width="{stroke_w}" stroke-linecap="round" fill="none">
      <path d="M {left_ant_start[0]} {left_ant_start[1]} L {left_ant_end[0]} {left_ant_end[1]}"/>
      <path d="M {right_ant_start[0]} {right_ant_start[1]} L {right_ant_end[0]} {right_ant_end[1]}"/>
    </g>
    <circle cx="{left_ant_end[0]}" cy="{left_ant_end[1]}" r="{ant_r}" fill="{colors['antenna']}"/>
    <circle cx="{right_ant_end[0]}" cy="{right_ant_end[1]}" r="{ant_r}" fill="{colors['antenna']}"/>
    <!-- العينان: عينان تحليل تفحصان الكود -->
    <circle cx="{round(cx - eye_dx, 3)}" cy="{round(cy + eye_dy, 3)}" r="{eye_r}" fill="{colors['eye']}"/>
    <circle cx="{round(cx + eye_dx, 3)}" cy="{round(cy + eye_dy, 3)}" r="{eye_r}" fill="{colors['eye']}"/>
  </g>"""


def severity_bars_group(
    cx: float,
    base_y: float,
    colors: dict[str, str],
    scale: float = 1.0,
    baseline: bool = True,
    baseline_pad: float = 14.0,
) -> str:
    """أربعة أعمدة خطورة تصاعدية (Low → Critical) وخط أساس اختياري.

    الهندسة مضبوطة لتقع الأعمدة **داخل** الدرع أسفل الحلقة/الرأس مع هامش:
    العرض 30×scale، الفجوة 16×scale، الارتفاعات [46, 74, 106, 146]×scale.
    """
    bar_w = 30.0 * scale
    gap = 16.0 * scale
    heights = [h * scale for h in (46.0, 74.0, 106.0, 146.0)]
    total = 4 * bar_w + 3 * gap
    x0 = cx - total / 2.0
    rx = bar_w / 2.0
    parts = ["  <!-- أعمدة الخطورة: Low → Medium → High → Critical -->", '  <g id="lg-bars">']
    for i, h in enumerate(heights):
        x = x0 + i * (bar_w + gap)
        fill = colors["bar_hot"] if i == 3 else colors["bar_cool"]
        label = "Critical" if i == 3 else ("Low", "Medium", "High")[i]
        # في النسخة الأحادية نُفرّق الأعمدة بالشفافية (الارتفاع وحده غير كافٍ للطباعة)
        opacity = ""
        if colors.get("mono"):
            opacity = ' fill-opacity="1"' if i == 3 else f' fill-opacity="{0.4 + 0.15 * i:.2f}"'
        parts.append(
            f'    <!-- العمود {i + 1}: {label} -->\n'
            f'    <rect x="{x:.2f}" y="{base_y - h:.2f}" width="{bar_w:.2f}" height="{h:.2f}" rx="{rx:.2f}" fill="{fill}"{opacity}/>'
        )
    if baseline:
        parts.append(
            f'    <path d="M {x0 - baseline_pad * scale:.2f} {base_y + 14 * scale:.2f} H {x0 + total + baseline_pad * scale:.2f}" '
            f'stroke="{colors["baseline"]}" stroke-opacity="0.55" stroke-width="{2.4 * scale:.2f}" stroke-linecap="round"/>'
        )
    parts.append("  </g>")
    return "\n".join(parts)


# =====================================================================
# 3) الألوان لكل نسخة
# =====================================================================
def theme(family: str) -> dict[str, str]:
    """ألوان العناصر حسب عائلة النسخة (داكن / فاتح / أحادي)."""
    if family == "mono":
        ink = "#111111"
        return {
            "mono": True,
            "shield_fill": "none", "shield_stroke": ink,
            "orbit": ink, "node": ink, "node_halo": ink,
            "head_fill": "none", "head_stroke": ink, "antenna": ink, "eye": ink,
            "bar_cool": ink, "bar_hot": ink, "baseline": ink, "glow": "none",
        }
    if family == "ink":  # على خلفية فاتحة: الدرع معبّأ بالكحلي ليبقى التباين
        return {
            "shield_fill": f"url(#lg-shield-fill)", "shield_stroke": f"url(#lg-shield-stroke)",
            "orbit": PALETTE["cyan"], "node": PALETTE["cyan_bright"], "node_halo": PALETTE["cyan"],
            "head_fill": PALETTE["navy_700"], "head_stroke": PALETTE["cyan_bright"],
            "antenna": PALETTE["cyan"], "eye": PALETTE["white"],
            "bar_cool": f"url(#lg-bar-cool)", "bar_hot": f"url(#lg-sev-high)",
            "baseline": PALETTE["cyan"], "glow": f"url(#lg-glow)",
        }
    return {  # داكن (الأساسي)
        "shield_fill": "url(#lg-shield-fill)", "shield_stroke": "url(#lg-shield-stroke)",
        "orbit": PALETTE["cyan"], "node": PALETTE["cyan_bright"], "node_halo": PALETTE["cyan"],
        "head_fill": PALETTE["navy_700"], "head_stroke": PALETTE["cyan_bright"],
        "antenna": PALETTE["cyan"], "eye": PALETTE["white"],
        "bar_cool": "url(#lg-bar-cool)", "bar_hot": "url(#lg-sev-high)",
        "baseline": PALETTE["cyan"], "glow": "url(#lg-glow)",
    }


# =====================================================================
# 4) تجميع الملفات
# =====================================================================
def build_mark_svg(
    family: str = "dark",
    plate: str | None = None,
    simplified: bool = False,
    title: str = "Android Vulnerability Severity MAS",
) -> str:
    """يبني SVG المربّع الكامل (512×512) — مع أو بلا لوحة خلفية."""
    colors = theme(family)
    # هندسة محسوبة: الرأس والحلقة في الأعلى، الأعمدة أسفلهما بهامش محفوظ،
    # وكل شيء داخل حدود الدرع (نطاقه الداخلي ≈ 162–350 أفقياً عند الأسفل).
    geometry = (
        dict(head_cx=256.0, head_cy=234.0, head_r=68.0, orbit_r=None, bar_scale=0.85, bar_base=424.0, baseline=False)
        if simplified
        else dict(head_cx=256.0, head_cy=204.0, head_r=44.0, orbit_r=66.0, bar_scale=1.0, bar_base=392.0, baseline=True)
    )
    layers = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512" '
              f'role="img" aria-label="{title}">', f"  <title>{title}</title>", defs_block()]
    if plate == "dark":
        layers.append(
            f'  <!-- لوحة داكنة مستديرة (Dark Mode) -->\n'
            f'  <rect x="0" y="0" width="512" height="512" rx="96" fill="{PALETTE["navy"]}"/>'
        )
    elif plate == "light":
        layers.append(
            f'  <!-- لوحة فاتحة مستديرة (Light Mode) -->\n'
            f'  <rect x="0" y="0" width="512" height="512" rx="96" fill="{PALETTE["paper"]}"/>'
        )
    if family not in ("mono",) and plate in (None, "dark", "light"):
        cx, cy = geometry["head_cx"], geometry["head_cy"]
        layers.append(
            f'  <!-- توهّج مركزي خفيف (محصور داخل الدرع) -->\n'
            f'  <circle cx="{cx}" cy="{cy + 16}" r="138" fill="url(#lg-glow)"/>'
        )
    bars = severity_bars_group(
        geometry["head_cx"], geometry["bar_base"], colors, geometry["bar_scale"], geometry["baseline"]
    )
    orbit = (
        ""
        if geometry["orbit_r"] is None
        else orbit_group(
            geometry["head_cx"], geometry["head_cy"] + 2, geometry["orbit_r"], colors, node_r=6.2, arrow=16.0
        )
    )
    mark_layers = [
        shield_group("lg", colors, simplified=simplified),
        orbit,
        android_head_group(geometry["head_cx"], geometry["head_cy"], geometry["head_r"], colors),
        bars,
    ]
    layers.extend(mark_layers)
    layers.append("</svg>")
    return "\n".join(layer for layer in layers if layer)


# =====================================================================
# 5) النصوص إلى مسارات (يستلزم fontTools + خطوط OFL محلية)
# =====================================================================
def _instanced_font(path: Path, weight: float):
    """يبني خطاً مثبّت الوزن من عائلة متغيّرة (Variable) ويعيد (TTFont, GlyphSet)."""
    from fontTools.ttLib import TTFont
    from fontTools.varLib.instancer import instantiateVariableFont

    font = TTFont(str(path))
    if "fvar" in font:
        axes = {axis.axisTag: (weight if axis.axisTag == "wght" else axis.defaultValue)
                for axis in font["fvar"].axes}
        font = instantiateVariableFont(font, axes)
    return font


def text_to_path(
    text: str,
    font_path: Path,
    weight: float,
    size: float,
    letter_spacing: float = 0.0,
    x: float = 0.0,
    y: float = 0.0,
) -> tuple[str, float]:
    """يحوّل نصاً إلى مسار SVG واحد ويعيد (d, العرض الكلي) — بلا أي اعتماد على خطوط."""
    from fontTools.pens.svgPathPen import SVGPathPen

    font = _instanced_font(font_path, weight)
    upem = font["head"].unitsPerEm
    cmap = font.getBestCmap()
    glyph_set = font.getGlyphSet()
    scale = size / upem
    cursor = 0.0
    segments: list[str] = []
    for char in text:
        glyph_name = cmap.get(ord(char))
        if glyph_name is None:
            cursor += size * 0.35 + letter_spacing
            continue
        pen = SVGPathPen(glyph_set)
        glyph_set[glyph_name].draw(pen)
        commands = pen.getCommands()
        if commands:
            # التحويل في عنصر مستقل: خاصية d تقبل أوامر المسار فقط (M/L/Q/C/Z)
            segments.append(
                f'<path transform="translate({x + cursor:.2f} {y:.2f}) scale({scale:.6f} {-scale:.6f})" '
                f'd="{commands}"/>'
            )
        cursor += glyph_set[glyph_name].width * scale + letter_spacing
    return (" ".join(segments), cursor - (letter_spacing if text else 0.0))


def build_horizontal_svg(family: str = "dark_plate") -> str:
    """الشعار الأفقي 1200×300: العلامة يساراً + الاسم سطرين + شعار فرعي بأقواس.

    التخطيط محسوب بالأرقام: العلامة 512×512 بمقياس 0.47 ⇒ 240.6px، تبدأ عند x=40،
    ويبدأ كتلة النص عند x=330 مع فاصل بصري واضح بين العلامة والاسم.
    """
    colors = theme("ink" if family == "light_plate" else "dark")
    width, height = 1200, 300
    plate_fill = PALETTE["navy"] if family == "dark_plate" else PALETTE["paper"]
    text_main = PALETTE["white"] if family == "dark_plate" else PALETTE["gray_dark"]
    text_sub = PALETTE["gray_mid"] if family == "dark_plate" else "#4A5C72"

    mark = "\n".join(
        [
            shield_group("lg", colors),
            orbit_group(256.0, 206.0, 66.0, colors, node_r=6.2, arrow=16.0),
            android_head_group(256.0, 204.0, 44.0, colors),
            severity_bars_group(256.0, 392.0, colors, 1.0, baseline=True),
        ]
    )

    text_x = 330.0
    line1, line1_w = text_to_path(
        "ANDROID VULN", FONT_DIR / "SpaceGrotesk.ttf", 700, 66.0, letter_spacing=5.5, x=text_x, y=126
    )
    line2, line2_w = text_to_path(
        "SEVERITY MAS", FONT_DIR / "SpaceGrotesk.ttf", 700, 66.0, letter_spacing=5.5, x=text_x, y=196
    )
    title_w = max(line1_w, line2_w)

    chev_l, chev_l_w = text_to_path("<", FONT_DIR / "JetBrainsMono.ttf", 600, 24.0, x=text_x, y=246)
    tagline, tagline_w = text_to_path(
        "MULTI-AGENT · OWASP MASVS · HITL",
        FONT_DIR / "JetBrainsMono.ttf", 500, 21.0, letter_spacing=2.6, x=text_x + chev_l_w + 10, y=246,
    )
    chev_r, _ = text_to_path(
        ">", FONT_DIR / "JetBrainsMono.ttf", 600, 24.0, x=text_x + chev_l_w + 10 + tagline_w + 10, y=246
    )
    # خط فاصل رفيع أسفل الاسم (تفصيل بصري يربط الكتلة)
    rule_y = 226.0
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" aria-label="Android Vulnerability Severity MAS — horizontal logo">
  <title>Android Vulnerability Severity MAS</title>
{defs_block()}
  <!-- لوحة الخلفية (متجاوبة لونياً مع الوضعين) -->
  <rect x="0" y="0" width="{width}" height="{height}" fill="{plate_fill}"/>
  <!-- العلامة على اليسار: مقياس 0.47 × 512 = 240.6px -->
  <g transform="translate(40 30) scale(0.47)">
{mark}
  </g>
  <!-- الاسم: مسارات متجهية محوّلة من Space Grotesk (OFL) -->
  <g fill="{text_main}">
    {line1}
    {line2}
  </g>
  <path d="M {text_x} {rule_y} H {text_x + title_w:.1f}" stroke="{PALETTE['cyan']}" stroke-width="3" stroke-linecap="round" opacity="0.85"/>
  <!-- الشعار الفرعي: خط أحادي + قوسان برمجيان بالسيان -->
  <g fill="{PALETTE['cyan']}">{chev_l}{chev_r}</g>
  <g fill="{text_sub}">{tagline}</g>
</svg>
"""


# =====================================================================
# 6) التصدير: PNG + ICO
# =====================================================================
def write_svg(name: str, content: str) -> Path:
    """يكتب ملف SVG ويعيد مساره."""
    path = LOGO_DIR / name
    path.write_text(content, encoding="utf-8")
    return path


def render_png(svg_path: Path, out_path: Path, width: int, height: int | None = None) -> Path:
    """يُصيّر SVG إلى PNG بالحجم المطلوب (cairosvg)."""
    import cairosvg

    cairosvg.svg2png(
        url=str(svg_path), write_to=str(out_path),
        output_width=width, output_height=height or width,
    )
    return out_path


def build_favicon(source_svg: Path, out_path: Path, sizes: Sequence[int] = (16, 32, 48, 64)) -> Path:
    """يبني favicon.ico متعدد الأحجام — كل حجم مُصيَّر من المتجه مباشرة (حدّة كاملة)."""
    import io

    from PIL import Image

    frames = []
    for size in sizes:
        buffer = io.BytesIO()
        import cairosvg

        cairosvg.svg2png(url=str(source_svg), write_to=buffer, output_width=size, output_height=size)
        buffer.seek(0)
        frames.append(Image.open(buffer).convert("RGBA"))
    frames[-1].save(out_path, format="ICO", sizes=[(s, s) for s in sizes])
    return out_path


# =====================================================================
# 7) المعاينة + الدليل (يكتبهما السكربت أيضاً ليبقيا متطابقين مع المصدر)
# =====================================================================
def build_preview_html(svgs: dict[str, str]) -> str:
    """صفحة معاينة مستقلة (SVG مضمّن — تعمل بلا إنترنت وبلا خطوط خارجية)."""
    cards = []
    for name, svg in svgs.items():
        cards.append(
            f'<figure class="card"><div class="frame">{svg}</div>'
            f"<figcaption><code>{name}</code></figcaption></figure>"
        )
    return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>هوية Android Vulnerability Severity MAS</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; padding: 40px 24px; background: {PALETTE['navy']}; color: {PALETTE['gray_light']};
         font-family: "Cairo", "Segoe UI", system-ui, sans-serif; }}
  h1 {{ font-size: 30px; margin: 0 0 6px; letter-spacing: .5px; }}
  h2 {{ font-size: 19px; margin: 44px 0 14px; color: {PALETTE['cyan_bright']}; font-weight: 600; }}
  p.lead {{ color: {PALETTE['gray_mid']}; margin: 0 0 8px; }}
  .swatches {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 10px 0 4px; }}
  .sw {{ width: 148px; border-radius: 12px; overflow: hidden; border: 1px solid #23364d; }}
  .sw .chip {{ height: 62px; }}
  .sw .meta {{ padding: 8px 10px; font-size: 12px; line-height: 1.6; font-family: ui-monospace, monospace; }}
  .grid {{ display: grid; gap: 22px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }}
  .card {{ margin: 0; background: #0E2233; border: 1px solid #23364d; border-radius: 16px; padding: 18px; }}
  .frame {{ display: grid; place-items: center; padding: 12px; background:
            repeating-conic-gradient(#16283c 0% 25%, #12213418 0% 50%) 50% / 22px 22px; border-radius: 12px; }}
  .frame svg {{ width: 100%; height: auto; max-width: 300px; }}
  figcaption {{ margin-top: 12px; text-align: center; font-size: 12.5px; color: {PALETTE['gray_mid']}; }}
  .wide .frame svg {{ max-width: 100%; }}
  .sizes {{ display: flex; align-items: flex-end; gap: 20px; flex-wrap: wrap; }}
  .sizes div {{ text-align: center; font-size: 12px; color: {PALETTE['gray_mid']}; }}
  footer {{ margin-top: 48px; color: {PALETTE['gray_mid']}; font-size: 13px; border-top: 1px solid #23364d; padding-top: 18px; }}
</style>
</head>
<body>
<h1>Android Vulnerability Severity MAS</h1>
<p class="lead">الهوية البصرية v1.0 — مولَّدة آلياً بـ <code>scripts/build_logo.py</code> (مسارات متجهية، بلا خطوط خارجية).</p>
<p class="lead">المهندس محمد منير · <a style="color:{PALETTE['cyan']}" href="mailto:moh123mon456@gmail.com">moh123mon456@gmail.com</a></p>

<h2>لوحة الألوان</h2>
<div class="swatches">
  <div class="sw"><div class="chip" style="background:{PALETTE['navy']}"></div><div class="meta">Navy #0A1929</div></div>
  <div class="sw"><div class="chip" style="background:{PALETTE['cyan']}"></div><div class="meta">Cyan #00B4D8</div></div>
  <div class="sw"><div class="chip" style="background:{PALETTE['cyan_bright']}"></div><div class="meta">Cyan Bright #48CAE4</div></div>
  <div class="sw"><div class="chip" style="background:{PALETTE['green']}"></div><div class="meta">Green #00FF88</div></div>
  <div class="sw"><div class="chip" style="background:{PALETTE['orange']}"></div><div class="meta">Orange #FF6B35</div></div>
  <div class="sw"><div class="chip" style="background:{PALETTE['red']}"></div><div class="meta">Red #D62828</div></div>
  <div class="sw"><div class="chip" style="background:{PALETTE['gray_light']}"></div><div class="meta">Text #E0E0E0</div></div>
</div>

<h2>النسخ الرسمية</h2>
<div class="grid">
{''.join(cards[:2])}
</div>
<div class="grid wide" style="margin-top:22px">
{''.join(cards[2:])}
</div>

<h2>أحجام الاستخدام (من المتجه مباشرة)</h2>
<div class="sizes">
  <div><div style="width:16px;height:16px">{svgs['logo-icon.svg'].replace('width="512" height="512"', 'width="16" height="16"')}</div>16px</div>
  <div><div style="width:32px;height:32px">{svgs['logo-icon.svg'].replace('width="512" height="512"', 'width="32" height="32"')}</div>32px</div>
  <div><div style="width:64px;height:64px">{svgs['logo-icon.svg'].replace('width="512" height="512"', 'width="64" height="64"')}</div>64px</div>
  <div><div style="width:128px;height:128px">{svgs['logo-icon.svg'].replace('width="512" height="512"', 'width="128" height="128"')}</div>128px</div>
</div>

<footer>© 2026 Engineer Mohammed Moneer · MIT License · <code>assets/logo/preview.html</code></footer>
</body>
</html>
"""



def build_usage_svg() -> str:
    """لوحة «افعل/لا تفعل» (8 بطاقات) — مرجع بصري لدليل الهوية.

    ملاحظة تنفيذية: التسميات **بالإنجليزية** لأن مُصيّر SVG (cairosvg) لا يطبّق
    تشكيل Bidi/الاتصال العربي على عناصر `<text>` — والنص العربي الكامل موجود في
    ``BRAND_GUIDE.md`` الذي يُعرض في المتصفح. البطاقات الأربع الصحيحة تعرض النسخ
    الرسمية نفسها، والأربع الخاطئة **نفس** المكوّنات بتحويل مقصود.
    """
    dark = theme("dark")
    ink = theme("ink")
    mono = theme("mono")

    def mark(layers_theme: dict[str, str], simple: bool = False) -> str:
        geometry = (
            dict(cx=256.0, cy=234.0, r=68.0, orbit=None, bars=424.0, scale=0.85, baseline=False)
            if simple
            else dict(cx=256.0, cy=204.0, r=44.0, orbit=66.0, bars=392.0, scale=1.0, baseline=True)
        )
        parts = [shield_group("lg", layers_theme, simplified=simple)]
        if geometry["orbit"] is not None:
            parts.append(orbit_group(geometry["cx"], geometry["cy"] + 2, geometry["orbit"], layers_theme, 6.2, 16.0))
        parts.append(android_head_group(geometry["cx"], geometry["cy"], geometry["r"], layers_theme))
        parts.append(severity_bars_group(geometry["cx"], geometry["bars"], layers_theme, geometry["scale"], geometry["baseline"]))
        return "\n".join(parts)

    def tile(
        x: float, y: float, label: str, good: bool, glyph: str,
        bg: str = PALETTE["navy_800"], body: str | None = None,
        transform: str = "", overlay: str = "", text_color: str | None = None,
    ) -> str:
        """بطاقة 258×258: خلفية + العلامة (بتحويل/تشوش اختياري) + تسمية + شارة."""
        body = body if body is not None else mark(theme("dark"))
        badge = PALETTE["green"] if good else PALETTE["red"]
        label_color = text_color or PALETTE["gray_light"]
        return (
            f'  <g transform="translate({x} {y})">\n'
            f'    <rect width="258" height="258" rx="18" fill="{bg}" stroke="{PALETTE["navy_600"]}"/>\n'
            f'    <g transform="translate(24 16) scale(0.41)"><g transform="{transform}">\n{body}\n      </g></g>\n'
            f'    {overlay}\n'
            f'    <circle cx="232" cy="30" r="14" fill="{badge}"/>\n'
            f'    <text x="232" y="35" text-anchor="middle" font-family="sans-serif" font-size="15" font-weight="700" fill="{PALETTE["navy"]}">{glyph}</text>\n'
            f'    <text x="16" y="240" font-family="sans-serif" font-size="14.5" fill="{label_color}">{label}</text>\n'
            f'  </g>'
        )

    du = [
        tile(20, 96, "Primary mark · logo-dark.svg", True, "✓"),
        tile(298, 96, "Light surfaces · logo-light.svg", True, "✓", bg=PALETTE["paper"],
             body=mark(ink), text_color=PALETTE["gray_dark"]),
        tile(576, 96, "Below 48px · logo-icon.svg", True, "✓", body=mark(theme("dark"), simple=True)),
        tile(854, 96, "Print / 1-color · logo-mono.svg", True, "✓", bg=PALETTE["white"],
             body=mark(mono), text_color=PALETTE["gray_dark"]),
    ]
    donts = [
        tile(20, 396, "Don&#39;t stretch or squash", False, "✕", transform="scale(1.16 0.84)"),
        tile(298, 396, "Don&#39;t rotate or skew", False, "✕", transform="rotate(16 256 256)"),
        tile(576, 396, "Don&#39;t tint outside palette", False, "✕", bg="#6D28D9",
             overlay=f'<rect x="0" y="0" width="258" height="258" rx="18" fill="#F472B6" opacity="0.38"/>'),
        tile(854, 396, "Don&#39;t place on low contrast", False, "✕", bg=PALETTE["cyan"],
             overlay='<rect x="0" y="0" width="258" height="258" rx="18" fill="#00B4D8" opacity="0.55"/>'),
    ]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1132 678" width="1132" height="678" role="img" aria-label="Logo usage: do and don't">
  <title>Logo usage — do &amp; don&#39;t — Android Vulnerability Severity MAS</title>
{defs_block()}
  <rect width="1132" height="678" fill="{PALETTE['navy']}"/>
  <text x="20" y="42" font-family="sans-serif" font-size="22" font-weight="700" fill="{PALETTE['white']}">DO — approved applications</text>
  <text x="20" y="66" font-family="ui-monospace, monospace" font-size="13" fill="{PALETTE['gray_mid']}">Android Vulnerability Severity MAS · Brand v1.0 · assets/logo/</text>
  <text x="20" y="382" font-family="sans-serif" font-size="22" font-weight="700" fill="{PALETTE['orange']}">DON&#39;T — misuse</text>
{chr(10).join(du)}
{chr(10).join(donts)}
</svg>
"""



def main() -> None:
    """يبني كل الملفات ويطبع تقريراً مختصراً."""
    LOGO_DIR.mkdir(parents=True, exist_ok=True)

    # ── الملفات المتجهية ──
    dark_mark = build_mark_svg("dark", plate=None)
    svgs: dict[str, str] = {}

    svgs["logo.svg"] = build_mark_svg("dark", plate=None)          # الأساسي (شفاف، للخلفيات الداكنة)
    svgs["logo-dark.svg"] = build_mark_svg("dark", plate="dark")   # لوحة داكنة
    svgs["logo-light.svg"] = build_mark_svg("ink", plate="light")  # لوحة فاتحة
    svgs["logo-icon.svg"] = build_mark_svg("dark", plate="dark", simplified=True)
    svgs["logo-mono.svg"] = build_mark_svg("mono", plate=None)
    svgs["logo-horizontal.svg"] = build_horizontal_svg("dark_plate")

    written: list[Path] = [write_svg(name, content) for name, content in svgs.items()]

    # ── الصور النقطية ──
    written.append(render_png(LOGO_DIR / "logo-dark.svg", LOGO_DIR / "logo.png", 512))
    written.append(render_png(LOGO_DIR / "logo-dark.svg", LOGO_DIR / "logo@2x.png", 1024))
    written.append(render_png(LOGO_DIR / "logo-icon.svg", LOGO_DIR / "logo-icon.png", 64))
    written.append(render_png(LOGO_DIR / "logo-icon.svg", LOGO_DIR / "logo-icon@2x.png", 128))
    written.append(render_png(LOGO_DIR / "logo-horizontal.svg", LOGO_DIR / "logo-horizontal.png", 1200, 300))
    written.append(build_favicon(LOGO_DIR / "logo-icon.svg", LOGO_DIR / "favicon.ico"))

    # ── النسخ المرآتية في مجلد رسوم الأطروحة ──
    figures = PROJECT_ROOT / "docs" / "thesis" / "figures" / "brand"
    figures.mkdir(parents=True, exist_ok=True)
    for name in ("logo.svg", "logo-dark.svg", "logo-horizontal.svg", "logo-icon.svg"):
        (figures / name).write_text(svgs[name], encoding="utf-8")

    # ── لوحة الاستخدام + المعاينة ──
    usage = write_svg("usage-dos-donts.svg", build_usage_svg())
    written.append(usage)

    preview = LOGO_DIR / "preview.html"
    preview.write_text(build_preview_html(svgs), encoding="utf-8")
    written.append(preview)

    print(f"✅ ملفات الهوية: {len(written)} ملفاً في assets/logo/")
    for path in written:
        print(f"   · {path.name:24s} {path.stat().st_size / 1024:8.1f} KiB")
    print(f"   · نسخ الأطروحة في {figures.relative_to(PROJECT_ROOT)}/ (4 ملفات)")


if __name__ == "__main__":
    main()
