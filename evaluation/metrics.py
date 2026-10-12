"""المقاييس الإحصائية لتجربة القياس (المرحلة 7).

كل دالة هنا مُختبرة بأمثلة محسوبة يدوياً في tests/unit/test_metrics.py:
    • precision_recall_f1        — كشف الثغرات (RQ1)
    • percent_agreement          — الاتفاق الخام (RQ2)
    • weighted_cohens_kappa      — كابا كوهين بأوزان تربيعية (RQ2) — sklearn
    • manual_quadratic_kappa     — نفس المعادلة يدوياً (تحقق متقاطع إجباري)
    • gwet_ac1                   — Gwet's AC1 يدوياً (غير متوفر في sklearn) (RQ2)
    • confusion_matrix           — مصفوفة الالتباس بترتيب فئات ثابت
    • bootstrap_ci               — فترات ثقة 95% بـ 10000 إعادة معاينة
    • interpret_kappa            — سلّم Landis & Koch
    • cohens_d_paired / paired_test — حجم الأثر والاختبار المزدوج (RQ5)

قرارات موثقة (docs/evaluation_protocol.md):
    • أوزان كابا تربيعية: w_ij = (i−j)²/(K−1)² — العقوبة تربيعية لتباعد الفئات.
    • فئات الخطورة مرتبة ترتيباً ترتيبياً: Low=0 → Medium=1 → High=2 → Critical=3.
    • طريقة البووتستراب: percentile method على إعادة معاينة العناصر (الأزواج)
      بذرة ثابتة افتراضية (42) — إعادة إنتاج كاملة.
    • AC1 صيغة Gwet (2008): Pe = Σ π_k(1−π_k)/(q−1) حيث π_k حصة الفئة k من
      مجموع تقييمي المتقيّمين — تتفادى مفارقة كابا عند انتشار فئة واحدة.
"""
from __future__ import annotations

import math
import warnings
from typing import Any, Callable, Optional, Sequence

import numpy as np

# ترتيب الفئات الترتيبي المعتمد (Low أخف — Critical أشد)
SEVERITY_CATEGORIES: list[str] = ["Low", "Medium", "High", "Critical"]
ORDINAL = {label: index for index, label in enumerate(SEVERITY_CATEGORIES)}

BOOTSTRAP_DEFAULT_ITERATIONS = 10_000
BOOTSTRAP_DEFAULT_SEED = 42

KAPPA_BANDS = [
    (0.20, "ضعيف جداً"),
    (0.40, "ضعيف"),
    (0.60, "متوسط"),
    (0.80, "جيد"),
    (1.01, "ممتاز"),
]


# =====================================================================
# 1) كشف الثغرات
# =====================================================================
def precision_recall_f1(tp: int, fp: int, fn: int) -> dict[str, float]:
    """Precision/Recall/F1 من أعداد المواجهة — بحصانة أقسام على صفر."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
    }


# =====================================================================
# 2) الاتفاق بين متقيّمَين
# =====================================================================
def _validate_pair(rater1: Sequence[Any], rater2: Sequence[Any]) -> None:
    """تحقق مشترك: قوائم متساوية الطول وغير فارغة."""
    if len(rater1) != len(rater2):
        raise ValueError("طول قائمتي المتقيّمَين مختلف")
    if len(rater1) == 0:
        raise ValueError("لا بيانات — قائمة فارغة")


def percent_agreement(rater1: Sequence[Any], rater2: Sequence[Any]) -> float:
    """نسبة الاتفاق الخام = المتطابقات / الإجمالي."""
    _validate_pair(rater1, rater2)
    matches = sum(1 for a, b in zip(rater1, rater2, strict=True) if a == b)
    return round(matches / len(rater1), 4)


def _to_ordinal(values: Sequence[Any], categories: Sequence[str]) -> list[int]:
    """يحوّل تسميات الخطورة النصية إلى أرقام ترتيبية بترتيب الفئات المعطى."""
    mapping = {label: index for index, label in enumerate(categories)}
    result = []
    for value in values:
        if isinstance(value, str):
            if value not in mapping:
                raise ValueError(f"فئة غير معروفة: {value}")
            result.append(mapping[value])
        else:
            result.append(int(value))
    return result


def weighted_cohens_kappa(
    rater1: Sequence[Any],
    rater2: Sequence[Any],
    weights: str = "quadratic",
    categories: Optional[Sequence[str]] = None,
) -> float:
    """كابا كوهين الموزونة (عبر sklearn) — تحويل ترتيبي للفئات النصية."""
    from sklearn.metrics import cohen_kappa_score

    _validate_pair(rater1, rater2)
    labels = list(categories or SEVERITY_CATEGORIES)
    y1 = _to_ordinal(rater1, labels)
    y2 = _to_ordinal(rater2, labels)
    with warnings.catch_warnings():  # sklearn يحذّر على الحالات المنحلّة
        warnings.simplefilter("ignore")
        try:
            value = float(cohen_kappa_score(y1, y2, weights=weights))
        except Exception:
            value = float("nan")
    if math.isnan(value):
        # الحالة المنحلّة 0/0 (متقيّم ثابت لا تباين لديه): تُحسم بالحساب اليدوي
        # وفق الاتفاق الاصطلاحي الموثق في protocol.md (تطابق تام ⇒ 1.0).
        return manual_quadratic_kappa(rater1, rater2, categories=labels)
    return round(value, 4)


def manual_quadratic_kappa(
    rater1: Sequence[Any],
    rater2: Sequence[Any],
    categories: Optional[Sequence[str]] = None,
) -> float:
    """كابا التربيعي يدوياً: 1 − ΣW∘O / ΣW∘E — تحقق متقاطع ضد sklearn.

    w_ij = (i−j)²/(K−1)² ، O مصفوفة التوافق المرصودة،
    E_ij = h1_i·h2_j/n (حاصل ضرب الهوامش).
    """
    _validate_pair(rater1, rater2)
    labels = list(categories or SEVERITY_CATEGORIES)
    y1 = _to_ordinal(rater1, labels)
    y2 = _to_ordinal(rater2, labels)
    k = len(labels)
    observed = np.zeros((k, k), dtype=float)
    for a, b in zip(y1, y2, strict=True):
        observed[a, b] += 1
    n = observed.sum()
    if k > 1:
        weights_matrix = np.array(
            [[(i - j) ** 2 / ((k - 1) ** 2) for j in range(k)] for i in range(k)]
        )
    else:
        weights_matrix = np.zeros((1, 1))
    expected = np.outer(observed.sum(axis=1), observed.sum(axis=0)) / n
    numerator = float((weights_matrix * observed).sum())
    denominator = float((weights_matrix * expected).sum())
    if denominator == 0:  # كل الأزواج مطابقة تماماً
        return 1.0 if numerator == 0 else 0.0
    return round(1.0 - numerator / denominator, 4)


def gwet_ac1(
    rater1: Sequence[Any],
    rater2: Sequence[Any],
    categories: Optional[Sequence[str]] = None,
) -> float:
    """Gwet's AC1 يدوياً (2008) — لا يتوفر في sklearn.

    AC1 = (Po − Pe) / (1 − Pe) حيث Pe = Σ_k π_k(1−π_k)/(q−1)
    و π_k = (عدد تقييمات الفئة k لدى المتقيّمَين) / (2n).
    """
    _validate_pair(rater1, rater2)
    labels = list(categories or SEVERITY_CATEGORIES)
    n = len(rater1)
    observed_agreement = sum(1 for a, b in zip(rater1, rater2, strict=True) if a == b) / n
    q = len(labels)
    if q < 2:
        return 1.0 if observed_agreement == 1.0 else 0.0
    counts = {label: 0 for label in labels}
    for value in list(rater1) + list(rater2):
        if value in counts:
            counts[value] += 1
        elif isinstance(value, str):
            raise ValueError(f"فئة غير معروفة: {value}")
    proportions = np.array([counts[label] / (2 * n) for label in labels])
    chance = float(np.sum(proportions * (1 - proportions)) / (q - 1))
    if chance >= 1.0:
        return 1.0 if observed_agreement == 1.0 else 0.0
    return round((observed_agreement - chance) / (1 - chance), 4)


def confusion_matrix(
    rater1: Sequence[Any],
    rater2: Sequence[Any],
    categories: Optional[Sequence[str]] = None,
) -> np.ndarray:
    """مصفوفة الالتباس: الصفوف = rater1 والعمود = rater2 بترتيب الفئات."""
    _validate_pair(rater1, rater2)
    labels = list(categories or SEVERITY_CATEGORIES)
    index = {label: position for position, label in enumerate(labels)}
    matrix = np.zeros((len(labels), len(labels)), dtype=int)
    for a, b in zip(rater1, rater2, strict=True):
        if a not in index or b not in index:
            raise ValueError(f"فئة خارج القائمة: {a} / {b}")
        matrix[index[a], index[b]] += 1
    return matrix


# =====================================================================
# 3) البووتستراب وفترات الثقة
# =====================================================================
def bootstrap_ci(
    data: Sequence[Any],
    metric_func: Callable[[list[Any]], float],
    n_iterations: int = BOOTSTRAP_DEFAULT_ITERATIONS,
    ci: float = 0.95,
    seed: int = BOOTSTRAP_DEFAULT_SEED,
) -> tuple[float, float]:
    """فترة ثقة بالنسب المئوية (percentile) بـ 10000 إعادة معاينة.

    metric_func يستقبل عيّنة معاد معاينتها (نفس نوع عناصر data) ويعيد قيمة.
    """
    if not data:
        raise ValueError("لا بيانات للبووتستراب")
    if n_iterations < 100:
        raise ValueError("n_iterations < 100 — عيّنات غير موثوقة")
    rng = np.random.default_rng(seed)
    values = np.asarray(data, dtype=object)
    n = len(values)
    statistics = np.empty(n_iterations, dtype=float)
    for iteration in range(n_iterations):
        sample = values[rng.integers(0, n, size=n)].tolist()
        statistics[iteration] = float(metric_func(sample))
    lower = float(np.quantile(statistics, (1 - ci) / 2))
    upper = float(np.quantile(statistics, 1 - (1 - ci) / 2))
    return round(lower, 4), round(upper, 4)


# =====================================================================
# 4) التفسير وحجم الأثر
# =====================================================================
def interpret_kappa(kappa_value: float) -> str:
    """سلّم Landis & Koch — التسمية العربية للمدى."""
    for upper, label in KAPPA_BANDS:
        if kappa_value < upper:
            return label
    return "ممتاز"


def cohens_d_paired(sample_a: Sequence[float], sample_b: Sequence[float]) -> dict[str, float]:
    """حجم الأثر المزدوج: d = mean(diff)/sd(diff) — diff = b − a."""
    if len(sample_a) != len(sample_b):
        raise ValueError("طول العيّنتين مختلف")
    diffs = np.asarray(sample_b, dtype=float) - np.asarray(sample_a, dtype=float)
    if len(diffs) < 2:
        raise ValueError("حجم أثر يحتاج ≥ 2 فروق")
    sd = float(diffs.std(ddof=1))
    d = float(diffs.mean() / sd) if sd > 0 else 0.0
    return {"d": round(d, 4), "mean_diff": round(float(diffs.mean()), 4), "sd_diff": round(sd, 4)}


def paired_test(sample_a: Sequence[float], sample_b: Sequence[float]) -> dict[str, Any]:
    """اختبار مزدوج: t-test + Wilcoxon + حجم الأثر (scipy) للـ A/B (RQ5)."""
    from scipy import stats

    if len(sample_a) != len(sample_b):
        raise ValueError("طول العيّنتين مختلف")
    n = len(sample_a)
    if n < 2:
        return {"n": n, "note": "n < 2 — لا يكفي لاختبار مزدوج", "t_stat": None, "t_pvalue": None,
                "wilcoxon_stat": None, "wilcoxon_pvalue": None, "cohens_d": None}
    result: dict[str, Any] = {"n": n}
    t_stat, t_p = stats.ttest_rel(sample_a, sample_b)
    result["t_stat"] = round(float(t_stat), 4)
    result["t_pvalue"] = round(float(t_p), 4)
    try:
        with warnings.catch_warnings():  # فروق صفرية ⇒ scipy يحذّر قبل ValueError
            warnings.simplefilter("ignore")
            w_stat, w_p = stats.wilcoxon(sample_a, sample_b)
        result["wilcoxon_stat"] = round(float(w_stat), 4)
        result["wilcoxon_pvalue"] = round(float(w_p), 4)
    except ValueError:  # كل الفروق صفر (تطابق تام) — موثق لا خطأ
        result["wilcoxon_stat"] = 0.0
        result["wilcoxon_pvalue"] = 1.0
        result["note"] = "كل الفروق صفرية — اختبر Wilcoxon غير معرّف"
    effect = cohens_d_paired(sample_a, sample_b)
    result["mean_diff"] = effect["mean_diff"]
    result["cohens_d"] = effect["d"] if len(sample_a) >= 2 else None
    return result
