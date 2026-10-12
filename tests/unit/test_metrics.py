"""اختبارات وحدة — المقاييس الإحصائية (المرحلة 7).

★ كل قيمة متوقعة في هذا الملف محسوبة يدوياً (hand-computed) ومدوّنة في
  التعليقات بخطواتها، ثم تطابقها الدوال — لا لقطات آلية أعمى.
"""
from __future__ import annotations

import numpy as np
import pytest

from evaluation.metrics import (
    SEVERITY_CATEGORIES,
    bootstrap_ci,
    cohens_d_paired,
    confusion_matrix,
    gwet_ac1,
    interpret_kappa,
    manual_quadratic_kappa,
    paired_test,
    percent_agreement,
    precision_recall_f1,
    weighted_cohens_kappa,
)


# =====================================================================
# 1) precision_recall_f1
# =====================================================================
class TestPrecisionRecallF1:
    def test_hand_computed_case(self) -> None:
        """tp=8, fp=2, fn=4 ⇒ P=8/10=0.8 · R=8/12=0.6667 · F1=8/11=0.7273."""
        result = precision_recall_f1(tp=8, fp=2, fn=4)
        assert result["precision"] == 0.8
        assert result["recall"] == pytest.approx(0.6667, abs=1e-4)
        assert result["f1"] == pytest.approx(0.7273, abs=1e-4)  # 2·0.8·(2/3)/(0.8+2/3)=8/11
        assert result["tp"] == 8 and result["fp"] == 2 and result["fn"] == 4

    def test_perfect_and_empty_cases(self) -> None:
        perfect = precision_recall_f1(tp=10, fp=0, fn=0)
        assert perfect["precision"] == perfect["recall"] == perfect["f1"] == 1.0
        empty = precision_recall_f1(tp=0, fp=0, fn=0)
        assert empty["precision"] == empty["recall"] == empty["f1"] == 0.0

    def test_zero_division_guards(self) -> None:
        only_fp = precision_recall_f1(tp=0, fp=5, fn=0)
        assert only_fp["precision"] == 0.0 and only_fp["f1"] == 0.0
        only_fn = precision_recall_f1(tp=0, fp=0, fn=5)
        assert only_fn["recall"] == 0.0


# =====================================================================
# 2) percent_agreement
# =====================================================================
class TestPercentAgreement:
    def test_hand_computed_case(self) -> None:
        """5 عناصر، 3 متطابقة ⇒ 0.6."""
        rater1 = ["Critical", "High", "Low", "Medium", "Low"]
        rater2 = ["Critical", "Medium", "Low", "High", "Low"]  # متطابق في 1,3,5
        assert percent_agreement(rater1, rater2) == 0.6

    def test_perfect(self) -> None:
        assert percent_agreement(["High"], ["High"]) == 1.0

    def test_length_mismatch_raises(self) -> None:
        with pytest.raises(ValueError):
            percent_agreement(["High"], ["High", "Low"])

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            percent_agreement([], [])


# =====================================================================
# 3) weighted_cohens_kappa (+ التحقق اليدوي المتقاطع)
# =====================================================================
class TestWeightedKappa:
    def test_hand_computed_case(self) -> None:
        """سيناريو محسوب يدوياً (3 فئات، أوزان w=(i−j)²/4):
        r1=[0,0,1,1,2,2]، r2=[0,1,1,1,2,2] ⇒ 5 اتفاق من 6.
        O=[[1,1,0],[0,3,0],[0,0,2]] ⇒ Do=Σw∘O/n=(1/4)/6=1/24
        E=هوامش⊤/n=الصفوف [2,6,4]/6 ⇒ Σw∘E=1.75 ⇒ De=1.75/6=7/24
        κ = 1 − (1/24)/(7/24) = 1 − 1/7 = 6/7 = 0.8571."""
        rater1 = [0, 0, 1, 1, 2, 2]
        rater2 = [0, 1, 1, 1, 2, 2]
        categories = ["A", "B", "C"]
        assert weighted_cohens_kappa(rater1, rater2, categories=categories) == pytest.approx(
            0.8571, abs=1e-4
        )  # 6/7
        # تقاطع مع الحساب اليدوي (نفس المعادلة دون sklearn)
        assert manual_quadratic_kappa(rater1, rater2, categories=categories) == pytest.approx(
            0.8571, abs=1e-4
        )

    def test_sklearn_and_manual_agree(self) -> None:
        """عيّنة أوسع: الدالتان يجب أن تتطابقا في كل الحالات."""
        rng = np.random.default_rng(7)
        rater1 = rng.integers(0, 4, size=200).tolist()
        rater2 = np.clip(rng.normal(0.4, 1.1, size=200), 0, 3).round().astype(int).tolist()
        assert weighted_cohens_kappa(rater1, rater2, categories=["L0", "L1", "L2", "L3"]) == pytest.approx(
            manual_quadratic_kappa(rater1, rater2, categories=["L0", "L1", "L2", "L3"]), abs=1e-4
        )

    def test_perfect_and_chance_cases(self) -> None:
        perfect = ["Low", "Medium", "High", "Critical"]
        assert weighted_cohens_kappa(perfect, perfect) == 1.0
        # حالة منحلّة 0/0: متقيّم ثابت تماماً (لا تباين) — sklearn يعيد NaN
        # فنحسمها اصطلاحياً (تطابق تام ⇒ 1.0) عبر الحساب اليدوي (موثق)
        constant = ["High"] * 4
        assert weighted_cohens_kappa(constant, constant) == 1.0
        assert weighted_cohens_kappa(["High"] * 4, ["Low"] * 4) == 0.0

    def test_severity_strings_ordinal_mapping(self) -> None:
        """العقوبة التربيعية تصنّف الأحكام بعيد المدى (كلا السيناريوهين محسوب يدوياً):
        سيناريو أ: خطأ واحد High→Critical (خطوة): κ = 1 − (1/36)/(2/9) = 7/8 = 0.875
        سيناريو ب: خطأ واحد Low→Critical (3 خطوات): κ = 1 − (1/4)/(5/18) = 1/10 = 0.1
        نفس عدد الأخطاء (1 من 4) — الكابا التربيعي يميّز البُعد."""
        assert SEVERITY_CATEGORIES == ["Low", "Medium", "High", "Critical"]
        one_step = weighted_cohens_kappa(
            ["Low", "Medium", "High", "High"], ["Low", "Medium", "High", "Critical"]
        )
        three_step = weighted_cohens_kappa(
            ["Low", "Medium", "High", "Low"], ["Low", "Medium", "High", "Critical"]
        )
        assert one_step == pytest.approx(0.875, abs=1e-4)
        assert three_step == pytest.approx(0.1, abs=1e-4)
        assert one_step > three_step


# =====================================================================
# 4) Gwet's AC1
# =====================================================================
class TestGwetAC1:
    def test_hand_computed_case(self) -> None:
        """r1=[1,1,2,2]، r2=[1,2,2,2]:
        Po=3/4=0.75 · π1=3/8, π2=5/8 · Pe=(3/8·5/8+5/8·3/8)/1=30/64=0.46875
        AC1=(0.75−0.46875)/(1−0.46875)=0.28125/0.53125=9/17=0.5294."""
        assert gwet_ac1([1, 1, 2, 2], [1, 2, 2, 2], categories=[1, 2]) == pytest.approx(
            0.5294, abs=1e-4
        )

    def test_perfect_agreement(self) -> None:
        """اتفاق تام على فئة واحدة: πk=1 ⇒ Pe=0 ⇒ AC1=1 (ميزة AC1 على κ)."""
        assert gwet_ac1(["High"] * 5, ["High"] * 5) == 1.0

    def test_disagreement_negative(self) -> None:
        """تباعد شبه كامل ⇒ AC1 سالب (أسوأ من الصدفة)."""
        assert gwet_ac1(["Low", "Low", "Low"], ["Critical", "Critical", "Critical"]) < 0

    def test_kappa_paradox_advantage(self) -> None:
        """حالة تفضيل AC1 الموثقة: انتشار فئة غالبة + اتفاق خام عالٍ."""
        rater1 = ["Low"] * 8 + ["High", "High"]
        rater2 = ["Low"] * 7 + ["High"] * 3
        # اتفاق خام = 7 Low + 2 High = 9/10
        assert percent_agreement(rater1, rater2) == 0.9
        kappa = weighted_cohens_kappa(rater1, rater2)
        ac1 = gwet_ac1(rater1, rater2)
        assert ac1 > kappa, "AC1 يجب أن يعالج مفارقة الانتشار أفضل من κ هنا"


# =====================================================================
# 5) confusion_matrix
# =====================================================================
class TestConfusionMatrix:
    def test_hand_computed_matrix(self) -> None:
        rater1 = ["Low", "Low", "High", "Critical"]
        rater2 = ["Low", "Medium", "High", "High"]
        matrix = confusion_matrix(rater1, rater2)
        # الترتيب: Low, Medium, High, Critical
        assert matrix.tolist() == [
            [1, 1, 0, 0],  # Low:  → Low, Medium
            [0, 0, 0, 0],  # Medium: لا شيء
            [0, 0, 1, 0],  # High: → High
            [0, 0, 1, 0],  # Critical: → High
        ]
        assert matrix.sum() == len(rater1)
        assert matrix.shape == (4, 4)

    def test_unknown_category_raises(self) -> None:
        with pytest.raises(ValueError):
            confusion_matrix(["Bogus"], ["Low"])


# =====================================================================
# 6) bootstrap_ci
# =====================================================================
class TestBootstrapCI:
    def test_mean_of_known_sample(self) -> None:
        """متوسط 10 قيم = 5.5 ⇒ الفترة يجب أن تحيط بالمعدل وتبقى قريبة منه."""
        data = list(range(1, 11))  # mean = 5.5
        lower, upper = bootstrap_ci(data, lambda sample: float(np.mean(sample)))
        assert lower < 5.5 < upper
        assert upper - lower < 4.0, "عيّنة صغيرة متجانسة ⇒ فترة ضيقة"

    def test_deterministic_with_seed(self) -> None:
        data = [0, 1, 1, 1, 0, 1, 0, 1]
        metric = lambda sample: float(np.mean(sample))  # noqa: E731
        assert bootstrap_ci(data, metric, seed=7) == bootstrap_ci(data, metric, seed=7)
        assert bootstrap_ci(data, metric, seed=8) != bootstrap_ci(data, metric, seed=7)

    def test_iterations_validation(self) -> None:
        with pytest.raises(ValueError):
            bootstrap_ci([1, 2], float, n_iterations=50)
        with pytest.raises(ValueError):
            bootstrap_ci([], float)

    def test_ci_brackets_kappa_estimate(self) -> None:
        """فترة ثقة للكابا على أزواج مصممة (0.7 اتفاق) — تحيط بالقيمة النقطية."""
        pairs = [("Low", "Low"), ("Medium", "Medium"), ("High", "High"), ("Low", "Medium"),
                 ("High", "High"), ("Medium", "Medium"), ("Critical", "Critical"),
                 ("Low", "Low"), ("Medium", "High"), ("High", "High")]

        def kappa_of(pair_sample: list) -> float:
            left = [a for a, _ in pair_sample]
            right = [b for _, b in pair_sample]
            return weighted_cohens_kappa(left, right)

        point = kappa_of(pairs)
        lower, upper = bootstrap_ci(pairs, kappa_of, n_iterations=2000)
        assert lower <= point <= upper, "الفترة يجب أن تحيط بالتقدير النقطي"


# =====================================================================
# 7) interpret_kappa
# =====================================================================
class TestInterpretKappa:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (-0.2, "ضعيف جداً"),
            (0.0, "ضعيف جداً"),
            (0.19, "ضعيف جداً"),
            (0.20, "ضعيف"),
            (0.35, "ضعيف"),
            (0.40, "متوسط"),  # 0.40 ليس < 0.40 ⇒ ينتقل للمدى التالي
            (0.55, "متوسط"),
            (0.61, "جيد"),
            (0.80, "ممتاز"),
            (0.85, "ممتاز"),
            (1.0, "ممتاز"),
        ],
    )
    def test_band_boundaries(self, value: float, expected: str) -> None:
        assert interpret_kappa(value) == expected


# =====================================================================
# 8) حجم الأثر والاختبار المزدوج (A/B)
# =====================================================================
class TestEffectSizeAndPairedTest:
    def test_cohens_d_hand_computed(self) -> None:
        """a=[1,1,2,2]، b=[2,3,3,4] ⇒ diff=[1,2,1,2]، mean=1.5،
        sd(ddof=1)=√( (0.25+0.25+0.25+0.25)/3 )=√(1/3)=0.5774 ⇒ d≈2.5981."""
        result = cohens_d_paired([1, 1, 2, 2], [2, 3, 3, 4])
        assert result["mean_diff"] == pytest.approx(1.5, abs=1e-4)
        assert result["sd_diff"] == pytest.approx(0.5774, abs=1e-3)
        assert result["d"] == pytest.approx(2.5981, abs=1e-3)

    def test_paired_test_direction_and_n(self) -> None:
        before = [0.5, 0.5, 0.6, 0.6, 0.5]
        after = [0.8, 0.9, 0.8, 0.9, 0.8]
        result = paired_test(before, after)
        assert result["n"] == 5
        assert result["mean_diff"] > 0
        assert result["t_pvalue"] < 0.05, "تعزيز منتظم ⇒ دلالة إحصائية متوقعة"
        assert result["wilcoxon_pvalue"] is not None

    def test_paired_test_insufficient_n(self) -> None:
        result = paired_test([1.0], [1.0])
        assert result["n"] == 1 and result["t_stat"] is None

    def test_identical_samples_zero_effect(self) -> None:
        sample = [0.5, 0.7, 0.9, 0.6]
        result = paired_test(sample, sample)
        assert result["cohens_d"] == 0.0
        assert result["wilcoxon_pvalue"] == 1.0
