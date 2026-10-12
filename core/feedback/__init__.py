"""حلقة التغذية الراجعة — Human-in-the-Loop feedback loop (المرحلة 5).

كل تصحيح بشري يسلك المسار:
    corrections (السجل) → تحديث assessments.severity + review_status
    → feedback_examples (مثال few-shot نشط للوكلاء)

القاعدة الصارمة: `final_score` (قيمة المحرك) لا يُعدَّل أبداً؛ الدرجة
المُصحَّحة تُخزَّن منفصلة في corrections.corrected_score فقط.
"""
from core.feedback.corrections import CorrectionManager
from core.feedback.feedback_extractor import (
    extract_feedback_example,
    select_fewshot_examples,
)

__all__ = ["CorrectionManager", "extract_feedback_example", "select_fewshot_examples"]
