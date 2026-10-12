"""مدير التصحيحات البشرية — CorrectionManager (قلب حلقة HITL).

submit_correction() عملية واحدة ذرّياً:
    ① سجل corrections (original + corrected + reason)
    ② تحديث assessments.severity + review_status='approved'
       (final_score يبقى قيمة المحرك — قاعدة صارمة موثقة)
    ③ توليد feedback_example نشط تلقائياً

التحقق: severity مصحَّحة ضمن {Critical, High, Medium, Low} وسبب إلزامي —
التصحيح بلا مبرر مرفوض (شرط تدقيق).
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select

from db.connection import get_session
from db.models import Assessment, Correction, FeedbackExample, Vulnerability
from db.repositories import feedback_repo

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


class CorrectionManager:
    """إدارة قائمة المراجعة البشرية وتصحيحاتها."""

    # ------------------------------------------------------------------
    # إرسال تصحيح / Submit
    # ------------------------------------------------------------------
    def submit_correction(
        self,
        assessment_id: int,
        reviewer_id: int,
        corrected_severity: str,
        corrected_score: float,
        reason: str,
    ) -> int:
        """يسجّل تصحيحاً بشرياً — يعيد correction_id.

        Raises:
            ValueError: معرف غير موجود أو severity غير صالحة أو سبب فارغ.
        """
        if corrected_severity not in VALID_SEVERITIES:
            raise ValueError(
                f"severity غير صالحة: {corrected_severity!r} — المسموح {sorted(VALID_SEVERITIES)}"
            )
        if not reason.strip():
            raise ValueError("سبب التصحيح إلزامي (reason) — لا تصحيح بلا مبرر")
        if not (0.0 <= float(corrected_score) <= 10.0):
            raise ValueError("corrected_score يجب أن يكون ضمن [0, 10]")

        with get_session() as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                raise ValueError(f"assessment غير موجود: id={assessment_id}")
            vuln = session.get(Vulnerability, assessment.vulnerability_id)

            # ① سجل التصحيح (يحتفظ بالقيم الأصلية للتدقيق)
            correction = feedback_repo.create_correction(
                assessment_id=assessment_id,
                reviewer_id=reviewer_id,
                original_severity=assessment.severity,
                corrected_severity=corrected_severity,
                original_score=assessment.final_score,
                corrected_score=float(corrected_score),
                reason=reason.strip(),
            )

            # ② تحديث التقييم: severity المصحَّحة + اعتماد؛ final_score يبقى
            assessment.severity = corrected_severity
            assessment.review_status = "approved"
            assessment.reviewed_by = reviewer_id

        # ③ توليد مثال Few-Shot تلقائياً (خارج جلسة التعديل — قابل لإعادة المحاولة)
        example = _build_example(correction, assessment_id)
        feedback_repo.create_feedback(**example)
        return int(correction["id"])

    # ------------------------------------------------------------------
    # قائمة المراجعة / Review queue
    # ------------------------------------------------------------------
    def list_pending_reviews(
        self, limit: int = 50, severity: str | None = None
    ) -> list[dict[str, Any]]:
        """سرد التقييمات المعلّقة (review_status='pending') مرتبة بخطورتها."""
        with get_session() as session:
            stmt = (
                select(Assessment, Vulnerability)
                .join(Vulnerability, Assessment.vulnerability_id == Vulnerability.id)
                .where(Assessment.review_status == "pending")
                .order_by(Assessment.final_score.desc())
                .limit(limit)
            )
            if severity:
                stmt = stmt.where(Assessment.severity == severity)
            rows = session.execute(stmt).all()
        return [
            {
                "id": assessment.id,
                "vulnerability_id": vuln.id,
                "title": vuln.title,
                "masvs_category": vuln.masvs_category,
                "cwe_id": vuln.cwe_id,
                "final_score": assessment.final_score,
                "severity": assessment.severity,
                "confidence_factor": assessment.confidence_factor,
                "review_notes": assessment.review_notes,
            }
            for assessment, vuln in rows
        ]

    def get_assessment_details(self, assessment_id: int) -> dict[str, Any] | None:
        """تفاصيل تقييم واحد للمراجعة (مع بيانات الثغرة والتصحيحات السابقة)."""
        with get_session() as session:
            assessment = session.get(Assessment, assessment_id)
            if assessment is None:
                return None
            vuln = session.get(Vulnerability, assessment.vulnerability_id)
            corrections = session.scalars(
                select(Correction)
                .where(Correction.assessment_id == assessment_id)
                .order_by(Correction.id)
            ).all()
        return {
            "id": assessment.id,
            "vulnerability": {
                "id": vuln.id,
                "title": vuln.title,
                "masvs_category": vuln.masvs_category,
                "cwe_id": vuln.cwe_id,
                "description": vuln.description,
            },
            "base_score": assessment.base_score,
            "context_score": assessment.context_score,
            "evidence_score": assessment.evidence_score,
            "confidence_factor": assessment.confidence_factor,
            "final_score": assessment.final_score,
            "severity": assessment.severity,
            "rationale": assessment.rationale,
            "rule_version": assessment.rule_version,
            "review_status": assessment.review_status,
            "review_notes": assessment.review_notes,
            "corrections": [
                {
                    "id": c.id,
                    "original_severity": c.original_severity,
                    "corrected_severity": c.corrected_severity,
                    "original_score": c.original_score,
                    "corrected_score": c.corrected_score,
                    "reason": c.reason,
                    "corrected_at": str(c.corrected_at),
                }
                for c in corrections
            ],
        }

    def get_review_queue_stats(self) -> dict[str, Any]:
        """إحصائيات قائمة المراجعة (للوحة القيادة لاحقاً)."""
        with get_session() as session:
            status_rows = session.execute(
                select(Assessment.review_status, func.count(Assessment.id)).group_by(
                    Assessment.review_status
                )
            ).all()
            severity_rows = session.execute(
                select(Assessment.severity, func.count(Assessment.id))
                .where(Assessment.review_status == "pending")
                .group_by(Assessment.severity)
            ).all()
            corrections_total = session.scalar(select(func.count(Correction.id))) or 0
            examples_total = session.scalar(select(func.count(FeedbackExample.id))) or 0
        by_status = {status or "unknown": count for status, count in status_rows}
        return {
            "pending": by_status.get("pending", 0),
            "approved": by_status.get("approved", 0),
            "rejected": by_status.get("rejected", 0),
            "pending_by_severity": {sev or "unknown": n for sev, n in severity_rows},
            "corrections_total": corrections_total,
            "feedback_examples_total": examples_total,
        }


# ----------------------------------------------------------------------
# باني المثال / Example builder (داخلي)
# ----------------------------------------------------------------------
def _build_example(correction: dict[str, Any], assessment_id: int) -> dict[str, Any]:
    """تجميع مثال Few-Shot كامل بعد إقفال جلسة التصحيح."""
    from core.feedback.feedback_extractor import extract_feedback_example

    with get_session() as session:
        assessment = session.get(Assessment, assessment_id)
        vuln = session.get(Vulnerability, assessment.vulnerability_id)
        assessment_dict = {
            "final_score": assessment.final_score,
            "severity": assessment.severity,
            "rationale": assessment.rationale,
        }
        vuln_dict = {
            "title": vuln.title,
            "masvs_category": vuln.masvs_category,
            "cwe_id": vuln.cwe_id,
        }
    example = extract_feedback_example(correction, assessment_dict, vuln_dict)
    return {
        "correction_id": example["correction_id"],
        "example_type": example["example_type"],
        "prompt_payload": example["prompt_payload"],
        "active": example["active"],
    }
