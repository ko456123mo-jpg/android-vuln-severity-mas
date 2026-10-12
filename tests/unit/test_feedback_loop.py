"""اختبارات وحدة حلقة التغذية الراجعة — core/feedback (المرحلة 5).

يتحقق حرفياً من عقد HITL:
    • submit_correction: corrections + تحديث assessments.severity/review_status
      + توليد feedback_example تلقائياً — **دون المساس بـ final_score**
    • قواعد الرفض: severity غير صالحة / سبب فارغ / تقييم غير موجود / درجة خارجة
    • قائمة المراجعة: pending مرتبة تنازلياً + فلتر severity + التفاصيل
    • select_fewshot_examples: نفس MASVS + active فقط + الأحدث أولاً
"""
from __future__ import annotations

import uuid

import pytest

from core.feedback.corrections import CorrectionManager
from core.feedback.feedback_extractor import (
    extract_feedback_example,
    select_fewshot_examples,
)
from db.connection import get_session
from db.models import Assessment, Correction, FeedbackExample
from db.repositories import (
    applications_repo,
    assessments_repo,
    findings_repo,
    projects_repo,
    scans_repo,
)
from sqlalchemy import func, select


def _make_assessment(severity: str = "High", score: float = 8.2, masvs: str = "MASVS-CRYPTO") -> dict:
    """تقييم معلّق جاهز للاختبار (تطبيق + ثغرة + assessment pending)."""
    project = projects_repo.create(name=f"hitl-{uuid.uuid4().hex[:6]}")
    app = applications_repo.create(
        project_id=project["id"],
        name="HitlBank",
        sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        file_path="/data/apks/hitl.apk",
        package_name="com.hitl.bank",
        version="1.0.0",
    )
    scan = scans_repo.create_scan(application_id=app["id"])
    record = findings_repo.create_vulnerability(
        application_id=app["id"],
        title=f"Hardcoded API Key example ({severity})",
        description="fixture",
        masvs_category=masvs,
        cwe_id="CWE-321",
        dedup_fingerprint=f"hitl-{uuid.uuid4().hex[:12]}",
    )
    assessment = assessments_repo.upsert_by_vuln(
        vulnerability_id=record["id"],
        base_score=9.0, context_score=10.0, evidence_score=8.0,
        confidence_factor=0.8, final_score=score, severity=severity,
        rationale="1) base=9.00 ← CRYPTO …\n2) context=10.00 …",
        rule_version="v1.1", assessed_by="agent", review_status="pending",
    )
    return {"app": app, "scan": scan, "vuln": record, "assessment": assessment}


class TestSubmitCorrection:
    def test_full_correction_cycle(self):
        fixture = _make_assessment(severity="High", score=8.2)
        aid = fixture["assessment"]["id"]
        manager = CorrectionManager()

        correction_id = manager.submit_correction(
            assessment_id=aid, reviewer_id=1,
            corrected_severity="Critical", corrected_score=9.5,
            reason="المفتاح يسمح بالوصول الكامل لـ API البنك",
        )
        assert correction_id >= 1

        with get_session() as session:
            correction = session.get(Correction, correction_id)
            assessment = session.get(Assessment, aid)

            # ① سجل التصحيح كامل
            assert correction.original_severity == "High"
            assert correction.corrected_severity == "Critical"
            assert correction.original_score == 8.2
            assert correction.corrected_score == 9.5
            assert correction.reviewer_id == 1

            # ② التقييم محدّث: severity معتمدة — final_score لم يُمَس
            assert assessment.severity == "Critical"
            assert assessment.review_status == "approved"
            assert assessment.final_score == 8.2  # قاعدة صارمة: لا تعديل

            # ③ مثال Few-Shot تولّد تلقائياً
            example = session.scalar(
                select(FeedbackExample).where(FeedbackExample.correction_id == correction_id)
            )
            assert example is not None and example.active is True
            payload = example.prompt_payload
            assert payload["original_severity"] == "High"
            assert payload["corrected_severity"] == "Critical"
            assert payload["corrected_score"] == 9.5
            assert payload["masvs_category"] == "MASVS-CRYPTO"
            assert "Hardcoded API Key" in payload["vuln_pattern"]

    def test_multiple_corrections_history(self):
        fixture = _make_assessment()
        aid = fixture["assessment"]["id"]
        manager = CorrectionManager()
        first = manager.submit_correction(aid, 1, "Critical", 9.0, "سبب أول")
        second = manager.submit_correction(aid, 1, "Medium", 5.0, "سبب ثانٍ مُعدَّل")
        assert second != first
        details = manager.get_assessment_details(aid)
        assert len(details["corrections"]) == 2
        assert details["severity"] == "Medium"  # آخر تصحيح يسود

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"corrected_severity": "ألترا-حرجة", "corrected_score": 9.0, "reason": "سبب"},
            {"corrected_severity": "Low", "corrected_score": 1.0, "reason": "  "},
            {"corrected_severity": "Low", "corrected_score": 11.0, "reason": "سبب"},
        ],
    )
    def test_invalid_inputs_rejected(self, kwargs):
        fixture = _make_assessment()
        with pytest.raises(ValueError):
            CorrectionManager().submit_correction(
                fixture["assessment"]["id"], 1, **kwargs
            )

    def test_unknown_assessment_rejected(self):
        with pytest.raises(ValueError):
            CorrectionManager().submit_correction(999_999_999, 1, "Critical", 9.0, "سبب")


class TestReviewQueue:
    def test_pending_ordering_and_details(self):
        fixture = _make_assessment(severity="High", score=8.2)
        manager = CorrectionManager()
        # حدّ صريح واسع: قائمة الانتظار مشتركة عبر جلسة الاختبار كلها (المرحلة 8
        # أضافت فحوصاً أكثر)، والافتراضي 50 قد لا يضم التقييم المنشأ للتوّ.
        pending = manager.list_pending_reviews(limit=500)
        scorable = [p for p in pending if p["final_score"] is not None]
        scores = [p["final_score"] for p in scorable]
        assert scores == sorted(scores, reverse=True)  # تنازلي بالدرجة

        record = next(p for p in pending if p["id"] == fixture["assessment"]["id"])
        assert record["cwe_id"] == "CWE-321" and record["severity"] == "High"

        details = manager.get_assessment_details(fixture["assessment"]["id"])
        assert details["final_score"] == 8.2
        assert details["vulnerability"]["masvs_category"] == "MASVS-CRYPTO"
        assert details["corrections"] == []

    def test_severity_filter(self):
        fixture = _make_assessment(severity="Low", score=2.5)
        pending = CorrectionManager().list_pending_reviews(severity="Low")
        assert all(p["severity"] == "Low" for p in pending)
        assert any(p["id"] == fixture["assessment"]["id"] for p in pending)

    def test_queue_stats_shape(self):
        _make_assessment()
        stats = CorrectionManager().get_review_queue_stats()
        for key in ("pending", "approved", "rejected", "pending_by_severity",
                    "corrections_total", "feedback_examples_total"):
            assert key in stats
        assert stats["pending"] >= 1

    def test_unknown_details_none(self):
        assert CorrectionManager().get_assessment_details(999_999_999) is None


class TestFewShotExtraction:
    def test_extract_payload_fields(self):
        example = extract_feedback_example(
            {"id": 7, "original_severity": "High", "original_score": 8.2,
             "corrected_severity": "Critical", "corrected_score": 9.5,
             "reason": "خطورة حقيقية."},
            {"final_score": 8.2, "severity": "High", "rationale": "s1\ns2\ns3"},
            {"title": "Hardcoded Key", "masvs_category": "MASVS-CRYPTO", "cwe_id": "CWE-321"},
        )
        assert example["correction_id"] == 7
        assert example["example_type"] == "severity_correction"
        assert example["active"] is True
        payload = example["prompt_payload"]
        assert payload["corrected_severity"] == "Critical"
        assert payload["cwe_id"] == "CWE-321"
        assert payload["context_summary"].startswith("s1")  # أول سطرين فقط

    def test_select_filters_by_category_and_active(self):
        fixture = _make_assessment(masvs="MASVS-CRYPTO")
        aid = fixture["assessment"]["id"]
        manager = CorrectionManager()
        manager.submit_correction(aid, 1, "Critical", 9.5, "تصحيح اختبار 1")
        manager.submit_correction(aid, 1, "Medium", 5.0, "تصحيح اختبار 2")

        examples = select_fewshot_examples("MASVS-CRYPTO", limit=5)
        assert len(examples) >= 2
        payloads = [e["prompt_payload"] for e in examples]
        assert all(p["masvs_category"] == "MASVS-CRYPTO" for p in payloads)
        # الأحدث أولاً (تصحيح 2 قبل تصحيح 1)
        crypto_payloads = [p for p in payloads if p["reason"].startswith("تصحيح اختبار")]
        assert crypto_payloads[0]["reason"] == "تصحيح اختبار 2"

        # فئة مختلفة لا تعيد شيئاً
        assert select_fewshot_examples("MASVS-CODE") == []

        # تعطيل المثال يُخرجه من الاختيار
        with get_session() as session:
            newest = session.scalar(
                select(FeedbackExample).order_by(FeedbackExample.id.desc())
            )
            newest.active = False
        remaining = select_fewshot_examples("MASVS-CRYPTO", limit=50)
        ids = {e["example_id"] for e in remaining}
        with get_session() as session:
            disabled_id = session.scalar(select(func.max(FeedbackExample.id)))
        assert disabled_id not in ids
