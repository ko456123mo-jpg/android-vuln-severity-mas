"""مخططات Pydantic مشتركة بين الموجّهات (المرحلة 6).

تُستورد من أكثر من router (scans/applications/findings/assessments) لتفادي
تكرار نماذج الاستجابة — كل endpoint يعرّف response_model من هنا أو من موضعه.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ScanOut(BaseModel):
    """صف فحص (scans) بلا تفاصيل تجميعية."""

    id: int
    application_id: int
    status: str
    tools_used: Optional[list[str]] = None
    rule_version: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    total_tokens: int = 0
    total_duration_ms: int = 0


class AssessmentBrief(BaseModel):
    """ملخص تقييم — للعرض المدمج داخل الثغرات/الفحوص."""

    id: int
    vulnerability_id: int
    severity: Optional[str] = None
    final_score: Optional[float] = None
    review_status: Optional[str] = None
    assessed_by: Optional[str] = None


class EvidenceBrief(BaseModel):
    """ملخص أدلة ثغرة داخل فحص."""

    findings_count: int = 0
    tools: list[str] = []


class LastLogOut(BaseModel):
    """آخر إجراء وكيل مسجَّل (لتقدم الفحص الحيّ)."""

    agent_name: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    created_at: Optional[datetime] = None


class AssessmentDetailOut(AssessmentBrief):
    """تقييم كامل بمكوّنات المعادلة (يُستخدم في /findings و/assessments)."""

    base_score: Optional[float] = None
    context_score: Optional[float] = None
    evidence_score: Optional[float] = None
    confidence_factor: Optional[float] = None
    rationale: Optional[str] = None
    rule_version: Optional[str] = None
    assessed_at: Optional[datetime] = None
    reviewed_by: Optional[int] = None
    review_notes: Optional[str] = None
