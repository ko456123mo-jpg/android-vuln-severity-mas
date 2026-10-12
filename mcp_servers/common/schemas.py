"""عقود Pydantic لأدوات MCP — Input/Output schemas لكل أداة.

تُستخدم داخل أدوات الخوادم للتحقق من المدخلات وضمان شكل المخرجات
(Output Validation قبل إرسال أي نتيجة للوكلاء/LLM).
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

# =====================================================================
# JADX — تحليل ساكن
# =====================================================================
class JadxDecompileInput(BaseModel):
    apk_path: str = Field(min_length=1, description="مسار ملف APK")
    timeout: int = Field(default=300, ge=1, le=3600)


class JadxDecompileOutput(BaseModel):
    success: bool
    artifact_ref: Optional[str] = None
    classes_count: int = 0
    error: Optional[str] = None


class JadxGetManifestInput(BaseModel):
    apk_path: str = Field(min_length=1)


class JadxGetManifestOutput(BaseModel):
    success: bool
    manifest: Optional[dict[str, Any]] = None
    error: Optional[str] = None


class JadxSearchCodeInput(BaseModel):
    apk_path: str = Field(min_length=1)
    keyword: str = Field(min_length=1, max_length=200, description="الكلمة المفتاحية")
    max_results: int = Field(default=50, ge=1, le=500)


class JadxSearchCodeOutput(BaseModel):
    success: bool
    matches: list[dict[str, Any]] = []
    total: int = 0
    error: Optional[str] = None


class JadxGetClassInput(BaseModel):
    apk_path: str = Field(min_length=1)
    class_name: str = Field(min_length=1, description="الاسم الكامل للفئة com.x.Y")


class JadxGetClassOutput(BaseModel):
    success: bool
    class_name: Optional[str] = None
    source: Optional[str] = None
    error: Optional[str] = None


class JadxPermissionsInput(BaseModel):
    apk_path: str = Field(min_length=1)


class JadxPermissionsOutput(BaseModel):
    success: bool
    permissions: list[str] = []
    error: Optional[str] = None


# =====================================================================
# MobSF — إطار تحليل شامل
# =====================================================================
class MobSFUploadInput(BaseModel):
    apk_path: str = Field(min_length=1)


class MobSFUploadOutput(BaseModel):
    success: bool
    scan_hash: Optional[str] = None
    file_name: Optional[str] = None
    error: Optional[str] = None


class MobSFScanInput(BaseModel):
    scan_hash: str = Field(min_length=8)


class MobSFScanOutput(BaseModel):
    success: bool
    scan_id: Optional[str] = None
    status: str = "unknown"
    error: Optional[str] = None


class MobSFReportInput(BaseModel):
    scan_id: str = Field(min_length=1)


class MobSFReportOutput(BaseModel):
    success: bool
    artifact_ref: Optional[str] = None
    error: Optional[str] = None


class MobSFFindingsInput(BaseModel):
    scan_id: str = Field(min_length=1)
    severity_filter: Optional[str] = Field(
        default=None, description="high | medium | low | info — فارغ = الكل"
    )


class MobSFFinding(BaseModel):
    title: str
    severity: str
    description: str = ""
    cwe_id: Optional[str] = None
    masvs_category: Optional[str] = None
    location: Optional[str] = None
    evidence_type: str = "static"
    tool: str = "mobsf"


class MobSFFindingsOutput(BaseModel):
    success: bool
    findings: list[MobSFFinding] = []
    total: int = 0
    error: Optional[str] = None


# =====================================================================
# Frida — تحليل ديناميكي
# =====================================================================
class FridaDevicesOutput(BaseModel):
    success: bool
    devices: list[dict[str, Any]] = []
    error: Optional[str] = None


class FridaSpawnInput(BaseModel):
    package_name: str = Field(min_length=3, description="اسم الحزمة com.x.y")
    device_id: Optional[str] = None


class FridaSpawnOutput(BaseModel):
    success: bool
    session_id: Optional[str] = None
    pid: Optional[int] = None
    error: Optional[str] = None


class FridaRunHookInput(BaseModel):
    session_id: str = Field(min_length=1)
    script_name: str = Field(min_length=1, description="اسم سكربت JS من scripts/")
    duration: int = Field(default=15, ge=1, le=600, description="مدة جمع الأحداث بالثواني")


class FridaRunHookOutput(BaseModel):
    success: bool
    artifact_ref: Optional[str] = None
    events_count: int = 0
    error: Optional[str] = None


class FridaCaptureInput(BaseModel):
    session_id: str = Field(min_length=1)
    duration: int = Field(default=30, ge=1, le=600)


class FridaCaptureOutput(BaseModel):
    success: bool
    artifact_ref: Optional[str] = None
    captured_count: int = 0
    error: Optional[str] = None


# =====================================================================
# Objection — فحص runtime
# =====================================================================
class ObjectionPackageInput(BaseModel):
    package_name: str = Field(min_length=3)


class ObjectionExploreOutput(BaseModel):
    success: bool
    artifact_ref: Optional[str] = None
    error: Optional[str] = None


class ObjectionKeystoreOutput(BaseModel):
    success: bool
    artifact_ref: Optional[str] = None
    items_count: int = 0
    error: Optional[str] = None


class ObjectionBypassOutput(BaseModel):
    success: bool
    bypassed: bool = False
    detail: str = ""
    error: Optional[str] = None


class ObjectionActivitiesOutput(BaseModel):
    success: bool
    activities: list[str] = []
    error: Optional[str] = None
