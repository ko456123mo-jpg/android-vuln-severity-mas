"""BaseAgent — القاعدة المجردة لكل الوكلاء.

Abstract base for all agents: LLM access + تسجيل إجباري في agent_logs +
Structured Output مع Pydantic validation وحلقة إصلاح (retry-with-error).

ملاحظة: run() تعيد dict تحديثات جزئية (وليس ScanState كاملة) ليتوافق مع
عقد LangGraph — تُدمج التحديثات تلقائياً في الحالة.
run() returns partial-update dicts (LangGraph node semantics).
"""
from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from agents.llm_client import LLMClient
from agents.state import ScanState

SchemaT = TypeVar("SchemaT", bound=BaseModel)

_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)


class StructuredOutputError(ValueError):
    """فشل التحقق من المخرجات المنظمة بعد كل محاولات الإصلاح."""


class BaseAgent(ABC):
    """وكيل أساسي: LLM + تدقيق + structured output.

    Args:
        name: اسم الوكيل (يُسجَّل في agent_logs).
        llm: نموذج محادثة LangChain/Mock — None ⇒ يُبنى من settings.yaml
             عبر LLMClient (مع Fallback Chain؛ MockLLM عند LLM_MOCK_MODE=1).
        temperature: تُمرَّر للنموذج عند الإنشاء (توثيقية للـ Mock).
    """

    def __init__(self, name: str, llm: Any = None, temperature: float = 0.1) -> None:
        self.name = name
        self.temperature = temperature
        if llm is None:
            llm = LLMClient().get_llm_with_fallback(name)
        self.llm = llm

    # ------------------------------------------------------------------
    # الواجهة المجردة / Abstract API
    # ------------------------------------------------------------------
    @abstractmethod
    async def run(self, state: ScanState) -> dict[str, Any]:
        """منطق الوكيل الأساسي — يعيد تحديثات جزئية للحالة."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # استدعاء LLM / LLM invocation
    # ------------------------------------------------------------------
    async def call_llm(
        self, prompt: str, scan_id: int | None = None, **kwargs: Any
    ) -> str:
        """استدعاء LLM مع قياس الزمن + تسجيل إجباري في agent_logs.

        كل استدعاء — ناجحاً كان أم فاشلاً — يُسجَّل (شرط حوكمة).
        """
        model_name = getattr(self.llm, "model", None) or getattr(
            self.llm, "model_name", None
        ) or type(self.llm).__name__
        started = time.perf_counter()
        status, text, error = "success", "", None
        try:
            response = await self.llm.ainvoke(prompt, **kwargs)
            text = str(getattr(response, "content", response))
        except Exception as exc:  # نسجّل ثم نرمي — لا فشل صامت
            status, error = "failed", str(exc)
            raise
        finally:
            duration_ms = int((time.perf_counter() - started) * 1000)
            # تقدير الرموز عند غياب عدّاد المزوّد (≈ 4 أحرف لكل token)
            tokens_in = kwargs.get("tokens_in") or len(prompt) // 4
            tokens_out = len(text) // 4
            self.log_action(
                action="llm_call",
                details={"reasoning": prompt[:800]},
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                duration_ms=duration_ms,
                status=status,
                scan_id=scan_id,
                llm_model=str(model_name),
                error_message=error,
            )
        return text

    async def call_llm_structured(
        self,
        prompt: str,
        schema: type[SchemaT],
        scan_id: int | None = None,
        max_retries: int = 1,
        **kwargs: Any,
    ) -> SchemaT:
        """استدعاء LLM لإرجاع JSON مطابق لمخطط Pydantic (Output Validation).

        يستخرج JSON من الرد (يدعم ```json fences) → schema.model_validate →
        عند الفشل: إعادة المحاولة مع إرفاق الخطأ (repair loop) → بعد
        الاستنزاف: يرفع StructuredOutputError.
        """
        last_error: str = "unknown"
        current_prompt = prompt
        for attempt in range(1, max_retries + 2):
            text = await self.call_llm(current_prompt, scan_id=scan_id, **kwargs)
            try:
                payload = self._extract_json(text)
                return schema.model_validate(payload)
            except (ValueError, ValidationError) as exc:
                last_error = str(exc)[:400]
                current_prompt = (
                    f"{prompt}\n\n⚠️ ردك السابق لم يجتز التحقق / validation failed:\n"
                    f"{last_error}\n"
                    f"أعد JSON صالحاً يطابق المخطط المطلوب فقط، بلا أي نص إضافي."
                )
        raise StructuredOutputError(
            f"[{self.name}] مخرجات غير صالحة بعد {max_retries + 1} محاولة: {last_error}"
        )

    @staticmethod
    def _extract_json(text: str) -> Any:
        """استخراج JSON من رد LLM (fences أو أول كتلة متوازنة الأقواس)."""
        fence = _JSON_BLOCK.search(text)
        if fence:
            return json.loads(fence.group(1))
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise ValueError(f"لم يُعثر على JSON في الرد: {text[:160]!r}")

    # ------------------------------------------------------------------
    # التدقيق / Audit logging
    # ------------------------------------------------------------------
    def log_action(
        self,
        action: str,
        details: dict[str, Any],
        tokens_in: int,
        tokens_out: int,
        duration_ms: int,
        status: str,
        scan_id: int | None = None,
        llm_model: str | None = None,
        error_message: str | None = None,
    ) -> None:
        """تسجيل الإجراء في جدول agent_logs — صامت عند فشل القاعدة."""
        try:
            from db.repositories.logs_repo import log_agent_action

            log_agent_action(
                agent_name=self.name[:30],
                action=action[:100],
                scan_id=scan_id,
                llm_model=(llm_model or "")[:100] or None,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                latency_ms=duration_ms,
                status=status,
                error_message=error_message,
                reasoning=details.get("reasoning"),
            )
        except Exception:
            pass  # التسجيل لا يجب أن يعطّل سير الفحص نفسه

    def log_tool_action(
        self,
        tool_name: str,
        ok: bool,
        duration_ms: int,
        scan_id: int | None = None,
        error_message: str | None = None,
    ) -> None:
        """اختصار لتسجيل استدعاء أداة MCP."""
        self.log_action(
            action=f"tool:{tool_name}",
            details={},
            tokens_in=0,
            tokens_out=0,
            duration_ms=duration_ms,
            status="success" if ok else "failed",
            scan_id=scan_id,
            llm_model=None,
            error_message=error_message,
        )
