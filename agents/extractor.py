"""ExtractorAgent — وكيل استخراج الثغرات من مخرجات الأدوات.

المسؤوليات:
    1. تحميل bundles من ArtifactStore (raw_artifacts في الحالة)
    2. تعقيم المخرجات قبل LLM (Prompt Injection Protection — core/guardrails)
    3. استخراج الثغرات عبر LLM مع الاستعانة بـ knowledge_base (Structured Output)
    4. حساب dedup_fingerprint ودمج الثغرات المكررة بين الأدوات
    5. كشف محاولات الحقن وتسجيلها
    6. تسجيل كل خطوة في agent_logs (وراثة من BaseAgent)

الحفظ في قاعدة البيانات يتم في عقدة finalize (agents/graph.py).
"""
from __future__ import annotations

import json
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from agents.base_agent import BaseAgent, StructuredOutputError
from agents.llm_client import PROMPTS_DIR
from agents.state import ScanState
from core.correlation.fingerprints import compute_vuln_fingerprint
from core.guardrails.injection_shield import (
    CANARY_TOKEN,
    detect_injection,
    sanitize_tool_output,
)
from mcp_servers.common.artifact_store import ArtifactStore

STATIC_SOURCE_TOOLS = ("jadx", "mobsf")
DYNAMIC_SOURCE_TOOLS = ("frida", "objection")

_jinja = Environment(
    loader=FileSystemLoader(PROMPTS_DIR), autoescape=select_autoescape(disabled_extensions=("j2",))
)


class ExtractedVuln(BaseModel):
    """عقد ثغرة مستخرجة (Output Validation لكل عنصر)."""

    title: str = Field(min_length=3, max_length=255)
    description: str = ""
    evidence: str = Field(min_length=1)
    masvs_category: str | None = None
    cwe_id: str | None = None
    sub_category: str = ""
    discovered_by: str = Field(min_length=1, max_length=20)
    is_confirmed: bool = False
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    location: str = ""


class ExtractorOutput(BaseModel):
    """عقد مخرجات الاستخراج الكلي."""

    vulnerabilities: list[ExtractedVuln] = []
    injection_attempts_detected: list[str] = []


class ExtractorAgent(BaseAgent):
    """وكيل الاستخراج — يورث التدقيق و LLM من BaseAgent."""

    def __init__(self, llm: Any = None, store: ArtifactStore | None = None, **kwargs: Any) -> None:
        super().__init__(name="extractor", llm=llm, **kwargs)
        self.store = store or ArtifactStore()

    # ------------------------------------------------------------------
    # واجهة BaseAgent (الافتراضي = المرحلة الساكنة) / ABC contract
    # ------------------------------------------------------------------
    async def run(self, state: ScanState) -> dict[str, Any]:
        return await self.extract_static(state)

    async def extract_static(self, state: ScanState) -> dict[str, Any]:
        return await self._extract(state, STATIC_SOURCE_TOOLS)

    async def extract_dynamic(self, state: ScanState) -> dict[str, Any]:
        return await self._extract(state, DYNAMIC_SOURCE_TOOLS)

    # ------------------------------------------------------------------
    # المنطق الأساسي / Core extraction
    # ------------------------------------------------------------------
    async def _extract(self, state: ScanState, tools: tuple[str, ...]) -> dict[str, Any]:
        merged: list[dict[str, Any]] = list(state.vulnerabilities)
        errors: list[str] = []
        injection_hits: list[str] = []

        for tool in tools:
            if tool not in state.tools_executed or tool not in state.raw_artifacts:
                continue  # لم تنجح الأداة — لا بيانات للاستخراج منها
            try:
                bundle = self.store.load(state.raw_artifacts[tool])
            except Exception as exc:
                errors.append(f"extractor: cannot load {tool} bundle: {exc}")
                continue

            raw_text = json.dumps(bundle, ensure_ascii=False, default=str)
            # ① كشف الحقن على النص الخام (قبل التعقيم)
            injection_hits.extend(
                f"{tool}:{pattern}" for pattern in detect_injection(raw_text)
            )
            # ② التعقيم قبل أي LLM (Prompt Injection Protection)
            sanitized = sanitize_tool_output(raw_text, max_length=40_000)

            # ③ RAG (المرحلة 7): أنسب الأنماط لهذه المخرجات بدل قاعدة المعرفة كاملة
            kb_block = self._retrieval_block(sanitized, state)

            prompt = _jinja.get_template("extractor.j2").render(
                knowledge_base_patterns=kb_block,
                tool_name=tool,
                sanitized_output=sanitized,
                canary=CANARY_TOKEN,
            )
            try:
                output = await self.call_llm_structured(
                    prompt, ExtractorOutput, scan_id=state.db_scan_id
                )
            except StructuredOutputError as exc:
                errors.append(f"extractor LLM failed for {tool}: {exc}")
                continue

            injection_hits.extend(output.injection_attempts_detected)
            entries = [
                self._to_state_vuln(v, tool, state.package_name, state.application_id)
                for v in output.vulnerabilities
            ]
            if not getattr(state, "disable_rag", False):
                self._attach_retrieved_patterns(entries)
            merged = self.merge_vulnerabilities(merged, entries)
            self.log_tool_action(
                f"extract:{tool}", ok=True, duration_ms=0, scan_id=state.db_scan_id
            )

        # دمج مع الأخطاء المتراكمة (فشل أدوات المرحلة السابقة) — إرجاع قائمة
        # محلية هنا كان يمحو أخطاء orchestrator/execute_stage بصمت.
        accumulated = list(state.errors) + errors
        updates: dict[str, Any] = {
            "vulnerabilities": merged,
            "errors": accumulated,
            "current_stage": "extraction",
        }
        if injection_hits:
            updates["errors"] = accumulated + [
                f"injection attempts detected: {len(injection_hits)} ({sorted(set(injection_hits))[:5]})"
            ]
        return updates

    def _to_state_vuln(
        self, vuln: ExtractedVuln, tool: str, package_name: str, application_id: int
    ) -> dict[str, Any]:
        """تحويل ثغرة LLM إلى مدخل حالة مع fingerprint وأدلة لكل أداة.

        الـ fingerprint محصور بنطاق التطبيق (fingerprint_scope) حتى لا
        يتصادم تطبيقان منفصلان بنفس الـ package على UNIQUE(dedup_fingerprint).
        """
        entry = vuln.model_dump()
        entry["dedup_fingerprint"] = compute_vuln_fingerprint(
            {
                "package_name": package_name,
                "cwe_id": vuln.cwe_id,
                "location": vuln.location,
                "fingerprint_scope": f"app:{application_id}",
            }
        )
        entry["discovered_by"] = [tool]  # قائمة قابلة للدمج
        entry["evidence_by_tool"] = {tool: vuln.evidence}
        return entry

    # ------------------------------------------------------------------
    # الدمج / Dedup merge
    # ------------------------------------------------------------------
    @staticmethod
    def merge_vulnerabilities(
        existing: list[dict[str, Any]], new: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """دمج الثغرات المكررة بالـ fingerprint (تأكيد متعدد الأدوات).

        عند التطابق: ندمج discovered_by و evidence_by_tool، نرفع الثقة
        (min(1, max+0.1))، ونفعّل is_confirmed إذا أي مصدر ديناميكي أكّدها.
        """
        index = {v.get("dedup_fingerprint"): v for v in existing}
        merged: list[dict[str, Any]] = list(existing)
        for entry in new:
            fp = entry.get("dedup_fingerprint")
            current = index.get(fp)
            if current is None:
                index[fp] = entry
                merged.append(entry)
                continue
            for tool in entry["discovered_by"]:
                if tool not in current["discovered_by"]:
                    current["discovered_by"].append(tool)
                    current["confidence"] = min(1.0, current["confidence"] + 0.1)
            current["evidence_by_tool"].update(entry["evidence_by_tool"])
            current["is_confirmed"] = current["is_confirmed"] or entry["is_confirmed"]
            if entry["confidence"] > current["confidence"]:
                current["confidence"] = min(1.0, entry["confidence"] + 0.05)
        return merged

    # ------------------------------------------------------------------
    # قاعدة المعرفة / Knowledge base block
    # ------------------------------------------------------------------
    def _retrieval_block(self, sanitized_output: str, state: ScanState) -> str:
        """كتلة المعرفة عبر RAG: أنسب الأنماط لمحتوى مخرجات الأداة (المرحلة 7).

        حجم الـ prompt ينخفض من «كل الأنماط» إلى top_k (config: rag.retrieval_top_k).
        أي فشل في طبقة RAG ⇒ تراجع آمن إلى الكتلة الكاملة (سلوك المرحلة 3)
        بدل إسقاط الاستخراج.
        """
        if getattr(state, "disable_rag", False):
            return self._full_knowledge_block()
        try:
            from rag.retriever import KnowledgeRetriever, build_context_prompt

            retrieved = KnowledgeRetriever().retrieve(sanitized_output[:6000])
            if retrieved:
                return build_context_prompt(retrieved)
        except Exception:
            pass
        return self._full_knowledge_block()

    @staticmethod
    def _attach_retrieved_patterns(entries: list[dict[str, Any]]) -> None:
        """يُثري كل ثغرة مستخرجة بمعرّفات الأنماط الأقرب لها (تدقيق RAG).

        يُخزَّن في retrieved_patterns داخل قاموس الثغرة (حقل state فقط —
        لا عمود قاعدة بيانات، وpersist يتجاهل المفاتيح الإضافية).
        """
        try:
            from rag.retriever import KnowledgeRetriever

            retriever = KnowledgeRetriever()
            for entry in entries:
                try:
                    retrieved = retriever.retrieve_for_vulnerability(entry, top_k=3)
                    entry["retrieved_patterns"] = [
                        item.get("ref_id") for item in retrieved if item.get("ref_id")
                    ]
                except Exception as exc:  # تُوثَّق العلة ولا تُبتلع بصمت
                    entry["retrieved_patterns"] = []
                    entry["retrieval_error"] = str(exc)[:200]
        except Exception:
            for entry in entries:
                entry.setdefault("retrieved_patterns", [])

    @staticmethod
    def _full_knowledge_block(max_rows: int = 30) -> str:
        """أنماط MASVS/CWE من knowledge_base كنص يُحقن في البرومبت.

        (سلوك المرحلة 3 — يُستخدم عند تعطيل RAG تجريبياً أو فشل الاسترجاع.)
        """
        try:
            from sqlalchemy import select

            from db.connection import get_session
            from db.models import KnowledgeBase

            with get_session() as session:
                rows = session.scalars(
                    select(KnowledgeBase).order_by(KnowledgeBase.id).limit(max_rows)
                ).all()
                return "\n".join(
                    f"- {r.ref_id} | {r.title} | {r.cwe_id} | {r.masvs_category}: {r.content}"
                    for r in rows
                ) or "(قاعدة معرفة فارغة)"
        except Exception:
            return "(تعذّر الوصول لقاعدة المعرفة — اعتمد على معرفتك العامة بـ MASVS/CWE)"
