# 🤖 تصميم الوكلاء / Agents Design (Phase 3)

## المكونات / Components

| الملف | الدور |
|------|------|
| `agents/state.py` | ScanState (Pydantic) — يتدفق بين العقد؛ حقول مجمّعة بمنطق «استبدال كامل» لدعم الدمج اليدوي (dedup) |
| `agents/base_agent.py` | BaseAgent (ABC): call_llm مع تسجيل إجباري في agent_logs · call_llm_structured مع Pydantic validation + repair loop (retry-with-error) · log_action/log_tool_action |
| `agents/orchestrator.py` | تخطيط عبر LLM (orchestrator.j2) → تحقق من الخطة مقابل TOOL_CATALOG → تنفيذ حزم static/dynamic عبر AgentMCPClient → bundles في ArtifactStore |
| `agents/extractor.py` | تحميل bundles → injection_shield قبل LLM → استخراج via extractor.j2 + knowledge_base → fingerprints + دمج متعدد الأدوات |
| `agents/graph.py` | StateGraph: orchestrator → run_static→extractor_static →(run_dynamic→extractor_dynamic)→ finalize · SqliteSaver checkpointing · finalize يحفظ في DB |
| `agents/mcp_client.py` | AgentMCPClient: direct mode (mock) / protocol mode (MultiServerMCPClient) · timeout لكل خادم |
| `agents/llm_client.py` | + MockLLM (LLM_MOCK_MODE=1): JSON واقعي مطابق لمخططات الوكلاء بلا مزوّد خارجي |

## آلة الحالة / State machine

```
orchestrator ──(خطة)──▶ {run_static_tools | run_dynamic_tools | finalize}
run_static_tools   ──▶ extractor_static ──(dynamic؟)──▶ {run_dynamic_tools | finalize}
run_dynamic_tools  ──▶ extractor_dynamic ──▶ finalize ──▶ END
finalize: upsert vulnerabilities (fingerprint UNIQUE) + findings لكل أداة + scan status
```

## قرارات المرحلة 3 / Design decisions

1. **run() تعيد تحديثات جزئية (dict)** — عقد LangGraph تستقبل الدالة وتحدّث الحالة تلقائياً؛
   إعادة ScanState كاملة غير مدروسة في هذا الإصدار من langgraph (يحدّث بالمخرجات الجزئية).
2. **لا reducers بـ operator.add** — لأن dedup بين static وdynamic يتطلب قراءة+دمج يدوي.
3. **كتالوج أدوات مسموح** — خطة LLM تُنقّى مقابل TOOL_CATALOG (المرحلة 2)؛ الأفعال المخترعة تُسقط وتُسجَّل. خطة فارغة ⇒ fallback شامل قواعدي.
4. **تسجيل كل استدعاء LLM بلا استثناء** — على التوازي مع success/failed + تقدير الرموز (≈4 حروف/token) عند غياب عدّاد المزوّد، لأن LangChain لا يوحّد token usage عبر المزوّدين.
5. **Bundle لكل أداة** — جدولة أدوات الخادم (مثل سلسلة MobSF upload→scan→report→findings) داخل Orchestrator، والنتيجة bundle.hook واحدة لكل أداة: `raw_artifacts[tool] = ref`.
6. **Direct mode في MCP client عند Mock** — نفس أجسام دوال FastMCP تُستدعى مباشرة (bلا عمليات فرعية في CI)؛ الوضع protocol عبر MultiServerMCPClient في الإنتاج.
7. **Injection protection قبل LLM دائماً** — regex detect على الخام (للتسجيل) + sanitize + wrapper anti-injection في extractor.j2 + canary token.
8. **Fingerprint قانوني** — APP_WIDE_CWE مفاتيح ثابتة لثغرات نطاق التطبيق (SSL/root/storage/cleartext) لأن تنسيقات الموقع تختلف بين الأدوات؛ وأسماء الفئات تُطبَّع بإسقاط `.java`/`.method`.
9. **thread_id مطلوب مع checkpointer** — ainvoke يحتاج config={"configurable": {"thread_id": scan_id}}.

## تشخيصات متوقعة في الإنتاج / Production notes

- `llm.invoke` موحّد عبر MockLLM وChatOllama وChatGroq (كلها تملك ainvoke → .content).
- فشل أداة واحدة (مثلاً frida بلا جهاز) لا يوقف الفحص: يُسجَّل في state.errors وتصبح حالة الـ scan "partial".
- checkpointing يمكّن استئناف الفحص بعد انقطاع، ونقاط التوقف البشري (interrupts) في المرحلة 6.
