"""تدقيق الوكلاء / Agent logs repository (audit + token stats)."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select

from db.connection import get_session
from db.models import AgentLog
from db.repositories import row_to_dict


def log_agent_action(
    agent_name: str,
    action: str,
    scan_id: int | None = None,
    llm_model: str | None = None,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    latency_ms: int | None = None,
    status: str = "success",
    error_message: str | None = None,
    reasoning: str | None = None,
) -> dict[str, Any]:
    """تسجيل إجراء وكيل (مع التكلفة والزمن) — يغذي scans.total_tokens."""
    with get_session() as session:
        log = AgentLog(
            scan_id=scan_id,
            agent_name=agent_name,
            action=action,
            llm_model=llm_model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
            status=status,
            error_message=error_message,
            reasoning=reasoning,
        )
        session.add(log)
        session.flush()
        session.refresh(log)
        return row_to_dict(log)


def list_by_scan(scan_id: int) -> list[dict[str, Any]]:
    """سرد سجلات فحص معيّن بالترتيب الزمني."""
    with get_session() as session:
        logs = session.scalars(
            select(AgentLog).where(AgentLog.scan_id == scan_id).order_by(AgentLog.id)
        ).all()
        return [row_to_dict(log) for log in logs]


def get_token_stats(scan_id: int | None = None) -> dict[str, Any]:
    """إحصائيات استهلاك الرموز (لكل فحص أو إجمالي).

    يعيد: عدد الاستدعاءات، مجموع tokens_in/out، متوسط زمن الاستجابة.
    """
    with get_session() as session:
        stmt = select(
            func.count(AgentLog.id).label("total_calls"),
            func.coalesce(func.sum(AgentLog.tokens_in), 0).label("total_tokens_in"),
            func.coalesce(func.sum(AgentLog.tokens_out), 0).label("total_tokens_out"),
            func.avg(AgentLog.latency_ms).label("avg_latency_ms"),
        )
        if scan_id is not None:
            stmt = stmt.where(AgentLog.scan_id == scan_id)
        row = session.execute(stmt).one()
        return {
            "scan_id": scan_id,
            "total_calls": int(row.total_calls),
            "total_tokens_in": int(row.total_tokens_in),
            "total_tokens_out": int(row.total_tokens_out),
            "total_tokens": int(row.total_tokens_in) + int(row.total_tokens_out),
            "avg_latency_ms": round(float(row.avg_latency_ms), 1)
            if row.avg_latency_ms is not None
            else None,
        }
