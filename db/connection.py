"""اتصال قاعدة البيانات — SQLAlchemy 2.0 engine/session (SQLite + WAL).

يوفّر / Provides:
    get_engine()  -> Engine                 (WAL + foreign_keys=ON لكل اتصال)
    get_session() -> Session (context manager مع commit/rollback تلقائي)
    init_db()     -> list[str]              (ينشئ الجداول من db/schema.sql)
    get_db_path() -> Path                   (مسار ملف القاعدة المحسوب)
"""
from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SCHEMA_PATH = PROJECT_ROOT / "db" / "schema.sql"
_DEFAULT_DB_PATH = DATA_DIR / "app.db"

_ENGINE: Engine | None = None


def _resolve_db_path() -> Path:
    """أولوية المسار: DATABASE_PATH (env) ← config/settings.yaml ← data/app.db."""
    env_path = os.getenv("DATABASE_PATH")
    if env_path:
        p = Path(env_path).expanduser()
        return p if p.is_absolute() else (PROJECT_ROOT / p)

    settings_yaml = PROJECT_ROOT / "config" / "settings.yaml"
    if settings_yaml.exists():
        try:
            import yaml

            cfg = yaml.safe_load(settings_yaml.read_text(encoding="utf-8")) or {}
            rel = (cfg.get("paths") or {}).get("db")
            if rel:
                p = Path(str(rel)).expanduser()
                return p if p.is_absolute() else (PROJECT_ROOT / p)
        except Exception:
            pass  # نكمل بالمسار الافتراضي / fall through to default
    return _DEFAULT_DB_PATH


def get_engine(db_path: str | os.PathLike | None = None) -> Engine:
    """إنشاء (أو إرجاع المخزَّن) محرك SQLite مع PRAGMAs الموصى بها.

    WAL يسمح بقراءات متزامنة أثناء الكتابة (مهم لوكلاء متوازيين + واجهة).
    """
    global _ENGINE
    if db_path is None and _ENGINE is not None:
        return _ENGINE

    path = Path(db_path) if db_path else _resolve_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{path}", echo=False, future=True)

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _conn_record):  # noqa: ANN001, ANN202
        # مصدر واحد لـ PRAGMAs (المرحلة 8): WAL + busy_timeout + synchronous + foreign_keys
        try:
            from core.performance.db_optimizer import apply_connection_pragmas

            apply_connection_pragmas(dbapi_conn)
        except Exception:  # لا نُسقط الاتصال لو تعذّر استيراد طبقة الأداء
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

    if db_path is None:
        _ENGINE = engine
    return engine


@contextmanager
def get_session(db_path: str | os.PathLike | None = None) -> Iterator[Session]:
    """جلسة كـ context manager: commit عند النجاح / rollback عند الاستثناء."""
    factory = sessionmaker(
        bind=get_engine(db_path), autoflush=False, expire_on_commit=False, future=True
    )
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(schema_path: str | os.PathLike | None = None) -> list[str]:
    """تنفيذ schema.sql (idempotent) وإرجاع أسماء الجداول الموجودة."""
    schema_file = Path(schema_path) if schema_path else SCHEMA_PATH
    sql_script = schema_file.read_text(encoding="utf-8")
    engine = get_engine()
    raw = engine.raw_connection()
    try:
        raw.executescript(sql_script)
        raw.commit()
    finally:
        raw.close()
    return sorted(inspect(engine).get_table_names())


def get_db_path() -> Path:
    """إرجاع مسار ملف قاعدة البيانات المحسوب (بدون إنشائه)."""
    return _resolve_db_path()
