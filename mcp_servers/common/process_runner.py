"""تشغيل أوامر خارجية بأمان — timeout + retries/backoff + التقاط المخرجات.

Safe external process execution used by all tool wrappers (JADX/Objection CLIs).

run_command() يعيد dict:
    {exit_code, stdout, stderr, duration_ms, timed_out, attempts}
"""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
from collections.abc import Sequence
from typing import Any


def run_command(
    cmd: Sequence[str] | str,
    timeout: int = 300,
    capture_output: bool = True,
    retries: int = 0,
    backoff: float = 1.0,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """تنفيذ أمر خارجي مع مهلة وقاتل للعملية الفرعية بأكمل مجموعتها.

    Args:
        cmd: الأمر كقائمة أو نص (يُقسَّم بـ shlex عند النص).
        timeout: المهلة بالثواني — عند تجاوزها تُقتل مجموعة العملية (SIGKILL).
        capture_output: التقاط stdout/stderr أم توجيههما لـ DEVNULL.
        retries: عدد إعادات المحاولة الإضافية عند الفشل (خروج غير صفري أو timeout).
        backoff: أساس التأخير بين المحاولات (يتضاعف أسّياً: backoff * 2^(n-1)).
        cwd: مجلد العمل. env: متغيرات بيئة إضافية.

    Returns:
        dict بالمفاتيح: exit_code, stdout, stderr, duration_ms, timed_out, attempts.
        عند timeout: exit_code=-9 و timed_out=True.

    Raises:
        ValueError: عند أمر فارغ.
        FileNotFoundError: عندما لا يكون الملف التنفيذي موجوداً (لا فائدة من retry).
    """
    argv = shlex.split(cmd) if isinstance(cmd, str) else [str(c) for c in cmd]
    if not argv:
        raise ValueError("الأمر فارغ / empty command")

    total_attempts = retries + 1
    merged_env = {**os.environ, **(env or {})}
    stdout_target = subprocess.PIPE if capture_output else subprocess.DEVNULL
    stderr_target = subprocess.PIPE if capture_output else subprocess.DEVNULL

    result: dict[str, Any] = {}
    for attempt in range(1, total_attempts + 1):
        started = time.perf_counter()
        timed_out = False
        try:
            proc = subprocess.Popen(
                argv,
                stdout=stdout_target,
                stderr=stderr_target,
                cwd=cwd,
                env=merged_env,
                start_new_session=True,  # مجموعة عملية مستقلة لقتل الأبناء مع الأب
            )
            try:
                raw_out, raw_err = proc.communicate(timeout=timeout)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)  # اقتل المجموعة كاملة
                except ProcessLookupError:
                    pass
                raw_out, raw_err = proc.communicate()  # تصريف ما تبقى
                exit_code = -9
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                f"الأمر غير موجود / command not found: {argv[0]} — {exc}"
            ) from exc

        duration_ms = int((time.perf_counter() - started) * 1000)
        result = {
            "exit_code": exit_code,
            "stdout": (raw_out or b"").decode("utf-8", "replace") if capture_output else "",
            "stderr": (raw_err or b"").decode("utf-8", "replace") if capture_output else "",
            "duration_ms": duration_ms,
            "timed_out": timed_out,
            "attempts": attempt,
        }

        if exit_code == 0 and not timed_out:
            break  # نجاح — لا حاجة لإعادة المحاولة
        if attempt < total_attempts:
            time.sleep(backoff * (2 ** (attempt - 1)))  # انتظار أسّي

    return result
