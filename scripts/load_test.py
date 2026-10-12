"""اختبار الحمل / Load testing (المرحلة 8).

    python scripts/load_test.py                             # 100 طلب · 10 متوازين
    python scripts/load_test.py --requests 300 --concurrency 20
    python scripts/load_test.py --scans 20 --skip-api       # إنتاجية الفحص فقط

المساران:

1. **قِيس سطح الـ API** — يُشغَّل تطبيق uvicorn حقيقياً في عملية فرعية على منفذ
   حر، ثم 10 عملاء متوازيين ينفّذون مزيجاً مرجّحاً من الطلبات (صحة/لوحة/قوائم)
   ويُقاس p50/p95/p99 وعدد الأخطاء.
   ملاحظة: يُرفع حدّ المعدل (`MAS_RATE_LIMIT_PER_MINUTE=10^6`) لأن اختبار الحمل
   يقيس التطبيق لا الحماية الإدارية — وحدّ 60/دقيقة مُختبَر في ``tests/security``.
2. **إنتاجية الفحص الكاملة** — تشغيل ``ainvoke_pipeline`` في العملية الحالية
   (Mock) وقياس عدد الفحوص/دقيقة + زمن الفحص الواحد (p50/p95).

★ كل رقم في ``results/load_test.md`` مقيس فعلياً في هذا التشغيل — ولا يُقارن
   مباشرة بنشر إنتاجي (بلا شبكة/نماذج حقيقية).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

RESULTS_DIR = PROJECT_ROOT / "results"
DEFAULT_MD = RESULTS_DIR / "load_test.md"
DEFAULT_JSON = RESULTS_DIR / "load_test.json"

# اختبار الحمل يعمل في Mock افتراضياً كي يكون قابلاً لإعادة الإنتاج بلا مفاتيح
# (يمكن تجاوزه بتعيين المتغيرات في البيئة قبل التشغيل)
os.environ.setdefault("LLM_MOCK_MODE", "1")
os.environ.setdefault("MCP_MOCK_MODE", "1")
os.environ.setdefault("EMBEDDING_MOCK_MODE", "1")

MOCK_ENV = {
    "LLM_MOCK_MODE": "1",
    "MCP_MOCK_MODE": "1",
    "EMBEDDING_MOCK_MODE": "1",
    "MAS_RATE_LIMIT_PER_MINUTE": "1000000",
    "MAS_ENV": "development",
}

# مزيج الطلبات (المسار، الوزن) — قراءات شائعة في الواجهة
REQUEST_MIX: list[tuple[str, int]] = [
    ("/health", 3),
    ("/dashboard/summary", 2),
    ("/dashboard/recent_scans", 2),
    ("/dashboard/severity_chart", 2),
    ("/projects", 2),
    ("/scans", 2),
    ("/assessments/stats", 1),
]


def free_port() -> int:
    """منفذ TCP حر من النظام."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def percentiles(samples: list[float]) -> dict[str, float]:
    """p50/p95/p99 + المتوسط والأقصى (ms) — بطريقة الفهرسة الخطية."""
    if not samples:
        return {}
    ordered = sorted(samples)

    def pick(quantile: float) -> float:
        index = min(len(ordered) - 1, max(0, int(round(quantile * (len(ordered) - 1)))))
        return round(ordered[index], 3)

    return {
        "count": len(ordered),
        "mean_ms": round(statistics.fmean(ordered), 3),
        "p50_ms": pick(0.50),
        "p95_ms": pick(0.95),
        "p99_ms": pick(0.99),
        "max_ms": round(ordered[-1], 3),
        "min_ms": round(ordered[0], 3),
    }


# ---------------------------------------------------------------------
# 1) حمل سطح الـ API
# ---------------------------------------------------------------------
async def _hit(client: Any, method: str, path: str, headers: dict[str, str]) -> tuple[float, int]:
    """طلب واحد — يُعيد (الزمن ms، رمز الحالة) بلا رفع استثناء."""
    started = time.perf_counter()
    try:
        response = await client.request(method, path, headers=headers)
        status = response.status_code
    except Exception:  # noqa: BLE001 — خطأ شبكة يُحسب فشلاً لا انهياراً
        status = 0
    return (time.perf_counter() - started) * 1000, status


async def run_api_load(
    base_url: str, username: str, password: str, requests_total: int, concurrency: int
) -> dict[str, Any]:
    """تنفيذ N طلباً بـ C عملاء متوازيين وقياس التوزيع."""
    import httpx

    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        login = await client.post("/auth/login", json={"username": username, "password": password})
        if login.status_code != 200:
            return {"error": f"فشل تسجيل الدخول للأداء: {login.status_code} {login.text[:200]}"}
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        schedule: list[str] = []
        while len(schedule) < requests_total:
            for path, weight in REQUEST_MIX:
                schedule.extend([path] * weight)
        schedule = schedule[:requests_total]

        queue: asyncio.Queue[str] = asyncio.Queue()
        for path in schedule:
            queue.put_nowait(path)

        latencies: list[float] = []
        status_counts: dict[int, int] = {}
        lock = asyncio.Lock()

        async def worker() -> None:
            while True:
                try:
                    path = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                elapsed, status = await _hit(client, "GET", path, headers)
                async with lock:
                    latencies.append(elapsed)
                    status_counts[status] = status_counts.get(status, 0) + 1

        wall_started = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(concurrency)))
        wall = time.perf_counter() - wall_started

    successful = sum(count for status, count in status_counts.items() if 200 <= status < 300)
    return {
        "requests": len(latencies),
        "concurrency": concurrency,
        "wall_seconds": round(wall, 3),
        "requests_per_second": round(len(latencies) / wall, 1) if wall else None,
        "status_counts": {str(k): v for k, v in sorted(status_counts.items())},
        "success_rate": round(successful / len(latencies), 4) if latencies else None,
        "latency": percentiles(latencies),
    }


def start_api_subprocess(port: int) -> subprocess.Popen:
    """تشغيل uvicorn في عملية فرعية (Mock + حدّ معدل مرتفع)."""
    env = {**os.environ, **MOCK_ENV}
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1",
         "--port", str(port), "--log-level", "warning"],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 45
    import httpx

    while time.time() < deadline:
        if process.poll() is not None:
            output = process.stdout.read().decode("utf-8", "ignore") if process.stdout else ""
            raise RuntimeError(f"الـ API توقف أثناء الإقلاع:\n{output[-1500:]}")
        try:
            with httpx.Client(timeout=2.0) as probe:
                if probe.get(f"http://127.0.0.1:{port}/health").status_code == 200:
                    return process
        except Exception:  # noqa: BLE001 — لم يجهز بعد
            time.sleep(0.5)
    process.terminate()
    raise RuntimeError("انتهت مهلة إقلاع الـ API (45s)")


# ---------------------------------------------------------------------
# 2) إنتاجية الفحص
# ---------------------------------------------------------------------
def run_scan_throughput(scans: int) -> dict[str, Any]:
    """قياس زمن فحص كامل (Mock) عبر ainvoke_pipeline — p50/p95 وفحوص/دقيقة."""
    from agents.graph import ainvoke_pipeline, build_scan_graph
    from agents.state import ScanState

    apks_dir = PROJECT_ROOT / "data" / "apks"
    apks_dir.mkdir(parents=True, exist_ok=True)
    sample = apks_dir / "benchmark_sample.apk"
    if not sample.exists():
        sample.write_bytes(b"PK\x03\x04" + b"load-test-placeholder" * 64)

    durations: list[float] = []
    stages: dict[str, int] = {}
    for index in range(max(1, scans)):
        state = ScanState(
            scan_id=f"load_{index}",
            application_id=3,
            apk_path=str(sample),
            package_name="load.package",
            app_category="utility",
            user_request="اختبار حمل",
        )

        async def once() -> dict[str, Any]:
            graph = build_scan_graph()
            return await ainvoke_pipeline(graph, state)

        started = time.perf_counter()
        result = asyncio.run(once())
        durations.append((time.perf_counter() - started) * 1000)
        stage = str(result.get("current_stage"))
        stages[stage] = stages.get(stage, 0) + 1

    summary = percentiles(durations)
    summary["scans_per_minute"] = (
        round(60_000 / summary["mean_ms"], 1) if summary.get("mean_ms") else None
    )
    summary["final_stages"] = stages
    return summary


# ---------------------------------------------------------------------
# التقرير
# ---------------------------------------------------------------------
def build_report(data: dict[str, Any]) -> str:
    """تقرير Markdown — المقيس فقط."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# تقرير اختبار الحمل (Load Test) — الإصدار v1.0",
        f"\n**تاريخ التوليد:** {generated}",
        f"**البيئة:** Mock كامل · Python {sys.version.split()[0]} · "
        f"منصة {sys.platform}",
        "",
    ]

    api = data.get("api") or {}
    lines += ["## 1) حمل سطح الـ API", ""]
    if api.get("error"):
        lines.append(f"> ⚠️ {api['error']}")
    else:
        latency = api["latency"]
        lines += [
            f"- الطلبات: **{api['requests']}** · التوازي: **{api['concurrency']}** · "
            f"الجدار الزمني: **{api['wall_seconds']}s**",
            f"- الإنتاجية: **{api['requests_per_second']} طلب/ثانية** · "
            f"نسبة النجاح: **{api['success_rate']}**",
            f"- رموز الحالة: `{api['status_counts']}`",
            "",
            "| المقياس | القيمة (ms) |",
            "|---|---|",
            f"| p50 | {latency['p50_ms']} |",
            f"| p95 | {latency['p95_ms']} |",
            f"| p99 | {latency['p99_ms']} |",
            f"| المتوسط | {latency['mean_ms']} |",
            f"| الأدنى / الأعلى | {latency['min_ms']} / {latency['max_ms']} |",
        ]
    lines.append("")

    scan = data.get("scans") or {}
    lines += ["## 2) إنتاجية الفحص الكاملة (Mock)", ""]
    if scan:
        lines += [
            f"- الفحوص: **{scan['count']}** · المراحل النهائية: `{scan['final_stages']}`",
            f"- الإنتاجية: **{scan['scans_per_minute']} فحص/دقيقة** (تسلسلياً)",
            "",
            "| المقياس | القيمة (ms) |",
            "|---|---|",
            f"| p50 | {scan['p50_ms']} |",
            f"| p95 | {scan['p95_ms']} |",
            f"| p99 | {scan['p99_ms']} |",
            f"| المتوسط | {scan['mean_ms']} |",
            "",
            "> في النشر الفعلي: عامل uvicorn واحد + SQLite ⇒ الفحوص تُصفّ "
            "(BackgroundTasks)، والتوسع الأفقي يحتاج قاعدة/طابوراً خارجياً "
            "(انظر limitations_and_future_work.md).",
        ]
    lines += [
        "",
        "## 3) منهجية وحدود",
        "",
        "- القياس على **نفس الجهاز** الذي يشغّل التطبيق؛ أرقام السطح لا تتضمن شبكة حقيقية.",
        f"- مزيج الطلبات: `{REQUEST_MIX}` (قراءات فقط — الكتابة الثقيلة مُقاسة في benchmark.md).",
        "- حدّ المعدل مرفوع أثناء الاختبار (يقيس سلوك التطبيق لا الحماية) — حدّ الإنتاج "
        "60/دقيقة مُختبَر في `tests/security/test_security.py`.",
        "- إعادة التشغيل: `python scripts/load_test.py --requests 300 --concurrency 20`.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    """يشغّل المسارين ويكتب ``results/load_test.md`` + JSON."""
    parser = argparse.ArgumentParser(description="اختبار حمل النظام")
    parser.add_argument("--requests", type=int, default=100, help="عدد طلبات سطح الـ API")
    parser.add_argument("--concurrency", type=int, default=10, help="عدد العملاء المتوازيين")
    parser.add_argument("--scans", type=int, default=10, help="عدد الفحوص الكاملة")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default=os.getenv("ADMIN_PASSWORD", "admin123"))
    parser.add_argument("--skip-api", action="store_true", help="تخطي حمل سطح الـ API")
    parser.add_argument("--skip-scans", action="store_true", help="تخطي فحوص الإنتاجية")
    parser.add_argument("--output", default=str(DEFAULT_MD))
    parser.add_argument("--json", default=str(DEFAULT_JSON))
    args = parser.parse_args()

    data: dict[str, Any] = {
        "requests": args.requests,
        "concurrency": args.concurrency,
        "scans_requested": args.scans,
    }

    if not args.skip_api:
        port = free_port()
        print(f"◉ تشغيل الـ API على المنفذ {port} (Mock)…")
        process = start_api_subprocess(port)
        try:
            data["api"] = asyncio.run(
                run_api_load(
                    f"http://127.0.0.1:{port}", args.username, args.password,
                    args.requests, args.concurrency,
                )
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        api = data["api"]
        if api.get("error"):
            print("  ⚠️", api["error"])
        else:
            print(
                f"  ✓ {api['requests']} طلباً · {api['concurrency']} متوازياً · "
                f"p50={api['latency']['p50_ms']}ms p95={api['latency']['p95_ms']}ms "
                f"p99={api['latency']['p99_ms']}ms · نجاح {api['success_rate']}"
            )

    if not args.skip_scans:
        print(f"◉ قياس إنتاجية الفحص ({args.scans} فحوص Mock)…")
        data["scans"] = run_scan_throughput(args.scans)
        print(
            f"  ✓ p50={data['scans']['p50_ms']}ms p95={data['scans']['p95_ms']}ms · "
            f"{data['scans']['scans_per_minute']} فحص/دقيقة"
        )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(build_report(data), encoding="utf-8")
    Path(args.json).write_text(
        json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8"
    )
    print(f"✅ التقرير: {output}")
    print(f"✅ JSON:    {args.json}")


if __name__ == "__main__":
    main()
