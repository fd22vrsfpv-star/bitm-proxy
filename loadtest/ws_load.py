#!/usr/bin/env python3
"""Concurrency load test for :8092 /ws/data.

Spawns N WebSocket subscribers in parallel, measures:
  - time-to-first-message per client
  - sustained per-client message rate
  - server-side bus metrics (pushed / dropped / fanned_out) via /api/metrics
  - p50 / p95 / p99 client-side message gap
  - CPU & RSS growth from the snapshot endpoint

Usage:
    python3 loadtest/ws_load.py \\
        --url http://127.0.0.1:8092 \\
        --clients 20 \\
        --duration 30

Metrics at end are printed as one-line JSON so you can feed multiple
runs into a comparison table.

No third-party deps beyond `websockets` (already in the venv via
Playwright's requirements).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from urllib.parse import urlparse

try:
    import websockets
except ImportError:
    print("missing `websockets` — pip install websockets", file=sys.stderr)
    sys.exit(2)

try:
    import urllib.request
except ImportError:
    urllib = None


# ── helpers ────────────────────────────────────────────────────────────

def fetch_metrics(base: str) -> dict:
    try:
        with urllib.request.urlopen(base.rstrip("/") + "/api/metrics",
                                    timeout=2) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"_err": str(e)}


def ws_url(base: str, path: str) -> str:
    u = urlparse(base)
    scheme = "wss" if u.scheme == "https" else "ws"
    return f"{scheme}://{u.netloc}{path}"


# ── one client ─────────────────────────────────────────────────────────

async def run_client(cid: int, url: str, duration: float,
                     results: list[dict], stop: asyncio.Event):
    start = time.perf_counter()
    first_msg_at: float | None = None
    n_msgs = 0
    gaps: list[float] = []
    last_recv: float | None = None
    errors = 0

    try:
        async with websockets.connect(url, max_size=2**24,
                                       open_timeout=10,
                                       ping_interval=30) as ws:
            connected_at = time.perf_counter()
            while not stop.is_set():
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    errors += 1
                    break
                now = time.perf_counter()
                if first_msg_at is None:
                    first_msg_at = now
                if last_recv is not None:
                    gaps.append(now - last_recv)
                last_recv = now
                n_msgs += 1
                if now - start >= duration:
                    break
    except Exception as e:
        results.append({"cid": cid, "connect_error": str(e)})
        return

    ttfm = (first_msg_at - connected_at) if first_msg_at else None
    results.append({
        "cid": cid,
        "connect_latency_ms": round((connected_at - start) * 1000, 1),
        "ttfm_ms": round(ttfm * 1000, 1) if ttfm is not None else None,
        "msgs": n_msgs,
        "msgs_per_sec": round(n_msgs / max(1e-6, duration), 2),
        "gap_p50_ms": round(statistics.median(gaps) * 1000, 2) if gaps else None,
        "gap_p95_ms": round(
            statistics.quantiles(gaps, n=20)[-1] * 1000, 2) if len(gaps) >= 20 else None,
        "gap_p99_ms": round(
            statistics.quantiles(gaps, n=100)[-1] * 1000, 2) if len(gaps) >= 100 else None,
        "errors": errors,
    })


# ── main ───────────────────────────────────────────────────────────────

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8092",
                    help="Debug dashboard base URL (http://host:port)")
    ap.add_argument("--clients", type=int, default=10)
    ap.add_argument("--duration", type=float, default=15.0,
                    help="Seconds each client stays connected")
    ap.add_argument("--stagger-ms", type=float, default=20.0,
                    help="Delay between client spawns (smooths connect flood)")
    ap.add_argument("--path", default="/ws/data")
    args = ap.parse_args()

    url = ws_url(args.url, args.path)
    print(f"# connecting {args.clients} clients to {url} for {args.duration}s",
          file=sys.stderr)

    m_before = fetch_metrics(args.url)
    stop = asyncio.Event()
    results: list[dict] = []
    tasks = []
    start = time.perf_counter()

    for i in range(args.clients):
        tasks.append(asyncio.create_task(
            run_client(i, url, args.duration, results, stop)))
        if args.stagger_ms > 0:
            await asyncio.sleep(args.stagger_ms / 1000.0)

    # Let them all finish.
    await asyncio.gather(*tasks, return_exceptions=True)
    wall = time.perf_counter() - start
    m_after = fetch_metrics(args.url)

    ok = [r for r in results if "connect_error" not in r]
    err = [r for r in results if "connect_error" in r]

    all_gaps_p50 = [r["gap_p50_ms"] for r in ok if r.get("gap_p50_ms") is not None]
    all_msgs = sum(r.get("msgs", 0) for r in ok)
    all_ttfm = [r["ttfm_ms"] for r in ok if r.get("ttfm_ms") is not None]

    summary = {
        "clients":        args.clients,
        "duration_s":     args.duration,
        "wall_s":         round(wall, 2),
        "connected_ok":   len(ok),
        "connect_errors": len(err),
        "msgs_total":     all_msgs,
        "msgs_per_client_sec": round(all_msgs / max(1, len(ok)) / max(1e-6, args.duration), 2),
        "ttfm_median_ms": round(statistics.median(all_ttfm), 1) if all_ttfm else None,
        "ttfm_max_ms":    round(max(all_ttfm), 1) if all_ttfm else None,
        "gap_median_of_medians_ms": round(statistics.median(all_gaps_p50), 2) if all_gaps_p50 else None,
        "server_before":  m_before.get("bus", {}),
        "server_after":   m_after.get("bus", {}),
        "rss_before":     m_before.get("rss_bytes"),
        "rss_after":      m_after.get("rss_bytes"),
    }
    # Bus deltas
    b, a = summary["server_before"], summary["server_after"]
    if b and a:
        summary["bus_delta"] = {k: a.get(k, 0) - b.get(k, 0)
                                 for k in ("pushed", "fanned_out", "dropped")}
    print(json.dumps(summary, indent=2))
    for e in err[:5]:
        print(f"# connect error c{e['cid']}: {e.get('connect_error')}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
