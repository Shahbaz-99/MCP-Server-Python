"""Load and memory test against a real mcp_hub HTTP server (auth on, API key).

Usage: uv run python scripts/loadtest.py [--clients 100] [--duration 20] [--paced-rps 2] [--soak 0]

Scenarios (each prints latency percentiles, error count and throughput):
  idle      one client, sequential calls: pure per-request latency
  saturate  N clients in a closed loop: maximum throughput; latency = queueing (Little's law)
  paced     N clients at a fixed per-client rate: latency under concurrent load below capacity
Server RSS is sampled throughout and growth after warm-up is reported.

The load generator uses threads with keep-alive http.client connections on purpose: an asyncio
httpx client on Windows tops out around 100-200 requests/s and would measure itself, not the server.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import psutil

from mcp_hub.security.apikeys import KeyStore

BODY = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "load"}},
    }
)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


def scenario(
    name: str, port: int, key: str, clients: int, duration: float, per_client_rps: float = 0.0
) -> dict[str, float | int | str]:
    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    lat: list[float] = []
    errors = [0]
    lock = threading.Lock()
    stop_at = time.perf_counter() + duration
    interval = 1.0 / per_client_rps if per_client_rps else 0.0

    def worker() -> None:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        local: list[float] = []
        bad = 0
        next_at = time.perf_counter()
        while time.perf_counter() < stop_at:
            if interval:
                next_at += interval
                if (delay := next_at - time.perf_counter()) > 0:
                    time.sleep(delay)
            t0 = time.perf_counter()
            try:
                conn.request("POST", "/mcp", body=BODY, headers=headers)
                resp = conn.getresponse()
                text = resp.read().decode()
                ok = resp.status == 200 and '"isError":false' in text.replace(" ", "")
            except (OSError, http.client.HTTPException):
                ok = False
                conn.close()
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            local.append((time.perf_counter() - t0) * 1000)
            bad += 0 if ok else 1
        with lock:
            lat.extend(local)
            errors[0] += bad

    threads = [threading.Thread(target=worker) for _ in range(clients)]
    t_start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t_start
    out: dict[str, float | int | str] = {
        "scenario": name,
        "clients": clients,
        "requests": len(lat),
        "errors": errors[0],
        "rps": round(len(lat) / elapsed, 1),
        "p50_ms": round(pct(lat, 0.50), 2),
        "p95_ms": round(pct(lat, 0.95), 2),
        "p99_ms": round(pct(lat, 0.99), 2),
        "max_ms": round(max(lat), 2),
        "mean_ms": round(statistics.fmean(lat), 2),
    }
    print(json.dumps(out), flush=True)  # noqa: T201
    return out


def server_rss_mb(proc: psutil.Process) -> float:
    """RSS of the real server: on Windows the venv launcher is a tiny parent of the interpreter."""
    procs = [proc, *proc.children(recursive=True)]
    return max(p.memory_info().rss for p in procs) / 1e6


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=100)
    ap.add_argument("--duration", type=float, default=20.0)
    ap.add_argument("--paced-rps", type=float, default=2.0)
    ap.add_argument("--soak", type=float, default=0.0, help="extra seconds of saturating load")
    args = ap.parse_args()

    port = free_port()
    with tempfile.TemporaryDirectory() as tmp:
        key_file = Path(tmp) / "keys.json"
        key, _ = KeyStore(key_file).create("loadtest", ["sample:read"])
        env = dict(os.environ)
        env.update(
            {
                "MCP_HUB_ENABLED_PLUGINS": '["sample"]',
                "MCP_HUB_AUTH__ENABLED": "true",
                "MCP_HUB_AUTH__RESOURCE_URL": f"http://127.0.0.1:{port}/mcp",
                "MCP_HUB_AUTH__API_KEY_FILE": str(key_file),
                "MCP_HUB_HTTP__RATE_LIMIT_PER_MINUTE": "100000000",
                "MCP_HUB_HTTP__MAX_CONCURRENCY": "1024",
                "MCP_HUB_LOG_LEVEL": "WARNING",  # audit lines are INFO: measure the server
            }
        )
        proc = subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "mcp_hub", "--transport", "http", "--port", str(port)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(150):
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                    conn.request("GET", "/readyz")
                    if conn.getresponse().status == 200:
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                print("server did not start")  # noqa: T201
                return 2
            ps = psutil.Process(proc.pid)
            samples: list[float] = []
            sampling = threading.Event()

            def sampler() -> None:
                while not sampling.is_set():
                    samples.append(server_rss_mb(ps))
                    sampling.wait(1.0)

            threading.Thread(target=sampler, daemon=True).start()
            report = [
                scenario("idle", port, key, 1, min(args.duration, 10)),
                scenario("saturate", port, key, args.clients, args.duration),
                scenario("paced", port, key, args.clients, args.duration, args.paced_rps),
            ]
            if args.soak:
                report.append(scenario("soak", port, key, args.clients, args.soak))
            sampling.set()
            # Steady state = the second half of the run; early growth is connection/buffer warm-up.
            half = samples[len(samples) // 2 :]
            base = statistics.fmean(half[: max(1, len(half) // 4)])
            tail = statistics.fmean(half[-max(1, len(half) // 4) :])
            print(  # noqa: T201
                json.dumps(
                    {
                        "memory_mb": {
                            "start": round(samples[0], 1),
                            "steady_state_start": round(base, 1),
                            "end": round(tail, 1),
                            "peak": round(max(samples), 1),
                            "steady_state_growth_pct": round((tail - base) / base * 100, 1),
                        },
                        "total_errors": sum(int(r["errors"]) for r in report),
                    }
                )
            )
            return 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
