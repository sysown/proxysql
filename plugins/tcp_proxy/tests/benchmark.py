#!/usr/bin/env python3
"""HISTORICAL engine-only loopback benchmark tooling (superseded).

Current four-table product evidence is produced by daemon_benchmark.py with
direct/mysql/pgsql/haproxy modes.  This tool remains only for reproduction of
the earlier standalone-Engine measurements; it does not configure a real
daemon and must never be presented as four-table daemon evidence.  Native mode
is gated behind --allow-historical-engine-only and writes dated `-historical`
paths by default so it cannot overwrite current reports.

Modes
  direct   client -> task-owned echo backend (no proxy)
  native   client -> production tcp_proxy::Engine harness -> backend
  haproxy  client -> local HAProxy -> backend (optional comparator)

All modes use the same backend process, echo protocol, payload generator,
client parameters and worker count (where applicable).  Measurements are local
loopback observations, not deployment performance claims.

Default runs are short.  Native mode is skipped unless the coordinator-created
readiness marker and a built harness exist; it is then gated by an exact-byte
precheck.  Raw JSON and a dated Markdown summary are written on completion.

Byte direction:
  client_to_server = bytes sent by the benchmark client and echoed by the
                     server (application payload, not TCP headers).
  server_to_client = bytes returned to the client.
  throughput is reported separately for both directions and is therefore equal
  for the echo protocol.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

import tcp_proxy_testlib as lib

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parents[2]
DATE = "2026-11-11"
DEFAULT_JSON = (REPO_ROOT / "docs" / "benchmarks"
                / f"{DATE}-native-tcp-proxy-historical.json")
DEFAULT_MD = (REPO_ROOT / "docs" / "benchmarks"
              / f"{DATE}-native-tcp-proxy-historical.md")
DEFAULT_HARNESS = str(TESTS_DIR / "engine_harness")
DEFAULT_HAPROXY = "/tmp/native-tcp-proxy/haproxy-build/haproxy"
RAW_DIR = Path("/tmp/native-tcp-proxy/bench-raw")


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def percentile(sorted_samples: list[float], fraction: float) -> float:
    if not sorted_samples:
        return float("nan")
    index = max(0, min(len(sorted_samples) - 1,
                       math.ceil(fraction * len(sorted_samples)) - 1))
    return sorted_samples[index]


def summarize_samples(samples_ms: list[float]) -> dict:
    if not samples_ms:
        return {"count": 0}
    ordered = sorted(samples_ms)
    return {
        "count": len(ordered),
        "min_ms": round(ordered[0], 6),
        "p50_ms": round(percentile(ordered, 0.50), 6),
        "p95_ms": round(percentile(ordered, 0.95), 6),
        "p99_ms": round(percentile(ordered, 0.99), 6),
        "max_ms": round(ordered[-1], 6),
        "mean_ms": round(mean(ordered), 6),
    }


def read_json_wait(path: Path, timeout: float) -> dict:
    deadline = lib.Deadline(timeout)
    last_error = None
    while not deadline.expired():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(0.02)
    raise TimeoutError(f"could not read {path}: {last_error}")


def write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


# ---------------------------------------------------------------------------
# Task-owned processes
# ---------------------------------------------------------------------------


class BackendProcess:
    def __init__(self, results_dir: Path, host: str = lib.LOOPBACK_V4):
        stamp = f"{int(time.time() * 1000)}-{os.getpid()}"
        self.ready_path = results_dir / f"backend-{stamp}.ready.json"
        self.stats_path = results_dir / f"backend-{stamp}.stats.json"
        self.log_path = results_dir / f"backend-{stamp}.log"
        self.host = host
        self.proc: subprocess.Popen | None = None
        self.port = 0
        self.command: list[str] = []
        self.started_utc = ""

    def start(self, timeout: float = 10.0) -> None:
        for path in (self.ready_path, self.stats_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        self.command = [
            sys.executable, str(TESTS_DIR / "bench_backend.py"),
            "--host", self.host, "--port", "0",
            "--ready-file", str(self.ready_path),
            "--stats-file", str(self.stats_path),
            "--backlog", "1024", "--max-connections", "8192",
            "--stats-interval", "0.25",
        ]
        handle = open(self.log_path, "wb")
        try:
            self.proc = subprocess.Popen(self.command, stdout=handle, stderr=handle,
                                         close_fds=True)
        finally:
            handle.close()
        ready = read_json_wait(self.ready_path, timeout)
        if ready.get("pid") != self.proc.pid:
            raise RuntimeError(f"backend ready pid mismatch: {ready}")
        self.port = int(ready["port"])
        self.started_utc = ready.get("started_utc", "")
        if not lib.wait_port_listening(self.host, self.port, timeout):
            raise RuntimeError(f"backend did not listen on {self.host}:{self.port}")

    @property
    def pid(self) -> int:
        assert self.proc is not None
        return int(self.proc.pid)

    def live_stats(self, wait: bool = False) -> dict:
        try:
            if wait:
                return read_json_wait(self.stats_path, 2.0)
            return json.loads(self.stats_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TimeoutError):
            return {}

    def stop(self, timeout: float = 10.0) -> dict:
        if self.proc is None:
            return {}
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    pass
        try:
            return json.loads(self.stats_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"error": "final backend stats missing"}


class HAProxyProcess:
    def __init__(self, binary: str, backend_host: str, backend_port: int,
                 workers: int, results_dir: Path):
        stamp = f"{int(time.time() * 1000)}-{os.getpid()}"
        self.binary = binary
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.workers = workers
        self.config_path = results_dir / f"haproxy-{stamp}.cfg"
        self.log_path = results_dir / f"haproxy-{stamp}.log"
        self.pid_path = results_dir / f"haproxy-{stamp}.pid"
        self.host = lib.LOOPBACK_V4
        self.port = 0
        self.proc: subprocess.Popen | None = None
        self.command: list[str] = []

    def start(self, timeout: float = 10.0) -> None:
        self.port = lib.free_port()
        config = f"""global
    nbthread {self.workers}
    maxconn 8192

defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s

listen bench
    bind {self.host}:{self.port}
    server s1 {self.backend_host}:{self.backend_port}
"""
        self.config_path.write_text(config, encoding="utf-8")
        self.command = [self.binary, "-f", str(self.config_path), "-db",
                        "-p", str(self.pid_path)]
        handle = open(self.log_path, "wb")
        try:
            self.proc = subprocess.Popen(self.command, stdout=handle, stderr=handle,
                                         close_fds=True)
        finally:
            handle.close()
        if not lib.wait_port_listening(self.host, self.port, timeout):
            tail = ""
            try:
                tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
            except OSError:
                pass
            raise RuntimeError(f"HAProxy failed to listen: {tail}")

    @property
    def pid(self) -> int:
        assert self.proc is not None
        return int(self.proc.pid)

    def stop(self, timeout: float = 10.0) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    pass


class NativeEngineProcess:
    def __init__(self, harness: str, backend_host: str, backend_port: int,
                 workers: int, results_dir: Path):
        self.harness = harness
        self.command = [harness]
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.workers = workers
        self.results_dir = results_dir
        self.client: lib.HarnessClient | None = None
        self.host = lib.LOOPBACK_V4
        self.port = 0
        self.config: dict = {}
        self.stderr_path = results_dir / f"native-harness-{int(time.time() * 1000)}.stderr"

    def start(self, timeout: float = 15.0) -> None:
        self.port = lib.free_port()
        self.config = lib.simple_config(
            self.port, self.backend_port,
            settings_row=lib.settings(worker_threads=self.workers,
                                      max_connections=100000,
                                      buffer_size=16384),
            listener_overrides={"max_connections": 100000,
                                "connect_timeout_ms": 5000,
                                "idle_timeout_ms": 0,
                                "max_connect_attempts": 3},
            server_overrides={"max_connections": 100000},
        )
        self.client = lib.HarnessClient(self.harness, stderr_path=str(self.stderr_path))
        self.client.ping(timeout=5.0)
        response = self.client.start(self.config, timeout=timeout)
        if not response.get("ok"):
            raise RuntimeError(f"native start failed: {response.get('error')}")

    @property
    def pid(self) -> int:
        assert self.client is not None
        return self.client.pid

    def snapshot(self) -> dict:
        assert self.client is not None
        return self.client.snapshot()

    def stop(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None


# ---------------------------------------------------------------------------
# Process metrics
# ---------------------------------------------------------------------------


def process_metrics(pid: int | None) -> dict | None:
    if pid is None:
        return None
    return {
        "pid": pid,
        "rss_kb": lib.proc_rss_kb(pid),
        "fds": lib.proc_fd_count(pid),
        "threads": lib.proc_thread_count(pid),
        "cpu_ticks": lib.proc_cpu_ticks(pid),
    }


def capture_processes(pids: dict[str, int | None]) -> dict:
    return {name: process_metrics(pid) for name, pid in pids.items() if pid is not None}


def process_deltas(before: dict, after: dict, elapsed_s: float,
                    ticks_per_second: int) -> dict:
    out: dict = {}
    for name, start in before.items():
        end = after.get(name)
        if not start or not end:
            out[name] = {"before": start, "after": end}
            continue
        tick_delta = None
        if start.get("cpu_ticks") is not None and end.get("cpu_ticks") is not None:
            tick_delta = end["cpu_ticks"] - start["cpu_ticks"]
        cpu_seconds = (tick_delta / ticks_per_second) if tick_delta is not None else None
        cpu_percent = (100.0 * cpu_seconds / elapsed_s) if cpu_seconds is not None and elapsed_s else None
        out[name] = {
            "pid": start["pid"],
            "cpu_ticks_before": start.get("cpu_ticks"),
            "cpu_ticks_after": end.get("cpu_ticks"),
            "cpu_ticks_delta": tick_delta,
            "cpu_seconds": round(cpu_seconds, 6) if cpu_seconds is not None else None,
            "cpu_percent": round(cpu_percent, 3) if cpu_percent is not None else None,
            "rss_kb_before": start.get("rss_kb"),
            "rss_kb_after": end.get("rss_kb"),
            "rss_kb_delta": end.get("rss_kb", 0) - start.get("rss_kb", 0),
            "fds_before": start.get("fds"),
            "fds_after": end.get("fds"),
            "threads_before": start.get("threads"),
            "threads_after": end.get("threads"),
        }
    return out


def run_phase(name: str, pids: dict[str, int | None], func) -> dict:
    ticks = lib.clock_ticks_per_second()
    before = capture_processes(pids)
    started = time.monotonic()
    try:
        result = func()
        error = None
    except BaseException as exc:  # noqa: BLE001
        result = {}
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.monotonic() - started
    after = capture_processes(pids)
    phase = {
        "name": name,
        "status": "completed" if error is None else "error",
        "elapsed_s": round(elapsed, 6),
        "process": process_deltas(before, after, elapsed, ticks),
    }
    if error:
        phase["error"] = error
    phase.update(result)
    return phase


# ---------------------------------------------------------------------------
# Client workloads
# ---------------------------------------------------------------------------


def measure_latency(host: str, port: int, concurrency: int, warmup: int,
                    samples: int, payload: bytes, timeout: float = 10.0) -> dict:
    samples_ms: list[float] = []
    errors: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(concurrency + 1)
    live_sockets: list[socket.socket] = []

    def worker(index: int) -> None:
        sock = None
        local: list[float] = []
        try:
            sock = lib.connect_socket(host, port, timeout)
            with lock:
                live_sockets.append(sock)
            barrier.wait(timeout=timeout)
            for _ in range(warmup):
                sock.sendall(payload)
                if lib.recv_exact(sock, len(payload), timeout) != payload:
                    raise AssertionError("warmup echo mismatch")
            for _ in range(samples):
                started = time.perf_counter_ns()
                sock.sendall(payload)
                received = lib.recv_exact(sock, len(payload), timeout)
                elapsed = (time.perf_counter_ns() - started) / 1_000_000.0
                if received != payload:
                    raise AssertionError("measured echo mismatch")
                local.append(elapsed)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(f"worker {index}: {type(exc).__name__}: {exc}")
            try:
                barrier.abort()
            except Exception:  # noqa: BLE001
                pass
        finally:
            with lock:
                samples_ms.extend(local)
                if sock is not None and sock in live_sockets:
                    live_sockets.remove(sock)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(concurrency)]
    for thread in threads:
        thread.start()
    try:
        barrier.wait(timeout=timeout)
    except threading.BrokenBarrierError:
        pass
    for thread in threads:
        thread.join(timeout=timeout + 5.0)
    alive = [thread.name for thread in threads if thread.is_alive()]
    if alive:
        with lock:
            leftovers = list(live_sockets)
        for sock in leftovers:
            try:
                sock.close()
            except OSError:
                pass
        raise RuntimeError(f"RTT client threads still alive: {alive}")
    if errors:
        raise RuntimeError("; ".join(errors[:3]))
    expected = concurrency * samples
    if len(samples_ms) != expected:
        raise RuntimeError(
            f"RTT sample count {len(samples_ms)} != expected {expected}")
    if not samples_ms or any(not (value > 0.0 and math.isfinite(value))
                             for value in samples_ms):
        raise RuntimeError("RTT samples are empty or non-positive")
    return {"summary": summarize_samples(samples_ms), "samples_ms": samples_ms,
            "payload_bytes": len(payload), "payload_sha256": sha256_bytes(payload)}


def measure_connections(host: str, port: int, concurrency: int, duration: float,
                        payload: bytes, timeout: float = 10.0) -> dict:
    stop = threading.Event()
    errors: list[str] = []
    lock = threading.Lock()
    completed = [0]
    bytes_total = [0]
    barrier = threading.Barrier(concurrency + 1)
    live_sockets: list[socket.socket] = []

    def worker(index: int) -> None:
        try:
            barrier.wait(timeout=timeout)
            while not stop.is_set():
                sock = lib.connect_socket(host, port, timeout)
                with lock:
                    live_sockets.append(sock)
                try:
                    sock.sendall(payload)
                    received = lib.recv_exact(sock, len(payload), timeout)
                    if received != payload:
                        raise AssertionError("connection echo mismatch")
                    with lock:
                        completed[0] += 1
                        bytes_total[0] += len(payload)
                finally:
                    with lock:
                        if sock in live_sockets:
                            live_sockets.remove(sock)
                    sock.close()
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(f"worker {index}: {type(exc).__name__}: {exc}")
            try:
                barrier.abort()
            except Exception:  # noqa: BLE001
                pass

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(concurrency)]
    for thread in threads:
        thread.start()
    started = time.monotonic()
    try:
        barrier.wait(timeout=timeout)
    except threading.BrokenBarrierError:
        pass
    time.sleep(duration)
    stop.set()
    for thread in threads:
        thread.join(timeout=timeout + 5.0)
    # Denominator is the actual completion interval: in-flight transactions
    # that finish during the bounded join are counted exactly once.
    elapsed = time.monotonic() - started
    alive = [thread.name for thread in threads if thread.is_alive()]
    if alive:
        with lock:
            leftovers = list(live_sockets)
        for sock in leftovers:
            try:
                sock.close()
            except OSError:
                pass
        raise RuntimeError(f"connections/s client threads still alive: {alive}")
    if errors:
        raise RuntimeError("; ".join(errors[:3]))
    if completed[0] <= 0:
        raise RuntimeError("no completed connection transactions")
    return {
        "connections_completed": completed[0],
        "connections_per_s": round(completed[0] / elapsed, 3) if elapsed else None,
        "application_bytes_client_to_server": bytes_total[0],
        "application_bytes_server_to_client": bytes_total[0],
        "duration_s": round(elapsed, 6),
        "payload_bytes": len(payload),
        "payload_sha256": sha256_bytes(payload),
    }


def measure_throughput(host: str, port: int, concurrency: int, duration: float,
                       payload: bytes, timeout: float = 15.0) -> dict:
    stop = threading.Event()
    errors: list[str] = []
    lock = threading.Lock()
    totals = [0, 0]  # c2s, s2c
    transactions = [0]
    barrier = threading.Barrier(concurrency + 1)
    live_sockets: list[socket.socket] = []

    def worker(index: int) -> None:
        sock = None
        try:
            sock = lib.connect_socket(host, port, timeout)
            with lock:
                live_sockets.append(sock)
            barrier.wait(timeout=timeout)
            while not stop.is_set():
                sock.sendall(payload)
                received = lib.recv_exact(sock, len(payload), timeout)
                if received != payload:
                    raise AssertionError("throughput echo mismatch")
                with lock:
                    totals[0] += len(payload)
                    totals[1] += len(received)
                    transactions[0] += 1
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(f"worker {index}: {type(exc).__name__}: {exc}")
            try:
                barrier.abort()
            except Exception:  # noqa: BLE001
                pass
        finally:
            with lock:
                if sock is not None and sock in live_sockets:
                    live_sockets.remove(sock)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(concurrency)]
    for thread in threads:
        thread.start()
    started = time.monotonic()
    try:
        barrier.wait(timeout=timeout)
    except threading.BrokenBarrierError:
        pass
    time.sleep(duration)
    stop.set()
    for thread in threads:
        thread.join(timeout=timeout + 5.0)
    elapsed = time.monotonic() - started
    alive = [thread.name for thread in threads if thread.is_alive()]
    if alive:
        with lock:
            leftovers = list(live_sockets)
        for sock in leftovers:
            try:
                sock.close()
            except OSError:
                pass
        raise RuntimeError(f"throughput client threads still alive: {alive}")
    if errors:
        raise RuntimeError("; ".join(errors[:3]))
    if transactions[0] <= 0:
        raise RuntimeError("no completed throughput transactions")
    return {
        "duration_s": round(elapsed, 6),
        "transactions": transactions[0],
        "payload_bytes": len(payload),
        "payload_sha256": sha256_bytes(payload),
        "bytes_client_to_server": totals[0],
        "bytes_server_to_client": totals[1],
        "client_to_server_mib_per_s": round(totals[0] / elapsed / (1024 * 1024), 3)
        if elapsed else None,
        "server_to_client_mib_per_s": round(totals[1] / elapsed / (1024 * 1024), 3)
        if elapsed else None,
    }


def measure_idle(host: str, port: int, connections: int,
                 pids: dict[str, int | None], idle_interval: float = 1.0,
                 settle: float = 0.5) -> dict:
    """Establish idle flows, then sample a genuinely quiescent interval.

    Establishment CPU (connect + echo + settle) is reported separately from
    quiescent CPU sampled over ``idle_interval`` after the flows have settled.
    """
    if connections < 1:
        raise RuntimeError("idle measurement requires at least one connection")
    ticks = lib.clock_ticks_per_second()
    baseline = capture_processes(pids)
    socks: list[socket.socket] = []
    establish_started = time.monotonic()
    try:
        for _ in range(connections):
            sock = lib.connect_socket(host, port, 5.0)
            sock.sendall(b"i")
            if lib.recv_exact(sock, 1, 5.0) != b"i":
                raise AssertionError("idle establishment echo mismatch")
            socks.append(sock)
        time.sleep(settle)
        establish_elapsed = time.monotonic() - establish_started
        established = capture_processes(pids)
        delta = {}
        for name, start in baseline.items():
            end = established.get(name)
            if not start or not end:
                continue
            delta[name] = {
                "rss_kb_delta": end.get("rss_kb", 0) - start.get("rss_kb", 0),
                "fds_delta": end.get("fds", 0) - start.get("fds", 0),
                "threads_delta": end.get("threads", 0) - start.get("threads", 0),
            }

        quiescent_before = capture_processes(pids)
        quiescent_started = time.monotonic()
        time.sleep(idle_interval)
        quiescent_elapsed = time.monotonic() - quiescent_started
        quiescent_after = capture_processes(pids)
        return {
            "connections": connections,
            "settle_s": settle,
            "baseline": baseline,
            "with_idle": established,
            "delta": delta,
            "establishment": {
                "elapsed_s": round(establish_elapsed, 6),
                "process": process_deltas(baseline, established, establish_elapsed, ticks),
                "note": "connect + exact echo + settle; not idle CPU",
            },
            "quiescent": {
                "interval_s": round(quiescent_elapsed, 6),
                "ticks_per_second": ticks,
                "cpu_tick_precision_ms": round(1000.0 / ticks, 3) if ticks else None,
                "process": process_deltas(quiescent_before, quiescent_after,
                                          quiescent_elapsed, ticks),
            },
            "socket_options": {
                "tcp_nodelay": True,
                "scope": "benchmark client sockets and accepted Python backend sockets",
            },
        }
    finally:
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Mode orchestration
# ---------------------------------------------------------------------------


def echo_exact(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    sock = lib.connect_socket(host, port, timeout)
    try:
        sock.sendall(payload)
        return lib.recv_exact(sock, len(payload), timeout)
    finally:
        sock.close()


def precheck(host: str, port: int, seed: int) -> dict:
    payload = lib.deterministic_payload(1024 * 1024, seed + 99)
    started = time.monotonic()
    received = echo_exact(host, port, payload, timeout=20.0)
    elapsed = time.monotonic() - started
    if received != payload:
        raise AssertionError(
            f"precheck byte mismatch: sent sha256={sha256_bytes(payload)} "
            f"received sha256={sha256_bytes(received)}")
    return {"bytes": len(payload), "sha256": sha256_bytes(payload),
            "elapsed_s": round(elapsed, 6)}


def environment_metadata() -> dict:
    cpu_model = ""
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.lower().startswith("model name"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = None
    try:
        gxx = subprocess.check_output(["g++", "--version"], text=True,
                                      stderr=subprocess.STDOUT).splitlines()[0]
    except (OSError, subprocess.CalledProcessError, IndexError):
        gxx = ""
    uname = os.uname()
    return {
        "timestamp_utc": utc_now(),
        "hostname": uname.nodename,
        "kernel": uname.release,
        "machine": uname.machine,
        "cpu_model": cpu_model,
        "cpu_count": os.cpu_count(),
        "loadavg_1_5_15": [load1, load5, load15],
        "python": sys.version,
        "gxx_version": gxx,
        "platform": platform.platform(),
    }


def haproxy_metadata(binary: str) -> dict:
    info = {"path": binary, "sha256": sha256_file(binary)}
    try:
        info["version"] = subprocess.check_output([binary, "-v"], text=True,
                                                  stderr=subprocess.STDOUT).splitlines()[0]
    except (OSError, subprocess.CalledProcessError, IndexError):
        info["version"] = ""
    return info


def engine_provenance() -> dict:
    ready, reason = lib.engine_sources_ready()
    if not ready:
        return {"ready": False, "reason": reason}
    marker_path = Path(reason)
    out: dict = {"ready": True, "marker": str(marker_path),
                 "marker_sha256": sha256_file(str(marker_path))}
    try:
        document = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    out.update({
        "manifest_document": document,
        "status": document.get("status"),
        "note": document.get("note"),
        "sha256": document.get("sha256"),
        "engine_sources": document.get("engine_sources"),
    })
    status_upper = str(document.get("status") or "").upper()
    out["provisional"] = any(token in status_upper for token in
                             ("PROVISIONAL", "CHECKPOINT", "TEST ONLY", "NOT FINAL"))
    try:
        import readiness as readiness_module
        sources, problems = readiness_module.load(marker_path)
        out["resolved_sources"] = sources
        out["problems"] = problems
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        out["problems"] = [f"readiness load failed: {type(exc).__name__}: {exc}"]
    header = TESTS_DIR.parent / "include" / "tcp_proxy.h"
    out["header_path"] = str(header)
    out["header_sha256"] = sha256_file(str(header))
    return out


def adversarial_suite_summary(path_text: str) -> dict:
    path = Path(path_text)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"available": False, "path": str(path)}
    failures = [
        {"scenario": row.get("scenario"), "status": row.get("status"),
         "detail": row.get("detail")}
        for row in document.get("scenarios", [])
        if row.get("status") != "PASS"
    ]
    return {
        "available": True,
        "path": str(path),
        "timestamp_utc": document.get("timestamp_utc"),
        "counts": document.get("counts"),
        "harness_sha256": document.get("harness_sha256"),
        "harness_header_sha256": document.get("harness_header_sha256"),
        "readiness": document.get("readiness"),
        "failures": failures,
    }


def run_mode(mode: str, args, backend: BackendProcess,
             results_dir: Path) -> dict:
    started = time.monotonic()
    state: dict = {
        "mode": mode,
        "status": "not_run",
        "started_utc": utc_now(),
    }
    setup = None
    pids: dict[str, int | None] = {"backend": backend.pid}
    target_host, target_port = backend.host, backend.port
    cleanup = None

    try:
        if mode == "direct":
            setup = "direct"
        elif mode == "native":
            ready, reason = lib.engine_sources_ready()
            state["readiness"] = reason
            if not ready:
                state.update({"status": "skipped", "reason": reason})
                return state
            if not lib.harness_available(args.harness):
                state.update({
                    "status": "skipped",
                    "reason": f"harness not built/executable: {args.harness}",
                })
                return state
            native = NativeEngineProcess(args.harness, backend.host, backend.port,
                                         args.workers, results_dir)
            try:
                native.start()
            except BaseException as exc:  # noqa: BLE001
                state.update({"status": "error",
                              "reason": f"native start failed: {type(exc).__name__}: {exc}"})
                native.stop()
                return state
            setup = native
            target_host, target_port = native.host, native.port
            pids["proxy"] = native.pid
            state["proxy_kind"] = "native-engine-harness"
            state["engine_settings"] = native.config["settings"]
            state["harness"] = {
                "path": args.harness,
                "sha256": sha256_file(args.harness),
                "command": [args.harness],
                "control_protocol": "newline JSON on stdin/stdout",
                "start_request": {
                    "op": "start",
                    "config": dict(native.config),
                    "backend_fixtures": list(
                        getattr(native.config, "backend_fixtures", [])),
                },
            }
            cleanup = native.stop
        elif mode == "haproxy":
            if not os.path.isfile(args.haproxy):
                state.update({"status": "skipped",
                              "reason": f"HAProxy binary not available: {args.haproxy}"})
                return state
            haproxy = HAProxyProcess(args.haproxy, backend.host, backend.port,
                                     args.workers, results_dir)
            try:
                haproxy.start()
            except BaseException as exc:  # noqa: BLE001
                state.update({"status": "error",
                              "reason": f"HAProxy start failed: {type(exc).__name__}: {exc}"})
                haproxy.stop()
                return state
            setup = haproxy
            target_host, target_port = haproxy.host, haproxy.port
            pids["proxy"] = haproxy.pid
            state["proxy_kind"] = "haproxy"
            state["haproxy"] = haproxy_metadata(args.haproxy)
            state["haproxy"].update({
                "nbthread": args.workers,
                "config_path": str(haproxy.config_path),
                "config": haproxy.config_path.read_text(encoding="utf-8"),
                "command": haproxy.command,
            })
            cleanup = haproxy.stop
        else:
            state.update({"status": "skipped", "reason": f"unknown mode {mode}"})
            return state

        state["target"] = {"host": target_host, "port": target_port}
        state["start_command"] = getattr(setup, "command", None) if setup not in (None, "direct") else None
        state["backend_connections_before"] = backend.live_stats(wait=True).get("connections_total")
        mode_started = time.monotonic()
        mode_process_before = capture_processes(pids)

        # Byte-forwarding gate before any benchmark claims.
        try:
            state["precheck"] = precheck(target_host, target_port, args.seed)
        except BaseException as exc:  # noqa: BLE001
            state.update({
                "status": "error",
                "reason": f"byte-forwarding precheck failed: {type(exc).__name__}: {exc}",
            })
            return state

        latency_payload = lib.deterministic_payload(64, args.seed + 1)
        connection_payload = lib.deterministic_payload(args.conn_payload, args.seed + 2)
        throughput_payload = lib.deterministic_payload(args.payload, args.seed + 3)

        state["phases"] = {}
        state["phases"]["latency"] = run_phase(
            "latency", pids,
            lambda: measure_latency(target_host, target_port, args.concurrency,
                                    args.warmup, args.latency_samples,
                                    latency_payload))
        state["phases"]["connections"] = run_phase(
            "connections", pids,
            lambda: measure_connections(target_host, target_port, args.concurrency,
                                        args.duration, connection_payload))
        state["phases"]["throughput"] = run_phase(
            "throughput", pids,
            lambda: measure_throughput(target_host, target_port, args.concurrency,
                                       args.duration, throughput_payload))
        state["phases"]["idle"] = (
            {"name": "idle", "status": "completed", "connections": 0, "skipped": True}
            if args.skip_idle else
            run_phase(
                "idle", pids,
                lambda: measure_idle(target_host, target_port,
                                     args.idle_connections, pids,
                                     args.idle_interval)))

        failed_phases = [name for name, phase in state["phases"].items()
                         if phase.get("status") != "completed"]
        if failed_phases:
            state["status"] = "error"
            state["reason"] = f"benchmark phase failed: {', '.join(failed_phases)}"
            return state

        backend_after = backend.live_stats(wait=True)
        state["backend_connections_after"] = backend_after.get("connections_total")
        state["backend_connections_delta"] = (
            (backend_after.get("connections_total") or 0) -
            (state.get("backend_connections_before") or 0)
            if state.get("backend_connections_before") is not None else None)
        state["status"] = "completed"
        if mode == "native":
            lib.wait_for(lambda: setup.snapshot().get("active_connections") == 0,
                         2.0, interval=0.05)
            state["engine_snapshot"] = setup.snapshot()
        mode_elapsed = time.monotonic() - mode_started
        state["process"] = process_deltas(mode_process_before, capture_processes(pids),
                                          mode_elapsed, lib.clock_ticks_per_second())
        state["process_elapsed_s"] = round(mode_elapsed, 6)
        state["elapsed_s"] = round(time.monotonic() - started, 3)
        return state
    finally:
        if cleanup is not None:
            try:
                cleanup()
            except BaseException:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def status_label(state: dict) -> str:
    return f"{state.get('status', 'unknown')}" + (
        f" ({state['reason']})" if state.get("reason") else "")


def build_markdown(report: dict) -> str:
    env = report["environment"]
    workload = report["workload"]
    modes = report["modes"]
    lines = [
        "# Native TCP proxy engine benchmark",
        "",
        f"Date: {report['date']}. Status: local loopback measurement; not a deployment claim.",
        "",
        f"Environment: `{env['hostname']}`, {env['kernel']}, {env['machine']}, "
        f"{env['cpu_count']} CPUs, `{env['cpu_model']}`. Load average at start: "
        f"{env['loadavg_1_5_15']}. Compiler: `{env['gxx_version']}`. "
        f"Python: `{env['python'].splitlines()[0]}`.",
        "",
        "## Workload",
        "",
        "| Parameter | Value |",
        "|---|---|",
        f"| Mode order | {', '.join(report['mode_order'])} |",
        f"| Backend | task-owned selector echo process, PID {report['backend']['pid']}, "
        f"127.0.0.1:{report['backend']['port']} |",
        f"| Client concurrency | {workload['concurrency']} |",
        f"| Engine/HAProxy worker threads | {workload['workers']} |",
        f"| RTT payload / warmup / samples per connection | {workload['latency_payload_bytes']} B / "
        f"{workload['warmup_per_connection']} / {workload['latency_samples_per_connection']} |",
        f"| Connections/s payload | {workload['connection_payload_bytes']} B |",
        f"| Throughput payload / duration | {workload['throughput_payload_bytes']} B / "
        f"{workload['duration_s']} s |",
        f"| Idle connections measured | {workload['idle_connections']} |",
        "",
        "Each connection/s sample is a completed connect + send + exact echo receive + close "
        "transaction. Throughput verifies every echoed payload chunk byte-for-byte; rates are "
        "application payload bytes per second, separately for client→server and server→client.",
        "",
        "Scope of native mode: the native target is the **standalone `engine_harness` "
        "process** linked from the reviewed Engine sources. Its proxy CPU, RSS, fd and "
        "thread figures describe only that harness process. They exclude ProxySQL core, "
        "Admin, SQLite, metrics and plugin/daemon integration work, so they are not a "
        "full-daemon or full-plugin footprint.",
        "",
        "## Results",
        "",
        "| Mode | Status | RTT p50 / p95 / p99 ms | Connections/s | MiB/s c→s | MiB/s s→c | "
        "Proxy CPU % (native = harness only) | Backend CPU % | "
        "Proxy idle CPU % (native = harness only) | Proxy RSS idle Δ KiB (native = harness only) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for mode in report["mode_order"]:
        state = modes.get(mode, {"status": "not_requested"})
        if state.get("status") != "completed":
            lines.append(f"| {mode} | {status_label(state)} | – | – | – | – | – | – | – | – |")
            continue
        phases = state["phases"]
        latency = phases["latency"].get("summary", {})
        conns = phases["connections"]
        throughput = phases["throughput"]
        process = state.get("process", {})
        proxy_cpu = process.get("proxy", {}).get("cpu_percent") if "proxy" in process else None
        backend_cpu = process.get("backend", {}).get("cpu_percent")
        idle = phases.get("idle", {})
        idle_delta = (idle.get("delta") or {}).get("proxy", {}).get("rss_kb_delta")
        idle_proxy_cpu = (((idle.get("quiescent") or {}).get("process") or {})
                          .get("proxy", {}).get("cpu_percent"))
        lines.append(
            f"| {mode} | completed | "
            f"{latency.get('p50_ms', float('nan')):.3f} / "
            f"{latency.get('p95_ms', float('nan')):.3f} / "
            f"{latency.get('p99_ms', float('nan')):.3f} | "
            f"{conns.get('connections_per_s', float('nan')):.1f} | "
            f"{throughput.get('client_to_server_mib_per_s', float('nan')):.2f} | "
            f"{throughput.get('server_to_client_mib_per_s', float('nan')):.2f} | "
            f"{'null' if proxy_cpu is None else f'{proxy_cpu:.1f}'} | "
            f"{'null' if backend_cpu is None else f'{backend_cpu:.1f}'} | "
            f"{'null' if idle_proxy_cpu is None else f'{idle_proxy_cpu:.1f}'} | "
            f"{'null' if idle_delta is None else idle_delta} |"
        )
    lines += [
        "",
        "Proxy/backend CPU percentages in the first CPU columns are process tick deltas over "
        "the mode's whole monotonic elapsed window (including bounded client-thread joins), "
        "not sums of short phase percentages. Direct mode has no proxy PID, so its proxy "
        "CPU/RSS fields are `null`; backend CPU is still measured. Native proxy CPU/RSS/fd/"
        "thread values cover only the standalone Engine harness, not a full ProxySQL daemon. "
        "The idle CPU column is a "
        "separate quiescent sample taken over the configured interval only after the idle "
        "flows were established and settled; establishment CPU is reported separately in the "
        "mode details. Idle RSS/fd/thread deltas compare the settled idle state with the "
        "pre-connection baseline.",
        "",
        "## Mode details",
        "",
    ]
    for mode in report["mode_order"]:
        state = modes.get(mode, {"status": "not_requested"})
        lines.append(f"### {mode}: {state.get('status')}")
        if state.get("reason"):
            lines.append("")
            lines.append(f"Reason: {state['reason']}")
        if state.get("status") == "completed":
            phases = state["phases"]
            lines.append("")
            lines.append(
                f"- Precheck: 1 MiB exact echo in {state['precheck']['elapsed_s']} s, "
                f"sha256 `{state['precheck']['sha256']}`.")
            lines.append(
                f"- RTT samples: {phases['latency']['summary']['count']} raw samples.")
            lines.append(
                f"- Connections/s: {phases['connections']['connections_completed']} completed "
                f"transactions in {phases['connections']['duration_s']} s.")
            lines.append(
                f"- Throughput: {phases['throughput']['bytes_client_to_server']} c→s bytes and "
                f"{phases['throughput']['bytes_server_to_client']} s→c bytes, "
                f"{phases['throughput']['transactions']} verified echo transactions.")
            idle = phases.get("idle", {})
            if idle.get("skipped"):
                lines.append("- Idle resources: skipped by --skip-idle.")
            else:
                quiescent = idle.get("quiescent", {})
                q_process = quiescent.get("process", {})
                establishment = idle.get("establishment", {})
                lines.append(
                    f"- Idle resources: {idle.get('connections')} connections; "
                    f"settle {idle.get('settle_s')} s.")
                lines.append(
                    f"  - Establishment (connect + echo + settle, {establishment.get('elapsed_s')} s) "
                    f"process CPU: proxy="
                    f"{(establishment.get('process', {}).get('proxy') or {}).get('cpu_percent')}, "
                    f"backend="
                    f"{(establishment.get('process', {}).get('backend') or {}).get('cpu_percent')}.")
                lines.append(
                    f"  - Quiescent {quiescent.get('interval_s')} s "
                    f"(tick precision {quiescent.get('cpu_tick_precision_ms')} ms) process CPU: "
                    f"proxy={(q_process.get('proxy') or {}).get('cpu_percent')}, "
                    f"backend={(q_process.get('backend') or {}).get('cpu_percent')}.")
                lines.append(
                    f"  - Baseline -> settled idle deltas: proxy "
                    f"{idle.get('delta', {}).get('proxy')}, backend "
                    f"{idle.get('delta', {}).get('backend')}.")
                lines.append(
                    "  - Socket options: TCP_NODELAY on benchmark client sockets and accepted "
                    "Python backend sockets.")
            if mode == "native" and state.get("engine_settings"):
                lines.append(
                    f"- Engine settings: worker_threads={state['engine_settings']['worker_threads']}, "
                    f"buffer_size={state['engine_settings']['buffer_size']}.")
                lines.append(
                    "- Native target scope: standalone Engine harness only; proxy CPU/RSS/fd/"
                    "thread values exclude ProxySQL core, Admin, SQLite, metrics and "
                    "plugin/daemon integration footprint.")
            if mode == "haproxy" and state.get("haproxy"):
                lines.append(
                    f"- HAProxy: `{state['haproxy'].get('version', '')}` "
                    f"sha256 `{state['haproxy'].get('sha256', '')}`, "
                    f"nbthread={state['haproxy'].get('nbthread')}.")
        lines.append("")
    provenance = report.get("engine_provenance", {})
    suite = report.get("adversarial_suite", {})
    lines += ["## Engine source provenance and test status", ""]
    if provenance.get("ready"):
        lines.append(f"- Readiness marker: `{provenance.get('marker')}` "
                     f"(manifest sha256 `{provenance.get('marker_sha256')}`).")
        lines.append(f"- Marker status: {provenance.get('status')}.")
        if provenance.get("note"):
            lines.append(f"- Marker note: {provenance['note']}")
        lines.append(f"- Frozen header sha256: `{provenance.get('header_sha256')}`.")
        sources = provenance.get("resolved_sources") or []
        if sources:
            lines.append("- Resolved source digests at run time:")
            for source in sources:
                lines.append(f"  - `{source.get('path')}` `{source.get('sha256')}`")
        else:
            for source in provenance.get("engine_sources") or []:
                lines.append(f"  - `{source.get('path')}` `{source.get('sha256')}`")
        for problem in provenance.get("problems") or []:
            lines.append(f"- Readiness problem: {problem}")
    else:
        lines.append(f"- Engine sources not approved: {provenance.get('reason')}")
    if suite.get("available"):
        counts = suite.get("counts", {})
        lines.append(
            f"- Adversarial suite at `{suite.get('path')}`: "
            f"{counts.get('PASS', 0)} PASS, {counts.get('FAIL', 0)} FAIL, "
            f"{counts.get('BLOCKED', 0)} BLOCKED, "
            f"{counts.get('INCONCLUSIVE', 0)} INCONCLUSIVE "
            f"({sum(counts.values()) if counts else 0} scenarios).")
        for failure in suite.get("failures", []):
            lines.append(
                f"- Suite {failure.get('status')} {failure.get('scenario')}: "
                f"{str(failure.get('detail', ''))[:400]}")
        if counts.get("FAIL"):
            lines.append(
                "- This benchmark is provisional because the adversarial suite reports "
                "remaining failures against this Engine snapshot (pending-connect deadline "
                "and/or half-close CPU spin); it covers steady-state echo forwarding only and "
                "must be rerun after repaired sources are supplied.")
        if provenance.get("provisional"):
            lines.append(
                "- The readiness marker labels this source snapshot non-final "
                f"({provenance.get('status')}); these measurements are checkpoint evidence "
                "and not final integration approval.")
    else:
        lines.append("- Adversarial suite summary not available.")
    lines += ["", "## Caveats", "",
        "- Loopback only; no external network, production endpoint or load generator.",
        "- Python clients/backends are subject to interpreter scheduling and GIL limits. "
        "The client process and backend are separate, but Python-side cost can dominate at "
        "high rates and masks some engine detail.",
        "- Mode order is sequential and each mode starts a fresh measurement session; the "
        "backend process is shared but counters are sampled around each mode.",
        "- Percentiles are nearest-rank over raw per-connection RTT samples; they are not "
        "confidence intervals.",
        "- Idle CPU comes from /proc utime+stime clock ticks, whose precision is stated per "
        "sample (typically 10 ms); a one-second quiescent sample therefore has tick-quantized "
        "resolution. RSS deltas are single-sample VmRSS observations, not allocator accounting.",
        "- Native mode is skipped unless production Engine sources were approved and a harness "
        "was built; a failed exact-byte precheck blocks benchmark runs rather than producing "
        "fabricated numbers.",
        "- Native mode measures the standalone `engine_harness` process only. Its CPU/RSS/fd/"
        "thread numbers exclude ProxySQL core, Admin, SQLite, metrics and plugin/daemon "
        "integration and cannot describe a full daemon/plugin footprint.",
        "- Measurements describe this host and these short runs only.",
        "",
        f"Raw evidence: `{report['artifacts']['json']}`.",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modes", default="direct,haproxy",
                        help="comma-separated: direct,native,haproxy "
                             "(native is historical and needs its explicit flag)")
    parser.add_argument("--allow-historical-engine-only", action="store_true",
                        help="run the superseded standalone-Engine native mode")
    parser.add_argument("--harness", default=DEFAULT_HARNESS)
    parser.add_argument("--haproxy", default=DEFAULT_HAPROXY)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--warmup", type=int, default=20,
                        help="warmup RTTs per persistent connection")
    parser.add_argument("--latency-samples", type=int, default=300,
                        help="measured RTTs per persistent connection")
    parser.add_argument("--duration", type=float, default=2.0,
                        help="seconds for connections/s and throughput phases")
    parser.add_argument("--payload", type=int, default=65536,
                        help="throughput echo payload bytes")
    parser.add_argument("--conn-payload", type=int, default=64,
                        help="connections/s echo payload bytes")
    parser.add_argument("--idle-connections", type=int, default=8)
    parser.add_argument("--idle-interval", type=float, default=1.0,
                        help="quiescent CPU sampling seconds after idle flows settle")
    parser.add_argument("--suite-summary",
                        default="/tmp/native-tcp-proxy/test-correction-results/summary.json",
                        help="adversarial suite summary embedded in benchmark metadata")
    parser.add_argument("--seed", type=int, default=20261111)
    parser.add_argument("--output-json", default=str(DEFAULT_JSON))
    parser.add_argument("--output-md", default=str(DEFAULT_MD))
    parser.add_argument("--raw-dir", default=str(RAW_DIR))
    parser.add_argument("--skip-idle", action="store_true")
    args = parser.parse_args(argv)

    modes = [item.strip() for item in args.modes.split(",") if item.strip()]
    allowed = {"direct", "native", "haproxy"}
    unknown = [mode for mode in modes if mode not in allowed]
    if unknown:
        print(f"unknown mode(s): {unknown}", file=sys.stderr)
        return 2
    if not modes:
        print("no modes selected", file=sys.stderr)
        return 2
    if "native" in modes and not args.allow_historical_engine_only:
        print("native mode is historical engine-only evidence; use "
              "daemon_benchmark.py for four-table daemon measurements, or pass "
              "--allow-historical-engine-only explicitly", file=sys.stderr)
        return 2

    results_dir = Path(args.raw_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    environment = environment_metadata()
    backend = BackendProcess(results_dir)
    backend.start()
    report: dict = {
        "kind": "historical-native-engine-benchmark",
        "historical_engine_only": True,
        "schema_version": 1,
        "date": DATE,
        "generated_utc": utc_now(),
        "environment": environment,
        "engine_provenance": engine_provenance(),
        "adversarial_suite": adversarial_suite_summary(args.suite_summary),
        "mode_order": modes,
        "workload": {
            "concurrency": args.concurrency,
            "workers": args.workers,
            "warmup_per_connection": args.warmup,
            "latency_samples_per_connection": args.latency_samples,
            "latency_payload_bytes": 64,
            "connection_payload_bytes": args.conn_payload,
            "throughput_payload_bytes": args.payload,
            "duration_s": args.duration,
            "idle_connections": 0 if args.skip_idle else args.idle_connections,
            "idle_settle_s": 0.5,
            "idle_quiescent_interval_s": args.idle_interval,
            "seed": args.seed,
            "protocol": "echo: every received byte returned in order",
            "socket_options": {
                "client_tcp_nodelay": True,
                "accepted_backend_tcp_nodelay": True,
                "haproxy_tcp_nodelay_option": "not set (no such HAProxy TCP option); "
                                              "proxy sockets are TCP_NODELAY by default",
                "note": "client sockets and accepted Python backend sockets set "
                        "TCP_NODELAY explicitly in all modes",
            },
            "byte_direction": {
                "client_to_server": "application payload bytes sent by the client and echoed",
                "server_to_client": "application payload bytes returned to the client",
            },
        },
        "backend": {
            "pid": backend.pid,
            "host": backend.host,
            "port": backend.port,
            "started_utc": backend.started_utc,
            "command": backend.command,
            "script": str(TESTS_DIR / "bench_backend.py"),
            "script_sha256": sha256_file(str(TESTS_DIR / "bench_backend.py")),
        },
        "modes": {},
    }
    try:
        for mode in modes:
            print(f"[bench] {mode}", flush=True)
            state = run_mode(mode, args, backend, results_dir)
            report["modes"][mode] = state
            print(f"[bench] {mode}: {status_label(state)}", flush=True)
        for missing in allowed - set(modes):
            report["modes"].setdefault(missing, {
                "mode": missing,
                "status": "skipped",
                "reason": f"not requested (--modes {args.modes})",
            })
    finally:
        final_stats = backend.stop()
    report["backend"]["final_stats"] = final_stats
    report["artifacts"] = {"json": os.path.abspath(args.output_json),
                           "markdown": os.path.abspath(args.output_md),
                           "raw_dir": str(results_dir)}
    report["caveats"] = [
        "Local loopback short-run measurements only; not deployment claims.",
        "Python client/backend scheduling limits apply; backend is a separate process.",
        "Native mode target is a standalone engine_harness linked from the reviewed "
        "Engine sources; its CPU/RSS/fd/thread figures exclude ProxySQL core, Admin, "
        "SQLite, metrics and plugin/daemon integration and cannot describe full "
        "daemon/plugin footprint.",
        "HISTORICAL engine-only: this tool does not configure the four-table "
        "daemon or a real mapped hostgroup. Current evidence uses "
        "daemon_benchmark.py direct/mysql/pgsql/haproxy.",
        "Native mode requires approved production sources and a built harness.",
        "This run is provisional if the readiness marker or adversarial suite reports "
        "unresolved defects; benchmark phases cover steady-state echo only.",
        "Modes run sequentially; worker counts match where applicable.",
    ]
    json_path = Path(args.output_json)
    md_path = Path(args.output_md)
    write_json_atomic(json_path, report)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(build_markdown(report), encoding="utf-8")
    print(f"json: {json_path}")
    print(f"markdown: {md_path}")
    return 0 if any(state.get("status") == "completed"
                    for state in report["modes"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
