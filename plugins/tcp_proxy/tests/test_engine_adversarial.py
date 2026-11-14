#!/usr/bin/env python3
"""Independent adversarial real-socket suite for tcp_proxy::Engine.

The Engine is reached only through ``engine_harness`` (production sources linked
by Makefile.integration).  Python owns clients/backends, payloads, exact byte
and hash assertions, /proc observations and cleanup.  There is no relay here.

  * Snapshot exposes active totals only; pending/reserved state is observed via
    backend handshakes and /proc socket states.
  * A start barrier alone does not prove apply overlap; busy is required only
    for intervals that actually overlap.
  * GEN-04 stages the free listener before the occupied endpoint.
  * Backpressure is observed via a stalled nonblocking send, not a fixed sleep.
  * Backlog saturation is verified with SYN_SENT before pending-connect tests.
  * IPv6 V6ONLY is checked with a wildcard [::] listener.
  * Post-stop rebind probes use SO_REUSEADDR.

Statuses: PASS, FAIL, BLOCKED (environment), INCONCLUSIVE (test condition not
observable).  Failures are recorded with the scenario's reproduction command;
the runner continues independent scenarios.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import signal
import socket
import ssl
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import tcp_proxy_testlib as lib

HARNESS_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "engine_harness")
RESULTS_DEFAULT = "/tmp/native-tcp-proxy/test-results"

SCENARIOS: dict[str, dict] = {}

class Blocked(Exception):
    """Required environment condition could not be created."""


class Inconclusive(Exception):
    """Condition exists but the required observation is not reliable."""


def scenario(sid: str, description: str = ""):
    def decorator(func):
        SCENARIOS[sid] = {"id": sid, "description": description or func.__doc__ or "",
                          "func": func}
        return func
    return decorator


class Context:
    def __init__(self, harness_path: str, results_dir: Path, seed: int,
                 verbose: bool = False, scenario_id: str = ""):
        self.harness_path = harness_path
        self.results_dir = results_dir
        self.seed = seed
        self.verbose = verbose
        self.scenario_id = scenario_id

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"    {message}", flush=True)

    @contextmanager
    def harness(self, label: str):
        stderr_path = self.results_dir / f"{self.scenario_id}-{label}-harness.stderr"
        client = lib.HarnessClient(self.harness_path, stderr_path=str(stderr_path))
        try:
            client.ping(timeout=5.0)
            yield client
        finally:
            client.close()

    @contextmanager
    def backend(self, **kwargs):
        backend = lib.Backend(**kwargs)
        try:
            yield backend
        finally:
            backend.stop()

    @contextmanager
    def blackhole(self, **kwargs):
        blackhole = lib.Blackhole(**kwargs)
        try:
            yield blackhole
        finally:
            blackhole.stop()

    @contextmanager
    def squatter(self, **kwargs):
        squatter = lib.Squatter(**kwargs)
        try:
            yield squatter
        finally:
            squatter.close()


# ---------------------------------------------------------------------------
# Assertion / flow helpers
# ---------------------------------------------------------------------------


def require(condition, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_concurrent_apply(h: lib.HarnessClient, response: dict,
                           candidates: list[dict], generation_before: int) -> dict:
    """Validate apply_concurrent by observable contract, not thread timing.

    Wrapper intervals prove nothing about Engine lock overlap: both calls may
    serialize legitimately.  Require consistent success/busy/error accounting,
    generation advancement per success, and a complete winning configuration.
    """
    require(response.get("ok"), f"apply_concurrent failed: {response.get('error')}")
    results = response.get("results")
    require(isinstance(results, list) and len(results) == len(candidates),
            f"expected {len(candidates)} apply results, saw {results!r}")
    successes = [row for row in results if row.get("ok")]
    busy = [row for row in results if not row.get("ok") and row.get("busy")]
    other = [row for row in results if not row.get("ok") and not row.get("busy")]
    require(response.get("successes") == len(successes),
            f"successes count {response.get('successes')} != {len(successes)}")
    require(response.get("busy_rejections") == len(busy),
            f"busy count {response.get('busy_rejections')} != {len(busy)}")
    require(len(successes) + len(busy) + len(other) == len(candidates),
            "apply outcome counts do not cover every contender")
    require(not other,
            f"unexpected concurrent apply failure(s): "
            f"{[row.get('error') for row in other]}")
    require(successes, "no concurrent apply succeeded")
    after = snapshot(h)["generation"]
    require(after == generation_before + len(successes),
            f"generation advanced {after - generation_before} for "
            f"{len(successes)} successful applies (before={generation_before}, "
            f"after={after})")
    final = h.config(timeout=10.0)["config"]
    winners = [lib.product_config(candidates[int(row["index"])]) for row in successes]
    require(any(final == candidate for candidate in winners),
            "final product Config is not a complete successful candidate; "
            f"hostgroup_comment={final.get('hostgroups', [{}])[0].get('comment')!r}")
    return {
        "successes": len(successes),
        "busy": len(busy),
        "overlapped": bool(response.get("overlapped")),
        "generation": after,
    }


def start_ok(h: lib.HarnessClient, cfg: dict, timeout: float = 15.0) -> dict:
    response = h.start(cfg, timeout=timeout)
    require(response.get("ok"), f"start failed: {response.get('error', '')}")
    return response


def apply_ok(h: lib.HarnessClient, cfg: dict, timeout: float = 15.0) -> dict:
    response = h.apply(cfg, timeout=timeout)
    require(response.get("ok"), f"apply failed: {response.get('error', '')}")
    return response


def apply_fail(h: lib.HarnessClient, cfg: dict, timeout: float = 15.0) -> dict:
    response = h.apply(cfg, timeout=timeout)
    require(not response.get("ok"), "apply unexpectedly succeeded")
    require(bool(response.get("error")), "failed apply returned an empty error")
    return response


def snapshot(h: lib.HarnessClient, timeout: float = 5.0) -> dict:
    return h.snapshot(timeout=timeout)


def wait_snapshot(h: lib.HarnessClient, predicate, timeout: float) -> dict:
    try:
        return lib.wait_snapshot(h, predicate, timeout)
    except lib.SnapshotWaitTimeout as exc:
        raise AssertionError(str(exc)) from None


def wait_active(h: lib.HarnessClient, expected: int, timeout: float = 5.0) -> dict:
    return wait_snapshot(h, lambda s: s["active_connections"] == expected, timeout)


def observation(h: lib.HarnessClient, timeout: float = 5.0) -> dict:
    """Explicit combined product Snapshot + TEST provider observation."""
    return h.observation(timeout=timeout)


def wait_observation(h: lib.HarnessClient, predicate, timeout: float) -> dict:
    deadline = lib.Deadline(timeout)
    last = None
    while not deadline.expired():
        last = observation(h, timeout=min(2.0, max(0.2, deadline.remaining())))
        if predicate(last):
            return last
        time.sleep(0.02)
    last = observation(h, timeout=min(2.0, max(0.2, deadline.remaining())))
    require(predicate(last), f"combined observation predicate not satisfied; last={last}")
    return last


def wait_server_health(h: lib.HarnessClient, server_id: int, expected: str,
                       timeout: float = 5.0) -> dict:
    # TEST provider health projection only; not a core HGM assertion.
    def predicate(observed):
        row = lib.provider_server(observed, server_id)
        return row is not None and row.get("health_status") == expected
    return wait_observation(h, predicate, timeout)


def server_row(observed: dict, server_id: int) -> dict:
    row = lib.provider_server(observed, server_id)
    require(row is not None, f"test fixture server {server_id} missing from provider snapshot")
    return row


def listener_row(snap: dict, listener_id: int) -> dict:
    row = lib.find_row(snap.get("listeners", []), "listener_id", listener_id)
    require(row is not None, f"listener {listener_id} missing from snapshot")
    return row


def effective_settings(h: lib.HarnessClient) -> dict:
    return h.config(timeout=10.0)["config"]["settings"]


def require_effective_setting(h: lib.HarnessClient, key: str, expected: int) -> None:
    actual = effective_settings(h).get(key)
    require(actual == expected,
            f"effective config {key}={actual!r}; expected {expected!r} "
            "(a listener override would be ignored by the frozen API)")


def open_flow(host: str, port: int, size: int = 32, seed: int = 1,
              timeout: float = 5.0) -> socket.socket:
    sock = lib.connect_socket(host, port, timeout)
    payload = lib.deterministic_payload(size, seed)
    sock.sendall(payload)
    received = lib.recv_exact(sock, len(payload), timeout)
    require(received == payload, "initial echo mismatch")
    return sock


def assert_echo(sock: socket.socket, payload: bytes, timeout: float = 5.0) -> None:
    sock.sendall(payload)
    received = lib.recv_exact(sock, len(payload), timeout)
    require(received == payload,
            f"echo mismatch: sent sha256={lib.sha256_bytes(payload)} "
            f"received sha256={lib.sha256_bytes(received)}")


def echo_once(host: str, port: int, payload: bytes, timeout: float = 5.0,
              source: str | None = None, shutdown_write: bool = False,
              read_eof: bool = False) -> bytes:
    sock = lib.connect_socket(host, port, timeout, source=source)
    try:
        sock.sendall(payload)
        if shutdown_write:
            sock.shutdown(socket.SHUT_WR)
        received = lib.recv_exact(sock, len(payload), timeout)
        if read_eof:
            sock.settimeout(timeout)
            extra = sock.recv(1)
            require(extra == b"", "expected EOF after echo")
        return received
    finally:
        sock.close()


def admission_probe(host: str, port: int, timeout: float = 2.0) -> str:
    """Return 'echo', 'closed', 'reset' or 'timeout' for a short probe."""
    sock = lib.connect_socket(host, port, timeout)
    try:
        sock.sendall(b"PROBE")
        sock.settimeout(timeout)
        try:
            data = sock.recv(5)
        except socket.timeout:
            return "timeout"
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return "reset"
        if not data:
            return "closed"
        return "echo" if data == b"PROBE" else "partial"
    finally:
        sock.close()


def close_quietly(*socks) -> None:
    for sock in socks:
        try:
            sock.close()
        except OSError:
            pass


def wait_backend_connections(backend: lib.Backend, count: int,
                             timeout: float = 5.0) -> None:
    require(backend.wait_connections(count, timeout),
            f"backend {backend.name} did not reach {count} connections "
            f"(saw {backend.connections_total})")


def wait_closed_with_evidence(client: socket.socket, timeout: float,
                              harness: lib.HarnessClient, label: str,
                              remote_port: int | None = None) -> float:
    """Wait for close; on timeout raise with snapshot and /proc evidence."""
    try:
        return lib.wait_until_closed(client, timeout)
    except TimeoutError:
        snap = snapshot(harness)
        sockets = [row for row in lib.proc_socket_states(harness.pid)
                   if remote_port is None or row["remote_port"] == remote_port]
        raise AssertionError(
            f"{label}: client still open after {timeout:.1f}s; "
            f"snapshot.active_connections={snap.get('active_connections')} "
            f"connect_errors={snap.get('connect_errors')} "
            f"engine_sockets={sockets}") from None
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        return 0.0


# ---------------------------------------------------------------------------
# CFG — validation and startup boundaries
# ---------------------------------------------------------------------------


@scenario("CFG-01", "structural/range/reference/address validation and rollback")
def cfg_01(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("cfg01") as h:
        port = lib.free_port()
        base = lib.simple_config(port, backend.port)
        start_ok(h, base)
        baseline = snapshot(h)
        fds0 = lib.proc_fd_count(h.pid)
        threads0 = lib.proc_thread_count(h.pid)

        def clone():
            return copy.deepcopy(base)

        bad: list[tuple[str, dict]] = []

        def add(name, cfg):
            bad.append((name, cfg))

        cfg = clone(); cfg["settings"]["worker_threads"] = 0; add("worker_threads=0", cfg)
        cfg = clone(); cfg["settings"]["worker_threads"] = 65; add("worker_threads=65", cfg)
        cfg = clone(); cfg["settings"]["max_connections"] = 0; add("max_connections=0", cfg)
        cfg = clone(); cfg["settings"]["max_connections"] = 1000001; add("max_connections=above", cfg)
        cfg = clone(); cfg["settings"]["buffer_size"] = 1023; add("buffer_size=1023", cfg)
        cfg = clone(); cfg["settings"]["buffer_size"] = 1048577; add("buffer_size=above", cfg)
        cfg = clone(); cfg["settings"]["shutdown_timeout_ms"] = -1; add("shutdown=-1", cfg)
        cfg = clone(); cfg["settings"]["shutdown_timeout_ms"] = 60001; add("shutdown=above", cfg)
        cfg = clone(); cfg["settings"]["half_close_timeout_ms"] = 0; add("half_close=0", cfg)
        cfg = clone(); cfg["settings"]["half_close_timeout_ms"] = 3600001; add("half_close=above", cfg)

        cfg = clone(); cfg["hostgroups"][0]["hostgroup_id"] = -1; add("hostgroup id negative", cfg)
        cfg = clone(); cfg["hostgroups"][0]["hostgroup_id"] = 2147483648; add("hostgroup id above int32", cfg)
        cfg = clone(); cfg["hostgroups"][0]["source_protocol"] = ""; add("source protocol empty", cfg)
        cfg = clone(); cfg["hostgroups"][0]["source_protocol"] = "ORACLE"; add("source protocol invalid", cfg)
        cfg = clone(); cfg["hostgroups"][0]["source_protocol"] = "mysql"; add("source protocol lowercase", cfg)
        cfg = clone(); cfg["hostgroups"][0]["source_hostgroup"] = -1; add("source hostgroup negative", cfg)
        cfg = clone(); cfg["hostgroups"][0]["source_hostgroup"] = 2147483648; add("source hostgroup above int32", cfg)
        cfg = clone(); cfg["hostgroups"][0]["comment"] = "\x00bad"; add("hostgroup embedded NUL", cfg)
        cfg = clone(); cfg["hostgroups"][0]["balance"] = "roundrobin"; add("obsolete hostgroup balance", cfg)
        cfg = clone(); cfg["hostgroups"][0]["health_check_interval_ms"] = 0; add("obsolete hostgroup health", cfg)
        cfg = clone(); cfg["servers"] = ["outside-product-config"]; add("obsolete config servers key", cfg)
        cfg = clone(); cfg["hostgroup_mappings"] = []; add("obsolete config mappings key", cfg)
        cfg = clone(); cfg["backend_fixtures"] = []; add("fixtures embedded in config", cfg)

        cfg = clone(); cfg.backend_fixtures[0]["weight"] = 0; add("weight 0", cfg)
        cfg = clone(); cfg.backend_fixtures[0]["weight"] = 1001; add("weight above", cfg)
        cfg = clone(); cfg.backend_fixtures[0]["max_connections"] = 0; add("server max 0", cfg)
        cfg = clone(); cfg.backend_fixtures[0]["max_connections"] = 1000001; add("server max above", cfg)
        cfg = clone(); cfg.backend_fixtures[0]["status"] = "MAYBE"; add("server status invalid", cfg)
        cfg = clone(); cfg.backend_fixtures[0]["port"] = 0; add("server port 0", cfg)
        cfg = clone(); cfg.backend_fixtures[0]["port"] = 65536; add("server port above", cfg)
        cfg = clone(); cfg.backend_fixtures[0]["hostname"] = "localhost"; add("server nonnumeric", cfg)
        cfg = clone(); cfg.backend_fixtures[0]["hostname"] = "127.0.0.1\x00evil"; add("server embedded NUL", cfg)
        cfg = clone(); cfg.backend_fixtures[0]["hostgroup_id"] = 99; add("server dangling hg", cfg)

        cfg = clone(); cfg["listeners"][0]["listener_id"] = -1; add("listener id negative", cfg)
        cfg = clone(); cfg["listeners"][0]["listener_id"] = 2147483648; add("listener id above int32", cfg)
        cfg = clone(); cfg["listeners"][0]["active"] = 2; add("listener active=2", cfg)
        cfg = clone(); cfg["listeners"][0]["bind_port"] = 0; add("listener port 0", cfg)
        cfg = clone(); cfg["listeners"][0]["bind_port"] = 65536; add("listener port above", cfg)
        cfg = clone(); cfg["listeners"][0]["bind_address"] = "not-an-ip"; add("listener nonnumeric", cfg)
        cfg = clone(); cfg["listeners"][0]["bind_address"] = "::ffff:127.0.0.1"; add("mapped IPv6", cfg)
        cfg = clone(); cfg["listeners"][0]["default_hostgroup"] = 99; add("listener dangling hg", cfg)
        cfg = clone(); cfg["listeners"][0]["max_connections"] = 0; add("listener max 0", cfg)
        cfg = clone(); cfg["listeners"][0]["connect_timeout_ms"] = 0; add("connect timeout 0", cfg)
        cfg = clone(); cfg["listeners"][0]["connect_timeout_ms"] = 60001; add("connect timeout above", cfg)
        cfg = clone(); cfg["listeners"][0]["idle_timeout_ms"] = -1; add("idle timeout -1", cfg)
        cfg = clone(); cfg["listeners"][0]["idle_timeout_ms"] = 86400001; add("idle timeout above", cfg)
        cfg = clone(); cfg["listeners"][0]["max_connect_attempts"] = 0; add("attempts 0", cfg)
        cfg = clone(); cfg["listeners"][0]["max_connect_attempts"] = 17; add("attempts above", cfg)

        cfg = clone(); cfg["rules"] = [lib.rule(-1, action="ROUTE", destination_hostgroup=1)]; add("rule id negative", cfg)
        cfg = clone(); cfg["rules"] = [lib.rule(2147483648, action="ROUTE", destination_hostgroup=1)]; add("rule id above int32", cfg)
        cfg = clone(); cfg["rules"] = [lib.rule(1, action="BOUNCE", destination_hostgroup=1)]; add("rule action invalid", cfg)
        cfg = clone(); cfg["rules"] = [lib.rule(1, action="ROUTE")]; add("ROUTE without destination", cfg)
        cfg = clone(); cfg["rules"] = [lib.rule(1, action="REJECT", destination_hostgroup=1)]; add("REJECT with destination", cfg)
        cfg = clone(); cfg["rules"] = [lib.rule(1, action="ROUTE", destination_hostgroup=99)]; add("rule dangling destination", cfg)
        cfg = clone(); cfg["rules"] = [lib.rule(1, listener_id=99, action="ROUTE", destination_hostgroup=1)]; add("rule dangling listener", cfg)
        cfg = clone(); cfg["rules"] = [lib.rule(1, source_cidr="127.0.0.1/33", action="ROUTE", destination_hostgroup=1)]; add("invalid CIDR", cfg)
        cfg = clone(); cfg["rules"] = [lib.rule(1, source_cidr="::ffff:127.0.0.1/128", action="ROUTE", destination_hostgroup=1)]; add("mapped CIDR", cfg)
        cfg = clone(); cfg["rules"] = [lib.rule(1, active=0, listener_id=99, action="ROUTE", destination_hostgroup=99)]; add("inactive dangling rule", cfg)

        cfg = clone(); cfg["hostgroups"].append(copy.deepcopy(cfg["hostgroups"][0])); add("duplicate hostgroup id", cfg)
        cfg = clone(); cfg.backend_fixtures.append(copy.deepcopy(cfg.backend_fixtures[0])); add("duplicate server id", cfg)
        cfg = clone(); cfg["listeners"].append(copy.deepcopy(cfg["listeners"][0])); add("duplicate listener id", cfg)
        cfg = clone(); cfg["rules"] = [lib.rule(1, destination_hostgroup=1), lib.rule(1, destination_hostgroup=1)]; add("duplicate rule id", cfg)

        cfg = clone()
        cfg["listeners"].append(lib.listener(2, port, 1, bind_address="0.0.0.0"))
        add("overlapping 0.0.0.0 and 127.0.0.1", cfg)
        cfg = clone()
        cfg["listeners"].append(lib.listener(2, port, 1, bind_address="0.0.0.0"))
        cfg["listeners"][0]["bind_address"] = "0.0.0.0"
        add("duplicate wildcard", cfg)

        invalid_errors = {}
        for name, candidate in bad:
            response = h.validate(candidate)
            require(response.get("ok"), f"validate request failed for {name}")
            require(not response.get("valid"),
                    f"candidate unexpectedly valid: {name}")
            require(bool(response.get("error")),
                    f"invalid candidate returned empty error: {name}")
            invalid_errors[name] = response["error"]

        # Apply representative invalid candidates and verify no publication.
        for name, candidate in bad[:6] + bad[-4:]:
            response = h.apply(candidate)
            require(not response.get("ok"), f"invalid apply succeeded: {name}")
            current = snapshot(h)
            require(current["generation"] == baseline["generation"],
                    f"generation changed after invalid apply: {name}")
            require(current["running"] is True, "engine stopped after invalid apply")
            require(len(current["listeners"]) == 1 and
                    current["listeners"][0]["listener_id"] == 1,
                    f"listener rows changed after invalid apply: {name}")
            require(bool(current.get("last_error")),
                    f"last_error empty after invalid apply: {name}")
            require(lib.proc_fd_count(h.pid) == fds0,
                    f"fd count changed after invalid apply: {name}")

        # Distinguish harness JSON/obsolete-key rejection from actual Engine
        # product validation: only the latter may change Engine::last_error.
        parser_name = "obsolete config servers key"
        parser_candidate = dict(bad)[parser_name]
        engine_error_before = snapshot(h)["last_error"]
        parser_response = h.apply(parser_candidate)
        require(not parser_response.get("ok"), "obsolete config key was accepted")
        require("obsolete/unsupported key" in parser_response.get("error", ""),
                f"parser error not descriptive: {parser_response.get('error')}")
        require(snapshot(h)["last_error"] == engine_error_before,
                "harness parser rejection was misreported as Engine last_error")
        engine_name = "worker_threads=0"
        engine_candidate = dict(bad)[engine_name]
        engine_response = h.apply(engine_candidate)
        require(not engine_response.get("ok"), "invalid product config accepted")
        require(snapshot(h)["last_error"] == engine_response.get("error"),
                "Engine::last_error does not match the actual Engine rejection")

        # Valid boundary values apply cleanly.
        valid = clone()
        valid["settings"].update({
            "worker_threads": 64, "max_connections": 1000000,
            "buffer_size": 1048576, "shutdown_timeout_ms": 60000,
            "half_close_timeout_ms": 3600000,
        })
        valid["hostgroups"][0].update({
            "hostgroup_id": 2147483647,
            "source_protocol": "PGSQL", "source_hostgroup": 2147483647,
            "comment": "valid boundary mapping",
        })
        valid["listeners"][0]["listener_id"] = 2147483647
        valid["listeners"][0]["default_hostgroup"] = 2147483647
        valid.backend_fixtures[0]["hostgroup_id"] = 2147483647
        # Server limits remain TEST fixture controls, not product Config fields.
        valid.backend_fixtures[0].update({"weight": 1000, "max_connections": 1000000})
        valid["listeners"][0].update({
            "max_connections": 1000000, "connect_timeout_ms": 60000,
            "idle_timeout_ms": 86400000, "max_connect_attempts": 16,
        })
        valid["rules"] = [lib.rule(2147483647, source_cidr="127.0.0.0/8",
                                   action="ROUTE", destination_hostgroup=2147483647)]
        response = h.validate(valid)
        require(response.get("valid"), f"valid boundary candidate rejected: {response.get('error')}")
        # worker_threads/buffer_size are startup-only while running: only validate here.

        require(lib.proc_thread_count(h.pid) == threads0,
                "thread count changed during validation-only work")
        return {
            "invalid_cases": len(bad),
            "invalid_errors_sample": dict(list(invalid_errors.items())[:5]),
            "baseline_generation": baseline["generation"],
        }


@scenario("CFG-02", "failed start leaves no resources and a later start succeeds")
def cfg_02(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("cfg02") as h:
        fds0 = lib.proc_fd_count(h.pid)
        threads0 = lib.proc_thread_count(h.pid)
        port = lib.free_port()
        invalid = lib.simple_config(port, backend.port)
        invalid["settings"]["worker_threads"] = 0
        response = h.start(invalid)
        require(not response.get("ok"), "invalid start unexpectedly succeeded")
        require(bool(response.get("error")), "failed start returned empty error")
        snap = snapshot(h)
        require(snap["running"] is False, "running true after failed start")
        require(snap["generation"] == 0, f"generation {snap['generation']} after failed start")
        require(not lib.try_connect(lib.LOOPBACK_V4, port, 0.2),
                "listener bound after failed start")
        require(lib.proc_fd_count(h.pid) == fds0, "fd leak after failed start")
        require(lib.proc_thread_count(h.pid) == threads0, "thread leak after failed start")

        valid = lib.simple_config(port, backend.port)
        start_ok(h, valid)
        require(echo_once(lib.LOOPBACK_V4, port, b"after-failed-start") == b"after-failed-start",
                "valid start after failed start did not forward")
        return {"fds_baseline": fds0, "threads_baseline": threads0}


@scenario("CFG-03", "startup-only settings rejection is atomic")
def cfg_03(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("cfg03") as h:
        port = lib.free_port()
        base = lib.simple_config(port, backend.port)
        start_ok(h, base)
        generation = snapshot(h)["generation"]
        held = open_flow(lib.LOOPBACK_V4, port, size=128, seed=31)

        candidates = []
        cfg = copy.deepcopy(base); cfg["settings"]["worker_threads"] = 3; candidates.append(("worker_threads", cfg))
        cfg = copy.deepcopy(base); cfg["settings"]["buffer_size"] = 32768; candidates.append(("buffer_size", cfg))
        cfg = copy.deepcopy(base); cfg["settings"]["worker_threads"] = 3; cfg["settings"]["buffer_size"] = 32768
        cfg["listeners"][0]["max_connections"] = 5000; candidates.append(("both+policy", cfg))
        for name, candidate in candidates:
            apply_fail(h, candidate)
            current = snapshot(h)
            require(current["generation"] == generation,
                    f"generation changed on startup-only rejection ({name})")
            assert_echo(held, b"still-alive")
            require(echo_once(lib.LOOPBACK_V4, port, b"new-flow") == b"new-flow",
                    f"new flow failed after rejected apply ({name})")
        close_quietly(held)

        h.stop()
        changed = copy.deepcopy(base)
        changed["settings"]["worker_threads"] = 3
        changed["settings"]["buffer_size"] = 32768
        start_ok(h, changed)
        effective = h.config()
        require(effective["config"]["settings"]["worker_threads"] == 3,
                "worker_threads change not reflected after restart")
        require(effective["config"]["settings"]["buffer_size"] == 32768,
                "buffer_size change not reflected after restart")
        h.stop()
        start_ok(h, base)
        require(echo_once(lib.LOOPBACK_V4, port, b"restored") == b"restored",
                "original configuration failed after restart")
        return {"rejections": [name for name, _ in candidates]}


@scenario("CFG-04", "IPv4/IPv6 family behavior and wildcard V6ONLY")
def cfg_04(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("cfg04") as h:
        port4 = lib.free_port(lib.LOOPBACK_V4)
        cfg = lib.simple_config(port4, backend.port)
        start_ok(h, cfg)
        require(echo_once(lib.LOOPBACK_V4, port4, b"ipv4") == b"ipv4", "IPv4 echo failed")

        details = {"ipv6": lib.ipv6_available()}
        if not lib.ipv6_available():
            raise Blocked("IPv6 loopback unavailable")

        port6 = lib.free_port(lib.LOOPBACK_V6)
        cfg = lib.simple_config(port4, backend.port)
        cfg["listeners"].append(lib.listener(2, port6, 1, bind_address=lib.LOOPBACK_V6))
        apply_ok(h, cfg)
        require(echo_once(lib.LOOPBACK_V6, port6, b"ipv6") == b"ipv6", "IPv6 echo failed")

        # Wildcard [::] must be V6ONLY: IPv4 127.0.0.1:P must not reach it.
        wildcard_port = lib.free_port(lib.WILDCARD_V6, family=lib.AF_INET6)
        cfg = lib.simple_config(port4, backend.port)
        cfg["listeners"].append(lib.listener(3, wildcard_port, 1,
                                             bind_address=lib.WILDCARD_V6))
        apply_ok(h, cfg)
        require(not lib.try_connect(lib.LOOPBACK_V4, wildcard_port, 0.5),
                "IPv4 reached a [::] wildcard listener; IPV6_V6ONLY not effective")
        require(echo_once(lib.LOOPBACK_V6, wildcard_port, b"wildv6") == b"wildv6",
                "IPv6 through [::] wildcard failed")

        # Overlapping wildcard candidates are rejected without changing state.
        generation = snapshot(h)["generation"]
        overlap = lib.simple_config(port4, backend.port)
        overlap["listeners"].append(lib.listener(4, port4, 1, bind_address=lib.WILDCARD_V4))
        apply_fail(h, overlap)
        require(snapshot(h)["generation"] == generation, "generation changed on overlap reject")
        require(echo_once(lib.LOOPBACK_V4, port4, b"still") == b"still", "IPv4 listener lost after reject")
        details["wildcard_port"] = wildcard_port
        return details


# ---------------------------------------------------------------------------
# BIN — byte transparency, backpressure and close semantics
# ---------------------------------------------------------------------------


@scenario("BIN-01", "binary payload larger than several buffers")
def bin_01(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("bin01") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, backend.port,
                                listener_overrides={"idle_timeout_ms": 0})
        start_ok(h, cfg)
        payload = lib.deterministic_payload(8 * 1024 * 1024, ctx.seed)
        sock = lib.connect_socket(lib.LOOPBACK_V4, port, 10.0)
        received = bytearray()
        error: list[BaseException] = []

        def reader():
            try:
                while len(received) < len(payload):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
            except BaseException as exc:  # noqa: BLE001
                error.append(exc)

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        thread.join(timeout=30.0)
        require(not thread.is_alive(), "8 MiB echo did not finish")
        require(not error, f"reader error: {error}")
        require(len(received) == len(payload),
                f"length mismatch {len(received)} != {len(payload)}")
        require(bytes(received) == payload, "8 MiB payload mismatch")
        close_quietly(sock)
        require(backend.connections_total == 1,
                f"expected one backend connection, saw {backend.connections_total}")
        return {"bytes": len(payload), "sha256": lib.sha256_bytes(payload)}


@scenario("BIN-02", "observed backpressure with paused backend reads")
def bin_02(ctx: Context) -> dict:
    with ctx.backend(mode="echo", pause_read=0.9) as backend, ctx.harness("bin02") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, backend.port,
                                listener_overrides={"idle_timeout_ms": 0})
        start_ok(h, cfg)
        payload = lib.deterministic_payload(32 * 1024 * 1024, ctx.seed + 2)
        sock = lib.connect_socket(lib.LOOPBACK_V4, port, 10.0)
        sock.setblocking(False)
        received = bytearray()
        reader_error: list[BaseException] = []
        stop_reader = threading.Event()

        def reader():
            try:
                while len(received) < len(payload) and not stop_reader.is_set():
                    try:
                        chunk = sock.recv(65536)
                    except BlockingIOError:
                        select_wait = True
                        import select as _select
                        _select.select([sock], [], [], 0.05)
                        continue
                    if not chunk:
                        break
                    received.extend(chunk)
            except BaseException as exc:  # noqa: BLE001
                reader_error.append(exc)

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        sent = 0
        view = memoryview(payload)
        rss0 = lib.proc_rss_kb(h.pid)
        rss_peak = rss0
        stall_deadline = time.monotonic() + 0.45
        while sent < len(payload) and time.monotonic() < stall_deadline:
            try:
                sent += sock.send(view[sent:sent + 65536])
            except BlockingIOError:
                import select as _select
                _select.select([], [sock], [], 0.02)
            rss_peak = max(rss_peak, lib.proc_rss_kb(h.pid))
        require(sent < len(payload),
                "client sent the whole 32 MiB payload while the backend was paused; "
                "backpressure was not observed (INCONCLUSIVE environment)")
        before_resume = sent
        self_stall = True

        # Continue nonblocking sends; backend resumes after its pause.
        deadline = lib.Deadline(60.0)
        while sent < len(payload) and not deadline.expired():
            try:
                sent += sock.send(view[sent:sent + 65536])
            except BlockingIOError:
                import select as _select
                _select.select([], [sock], [], 0.05)
            rss_peak = max(rss_peak, lib.proc_rss_kb(h.pid))
        require(sent == len(payload), f"only sent {sent}/{len(payload)} after resume")
        thread.join(timeout=60.0)
        require(not thread.is_alive(), "reader thread did not finish")
        require(not reader_error, f"reader error: {reader_error}")
        require(bytes(received) == payload, "payload mismatch after backpressure")
        close_quietly(sock)
        rss_delta = max(0, rss_peak - rss0)
        require(rss_delta < 64 * 1024,
                f"Engine RSS grew {rss_delta} KiB while paused; bound is 64 MiB")
        return {
            "bytes": len(payload), "sent_before_resume": before_resume,
            "rss_delta_kib": rss_delta,
        }


@scenario("BIN-03", "server-first greeting without client bytes")
def bin_03(ctx: Context) -> dict:
    greeting = b"\x00\xffGREETING" * 32
    with ctx.backend(mode="greeting", greeting=greeting) as backend, ctx.harness("bin03") as h:
        port = lib.free_port()
        start_ok(h, lib.simple_config(port, backend.port))
        sock = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        try:
            require(lib.recv_exact(sock, len(greeting), 5.0) == greeting,
                    "greeting mismatch")
            assert_echo(sock, lib.deterministic_payload(4096, ctx.seed + 3))
        finally:
            close_quietly(sock)
        require(backend.connections_total == 1,
                f"expected one backend connection, saw {backend.connections_total}")
        return {"greeting_bytes": len(greeting)}


@scenario("BIN-04", "response after client SHUT_WR and reverse half-close")
def bin_04(ctx: Context) -> dict:
    response = lib.deterministic_payload(256 * 1024, ctx.seed + 4)
    with ctx.backend(mode="half_close", response=response,
                     half_close_delay=0.1) as backend, ctx.harness("bin04a") as h:
        port = lib.free_port()
        start_ok(h, lib.simple_config(
            port, backend.port,
            settings_row=lib.settings(half_close_timeout_ms=5000)))
        require_effective_setting(h, "half_close_timeout_ms", 5000)
        request = lib.deterministic_payload(128 * 1024, ctx.seed + 5)
        sock = lib.connect_socket(lib.LOOPBACK_V4, port, 10.0)
        try:
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            received = lib.recv_until_eof(sock, 15.0)
            require(received == response,
                    f"response mismatch: got {len(received)} expected {len(response)}")
        finally:
            close_quietly(sock)
        require(backend.eof_total == 1, "backend did not observe exactly one EOF")
        require(backend.bytes_c2s == len(request), "backend request length mismatch")

    response = lib.deterministic_payload(64 * 1024, ctx.seed + 6)
    with ctx.backend(mode="reverse_half_close",
                     response=response) as backend, ctx.harness("bin04b") as h:
        port = lib.free_port()
        start_ok(h, lib.simple_config(
            port, backend.port,
            settings_row=lib.settings(half_close_timeout_ms=5000)))
        require_effective_setting(h, "half_close_timeout_ms", 5000)
        request = lib.deterministic_payload(32 * 1024, ctx.seed + 7)
        sock = lib.connect_socket(lib.LOOPBACK_V4, port, 10.0)
        try:
            require(lib.recv_exact(sock, len(response), 10.0) == response,
                    "reverse-half-close response mismatch")
            sock.settimeout(5.0)
            require(sock.recv(1) == b"", "backend SHUT_WR did not reach client")
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            require(backend.wait_bytes_c2s(len(request), 10.0),
                    "client-to-backend stream incomplete after backend half-close")
            require(backend.eof_total == 1, "backend did not observe client EOF")
        finally:
            close_quietly(sock)
    return {"response_bytes": 256 * 1024, "reverse_bytes": 64 * 1024}


@scenario("BIN-05", "partial/nonblocking I/O across buffer boundaries")
def bin_05(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("bin05") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, backend.port,
                                listener_overrides={"idle_timeout_ms": 0})
        start_ok(h, cfg)
        fds0 = lib.proc_fd_count(h.pid)
        sizes = [1, 1023, 1024, 16383, 16384, 16385, 65536]
        errors: list[str] = []
        completed = [0]
        lock = threading.Lock()

        def worker(index: int) -> None:
            for iteration in range(2):
                size = sizes[(index + iteration) % len(sizes)]
                payload = lib.deterministic_payload(size, ctx.seed + index * 31 + iteration)
                try:
                    if iteration == 0:
                        received = echo_once(lib.LOOPBACK_V4, port, payload, 10.0)
                        require(received == payload, "blocking echo mismatch")
                    else:
                        echo_nonblocking(port, payload, 10.0)
                    with lock:
                        completed[0] += 1
                except BaseException as exc:  # noqa: BLE001
                    with lock:
                        errors.append(f"worker {index}: {type(exc).__name__}: {exc}")

        with ThreadPoolExecutor(max_workers=32) as pool:
            futures = [pool.submit(worker, i) for i in range(32)]
            for future in futures:
                future.result(timeout=60.0)
        require(not errors, f"concurrent errors: {errors[:3]}")
        require(completed[0] == 64, f"only {completed[0]}/64 flows completed")
        time.sleep(0.2)
        require(lib.proc_fd_count(h.pid) <= fds0 + 2,
                f"fd growth: {fds0} -> {lib.proc_fd_count(h.pid)}")
        return {"flows": completed[0], "sizes": sizes}


def echo_nonblocking(port: int, payload: bytes, timeout: float) -> None:
    sock = lib.connect_socket(lib.LOOPBACK_V4, port, timeout)
    sock.setblocking(False)
    try:
        import select as _select
        view = memoryview(payload)
        sent = 0
        received = bytearray()
        deadline = lib.Deadline(timeout)
        while (sent < len(payload) or len(received) < len(payload)) and not deadline.expired():
            readable, writable, _ = _select.select([sock], [sock] if sent < len(payload) else [],
                                                   [], min(0.2, deadline.remaining()))
            if writable:
                try:
                    sent += sock.send(view[sent:sent + 4096])
                except BlockingIOError:
                    pass
            if readable:
                try:
                    chunk = sock.recv(65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    break
                received.extend(chunk)
        require(sent == len(payload), "nonblocking send incomplete")
        require(bytes(received) == payload, "nonblocking echo mismatch")
    finally:
        close_quietly(sock)


@scenario("BIN-06", "idle and half-close deadlines")
def bin_06(ctx: Context) -> dict:
    details = {}
    with ctx.backend(mode="echo") as backend, ctx.harness("bin06a") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, backend.port,
                                listener_overrides={"idle_timeout_ms": 600})
        start_ok(h, cfg)
        sock = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        try:
            sock.sendall(b"a")
            require(lib.recv_exact(sock, 1, 3.0) == b"a", "initial exchange failed")
            started = time.monotonic()
            elapsed = lib.wait_until_closed(sock, 5.0)
        finally:
            close_quietly(sock)
        require(0.3 <= elapsed <= 0.6 + 1.5,
                f"idle close took {elapsed:.3f}s for 600ms timeout")
        details["idle_close_s"] = round(elapsed, 3)

    with ctx.backend(mode="echo") as backend, ctx.harness("bin06b") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, backend.port,
                                listener_overrides={"idle_timeout_ms": 0})
        start_ok(h, cfg)
        sock = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        try:
            sock.sendall(b"a")
            require(lib.recv_exact(sock, 1, 3.0) == b"a", "initial exchange failed")
            time.sleep(1.5)
            assert_echo(sock, b"still-open")
        finally:
            close_quietly(sock)
        details["idle_disabled"] = True

    with ctx.backend(mode="half_close_silent") as backend, ctx.harness("bin06c") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, backend.port,
                                settings_row=lib.settings(half_close_timeout_ms=400))
        start_ok(h, cfg)
        require_effective_setting(h, "half_close_timeout_ms", 400)
        sock = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        try:
            sock.sendall(b"payload")
            sock.shutdown(socket.SHUT_WR)
            started = time.monotonic()
            try:
                received = lib.recv_until_eof(sock, 5.0)
            except TimeoutError:
                snap = snapshot(h)
                raise AssertionError(
                    "half_close_timeout_ms=400 was not enforced: flow stayed open "
                    f"after 5s (active={snap.get('active_connections')}, "
                    f"connect_errors={snap.get('connect_errors')})") from None
            elapsed = time.monotonic() - started
            require(received == b"", "silent half-close produced unexpected bytes")
        finally:
            close_quietly(sock)
        require(0.15 <= elapsed <= 0.4 + 1.5,
                f"half-close force close took {elapsed:.3f}s for 400ms timeout")
        details["half_close_s"] = round(elapsed, 3)

    response = lib.deterministic_payload(128 * 1024, ctx.seed + 8)
    with ctx.backend(mode="half_close", response=response,
                     half_close_delay=0.1) as backend, ctx.harness("bin06d") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, backend.port,
                                settings_row=lib.settings(half_close_timeout_ms=2000))
        start_ok(h, cfg)
        require_effective_setting(h, "half_close_timeout_ms", 2000)
        request = lib.deterministic_payload(64 * 1024, ctx.seed + 9)
        sock = lib.connect_socket(lib.LOOPBACK_V4, port, 10.0)
        try:
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            received = lib.recv_until_eof(sock, 10.0)
            require(received == response, "in-time half-close response mismatch")
        finally:
            close_quietly(sock)
        details["in_time_response"] = True
    return details


@scenario("BIN-07", "delayed half-close response does not burn CPU while waiting")
def bin_07(ctx: Context) -> dict:
    response = lib.deterministic_payload(64 * 1024, ctx.seed + 11)
    request = lib.deterministic_payload(4096, ctx.seed + 12)
    with ctx.backend(mode="half_close", response=response,
                     half_close_delay=0.4) as backend, ctx.harness("bin07") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, backend.port,
                                settings_row=lib.settings(half_close_timeout_ms=5000),
                                listener_overrides={"idle_timeout_ms": 0})
        start_ok(h, cfg)
        require_effective_setting(h, "half_close_timeout_ms", 5000)
        time.sleep(0.1)  # let startup activity settle before sampling
        sock = lib.connect_socket(lib.LOOPBACK_V4, port, 10.0)
        ticks_per_second = lib.clock_ticks_per_second()
        try:
            sock.sendall(request)
            before = lib.proc_cpu_ticks(h.pid)
            require(before is not None, "harness PID disappeared before CPU sample")
            started = time.monotonic()
            sock.shutdown(socket.SHUT_WR)
            received = lib.recv_exact(sock, len(response), 10.0)
            elapsed = time.monotonic() - started
            after = lib.proc_cpu_ticks(h.pid)
            require(after is not None, "harness PID disappeared after CPU sample")
            require(received == response,
                    "delayed half-close response mismatch: sent sha256="
                    f"{lib.sha256_bytes(response)} received sha256="
                    f"{lib.sha256_bytes(received)}")
            require(backend.eof_total == 1,
                    "backend did not observe the client request EOF before replying")
            require(backend.bytes_c2s == len(request),
                    f"backend saw {backend.bytes_c2s}/{len(request)} request bytes")
            require(elapsed >= 0.30,
                    f"response arrived after only {elapsed:.3f}s; delayed wait not exercised")
        finally:
            close_quietly(sock)
        tick_delta = after - before
        cpu_ms = tick_delta * 1000.0 / ticks_per_second
        threshold_ms = 100.0
        details = {
            "request_bytes": len(request),
            "response_bytes": len(response),
            "wait_elapsed_s": round(elapsed, 3),
            "harness_pid": h.pid,
            "cpu_ticks_before": before,
            "cpu_ticks_after": after,
            "cpu_tick_delta": tick_delta,
            "ticks_per_second": ticks_per_second,
            "cpu_ms_during_wait": round(cpu_ms, 3),
            "threshold_ms": threshold_ms,
            "response_sha256": lib.sha256_bytes(response),
        }
        require(cpu_ms < threshold_ms,
                f"Engine burned {cpu_ms:.1f}ms CPU during a {elapsed * 1000:.0f}ms "
                f"half-close wait (threshold {threshold_ms:.0f}ms, "
                f"{tick_delta} ticks at {ticks_per_second}Hz); expected an idle "
                "EPOLLRDHUP wait, not a spin")
        return details


@scenario("TLS-01", "real TLS handshake and exact binary echo across many buffers")
def tls_01(ctx: Context) -> dict:
    try:
        with tempfile.TemporaryDirectory(prefix="tcp-proxy-tls-") as tmp:
            material = lib.generate_test_tls_material(tmp)
            with lib.TlsEchoBackend(material["server_cert"],
                                    material["server_key"]) as backend, \
                    ctx.harness("tls01") as h:
                port = lib.free_port()
                cfg = lib.simple_config(
                    port, backend.port,
                    settings_row=lib.settings(half_close_timeout_ms=5000),
                    listener_overrides={"idle_timeout_ms": 0},
                )
                start_ok(h, cfg)
                payload = lib.deterministic_payload(256 * 1024, ctx.seed + 13)
                raw = lib.connect_socket(lib.LOOPBACK_V4, port, 10.0)
                context = lib.tls_client_context(material["ca_cert"])
                tls = context.wrap_socket(raw, server_hostname="localhost")
                close_detail = ""
                try:
                    tls.sendall(payload)
                    received = lib.recv_exact(tls, len(payload), 15.0)
                    require(received == payload,
                            "TLS echo mismatch: sent sha256="
                            f"{lib.sha256_bytes(payload)} received sha256="
                            f"{lib.sha256_bytes(received)}")
                    version = tls.version()
                    cipher = tls.cipher()[0] if tls.cipher() else ""
                    # Both endpoints are normal task-owned TLS peers.  A close
                    # that raises here is a concrete transport defect, never a
                    # pass with orderly=False.
                    try:
                        tls.unwrap()
                    except (ssl.SSLError, OSError) as exc:
                        close_detail = f"{type(exc).__name__}: {exc}"
                        raise AssertionError(
                            "TLS close_notify exchange failed: "
                            f"{close_detail}") from None
                finally:
                    try:
                        tls.close()
                    except OSError:
                        pass
                    try:
                        raw.close()
                    except OSError:
                        pass
                require(backend.wait_connections(1, 5.0),
                        "TLS backend did not accept the Engine connection")
                require(backend.handshake_errors == 0,
                        f"TLS backend handshake/transport errors: {backend.stats()}")
                require(lib.wait_for(lambda: backend.bytes_c2s == len(payload), 5.0,
                                     interval=0.02,
                                     description="TLS backend received payload"),
                        f"TLS backend saw {backend.bytes_c2s}/{len(payload)} bytes")
                require(backend.bytes_s2c == len(payload),
                        f"TLS backend sent {backend.bytes_s2c}/{len(payload)} bytes")
                require(lib.wait_for(lambda: backend.eof_total == 1, 5.0,
                                     interval=0.02, description="TLS close_notify"),
                        "TLS backend did not observe the client close_notify")
                require(lib.wait_for(lambda: backend.close_total == 1, 5.0,
                                     interval=0.02,
                                     description="TLS backend completed close_notify"),
                        "TLS backend did not complete an orderly close: "
                        f"{backend.stats()}")
                require(backend.close_errors == 0,
                        f"TLS backend close_notify errors: {backend.stats()}")
                snap = snapshot(h)
                require(snap["accepted_total"] >= 1,
                        "Engine did not accept the TLS flow")
                details = {
                    "tls_version": version,
                    "cipher": cipher,
                    "payload_bytes": len(payload),
                    "payload_sha256": lib.sha256_bytes(payload),
                    "client_verified_generated_ca_and_hostname": True,
                    "backend_loaded_generated_server_cert": True,
                    "mutual_client_certificate_authentication": False,
                    "binary_echo_exact": True,
                    "orderly_tls_close": True,
                    "backend": backend.stats(),
                }
                return details
    except lib.TlsUnavailable as exc:
        raise Blocked(str(exc))


# ---------------------------------------------------------------------------
# CAP — admission and capacity
# ---------------------------------------------------------------------------


@scenario("CAP-01", "global, listener and server limits")
def cap_01(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("cap01") as h:
        port = lib.free_port()
        cfg = lib.simple_config(
            port, backend.port,
            settings_row=lib.settings(max_connections=4),
            listener_overrides={"max_connections": 3},
            server_overrides={"max_connections": 2},
        )
        start_ok(h, cfg)
        held = []
        for index in range(2):
            held.append(open_flow(lib.LOOPBACK_V4, port, size=64, seed=100 + index))
            wait_backend_connections(backend, index + 1)
        require(backend.connections_total == 2, "server limit not reached with two flows")

        outcomes = [admission_probe(lib.LOOPBACK_V4, port, 2.0) for _ in range(4)]
        require(all(outcome in ("closed", "reset") for outcome in outcomes),
                f"excess clients were admitted: {outcomes}")
        time.sleep(0.2)
        require(backend.connections_total == 2,
                f"backend accepted beyond server limit: {backend.connections_total}")
        snap = snapshot(h)
        require(snap["active_connections"] <= 4, "global capacity exceeded")
        require(listener_row(snap, 1)["active_connections"] <= 3, "listener capacity exceeded")
        require(server_row(observation(h), 1)["active_connections"] <= 2, "server capacity exceeded")
        require(snap["rejected_total"] >= 1, "no rejections counted at capacity")

        close_quietly(held.pop())
        wait_snapshot(h, lambda s: s["active_connections"] <= 1, 5.0)
        replacement = open_flow(lib.LOOPBACK_V4, port, size=64, seed=200)
        wait_backend_connections(backend, 3)
        close_quietly(replacement, *held)
        final = wait_active(h, 0, 5.0)
        require(final["active_connections"] == 0, "connections leaked after close")
        return {"outcomes": outcomes, "rejected_total": snap["rejected_total"]}


@scenario("CAP-02", "pending connects consume capacity and release at connect budget")
def cap_02(ctx: Context) -> dict:
    budget_ms = 500
    grace = 1.5
    with ctx.blackhole(backlog=1) as blackhole, ctx.harness("cap02") as h:
        require(blackhole.fill(), "could not saturate blackhole accept queue")
        port = lib.free_port()
        cfg = lib.simple_config(
            port, blackhole.port,
            settings_row=lib.settings(max_connections=2),
            listener_overrides={"max_connections": 2,
                                "connect_timeout_ms": budget_ms,
                                "max_connect_attempts": 1,
                                "idle_timeout_ms": 0},
            server_overrides={"max_connections": 2},
        )
        start_ok(h, cfg)
        require(h.config(timeout=10.0)["config"]["listeners"][0]["connect_timeout_ms"] ==
                budget_ms, "connect_timeout_ms not effective")
        accepted_at = time.monotonic()
        clients = [lib.connect_socket(lib.LOOPBACK_V4, port, 5.0) for _ in range(2)]
        try:
            for client in clients:
                client.sendall(b"pending")
            require(lib.wait_syn_sent(h.pid, blackhole.port, 3.0),
                    "no Engine SYN_SENT observed for pending flow")
            snap = wait_active(h, 2, 5.0)
            require(snap["active_connections"] == 2,
                    "pending flows not counted as active")

            extra = admission_probe(lib.LOOPBACK_V4, port, 2.0)
            require(extra in ("closed", "reset"),
                    f"third client admitted while two pending flows active: {extra}")
            snap = snapshot(h)
            require(snap["active_connections"] <= 2,
                    "global limit exceeded with pending flows")
            require(snap["rejected_total"] >= 1, "capacity rejection not counted")

            # A client FIN is indistinguishable from a valid SHUT_WR, so the
            # pending slot may legitimately persist until the connect budget
            # expires.  Require release within budget + explicit grace, never
            # immediate teardown on RDHUP.
            close_quietly(clients.pop())
            remaining = max(0.2, accepted_at + budget_ms / 1000.0 + grace - time.monotonic())
            released = wait_snapshot(h, lambda s: s["active_connections"] <= 1, remaining)
            require(released["active_connections"] <= 1,
                    f"pending slot not released within {budget_ms}ms budget + "
                    f"{grace}s grace: {released.get('active_connections')} active")

            replacement_accept_started = time.monotonic()
            replacement = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
            replacement.sendall(b"replacement")
            try:
                expected_active = released["active_connections"] + 1
                snap = wait_snapshot(
                    h, lambda s: s["active_connections"] >= expected_active, 5.0)
                require(snap["active_connections"] == expected_active,
                        f"released pending slot was not reusable: active="
                        f"{snap['active_connections']}, expected {expected_active}")
            finally:
                close_quietly(replacement)
            # Remaining flow must also release at its own budget expiry.
            final_remaining = max(
                0.2, replacement_accept_started + budget_ms / 1000.0 + grace -
                time.monotonic())
            final = wait_snapshot(h, lambda s: s["active_connections"] == 0,
                                  final_remaining)
            require(final["active_connections"] == 0,
                    f"pending flow slot leaked after budget: {final}")
            require(not lib.proc_has_remote_port(h.pid, blackhole.port, lib.TCP_SYN_SENT),
                    "SYN_SENT remained after the total connect budget "
                    f"(snapshot={final}, sockets="
                    f"{[r for r in lib.proc_socket_states(h.pid) if r['remote_port'] == blackhole.port]})")
            return {"pending_observed": True, "extra_outcome": extra,
                    "budget_ms": budget_ms, "grace_s": grace,
                    "released_within_budget_plus_grace": True}
        finally:
            for client in clients:
                close_quietly(client)


@scenario("CAP-03", "lowering capacity preserves established sessions")
def cap_03(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("cap03") as h:
        port = lib.free_port()
        base = lib.simple_config(port, backend.port,
                                 listener_overrides={"idle_timeout_ms": 0})
        start_ok(h, base)
        held = [open_flow(lib.LOOPBACK_V4, port, size=64, seed=300 + i) for i in range(8)]
        wait_backend_connections(backend, 8)

        lowered = copy.deepcopy(base)
        lowered["settings"]["max_connections"] = 2
        lowered.backend_fixtures[0]["max_connections"] = 2
        apply_ok(h, lowered)
        for index, sock in enumerate(held):
            assert_echo(sock, f"survivor-{index}".encode())
        snap = snapshot(h)
        require(snap["active_connections"] == 8,
                "capacity reduction killed or miscounted established flows")
        outcome = admission_probe(lib.LOOPBACK_V4, port, 2.0)
        require(outcome in ("closed", "reset"),
                f"new admission succeeded above lowered global limit: {outcome}")

        for sock in held[:-1]:
            close_quietly(sock)
        wait_snapshot(h, lambda s: s["active_connections"] <= 1, 5.0)
        newcomer = open_flow(lib.LOOPBACK_V4, port, size=64, seed=399)
        assert_echo(held[-1], b"still")
        close_quietly(newcomer, held[-1])
        wait_active(h, 0, 5.0)
        return {"established": 8, "outcome": outcome}


@scenario("CAP-04", "bounded admission under burst pressure")
def cap_04(ctx: Context) -> dict:
    with ctx.backend(mode="echo", pause_read=0.2) as backend, ctx.harness("cap04") as h:
        port = lib.free_port()
        cfg = lib.simple_config(
            port, backend.port,
            settings_row=lib.settings(max_connections=8),
            listener_overrides={"max_connections": 8, "idle_timeout_ms": 0},
            server_overrides={"max_connections": 8},
        )
        start_ok(h, cfg)
        fds0 = lib.proc_fd_count(h.pid)
        outcomes: list[str] = []
        lock = threading.Lock()

        def client(index: int) -> None:
            payload = lib.deterministic_payload(256, ctx.seed + index)
            try:
                sock = lib.connect_socket(lib.LOOPBACK_V4, port, 3.0)
                try:
                    sock.sendall(payload)
                    try:
                        data = lib.recv_exact(sock, len(payload), 2.0)
                    except (socket.timeout, TimeoutError):
                        result = "timeout"
                    except EOFError as exc:
                        received = getattr(exc, "received", 0)
                        result = "closed" if received == 0 else "partial"
                    except (ConnectionResetError, ConnectionAbortedError,
                            BrokenPipeError) as exc:
                        received = getattr(exc, "received", 0)
                        result = "reset" if received == 0 else "partial"
                    else:
                        if data == payload:
                            result = "echo"
                        elif len(data) < len(payload):
                            result = "partial"
                        else:
                            result = "corrupt"
                finally:
                    close_quietly(sock)
            except OSError:
                result = "connect-error"
            with lock:
                outcomes.append(result)

        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = [pool.submit(client, i) for i in range(100)]
            for future in futures:
                future.result(timeout=30.0)
        require(all(result != "timeout" for result in outcomes),
                "client hung during burst admission")
        require(all(result not in ("partial", "corrupt") for result in outcomes),
                f"client received a short or corrupt echo during burst: "
                f"{[r for r in outcomes if r in ('partial', 'corrupt')][:5]}")
        require(all(result in ("echo", "closed", "reset", "connect-error")
                    for result in outcomes),
                f"unexpected burst outcome: {set(outcomes)}")
        time.sleep(0.5)
        snap = wait_active(h, 0, 10.0)
        require(snap["active_connections"] == 0, "connections leaked after burst")
        require(lib.proc_fd_count(h.pid) <= fds0 + 2,
                f"fd growth after burst: {fds0} -> {lib.proc_fd_count(h.pid)}")
        require(echo_once(lib.LOOPBACK_V4, port, b"responsive") == b"responsive",
                "Engine unresponsive after burst")
        return {"outcomes": {name: outcomes.count(name) for name in set(outcomes)}}


# ---------------------------------------------------------------------------
# SEL — balancing, primary/backup, routing
# ---------------------------------------------------------------------------


@scenario("SEL-04", "source routing, REJECT, default and rule order")
def sel_04(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as b1, ctx.backend(mode="echo") as b2, \
            ctx.harness("sel04") as h:
        port = lib.free_port()
        cfg = lib.config(
            hostgroups=[lib.hostgroup(1), lib.hostgroup(2)],
            backend_fixtures=[lib.server(1, 1, b1.port), lib.server(2, 2, b2.port)],
            listeners=[lib.listener(1, port, 1, bind_address=lib.WILDCARD_V4)],
            rules=[
                lib.rule(1, source_cidr="127.0.0.2/32", action="ROUTE",
                         destination_hostgroup=2),
                lib.rule(2, source_cidr="127.0.0.3/32", action="REJECT"),
            ],
        )
        start_ok(h, cfg)
        try:
            echo_once(lib.LOOPBACK_V4, port, b"default", 3.0, source="127.0.0.1")
            echo_once(lib.LOOPBACK_V4, port, b"route2", 3.0, source="127.0.0.2")
        except OSError as exc:
            raise Blocked(f"cannot bind loopback source aliases: {exc}") from exc
        require(b1.connections_total >= 1 and b2.connections_total >= 1,
                f"routing did not hit both backends: {b1.connections_total}/"
                f"{b2.connections_total}")
        rejected = admission_probe_source(port, "127.0.0.3", 2.0)
        require(rejected in ("closed", "reset"),
                f"REJECT source was admitted: {rejected}")

        disabled = copy.deepcopy(cfg)
        lib.find_row(disabled["rules"], "rule_id", 2)["active"] = 0
        apply_ok(h, disabled)
        before1 = b1.connections_total
        echo_once(lib.LOOPBACK_V4, port, b"now-default", 3.0, source="127.0.0.3")
        require(b1.connections_total == before1 + 1,
                "disabled REJECT rule still blocked or misrouted")

        # Ordering: first ascending rule wins.
        ordered = copy.deepcopy(disabled)
        ordered["rules"] = [
            lib.rule(1, source_cidr="127.0.0.0/8", action="ROUTE",
                     destination_hostgroup=1),
            lib.rule(2, source_cidr="127.0.0.2/32", action="ROUTE",
                     destination_hostgroup=2),
        ]
        apply_ok(h, ordered)
        before1, before2 = b1.connections_total, b2.connections_total
        echo_once(lib.LOOPBACK_V4, port, b"first-wins", 3.0, source="127.0.0.2")
        require(b1.connections_total == before1 + 1 and
                b2.connections_total == before2,
                "rule ordering did not honor first ascending match")

        reversed_rules = copy.deepcopy(ordered)
        reversed_rules["rules"] = [
            lib.rule(1, source_cidr="127.0.0.2/32", action="ROUTE",
                     destination_hostgroup=2),
            lib.rule(2, source_cidr="127.0.0.0/8", action="ROUTE",
                     destination_hostgroup=1),
        ]
        apply_ok(h, reversed_rules)
        before1, before2 = b1.connections_total, b2.connections_total
        echo_once(lib.LOOPBACK_V4, port, b"specific-first", 3.0, source="127.0.0.2")
        require(b2.connections_total == before2 + 1 and
                b1.connections_total == before1,
                "specific rule did not win after reordering")
        return {"rejected": rejected, "rule_order": "ascending"}


def admission_probe_source(port: int, source: str, timeout: float) -> str:
    sock = lib.connect_socket(lib.LOOPBACK_V4, port, timeout, source=source)
    try:
        sock.sendall(b"PROBE")
        sock.settimeout(timeout)
        try:
            data = sock.recv(5)
        except socket.timeout:
            return "timeout"
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return "reset"
        if not data:
            return "closed"
        return "echo" if data == b"PROBE" else "partial"
    finally:
        close_quietly(sock)


# ---------------------------------------------------------------------------
# RT — health checking
# ---------------------------------------------------------------------------


@scenario("GEN-01", "endpoint/policy edit preserves established flows")
def gen_01(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as e1, ctx.backend(mode="echo") as e2, \
            ctx.harness("gen01") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, e1.port)
        start_ok(h, cfg)
        generation = snapshot(h)["generation"]
        held = open_flow(lib.LOOPBACK_V4, port, size=64, seed=5100)

        client_errors: list[str] = []
        stop = threading.Event()

        def connector():
            while not stop.is_set():
                try:
                    echo_once(lib.LOOPBACK_V4, port,
                              lib.deterministic_payload(32, ctx.seed + 5101), 3.0)
                except BaseException as exc:  # noqa: BLE001
                    client_errors.append(f"{type(exc).__name__}: {exc}")

        thread = threading.Thread(target=connector, daemon=True)
        thread.start()
        changed = copy.deepcopy(cfg)
        changed.backend_fixtures[0]["port"] = e2.port
        changed.backend_fixtures[0]["weight"] = 5
        apply_ok(h, changed)
        time.sleep(0.2)
        stop.set()
        thread.join(timeout=5.0)
        require(not thread.is_alive(), "connector thread did not exit")
        require(not client_errors, f"connections failed during apply: {client_errors[:3]}")
        require(snapshot(h)["generation"] == generation + 1,
                "generation did not increment exactly once")
        # Capture outcome baselines only after the concurrent connector has
        # stopped.  A faulty migration during apply would already be visible in
        # these backend byte/connection counters, so the held flow is proven by
        # an exact old-endpoint byte delta rather than cumulative totals alone.
        e1_bytes_before = e1.bytes_c2s
        e2_bytes_before = e2.bytes_c2s
        e1_conns_before = e1.connections_total
        e2_conns_before = e2.connections_total
        held_payload = lib.deterministic_payload(97, ctx.seed + 5103)
        assert_echo(held, held_payload)
        require(lib.wait_for(lambda: e1.bytes_c2s >= e1_bytes_before + len(held_payload),
                             2.0, interval=0.02,
                             description="old endpoint received the pinned payload"),
                f"old endpoint saw {e1.bytes_c2s - e1_bytes_before}/"
                f"{len(held_payload)} held-flow bytes")
        time.sleep(0.05)
        require(e1.bytes_c2s - e1_bytes_before == len(held_payload),
                "old endpoint c2s delta does not equal the unique held payload: "
                f"delta={e1.bytes_c2s - e1_bytes_before} expected={len(held_payload)}")
        require(e2.bytes_c2s == e2_bytes_before,
                "pinned established flow was moved to the new generation endpoint "
                f"(new backend c2s delta={e2.bytes_c2s - e2_bytes_before})")
        held_e2_delta = e2.bytes_c2s - e2_bytes_before
        require(e1.connections_total == e1_conns_before,
                "pinned established flow reconnected to its old endpoint")
        require(e2.connections_total == e2_conns_before,
                "pinned established flow was moved to the new generation endpoint")
        newcomer = open_flow(lib.LOOPBACK_V4, port, size=64, seed=5102)
        require(e2.connections_total == e2_conns_before + 1,
                "new flow did not use generation 2 endpoint")
        require(e1.connections_total == e1_conns_before,
                "new flow unexpectedly used the old generation endpoint")
        close_quietly(held, newcomer)
        return {"during_apply_errors": len(client_errors),
                "pinned_endpoint": "old",
                "pinned_payload_bytes": len(held_payload),
                "old_backend_c2s_delta_during_held_echo": e1.bytes_c2s - e1_bytes_before,
                "new_backend_c2s_delta_during_held_echo": held_e2_delta,
                "pinned_endpoint_connections": e1_conns_before,
                "new_flow_connections": e2.connections_total - e2_conns_before}


@scenario("GEN-02", "OFFLINE_HARD closes old-generation established and pending flows")
def gen_02(ctx: Context) -> dict:
    with ctx.backend(mode="echo", backlog=1) as s1, ctx.backend(mode="echo") as s2, \
            ctx.harness("gen02") as h:
        l1_port = lib.free_port()
        l2_port = lib.free_port()
        cfg = lib.config(
            hostgroups=[lib.hostgroup(1), lib.hostgroup(2)],
            backend_fixtures=[lib.server(1, 1, s1.port), lib.server(2, 2, s2.port)],
            listeners=[lib.listener(1, l1_port, 1), lib.listener(2, l2_port, 2)],
        )
        start_ok(h, cfg)
        held = open_flow(lib.LOOPBACK_V4, l1_port, size=64, seed=5200)
        control = open_flow(lib.LOOPBACK_V4, l2_port, size=64, seed=5201)

        s1.pause_accept()
        require(s1.fill_accept_queue(), "could not saturate S1 accept queue")
        pending = lib.connect_socket(lib.LOOPBACK_V4, l1_port, 5.0)
        pending.sendall(b"pending-data")
        require(lib.wait_syn_sent(h.pid, s1.port, 5.0),
                "no Engine SYN_SENT for hard-offline pending case")

        hard = copy.deepcopy(cfg)
        lib.find_row(hard.backend_fixtures, "server_id", 1)["status"] = "OFFLINE_HARD"
        apply_ok(h, hard)

        require(lib.wait_until_closed(held, 2.0) >= 0,
                "established S1 flow survived OFFLINE_HARD")
        require(lib.wait_until_closed(pending, 2.0) >= 0,
                "pending S1 flow survived OFFLINE_HARD")
        assert_echo(control, b"control-unaffected")
        snap = snapshot(h)
        row = server_row(observation(h), 1)
        require(row["status"] == "OFFLINE_HARD", "administrative status not exposed")
        require(row["active_connections"] == 0,
                f"S1 still has {row['active_connections']} active flows")
        require(not lib.proc_has_remote_port(h.pid, s1.port, lib.TCP_SYN_SENT),
                "new SYN_SENT to hard-offlined S1 observed")
        close_quietly(held, pending, control)
        s1.release_fillers()
        s1.resume_accept()
        return {"ack": True, "control_preserved": True}


@scenario("GEN-03", "soft removal; retry excludes removed/replaced endpoint")
def gen_03(ctx: Context) -> dict:
    with ctx.blackhole(backlog=1) as s1, ctx.backend(mode="echo") as s2, \
            ctx.harness("gen03") as h:
        require(s1.fill(), "could not saturate S1 accept queue")
        port = lib.free_port()
        cfg = lib.config(
            hostgroups=[lib.hostgroup(1)],
            backend_fixtures=[lib.server(1, 1, s1.port, status="ONLINE"),
                     lib.server(2, 1, s2.port, status="OFFLINE_SOFT")],
            listeners=[lib.listener(1, port, 1, connect_timeout_ms=3000)],
        )
        start_ok(h, cfg)
        payload = lib.deterministic_payload(32 * 1024, ctx.seed + 5300)
        client = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        client.sendall(payload)
        require(lib.wait_syn_sent(h.pid, s1.port, 5.0),
                "no SYN_SENT to the only initially eligible server")

        enable = copy.deepcopy(cfg)
        lib.find_row(enable.backend_fixtures, "server_id", 2)["status"] = "ONLINE"
        apply_ok(h, enable)
        s1.fail()
        received = lib.recv_exact(client, len(payload), 10.0)
        require(received == payload, "retry did not deliver exact client payload")
        require(s2.connections_total == 1,
                f"S2 accepted {s2.connections_total} times; expected exactly one")
        require(s1.connections_total == 0, "blackholed S1 accepted application connection")

        removal = copy.deepcopy(enable)
        removal.backend_fixtures = [row for row in removal.backend_fixtures if row["server_id"] != 1]
        apply_ok(h, removal)
        assert_echo(client, b"established-survives-removal")
        soft = copy.deepcopy(removal)
        soft.backend_fixtures[0]["status"] = "OFFLINE_SOFT"
        apply_ok(h, soft)
        assert_echo(client, b"established-survives-soft")
        close_quietly(client)
        return {"retry_target": "S2", "removed_endpoint_retried": False}


@scenario("GEN-04", "atomic bind rollback stages free listener then occupied endpoint")
def gen_04(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.squatter() as squatter, \
            ctx.harness("gen04") as h:
        port1 = lib.free_port()
        port3 = lib.free_port()
        cfg = lib.simple_config(port1, backend.port)
        start_ok(h, cfg)
        generation = snapshot(h)["generation"]
        held = open_flow(lib.LOOPBACK_V4, port1, size=64, seed=5400)

        # Candidate order: free L3 first, occupied L2 second.
        candidate = copy.deepcopy(cfg)
        candidate["listeners"].append(lib.listener(3, port3, 1))
        candidate["listeners"].append(lib.listener(2, squatter.port, 1))
        apply_fail(h, candidate)
        current = snapshot(h)
        require(current["generation"] == generation,
                "generation changed after bind rollback")
        require(len(current["listeners"]) == 1 and
                current["listeners"][0]["listener_id"] == 1,
                "half-published listener row after failed apply")
        require(bool(current.get("last_error")), "rollback error text missing")
        assert_echo(held, b"listener-still-serving")
        require(lib.try_connect(lib.LOOPBACK_V4, squatter.port, 0.5),
                "squatter lost its occupied endpoint")

        # P3 must be bindable again while the Engine is still running.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((lib.LOOPBACK_V4, port3))
            probe.listen(1)
        finally:
            probe.close()
        close_quietly(held)
        return {"transient_free_bind_observed": "not asserted; preparation order not exposed"}


@scenario("GEN-05", "overlapping replacement and different-port move")
def gen_05(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("gen05") as h:
        port1 = lib.free_port()
        cfg = lib.simple_config(port1, backend.port)
        start_ok(h, cfg)
        held = open_flow(lib.LOOPBACK_V4, port1, size=64, seed=5500)

        overlapping = copy.deepcopy(cfg)
        overlapping["listeners"][0]["bind_address"] = lib.WILDCARD_V4
        response = h.apply(overlapping)
        require(not response.get("ok"),
                "overlapping 127.0.0.1 -> 0.0.0.0 replacement was not rejected")
        require("remove" in response.get("error", "").lower() or
                "overlap" in response.get("error", "").lower() or
                bool(response.get("error")),
                "overlap rejection lacks a descriptive error")
        assert_echo(held, b"old-listener-serving")
        require(echo_once(lib.LOOPBACK_V4, port1, b"old-endpoint") == b"old-endpoint",
                "old listener stopped serving after rejected overlap")

        port2 = lib.free_port()
        moved = copy.deepcopy(cfg)
        moved["listeners"][0]["bind_port"] = port2
        apply_ok(h, moved)
        assert_echo(held, b"pinned-flow-survives-move")
        require(echo_once(lib.LOOPBACK_V4, port2, b"moved-listener") == b"moved-listener",
                "new listener port did not serve")

        with ctx.squatter() as squatter:
            blocked = copy.deepcopy(moved)
            blocked["listeners"][0]["bind_port"] = squatter.port
            apply_fail(h, blocked)
            assert_echo(held, b"still-after-occupied-move")
            require(echo_once(lib.LOOPBACK_V4, port2, b"old-port-still") == b"old-port-still",
                    "old moved listener lost after occupied destination failure")
        close_quietly(held)
        return {"overlap_rejected": True, "move_preserved": True}


@scenario("GEN-06", "concurrent apply and admission")
def gen_06(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as b1, ctx.backend(mode="echo") as b2, \
            ctx.harness("gen06") as h:
        port1, port2 = lib.free_ports(2)
        base = lib.config(
            hostgroups=[lib.hostgroup(1)],
            backend_fixtures=[lib.server(1, 1, b1.port, weight=1),
                     lib.server(2, 1, b2.port, weight=1)],
            listeners=[lib.listener(1, port1, 1), lib.listener(2, port2, 1)],
        )
        start_ok(h, base)
        fds0 = lib.proc_fd_count(h.pid)
        threads0 = lib.proc_thread_count(h.pid)
        errors: list[str] = []
        completed = [0]
        stop = threading.Event()
        lock = threading.Lock()

        def worker(index: int) -> None:
            port = port1 if index % 2 == 0 else port2
            iteration = 0
            while not stop.is_set() and iteration < 120:
                payload = lib.deterministic_payload(64, ctx.seed + index * 1000 + iteration)
                try:
                    received = echo_once(lib.LOOPBACK_V4, port, payload, 5.0)
                    if received != payload:
                        raise AssertionError("payload mismatch")
                    with lock:
                        completed[0] += 1
                except BaseException as exc:  # noqa: BLE001
                    with lock:
                        errors.append(f"worker {index}: {type(exc).__name__}: {exc}")
                iteration += 1

        workers = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(8)]
        for thread in workers:
            thread.start()

        generations = [snapshot(h)["generation"]]
        for index in range(10):
            candidate = copy.deepcopy(base)
            candidate.backend_fixtures[0]["weight"] = 1 + (index % 3)
            candidate.backend_fixtures[1]["weight"] = 1 + ((index + 1) % 3)
            candidate.backend_fixtures[0]["comment"] = f"sequential-{index}"
            apply_ok(h, candidate)
            current = snapshot(h)["generation"]
            require(current == generations[-1] + 1,
                    f"generation advanced {current - generations[-1]} for one "
                    f"sequential apply ({generations[-1]} -> {current})")
            generations.append(current)

        # Repeated real contenders.  Either result is legal: the Engine may
        # serialize both calls, or reject a genuinely concurrent one busy.
        # Only observable accounting/generation/config invariants are asserted.
        rounds = 20
        contenders_per_round = 4
        observed_busy = 0
        observed_overlap = 0
        concurrent_successes = 0
        for round_index in range(rounds):
            generation_before = snapshot(h)["generation"]
            candidates = []
            for index in range(contenders_per_round):
                candidate = copy.deepcopy(base)
                candidate.backend_fixtures[0]["weight"] = 1 + ((round_index + index) % 3)
                candidate.backend_fixtures[1]["weight"] = 1 + ((round_index + index + 1) % 3)
                candidate.backend_fixtures[0]["comment"] = f"round-{round_index}-c{index}"
                candidate["hostgroups"][0]["comment"] = f"round-{round_index}-c{index}"
                candidates.append(candidate)
            response = h.apply_concurrent(candidates)
            observed = check_concurrent_apply(h, response, candidates, generation_before)
            observed_busy += observed["busy"]
            observed_overlap += 1 if observed["overlapped"] else 0
            concurrent_successes += observed["successes"]

        stop.set()
        for thread in workers:
            thread.join(timeout=10.0)
        require(all(not thread.is_alive() for thread in workers),
                "admission worker threads did not exit")
        require(not errors, f"admission errors during reload: {errors[:3]}")
        require(completed[0] > 0, "no flows completed during reload")
        require(all(generations[i] < generations[i + 1]
                    for i in range(len(generations) - 1)),
                f"generation went backwards: {generations}")
        time.sleep(0.5)
        snap = wait_active(h, 0, 10.0)
        require(snap["active_connections"] == 0, "flows leaked after reload load")
        require(lib.proc_fd_count(h.pid) <= fds0 + 2,
                f"fd growth after reload load: {fds0} -> {lib.proc_fd_count(h.pid)}")
        require(lib.proc_thread_count(h.pid) <= threads0 + 1,
                "thread growth after reload load")
        return {"completed": completed[0],
                "sequential_successes": 10,
                "concurrent_rounds": rounds,
                "concurrent_contenders": rounds * contenders_per_round,
                "concurrent_successes": concurrent_successes,
                "observed_busy": observed_busy,
                "observed_wrapper_overlap": observed_overlap}


@scenario("GEN-07", "idempotent reload and repeated restart")
def gen_07(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("gen07") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, backend.port)
        start_ok(h, cfg)
        generations = [snapshot(h)["generation"]]
        for _ in range(10):
            apply_ok(h, cfg)
            generations.append(snapshot(h)["generation"])
        require(all(generations[i] < generations[i + 1] for i in range(len(generations) - 1)),
                f"idempotent apply did not advance generation monotonically: {generations}")

        fds_samples = []
        thread_samples = []
        for cycle in range(10):
            h.stop()
            time.sleep(0.05)
            fds_samples.append(lib.proc_fd_count(h.pid))
            thread_samples.append(lib.proc_thread_count(h.pid))
            start_ok(h, cfg)
            require(echo_once(lib.LOOPBACK_V4, port, f"cycle-{cycle}".encode()) ==
                    f"cycle-{cycle}".encode(), "flow failed after restart")
            snap = snapshot(h)
            require(len(lib.provider_servers(observation(h))) == 1 and
                    len(snap["listeners"]) == 1,
                    "stale product/provider rows across restart")
        h.stop()
        later_fds = fds_samples[5:]
        earlier_fds = fds_samples[:5]
        require(max(later_fds) <= max(earlier_fds) + 2,
                f"fd growth across restarts: {fds_samples}")
        require(max(thread_samples[5:]) <= max(thread_samples[:5]) + 1,
                f"thread growth across restarts: {thread_samples}")
        return {"generations": generations, "fds": fds_samples,
                "threads": thread_samples}


# ---------------------------------------------------------------------------
# RET — pending-connect retries
# ---------------------------------------------------------------------------


@scenario("RET-01", "pending connect RST then retry succeeds exactly once")
def ret_01(ctx: Context) -> dict:
    with ctx.blackhole(backlog=1) as s1, ctx.backend(mode="echo") as s2, \
            ctx.harness("ret01") as h:
        require(s1.fill(), "could not saturate S1 accept queue")
        port = lib.free_port()
        cfg = lib.config(
            hostgroups=[lib.hostgroup(1)],
            backend_fixtures=[lib.server(1, 1, s1.port, status="ONLINE"),
                     lib.server(2, 1, s2.port, status="OFFLINE_SOFT")],
            listeners=[lib.listener(1, port, 1, connect_timeout_ms=2000,
                                    max_connect_attempts=3)],
        )
        start_ok(h, cfg)
        payload = lib.deterministic_payload(32 * 1024, ctx.seed + 6100)
        client = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        client.sendall(payload)
        require(lib.wait_syn_sent(h.pid, s1.port, 5.0),
                "Engine never produced SYN_SENT to S1")
        require(not lib.proc_has_remote_port(h.pid, s2.port, lib.TCP_ESTABLISHED),
                "S2 was contacted while only S1 was eligible")

        enable = copy.deepcopy(cfg)
        lib.find_row(enable.backend_fixtures, "server_id", 2)["status"] = "ONLINE"
        apply_ok(h, enable)
        started = time.monotonic()
        s1.fail()
        received = lib.recv_exact(client, len(payload), 10.0)
        elapsed = time.monotonic() - started
        require(received == payload, "retry did not preserve payload bytes")
        require(s2.connections_total == 1,
                f"S2 accepted {s2.connections_total} connections; expected one")
        require(s1.connections_total == 0, "blackholed S1 accepted application data")
        require(elapsed <= 2.0 + 2.0,
                f"retry took {elapsed:.3f}s beyond connect budget plus grace")
        snap = snapshot(h)
        require(snap["connect_errors"] >= 1, "connect error not counted")
        require(not lib.proc_has_remote_port(h.pid, s1.port, lib.TCP_SYN_SENT),
                "SYN_SENT to S1 remained after retry")
        close_quietly(client)
        return {"retry_elapsed_s": round(elapsed, 3),
                "s2_connections": s2.connections_total}


@scenario("RET-02", "pending connect consumes total budget and fails closed")
def ret_02(ctx: Context) -> dict:
    with ctx.blackhole(backlog=1) as s1, ctx.harness("ret02") as h:
        require(s1.fill(), "could not saturate blackhole accept queue")
        port = lib.free_port()
        cfg = lib.simple_config(
            port, s1.port,
            settings_row=lib.settings(max_connections=10),
            listener_overrides={"connect_timeout_ms": 400,
                                "max_connect_attempts": 3,
                                "idle_timeout_ms": 0},
            server_overrides={"max_connections": 10},
        )
        start_ok(h, cfg)
        client = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        client.sendall(lib.deterministic_payload(8 * 1024, ctx.seed + 6200))
        require(lib.wait_syn_sent(h.pid, s1.port, 3.0),
                "no SYN_SENT observed before budget expiry")
        started = time.monotonic()
        try:
            received = lib.recv_until_eof_or_reset(client, 5.0)
        except TimeoutError:
            snap = snapshot(h)
            states = [row for row in lib.proc_socket_states(h.pid)
                      if row["remote_port"] == s1.port]
            raise AssertionError(
                "connect_timeout_ms=400 was not enforced: client still open after 5s "
                f"(active={snap.get('active_connections')}, "
                f"connect_errors={snap.get('connect_errors')}, sockets={states})") from None
        elapsed = time.monotonic() - started
        require(received == b"", f"partial application bytes delivered: {len(received)}")
        require(elapsed <= 0.4 + 2.0,
                f"failure took {elapsed:.3f}s beyond 400ms budget plus grace")
        snap = wait_active(h, 0, 5.0)
        require(snap["connect_errors"] >= 1, "connect error not counted")
        require(not lib.proc_has_remote_port(h.pid, s1.port, lib.TCP_SYN_SENT),
                "SYN_SENT remained after budget expiry")
        close_quietly(client)
        return {"failure_elapsed_s": round(elapsed, 3)}


@scenario("RET-03", "all candidates pending: bounded exhaustion and release")
def ret_03(ctx: Context) -> dict:
    with ctx.blackhole(backlog=1) as s1, ctx.blackhole(backlog=1) as s2, \
            ctx.harness("ret03") as h:
        require(s1.fill(), "could not saturate S1 accept queue")
        require(s2.fill(), "could not saturate S2 accept queue")
        port = lib.free_port()
        cfg = lib.config(
            hostgroups=[lib.hostgroup(1)],
            backend_fixtures=[lib.server(1, 1, s1.port), lib.server(2, 1, s2.port)],
            listeners=[lib.listener(1, port, 1, connect_timeout_ms=800,
                                    max_connect_attempts=3, idle_timeout_ms=0)],
        )
        start_ok(h, cfg)
        client = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        client.sendall(lib.deterministic_payload(8 * 1024, ctx.seed + 6300))
        require(lib.wait_syn_sent(h.pid, s1.port, 3.0) or
                lib.wait_syn_sent(h.pid, s2.port, 3.0),
                "no SYN_SENT observed to either blackhole")
        started = time.monotonic()
        try:
            received = lib.recv_until_eof_or_reset(client, 6.0)
        except TimeoutError:
            snap = snapshot(h)
            states = [row for row in lib.proc_socket_states(h.pid)
                      if row["remote_port"] in (s1.port, s2.port)]
            raise AssertionError(
                "connect_timeout_ms=800 was not enforced: client still open after 6s "
                f"(active={snap.get('active_connections')}, "
                f"connect_errors={snap.get('connect_errors')}, sockets={states})") from None
        elapsed = time.monotonic() - started
        require(received == b"", "application bytes delivered to blackhole")
        require(elapsed <= 0.8 + 2.0,
                f"exhaustion took {elapsed:.3f}s beyond budget plus grace")
        snap = wait_active(h, 0, 5.0)
        require(snap["connect_errors"] <= 3,
                f"connect attempts exceeded max_connect_attempts: {snap['connect_errors']}")
        require(not lib.proc_has_remote_port(h.pid, s1.port, lib.TCP_SYN_SENT) and
                not lib.proc_has_remote_port(h.pid, s2.port, lib.TCP_SYN_SENT),
                "SYN_SENT remained after exhaustion")
        # Capacity released: the next client is admitted (then fails again).
        first = admission_probe(lib.LOOPBACK_V4, port, 3.0)
        require(first in ("closed", "reset", "timeout"),
                f"next client unexpectedly echoed: {first}")
        wait_active(h, 0, 5.0)
        close_quietly(client)
        return {"failure_elapsed_s": round(elapsed, 3), "connect_errors": snap["connect_errors"]}


@scenario("RET-04", "pending connect succeeds late; no retry after establishment")
def ret_04(ctx: Context) -> dict:
    with ctx.blackhole(backlog=1) as s1, ctx.backend(mode="echo") as s2, \
            ctx.harness("ret04") as h:
        require(s1.fill(), "could not saturate S1 accept queue")
        port = lib.free_port()
        cfg = lib.config(
            hostgroups=[lib.hostgroup(1)],
            backend_fixtures=[lib.server(1, 1, s1.port, status="ONLINE"),
                     lib.server(2, 1, s2.port, status="OFFLINE_SOFT")],
            listeners=[lib.listener(1, port, 1, connect_timeout_ms=3000,
                                    max_connect_attempts=3)],
        )
        start_ok(h, cfg)
        payload = lib.deterministic_payload(8 * 1024, ctx.seed + 6400)
        client = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        client.sendall(payload)
        require(lib.wait_syn_sent(h.pid, s1.port, 5.0),
                "no SYN_SENT observed to late-accept endpoint")
        s1.start_accepting(echo=True)
        received = lib.recv_exact(client, len(payload), 10.0)
        require(received == payload, "late connect did not deliver exact payload")
        require(s2.connections_total == 0,
                f"S2 received {s2.connections_total} connections despite S1 success")
        require(s1.bytes_c2s >= len(payload),
                "S1 did not receive the application payload exactly once")
        close_quietly(client)
        return {"s1_bytes": s1.bytes_c2s, "s2_connections": s2.connections_total}


@scenario("RET-05", "no client bytes read/replayed while pending; half-close")
def ret_05(ctx: Context) -> dict:
    with ctx.blackhole(backlog=1) as s1, ctx.backend(mode="echo") as s2, \
            ctx.harness("ret05") as h:
        require(s1.fill(), "could not saturate S1 accept queue")
        port = lib.free_port()
        cfg = lib.config(
            hostgroups=[lib.hostgroup(1)],
            backend_fixtures=[lib.server(1, 1, s1.port, status="ONLINE"),
                     lib.server(2, 1, s2.port, status="OFFLINE_SOFT")],
            listeners=[lib.listener(1, port, 1, connect_timeout_ms=3000,
                                    max_connect_attempts=3)],
        )
        start_ok(h, cfg)
        payload = lib.deterministic_payload(64 * 1024, ctx.seed + 6500)
        client = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        require(lib.wait_syn_sent(h.pid, s1.port, 5.0),
                "no SYN_SENT observed while holding 64 KiB pending")
        require(s1.bytes_c2s == 0, "blackhole delivered application bytes while pending")

        enable = copy.deepcopy(cfg)
        lib.find_row(enable.backend_fixtures, "server_id", 2)["status"] = "ONLINE"
        apply_ok(h, enable)
        s1.fail()
        received = lib.recv_until_eof(client, 10.0)
        require(received == payload, "half-closed retry payload mismatch or truncation")
        require(s2.bytes_c2s == len(payload),
                f"S2 received {s2.bytes_c2s}/{len(payload)} bytes")
        require(s2.eof_total == 1, "client half-close was not forwarded as EOF")
        close_quietly(client)
        return {"bytes": len(payload)}


# ---------------------------------------------------------------------------
# LIFE — bounded lifecycle
# ---------------------------------------------------------------------------


@scenario("LIFE-01", "bounded stop with active, pending and half-closed flows")
def life_01(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as echo, ctx.blackhole(backlog=1) as blackhole, \
            ctx.backend(mode="half_close_silent") as silent, ctx.harness("life01") as h:
        require(blackhole.fill(), "could not saturate blackhole queue")
        echo_port, pending_port, half_port = lib.free_port(), lib.free_port(), lib.free_port()
        cfg = lib.config(
            settings_row=lib.settings(shutdown_timeout_ms=300, max_connections=100),
            hostgroups=[lib.hostgroup(1), lib.hostgroup(2), lib.hostgroup(3)],
            backend_fixtures=[lib.server(1, 1, echo.port), lib.server(2, 2, blackhole.port),
                     lib.server(3, 3, silent.port)],
            listeners=[lib.listener(1, echo_port, 1), lib.listener(2, pending_port, 2),
                       lib.listener(3, half_port, 3)],
        )
        start_ok(h, cfg)
        fds0 = lib.proc_fd_count(h.pid)
        threads0 = lib.proc_thread_count(h.pid)
        established = [open_flow(lib.LOOPBACK_V4, echo_port, 32, 6600 + i) for i in range(30)]
        pending = []
        for _ in range(5):
            sock = lib.connect_socket(lib.LOOPBACK_V4, pending_port, 5.0)
            sock.sendall(b"pending")
            pending.append(sock)
        require(lib.wait_syn_sent(h.pid, blackhole.port, 5.0),
                "pending flows did not reach SYN_SENT")
        half_closed = []
        for _ in range(5):
            sock = lib.connect_socket(lib.LOOPBACK_V4, half_port, 5.0)
            sock.sendall(b"half")
            sock.shutdown(socket.SHUT_WR)
            half_closed.append(sock)

        started = time.monotonic()
        h.stop(timeout=10.0)
        elapsed = time.monotonic() - started
        require(elapsed <= 0.3 + 1.0 + 0.5,
                f"stop took {elapsed:.3f}s for 300ms shutdown timeout")
        repeated_start = time.monotonic()
        h.stop(timeout=5.0)
        require(time.monotonic() - repeated_start < 1.0, "repeated stop not prompt")
        for sock in established + pending + half_closed:
            try:
                lib.wait_until_closed(sock, 2.0)
            except TimeoutError:
                raise AssertionError("client socket still open after stop")
            finally:
                close_quietly(sock)
        require(not lib.try_connect(lib.LOOPBACK_V4, echo_port, 0.3),
                "listener accepted after stop returned")
        time.sleep(0.3)
        require(lib.proc_fd_count(h.pid) <= fds0 + 2,
                f"fd leak after stop: {fds0} -> {lib.proc_fd_count(h.pid)}")
        require(lib.proc_thread_count(h.pid) <= threads0 + 1,
                f"thread leak after stop: {threads0} -> {lib.proc_thread_count(h.pid)}")
        return {"stop_s": round(elapsed, 3), "flows": 40}


@scenario("LIFE-02", "failed start, repeated stop and restart")
def life_02(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("life02") as h:
        port = lib.free_port()
        invalid = lib.simple_config(port, backend.port)
        invalid.backend_fixtures[0]["hostname"] = "not-an-address"
        response = h.start(invalid)
        require(not response.get("ok"), "invalid start succeeded")
        require(snapshot(h)["running"] is False, "running after failed start")
        fds0 = lib.proc_fd_count(h.pid)
        threads0 = lib.proc_thread_count(h.pid)

        cfg = lib.simple_config(port, backend.port)
        start_ok(h, cfg)
        require(echo_once(lib.LOOPBACK_V4, port, b"first") == b"first", "first flow failed")
        h.stop()
        h.stop()
        fds1 = lib.proc_fd_count(h.pid)
        threads1 = lib.proc_thread_count(h.pid)
        require(fds1 <= fds0 + 2, f"fd leak after repeated stop: {fds0} -> {fds1}")
        require(threads1 <= threads0 + 1,
                f"thread leak after repeated stop: {threads0} -> {threads1}")
        start_ok(h, cfg)
        require(echo_once(lib.LOOPBACK_V4, port, b"second") == b"second",
                "flow failed after restart")
        h.stop()
        return {"fds": [fds0, fds1], "threads": [threads0, threads1]}


@scenario("LIFE-03", "listener socket ownership after stop")
def life_03(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("life03") as h:
        port = lib.free_port()
        cfg = lib.simple_config(port, backend.port)
        start_ok(h, cfg)
        client = lib.connect_socket(lib.LOOPBACK_V4, port, 5.0)
        client.sendall(b"before-stop")
        require(lib.recv_exact(client, 11, 3.0) == b"before-stop", "pre-stop flow failed")
        connections_before = backend.connections_total
        h.stop()
        close_quietly(client)

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((lib.LOOPBACK_V4, port))
            probe.listen(8)
        finally:
            probe.close()
        require(lib.try_connect(lib.LOOPBACK_V4, port, 0.3) is False,
                "connection reached a stopped Engine listener")
        require(backend.connections_total == connections_before,
                "Engine accepted a new flow after stop")
        return {"rebind": "ok", "connections": backend.connections_total}


# ---------------------------------------------------------------------------
# LEAK — repeated lifecycle audit
# ---------------------------------------------------------------------------


@scenario("LEAK-01", "repeated start/apply/failed-apply/hard-offline/stop audit")
def leak_01(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as echo, ctx.squatter() as squatter, \
            ctx.harness("leak01") as h:
        baseline_fds = lib.proc_fd_count(h.pid)
        baseline_threads = lib.proc_thread_count(h.pid)
        samples: list[dict] = []

        for cycle in range(20):
            blackhole = lib.Blackhole(backlog=1)
            try:
                require(blackhole.fill(), "could not saturate blackhole queue")
                l1, l2 = lib.free_port(), lib.free_port()
                cfg = lib.config(
                    settings_row=lib.settings(max_connections=100),
                    hostgroups=[lib.hostgroup(1), lib.hostgroup(2)],
                    backend_fixtures=[lib.server(1, 1, echo.port),
                             lib.server(2, 2, blackhole.port)],
                    listeners=[lib.listener(1, l1, 1), lib.listener(2, l2, 2)],
                )
                start_ok(h, cfg)
                flows = [open_flow(lib.LOOPBACK_V4, l1, 32, 7000 + cycle * 10 + i)
                         for i in range(5)]
                changed = copy.deepcopy(cfg)
                changed.backend_fixtures[0]["weight"] = 2 + (cycle % 3)
                apply_ok(h, changed)
                extra = [open_flow(lib.LOOPBACK_V4, l1, 32, 7100 + cycle * 10 + i)
                         for i in range(5)]
                failed = copy.deepcopy(changed)
                failed["listeners"].append(lib.listener(9, squatter.port, 1))
                apply_fail(h, failed)

                pending = lib.connect_socket(lib.LOOPBACK_V4, l2, 5.0)
                pending.sendall(b"pending")
                require(lib.wait_syn_sent(h.pid, blackhole.port, 5.0),
                        "pending flow missing in leak cycle")
                hard = copy.deepcopy(cfg)
                lib.find_row(hard.backend_fixtures, "server_id", 1)["status"] = "OFFLINE_HARD"
                lib.find_row(hard.backend_fixtures, "server_id", 2)["status"] = "OFFLINE_HARD"
                apply_ok(h, hard)
                close_quietly(*flows, *extra, pending)
                h.stop()
                time.sleep(0.25)
                samples.append({
                    "cycle": cycle,
                    "fds": lib.proc_fd_count(h.pid),
                    "threads": lib.proc_thread_count(h.pid),
                    "snapshot_active": snapshot(h)["active_connections"],
                })
            finally:
                blackhole.stop()

        empty = lib.config(settings_row=lib.settings())
        for cycle in range(10):
            start_ok(h, empty)
            h.stop()
            time.sleep(0.05)
            samples.append({
                "cycle": 20 + cycle,
                "fds": lib.proc_fd_count(h.pid),
                "threads": lib.proc_thread_count(h.pid),
                "empty": True,
            })

        running_fds = [row["fds"] for row in samples[:20]]
        require(max(running_fds[15:]) <= max(running_fds[:5]) + 2,
                f"fd growth in later cycles: {running_fds}")
        require(max(row["threads"] for row in samples[15:20]) <=
                max(row["threads"] for row in samples[:5]) + 1,
                f"thread growth in later cycles: {[r['threads'] for r in samples[:20]]}")
        final_fds = lib.proc_fd_count(h.pid)
        require(final_fds <= baseline_fds + 2,
                f"post-stop fds {final_fds} exceed baseline {baseline_fds} + 2")
        require(lib.proc_thread_count(h.pid) <= baseline_threads + 1,
                "threads exceeded baseline after leak audit")
        return {"baseline_fds": baseline_fds, "baseline_threads": baseline_threads,
                "samples": samples}


# ---------------------------------------------------------------------------
# RACE — concurrent operations
# ---------------------------------------------------------------------------


@scenario("RACE-01", "apply versus stop")
def race_01(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("race01") as h:
        port = lib.free_port()
        base = lib.simple_config(port, backend.port)
        baseline_fds = lib.proc_fd_count(h.pid)
        baseline_threads = lib.proc_thread_count(h.pid)
        outcomes = []
        for iteration in range(10):
            start_ok(h, base)
            held = open_flow(lib.LOOPBACK_V4, port, 32, 8000 + iteration)
            candidate = copy.deepcopy(base)
            candidate.backend_fixtures[0]["weight"] = 1 + iteration
            response = h.apply_stop_race(candidate, timeout=15.0)
            require(response.get("ok"), f"race request failed: {response.get('error')}")
            apply_result = response["apply"]
            outcomes.append({
                "iteration": iteration,
                "apply_ok": apply_result["ok"],
                "apply_busy": apply_result["busy"],
                "apply_error": apply_result["error"],
                "apply_interval": [apply_result["start_us"], apply_result["end_us"]],
                "stop_interval": [response["stop"]["start_us"], response["stop"]["end_us"]],
            })
            snap = response["snapshot"]
            require(snap["running"] is False,
                    "engine reported running after apply/stop race")
            close_quietly(held)
            h.stop(timeout=5.0)
        require(lib.proc_fd_count(h.pid) <= baseline_fds + 2,
                "fd growth after apply/stop race")
        require(lib.proc_thread_count(h.pid) <= baseline_threads + 2,
                "thread growth after apply/stop race")
        return {"iterations": 10, "outcomes": outcomes}


@scenario("RACE-02", "concurrent apply ordering and final configuration")
def race_02(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as backend, ctx.harness("race02") as h:
        port = lib.free_port()
        base = lib.simple_config(port, backend.port)
        start_ok(h, base)

        rounds = 20
        contenders_per_round = 4
        total_successes = 0
        total_busy = 0
        total_overlap = 0
        for round_index in range(rounds):
            generation_before = snapshot(h)["generation"]
            candidates = []
            for index in range(contenders_per_round):
                candidate = copy.deepcopy(base)
                candidate.backend_fixtures[0]["weight"] = 1 + ((round_index + index) % 7)
                candidate.backend_fixtures[0]["comment"] = f"round-{round_index}-c{index}"
                candidate["hostgroups"][0]["comment"] = f"round-{round_index}-c{index}"
                candidates.append(candidate)
            response = h.apply_concurrent(candidates)
            observed = check_concurrent_apply(h, response, candidates, generation_before)
            final = h.config()["config"]
            winner = next(candidate for candidate in candidates
                          if lib.product_config(candidate) == final)
            actual = h.provider_snapshot()["servers"]
            require(len(actual) == 1 and actual[0]["weight"] == winner.backend_fixtures[0]["weight"],
                    "provider fixtures do not match the actual final Engine Config")
            total_successes += observed["successes"]
            total_busy += observed["busy"]
            total_overlap += 1 if observed["overlapped"] else 0

        # Explicit sequential A then B: publication order is directly defined
        # by call order and must be reflected by generation and final Config.
        cand_a = copy.deepcopy(base)
        cand_a.backend_fixtures[0]["weight"] = 3
        cand_a.backend_fixtures[0]["comment"] = "candidate-A"
        cand_a["hostgroups"][0]["comment"] = "candidate-A"
        cand_b = copy.deepcopy(base)
        cand_b.backend_fixtures[0]["weight"] = 7
        cand_b.backend_fixtures[0]["comment"] = "candidate-B"
        cand_b["hostgroups"][0]["comment"] = "candidate-B"

        before = snapshot(h)["generation"]
        apply_ok(h, cand_a)
        middle = snapshot(h)["generation"]
        require(middle == before + 1,
                f"sequential A advanced generation {middle - before} times")
        require(h.config(timeout=10.0)["config"] == lib.product_config(cand_a),
                "sequential A did not become the complete effective product config")
        apply_ok(h, cand_b)
        after = snapshot(h)["generation"]
        require(after == middle + 1,
                f"sequential B advanced generation {after - middle} times")
        final = h.config(timeout=10.0)["config"]
        require(final == lib.product_config(cand_b),
                "sequential B was overwritten or published partially: "
                f"hostgroup_comment={final.get('hostgroups', [{}])[0].get('comment')!r}")
        require(len(final["hostgroups"]) == 1 and len(final["listeners"]) == 1,
                "partial product rows after concurrent/sequential applies")
        return {"rounds": rounds,
                "contenders": rounds * contenders_per_round,
                "successes": total_successes,
                "busy": total_busy,
                "observed_wrapper_overlap": total_overlap,
                "sequential_generation": [before, middle, after],
                "final": final["hostgroups"][0]["comment"]}


@scenario("RACE-03", "admission during repeated policy activation")
def race_03(ctx: Context) -> dict:
    with ctx.backend(mode="echo") as b1, ctx.backend(mode="echo") as b2, \
            ctx.harness("race03") as h:
        port1, port2 = lib.free_port(), lib.free_port()
        base = lib.config(
            hostgroups=[lib.hostgroup(1)],
            backend_fixtures=[lib.server(1, 1, b1.port, weight=1),
                     lib.server(2, 1, b2.port, weight=1)],
            listeners=[lib.listener(1, port1, 1), lib.listener(2, port2, 1)],
        )
        start_ok(h, base)
        baseline_fds = lib.proc_fd_count(h.pid)
        baseline_threads = lib.proc_thread_count(h.pid)
        stop = threading.Event()
        completed = [0]
        errors: list[str] = []
        lock = threading.Lock()

        def worker(index: int) -> None:
            iteration = 0
            while not stop.is_set() and iteration < 200:
                port = port1 if index % 2 == 0 else port2
                payload = lib.deterministic_payload(1024, ctx.seed + 9000 + index * 100 + iteration)
                try:
                    received = echo_once(lib.LOOPBACK_V4, port, payload, 5.0)
                    if received != payload:
                        raise AssertionError("byte mismatch")
                    with lock:
                        completed[0] += 1
                except BaseException as exc:  # noqa: BLE001
                    with lock:
                        errors.append(f"{type(exc).__name__}: {exc}")
                iteration += 1

        workers = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(20)]
        for thread in workers:
            thread.start()
        deadline = time.monotonic() + 2.0
        applied = 0
        while time.monotonic() < deadline and applied < 50:
            candidate = copy.deepcopy(base)
            candidate.backend_fixtures[0]["weight"] = 1 + (applied % 4)
            candidate.backend_fixtures[1]["weight"] = 1 + ((applied + 1) % 4)
            if applied % 2 == 0:
                candidate["rules"] = [lib.rule(1, active=1, action="ROUTE",
                                               destination_hostgroup=1)]
            response = h.apply(candidate)
            if response["ok"]:
                applied += 1
        stop.set()
        for thread in workers:
            thread.join(timeout=10.0)
        require(completed[0] > 0, "no admissions completed under activation load")
        require(not errors, f"admission errors under policy activation: {errors[:3]}")
        time.sleep(0.5)
        snap = wait_active(h, 0, 10.0)
        require(snap["active_connections"] == 0, "connections leaked after race load")
        require(lib.proc_fd_count(h.pid) <= baseline_fds + 2,
                "fd growth after admission/activation race")
        require(lib.proc_thread_count(h.pid) <= baseline_threads + 2,
                "thread growth after admission/activation race")
        return {"completed": completed[0], "applies": applied}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _alarm_handler(signum, frame):  # noqa: ARG001
    raise TimeoutError("scenario wall-clock deadline exceeded")


def run_scenario(sid: str, ctx_factory, results_dir: Path, scenario_timeout: float) -> dict:
    meta = SCENARIOS[sid]
    ctx = ctx_factory(sid)
    started = time.monotonic()
    status = "FAIL"
    detail = ""
    payload: dict = {}
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, scenario_timeout)
    try:
        result = meta["func"](ctx)
        status = "PASS"
        payload = result or {}
        detail = "ok"
    except Blocked as exc:
        status = "BLOCKED"
        detail = str(exc)
    except Inconclusive as exc:
        status = "INCONCLUSIVE"
        detail = str(exc)
    except TimeoutError as exc:
        status = "FAIL"
        detail = f"timeout: {exc}"
    except BaseException as exc:  # noqa: BLE001 - record and continue
        status = "FAIL"
        detail = f"{type(exc).__name__}: {exc}"
        payload = {"traceback": traceback.format_exc()}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
    elapsed = time.monotonic() - started
    row = {
        "scenario": sid,
        "description": meta["description"],
        "status": status,
        "detail": detail,
        "duration_s": round(elapsed, 3),
        "seed": ctx.seed,
        "reproduce": f"cd {Path(__file__).resolve().parent} && "
                     f"python3 test_engine_adversarial.py --scenarios {sid} "
                     f"--seed {ctx.seed}",
    }
    row.update(payload)
    path = results_dir / f"{sid}.json"
    path.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", default=HARNESS_DEFAULT)
    parser.add_argument("--scenarios", default="",
                        help="comma-separated IDs or prefixes (default: all)")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--results-dir", default=RESULTS_DEFAULT)
    parser.add_argument("--seed", type=int, default=20261111)
    parser.add_argument("--timeout", type=float, default=180.0,
                        help="per-scenario wall-clock deadline")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.list:
        for sid in sorted(SCENARIOS):
            print(f"{sid}: {SCENARIOS[sid]['description']}")
        return 0
    if not lib.harness_available(args.harness):
        print(f"harness not built or not executable: {args.harness}", file=sys.stderr)
        print("build with: make -f Makefile.integration harness", file=sys.stderr)
        return 2

    selected = sorted(SCENARIOS)
    if args.scenarios:
        wanted = [item.strip() for item in args.scenarios.split(",") if item.strip()]
        selected = [sid for sid in selected
                    if any(sid == item or sid.startswith(item + "-") for item in wanted)]
        missing = [item for item in wanted
                   if not any(sid == item or sid.startswith(item + "-") for sid in SCENARIOS)]
        if missing:
            print(f"unknown scenario selector(s): {missing}", file=sys.stderr)
            return 2

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    harness_header_sha256 = ""
    try:
        with lib.HarnessClient(args.harness) as probe:
            harness_header_sha256 = probe.ping(timeout=5.0).get("header_sha256", "")
    except (OSError, lib.HarnessError, TimeoutError) as exc:
        pass
    run_context = {
        "harness_header_sha256": harness_header_sha256,
        "harness_sha256": _sha256_file(args.harness),
        "python": sys.version,
        "seed": args.seed,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    (results_dir / "run-context.json").write_text(
        json.dumps(run_context, indent=2) + "\n", encoding="utf-8")

    def ctx_factory(sid: str) -> Context:
        return Context(args.harness, results_dir, args.seed, args.verbose, sid)

    rows = []
    for sid in selected:
        print(f"[RUN ] {sid}: {SCENARIOS[sid]['description']}", flush=True)
        row = run_scenario(sid, ctx_factory, results_dir, args.timeout)
        rows.append(row)
        print(f"[{row['status']:^5}] {sid}: {row['detail']} ({row['duration_s']}s)",
              flush=True)

    summary = {
        "kind": "adversarial-engine-suite",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "harness": os.path.abspath(args.harness),
        "harness_sha256": _sha256_file(args.harness),
        "harness_header_sha256": harness_header_sha256,
        "python": sys.version,
        "seed": args.seed,
        "scenarios": rows,
        "counts": {
            "PASS": sum(1 for row in rows if row["status"] == "PASS"),
            "FAIL": sum(1 for row in rows if row["status"] == "FAIL"),
            "BLOCKED": sum(1 for row in rows if row["status"] == "BLOCKED"),
            "INCONCLUSIVE": sum(1 for row in rows if row["status"] == "INCONCLUSIVE"),
        },
    }
    summary_path = results_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"\nsummary: {summary['counts']}")
    print(f"results: {summary_path}")
    return 1 if summary["counts"]["FAIL"] else 0


def _sha256_file(path: str) -> str:
    import hashlib
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


if __name__ == "__main__":
    sys.exit(main())
