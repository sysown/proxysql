#!/usr/bin/env python3
"""Gate 1 fixture self-checks, independent of the production Engine.

Exercises payload generation, loopback v4/v6 availability, every backend mode,
backlog saturation with verified pending state, port allocation, /proc helpers
and JSON configuration builders.  No harness/Engine is started.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import socket
import sys
import tempfile
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

import tcp_proxy_testlib as lib

RESULTS: list[dict] = []


class Blocked(Exception):
    """Required environment condition could not be created."""


class Inconclusive(Exception):
    """Condition exists but the required observation is not reliable."""


def record(name: str, status: str, detail: str = "", extra: dict | None = None) -> None:
    row = {"name": name, "status": status, "detail": detail}
    if extra:
        row.update(extra)
    RESULTS.append(row)
    print(f"[{status}] {name}: {detail}")


def case(name: str):
    def decorator(func):
        try:
            detail = func()
            record(name, "PASS", detail or "")
        except Blocked as exc:
            record(name, "BLOCKED", str(exc))
        except Inconclusive as exc:
            record(name, "INCONCLUSIVE", str(exc))
        except Exception as exc:  # noqa: BLE001 - report, continue independent cases
            record(name, "FAIL", f"{type(exc).__name__}: {exc}",
                   {"traceback": traceback.format_exc()})
        return func
    return decorator


@case("payload-deterministic")
def payload_deterministic() -> str:
    first = lib.deterministic_payload(65536, 1234)
    second = lib.deterministic_payload(65536, 1234)
    assert first == second
    assert lib.deterministic_payload(65536, 1235) != first
    assert len(first) == 65536
    assert set(first[:256]) == set(range(256))
    assert b"\x00" * 32 in first
    assert b"\xff" * 32 in first
    return f"sha256={lib.sha256_bytes(first)}"


@case("port-allocator")
def port_allocator() -> str:
    port = lib.free_port()
    assert 1 <= port <= 65535
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((lib.LOOPBACK_V4, port))
    finally:
        sock.close()
    return f"port={port}"


@case("ipv6-loopback")
def ipv6_loopback() -> str:
    if not lib.ipv6_available():
        raise Blocked("IPv6 loopback unavailable")
    with lib.Backend(host=lib.LOOPBACK_V6) as backend:
        with lib.connect_socket(lib.LOOPBACK_V6, backend.port) as client:
            payload = b"ipv6-echo\x00\xff"
            client.sendall(payload)
            assert lib.recv_exact(client, len(payload), 2.0) == payload
    return "IPv6 echo ok"


@case("echo-backpressure-friendly")
def echo_backend() -> str:
    with lib.Backend(mode="echo") as backend:
        with lib.connect_socket(lib.LOOPBACK_V4, backend.port) as client:
            payload = lib.deterministic_payload(2 * 1024 * 1024, 7)
            client.sendall(payload)
            received = lib.recv_exact(client, len(payload), 10.0)
            assert received == payload
    assert backend.connections_total == 1
    assert backend.bytes_c2s == len(payload)
    return f"2MiB exact, sha256={lib.sha256_bytes(payload)}"


@case("greeting-backend")
def greeting_backend() -> str:
    greeting = b"\x00GREETING\xff" * 4
    with lib.Backend(mode="greeting", greeting=greeting) as backend:
        with lib.connect_socket(lib.LOOPBACK_V4, backend.port) as client:
            assert lib.recv_exact(client, len(greeting), 2.0) == greeting
            client.sendall(b"request")
            assert lib.recv_exact(client, 7, 2.0) == b"request"
    return f"greeting={len(greeting)} bytes"


@case("half-close-response")
def half_close_response() -> str:
    response = lib.deterministic_payload(256 * 1024, 11)
    with lib.Backend(mode="half_close", response=response,
                     half_close_delay=0.05) as backend:
        with lib.connect_socket(lib.LOOPBACK_V4, backend.port) as client:
            request = lib.deterministic_payload(128 * 1024, 12)
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            received = lib.recv_until_eof(client, 10.0)
            assert received == response
    assert backend.bytes_c2s == len(request)
    assert backend.eof_total == 1
    return f"request={len(request)} response={len(response)}"


@case("half-close-silent-response")
def half_close_silent_response() -> str:
    request = lib.deterministic_payload(32 * 1024, 14)
    with lib.Backend(mode="half_close_silent") as backend:
        with lib.connect_socket(lib.LOOPBACK_V4, backend.port) as client:
            client.settimeout(0.5)
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            try:
                received = client.recv(1024)
            except socket.timeout:
                received = b""
            assert received == b""
    assert backend.bytes_c2s == len(request)
    return f"request={len(request)} response=0 (silent)"


@case("reverse-half-close")
def reverse_half_close() -> str:
    response = lib.deterministic_payload(64 * 1024, 21)
    with lib.Backend(mode="reverse_half_close", response=response) as backend:
        with lib.connect_socket(lib.LOOPBACK_V4, backend.port) as client:
            assert lib.recv_exact(client, len(response), 5.0) == response
            assert client.recv(1) == b""  # peer SHUT_WR reached client
            request = lib.deterministic_payload(32 * 1024, 22)
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            assert backend.wait_bytes_c2s(len(request), 5.0)
    return f"response={len(response)} request={len(request)}"


@case("sink-and-close-after-first")
def sink_and_close_after_first() -> str:
    with lib.Backend(mode="sink") as backend:
        with lib.connect_socket(lib.LOOPBACK_V4, backend.port) as client:
            client.sendall(b"discard-me" * 1000)
            assert backend.wait_bytes_c2s(10000, 3.0)
    with lib.Backend(mode="close_after_first") as backend:
        with lib.connect_socket(lib.LOOPBACK_V4, backend.port) as client:
            client.sendall(b"x")
            lib.wait_until_closed(client, 3.0)
    return "sink and close-after-first ok"


@case("paused-backend")
def paused_backend() -> str:
    with lib.Backend(mode="echo", pause_read=0.3) as backend:
        with lib.connect_socket(lib.LOOPBACK_V4, backend.port) as client:
            client.sendall(b"paused")
            assert backend.wait_connections(1, 1.0)
            time.sleep(0.1)
            assert backend.bytes_c2s == 0, "backend consumed bytes during pause_read"
            assert lib.recv_exact(client, 6, 3.0) == b"paused"
    return "pause_read observed"


@case("backlog-saturation")
def backlog_saturation() -> str:
    blackhole = lib.Blackhole(backlog=1)
    try:
        assert blackhole.fill(), "could not fill accept queue"
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.setblocking(False)
        try:
            rc = probe.connect_ex((lib.LOOPBACK_V4, blackhole.port))
            assert rc in (0, 101, 115), f"unexpected connect_ex {rc}"
            _, writable, _ = select.select([], [probe], [], 0.3)
            if writable:
                raise Blocked("probe connected; kernel did not keep queue saturated")
            assert lib.proc_has_remote_port(os.getpid(), blackhole.port, lib.TCP_SYN_SENT), \
                "no SYN_SENT socket observed for saturated backlog"
            blackhole.start_accepting(echo=True)
            _, writable, _ = select.select([], [probe], [], 3.0)
            assert writable, "pending connect did not complete after accept started"
            error = probe.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            assert error == 0, f"pending connect failed: errno {error}"
            probe_port = probe.getsockname()[1]
            assert lib.wait_for(lambda: probe_port in blackhole.accepted_peer_ports(),
                                2.0, interval=0.02,
                                description="blackhole accepted the probe"), (
                f"accepted peer ports do not include probe source port {probe_port}: "
                f"{blackhole.accepted_peer_ports()}")
        finally:
            probe.close()
        return "verified SYN_SENT then late accept; accepted source port attributed"
    finally:
        blackhole.stop()


@case("squatter")
def squatter() -> str:
    with lib.Squatter() as squatter:
        second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            second.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                second.bind((lib.LOOPBACK_V4, squatter.port))
            except OSError:
                pass
            else:
                raise AssertionError("second bind unexpectedly succeeded")
        finally:
            second.close()
    return "exclusive bind preserved"


@case("proc-helpers")
def proc_helpers() -> str:
    pid = os.getpid()
    assert lib.proc_fd_count(pid) > 2
    assert lib.proc_thread_count(pid) >= 1
    assert lib.proc_rss_kb(pid) > 0
    ticks = lib.proc_cpu_ticks(pid)
    assert ticks is not None and ticks >= 0
    with lib.Backend() as backend:
        with lib.connect_socket(lib.LOOPBACK_V4, backend.port) as client:
            client.sendall(b"proc")
            assert lib.recv_exact(client, 4, 2.0) == b"proc"
            states = lib.proc_socket_states(pid)
            assert any(row["remote_port"] == backend.port and
                       row["state"] == lib.TCP_ESTABLISHED for row in states)
    return f"fds={lib.proc_fd_count(pid)} threads={lib.proc_thread_count(pid)}"


@case("config-builders")
def config_builders() -> str:
    cfg = lib.simple_config(12345, 23456, listener_overrides={"idle_timeout_ms": 0})
    assert isinstance(cfg, lib.ScenarioConfig)
    encoded = json.dumps(cfg)
    decoded = json.loads(encoded)
    assert decoded["settings"]["worker_threads"] == 2
    assert decoded["listeners"][0]["bind_port"] == 12345
    assert decoded["listeners"][0]["idle_timeout_ms"] == 0
    assert decoded["hostgroups"][0]["hostgroup_id"] == 1
    assert decoded["hostgroups"][0]["source_protocol"] == "MYSQL"
    assert decoded["hostgroups"][0]["source_hostgroup"] == 1
    assert "balance" not in decoded["hostgroups"][0]
    assert cfg.backend_fixtures[0]["port"] == 23456
    assert set(decoded) == {"settings", "hostgroups", "listeners", "rules"}
    assert "backend_fixtures" not in decoded
    product = lib.product_config(cfg)
    assert "servers" not in product and "backend_fixtures" not in product
    assert set(product) == {"settings", "hostgroups", "listeners", "rules"}
    return f"json={len(encoded)} bytes; backend_fixtures explicitly outside config"


@case("cleanup-bounded")
def cleanup_bounded() -> str:
    port = lib.free_port()
    backend = lib.Backend(port=port)
    assert lib.try_connect(lib.LOOPBACK_V4, port)
    started = time.monotonic()
    backend.stop()
    elapsed = time.monotonic() - started
    assert elapsed < 3.0, f"backend stop took {elapsed:.2f}s"
    assert not lib.try_connect(lib.LOOPBACK_V4, port, 0.2)
    return f"stop={elapsed:.3f}s"


@case("wait-snapshot-timeout")
def wait_snapshot_timeout() -> str:
    class SnapshotOnly:
        def __init__(self) -> None:
            self.calls = 0

        def snapshot(self, timeout: float | None = None) -> dict:
            self.calls += 1
            return {"generation": 7, "active_connections": 1, "running": True}

    client = SnapshotOnly()
    try:
        lib.wait_snapshot(client, lambda snapshot: False, 0.15, interval=0.02)
    except lib.SnapshotWaitTimeout as exc:
        assert exc.last_snapshot == {"generation": 7, "active_connections": 1,
                                     "running": True}, exc.last_snapshot
        text = str(exc)
        assert "last snapshot" in text and "generation" in text, text
        assert client.calls >= 1
    else:
        raise AssertionError("wait_snapshot returned despite a false predicate")
    matched = lib.wait_snapshot(client, lambda snapshot: snapshot["generation"] == 7, 0.5)
    assert matched["generation"] == 7
    import test_engine_adversarial as adversarial
    try:
        adversarial.wait_snapshot(client, lambda snapshot: False, 0.1)
    except AssertionError as exc:
        assert "last snapshot" in str(exc)
    else:
        raise AssertionError("adversarial.wait_snapshot hid a false predicate")
    return f"timeout raised after {client.calls} polls; last snapshot retained"


@case("distinct-port-allocation")
def distinct_port_allocation() -> str:
    ports = lib.free_ports(8)
    assert len(set(ports)) == 8, ports
    return f"ports={ports}"


@case("tls-fixture")
def tls_fixture() -> str:
    try:
        with tempfile.TemporaryDirectory(prefix="tcp-proxy-tls-selfcheck-") as tmp:
            material = lib.generate_test_tls_material(tmp)
            backend = lib.TlsEchoBackend(material["server_cert"],
                                         material["server_key"])
            try:
                payload = lib.deterministic_payload(128 * 1024, 31)
                raw = lib.connect_socket(lib.LOOPBACK_V4, backend.port, 5.0)
                context = lib.tls_client_context(material["ca_cert"])
                client = context.wrap_socket(raw, server_hostname="localhost")
                try:
                    client.sendall(payload)
                    received = lib.recv_exact(client, len(payload), 10.0)
                    assert received == payload, "TLS echo mismatch"
                    client.unwrap()
                finally:
                    client.close()
                assert backend.wait_connections(1, 5.0)
                assert backend.handshake_errors == 0, backend.stats()
                assert backend.bytes_c2s == len(payload), backend.stats()
            finally:
                backend.stop()
            return f"verified CA + hostname; {len(payload)} binary bytes round-tripped"
    except lib.TlsUnavailable as exc:
        raise Blocked(str(exc))


@case("backend-cleanup")
def backend_cleanup() -> str:
    backend_port, listener_port = lib.free_ports(2)
    backend = lib.Backend(mode="echo", port=backend_port)
    clients: list[socket.socket] = []
    try:
        clients = [lib.connect_socket(lib.LOOPBACK_V4, backend_port, 3.0)
                   for _ in range(4)]
        for client in clients:
            client.sendall(b"cleanup")
            assert lib.recv_exact(client, 7, 3.0) == b"cleanup"
    finally:
        for client in clients:
            client.close()
        backend.stop()
    lingering = [thread.name for thread in threading.enumerate()
                 if thread.is_alive() and thread.name.startswith(f"{backend.name}-")]
    assert not lingering, f"backend threads still alive: {lingering}"
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((lib.LOOPBACK_V4, backend_port))
        probe.listen(1)
    finally:
        probe.close()
    return f"listener {backend_port} rebindable; no backend threads remain"


@case("harness-request-deadlines")
def harness_request_deadlines() -> str:
    # An owned child that never reads stdin must not hang request or close.
    with tempfile.TemporaryDirectory(prefix="tcp-harness-stall-") as directory:
        child = Path(directory) / "stall.py"
        child.write_text("#!" + sys.executable + "\nimport time\ntime.sleep(60)\n")
        child.chmod(0o700)
        harness = lib.HarnessClient(str(child))
        errors = []
        def blocked_request():
            try:
                harness.request("blocked", timeout=0.3, data="x" * (4 * 1024 * 1024))
            except Exception as exc:
                errors.append(exc)
        writer = threading.Thread(target=blocked_request, daemon=True)
        writer.start()
        time.sleep(0.05)
        closer = threading.Thread(target=harness.close, daemon=True)
        started = time.monotonic()
        closer.start()
        closer.join(timeout=3)
        try:
            assert not closer.is_alive(), "close hung behind a full stdin pipe"
            writer.join(timeout=1)
            assert not writer.is_alive(), "stdin request exceeded its deadline"
            assert any(isinstance(exc, TimeoutError) for exc in errors), errors
            assert harness.proc.poll() is not None, "close left child alive"
        finally:
            if harness.proc.poll() is None:
                harness.proc.kill()
                harness.proc.wait(timeout=2)

        harness = lib.HarnessClient(str(child))
        try:
            harness._write_lock.acquire()
            try:
                before = time.monotonic()
                try:
                    harness.ping(timeout=0.1)
                    raise AssertionError("request ignored occupied stdin lock")
                except TimeoutError:
                    assert time.monotonic() - before < 1
                assert not harness._pending, "timed-out request leaked pending waiter"
            finally:
                harness._write_lock.release()
            harness.proc.kill()
            harness.proc.wait(timeout=2)
            try:
                harness.ping(timeout=0.2)
                raise AssertionError("dead child accepted a request")
            except (lib.HarnessError, OSError):
                pass
            assert not harness._pending, "failed pipe write leaked pending waiter"
        finally:
            harness.close()
    return f"blocked pipe cleanup {time.monotonic() - started:.2f}s; lock and dead child bounded"


@case("retired-acceptor-timeout")
def retired_acceptor_timeout() -> str:
    backend = lib.Backend(mode="echo")
    release = threading.Event()
    try:
        backend.close_listener()
        backend._accept_thread.join(timeout=2)
        assert not backend._accept_thread.is_alive()
        stale = threading.Thread(target=release.wait, daemon=True)
        stale.start()
        backend._accept_thread = stale
        try:
            backend.start_listening()
            raise AssertionError("restart accepted a live retired acceptor")
        except TimeoutError:
            assert backend._listen_sock is None, "restart opened an unserviced listener"
    finally:
        release.set()
        backend.stop()
    return "restart fails bounded before opening replacement socket"


@case("truncated-receive-is-not-rejection")
def truncated_receive_is_not_rejection() -> str:
    for payload in (b"", b"partial"):
        reader, writer = socket.socketpair()
        try:
            writer.sendall(payload)
            writer.shutdown(socket.SHUT_WR)
            try:
                lib.recv_exact(reader, 16, 1.0)
                raise AssertionError("truncated response accepted")
            except EOFError as exc:
                assert exc.received == len(payload)
        finally:
            reader.close()
            writer.close()
    return "clean rejection and partial application response remain distinguishable"


def main() -> int:
    out_dir = Path(os.environ.get("TCP_PROXY_TEST_OUT", "/tmp/native-tcp-proxy"))
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "kind": "fixture-selfcheck",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "hostname": socket.gethostname(),
        "ipv6_loopback": lib.ipv6_available(),
        "openssl": shutil.which("openssl") or "",
        "cases": RESULTS,
    }
    failures = [row for row in RESULTS if row["status"] == "FAIL"]
    blocked = [row for row in RESULTS if row["status"] == "BLOCKED"]
    payload["counts"] = {
        "PASS": sum(1 for row in RESULTS if row["status"] == "PASS"),
        "FAIL": len(failures),
        "BLOCKED": len(blocked),
        "INCONCLUSIVE": sum(1 for row in RESULTS if row["status"] == "INCONCLUSIVE"),
    }
    payload["status"] = "PASS" if not failures else "FAIL"
    path = out_dir / "test-fixture-selfcheck.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\nfixture self-check: {payload['status']} "
          f"({payload['counts']['PASS']}/{len(RESULTS)} PASS, "
          f"{payload['counts']['BLOCKED']} BLOCKED)")
    print(f"report: {path}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
