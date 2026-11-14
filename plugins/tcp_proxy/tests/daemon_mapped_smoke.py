#!/usr/bin/env python3
"""Real-daemon mapped TCP hostgroup smoke tests.

Tests are written against the approved four-table mapping SQL and ABI-18
behaviour:

  * tcp_hostgroups carries the mandatory mapping columns directly:
    hostgroup_id/source_protocol/source_hostgroup/comment.
  * exactly four configuration tables exist; tcp_servers,
    tcp_hostgroup_mappings, their runtime projections and stats_tcp_servers
    must be absent.
  * the mapped TCP hostgroup has no local server inventory; all backends come
    from the named MySQL or PostgreSQL source hostgroup.
  * protocol HGM ConnUsed/ConnFree/ConnOK/ConnERR/MaxConnUsed/Bytes counters
    are authoritative for mapped traffic.
  * monitors are disabled for pure counter tests and enabled only for the real
    role-change cases.

Missing implementation or environment is reported as BLOCKED, never PASS.
This script never implements relay logic and never edits product source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

import daemon_admin_smoke as base
import tcp_proxy_testlib as lib
import upgrade_fixtures as upgrade
from mapped_monitor_fixtures import (
    HOST,
    PROTOCOLS,
    FixtureBlocked,
    MappedDaemon,
    MysqlFixture,
    PgWireFixture,
    configure_mapped,
    require_mapping_schema,
    set_monitor_variables,
    validate_source_namespaces,
    wait_until,
)

STATS_FIELDS = ("status", "ConnUsed", "ConnFree", "ConnOK", "ConnERR",
                "MaxConnUsed", "Bytes_data_sent", "Bytes_data_recv")
HARD_CLOSE_DEADLINE_S = 0.25  # 100 ms daemon poll plus test-side scheduling slack


class Blocked(Exception):
    """A required product/environment condition is unavailable."""


class ConditionTimeout(RuntimeError):
    """A required observation did not appear; this is a test failure."""


class Case:
    def __init__(self, name, evidence_dir):
        self.name = name
        self.evidence_dir = evidence_dir
        self.checks = []
        self.failures = []
        self.blocked = []
        self.daemons = []
        self.fixtures = []
        self.details = {}

    def check(self, name, ok, detail=""):
        detail = base.clip(detail)
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            self.failures.append(f"{name}: {detail}")
        return bool(ok)

    def must(self, name, ok, detail=""):
        if not self.check(name, ok, detail):
            raise RuntimeError(f"{name}: {base.clip(detail)}")

    def block(self, reason):
        reason = base.clip(reason)
        if reason not in self.blocked:
            self.blocked.append(reason)

    def result(self):
        status = "FAIL" if self.failures else ("BLOCKED" if self.blocked else "PASS")
        return {
            "name": self.name,
            "status": status,
            "checks": self.checks,
            "failures": self.failures,
            "blocked": self.blocked,
            "details": self.details,
            "fixtures": self.fixtures,
            "evidence_dir": self.evidence_dir,
            "daemons": [d.record() for d in self.daemons],
        }


def stats_row(d, protocol, hostgroup, port):
    meta = PROTOCOLS[protocol]
    sql = (
        "SELECT COALESCE(SUM(ConnUsed),0),COALESCE(SUM(ConnFree),0),"
        "COALESCE(SUM(ConnOK),0),COALESCE(SUM(ConnERR),0),"
        "COALESCE(MAX(MaxConnUsed),0),COALESCE(SUM(Bytes_data_sent),0),"
        "COALESCE(SUM(Bytes_data_recv),0) "
        f"FROM {meta['stats']} WHERE hostgroup={hostgroup} "
        f"AND srv_host='{HOST}' AND srv_port={port}"
    )
    cp = d.query(sql)
    if cp.returncode != 0:
        raise RuntimeError(f"stats query failed: {base.clip(cp.stderr)}")
    text = cp.stdout.strip()
    if not text:
        return None
    values = [int(value) for value in text.split("\t")]
    if len(values) != 7:
        raise RuntimeError(f"unexpected aggregated stats row: {text!r}")
    row = dict(zip(STATS_FIELDS[1:], values))
    row["status"] = "aggregated"
    return row


def _rows(d, sql):
    cp = d.query(sql)
    if cp.returncode != 0:
        raise RuntimeError(f"query failed: {base.clip(cp.stderr)}")
    return [line.split("\t") for line in cp.stdout.splitlines() if line]


def wait_stats(d, protocol, hostgroup, port, predicate, description, timeout=8.0):
    deadline, row = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        row = stats_row(d, protocol, hostgroup, port)
        if row is not None and predicate(row):
            return row
        time.sleep(0.05)
    raise ConditionTimeout(f"{description}; last stats row={row}")


def runtime_row(d, protocol, hostgroup, port):
    meta = PROTOCOLS[protocol]
    sql = (
        f"SELECT status,weight,max_connections FROM {meta['runtime']} "
        f"WHERE hostgroup_id={hostgroup} AND hostname='{HOST}' AND port={port}"
    )
    cp = d.query(sql)
    if cp.returncode != 0:
        raise RuntimeError(f"runtime query failed: {base.clip(cp.stderr)}")
    text = cp.stdout.strip()
    if not text:
        return None
    status, weight, max_connections = text.split("\t")
    return {"status": status, "weight": int(weight), "max_connections": int(max_connections)}


def wait_runtime(d, protocol, hostgroup, port, predicate, description, timeout=10.0):
    deadline, row = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        row = runtime_row(d, protocol, hostgroup, port)
        if row is not None and predicate(row):
            return row
        time.sleep(0.1)
    raise ConditionTimeout(f"{description}; last runtime row={row}")


def wait_demoted(d, protocol, writer_hg, reader_hg, port, timeout=20.0):
    """A retired writer may be purged after its last in-use lease is destroyed."""
    deadline, rows = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        writer = runtime_row(d, protocol, writer_hg, port)
        reader = runtime_row(d, protocol, reader_hg, port)
        rows = {"writer": writer, "reader": reader}
        if (reader and reader["status"] == "ONLINE"
                and (writer is None or writer["status"] == "OFFLINE_HARD")):
            return rows
        time.sleep(0.05)
    raise ConditionTimeout(f"writer demotion and reader admission absent; last={rows}")


def update_source_server(d, protocol, hostgroup, port, assignments):
    meta = PROTOCOLS[protocol]
    cp = d.query(
        f"UPDATE {meta['servers']} SET {assignments} "
        f"WHERE hostgroup_id={hostgroup} AND hostname='{HOST}' AND port={port}"
    )
    if cp.returncode != 0:
        raise RuntimeError(f"source server update failed: {base.clip(cp.stderr)}")
    base.exec_sqls(d, [meta["load"]])


def exchange(port, chunks, timeout=5.0):
    with socket.create_connection((HOST, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        for chunk in chunks:
            sock.sendall(chunk)
        sock.shutdown(socket.SHUT_WR)
        out = bytearray()
        while True:
            data = sock.recv(65536)
            if not data:
                return bytes(out)
            out.extend(data)


def read_server_first(port, size, timeout=5.0):
    sock = socket.create_connection((HOST, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock, lib.recv_exact(sock, size, timeout)


def pending_client(port, timeout=5.0):
    sock = socket.create_connection((HOST, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def monitor_log_latest(d, protocol, port):
    table = ("mysql_server_read_only_log" if protocol == "MYSQL"
             else "pgsql_server_read_only_log")
    cp = d.query(
        f"SELECT read_only,COALESCE(error,'') FROM {table} "
        f"WHERE hostname='{HOST}' AND port={port} "
        "ORDER BY time_start_us DESC LIMIT 1"
    )
    if cp.returncode != 0:
        raise RuntimeError(f"monitor log query failed: {base.clip(cp.stderr)}")
    text = cp.stdout
    if not text.strip():
        return None
    line = text.splitlines()[0]
    if "\t" in line:
        value, error = line.split("\t", 1)
    else:
        value, error = line, ""
    try:
        read_only = int(value)
    except ValueError:
        return {"read_only": None, "error": f"unparseable read_only={value!r} {error}"}
    return {"read_only": read_only, "error": error.strip()}


def wait_monitor_read_only(d, protocol, port, value, timeout=15.0):
    deadline, row = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        row = monitor_log_latest(d, protocol, port)
        if row is not None and row["read_only"] == value and not row["error"]:
            return row
        time.sleep(0.1)
    raise ConditionTimeout(
        f"{protocol} monitor did not record read_only={value} without error; last={row}")


def add_fixture(case, fixture):
    case.fixtures.append(fixture.record() if hasattr(fixture, "record") else fixture)
    return fixture


def case_raw(ctx, protocol):
    case = Case(f"{protocol.lower()}_raw", os.path.join(ctx.run_dir, protocol.lower() + "-raw"))
    ctx.current_case = case
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = MappedDaemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, case.name)
    case.daemons.append(d)
    echo = greeting_backend = tls_backend = None
    try:
        d.start()
        require_mapping_schema(d)
        source_hg, tcp_hg = 10, 20
        listener = base.free_port()
        echo = lib.Backend(mode="echo", name="mapped-raw-echo")
        configure_mapped(d, protocol, source_hg, tcp_hg, listener,
                         [{"port": echo.port, "max_connections": 1000}])
        d.wait_echo(listener, b"mapped-raw-ready")

        for first in (0x00, 0xFF):
            rest = lib.deterministic_payload(4096, 0x1000 + first)
            expected = bytes([first]) + rest
            got = exchange(listener, [bytes([first]), rest])
            case.check(f"first byte 0x{first:02x} exact echo", got == expected,
                       f"sent {len(expected)} got {len(got)} sha={lib.sha256_bytes(got)}")

        greeting = b"\x00\xffserver-first\x00greeting"
        greeting_backend = lib.Backend(mode="greeting", greeting=greeting)
        configure_mapped(d, protocol, source_hg, tcp_hg, listener,
                         [{"port": greeting_backend.port, "max_connections": 1000}])
        sock, seen = read_server_first(listener, len(greeting))
        payload = b"\x00\xffafter-greeting" * 64
        sock.sendall(payload)
        echoed = lib.recv_exact(sock, len(payload), 5.0)
        try:
            sock.close()
        except OSError:
            pass
        case.check("server-first greeting exact", seen == greeting,
                   f"seen={base.clip(seen)!r}")
        case.check("server-first greeting then echo", echoed == payload,
                   f"echoed {len(echoed)}/{len(payload)}")

        try:
            material = lib.generate_test_tls_material(os.path.join(case.evidence_dir, "tls"))
        except lib.TlsUnavailable as exc:
            case.block(f"TLS verification handshake: {exc}")
            material = None
        if material:
            tls_backend = lib.TlsEchoBackend(material["server_cert"], material["server_key"])
            configure_mapped(d, protocol, source_hg, tcp_hg, listener,
                             [{"port": tls_backend.port, "max_connections": 1000}])
            context = lib.tls_client_context(material["ca_cert"])
            raw_sock = socket.create_connection((HOST, listener), timeout=5.0)
            tls_sock = context.wrap_socket(raw_sock, server_hostname="localhost")
            tls_payload = lib.deterministic_payload(65536, 0x7E5)
            tls_sock.sendall(tls_payload)
            received = lib.recv_exact(tls_sock, len(tls_payload), 10.0)
            try:
                tls_sock.unwrap()
            except (ssl.SSLError, OSError) as exc:
                case.check("TLS orderly close", False, repr(exc))
            finally:
                try:
                    tls_sock.close()
                except OSError:
                    pass
            case.check("verified TLS handshake through mapped route",
                       received == tls_payload,
                       f"verified hostname=localhost CA=generated, {len(received)} bytes")
            case.check("TLS backend terminated the handshake (proxy did not)",
                       tls_backend.handshake_errors == 0 and tls_backend.connections_total == 1,
                       f"handshake_errors={tls_backend.handshake_errors} "
                       f"connections={tls_backend.connections_total}")
            case.details["tls_backend"] = tls_backend.stats()
        case.details["echo_backend"] = echo.stats() if echo else None
    finally:
        if greeting_backend:
            greeting_backend.stop()
        if tls_backend:
            tls_backend.stop()
        if echo:
            echo.stop()
        d.close()
    return case


def case_limits(ctx, protocol):
    case = Case(f"{protocol.lower()}_limits", os.path.join(ctx.run_dir, protocol.lower() + "-limits"))
    ctx.current_case = case
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = MappedDaemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, case.name)
    case.daemons.append(d)
    backends = []
    flow = None
    try:
        d.start()
        require_mapping_schema(d)
        source_hg, tcp_hg = 10, 20
        listener = base.free_port()

        # Shared max_connections, held flow, rejection without a new backend.
        cap_backend = lib.Backend(mode="echo", name="mapped-capacity-echo")
        backends.append(cap_backend)
        configure_mapped(d, protocol, source_hg, tcp_hg, listener,
                         [{"port": cap_backend.port, "max_connections": 1}])
        d.wait_echo(listener, b"capacity-warm")
        baseline = wait_stats(d, protocol, source_hg, cap_backend.port,
                              lambda r: r["ConnUsed"] == 0 and r["ConnFree"] == 0,
                              "capacity baseline idle")
        payload = b"\x00\xffcapacity-held" * 32
        flow = base.open_flow(listener, payload)
        held = wait_stats(d, protocol, source_hg, cap_backend.port,
                          lambda r: r["ConnUsed"] == 1 and r["ConnFree"] == 0,
                          "held flow ConnUsed=1 ConnFree=0")
        case.check("held raw flow ConnUsed=1", held["ConnUsed"] == 1, str(held))
        case.check("raw flow ConnFree always zero", held["ConnFree"] == 0, str(held))
        accepts_before = cap_backend.connections_total
        ok, why = base.rejected(listener)
        time.sleep(0.1)
        case.check("max_connections=1 rejects second admission", ok, why)
        case.check("rejected second opened no backend connection",
                   cap_backend.connections_total == accepts_before,
                   f"{accepts_before}->{cap_backend.connections_total}")
        flow.sendall(b"still-alive")
        case.check("admitted flow survives at capacity",
                   base.recv_exact(flow, len(b"still-alive")) == b"still-alive", "")
        flow.close()
        flow = None
        final = wait_stats(
            d, protocol, source_hg, cap_backend.port,
            lambda r: (r["ConnUsed"] == 0 and r["ConnFree"] == 0
                       and r["ConnOK"] == baseline["ConnOK"] + 1
                       and r["ConnERR"] == baseline["ConnERR"]
                       and r["Bytes_data_sent"] - baseline["Bytes_data_sent"]
                       == len(payload) + len(b"still-alive")
                       and r["Bytes_data_recv"] - baseline["Bytes_data_recv"]
                       == len(payload) + len(b"still-alive")),
            "close releases usage and balances counters/bytes")
        case.check("exact ConnOK and byte deltas after close", True, str(final))
        case.check("admission rejection leaves ConnERR unchanged",
                   final["ConnERR"] == baseline["ConnERR"],
                   f"{baseline['ConnERR']}->{final['ConnERR']}")

        # Sequential clients always create a fresh backend socket, no free reuse.
        fresh = lib.Backend(mode="echo", name="mapped-fresh-echo")
        backends.append(fresh)
        configure_mapped(d, protocol, source_hg, tcp_hg, listener,
                         [{"port": fresh.port, "max_connections": 100}])
        d.wait_echo(listener, b"fresh-warm")
        base_stats = wait_stats(d, protocol, source_hg, fresh.port,
                                lambda r: r["ConnUsed"] == 0, "fresh baseline")
        ports_before = len(fresh.accepted_addresses)
        for index in range(3):
            got = base.roundtrip(listener, lib.deterministic_payload(512, index))
            case.check(f"fresh client {index + 1} echo",
                       got == lib.deterministic_payload(512, index), f"{len(got)} bytes")
            wait_stats(d, protocol, source_hg, fresh.port,
                       lambda r, i=index: (r["ConnOK"] == base_stats["ConnOK"] + i + 1
                                           and r["ConnUsed"] == 0 and r["ConnFree"] == 0),
                       f"fresh client {index + 1} counters")
        fresh_ports = [addr[1] for addr in fresh.accepted_addresses[ports_before:]]
        case.check("three fresh backend accepts", len(fresh_ports) == 3, str(fresh_ports))
        case.check("no backend socket reuse (distinct source ports)",
                   len(set(fresh_ports)) == 3, str(fresh_ports))
        case.check("ConnFree remains zero across sequential clients",
                   stats_row(d, protocol, source_hg, fresh.port)["ConnFree"] == 0, "")

        # Real server weight/status rows drive selection.
        weighted_a = lib.Backend(mode="echo", name="mapped-weight-a")
        weighted_b = lib.Backend(mode="echo", name="mapped-weight-b")
        backends.extend([weighted_a, weighted_b])
        configure_mapped(d, protocol, source_hg, tcp_hg, listener, [
            {"port": weighted_a.port, "weight": 0, "max_connections": 100},
            {"port": weighted_b.port, "weight": 100, "max_connections": 100},
        ])
        d.wait_echo(listener, b"weight-warm")
        for _ in range(8):
            base.roundtrip(listener, b"weight-zero-probe")
        case.check("weight zero is never selected", weighted_a.connections_total == 0,
                   f"weighted_a accepts={weighted_a.connections_total}")
        case.check("nonzero weight receives traffic", weighted_b.connections_total >= 9,
                   f"weighted_b accepts={weighted_b.connections_total}")
        row_a = runtime_row(d, protocol, source_hg, weighted_a.port)
        row_b = runtime_row(d, protocol, source_hg, weighted_b.port)
        case.check("runtime weight/status mirror real server rows",
                   row_a and row_b and row_a["weight"] == 0 and row_b["weight"] == 100
                   and row_a["status"] == "ONLINE" and row_b["status"] == "ONLINE",
                   f"a={row_a} b={row_b}")

        configure_mapped(d, protocol, source_hg, tcp_hg, listener, [
            {"port": weighted_a.port, "weight": 1, "max_connections": 100},
            {"port": weighted_b.port, "weight": 4, "max_connections": 100},
        ])
        a_before, b_before = weighted_a.connections_total, weighted_b.connections_total
        for _ in range(40):
            base.roundtrip(listener, b"weighted")
        a_delta = weighted_a.connections_total - a_before
        b_delta = weighted_b.connections_total - b_before
        case.check("unequal weights select both backends", a_delta > 0 and b_delta > 0,
                   f"1:4 deltas a={a_delta} b={b_delta}")
        case.check("unequal weight distribution within generous bounds",
                   2 <= a_delta <= 20 and b_delta >= 20, f"1:4 deltas a={a_delta} b={b_delta}")

        # Unreachable loopback port: connect error, no leaked usage.
        unreachable = base.free_port()
        configure_mapped(d, protocol, source_hg, tcp_hg, listener,
                         [{"port": unreachable, "max_connections": 100}])
        baseline = stats_row(d, protocol, source_hg, unreachable) or {
            "ConnOK": 0, "ConnERR": 0, "ConnUsed": 0, "ConnFree": 0}
        for _ in range(2):
            base.rejected(listener)
        err = wait_stats(d, protocol, source_hg, unreachable,
                         lambda r: r["ConnERR"] >= baseline["ConnERR"] + 1
                         and r["ConnUsed"] == 0 and r["ConnFree"] == 0,
                         "unreachable connect increments ConnERR and releases usage")
        case.check("unreachable port ConnERR > 0 and Used=0",
                   err["ConnERR"] > baseline["ConnERR"] and err["ConnUsed"] == 0, str(err))
        case.check("unreachable port does not fabricate ConnOK",
                   err["ConnOK"] == baseline["ConnOK"], str(err))

        # Lowering capacity does not kill already admitted flows.
        lower = lib.Backend(mode="echo", name="mapped-lower-echo")
        backends.append(lower)
        configure_mapped(d, protocol, source_hg, tcp_hg, listener,
                         [{"port": lower.port, "max_connections": 10}])
        first = base.open_flow(listener, b"lower-one")
        second = base.open_flow(listener, b"lower-two")
        try:
            wait_stats(d, protocol, source_hg, lower.port,
                       lambda r: r["ConnUsed"] == 2 and r["ConnFree"] == 0,
                       "two admitted flows")
            update_source_server(d, protocol, source_hg, lower.port, "max_connections=1")
            for index, sock in enumerate((first, second), 1):
                sock.sendall(f"lower-{index}-alive".encode())
                case.check(f"lowered capacity keeps admitted flow {index}",
                           base.recv_exact(sock, len(f"lower-{index}-alive"))
                           == f"lower-{index}-alive".encode(), "")
        finally:
            for sock in (first, second):
                try:
                    sock.close()
                except OSError:
                    pass
        case.details["limit_backends"] = [b.stats() for b in backends]
    finally:
        if flow:
            flow.close()
        for backend in backends:
            backend.stop()
        d.close()
    return case


def case_status(ctx, protocol):
    case = Case(f"{protocol.lower()}_status", os.path.join(ctx.run_dir, protocol.lower() + "-status"))
    ctx.current_case = case
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = MappedDaemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, case.name)
    case.daemons.append(d)
    backends = []
    blackhole = None
    clients = []
    try:
        d.start()
        require_mapping_schema(d)
        source_hg, tcp_hg = 10, 20
        listener = base.free_port()
        backend = lib.Backend(mode="echo", name="mapped-status-echo")
        backends.append(backend)
        configure_mapped(d, protocol, source_hg, tcp_hg, listener,
                         [{"port": backend.port, "max_connections": 100}])
        flow = base.open_flow(listener, b"status-active")
        clients.append(flow)
        for state in ("OFFLINE_SOFT", "SHUNNED"):
            update_source_server(d, protocol, source_hg, backend.port, f"status='{state}'")
            wait_runtime(d, protocol, source_hg, backend.port,
                         lambda r, s=state: r["status"] == s, f"runtime status {state}")
            flow.sendall(state.encode())
            case.check(f"{state} keeps established flow", 
                       base.recv_exact(flow, len(state)) == state.encode(), "")
            ok, why = base.rejected(listener)
            case.check(f"{state} rejects new admission", ok, why)
        update_source_server(d, protocol, source_hg, backend.port, "status='ONLINE'")
        wait_runtime(d, protocol, source_hg, backend.port,
                     lambda r: r["status"] == "ONLINE", "ONLINE restoration")
        d.wait_echo(listener, b"online-restored")
        case.check("ONLINE restores fresh connections", True, "")

        # OFFLINE_HARD alone closes an active stream and rejects new admission.
        update_source_server(d, protocol, source_hg, backend.port, "status='OFFLINE_HARD'")
        started = time.monotonic()
        closed, why = base.wait_closed(flow, timeout=2.0)
        elapsed = time.monotonic() - started
        case.check("OFFLINE_HARD closes established flow", closed, why)
        case.check("OFFLINE_HARD close within 100 ms poll budget plus slack",
                   elapsed <= HARD_CLOSE_DEADLINE_S, f"elapsed={elapsed:.3f}s")
        ok, why = base.rejected(listener)
        case.check("OFFLINE_HARD rejects new admission", ok, why)
        try:
            flow.close()
        except OSError:
            pass
        clients.remove(flow)

        # Pending connect: daemon-owned SYN_SENT, HARD close, no retry.
        blackhole = lib.Blackhole(backlog=1)
        healthy = lib.Backend(mode="echo", name="mapped-pending-healthy")
        backends.append(healthy)
        configure_mapped(d, protocol, source_hg, tcp_hg, listener, [
            {"port": blackhole.port, "weight": 1, "max_connections": 100},
        ], listener_overrides={"connect_timeout_ms": 30000, "max_connect_attempts": 3})
        if not blackhole.fill():
            case.block("pending-connect: could not saturate the task-owned loopback backlog")
        else:
            attempt = pending_client(listener)
            clients.append(attempt)
            if not lib.wait_syn_sent(d.proc.pid, blackhole.port, 3.0):
                case.block("pending-connect: daemon-owned SYN_SENT socket not observable via /proc")
            else:
                pending_before = wait_stats(
                    d, protocol, source_hg, blackhole.port,
                    lambda r: r["ConnUsed"] == 1 and r["ConnFree"] == 0,
                    "pending SYN_SENT counts as ConnUsed=1")
                healthy_before = healthy.connections_total
                meta = PROTOCOLS[protocol]
                d.query(f"UPDATE {meta['servers']} SET status='OFFLINE_HARD' "
                        f"WHERE hostgroup_id={source_hg} AND port={blackhole.port}")
                d.query(f"INSERT INTO {meta['servers']}(hostgroup_id,hostname,port,status,"
                        f"weight,max_connections,comment) VALUES({source_hg},'{HOST}',"
                        f"{healthy.port},'ONLINE',1,100,'pending-second-candidate')")
                base.exec_sqls(d, [meta["load"]])
                closed, why = base.wait_closed(attempt, timeout=3.0)
                case.check("pending HARD closes client flow", closed, why)
                pending_after = wait_stats(d, protocol, source_hg, blackhole.port,
                                           lambda r: r["ConnUsed"] == 0 and r["ConnFree"] == 0,
                                           "pending HARD releases ConnUsed")
                case.check("pending HARD leaves Used=0 Free=0",
                           pending_after["ConnUsed"] == 0 and pending_after["ConnFree"] == 0,
                           str(pending_after))
                case.check("pending HARD cancellation leaves ConnERR unchanged",
                           pending_after["ConnERR"] == pending_before["ConnERR"],
                           f"{pending_before['ConnERR']}->{pending_after['ConnERR']}")
                case.check("pending HARD cancellation leaves ConnOK unchanged",
                           pending_after["ConnOK"] == pending_before["ConnOK"],
                           f"{pending_before['ConnOK']}->{pending_after['ConnOK']}")
                time.sleep(0.2)
                case.check("pending HARD does not retry a second ONLINE candidate",
                           healthy.connections_total == healthy_before,
                           f"healthy accepts {healthy_before}->{healthy.connections_total}")
            try:
                attempt.close()
            except OSError:
                pass
            clients.remove(attempt)

        # Fast HARD->ONLINE latch, then real remove/readd identity.  The old
        # client FD stays open until peer EOF/reset is observed.
        old = lib.Backend(mode="echo", name="mapped-aba-echo")
        backends.append(old)
        configure_mapped(d, protocol, source_hg, tcp_hg, listener,
                         [{"port": old.port, "max_connections": 100}])
        old_flow = base.open_flow(listener, b"old-lease")
        clients.append(old_flow)
        wait_stats(d, protocol, source_hg, old.port,
                   lambda r: r["ConnUsed"] == 1 and r["ConnFree"] == 0,
                   "old lease Used=1 before ABA transitions")
        meta = PROTOCOLS[protocol]
        d.query(f"UPDATE {meta['servers']} SET status='OFFLINE_HARD' "
                f"WHERE hostgroup_id={source_hg} AND port={old.port}")
        base.exec_sqls(d, [meta["load"]])
        d.query(f"UPDATE {meta['servers']} SET status='ONLINE' "
                f"WHERE hostgroup_id={source_hg} AND port={old.port}")
        base.exec_sqls(d, [meta["load"]])
        closed, why = base.wait_closed(old_flow, timeout=2.0)
        case.check("rapid HARD->ONLINE closes the old lease", closed, why)
        old_flow.close()
        clients.remove(old_flow)
        old_flow = base.open_flow(listener, b"old-lease-before-remove")
        clients.append(old_flow)
        wait_stats(d, protocol, source_hg, old.port,
                   lambda r: r["ConnUsed"] == 1 and r["ConnFree"] == 0,
                   "live old lease before remove/readd")
        base.exec_sqls(d, [
            f"DELETE FROM {meta['servers']} WHERE hostgroup_id={source_hg}",
            meta["load"],
            f"INSERT INTO {meta['servers']}(hostgroup_id,hostname,port,status,weight,"
            f"max_connections,comment) VALUES({source_hg},'{HOST}',{old.port},"
            "'ONLINE',1,1,'readded')",
            meta["load"],
        ])
        closed_again, why_again = base.wait_closed(old_flow, timeout=0.5)
        case.check("removed/readded endpoint does not revive old flow", closed_again, why_again)
        new_flow = base.open_flow(listener, b"replacement")
        clients.append(new_flow)
        replacement = wait_stats(d, protocol, source_hg, old.port,
                                 lambda r: r["ConnUsed"] == 1 and r["ConnFree"] == 0,
                                 "replacement lease only")
        case.check("replacement capacity admission unaffected by old lease",
                   replacement["ConnUsed"] == 1, str(replacement))
        accepts_before = old.connections_total
        ok, why = base.rejected(listener)
        case.check("replacement max_connections=1 rejects second admission", ok, why)
        time.sleep(0.1)
        case.check("replacement rejection does not open a backend",
                   old.connections_total == accepts_before,
                   f"{accepts_before}->{old.connections_total}")
        new_flow.close()
        clients.remove(new_flow)
        wait_stats(d, protocol, source_hg, old.port,
                   lambda r: r["ConnUsed"] == 0, "replacement close releases usage")
        old_flow.close()
        clients.remove(old_flow)
    finally:
        for sock in clients:
            try:
                sock.close()
            except OSError:
                pass
        if blackhole:
            blackhole.stop()
        for backend in backends:
            backend.stop()
        d.close()
    return case


def case_mysql_monitor(ctx):
    case = Case("mysql_monitor", os.path.join(ctx.run_dir, "mysql-monitor"))
    ctx.current_case = case
    os.makedirs(case.evidence_dir, exist_ok=True)
    fixture = None
    d = None
    client = None
    try:
        fixture = add_fixture(case, MysqlFixture.create(os.path.join(case.evidence_dir, "mysqld"),
                                                        ctx.mysql))
        d = MappedDaemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, case.name,
                         monitors=True)
        case.daemons.append(d)
        d.start()
        require_mapping_schema(d)
        set_monitor_variables(d, "MYSQL", fixture.username, fixture.password)
        source_hg, reader_hg, tcp_hg = 10, 11, 20
        listener = base.free_port()
        base.exec_sqls(d, [
            "DELETE FROM mysql_replication_hostgroups",
            "INSERT INTO mysql_replication_hostgroups(writer_hostgroup,reader_hostgroup,"
            f"check_type,comment) VALUES({source_hg},{reader_hg},'read_only','mapped-monitor')",
        ])
        configure_mapped(d, "MYSQL", source_hg, tcp_hg, listener,
                         [{"port": fixture.port, "max_connections": 10,
                           "comment": "real task-owned mysqld"}])
        wait_runtime(d, "MYSQL", source_hg, fixture.port,
                     lambda r: r["status"] == "ONLINE", "real MySQL monitor sees writer ONLINE")
        client, greeting = read_server_first(listener, 64)
        case.check("mapped raw client holds/reads real MySQL greeting",
                   len(greeting) >= 5 and greeting[4] == 10, f"{base.clip(greeting)!r}")
        fixture.set_read_only(True)
        log_row = wait_monitor_read_only(d, "MYSQL", fixture.port, 1)
        case.check("real MySQL monitor read_only log records 1", log_row["read_only"] == 1,
                   str(log_row))
        demoted = wait_demoted(d, "MYSQL", source_hg, reader_hg, fixture.port)
        case.check("monitor removes writer membership and admits reader", True, str(demoted))
        closed, why = base.wait_closed(client, timeout=5.0)
        case.check("monitor demotion closes mapped raw client", closed, why)
        try:
            client.close()
        except OSError:
            pass
        client = None
        fixture.set_read_only(False)
        wait_runtime(d, "MYSQL", source_hg, fixture.port,
                     lambda r: r["status"] == "ONLINE",
                     "writer ONLINE after read_only=0", timeout=20.0)
        fresh, greeting = read_server_first(listener, 64)
        try:
            fresh.close()
        except OSError:
            pass
        case.check("fresh writer admission after read_only=0",
                   len(greeting) >= 5 and greeting[4] == 10, f"{base.clip(greeting)!r}")
    finally:
        if client:
            try:
                client.close()
            except OSError:
                pass
        try:
            if d:
                d.close()
        finally:
            if fixture:
                fixture.close()
    return case


def case_pgsql_monitor(ctx):
    case = Case("pgsql_monitor", os.path.join(ctx.run_dir, "pgsql-monitor"))
    ctx.current_case = case
    os.makedirs(case.evidence_dir, exist_ok=True)
    fixture = None
    d = None
    client = None
    try:
        fixture = add_fixture(case, PgWireFixture())
        case.details["fixture_scope"] = (
            "SIMULATED PostgreSQL wire endpoint (startup/AuthOK, empty query, "
            "pg_is_in_recovery boolean); assertions target real ProxySQL monitor, "
            "HGM and socket behaviour")
        d = MappedDaemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, case.name,
                         monitors=True)
        case.daemons.append(d)
        d.start()
        require_mapping_schema(d)
        set_monitor_variables(d, "PGSQL", "tcpfixture", "tcpfixture-local-only")
        source_hg, reader_hg, tcp_hg = 10, 11, 20
        listener = base.free_port()
        base.exec_sqls(d, [
            "DELETE FROM pgsql_replication_hostgroups",
            "INSERT INTO pgsql_replication_hostgroups(writer_hostgroup,reader_hostgroup,"
            f"check_type,comment) VALUES({source_hg},{reader_hg},'read_only','mapped-monitor')",
        ])
        configure_mapped(d, "PGSQL", source_hg, tcp_hg, listener,
                         [{"port": fixture.port, "max_connections": 10,
                           "comment": "simulated pgsql wire fixture"}])
        wait_runtime(d, "PGSQL", source_hg, fixture.port,
                     lambda r: r["status"] == "ONLINE",
                     "real PG monitor sees simulated writer ONLINE", timeout=20.0)
        payload = b"\x00\xffpg-raw-mapped" * 64
        got = base.roundtrip(listener, payload)
        case.check("arbitrary raw mapped client echoes through PG mapping", got == payload,
                   f"{len(got)}/{len(payload)} bytes")
        client = base.open_flow(listener, b"pg-held")
        fixture.set_recovery(True)
        log_row = wait_monitor_read_only(d, "PGSQL", fixture.port, 1)
        case.check("real PG monitor read_only log records 1", log_row["read_only"] == 1,
                   str(log_row))
        demoted = wait_demoted(d, "PGSQL", source_hg, reader_hg, fixture.port)
        case.check("PG monitor removes writer membership and admits reader", True, str(demoted))
        closed, why = base.wait_closed(client, timeout=5.0)
        case.check("PG monitor demotion closes mapped raw client", closed, why)
        try:
            client.close()
        except OSError:
            pass
        client = None
        fixture.set_recovery(False)
        wait_runtime(d, "PGSQL", source_hg, fixture.port,
                     lambda r: r["status"] == "ONLINE",
                     "PG writer ONLINE after recovery=false", timeout=20.0)
        restored = base.roundtrip(listener, b"pg-fresh-after-recovery")
        case.check("fresh PG writer admission after recovery=false",
                   restored == b"pg-fresh-after-recovery", f"{base.clip(restored)!r}")
        case.details["pg_fixture_stats"] = fixture.record()
    finally:
        if client:
            try:
                client.close()
            except OSError:
                pass
        try:
            if d:
                d.close()
        finally:
            if fixture:
                fixture.close()
    return case


def case_control(ctx, protocol):
    case = Case(f"{protocol.lower()}_control", os.path.join(ctx.run_dir, protocol.lower() + "-control"))
    ctx.current_case = case
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = MappedDaemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, case.name)
    case.daemons.append(d)
    backends = []
    try:
        d.start()
        require_mapping_schema(d)
        source_hg, tcp_hg, second_tcp_hg = 30, 40, 41
        listener, second_listener = base.free_port(), base.free_port()
        mapped_backend = lib.Backend(mode="echo", name="mapped-control")
        backends.append(mapped_backend)
        meta = PROTOCOLS[protocol]

        configure_mapped(d, protocol, source_hg, tcp_hg, listener, [])
        ok, why = base.rejected(listener)
        case.check("empty mapped source hostgroup rejects new connections", ok, why)
        mappings = validate_source_namespaces(d)
        case.check("mandatory mapping row present",
                   any(row["hostgroup_id"] == tcp_hg
                       and row["source_protocol"] == protocol
                       and row["source_hostgroup"] == source_hg for row in mappings),
                   str(mappings))

        # Populate the protocol source only; no TCP reload should be needed.
        base.exec_sqls(d, [
            f"INSERT INTO {meta['servers']}(hostgroup_id,hostname,port,status,weight,"
            f"max_connections,comment) VALUES({source_hg},'{HOST}',"
            f"{mapped_backend.port},'ONLINE',1,100,'late-source')",
            meta["load"],
        ])
        d.wait_echo(listener, b"protocol-only-admission")
        case.check("protocol-only LOAD admits without TCP reload", True, "")

        # A second TCP group may share the same core source hostgroup.
        base.exec_sqls(d, [
            "INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,source_hostgroup,"
            f"comment) VALUES({second_tcp_hg},{base.sql_lit(protocol)},"
            f"{source_hg},'second-mapped')",
            "INSERT INTO tcp_listeners(listener_id,active,bind_address,bind_port,"
            "default_hostgroup,max_connections,connect_timeout_ms,idle_timeout_ms,"
            "max_connect_attempts,comment) "
            f"VALUES(2,1,'{HOST}',{second_listener},{second_tcp_hg},10000,2000,60000,3,"
            "'second-mapped')",
            "LOAD TCP CONFIG TO RUNTIME",
        ])
        d.wait_echo(listener, b"first-shared-group")
        d.wait_echo(second_listener, b"second-shared-group")
        case.check("two TCP hostgroups share one source namespace", True,
                   f"{tcp_hg},{second_tcp_hg}->{protocol}:{source_hg}")

        generation_before = base.generation(d)
        bad_protocol = d.query(
            "INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,source_hostgroup,"
            f"comment) VALUES(99,'ORACLE',{source_hg},'invalid-namespace')")
        case.check("DDL rejects invalid source_protocol", bad_protocol.returncode != 0,
                   base.clip(bad_protocol.stderr))
        bad_source = d.query(
            "INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,source_hostgroup,"
            f"comment) VALUES(98,{base.sql_lit(protocol)},-1,'negative-source')")
        case.check("DDL rejects negative source_hostgroup", bad_source.returncode != 0,
                   base.clip(bad_source.stderr))
        case.check("rejected namespace rows leave TCP generation unchanged",
                   base.generation(d) == generation_before,
                   f"{generation_before}->{base.generation(d)}")
        d.wait_echo(listener, b"after-namespace-reject")

        mapping_comment = "mapped 'quoted'\tcomment"
        rule_comment = "rule 'quoted';\tline1\nline2\\end"
        base.exec_sqls(d, [
            f"UPDATE tcp_hostgroups SET comment={base.sql_lit(mapping_comment)} "
            f"WHERE hostgroup_id={tcp_hg}",
            "INSERT INTO tcp_routing_rules(rule_id,active,listener_id,source_cidr,"
            "action,destination_hostgroup,comment) "
            f"VALUES(1,1,1,NULL,'ROUTE',{tcp_hg},{base.sql_lit(rule_comment)})",
            "LOAD TCP CONFIG TO RUNTIME",
        ])
        runtime_comment_before = d.value(
            f"SELECT hex(comment) FROM runtime_tcp_hostgroups WHERE hostgroup_id={tcp_hg}")
        settings_before = d.value("SELECT worker_threads FROM tcp_settings")
        saved = {
            "hostgroups": {
                str(row[0]): (row[1], row[2], row[3])
                for row in _rows(d, "SELECT hostgroup_id,source_protocol,"
                                   "source_hostgroup,hex(comment) FROM tcp_hostgroups")
            },
            "listeners": {
                str(row[0]): (row[1], row[2])
                for row in _rows(d, "SELECT listener_id,bind_port,hex(comment) FROM tcp_listeners")
            },
            "rules": {
                str(row[0]): tuple(row[1:])
                for row in _rows(
                    d, "SELECT rule_id,active,COALESCE(listener_id,'NULL'),"
                       "COALESCE(source_cidr,'NULL'),action,"
                       "COALESCE(destination_hostgroup,'NULL'),hex(comment) "
                       "FROM tcp_routing_rules")
            },
        }
        cp = d.query("SAVE TCP CONFIG TO DISK", timeout=15)
        case.must("SAVE TCP CONFIG TO DISK succeeds", cp.returncode == 0,
                  base.clip(cp.stderr))

        base.exec_sqls(d, [
            "UPDATE tcp_settings SET worker_threads=3",
            "UPDATE tcp_hostgroups SET source_hostgroup=99,comment='mutated'",
            "UPDATE tcp_listeners SET bind_port=1,comment='mutated'",
            "DELETE FROM tcp_routing_rules",
        ])
        cp = d.query("LOAD TCP CONFIG FROM DISK", timeout=15)
        case.must("LOAD TCP CONFIG FROM DISK succeeds", cp.returncode == 0,
                  base.clip(cp.stderr))
        case.check("four-table settings restored",
                   d.value("SELECT worker_threads FROM tcp_settings") == settings_before,
                   d.value("SELECT worker_threads FROM tcp_settings"))
        restored_hostgroups = {
            str(row[0]): (row[1], row[2], row[3])
            for row in _rows(d, "SELECT hostgroup_id,source_protocol,"
                                "source_hostgroup,hex(comment) FROM tcp_hostgroups")
        }
        case.check("four-table hostgroups restored",
                   restored_hostgroups == saved["hostgroups"],
                   f"{restored_hostgroups} != {saved['hostgroups']}")
        restored_listeners = {
            str(row[0]): (row[1], row[2])
            for row in _rows(d, "SELECT listener_id,bind_port,hex(comment) FROM tcp_listeners")
        }
        case.check("four-table listeners restored",
                   restored_listeners == saved["listeners"],
                   f"{restored_listeners} != {saved['listeners']}")
        restored_rules = {
            str(row[0]): tuple(row[1:])
            for row in _rows(
                d, "SELECT rule_id,active,COALESCE(listener_id,'NULL'),"
                   "COALESCE(source_cidr,'NULL'),action,"
                   "COALESCE(destination_hostgroup,'NULL'),hex(comment) "
                   "FROM tcp_routing_rules")
        }
        case.check("four-table routing rules restored", restored_rules == saved["rules"],
                   f"{restored_rules} != {saved['rules']}")
        case.check("mapped ROUTE rule restored with full row",
                   restored_rules.get("1") == (
                       "1", "1", "NULL", "ROUTE", str(tcp_hg),
                       rule_comment.encode().hex().upper()),
                   str(restored_rules.get("1")))
        case.check("mapped ROUTE rule comment restores every quoted/tab/newline byte",
                   d.value("SELECT hex(comment) FROM tcp_routing_rules WHERE rule_id=1")
                   == rule_comment.encode().hex().upper(), "")
        case.check("runtime ROUTE rule matches restored saved row",
                   d.value("SELECT active,COALESCE(listener_id,'NULL'),action,"
                           "COALESCE(destination_hostgroup,'NULL'),hex(comment) "
                           "FROM runtime_tcp_routing_rules WHERE rule_id=1")
                   == "1\t1\tROUTE\t" + str(tcp_hg) + "\t"
                   + rule_comment.encode().hex().upper(), "")
        case.check("mapping comment restores every quoted/tab byte",
                   d.value(f"SELECT hex(comment) FROM tcp_hostgroups WHERE hostgroup_id={tcp_hg}")
                   == mapping_comment.encode().hex().upper(), "")
        case.check("LOAD FROM DISK preserves runtime mapping comment",
                   d.value(f"SELECT hex(comment) FROM runtime_tcp_hostgroups "
                           f"WHERE hostgroup_id={tcp_hg}") == runtime_comment_before, "")
        runtime_mapping = d.value(
            "SELECT source_protocol,source_hostgroup,comment "
            f"FROM runtime_tcp_hostgroups WHERE hostgroup_id={tcp_hg}")
        case.check("runtime mapping separated from saved inventory",
                   runtime_mapping.split("\t")[:2] == [protocol, str(source_hg)],
                   runtime_mapping)
        case.check("mapped runtime hostgroup has no local server inventory",
                   d.query("SELECT count(*) FROM runtime_tcp_servers").returncode != 0, "")
        case.check("restored mapping route serves",
                   base.roundtrip(listener, b"restored-mapping")
                   == b"restored-mapping", "")
        case.check("restored shared mapping route serves",
                   base.roundtrip(second_listener, b"restored-shared-mapping")
                   == b"restored-shared-mapping", "")

        base.exec_sqls(d, [f"SAVE {protocol} SERVERS TO DISK"])
        case.must("control preparation slow shutdown exits 0", d.shutdown_slow() == 0, "")
        d.initial = False
        d.start()
        base.exec_sqls(d, [meta["load"]])
        d.wait_echo(listener, b"restart-mapping")
        d.wait_echo(second_listener, b"restart-shared-mapping")
        case.check("restart same datadir serves saved mapped and shared routes", True, "")
        case.check("restart runtime mapping projection present",
                   d.value("SELECT source_protocol FROM runtime_tcp_hostgroups "
                           f"WHERE hostgroup_id={tcp_hg}") == protocol, "")
    finally:
        for backend in backends:
            backend.stop()
        d.close()
    return case


def case_remap(ctx, protocol):
    case = Case(f"{protocol.lower()}_remap", os.path.join(ctx.run_dir, protocol.lower() + "-remap"))
    ctx.current_case = case
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = MappedDaemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, case.name)
    case.daemons.append(d)
    old_backend = new_backend = None
    old_flow = new_flow = None
    try:
        d.start()
        require_mapping_schema(d)
        source_a, source_b, tcp_hg = 50, 51, 60
        listener = base.free_port()
        old_backend = lib.Backend(mode="echo", name="mapped-remap-old")
        new_backend = lib.Backend(mode="echo", name="mapped-remap-new")
        configure_mapped(d, protocol, source_a, tcp_hg, listener,
                         [{"port": old_backend.port, "max_connections": 100}])
        old_flow = base.open_flow(listener, b"remap-old")
        wait_stats(d, protocol, source_a, old_backend.port,
                   lambda r: r["ConnUsed"] == 1 and r["ConnFree"] == 0,
                   "old mapped flow Used=1")
        meta = PROTOCOLS[protocol]
        base.exec_sqls(d, [
            f"INSERT INTO {meta['servers']}(hostgroup_id,hostname,port,status,weight,"
            f"max_connections,comment) VALUES({source_b},'{HOST}',"
            f"{new_backend.port},'ONLINE',1,100,'remap-new')",
            meta["load"],
            f"UPDATE tcp_hostgroups SET source_hostgroup={source_b} "
            f"WHERE hostgroup_id={tcp_hg}",
            "LOAD TCP CONFIG TO RUNTIME",
        ])
        old_flow.sendall(b"remap-old-survives")
        case.check("old flow survives mapping to another source hostgroup",
                   base.recv_exact(old_flow, len(b"remap-old-survives"))
                   == b"remap-old-survives", "")
        new_flow = base.open_flow(listener, b"remap-new")
        wait_stats(d, protocol, source_b, new_backend.port,
                   lambda r: r["ConnUsed"] == 1 and r["ConnFree"] == 0,
                   "new mapped flow uses new source hostgroup")
        case.check("new flow uses remapped source backend", True, "")
        update_source_server(d, protocol, source_a, old_backend.port, "status='OFFLINE_HARD'")
        closed, why = base.wait_closed(old_flow, timeout=2.0)
        case.check("old source HARD closes only old flow", closed, why)
        new_flow.sendall(b"remap-new-alive")
        case.check("new flow survives old source HARD",
                   base.recv_exact(new_flow, len(b"remap-new-alive")) == b"remap-new-alive", "")
        wait_stats(d, protocol, source_a, old_backend.port,
                   lambda r: r["ConnUsed"] == 0, "old source usage released")
        current = wait_stats(d, protocol, source_b, new_backend.port,
                             lambda r: r["ConnUsed"] == 1 and r["ConnFree"] == 0,
                             "new source usage remains")
        case.check("new source accounting unaffected by old HARD", current["ConnUsed"] == 1,
                   str(current))
    finally:
        for sock in (old_flow, new_flow):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        for backend in (old_backend, new_backend):
            if backend is not None:
                backend.stop()
        d.close()
    return case


def case_shared(ctx, protocol):
    """Two TCP groups must share one core source hostgroup and its capacity."""
    case = Case(f"{protocol.lower()}_shared",
                os.path.join(ctx.run_dir, protocol.lower() + "-shared"))
    ctx.current_case = case
    os.makedirs(case.evidence_dir, exist_ok=True)
    d = MappedDaemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, case.name)
    case.daemons.append(d)
    backend = None
    flow = None
    try:
        d.start()
        require_mapping_schema(d)
        source_hg, tcp_a, tcp_b = 70, 71, 72
        listener_a, listener_b = base.free_port(), base.free_port()
        backend = lib.Backend(mode="echo", name=f"mapped-{protocol.lower()}-shared")
        configure_mapped(d, protocol, source_hg, tcp_a, listener_a,
                         [{"port": backend.port, "max_connections": 1}],
                         mapping_comment="shared-a")
        base.exec_sqls(d, [
            "INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,source_hostgroup,"
            f"comment) VALUES({tcp_b},{base.sql_lit(protocol)},{source_hg},'shared-b')",
            "INSERT INTO tcp_listeners(listener_id,active,bind_address,bind_port,"
            "default_hostgroup,max_connections,connect_timeout_ms,idle_timeout_ms,"
            "max_connect_attempts,comment) "
            f"VALUES(2,1,'{HOST}',{listener_b},{tcp_b},10000,2000,60000,3,'shared-b')",
            "LOAD TCP CONFIG TO RUNTIME",
        ])
        mapping_rows = [row for row in validate_source_namespaces(d)
                        if row["hostgroup_id"] in (tcp_a, tcp_b)]
        case.check("two distinct TCP groups map to one source namespace",
                   len(mapping_rows) == 2
                   and {row["source_protocol"] for row in mapping_rows} == {protocol}
                   and {row["source_hostgroup"] for row in mapping_rows} == {source_hg},
                   str(mapping_rows))
        payload = b"\x00\xffshared-capacity" * 16
        flow = base.open_flow(listener_a, payload)
        wait_stats(d, protocol, source_hg, backend.port,
                   lambda r: r["ConnUsed"] == 1 and r["ConnFree"] == 0,
                   "first TCP group consumes the shared source connection")
        accepts_before = backend.connections_total
        ok, why = base.rejected(listener_b)
        case.check("shared source capacity rejects the second TCP group", ok, why)
        case.check("shared rejection opened no extra backend connection",
                   backend.connections_total == accepts_before,
                   f"{accepts_before}->{backend.connections_total}")
        flow.sendall(b"shared-held-alive")
        case.check("admitted flow survives at shared capacity",
                   base.recv_exact(flow, len(b"shared-held-alive")) == b"shared-held-alive",
                   "")
        flow.close()
        flow = None
        wait_stats(d, protocol, source_hg, backend.port,
                   lambda r: r["ConnUsed"] == 0 and r["ConnFree"] == 0,
                   "first group release returns shared capacity")
        d.wait_echo(listener_b, b"second-group-after-release")
        case.check("released shared capacity admits the other TCP group", True, "")
    finally:
        if flow:
            try:
                flow.close()
            except OSError:
                pass
        if backend:
            backend.stop()
        d.close()
    return case


UPGRADE_SENTINEL_TEXT = "sentinel 'quoted'\tline1\nline2\\end"
UPGRADE_SENTINEL_BLOB = b"\x00\xffupgrade\x00blob"

LEGACY_HOSTGROUP_FIXTURES = (
    {"hostgroup_id": 20, "hostgroup_comment": "", "mapping_comment": "mapped nonempty"},
    {"hostgroup_id": 21, "hostgroup_comment": "equal comment",
     "mapping_comment": "equal comment"},
    {"hostgroup_id": 22,
     "hostgroup_comment": "host 'quoted'\tline1\nline2\\end",
     "mapping_comment": "map 'quoted'\tline1\nline2\\end"},
    {"hostgroup_id": 23, "hostgroup_comment": "host-only comment",
     "mapping_comment": ""},
)


def _run_converter(converter, database, apply=False, backup=None, timeout=120):
    argv = [sys.executable, str(converter), "--database", str(database)]
    argv.append("--apply" if apply else "--check")
    if backup is not None:
        argv += ["--backup", str(backup)]
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=timeout)


def _converter_refusal(case, converter, database, label, backup=None):
    before_hash = upgrade.file_sha256(Path(database))
    before_logical = upgrade.logical_database_snapshot(Path(database))
    completed = _run_converter(converter, database, apply=backup is not None,
                               backup=backup)
    case.check(f"{label}: converter refuses", completed.returncode != 0,
               base.clip(completed.stdout + completed.stderr))
    case.check(f"{label}: database bytes unchanged",
               upgrade.file_sha256(Path(database)) == before_hash, "")
    case.check(f"{label}: database logical tables unchanged",
               upgrade.logical_database_snapshot(Path(database)) == before_logical, "")
    if backup is not None:
        case.check(f"{label}: refused apply created no backup",
                   not Path(backup).exists(), str(backup))
    return completed


def _clone_datadir_for_database(ctx, base_daemon, database, name):
    daemon = MappedDaemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir, name,
                          initial=False)
    upgrade.clone_datadir(Path(base_daemon.datadir), Path(daemon.datadir))
    upgrade.clone_database(Path(database), Path(daemon.datadir) / "proxysql.db")
    # Saved global_variables override generated config on non-initial startup.
    # Prepare the task-owned child's endpoint before any preservation baseline.
    with sqlite3.connect(_actual_daemon_db(daemon)) as connection:
        updated = connection.execute(
            "UPDATE global_variables SET variable_value=? "
            "WHERE variable_name='admin-mysql_ifaces'",
            (f"{base.HOST}:{daemon.admin_port}",))
        if updated.rowcount != 1:
            raise RuntimeError("saved database lacks a unique admin-mysql_ifaces row")
    return daemon


def _core_schema_refusal_log(log_segment):
    """Stable core guard context, not an unrelated startup-crash token match."""
    text = (log_segment or "").lower()
    return ("schema preflight" in text
            and "tcp_hostgroups" in text
            and "offline" in text
            and ("migration" in text or "migrate" in text))


def _admin_rows(d, sql):
    completed = d.query(sql)
    if completed.returncode != 0:
        raise RuntimeError(f"Admin rows query failed: {base.clip(completed.stderr)}")
    return tuple(tuple(line.split("\t")) for line in completed.stdout.splitlines()
                 if line)


def _editable_admin_snapshot(d):
    """Complete editable four-table Admin memory, CLI-safe for text bytes."""
    return {
        "tcp_settings": _admin_rows(
            d, "SELECT id,worker_threads,max_connections,buffer_size,"
               "shutdown_timeout_ms,half_close_timeout_ms FROM tcp_settings "
               "ORDER BY id"),
        "tcp_hostgroups": _admin_rows(
            d, "SELECT hostgroup_id,source_protocol,source_hostgroup,hex(comment) "
               "FROM tcp_hostgroups ORDER BY hostgroup_id"),
        "tcp_listeners": _admin_rows(
            d, "SELECT listener_id,active,bind_address,bind_port,default_hostgroup,"
               "max_connections,connect_timeout_ms,idle_timeout_ms,"
               "max_connect_attempts,hex(comment) FROM tcp_listeners "
               "ORDER BY listener_id"),
        "tcp_routing_rules": _admin_rows(
            d, "SELECT rule_id,active,COALESCE(listener_id,'NULL'),"
               "COALESCE(source_cidr,'NULL'),action,"
               "COALESCE(destination_hostgroup,'NULL'),hex(comment) "
               "FROM tcp_routing_rules ORDER BY rule_id"),
    }


def _actual_daemon_db(daemon):
    return Path(daemon.datadir) / "proxysql.db"


def _legacy_startup_refusal(case, ctx, base_daemon, database, listener_port, label):
    original_before = upgrade.logical_database_snapshot(Path(database))
    daemon = _clone_datadir_for_database(
        ctx, base_daemon, database, "upgrade-refusal-" + label)
    inspected_db = _actual_daemon_db(daemon)
    clone_before = upgrade.logical_database_snapshot(inspected_db)
    try:
        result = daemon.start_expect_refusal(timeout=25)
        clone_after = upgrade.logical_database_snapshot(inspected_db)
    finally:
        daemon.close()
    result["inspected_database"] = str(inspected_db)
    result["original_database"] = str(database)
    case.check(f"{label}: restart argv omits --initial",
               "--initial" not in result["argv"], str(result["argv"]))
    case.check(f"{label}: daemon refused within bounded start",
               not result["timed_out"], str(result))
    case.check(f"{label}: daemon exited nonzero",
               result["returncode"] not in (0, None), str(result))
    log_segment = result.get("log_segment") or ""
    case.check(f"{label}: actual child log matches core schema-preflight guard",
               _core_schema_refusal_log(log_segment),
               base.clip(log_segment))
    case.check(f"{label}: no TCP listener was activated",
               not base.can_connect(listener_port, 0.5), f"port {listener_port}")
    case.check(f"{label}: actual cloned daemon DB unchanged by refusal",
               clone_after == clone_before, str(inspected_db))
    case.check(f"{label}: original fixture untouched",
               upgrade.logical_database_snapshot(Path(database)) == original_before,
               str(database))
    return result


def case_upgrade(ctx):
    """Fresh-database legacy refusal, portable conversion, and converted restart."""
    case = Case("upgrade", os.path.join(ctx.run_dir, "upgrade"))
    ctx.current_case = case
    os.makedirs(case.evidence_dir, exist_ok=True)
    converter = Path(ctx.converter)
    if not converter.is_file():
        case.block(f"converter not provided: {converter}")
        return case
    try:
        constants = upgrade.read_converter_constants(converter)
    except (OSError, ValueError) as exc:
        case.block(f"converter DDL constants unavailable: {exc}")
        return case

    backend = lib.Backend(mode="echo", name="upgrade-source-backend")
    base_daemon = None
    converted_daemon = None
    try:
        # Fresh CURRENT daemon-created database: saved and stopped cleanly.
        base_daemon = MappedDaemon(ctx.host, ctx.plugin, ctx.mysql, ctx.run_dir,
                                   "upgrade-base")
        case.daemons.append(base_daemon)
        base_daemon.start()
        require_mapping_schema(base_daemon)
        listener_port = base.free_port()
        mapping_comment = "base mapping 'quoted'\tcomment"
        listener_comment = "listener 'quoted'\tline1\nline2\\end"
        rule_comment = "rule 'quoted';\tline1\nline2\\end"
        configure_mapped(
            base_daemon, "MYSQL", 10, 20, listener_port,
            [{"port": backend.port, "max_connections": 100,
              "comment": "upgrade source endpoint"}],
            mapping_comment=mapping_comment, listener_comment=listener_comment)
        base.exec_sqls(base_daemon, [
            "INSERT INTO tcp_routing_rules(rule_id,active,listener_id,source_cidr,"
            "action,destination_hostgroup,comment) "
            f"VALUES(1,1,1,NULL,'ROUTE',20,{base.sql_lit(rule_comment)})",
        ])
        cp = base_daemon.query("SAVE TCP CONFIG TO DISK", timeout=15)
        case.must("base current SAVE TCP CONFIG TO DISK", cp.returncode == 0,
                  base.clip(cp.stderr))
        cp = base_daemon.query("SAVE MYSQL SERVERS TO DISK", timeout=15)
        case.must("base current SAVE MYSQL SERVERS TO DISK", cp.returncode == 0,
                  base.clip(cp.stderr))
        case.must("base preparation slow shutdown exits 0",
                  base_daemon.shutdown_slow() == 0, "")
        base_db = Path(base_daemon.datadir) / "proxysql.db"
        case.must("fresh current database exists", base_db.is_file(), str(base_db))
        # Task-owned unrelated sentinel proves global preservation, not just
        # the core source tables.
        sentinel_connection = sqlite3.connect(base_db)
        try:
            sentinel_connection.execute(
                "CREATE TABLE upgrade_sentinel(id INTEGER PRIMARY KEY,"
                "payload TEXT,payload_blob BLOB)")
            sentinel_connection.execute(
                "INSERT INTO upgrade_sentinel(id,payload,payload_blob) VALUES(?,?,?)",
                (1, UPGRADE_SENTINEL_TEXT, sqlite3.Binary(UPGRADE_SENTINEL_BLOB)))
            sentinel_connection.commit()
        finally:
            sentinel_connection.close()

        legacy_mapped = Path(case.evidence_dir) / "legacy-mapped.db"
        fixture = upgrade.create_legacy_mapped_fixture(
            base_db, legacy_mapped, constants, LEGACY_HOSTGROUP_FIXTURES)
        static_db = Path(case.evidence_dir) / "legacy-static.db"
        upgrade.create_legacy_static_fixture(
            base_db, static_db, constants, backend.port)
        unmapped_db = Path(case.evidence_dir) / "legacy-unmapped.db"
        upgrade.create_legacy_unmapped_fixture(base_db, unmapped_db, constants)
        unknown_db = Path(case.evidence_dir) / "unknown-layout.db"
        upgrade.create_unknown_layout_fixture(legacy_mapped, unknown_db)

        # Real startup refusal on normal legacy mapped and static databases.
        mapped_refusal = _legacy_startup_refusal(
            case, ctx, base_daemon, legacy_mapped, listener_port, "legacy-mapped")
        static_refusal = _legacy_startup_refusal(
            case, ctx, base_daemon, static_db, listener_port, "legacy-static")
        case.details["legacy_mapped_refusal"] = mapped_refusal
        case.details["legacy_static_refusal"] = static_refusal

        # Converter check is read-only for the valid mapped fixture.
        mapped_hash = upgrade.file_sha256(legacy_mapped)
        mapped_logical = upgrade.logical_database_snapshot(legacy_mapped)
        checked = _run_converter(converter, legacy_mapped)
        case.check("converter --check accepts legacy six-table mapped fixture",
                   checked.returncode == 0, base.clip(checked.stdout + checked.stderr))
        case.check("converter --check is read-only",
                   upgrade.file_sha256(legacy_mapped) == mapped_hash, "")

        # Existing backup is never overwritten; missing database is never created.
        collision_backup = Path(case.evidence_dir) / "existing-backup.bak"
        collision_backup.write_bytes(b"task-owned-existing-backup-sentinel")
        os.chmod(collision_backup, 0o600)
        collision_bytes = collision_backup.read_bytes()
        collision = _run_converter(converter, legacy_mapped, apply=True,
                                   backup=collision_backup)
        case.check("existing backup path refuses conversion",
                   collision.returncode != 0, base.clip(collision.stdout + collision.stderr))
        case.check("existing backup bytes untouched",
                   collision_backup.read_bytes() == collision_bytes, "")
        case.check("existing-backup refusal leaves database unchanged",
                   upgrade.file_sha256(legacy_mapped) == mapped_hash, "")

        missing_db = Path(case.evidence_dir) / "missing-does-not-exist.db"
        missing_backup = Path(case.evidence_dir) / "missing-backup.bak"
        missing = _run_converter(converter, missing_db, apply=True,
                                 backup=missing_backup)
        case.check("missing database is refused", missing.returncode != 0,
                   base.clip(missing.stdout + missing.stderr))
        case.check("missing database was not created", not missing_db.exists(), "")
        case.check("missing database created no backup", not missing_backup.exists(), "")

        # Apply with a fresh backup.
        fresh_backup = Path(case.evidence_dir) / "legacy-mapped.backup.db"
        applied = _run_converter(converter, legacy_mapped, apply=True,
                                 backup=fresh_backup)
        case.must("converter --apply migrates valid legacy mapped fixture",
                  applied.returncode == 0, base.clip(applied.stdout + applied.stderr))
        case.must("apply created requested backup", fresh_backup.is_file(), "")
        case.check("backup permissions are 0600",
                   upgrade.backup_mode(fresh_backup) == 0o600,
                   oct(upgrade.backup_mode(fresh_backup)))
        case.check("backup is full logical pre-migration database",
                   upgrade.logical_database_snapshot(fresh_backup) == mapped_logical, "")
        backup_hash = upgrade.file_sha256(fresh_backup)

        converted = upgrade.logical_database_snapshot(legacy_mapped)
        converted_tcp = upgrade.tcp_table_snapshot(legacy_mapped)
        case.check("converted schema has exactly four TCP tables",
                   tuple(sorted(converted_tcp["tables"])) == tuple(sorted(upgrade.CURRENT_TABLES)),
                   str(sorted(converted_tcp["tables"])))
        case.check("legacy tcp_servers/tcp_hostgroup_mappings removed",
                   not any(name in converted_tcp["tables"] for name in
                           ("tcp_servers", "tcp_hostgroup_mappings")),
                   str(sorted(converted_tcp["tables"])))
        ddl_by_name = {row[1]: row[3] for row in converted_tcp["schema"]}
        case.check("converted tcp_hostgroups DDL equals NEW_HOSTGROUPS_DDL",
                   ddl_by_name.get("tcp_hostgroups") == constants["NEW_HOSTGROUPS_DDL"],
                   str(ddl_by_name.get("tcp_hostgroups")))
        expected_groups = tuple(
            (row["hostgroup_id"], row["source_protocol"], row["source_hostgroup"],
             row["comment"]) for row in fixture["hostgroups"])
        actual_groups = tuple(converted_tcp["tables"]["tcp_hostgroups"]["rows"])
        case.check("mapping fields and merged comment bytes exact",
                   actual_groups == expected_groups,
                   f"{actual_groups!r} != {expected_groups!r}")
        before_tables = mapped_logical["tables"]
        for table in ("tcp_settings", "tcp_listeners", "tcp_routing_rules"):
            case.check(f"converted {table} every row untouched",
                       converted["tables"][table] == before_tables[table], "")
        case.check("unrelated tables and schema untouched",
                   upgrade.unrelated_snapshot(legacy_mapped)
                   == upgrade.unrelated_snapshot(fresh_backup), "")
        case.check("source mysql_servers row preserved",
                   converted["tables"].get("mysql_servers") ==
                   before_tables.get("mysql_servers"), "")
        case.check("unrelated sentinel text and BLOB rows preserved",
                   converted["tables"].get("upgrade_sentinel", {}).get("rows")
                   == [(1, UPGRADE_SENTINEL_TEXT, UPGRADE_SENTINEL_BLOB)], "")

        # Current schema is idempotent and does not create/overwrite backups.
        current_hash = upgrade.file_sha256(legacy_mapped)
        current_check = _run_converter(converter, legacy_mapped)
        case.check("converter --check accepts converted current schema",
                   current_check.returncode == 0,
                   base.clip(current_check.stdout + current_check.stderr))
        case.check("current --check is read-only",
                   upgrade.file_sha256(legacy_mapped) == current_hash, "")
        current_backup = Path(case.evidence_dir) / "current-noop-backup.bak"
        current_backup.write_bytes(b"current-backup-sentinel")
        os.chmod(current_backup, 0o600)
        current_bytes = current_backup.read_bytes()
        current_apply = _run_converter(converter, legacy_mapped, apply=True,
                                       backup=current_backup)
        case.check("current --apply is idempotent", current_apply.returncode == 0,
                   base.clip(current_apply.stdout + current_apply.stderr))
        case.check("current --apply leaves database unchanged",
                   upgrade.file_sha256(legacy_mapped) == current_hash, "")
        case.check("current --apply does not overwrite backup",
                   current_backup.read_bytes() == current_bytes, "")

        # Static, unmapped, and unknown layouts refuse check/apply unchanged.
        _converter_refusal(case, converter, static_db, "static legacy check")
        _converter_refusal(
            case, converter, static_db, "static legacy apply",
            backup=Path(case.evidence_dir) / "static-refused.bak")
        _converter_refusal(case, converter, unmapped_db, "unmapped legacy check")
        _converter_refusal(
            case, converter, unmapped_db, "unmapped legacy apply",
            backup=Path(case.evidence_dir) / "unmapped-refused.bak")
        _converter_refusal(
            case, converter, unknown_db, "unknown layout apply",
            backup=Path(case.evidence_dir) / "unknown-refused.bak")

        # Start the converted DB without --initial and serve saved mapped traffic.
        converted_daemon = _clone_datadir_for_database(
            ctx, base_daemon, legacy_mapped, "upgrade-converted")
        case.daemons.append(converted_daemon)
        converted_daemon.start()
        case.check("converted startup argv omits --initial",
                   "--initial" not in converted_daemon.argv, str(converted_daemon.argv))
        base.exec_sqls(converted_daemon, [
            "LOAD MYSQL SERVERS FROM DISK",
            "LOAD MYSQL SERVERS TO RUNTIME",
        ])
        require_mapping_schema(converted_daemon)
        binary_payload = (b"\x00\xff"
                          + lib.deterministic_payload(65536, 20261111))
        converted_daemon.wait_echo(listener_port, binary_payload, timeout=15)
        case.check("converted database serves saved mapped binary echo",
                   True, f"{len(binary_payload)} bytes with NUL/0xff")
        converted_db = _actual_daemon_db(converted_daemon)
        case.must("converted daemon database is the inspected datadir DB",
                  converted_db.is_file(), str(converted_db))
        for removed in upgrade.LEGACY_SIX_TABLES:
            if removed not in upgrade.CURRENT_TABLES:
                cp = converted_daemon.query(f"SELECT count(*) FROM {removed}")
                case.check(f"removed config table absent: {removed}",
                           cp.returncode != 0, base.clip(cp.stderr))

        # Four-table SAVE/LOAD oracle: Admin editable memory before SAVE, actual
        # changed Admin memory, then restored Admin rows; disk is the same real
        # daemon datadir database, never the original legacy fixture.
        initial_admin = _editable_admin_snapshot(converted_daemon)
        saved_mapping = "saved 'mapping'\tline1\nline2\\end"
        saved_listener = "saved 'listener'\tline1\nline2\\end"
        saved_rule = "saved 'rule'\tline1\nline2\\end"
        base.exec_sqls(converted_daemon, [
            "UPDATE tcp_settings SET worker_threads=3",
            f"UPDATE tcp_hostgroups SET comment={base.sql_lit(saved_mapping)} "
            "WHERE hostgroup_id=21",
            f"UPDATE tcp_listeners SET comment={base.sql_lit(saved_listener)} "
            "WHERE listener_id=1",
            f"UPDATE tcp_routing_rules SET comment={base.sql_lit(saved_rule)} "
            "WHERE rule_id=1",
        ])
        saved_memory = _editable_admin_snapshot(converted_daemon)
        case.check("editable Admin mutations actually changed memory",
                   saved_memory != initial_admin, "")
        case.check("saved mapping comment bytes present in Admin",
                   ("21", "MYSQL", "10",
                    saved_mapping.encode().hex().upper())
                   in saved_memory["tcp_hostgroups"], str(saved_memory["tcp_hostgroups"]))
        case.check("saved listener comment bytes present in Admin",
                   any(row[-1] == saved_listener.encode().hex().upper()
                       for row in saved_memory["tcp_listeners"]), "")
        case.check("saved rule comment bytes present in Admin",
                   any(row[-1] == saved_rule.encode().hex().upper()
                       for row in saved_memory["tcp_routing_rules"]), "")
        cp = converted_daemon.query("SAVE TCP CONFIG TO DISK", timeout=15)
        case.must("converted four-table SAVE TO DISK", cp.returncode == 0,
                  base.clip(cp.stderr))
        saved_disk = upgrade.tcp_table_snapshot(converted_db)
        case.check("actual datadir DB contains saved nonempty rules",
                   bool(saved_disk["tables"]["tcp_routing_rules"]["rows"]), "")

        base.exec_sqls(converted_daemon, [
            "UPDATE tcp_settings SET worker_threads=1",
            "UPDATE tcp_hostgroups SET comment='mutated'",
            "UPDATE tcp_listeners SET comment='mutated'",
            "DELETE FROM tcp_routing_rules",
        ])
        mutated_memory = _editable_admin_snapshot(converted_daemon)
        case.check("pre-LOAD Admin mutations actually changed memory",
                   mutated_memory != saved_memory, "")
        case.check("pre-LOAD rule deletion empty in Admin",
                   mutated_memory["tcp_routing_rules"] == (), "")
        cp = converted_daemon.query("LOAD TCP CONFIG FROM DISK", timeout=15)
        case.must("converted four-table LOAD FROM DISK", cp.returncode == 0,
                  base.clip(cp.stderr))
        loaded_memory = _editable_admin_snapshot(converted_daemon)
        case.check("LOAD FROM DISK restores complete editable Admin rows/comments",
                   loaded_memory == saved_memory, "")
        case.check("LOAD FROM DISK leaves actual datadir DB at saved snapshot",
                   upgrade.tcp_table_snapshot(converted_db) == saved_disk, "")
        case.check("LOAD FROM DISK restores nonnull saved rule row",
                   any(row[0] == "1" for row in loaded_memory["tcp_routing_rules"]), "")

        case.must("converted slow shutdown exits 0",
                  converted_daemon.shutdown_slow() == 0, "")
        converted_daemon.initial = False
        converted_daemon.start()
        base.exec_sqls(converted_daemon, [
            "LOAD MYSQL SERVERS FROM DISK",
            "LOAD MYSQL SERVERS TO RUNTIME",
        ])
        converted_daemon.wait_echo(listener_port, binary_payload, timeout=15)
        case.check("converted restart serves saved mapped binary echo",
                   True, f"{len(binary_payload)} bytes with NUL/0xff")
        case.check("converted restart argv omits --initial",
                   "--initial" not in converted_daemon.argv, str(converted_daemon.argv))
        require_mapping_schema(converted_daemon)
        restart_admin = _editable_admin_snapshot(converted_daemon)
        case.check("converted restart restores editable Admin rows/comments/rules",
                   restart_admin == saved_memory, "")
        case.check("converted restart actual datadir DB equals saved snapshot",
                   upgrade.tcp_table_snapshot(converted_db) == saved_disk, "")
        case.check("backup remains unchanged after conversion and restarts",
                   upgrade.file_sha256(fresh_backup) == backup_hash, "")
        case.details["converted_daemon_db"] = str(converted_db)
        case.details["saved_admin_rows"] = saved_memory
        case.details["loaded_admin_rows"] = loaded_memory
        case.details["restart_admin_rows"] = restart_admin

        case.details["converter"] = str(converter)
        case.details["converter_constants"] = sorted(constants)
        case.details["base_database"] = str(base_db)
        case.details["legacy_mapped_database"] = str(legacy_mapped)
        case.details["converted_backup"] = str(fresh_backup)
        case.details["listener_port"] = listener_port
        case.details["expected_hostgroups"] = fixture["hostgroups"]
    finally:
        if backend is not None:
            backend.stop()
        if converted_daemon is not None:
            converted_daemon.close()
        if base_daemon is not None:
            base_daemon.close()
    return case


CASES = {
    "mysql_raw": lambda ctx: case_raw(ctx, "MYSQL"),
    "mysql_limits": lambda ctx: case_limits(ctx, "MYSQL"),
    "mysql_status": lambda ctx: case_status(ctx, "MYSQL"),
    "mysql_control": lambda ctx: case_control(ctx, "MYSQL"),
    "mysql_remap": lambda ctx: case_remap(ctx, "MYSQL"),
    "mysql_monitor": case_mysql_monitor,
    "mysql_shared": lambda ctx: case_shared(ctx, "MYSQL"),
    "pgsql_raw": lambda ctx: case_raw(ctx, "PGSQL"),
    "pgsql_limits": lambda ctx: case_limits(ctx, "PGSQL"),
    "pgsql_status": lambda ctx: case_status(ctx, "PGSQL"),
    "pgsql_control": lambda ctx: case_control(ctx, "PGSQL"),
    "pgsql_remap": lambda ctx: case_remap(ctx, "PGSQL"),
    "pgsql_monitor": case_pgsql_monitor,
    "pgsql_shared": lambda ctx: case_shared(ctx, "PGSQL"),
    "upgrade": case_upgrade,
}


class Context:
    def __init__(self, args, run_dir):
        self.args = args
        self.run_dir = run_dir
        self.current_case = None
        self.host = args.proxysql
        self.plugin = args.plugin_copy
        self.mysql = args.mysql
        self.converter = args.converter


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--proxysql", required=True, help="absolute path to v4 host binary")
    parser.add_argument("--plugin", required=True, help="absolute path to immutable plugin DSO")
    parser.add_argument("--mysql", default=shutil.which("mysql") or "/usr/bin/mysql",
                        help="mysql CLI used for ProxySQL Admin and the task-owned mysqld fixture")
    parser.add_argument("--case", action="append", default=[],
                        help="repeat/comma list of: " + ",".join(CASES) + ",all")
    parser.add_argument("--converter", default=str(upgrade.resolve_converter_path()),
                        help="offline migrate_tcp_config.py (env TCP_PROXY_CONVERTER)")
    parser.add_argument("--output-json", default="")
    return parser.parse_args(argv)


def selected_cases(raw):
    names = []
    for item in raw or ["all"]:
        names.extend(x.strip() for x in item.split(",") if x.strip())
    if "all" in names:
        return list(CASES)
    unknown = [name for name in names if name not in CASES]
    if unknown:
        raise SystemExit(f"unknown case(s): {', '.join(unknown)}")
    return names


def exception_result(ctx, name, exc):
    case = ctx.current_case
    if case is None:
        case = Case(name, os.path.join(ctx.run_dir, name))
    if isinstance(exc, (Blocked, FixtureBlocked)):
        case.block(f"{type(exc).__name__}: {exc}")
    else:
        case.checks.append({"name": "exception", "ok": False,
                            "detail": base.clip(f"{type(exc).__name__}: {exc}")})
        case.failures.append(f"{type(exc).__name__}: {base.clip(exc)}")
        case.details["traceback"] = traceback.format_exc()
    return case.result()


def main(argv=None):
    args = parse_args(argv)
    args.proxysql = os.path.abspath(args.proxysql)
    args.plugin = os.path.abspath(args.plugin)
    args.mysql = os.path.abspath(args.mysql)
    for label, path in (("host", args.proxysql), ("plugin", args.plugin), ("mysql", args.mysql)):
        if not os.path.isfile(path):
            raise SystemExit(f"{label} not found: {path}")
    os.makedirs("/tmp/native-tcp-proxy", exist_ok=True)
    run_dir = os.path.join(
        "/tmp/native-tcp-proxy",
        "daemon-mapped-" + datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}")
    os.makedirs(run_dir, exist_ok=False)
    plugin_sha = base.sha256_file(args.plugin)
    args.plugin_copy = os.path.join(run_dir, "proxysql_tcp_proxy.snapshot.so")
    shutil.copyfile(args.plugin, args.plugin_copy)
    os.chmod(args.plugin_copy, 0o500)
    copy_sha, after_sha = base.sha256_file(args.plugin_copy), base.sha256_file(args.plugin)
    if not plugin_sha == copy_sha == after_sha:
        raise SystemExit(
            f"plugin changed while snapshotting: {plugin_sha}/{copy_sha}/{after_sha}")
    script = os.path.abspath(__file__)
    result = {
        "kind": "mapped-tcp-real-daemon-smoke",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "script": script,
        "script_sha256": base.sha256_file(script),
        "host": args.proxysql,
        "host_sha256": base.sha256_file(args.proxysql),
        "plugin_source": args.plugin,
        "plugin_source_sha256": plugin_sha,
        "plugin_copy": args.plugin_copy,
        "plugin_copy_sha256": copy_sha,
        "mysql_cli": args.mysql,
        "mysql_cli_sha256": base.sha256_file(args.mysql),
        "argv": argv if argv is not None else sys.argv[1:],
        "run_dir": run_dir,
        "cases": {},
        "failures": [],
        "blocked": [],
    }
    ctx = Context(args, run_dir)
    for name in selected_cases(args.case):
        started = time.monotonic()
        ctx.current_case = None
        try:
            item = CASES[name](ctx).result()
        except (Blocked, FixtureBlocked) as exc:
            item = exception_result(ctx, name, exc)
        except Exception as exc:  # noqa: BLE001 - every case is independent
            item = exception_result(ctx, name, exc)
        item["duration_s"] = round(time.monotonic() - started, 3)
        result["cases"][name] = item
        if item["status"] == "FAIL":
            result["failures"].append({"case": name, "failures": item["failures"]})
        elif item["status"] == "BLOCKED":
            result["blocked"].append({"case": name, "blocked": item["blocked"]})
        print(f"[{item['status']}] {name} ({item['duration_s']}s)", flush=True)
        for reason in item["failures"] + item["blocked"]:
            print(f"  {reason}", flush=True)
    counts = {status: sum(1 for item in result["cases"].values()
                          if item["status"] == status)
              for status in ("PASS", "FAIL", "BLOCKED")}
    result["counts"] = counts
    result["exit_code"] = 1 if counts["FAIL"] else (2 if counts["BLOCKED"] else 0)
    out_path = args.output_json or os.path.join(run_dir, "result.json")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"summary: PASS={counts['PASS']} FAIL={counts['FAIL']} "
          f"BLOCKED={counts['BLOCKED']}", flush=True)
    print(f"result: {out_path}", flush=True)
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
