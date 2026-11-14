#!/usr/bin/env python3
"""Four-mode full-daemon benchmark for mandatory mapped TCP forwarding.

Modes
  direct   client -> task-owned selector echo backend
  mysql    client -> real daemon + plugin -> mapped MySQL HGM -> backend
  pgsql    client -> real daemon + plugin -> mapped PostgreSQL HGM -> backend
  haproxy  client -> optional local HAProxy -> backend

There is no static tcp_servers mode: mandatory mapping is the only product
configuration.  Old five-mode reports remain historical and are never relabelled
as four-table measurements.

All modes import the same workload functions from ``benchmark.py`` and use the
same task-owned backend process, echo protocol and payload generator.  Monitors
are disabled for every ProxySQL mode.  Results describe the whole daemon process
(host and plugin hashes, config/log paths, PID CPU/RSS/fds/threads); they are not
engine-only measurements and are not deployment claims.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import benchmark as bench
import daemon_admin_smoke as base
import tcp_proxy_testlib as lib
from mapped_monitor_fixtures import (
    HOST,
    MappedDaemon,
    configure_mapped,
    require_mapping_schema,
)

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parents[2]
DATE = "2026-11-11"
DEFAULT_JSON = (REPO_ROOT / "docs" / "benchmarks"
                / f"{DATE}-tcp-four-table-daemon.json")
DEFAULT_MD = (REPO_ROOT / "docs" / "benchmarks"
              / f"{DATE}-tcp-four-table-daemon.md")
DEFAULT_RAW_DIR = Path("/tmp/native-tcp-proxy/tcp-four-table-bench-raw")
ALL_MODES = ("direct", "mysql", "pgsql", "haproxy")
PRECHECK_TIMEOUT = 20.0


def optional_sha256(path):
    if not path or not os.path.isfile(path):
        return None
    return bench.sha256_file(path)


def local_source_provenance():
    files = [
        "plugins/tcp_proxy/src/engine.cpp",
        "plugins/tcp_proxy/src/config.cpp",
        "plugins/tcp_proxy/src/admin.cpp",
        "plugins/tcp_proxy/src/plugin.cpp",
        "plugins/tcp_proxy/include/tcp_proxy.h",
        "plugins/tcp_proxy/include/tcp_proxy_plugin.h",
        "plugins/tcp_proxy/src/engine_internal.h",
        "include/ProxySQL_PluginRawBackend.h",
        "lib/ProxySQL_PluginRawBackend.cpp",
    ]
    out = []
    for relative in files:
        path = REPO_ROOT / relative
        if path.is_file():
            out.append({"path": relative, "sha256": bench.sha256_file(str(path))})
        else:
            out.append({"path": relative, "missing": True})
    return out


def load_verified_source_manifest(manifest_text):
    """Rehash the complete coordinator manifest against the private source root."""
    manifest = Path(manifest_text).expanduser().resolve()
    if not manifest.is_file():
        raise RuntimeError(f"source manifest not found: {manifest}")
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid source manifest: {exc}") from exc
    declared_root = Path(str(document.get("source_root", ""))).expanduser().resolve()
    if declared_root != REPO_ROOT.resolve():
        raise RuntimeError(
            f"source manifest root {declared_root} is not private worktree {REPO_ROOT}")
    rows = document.get("files")
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("source manifest has no files array")
    verified = []
    seen = set()
    for index, item in enumerate(rows):
        if not isinstance(item, dict):
            raise RuntimeError(f"source manifest files[{index}] is not an object")
        relative = str(item.get("path") or "")
        expected = str(item.get("sha256") or "").lower()
        if not relative or not expected:
            raise RuntimeError(f"source manifest files[{index}] lacks path/sha256")
        candidate = (declared_root / relative).resolve()
        try:
            candidate.relative_to(declared_root)
        except ValueError as exc:
            raise RuntimeError(f"source path escapes root: {relative}") from exc
        if relative in seen:
            raise RuntimeError(f"duplicate source manifest path: {relative}")
        if not candidate.is_file():
            raise RuntimeError(f"source manifest file missing: {relative}")
        actual = bench.sha256_file(str(candidate))
        if actual != expected:
            raise RuntimeError(
                f"source manifest hash mismatch for {relative}: {actual} != {expected}")
        seen.add(relative)
        verified.append({
            "path": relative,
            "sha256": actual,
            "components": list(item.get("components") or []),
        })
    metadata = {
        "path": str(manifest),
        "sha256": bench.sha256_file(str(manifest)),
        "source_root": str(declared_root),
        "file_count": len(verified),
        "core_manifest_sha256": document.get("core_manifest_sha256"),
        "plugin_manifest_sha256": document.get("plugin_manifest_sha256"),
        "deleted_units": document.get("deleted_units") or [],
        "status": document.get("status"),
    }
    return verified, metadata


def driver_artifacts():
    files = [
        "plugins/tcp_proxy/tests/daemon_benchmark.py",
        "plugins/tcp_proxy/tests/benchmark.py",
        "plugins/tcp_proxy/tests/bench_backend.py",
        "plugins/tcp_proxy/tests/tcp_proxy_testlib.py",
        "plugins/tcp_proxy/tests/daemon_admin_smoke.py",
        "plugins/tcp_proxy/tests/daemon_mapped_smoke.py",
        "plugins/tcp_proxy/tests/mapped_monitor_fixtures.py",
        "plugins/tcp_proxy/tests/upgrade_fixtures.py",
    ]
    return [{"path": relative, "sha256": bench.sha256_file(str(REPO_ROOT / relative))}
            for relative in files if (REPO_ROOT / relative).is_file()]


def fresh_backend_stats(backend, after_utc=None, timeout=4.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        stats = backend.live_stats()
        if stats and (after_utc is None or stats.get("updated_utc", "") > after_utc):
            return stats
        time.sleep(0.05)
    raise RuntimeError(f"backend stats did not advance past {after_utc!r} within {timeout}s")


def hgm_stats(d, protocol, hostgroup, port):
    table = ("stats_mysql_connection_pool" if protocol == "MYSQL"
             else "stats_pgsql_connection_pool")
    cp = d.query(
        "SELECT COALESCE(SUM(ConnUsed),0),COALESCE(SUM(ConnFree),0),"
        "COALESCE(SUM(ConnOK),0),COALESCE(SUM(ConnERR),0),"
        "COALESCE(MAX(MaxConnUsed),0),COALESCE(SUM(Bytes_data_sent),0),"
        "COALESCE(SUM(Bytes_data_recv),0) "
        f"FROM {table} WHERE hostgroup={hostgroup} "
        f"AND srv_host='{HOST}' AND srv_port={port}"
    )
    if cp.returncode != 0:
        raise RuntimeError(f"mapped HGM accounting unavailable: {base.clip(cp.stderr)}")
    text = cp.stdout.strip()
    if not text:
        raise RuntimeError("mapped HGM accounting returned no aggregate row")
    values = [int(value) for value in text.split("\t")]
    if len(values) != 7:
        raise RuntimeError(f"unexpected mapped HGM aggregate: {text!r}")
    return dict(zip(("ConnUsed", "ConnFree", "ConnOK", "ConnERR", "MaxConnUsed",
                     "Bytes_data_sent", "Bytes_data_recv"), values))


def wait_hgm_idle(d, protocol, hostgroup, port, timeout=6.0):
    deadline, last = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        last = hgm_stats(d, protocol, hostgroup, port)
        if last["ConnUsed"] == 0 and last["ConnFree"] == 0:
            return last
        time.sleep(0.05)
    raise RuntimeError(f"mapped HGM did not drain to Used=0 Free=0; last={last}")


def setup_daemon_mode(mode, args, backend, results_dir, state):
    if not args.proxysql or not os.path.isfile(args.proxysql):
        raise RuntimeError(f"--proxysql is required for mode {mode}: {args.proxysql!r}")
    plugin = getattr(args, "plugin_snapshot", None) or args.plugin
    if not plugin or not os.path.isfile(plugin):
        raise RuntimeError(f"--plugin is required for mode {mode}: {args.plugin!r}")
    if not args.mysql or not os.path.isfile(args.mysql):
        raise RuntimeError(f"--mysql CLI is required for mode {mode}: {args.mysql!r}")
    daemon = MappedDaemon(args.proxysql, plugin, args.mysql, results_dir,
                          f"bench-{mode}", monitors=False, no_start=True)
    try:
        daemon.start()
        # Initial --no-start has declared tables but has not seeded defaults.
        base.exec_sqls(daemon, ["INSERT OR IGNORE INTO tcp_settings(id) VALUES(1)"])
        cp = daemon.query(f"UPDATE tcp_settings SET worker_threads={args.workers}")
        if cp.returncode != 0:
            raise RuntimeError(f"tcp_settings worker_threads update failed: {cp.stderr}")
        # Phase B exposes staging tables; plugin commands become available
        # after START initializes the engine from those staged settings.
        cp = daemon.query("PROXYSQL START", timeout=15)
        if cp.returncode != 0:
            raise RuntimeError(f"PROXYSQL START failed: {cp.stderr}")
        listener = base.free_port()
        require_mapping_schema(daemon)
        protocol = "MYSQL" if mode == "mysql" else "PGSQL"
        state["mapping"] = configure_mapped(
            daemon, protocol, 10, 20, listener,
            [{"port": backend.port, "max_connections": 100000,
              "comment": f"bench-{mode}"}],
            mapping_comment=f"bench-{mode}")
        actual_workers = daemon.value("SELECT worker_threads FROM runtime_tcp_settings")
        if actual_workers != str(args.workers):
            raise RuntimeError(
                f"runtime worker_threads={actual_workers} != requested {args.workers}")
        daemon.wait_echo(listener, b"mapped-bench-setup")
    except BaseException:
        daemon.close()
        raise
    state["proxy_kind"] = "proxysql-daemon-" + mode
    state["daemon"] = daemon.record()
    state["daemon_pid"] = daemon.proc.pid
    state["start_command"] = daemon.argv
    state["listener_port"] = listener
    state["worker_threads"] = args.workers
    return daemon, listener


def run_mode(mode, args, backend, results_dir):
    started = time.monotonic()
    state = {"mode": mode, "status": "not_run", "started_utc": bench.utc_now()}
    pids = {"backend": backend.pid}
    daemon = None
    haproxy = None
    cleanup = None
    target_host, target_port = backend.host, backend.port
    try:
        if mode == "direct":
            state["proxy_kind"] = "none"
        elif mode in ("mysql", "pgsql"):
            daemon, listener = setup_daemon_mode(mode, args, backend, results_dir, state)
            target_host, target_port = HOST, listener
            pids["proxy"] = daemon.proc.pid
            cleanup = daemon.close
        elif mode == "haproxy":
            if not args.haproxy or not os.path.isfile(args.haproxy):
                state.update({
                    "status": "skipped",
                    "reason": f"optional HAProxy binary not available: {args.haproxy}",
                    "annotation": "requested HAProxy mode skipped explicitly",
                })
                return state
            haproxy = bench.HAProxyProcess(args.haproxy, backend.host, backend.port,
                                           args.workers, results_dir)
            try:
                haproxy.start()
            except BaseException:
                haproxy.stop()
                raise
            target_host, target_port = haproxy.host, haproxy.port
            pids["proxy"] = haproxy.pid
            state["proxy_kind"] = "haproxy"
            state["haproxy"] = bench.haproxy_metadata(args.haproxy)
            state["haproxy"].update({
                "nbthread": args.workers,
                "config_path": str(haproxy.config_path),
                "config": haproxy.config_path.read_text(encoding="utf-8"),
                "command": haproxy.command,
            })
            cleanup = haproxy.stop
        else:
            state.update({"status": "error", "reason": f"unknown mode {mode}"})
            return state

        state["target"] = {"host": target_host, "port": target_port}
        initial_stats = backend.live_stats()
        state["backend_stats_before"] = fresh_backend_stats(
            backend, initial_stats.get("updated_utc") if initial_stats else None)
        state["backend_connections_before"] = state["backend_stats_before"].get(
            "connections_total")
        hgm_before = None
        hgm_protocol = "MYSQL" if mode == "mysql" else ("PGSQL" if mode == "pgsql" else None)
        if hgm_protocol:
            hgm_before = wait_hgm_idle(daemon, hgm_protocol,
                                       state["mapping"]["source_hostgroup"],
                                       backend.port)
            state["hgm_before"] = hgm_before
        mode_started = time.monotonic()
        mode_process_before = bench.capture_processes(pids)
        try:
            state["precheck"] = bench.precheck(target_host, target_port, args.seed)
        except BaseException as exc:
            state.update({
                "status": "error",
                "reason": f"byte-forwarding precheck failed: {type(exc).__name__}: {exc}",
            })
            return state

        latency_payload = lib.deterministic_payload(64, args.seed + 1)
        connection_payload = lib.deterministic_payload(args.conn_payload, args.seed + 2)
        throughput_payload = lib.deterministic_payload(args.payload, args.seed + 3)
        state["phases"] = {
            "latency": bench.run_phase(
                "latency", pids,
                lambda: bench.measure_latency(target_host, target_port, args.concurrency,
                                              args.warmup, args.latency_samples,
                                              latency_payload)),
            "connections": bench.run_phase(
                "connections", pids,
                lambda: bench.measure_connections(target_host, target_port, args.concurrency,
                                                  args.duration, connection_payload)),
            "throughput": bench.run_phase(
                "throughput", pids,
                lambda: bench.measure_throughput(target_host, target_port, args.concurrency,
                                                 args.duration, throughput_payload)),
            "idle": (
                {"name": "idle", "status": "completed", "connections": 0, "skipped": True}
                if args.skip_idle else
                bench.run_phase(
                    "idle", pids,
                    lambda: bench.measure_idle(target_host, target_port,
                                               args.idle_connections, pids,
                                               args.idle_interval))),
        }
        failed = [name for name, phase in state["phases"].items()
                  if phase.get("status") != "completed"]
        if failed:
            state.update({"status": "error",
                          "reason": f"benchmark phase failed: {', '.join(failed)}"})
            return state

        end_probe = backend.live_stats()
        backend_after = fresh_backend_stats(
            backend, end_probe.get("updated_utc") if end_probe else None)
        state["backend_stats_after"] = backend_after
        state["backend_connections_after"] = backend_after.get("connections_total")
        state["backend_connections_delta"] = (
            (state["backend_connections_after"] or 0)
            - (state["backend_connections_before"] or 0)
            if state.get("backend_connections_before") is not None else None)

        phases = state["phases"]
        latency_bytes = args.concurrency * (args.warmup + args.latency_samples) * 64
        idle_bytes = 0 if args.skip_idle else args.idle_connections
        expected_c2s = (
            state["precheck"]["bytes"] + latency_bytes
            + phases["connections"]["application_bytes_client_to_server"]
            + phases["throughput"]["bytes_client_to_server"] + idle_bytes)
        expected_s2c = (
            state["precheck"]["bytes"] + latency_bytes
            + phases["connections"]["application_bytes_server_to_client"]
            + phases["throughput"]["bytes_server_to_client"] + idle_bytes)
        actual_c2s = (backend_after["bytes_client_to_server"]
                      - state["backend_stats_before"]["bytes_client_to_server"])
        actual_s2c = (backend_after["bytes_server_to_client"]
                      - state["backend_stats_before"]["bytes_server_to_client"])
        expected_connections = (
            1 + args.concurrency + phases["connections"]["connections_completed"]
            + args.concurrency + (0 if args.skip_idle else args.idle_connections))
        actual_connections = (backend_after["connections_total"]
                              - state["backend_stats_before"]["connections_total"])
        state["reconciliation"] = {
            "expected_client_to_server": expected_c2s,
            "expected_server_to_client": expected_s2c,
            "actual_client_to_server": actual_c2s,
            "actual_server_to_client": actual_s2c,
            "expected_connections": expected_connections,
            "actual_connections": actual_connections,
            "ok": (expected_c2s == actual_c2s and expected_s2c == actual_s2c
                   and expected_connections == actual_connections),
        }
        if not state["reconciliation"]["ok"]:
            state.update({
                "status": "error",
                "reason": "backend byte/connection reconciliation mismatch: "
                          + json.dumps(state["reconciliation"], sort_keys=True),
            })
            return state

        if hgm_protocol:
            hgm_after = wait_hgm_idle(daemon, hgm_protocol,
                                      state["mapping"]["source_hostgroup"],
                                      backend.port)
            state["hgm_after"] = hgm_after
            hgm_delta = {
                key: hgm_after[key] - hgm_before[key]
                for key in ("ConnOK", "ConnERR", "Bytes_data_sent", "Bytes_data_recv")
            }
            state["hgm_reconciliation"] = {
                "delta": hgm_delta,
                "used_after": hgm_after["ConnUsed"],
                "free_after": hgm_after["ConnFree"],
                "expected_client_to_server": expected_c2s,
                "expected_server_to_client": expected_s2c,
                "ok": (hgm_delta["Bytes_data_sent"] == expected_c2s
                       and hgm_delta["Bytes_data_recv"] == expected_s2c
                       and hgm_after["ConnUsed"] == 0 and hgm_after["ConnFree"] == 0),
            }
            if not state["hgm_reconciliation"]["ok"]:
                state.update({
                    "status": "error",
                    "reason": "mapped HGM byte/usage reconciliation mismatch: "
                              + json.dumps(state["hgm_reconciliation"], sort_keys=True),
                })
                return state

        elapsed = time.monotonic() - mode_started
        state["process"] = bench.process_deltas(
            mode_process_before, bench.capture_processes(pids), elapsed,
            lib.clock_ticks_per_second())
        state["process_elapsed_s"] = round(elapsed, 6)
        state["status"] = "completed"
        return state
    except BaseException as exc:
        state.update({"status": "error",
                      "reason": f"{type(exc).__name__}: {exc}",
                      "traceback": __import__("traceback").format_exc()})
        return state
    finally:
        state["elapsed_s"] = round(time.monotonic() - started, 3)
        if cleanup is not None:
            try:
                cleanup()
            except BaseException:
                pass
        if daemon is not None:
            state["daemon"] = daemon.record()


def build_markdown(report):
    env = report["environment"]
    workload = report["workload"]
    modes = report["modes"]
    prov_meta = report.get("source_provenance_manifest") or {}
    if prov_meta:
        provenance = (
            f"{prov_meta.get('file_count')} files verified from "
            f"`{prov_meta.get('path')}` sha256 `{prov_meta.get('sha256')}`; "
            f"core manifest `{prov_meta.get('core_manifest_sha256')}`, plugin manifest "
            f"`{prov_meta.get('plugin_manifest_sha256')}`. Full list in raw JSON.")
    else:
        provenance = ", ".join(
            f"`{item['path']}` " + (f"`{item['sha256']}`" if item.get("sha256")
                                    else "MISSING")
            for item in report.get("source_provenance", []))
    lines = [
        "# Four-table TCP proxy full-daemon benchmark",
        "",
        f"Date: {report['date']}. Status: local loopback measurement; not a deployment claim.",
        "",
        f"Environment: `{env['hostname']}`, {env['kernel']}, {env['machine']}, "
        f"{env['cpu_count']} CPUs, `{env['cpu_model']}`. Load average at start: "
        f"{env['loadavg_1_5_15']}. Python: `{env['python'].splitlines()[0]}`.",
        "",
        "## Provenance and scope",
        "",
        f"- ProxySQL host: `{report['host']['path']}` sha256 `{report['host']['sha256']}`.",
        f"- Plugin source: `{report['plugin']['path']}` sha256 `{report['plugin']['sha256']}`; "
        f"immutable run snapshot `{report['plugin']['snapshot_path']}` sha256 "
        f"`{report['plugin']['snapshot_sha256']}`.",
        "- ProxySQL modes use the whole daemon process PID for CPU/RSS/fd/thread "
        "values: core, Admin, SQLite, metrics, plugin and mapped HGM accounting are "
        "included. These are not `engine_harness` or engine-only measurements.",
        "- Monitors and SQL worker listeners were disabled for mysql and pgsql "
        "modes. TCP forwarding workers and the Admin interface remained active.",
        f"- Source files: {provenance}.",
        "",
        "## Workload",
        "",
        "| Parameter | Value |",
        "|---|---|",
        f"| Mode order | {', '.join(report['mode_order'])} |",
        f"| Backend | task-owned selector echo process PID {report['backend']['pid']} "
        f"127.0.0.1:{report['backend']['port']} |",
        f"| Client concurrency | {workload['concurrency']} |",
        f"| Daemon/HAProxy worker threads | {workload['workers']} |",
        f"| RTT payload / warmup / samples per connection | {workload['latency_payload_bytes']} B / "
        f"{workload['warmup_per_connection']} / {workload['latency_samples_per_connection']} |",
        f"| Connections/s payload | {workload['connection_payload_bytes']} B |",
        f"| Throughput payload / duration | {workload['throughput_payload_bytes']} B / "
        f"{workload['duration_s']} s |",
        f"| Idle connections | {workload['idle_connections']} |",
        "",
        "Each connection/s transaction requires connect + send + exact echo receive + close. "
        "Throughput verifies every echoed chunk byte-for-byte; MiB/s is application payload.",
        "",
        "## Results",
        "",
        "| Mode | Status | RTT p50 / p95 / p99 ms | Connections/s | MiB/s c→s | "
        "MiB/s s→c | Daemon CPU % | Daemon RSS KiB | Daemon fds | Daemon threads |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for mode in report["mode_order"]:
        state = modes.get(mode, {"status": "not_requested"})
        if state.get("status") != "completed":
            reason = bench.status_label(state).replace("|", "/")
            lines.append(f"| {mode} | {reason} | – | – | – | – | – | – | – | – |")
            continue
        phases = state["phases"]
        latency = phases["latency"].get("summary", {})
        conns = phases["connections"]
        throughput = phases["throughput"]
        proxy = (state.get("process") or {}).get("proxy") or {}
        proxy_cpu = (None if proxy.get("cpu_percent") is None
                     else f"{proxy['cpu_percent']:.1f}")
        lines.append(
            f"| {mode} | completed | "
            f"{latency.get('p50_ms', float('nan')):.3f} / "
            f"{latency.get('p95_ms', float('nan')):.3f} / "
            f"{latency.get('p99_ms', float('nan')):.3f} | "
            f"{conns.get('connections_per_s', float('nan')):.1f} | "
            f"{throughput.get('client_to_server_mib_per_s', float('nan')):.2f} | "
            f"{throughput.get('server_to_client_mib_per_s', float('nan')):.2f} | "
            f"{'null' if proxy_cpu is None else proxy_cpu} | "
            f"{proxy.get('rss_kb_after', 'null')} | "
            f"{proxy.get('fds_after', 'null')} | "
            f"{proxy.get('threads_after', 'null')} |"
        )
    lines += ["", "## Mode details", ""]
    for mode in report["mode_order"]:
        state = modes.get(mode, {"status": "not_requested"})
        lines.append(f"### {mode}: {state.get('status')}")
        if state.get("reason"):
            lines.append("")
            lines.append(f"Reason: {state['reason']}")
        if state.get("annotation"):
            lines.append(f"Annotation: {state['annotation']}")
        if state.get("status") == "completed":
            lines.append("")
            lines.append(
                f"- Target: {state['target']['host']}:{state['target']['port']}; "
                f"precheck 1 MiB exact echo sha256 `{state['precheck']['sha256']}`.")
            lines.append(
                f"- RTT samples: {state['phases']['latency']['summary']['count']}; "
                f"connections: {state['phases']['connections']['connections_completed']}; "
                f"throughput transactions: {state['phases']['throughput']['transactions']}.")
            idle = state["phases"].get("idle", {})
            if idle.get("skipped"):
                lines.append("- Idle resources: skipped by --skip-idle.")
            else:
                lines.append(
                    f"- Idle connections: {idle.get('connections')}; quiescent interval "
                    f"{idle.get('quiescent', {}).get('interval_s')} s; proxy idle CPU "
                    f"{(idle.get('quiescent', {}).get('process', {}).get('proxy') or {}).get('cpu_percent')}.")
            if state.get("daemon"):
                daemon = state["daemon"]
                lines.append(
                    f"- Whole daemon PID during measurement `{state.get('daemon_pid')}`; "
                    f"config `{daemon['config']}`, log `{daemon['log']}`, "
                    f"post-run returncode `{daemon.get('returncode')}`.")
            if state.get("reconciliation"):
                rec = state["reconciliation"]
                lines.append(
                    f"- Backend reconciliation: c→s {rec['actual_client_to_server']} "
                    f"(expected {rec['expected_client_to_server']}), s→c "
                    f"{rec['actual_server_to_client']} (expected "
                    f"{rec['expected_server_to_client']}), connections "
                    f"{rec['actual_connections']}/{rec['expected_connections']}.")
            if state.get("hgm_reconciliation"):
                hgm = state["hgm_reconciliation"]
                lines.append(
                    f"- Mapped HGM reconciliation: byte deltas "
                    f"{hgm['delta']['Bytes_data_sent']}/{hgm['delta']['Bytes_data_recv']} "
                    f"(expected {hgm['expected_client_to_server']}/"
                    f"{hgm['expected_server_to_client']}); Used/Free after drain "
                    f"{hgm['used_after']}/{hgm['free_after']}.")
            if state.get("mapping"):
                mapping = state["mapping"]
                lines.append(
                    f"- TCP hostgroup {mapping['tcp_hostgroup']} -> "
                    f"{mapping['protocol']} hostgroup {mapping['source_hostgroup']} "
                    f"(mandatory mapping; no local server inventory). SQL recorded in raw JSON.")
            if state.get("haproxy"):
                lines.append(
                    f"- HAProxy {state['haproxy'].get('version', '')} "
                    f"nbthread={state['haproxy'].get('nbthread')}.")
        lines.append("")
    lines += [
        "## Caveats",
        "",
        "- Local loopback short runs only; Python client/backend scheduling and GIL limits apply.",
        "- Modes run sequentially and each ProxySQL mode starts a fresh task-owned daemon.",
        "- `mysql` and `pgsql` CPU/RSS/fd/thread figures describe the whole daemon "
        "process, not the standalone Engine harness and not a deployment footprint.",
        "- Missing optional HAProxy is an explicit skipped mode and is never fabricated.",
        "- A failed exact-byte precheck or benchmark phase marks that mode `error`; the "
        "process exits nonzero if any requested mode errored.",
        "",
        f"Raw JSON: `{report['artifacts']['json']}`.",
        "",
    ]
    return "\n".join(lines)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--modes", default="direct,mysql,pgsql,haproxy",
                        help="comma-separated: direct,mysql,pgsql,haproxy")
    parser.add_argument("--proxysql", default="", help="absolute path to the v4 ProxySQL host binary")
    parser.add_argument("--plugin", default="", help="absolute path to the tcp_proxy plugin DSO")
    parser.add_argument("--mysql", default=shutil.which("mysql") or "",
                        help="mysql CLI used to configure the task-owned daemon")
    parser.add_argument("--haproxy", default="", help="optional HAProxy binary")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--latency-samples", type=int, default=300)
    parser.add_argument("--duration", type=float, default=2.0)
    parser.add_argument("--payload", type=int, default=65536)
    parser.add_argument("--conn-payload", type=int, default=64)
    parser.add_argument("--idle-connections", type=int, default=8)
    parser.add_argument("--idle-interval", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=20261111)
    parser.add_argument("--output-json", default=str(DEFAULT_JSON))
    parser.add_argument("--output-md", default=str(DEFAULT_MD))
    parser.add_argument("--raw-dir", default=str(DEFAULT_RAW_DIR))
    parser.add_argument("--skip-idle", action="store_true")
    parser.add_argument("--source-manifest", default="",
                        help="coordinator complete {source_root,files[]} manifest to rehash")
    parser.add_argument("--provenance-preflight", action="store_true",
                        help="verify provenance/artifact paths and exit without measuring")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    modes = [item.strip() for item in args.modes.split(",") if item.strip()]
    unknown = [mode for mode in modes if mode not in ALL_MODES]
    if unknown:
        print(f"unknown mode(s): {unknown}", file=sys.stderr)
        return 2
    if not modes:
        print("no modes selected", file=sys.stderr)
        return 2
    for mode in modes:
        if mode in ("mysql", "pgsql") and not (args.proxysql and args.plugin):
            print(f"mode {mode} requires --proxysql and --plugin", file=sys.stderr)
            return 2

    provenance_rows = local_source_provenance()
    provenance_metadata = {"mode": "local-default", "file_count": len(provenance_rows)}
    if args.source_manifest:
        try:
            provenance_rows, provenance_metadata = load_verified_source_manifest(
                args.source_manifest)
        except RuntimeError as exc:
            print(f"source provenance preflight failed: {exc}", file=sys.stderr)
            return 1
        provenance_metadata["mode"] = "verified-complete"

    if args.provenance_preflight:
        preflight = {
            "kind": "tcp-four-table-benchmark-provenance-preflight",
            "measurement": False,
            "source_provenance_manifest": provenance_metadata,
            "source_provenance": provenance_rows,
            "driver_artifacts": driver_artifacts(),
            "host": {"path": args.proxysql or None,
                     "sha256": optional_sha256(args.proxysql)},
            "plugin": {"path": args.plugin or None,
                       "sha256": optional_sha256(args.plugin)},
            "haproxy": {"path": args.haproxy or None,
                        "sha256": optional_sha256(args.haproxy)},
        }
        print(json.dumps(preflight, indent=2))
        return 0

    results_dir = Path(args.raw_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    args.plugin_snapshot = None
    plugin_source_sha = optional_sha256(args.plugin)
    if args.plugin and os.path.isfile(args.plugin):
        snapshot = results_dir / "proxysql_tcp_proxy.benchmark.snapshot.so"
        shutil.copyfile(args.plugin, snapshot)
        os.chmod(snapshot, 0o500)
        snapshot_sha = optional_sha256(str(snapshot))
        if snapshot_sha != plugin_source_sha or optional_sha256(args.plugin) != plugin_source_sha:
            print("plugin changed while snapshotting; refusing to benchmark", file=sys.stderr)
            return 1
        args.plugin_snapshot = str(snapshot)
    backend = bench.BackendProcess(results_dir)
    try:
        backend.start()
    except BaseException as exc:
        print(f"backend start failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    report = {
        "kind": "tcp-four-table-full-daemon-benchmark",
        "schema_version": 1,
        "date": DATE,
        "generated_utc": bench.utc_now(),
        "host": {"path": args.proxysql or None,
                 "sha256": optional_sha256(args.proxysql)},
        "plugin": {"path": args.plugin or None,
                   "sha256": plugin_source_sha,
                   "snapshot_path": args.plugin_snapshot,
                   "snapshot_sha256": optional_sha256(args.plugin_snapshot)},
        "haproxy": {"path": args.haproxy or None,
                    "sha256": optional_sha256(args.haproxy)},
        "source_provenance": provenance_rows,
        "source_provenance_manifest": provenance_metadata,
        "driver_artifacts": driver_artifacts(),
        "environment": bench.environment_metadata(),
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
            "monitors_enabled": False,
            "scope": "whole ProxySQL daemon process for mysql/pgsql modes",
        },
        "backend": {
            "pid": backend.pid,
            "host": backend.host,
            "port": backend.port,
            "started_utc": backend.started_utc,
            "command": backend.command,
            "script": str(TESTS_DIR / "bench_backend.py"),
            "script_sha256": bench.sha256_file(str(TESTS_DIR / "bench_backend.py")),
        },
        "schema": {
            "kind": "four-table mandatory mapping",
            "tables": ["tcp_settings", "tcp_hostgroups", "tcp_listeners",
                       "tcp_routing_rules"],
            "removed": ["tcp_servers", "tcp_hostgroup_mappings",
                        "runtime_tcp_servers", "runtime_tcp_hostgroup_mappings",
                        "stats_tcp_servers", "stats_tcp_hostgroup_mappings"],
        },
        "mode_order": modes,
        "modes": {},
    }
    try:
        for mode in modes:
            print(f"[mapped-bench] {mode}", flush=True)
            state = run_mode(mode, args, backend, results_dir)
            report["modes"][mode] = state
            print(f"[mapped-bench] {mode}: {bench.status_label(state)}", flush=True)
        for missing in ALL_MODES:
            if missing not in modes:
                report["modes"][missing] = {
                    "mode": missing,
                    "status": "skipped",
                    "reason": f"not requested (--modes {args.modes})",
                }
    finally:
        final_stats = backend.stop()
    report["backend"]["final_stats"] = final_stats
    report["artifacts"] = {
        "json": os.path.abspath(args.output_json),
        "markdown": os.path.abspath(args.output_md),
        "raw_dir": str(results_dir),
    }
    for name in ("host", "plugin", "haproxy"):
        entry = report[name]
        entry["sha256_after"] = optional_sha256(entry.get("path"))
        entry["stable"] = (entry.get("sha256") is None
                           or entry.get("sha256") == entry["sha256_after"])
    plugin_entry = report["plugin"]
    plugin_entry["snapshot_sha256_after"] = optional_sha256(
        plugin_entry.get("snapshot_path"))
    plugin_entry["snapshot_stable"] = (
        plugin_entry.get("snapshot_sha256") is None
        or plugin_entry.get("snapshot_sha256") == plugin_entry["snapshot_sha256_after"])
    report["errors"] = [
        {"mode": mode, "reason": state.get("reason")}
        for mode, state in report["modes"].items()
        if state.get("status") == "error"
    ]
    for name in ("host", "plugin"):
        if not report[name]["stable"]:
            report["errors"].append({
                "mode": name,
                "reason": f"{name} binary changed during the benchmark run",
            })
    if not report["plugin"].get("snapshot_stable", True):
        report["errors"].append({
            "mode": "plugin",
            "reason": "plugin snapshot changed during the benchmark run",
        })
    report["caveats"] = [
        "Local loopback short-run measurements only; not deployment claims.",
        "Python client/backend scheduling limits apply; backend is a separate process.",
        "ProxySQL modes measure the whole daemon process, not the standalone Engine harness.",
        "Missing optional HAProxy is skipped explicitly; no result is fabricated.",
        "Any requested mode error makes the process exit nonzero.",
    ]
    json_path, md_path = Path(args.output_json), Path(args.output_md)
    bench.write_json_atomic(json_path, report)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(build_markdown(report), encoding="utf-8")
    print(f"json: {json_path}")
    print(f"markdown: {md_path}")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
