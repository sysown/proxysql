# Native TCP proxy Engine — independent integration tests and benchmarks

This directory contains Task4-only tooling. It never implements a relay: all
data-path tests go through `tcp_proxy::Engine` linked from the approved
production sources. Python owns loopback clients/backends, deterministic
payloads, exact byte/hash assertions, `/proc` observations and cleanup.

Files:

| File | Purpose |
|---|---|
| `engine_harness.cpp` | Newline-JSON control harness around the production Engine, plus an explicitly TEST-only backend provider |
| `Makefile.integration` | Task4 build/test/benchmark targets (does not touch Task1 `Makefile`) |
| `tcp_proxy_testlib.py` | Backends, clients, config builders, harness client, `/proc` helpers |
| `test_fixtures_selfcheck.py` | Gate 1 fixture checks; no Engine needed |
| `test_engine_adversarial.py` | 36 active general scenarios + explicit 8-case RETIRED ledger |
| `daemon_admin_smoke.py` | Four-table mapped lifecycle/persistence/collision Admin smoke |
| `bench_backend.py` | Task-owned selector echo backend process for benchmarks |
| `benchmark.py` | HISTORICAL engine-only direct/native/optional HAProxy driver |
| `daemon_mapped_smoke.py` | Real-daemon four-table mapped MySQL/PGSQL HGM smoke cases |
| `daemon_benchmark.py` | Four-mode direct/mapped MySQL/mapped PGSQL/HAProxy daemon benchmark |
| `mapped_monitor_fixtures.py` | Task-owned mysqld and controlled PG wire monitor fixtures |
| `readiness.py` | Validates the explicit approved-source manifest |

## Prerequisites and build

Requirements: Linux, Python 3.10+, a C++17 compiler, and `deps/json/json.hpp`
in the repository (already vendored). `openssl` on `PATH` is required only for
the TLS regression (otherwise that scenario reports `BLOCKED`, never PASS).

Header-only syntax check (no production sources or marker needed):

```sh
cd plugins/tcp_proxy/tests
make -f Makefile.integration syntax
python3 -m py_compile tcp_proxy_testlib.py test_fixtures_selfcheck.py \
    test_engine_adversarial.py benchmark.py bench_backend.py readiness.py \
    daemon_admin_smoke.py daemon_mapped_smoke.py daemon_benchmark.py \
    mapped_monitor_fixtures.py mapped_fixture_selfcheck.py
```

Fixture self-check (no Engine, safe everywhere):

```sh
make -f Makefile.integration selfcheck
```

### Approved production sources

The coordinator supplies `/tmp/native-tcp-proxy/test-engine-sources-ready.json`
and copies the approved sources into this worktree. The manifest must contain
an explicit source list; wildcards are rejected. Accepted shapes include:

```json
{
  "engine_sources": [
    {"path": "plugins/tcp_proxy/src/config.cpp", "sha256": "..."},
    {"path": "plugins/tcp_proxy/src/engine.cpp", "sha256": "..."},
    {"path": "plugins/tcp_proxy/include/tcp_proxy.h", "sha256": "..."},
    {"path": "plugins/tcp_proxy/src/engine_internal.h", "sha256": "..."}
  ]
}
```

A plain JSON array of paths, or `sources`/`files`/`paths` arrays, also works.
`readiness.py --check` verifies existence and every supplied hash.

For a fresh checkout without the coordinator's private `/tmp` marker, generate a
local-source manifest from the explicit reviewed list (the two remaining Engine
`.cpp` units plus `tcp_proxy.h` and `engine_internal.h`):

```sh
make -f Makefile.integration local-manifest \
    LOCAL_MANIFEST=/tmp/native-tcp-proxy/local-engine-manifest.json
# equivalent:
python3 readiness.py --create-local-manifest /tmp/native-tcp-proxy/local-engine-manifest.json

READY_MARKER=/tmp/native-tcp-proxy/local-engine-manifest.json \
    make -f Makefile.integration check-engine-ready harness
# Use the same explicit manifest for tests and benchmark provenance:
READY_MARKER=/tmp/native-tcp-proxy/local-engine-manifest.json \
    make -f Makefile.integration test bench
```

The generated document is labelled `local-source` and records each computed
SHA256 (never a wildcard, never Admin/plugin sources). It is a reproducibility
aid, not coordinator approval; during active task work the coordinator marker
remains the gate.

Build the harness only after the marker exists:

```sh
make -f Makefile.integration check-engine-ready
make -f Makefile.integration harness
```

`ENGINE_SRCS` may be overridden with another reviewed explicit list; it is
never expanded from `src/*.cpp` (that would capture Admin/plugin dependencies).

## Harness control protocol

One JSON object per line on stdin; one response per line on stdout, correlated
by request `id`. Diagnostics go to stderr. Operations:

| `op` | Payload | Result |
|---|---|---|
| `ping` | – | pid, frozen-header SHA256 |
| `validate` | `config` + optional `backend_fixtures` | `valid`, descriptive `error` |
| `start` | `config` + optional `backend_fixtures` | `ok`, `error`, product `snapshot` + sibling `backend_provider` |
| `apply` | `config` + optional `backend_fixtures` | `ok`, `error`, product `snapshot` + sibling `backend_provider` |
| `snapshot` | – | product `snapshot` + sibling TEST `backend_provider` counters |
| `provider_snapshot` | – | TEST `backend_provider` counters only |
| `config` | – | effective four-table product `config`, `running` |
| `stop` | – | `ok`, product `snapshot` after stop + `backend_provider` |
| `apply_concurrent` | `configs` (2+) + optional parallel `backend_fixtures` arrays | per-thread `ok/busy/error`, `start_us/end_us`, `overlapped`, product `snapshot` |
| `apply_stop_race` | `config` + optional `backend_fixtures` | apply timing/result, stop timing, product `snapshot` |
| `quit` | – | stop Engine, exit 0 |

`config` is **exactly** the four product tables: settings, hostgroups (mapping
fields only), listeners and rules. Unknown or obsolete keys are rejected with a
descriptive error; there is no `config[servers]` fallback and no silent
stripping. In particular `servers`, `hostgroup_mappings`, and old hostgroup
`balance`/`health_check_*` fields are invalid.

Provider fixture controls live in the top-level sibling `backend_fixtures`,
consumed only by TestBackendProvider. The Python `ScenarioConfig` object keeps
them in `.backend_fixtures`, outside its four-key product dict. The test
provider supplies loopback endpoint identity, fixture capacity, administrative
status and retry order so the real Engine can retain generic relay/lifetime
coverage after static product servers were deleted. Its counters are labelled
`test-backend-provider` and are **not** evidence of core HGM selection, health
or counters. Actual HGM behavior is exercised only by the real-daemon suites.

Product `Snapshot` never contains provider rows. Tests that need both use
`HarnessClient.observation()` (product `snapshot` plus sibling
`backend_provider`) or `HarnessClient.provider_snapshot()`; plain
`HarnessClient.snapshot()` returns only the product Snapshot.

`apply_concurrent` and `apply_stop_race` use helper threads *only* to call the
real `Engine::apply`/`Engine::stop`; there is no test-side forwarding. A start
barrier is used, but the suite requires `busy` only when the measured Engine
call intervals actually overlap. The busy classifier accepts the engine's
descriptive "already in progress" phrasing as well as the word "busy".

Example:

```sh
printf '%s\n' '{"id":1,"op":"ping"}' | ./engine_harness
```

## Adversarial suite

```sh
make -f Makefile.integration test
# or:
python3 test_engine_adversarial.py --harness ./engine_harness \
    --results-dir /tmp/native-tcp-proxy/test-results
```

Useful options: `--list`, `--scenarios CFG,BIN,RET-02`,
`--seed`, `--timeout`, `--verbose`.

There are 36 active scenarios plus an explicit retirement ledger. Run:

```sh
python3 test_engine_adversarial.py --list
python3 test_engine_adversarial.py --list-retired
```

Retired because they **exclusively** tested deleted standalone selection/health
policy (SID and rationale are also written to `summary.json`). Materially
changed-but-retained cases carry their exact SID/change rationale in
`summary.json -> changed_scenarios`:

| SID | Rationale | Replacement coverage |
|---|---|---|
| SEL-01 | deleted product weighted-round-robin selection | core HGM; mapped daemon limits/monitor |
| SEL-02 | deleted product leastconn tie/capacity selection | core HGM; mapped daemon limits |
| SEL-03 | deleted product primary/backup and local saturation | core HGM; mapped daemon shared capacity |
| RT-01 | deleted local health fall/rise hysteresis | native monitor/HGM; mapped daemon status/monitor |
| RT-02 | deleted local health enable/disable policy | native monitor configuration; mapped daemon status |
| RT-03 | deleted local replacement probe epoch | core HGM identity/status; mapped daemon remove/readd |
| RT-04 | deleted local replacement rise/fall health | native monitor/HGM; mapped daemon monitor |
| RT-05 | deleted local reclaimed-server probe epoch | core HGM identity/status; mapped daemon remove/readd |

All generic BIN/TLS/CFG/CAP frontend/GEN/RET/LIFE/LEAK/RACE coverage remains,
including hard-fence semantics through the test provider.

The active scenarios cover:

- `CFG` validation bounds/references/CIDRs/overlap, failed start, startup-only
  rollback, IPv4/IPv6 and wildcard `IPV6_V6ONLY`.
- `BIN` multi-buffer binary payloads, observed backpressure, server-first
  greetings, both half-close directions, partial/nonblocking I/O, idle and
  half-close deadlines, and a delayed half-close response whose wait must not
  burn Engine CPU (`BIN-07`, measured from `/proc/<pid>/stat` ticks).
- `TLS` a real Python TLS handshake through the Engine using an ephemeral
  task-owned openssl CA and localhost certificate. The test client verifies the
  generated CA and server hostname; the backend loads the generated server
  certificate/key (there is no client-certificate or mutual-TLS assertion).
  Exact binary echo larger than several Engine buffers and an orderly
  `close_notify` exchange on both test endpoints (`TLS-01`).
- `CAP` global/listener frontend admission, test-fixture server capacity,
  pending-connect capacity released at the configured total connect budget,
  lowered capacity preservation, burst pressure with exact `recv_exact`
  classification.
- `SEL-04` source routing/REJECT/default/first-match order. The deleted
  balancing/backup cases are in the retirement table above.
- `GEN` pinned established flows, `OFFLINE_HARD` old-generation ack, soft
  removal/retry eligibility, bind rollback, overlapping moves, concurrent apply
  and admission, repeated reload/restart.
- `RET` verified `SYN_SENT` pending-connect scenarios: RST retry, total budget,
  all-candidates exhaustion, late success, no read/replay while pending.
- `LIFE` bounded stop with mixed flows, repeated stop/restart, post-stop socket
  ownership.
- `LEAK` repeated start/apply/failed-apply/hard-offline/stop fd/thread audit.
- `RACE` apply-vs-stop, concurrent apply accounting/ordering, admission during
  activation.

Concurrent-apply scenarios do not treat helper-thread call-interval overlap or
completion timestamps as proof of Engine lock overlap or publication order.
They require success + busy + unexpected-error counts to cover every contender,
generation increments to equal the number of successful applies, the final
Config to equal one complete successful candidate, and explicit sequential
A-then-B ordering. Repeated real contenders record whether busy rejections were
actually observed.

Statuses are `PASS`, `FAIL`, `BLOCKED` (environment), `INCONCLUSIVE` (required
condition not observable). Failures are never relaxed: each result records the
scenario, seed, detail/evidence and a reproduce command, and the runner
continues independent scenarios. Per-scenario JSON plus `summary.json` and
`run-context.json` go to `--results-dir`. The run context embeds the exact
readiness manifest bytes/digest, resolved source digests, frozen-header digest
and harness digest at run time, not just the mutable marker pathname.

Snapshot polls raise on predicate timeout and include the last snapshot; they
never return the last non-matching snapshot as if it satisfied the predicate.
Pending-connect tests first saturate a task-owned loopback backlog, then verify
the Engine's own outbound socket is in `SYN_SENT` via `/proc/<pid>/fd` inode
matching. If a kernel cannot create that state the scenario reports
`BLOCKED`, not a pass.

## Benchmarks

```sh
make -f Makefile.integration bench            # HISTORICAL direct+HAProxy
python3 benchmark.py --modes direct,haproxy   # tooling check without native
python3 benchmark.py --modes direct,native,haproxy \
    --allow-historical-engine-only            # historical engine-only native
python3 benchmark.py --duration 10 --concurrency 16 --latency-samples 2000
```

Each mode uses the same task-owned selector echo backend process, echo
protocol, payload generator, client parameters, and worker count where
applicable. HAProxy uses `nbthread` equal to `--workers` (default 2), TCP mode,
no health checks and no logging.

Measured phases:

- **RTT**: persistent connections, warmup then raw per-connection samples;
  reports nearest-rank p50/p95/p99. Local thread samples are merged and the
  expected `concurrency × samples` count is enforced.
- **Connections/s**: only completed connect + send + exact echo receive +
  close transactions are counted. Rates use the actual interval through the
  bounded client-thread joins, so in-flight transactions that finish during
  join are neither counted without a matching denominator nor silently lost.
- **Throughput**: every echoed chunk is compared byte-for-byte; bytes/s is
  reported separately for client→server and server→client application payload.
  All client threads must join; surviving threads fail the phase and owned
  sockets are closed.
- **Idle footprint**: RSS/fd/thread baseline before connections, settled-idle
  delta after establishing them, and a separate quiescent CPU interval sampled
  only after the flows settle. Establishment CPU (connect + echo + settle) is
  reported distinctly from quiescent CPU. Raw tick deltas, tick precision and
  the one-second default idle window are recorded.
- **CPU**: process tick deltas for proxy and backend over the whole monotonic
  mode window (direct has no proxy PID, so proxy CPU/RSS are `null`). Markdown
  never sums unrelated phase percentages.
- A 1 MiB exact-byte precheck gates every mode. A failed phase marks the mode
  `error`; it never produces fabricated results.

`benchmark.py` is **HISTORICAL engine-only tooling** and is superseded by
`daemon_benchmark.py`. Native mode requires the explicit
`--allow-historical-engine-only` flag and writes
`docs/benchmarks/2026-11-11-native-tcp-proxy-historical.{json,md}` by default,
so it cannot overwrite current four-table reports or be mistaken for daemon
evidence. The benchmark records the exact readiness manifest bytes/digest,
resolved source and header digests, endpoint `TCP_NODELAY` choices, and the
adversarial suite summary (pass `--suite-summary`).

For the corrected evidence run:

```sh
python3 benchmark.py --modes direct,native,haproxy \
    --duration 2 --concurrency 4 --latency-samples 300 \
    --idle-connections 256 --idle-interval 1.0 \
    --suite-summary /tmp/native-tcp-proxy/test-final-results/summary.json \
    --raw-dir /tmp/native-tcp-proxy/bench-raw-final \
    --allow-historical-engine-only
```

Native mode is skipped with an explicit reason when the readiness marker or
harness is absent. The native target is the **standalone `engine_harness`
process**, not a running ProxySQL daemon: its CPU, RSS, fd and thread figures
exclude ProxySQL core, Admin, SQLite, metrics and plugin/daemon integration and
cannot describe a full daemon/plugin footprint. The Markdown table and raw JSON
caveats state this explicitly. The benchmark records the marker status/note and
the adversarial-suite summary; if unresolved source defects are reported there,
the result is marked provisional and limited to steady-state echo measurements.

Limitations: loopback only; Python client/backend scheduling and the GIL can
dominate; modes run sequentially; short default runs are not deployment
claims or confidence intervals.

## Mapped TCP hostgroup daemon tests

These tests target the four-table mandatory mapping SQL and ABI-18 raw backend
service. Every mapped TCP hostgroup has
`hostgroup_id/source_protocol/source_hostgroup/comment`; `tcp_servers`,
`tcp_hostgroup_mappings`, their runtime projections and `stats_tcp_servers`
must be absent.
They do not implement a relay. `daemon_mapped_smoke.py` imports the existing
`Daemon`/`Mysql`/`SQL` helpers and test-owned plugin snapshot logic, but starts
the daemon with monitors enabled only for the monitor cases.

```sh
python3 daemon_mapped_smoke.py --help
python3 daemon_mapped_smoke.py \
    --proxysql /abs/path/proxysql --plugin /abs/path/proxysql_tcp_proxy.so \
    --mysql /usr/bin/mysql \
    --converter /abs/path/plugins/tcp_proxy/tools/migrate_tcp_config.py \
    --case all \
    --output-json /tmp/native-tcp-proxy/mapped-results/smoke.json
# or
make -f Makefile.integration daemon-mapped-smoke \
    PROXYSQL=/abs/path/proxysql PLUGIN=/abs/path/proxysql_tcp_proxy.so \
    CONVERTER=/abs/path/plugins/tcp_proxy/tools/migrate_tcp_config.py
```

Cases are independent so one failure does not suppress unrelated protocol
coverage:

| Case | Coverage |
|---|---|
| `mysql_raw`, `pgsql_raw` | first byte `0x00`/`0xff`, binary payloads, server-first greeting, verified TLS handshake through the mapped route |
| `mysql_limits`, `pgsql_limits` | held flow `ConnUsed=1`/`ConnFree=0`, `max_connections=1`, no backend accept for rejected admission, exact `ConnOK`/byte deltas, fresh sockets with no reuse, zero/nonzero weights, unreachable port `ConnERR`, lowered capacity preserving admitted flows |
| `mysql_status`, `pgsql_status` | `OFFLINE_SOFT`/`SHUNNED` drain/reject, `ONLINE` restore, `OFFLINE_HARD` close, fast HARD→ONLINE latch, `/proc`-verified daemon `SYN_SENT`, pending HARD with unchanged `ConnOK`/`ConnERR`, remove/readd identity and replacement capacity |
| `mysql_control`, `pgsql_control` | exactly four tables with removed schema absent, mandatory mapping/source namespace, empty source rejects, protocol-only load admits, two TCP groups share one source, invalid protocol LOAD rejected atomically, four-table SAVE/LOAD comments, restart from disk |
| `mysql_shared`, `pgsql_shared` | two TCP hostgroups share one native backend's connection limit: first held flow consumes it, second group is rejected without a backend accept, release admits the other group |
| `mysql_remap`, `pgsql_remap` | held old flow survives `tcp_hostgroups.source_hostgroup` remap, new flow uses the new backend, old source HARD closes only the old flow |
| `mysql_monitor` | fresh task-owned `mysqld --initialize-insecure` datadir, real MySQL monitor read_only log, writer demotion (retained HARD row or purged), reader admission, mapped client close, fresh writer admission after restore |
| `pgsql_monitor` | controlled PostgreSQL wire fixture (simulated backend), real PG monitor log, HGM writer demotion, mapped client close, fresh admission after recovery flag clears |
| `upgrade` | Portable fresh-daemon-DB fixture: builds legacy six-table mapped, five-table static, five-table unmapped and unknown layouts with task-owned SQLite. Proves real-daemon startup refusal without `--initial` by inspecting the actual cloned `datadir/proxysql.db` before/after, with only newly appended child-log evidence and exact core schema-preflight fragments; converter `--check` read-only and `--apply` exclusive 0600 backup, no-overwrite, missing-DB refusal, exact merged comment bytes, legacy-table removal and unrelated-row/BLOB preservation; static/unmapped/unknown refusal; current-schema idempotency; converted startup serves binary mapped traffic and four-table SAVE/LOAD is checked in editable Admin memory plus the actual `upgrade-converted/proxysql.db` before and after restart. Missing converter is BLOCKED, never PASS. |

Every case configures normal `mysql_servers`/`pgsql_servers` and loads that
protocol first, then inserts the mapped `tcp_hostgroups` row and listener, then
`LOAD TCP CONFIG TO RUNTIME`. Mapped TCP hostgroups never get local server rows.

Upgrade clones set their saved `admin-mysql_ifaces` to the child helper's
assigned Admin endpoint before taking the preservation baseline. Saved
variables override generated config during startup without `--initial`.

Status semantics: `FAIL` means an observed behaviour is wrong and exits `1`.
`BLOCKED` means an explicit fixture prerequisite is unavailable (for example a
missing TLS tool, monitor fixture binary or `/proc` `SYN_SENT` observation); it
exits `2` and is never counted as a pass. Condition timeouts for stats, runtime
rows or monitor logs are `FAIL`. A missing mapping schema is `BLOCKED` while the
mapped artifact is unavailable. The JSON records immutable host/plugin hashes,
the snapshot path, argv/config/log paths and all collected per-case observations,
including any case whose exception occurs after earlier checks.

Fixture selfcheck (uses installed `psql` and a task-owned `mysqld` datadir only):

```sh
make -f Makefile.integration daemon-mapped-selfcheck
python3 mapped_fixture_selfcheck.py --skip-mysql \
    --converter /abs/path/plugins/tcp_proxy/tools/migrate_tcp_config.py
```

## Four-table full-daemon benchmark

```sh
python3 daemon_benchmark.py --help
python3 daemon_benchmark.py \
    --source-manifest /abs/path/final-source-provenance.json \
    --provenance-preflight \
    --proxysql /abs/path/proxysql --plugin /abs/path/proxysql_tcp_proxy.so \
    --haproxy /abs/path/haproxy
python3 daemon_benchmark.py \
    --modes direct,mysql,pgsql,haproxy \
    --source-manifest /abs/path/final-source-provenance.json \
    --proxysql /abs/path/proxysql --plugin /abs/path/proxysql_tcp_proxy.so \
    --mysql /usr/bin/mysql --haproxy /abs/path/haproxy \
    --duration 2 --concurrency 4 --latency-samples 300 \
    --output-json /tmp/native-tcp-proxy/mapped-bench.json \
    --output-md /tmp/native-tcp-proxy/mapped-bench.md
# or
make -f Makefile.integration daemon-mapped-bench \
    PROXYSQL=/abs/path/proxysql PLUGIN=/abs/path/proxysql_tcp_proxy.so \
    SOURCE_MANIFEST=/abs/path/final-source-provenance.json
```

All four modes reuse the imported workload functions, task-owned selector echo
backend, echo protocol, payload generator and client parameters. `mysql`/`pgsql`
use real mandatory mapped hostgroups with monitors disabled; there is no static
`tcp_servers` mode. SQL worker listeners are disabled; TCP forwarding workers
and Admin remain active. Each ProxySQL mode starts a fresh task-owned daemon using the
`--no-start` flow so `tcp_settings.worker_threads` is set before the engine
starts; the tool asserts `runtime_tcp_settings.worker_threads` equals
`--workers`. The plugin is snapshotted immutably for the run and both source and
snapshot hashes are recorded.

Each mode runs a 1 MiB exact-byte precheck before measurement. Backend counters
are re-read after a fresh stats publication and reconciled exactly against
precheck bytes, RTT warmup/sample bytes, connections/s application bytes,
throughput bytes and idle-establishment bytes. `mysql`/`pgsql` also reconcile
the source HGM `Bytes_data_sent`/`Bytes_data_recv` deltas and require
`ConnUsed=ConnFree=0` after drain; a schema mismatch or missing four-table
artifact is an explicit mode error, never an unavailable success. A final run supplies
`--source-manifest` with the complete coordinator `{source_root,files[]}`
manifest; the driver rehashes every listed file from the private source root,
fails on any missing/mismatched path, and records the full verified list plus
source-manifest, core-manifest and plugin-manifest digests. The final JSON has
no `MISSING` source entries. Without the flag, local default provenance remains
available for tooling checks only. Current report paths are
`docs/benchmarks/2026-11-11-tcp-four-table-daemon.{md,json}`. The actual
2026-11-11 final run completed all four modes with exact backend
byte/connection reconciliation; MySQL and PgSQL also reconciled HGM byte deltas
and `ConnUsed=ConnFree=0`. Workload was 4 clients × 300 measured RTTs, 2 workers,
2 s connection/throughput phases and 8 idle connections.

The report contains RTT p50/p95/p99, completed connections/s, byte-verified
MiB/s in both directions, idle metrics, and whole-daemon PID CPU/RSS/fd/thread
observations where measured. The old `benchmark.py` native target is
historical, requires `--allow-historical-engine-only`, and stays explicitly
labeled engine-only; this tool makes no engine-harness memory claims.

Failure semantics: any requested mode that errors (including a failed precheck)
makes the process exit nonzero. A missing optional HAProxy binary is recorded as
an explicit `skipped` mode with an annotation. Unknown/missing required daemon
arguments are rejected before measurement. Raw JSON plus concise Markdown are
written; dated repository reports are produced only by an actual run.

## Cleanup and ownership

- All listeners use loopback and ephemeral ports. Only task-owned children are
  stopped, with bounded waits; there is no broad `pkill`.
- Backends/harness are closed in `finally` blocks; benchmark child PIDs and
  start commands are recorded.
- `make -f Makefile.integration clean` removes only `engine_harness` and
  `__pycache__`.
- The frozen four-table header is consumed as-is. This tooling makes no
  production engine/core/plugin edits. Final matching release host/DSO,
  converter and 318-file source provenance were executed and verified on
  2026-11-11.

Final matching-artifact daemon validation completed on 2026-11-11: Admin
**5/5 PASS**, mapped **15/15 PASS** with the portable upgrade case at **86
checks**, and the final Engine component is equivalent to the retained
**36/36 PASS** actual run. The measured four-mode report is
[`docs/benchmarks/2026-11-11-tcp-four-table-daemon.md`](../../../docs/benchmarks/2026-11-11-tcp-four-table-daemon.md);
historical reports remain untouched.
