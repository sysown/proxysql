# Native mapped TCP versus permanent SQL fast-forward

This focused harness compares three **real SQL** paths for each protocol:

| Path | Frontend endpoint | Backend |
|---|---|---|
| `direct` | task-owned MySQL/PostgreSQL server | same server |
| `native` | four-table `tcp_proxy` listener (mapped through ProxySQL HGM) | task-owned server |
| `ff` | ProxySQL SQL listener with runtime user `fast_forward=1` | task-owned server |

The same native C++ client, SQL text, result verification, TLS policy and clock
are used for all paths. Python only orchestrates. There is no echo backend,
simulated SQL server, fake result, or fallback.

## Files

- `fast_forward_bench_client.cpp` — native MariaDB Connector/C and libpq
  client. It owns the barrier, worker threads, `steady_clock` samples, SQL text,
  exact payload comparison, connection-rate cycles and throughput loops.
- `Makefile.fast-forward` — builds the client under `/tmp/tcp-ff-benchmark`.
- `fast_forward_benchmark.py` — task-owned fixtures, fresh equivalent ProxySQL
  daemons, active-FF proof, preflight/negative checks and reports.
- `README.fast-forward.md` — this document.

## Build

The immutable host is `/tmp/tcp-four-table/core-final/proxysql` and the
immutable plugin is
`/tmp/tcp-four-table/plugin-final/binaries/proxysql_tcp_proxy-release.so`.
Their expected SHA-256 values are checked before any run.

```sh
cd /home/rene/.codex/worktrees/483d/proxysql
make -f plugins/tcp_proxy/tests/Makefile.fast-forward \
     DEPS_PATH=/mnt/data/rene/proxysql5/proxysql/deps \
     OUT_DIR=/tmp/tcp-ff-benchmark
/tmp/tcp-ff-benchmark/fast_forward_bench_client --help
python3 plugins/tcp_proxy/tests/fast_forward_benchmark.py --help
```

The MariaDB client uses the donor's matching headers and
`libmariadbclient.a`. PostgreSQL uses the donor public headers with the system
`/lib/x86_64-linux-gnu/libpq.so.5`. Donor trees are read-only inputs. The
Makefile anchors its source and makefile paths, so invoking `-f` from the
repository root and `-C plugins/tcp_proxy/tests` both work.

## Safety and fixture policy

- All datadirs, configs, logs, ports, sockets and binaries are task-owned under
  `/tmp/tcp-ff-benchmark` or a `/tmp` run directory.
- Generated fixture/admin passwords are written only to mode-0600 files. They
  are never placed in client argv or reports. The runner redacts known generated
  values from errors.
- MySQL is a real local `mysqld --initialize-insecure` fixture. PostgreSQL is a
  real PostgreSQL 16 `initdb`/`pg_ctl` fixture with host MD5 auth, local trust and
  `ssl=off`; the benchmark role is verified to have an MD5 password hash.
- Cleanup is bounded and targets only the runner's own child PID or an owned
  postmaster PID whose cmdline contains its datadir. No `pkill`, process-group
  kill, system service, production database or real credential is used.

## Proxy daemon shape

Every proxy trial starts a fresh daemon with the same shape for native and FF:

- relevant protocol SQL workers = 2 (`threads=2`, matching workers enabled);
- other protocol SQL workers and both monitors disabled;
- Admin active;
- `tcp_settings.worker_threads=2`;
- both a SQL listener and a mapped four-table TCP listener active;
- the same dedicated SQL user with `fast_forward=1`, `backend=1`,
  `frontend=1`, `use_ssl=0`;
- source server `use_ssl=0`;
- MySQL `multiplexing=false`, query cache 0, query rules empty; PostgreSQL
  query cache 0, MD5 frontend authentication and query rules empty;
- MySQL/PG frontend TLS advertisement disabled with `have_ssl=false`;
- PostgreSQL clients request `sslmode=disable` and `gssencmode=disable`;
- every MySQL/libpq connection sets and observes `TCP_NODELAY=1`;
- no cache/rewrite rules.

The native mapping bypasses SQL frontend authentication, but the equivalent user
configuration remains `fast_forward=1` in both modes so process shape and config
stay fixed. Native mode is never checked for an SQL processlist row and is not
required to expose a SQL-user flag of 0.

## Workload defaults

The measured defaults are the approved design values:

- 3 rotated rounds: `direct,native,ff`; `native,ff,direct`; `ff,direct,native`.
- 4 concurrent native client threads.
- 20 warmup queries per client and 1000 steady-state RTT samples per client on a
  64-byte deterministic alphanumeric SELECT result.
- 2 seconds of fresh connect + authenticate + first verified query + close
  (the first query is included because FF may lazily open its backend). The
  connection-cycle timer includes the close, and its rate denominator is the
  actual shared elapsed time through the last cycle and join.
- 2 seconds of established-session throughput for 64 KiB and 1 MiB SQL literal /
  result payloads. The shared timer starts after all workers reach the barrier;
  requested duration is reported separately and rates use actual elapsed time
  through the last completion and close/join. The query text is precomputed and
  reused while every returned payload byte is still verified.
- Application request/response bytes are reported separately from SQL
  text/framing and from HGM/TCP wire counters.
- TLS, GSS encryption and compression disabled and observed for every path;
  `mysql_get_ssl_cipher` must be empty, `PQsslInUse`/`PQgssEncInUse` false, no
  `CLIENT_COMPRESS`, and `TCP_NODELAY` must read back as 1.

`smoke` overrides only to a tiny profile: one round, at most 2 clients, 2
warmups, 5 RTT samples per client and 0.5-second phases. Its report says
`SMOKE` explicitly and is not a measurement.
`smoke` overrides only to a tiny profile: one round, at most 2 clients, 2
warmups, 5 RTT samples per client and 0.5-second phases. Its report says
`SMOKE` explicitly and is not a measurement.

### Exact `SELECT 1` workload

`--workload select1` is additive; the default remains `--workload literal`.
The select1 profile issues the exact eight-byte SQL text `SELECT 1` for every
positive verify, hold, warmup, RTT sample, connection cycle and persistent QPS
query. It requires exactly one row, one field and the one-byte value `1`; no
alias, quoting, semicolon or short literal substitution is used. The literal
workload and all older reports remain unchanged.

The select1 default geometry is 3 rotated rounds, 4 clients, 100 warmups and
1000 RTT samples per client, a 5-second fresh connect/authenticate/first
`SELECT 1`/close phase, and a 5-second persistent `SELECT 1` QPS phase. The
phase keys are `rtt_select1`, `connections` and `select1_qps`; bulk 64 KiB /
1 MiB phases are omitted. It produces 18 trials, 54 phases and 72,000 RTT
samples. Use it with the task-owned select1 scratch directory:

```sh
python3 plugins/tcp_proxy/tests/fast_forward_benchmark.py smoke \
  --workload select1 \
  --client /tmp/tcp-select1-benchmark/fast_forward_bench_client \
  --work-dir /tmp/tcp-select1-benchmark

python3 plugins/tcp_proxy/tests/fast_forward_benchmark.py measure \
  --workload select1 \
  --proxysql /tmp/tcp-four-table/core-final/proxysql \
  --plugin /tmp/tcp-four-table/plugin-final/binaries/proxysql_tcp_proxy-release.so \
  --client /tmp/tcp-select1-benchmark/fast_forward_bench_client \
  --work-dir /tmp/tcp-select1-benchmark \
  --measurement-ready /tmp/tcp-select1-benchmark/measurement-ready.json
```

The measured command is gated by the select1 root marker and is not run during
the smoke/checkpoint task.

## Active fast-forward proof

For each FF trial the native client completes an ordinary benchmark SELECT,
keeps that socket open, and emits its local TCP port. The runner requires
exactly one matching processlist row and then queries Admin with that port:

- MySQL: `stats_mysql_processlist` command must be `Fast forward`, and
  `extended_info.$.fast_forward` must be numeric 1. The runtime frontend row
  must show `fast_forward=1`.
- PostgreSQL: `stats_pgsql_processlist` command must be `Fast forward` and
  `extended_info.$.status` must be 22. The runtime frontend row must show
  `fast_forward=1`. PostgreSQL does not expose a `fast_forward` JSON key; its
  absence is expected and is not treated as false.

Raw processlist rows, indented extended JSON, the held-client ready line and the
runtime user row are written beside each trial. Runtime frontend `active=1`,
`frontend=1`, `fast_forward=1` and the expected source hostgroup are required.
A proof failure aborts the run; it is never labelled as a successful FF
comparison.

Native mode uses the same held post-query socket. While it is open the runner
requires: no matching frontend SQL processlist row for the client TCP port;
plugin `active_connections>0`; plugin accepted and bidirectional proxied bytes
advanced; HGM `ConnUsed>0`; and zero plugin/HGM connect-error deltas. The native
proof file retains those raw held and post-close lifecycle rows.

## Commands

Focused selfcheck (real task-owned servers; negative credentials, wrong payload,
slow-query timeout propagation and FF-proof refusal):

```sh
cd /home/rene/.codex/worktrees/483d/proxysql
python3 plugins/tcp_proxy/tests/fast_forward_benchmark.py selfcheck \
  --client /tmp/tcp-ff-benchmark/fast_forward_bench_client \
  --work-dir /tmp/tcp-ff-benchmark
```

Tiny smoke for both protocols and all three paths:

```sh
python3 plugins/tcp_proxy/tests/fast_forward_benchmark.py smoke \
  --client /tmp/tcp-ff-benchmark/fast_forward_bench_client \
  --work-dir /tmp/tcp-ff-benchmark
```

Full measurement is intentionally gated. It refuses to run unless
`/tmp/tcp-ff-benchmark/measurement-ready.json` exists and does not contain
`"ready": false`. After smoke review and quiet-window approval:

```sh
python3 plugins/tcp_proxy/tests/fast_forward_benchmark.py measure \
  --proxysql /tmp/tcp-four-table/core-final/proxysql \
  --plugin /tmp/tcp-four-table/plugin-final/binaries/proxysql_tcp_proxy-release.so \
  --client /tmp/tcp-ff-benchmark/fast_forward_bench_client \
  --work-dir /tmp/tcp-ff-benchmark \
  --measurement-ready /tmp/tcp-ff-benchmark/measurement-ready.json
```

The measured command above uses the design defaults (3/4/20/1000/2 s). It writes
a frozen manifest before any trial and rechecks every input hash after the run.
The later comparison report is
`docs/benchmarks/2026-11-11-tcp-fast-forward-comparison.{json,md}`; this harness
does not create those files before measurement approval.

## Test-only negative switches

`--negative-timeout-test` issues a real `SELECT SLEEP(2)`/`SELECT pg_sleep(2)`
with a short client timeout. It reports `timed_out=true` only for an observed
timeout/lost-connection inside a bounded elapsed window.
`--negative-timeout-completes` instead completes a real trivial query and
proves that a payload mismatch is not mislabelled as a timeout.
`--corrupt-expectation` intentionally alters one expected byte after reading a
real result, so the same comparison code must reject a mismatch.
`--inject-late-error-ms` is a selfcheck-only worker failure used to prove an
error after the requested deadline is never suppressed. These switches exist
only for `selfcheck` and are never used by measurement.
