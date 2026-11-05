# DuckDB replica load characterization — 2026-11-05

The current applier completed roughly 480 changed data rows/s in this update-heavy overload test. Offering roughly 1,000 rows/s accumulated seconds of lag. Offering roughly 100 rows/s kept median observed visibility latency near 0.3 seconds. All six runs passed exact row and file/position/GTID checks after every workload.

These are observations from one shared host with two DuckDB threads. They do not define a supported capacity or latency SLA. No production optimization was made.

## Measurements

Each cell below is the median of three runs. Throughput parentheses show the observed range. Latency columns are medians of per-run transaction-latency percentiles, in seconds.

| Requested data rows/s | Aggregate readers | Completion data rows/s (range) | Visibility p50 s | Visibility p99 s | Final drain s |
|---:|---:|---:|---:|---:|---:|
| 100 | 0 | 90 (89.50–89.94) | 0.35 | 1.30 | 1.10 |
| 100 | 2 | 90 (89.79–89.88) | 0.31 | 1.30 | 1.10 |
| 1,000 | 0 | 485 (477.22–491.94) | 7.85 | 10.43 | 8.52 |
| 1,000 | 2 | 456 (449.80–455.89) | 8.64 | 11.22 | 9.57 |

Completion throughput divides all changed data rows by the time from the first scheduled write until the final marker is observed. It includes source generation and final drain. The lower-load case's approximately 90 rows/s completion rate includes that final drain; the source submits approximately 100 rows/s. Source achieved transaction rates and source elapsed times are in the [raw results](2026-11-05-duckdb-replica-load.csv).

Across six fresh child processes, the snapshot of 200,001 rows took a median **1.79 s**, range 1.64–1.85 s. That is 111,938 rows/s at the median. Snapshot timing starts before START and ends when applying state and the durable source coordinates are visible.

One source transaction updating 5,000 data rows plus one marker took a median **9.00 s** from submission to observation, range 8.87–9.29 s. Its completion rate was 556 data rows/s. Each run supplies only one sample for this phase; its individual p50/p99 fields describe that one observation.

The two analytical clients together completed about **402 queries/s** in the lower-load case and **390 queries/s** in the higher-load case. Their per-run p99 query times had medians of 7.34 ms and 7.52 ms, respectively. These sequential comparisons retain cache and execution-history effects; they do not isolate a causal reader penalty.

Sampled child RSS peaks ranged from **173 to 386 MiB** across phases. RSS is the whole ProxySQL child, including DuckDB and cached allocations. Sampling every 20 ms can miss transient peaks. Per-phase baselines and peaks are in the CSV; sequential history prevents attributing differences solely to readers. This short run does not establish long-term memory stability.

## Workload and method

- Linux x86_64, AMD Ryzen 9 5950X, 16 cores / 32 logical CPUs, about 125 GiB host RAM; shared host with other services. ProxySQL files use /tmp on ext4. The filesystem had about 1.4–1.6 GiB available during these runs.
- Production code at `1f78ca5d5`; the harness and shared fixture are the accompanying test-only change. DuckDB 1.4.5, two threads, default 1GB memory limit; dedicated MySQL 8.4.8 source in `proxysql/ci-infra:dbdeployer-mysql84-binlog`.
- The infra image runs three mysqld processes and three binlog helper processes. They share the host with the child. Source settings: ROW/FULL, checksum NONE, 128 MiB InnoDB buffer pool, `sync_binlog=0`, `innodb_flush_log_at_trx_commit=2`. These relaxed source flush settings affect source cost; this is process/load characterization rather than a power-loss durability test.
- Seed: 200,000 rows `(id INT PRIMARY KEY, val BIGINT, note VARCHAR(256))` with a repeated/compressible 256-character payload, plus one initial marker-table row. Dataset size, row widths and operations limit transfer to other workloads.
- Each paced phase submits 20 data-row UPDATEs and one inserted marker in each source transaction, at 5 or 50 transactions/s for eight seconds. There are 40 or 400 transactions. Marker overhead adds 5% to replicated row-event count; reported data-row throughput excludes markers.
- One observer polls distinct replicated markers every 10 ms using a dedicated DuckDB MySQL connection. Latency uses a single local monotonic clock from the source COMMIT response to receipt of the observer result. Every marker is counted, including several applied in the same flush; a commit-publication race is retried. These are observed upper bounds on visibility, including polling and query latency.
- The reader phase runs the same writes while two separate sessions continuously execute the query below. Reader connections are ready before timing. The measured interval includes drain; an in-flight read finishing after stop is omitted from query counts.
- Full row equality and exact source file/position/GTID agreement are checked after each timed interval. A deliberately stopped applier fails the marker deadline. Recovery regression passes all 19 assertions after the shared fixture extraction. Benchmark default skip and all six enabled runs pass (11 assertions each).

```sql
SELECT id%32 AS bucket, COUNT(*), SUM(val), SUM(length(note))
FROM replica.<fixture_schema>.a_bulk
GROUP BY 1 ORDER BY 1;
```

## Reproduction

Build the plugin/core normally, then build the harness:

```bash
make -C test/tap/tests test_duckdb_replica_bench-t

# Use a disposable source and standard administrative TAP_MYSQL* credentials.
RUN_DUCKDB_REPLICA_BENCH=1 test/tap/tests/test_duckdb_replica_bench-t
RUN_DUCKDB_REPLICA_BENCH=1 REPLICA_BENCH_RATE=5 \
  test/tap/tests/test_duckdb_replica_bench-t
```

Run each command three times for this matrix. The child uses its own ports and data directory. Credentials must permit fixture schema/account creation, grant/revoke and session `sql_log_bin=0`, as in the recovery test. The normal grouped runner forwards the opt-in and workload controls into its tester container. Its `TEST_TAP_TIMEOUT` must accommodate all phases; `REPLICA_BENCH_TIMEOUT` applies to each measured phase. Optional `TAP_PROXYSQL_BINARY` and `TAP_DUCKDB_PLUGIN` overrides select local build artifacts for direct execution.

Controls: `REPLICA_BENCH_ROWS` (default 200000), `REPLICA_BENCH_SECONDS` (8), `REPLICA_BENCH_RATE` (50 transactions/s), `REPLICA_BENCH_TXN_ROWS` (20), `REPLICA_BENCH_READERS` (2), `REPLICA_BENCH_LARGE_TXN_ROWS` (5000), `REPLICA_BENCH_TIMEOUT` (180 s). Without `RUN_DUCKDB_REPLICA_BENCH=1`, the test skips before accessing MySQL or creating a child. JSON measurements are emitted as `REPLICA_BENCH` TAP diagnostics.

## Next performance work

Profile the per-row execution path before choosing an optimization. The applier currently builds and runs a separate SQL statement for every changed row. Reusable prepared statements or grouped row operations are candidates to compare with this baseline; the current measurements establish the cost but do not isolate it from binding, index maintenance or other engine work.

Low-rate tail latency also warrants a separate flush experiment: the current 200 ms flush check runs on incoming events, and the requested heartbeat interval is one second. The observed roughly one-second final drain is consistent with that path; confirming the cause needs a controlled change and the same workload.
