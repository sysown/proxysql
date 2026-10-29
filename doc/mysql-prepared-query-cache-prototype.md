# MySQL prepared-statement result cache prototype

This prototype extends the existing MySQL query cache to native
`COM_STMT_EXECUTE`. The companion PostgreSQL implementation is described in
[PostgreSQL extended-protocol query cache](pgsql-extended-query-cache-prototype.md).
Enable caching with an ordinary
`mysql_query_rules.cache_ttl` rule matching the prepared SQL; no new variable or
cache backend is introduced.

## Build availability

Prepared-statement result caching is compiled only with `PROXYSQL31=1`
(Innovative tier), including `PROXYSQL40=1` builds, which imply that flag.
Stable builds without `PROXYSQL31` execute prepared statements normally but
never look up or insert their results in the query cache. MySQL text-protocol
caching is unchanged on every tier. Parameter-type tracking and malformed
execute validation remain active on every tier as protocol correctness fixes.

Clean core build artifacts when switching tiers, and pass the tier flag on
every build invocation, for example `PROXYSQL31=1 make -j4` after cleaning.
The TAP test reads the server's `admin-version`: it checks cache bypass and
backend execution on Stable builds, and runs the full prepared-cache suite on
Innovative and Plugin Chassis builds. Both paths verify text-query cache hits.

## Scope and key

Eligible requests are SELECTs recognized by the existing nonlocking-SELECT
check, with cursor flags zero, iteration count one, and **no pending LongData**
for that client statement (including zero-length LongData). This first version
also bypasses active transactions, autocommit-off sessions, locked hostgroups,
and rules requiring `min_gtid`, `gtid_from_hostgroup` or `max_lag_ms`. Unsupported requests continue
through the existing execution path; cursor support itself is not changed.

Cache eligibility additionally scans the entire prepared SQL once for `FOR`
and `LOCK` tokens, independently of the routing heuristic. Statement
terminators, arbitrary trailing comments and whitespace cannot hide a locking
clause. This deliberately conservative check can also bypass nonlocking SQL
containing those tokens in strings, comments, identifiers or expressions.

Conceptually, the key is:

```
existing user identity + binary-cache domain + destination hostgroup
  + hash(exact prepared-SQL identity, execute bytes from flags through end,
         effective raw parameter-type block, tracked session settings)
```

The statement manager already hashes the exact prepared SQL, username and
prepare-time schema. If a query rule rewrites SQL during PREPARE, this is the
effective SQL actually prepared, not the original pre-rewrite text. SQL digests
are not used as cache keys: embedded literals remain significant.

The four-byte packet header, command byte and client-local statement ID are
excluded from the execute hash so different handles/connections can share an
entry. Everything else in the execute payload is hashed unchanged. There is no
SQL literal substitution, parameter-value decoding or value canonicalization
for cache lookup.

The key also hashes length-delimited tracked session-variable values,
including time zone, SQL mode and character-set settings. Configured defaults
are used where available for values not yet present in the session tracker;
unset dynamically tracked variables have a distinct absent representation.
Changing these settings partitions entries without changing refresh or admission policies.
Equivalent tracked representations share entries across connections; this
does not canonicalize differently spelled but semantically equivalent values.

MySQL permits later executes to omit parameter types. The last raw two-byte
type descriptor per parameter is retained **per client statement handle**, and
included in every key. This preserves signedness and distinguishes identical
value bytes interpreted as, for example, FLOAT versus LONG. Backend misses
also use these effective types, rather than types last used by another handle
sharing the global statement. Closing a handle removes its type state; resetting
a statement clears LongData while retaining its types.

An explicit-type execute and an omitted-type execute intentionally have
different keys, even with equal values. Warm both packet forms. This is a
safe false miss, consistent with the opaque-byte design. Different binary
encodings of equal SQL values are not deduplicated. Keys use the existing
hash-based cache model, not collision-free full-key storage.

Hits replay cached **binary wire rows**, using the existing EOF/OK capability
conversion. Parameter values are decoded on misses, and on hits only when
prepared-parameter event logging is enabled. Rows-sent accounting is retained.
Only complete, successful, single resultsets are inserted; errors, partial
transfers and non-result responses are not cached.

TTL, soft-TTL refresh, eviction, warning handling and empty-result policy use
the existing cache implementation. This does not add invalidation or automatic
cache-safety analysis. As with text caching, operators must restrict rules to
appropriate reads: untracked session-dependent expressions, temporary tables,
schema changes and write freshness still need care. The tracked-state key does
not account for arbitrary backend state or initialization SQL; flush on changes
to backend defaults, permissions or schema semantics. The extra transaction
guards are not a claim that arbitrary SELECTs are safe to cache.

Protocol reference: [MySQL COM_STMT_EXECUTE](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html).

## Correctness test

Build with the repository's normal settings, then:

```sh
make -C test/tap/tests mysql-prepared_query_cache-t PROXYSQL40=1
```

Run `mysql-prepared_query_cache-t` with the normal `TAP_HOST`, `TAP_PORT`,
`TAP_USERNAME`, `TAP_PASSWORD`, `TAP_ADMINHOST`, `TAP_ADMINPORT`,
`TAP_ADMINUSERNAME`, and `TAP_ADMINPASSWORD` environment variables. The test
needs the TAP shared libraries on `LD_LIBRARY_PATH`. The harness loads `.env`
files next to the executable and can override shell settings; copying the test
executable into an isolated temporary directory avoids that override.

Use an **isolated ProxySQL instance**: the test flushes the shared query cache,
temporarily changes the warning policy, and installs/removes rule 971003. It
needs a reachable MySQL-compatible backend, but creates no backend tables.
Set `mysql-query_cache_soft_ttl_pct=0` for deterministic hit/expiry assertions,
and enable `mysql-enable_client_deprecate_eof` to exercise both EOF variants.
No other cache traffic should run concurrently because counters are global.

Coverage includes binary hits without backend execution, NULL/empty/embedded-NUL
values, type and unsignedness reuse, multiple client handles, temporal values,
multi-byte NULL bitmaps, LongData/reset, cursor bypass, protocol separation,
cross-connection EOF conversion, empty/warning admission, execution errors,
disabled rules, malformed packets, rejected-execute LongData cleanup, GTID
constraint bypass, hard expiry, locking-clause variants, tracked session-state
isolation and transaction bypass. Ordinary test cases use a long TTL; the
expiration case sets a short TTL and warms a fresh entry. Repeat with
`mysql-eventslog_stmt_parameters=1` to exercise decoded/logged hits.

## Benchmark starting point

Use warmed primary-key lookups through MySQL's binary prepared protocol to
measure the cache-hit path. On a disposable backend,
create a dedicated `ps_cache_bench` schema and prepare a sysbench point-select
dataset directly against that backend. For example, with credentials supplied
in a protected sysbench config file:

```sh
sysbench --config-file=backend.conf --db-driver=mysql --mysql-db=ps_cache_bench \
  --tables=1 --table-size=10000 --threads=1 oltp_point_select prepare
```

On an isolated ProxySQL, choose an unused rule ID and configure a narrowly
scoped rule (adjust the username to the benchmark user):

```sql
INSERT INTO mysql_query_rules
  (rule_id, active, username, schemaname, match_pattern, cache_ttl, apply)
VALUES
  (971004, 1, 'bench', 'ps_cache_bench',
   '^SELECT c FROM sbtest[0-9]+ WHERE id=', 3600000, 1);
LOAD MYSQL QUERY RULES TO RUNTIME;
```

Give the working set enough cache memory. The local 10,000-key smoke test
needed more than a 32 MB cache under the existing memory-accounting/eviction
rules; 256 MB was used for the warmed-hit check. Inspect
`Query_Cache_Memory_bytes` and `Query_Cache_Purged`, not just result payload size.

Run through ProxySQL with prepared statements explicitly enabled:

```sh
sysbench --config-file=proxy.conf --db-driver=mysql --mysql-db=ps_cache_bench \
  --db-ps-mode=auto --tables=1 --table-size=10000 --rand-type=uniform \
  --threads=16 --time=30 --report-interval=5 oltp_point_select run
```

The standard `oltp_point_select` script issues one primary-key SELECT per event
without BEGIN/COMMIT. Do not use an OLTP transaction workload for this first
prototype. `--db-ps-mode=disable` provides a text-protocol control run.

Warm up before measuring and inspect counter **deltas** over each measured
interval:

```sql
SELECT Variable_Name, Variable_Value FROM stats_mysql_global
WHERE Variable_Name IN (
  'Query_Cache_count_GET', 'Query_Cache_count_GET_OK', 'Query_Cache_count_SET',
  'Com_frontend_stmt_execute', 'Com_backend_stmt_execute');
```

For a fully warmed binary run, frontend executes and cache hits should rise
together while backend executes stay flat. Random warmup does not prove every
key is cached; verify the measured deltas. Repeat warmup if new workers send
previously unseen explicit-type packet forms.

For real throughput comparisons, use an optimized, non-DEBUG build; matching
SQL, row widths, key distribution and cache-hit ratio; the same TLS/compression
settings; comparable cache memory and TTL conditions; dedicated server CPUs;
and remote load generators that do not saturate first. Sweep concurrency and
report latency alongside QPS. Keep soft-TTL settings explicit and choose TTLs
long enough that refresh/expiration does not occur during a 100%-hit run.
Do not interpret changes in backend misses as cache-hit-path speedups.

This prototype reuses the existing cache's admission and refresh policies.
Throughput benchmarking is separate work from the correctness tests above.

## Local verification (2026-09-14)

Validated with a DEBUG ProxySQL build and an isolated MariaDB 10.11 backend:

- New integration suite: 128/128 assertions, repeated with prepared-parameter
  JSON event logging enabled (128/128).
- Existing regressions: `reg_test_5639_stmt_execute_max_allowed_packet-t` (8),
  `reg_test_3546-stmt_empty_params-t` (100), `reg_test_3585-stmt_metadata-t` (54),
  and `reg_test_3603-stmt_metadata-t` (14), all passing.
- sysbench 1.0.20 binary point-select smoke runs against 10,000 keys with 16
  local client threads; these are functional checks, not maximum-throughput
  measurements or a production-readiness claim.

## Review-fix verification (2026-09-15)

The expanded integration suite passes 187/187 assertions with an optimized,
non-debug build against both MariaDB 10.11 and MySQL 8.0. Each backend also
passes with prepared-parameter JSON event logging enabled. The same suite
reproduces 21 failed assertions against the pre-fix binary. MySQL 8.4, 9.0
and 9.5 are registered for CI coverage, not claimed as locally verified.
