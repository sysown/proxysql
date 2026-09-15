# PostgreSQL extended-protocol query cache prototype

This prototype adds result caching for a limited extended-query exchange. It
uses the existing PostgreSQL query cache, memory budget, query rules, TTL,
soft-refresh mechanism and empty-result policy. Simple-query cache entries
remain separate. No new runtime variable or cache table is required.

## Supported exchange

Prepare the statement in a separate, completed cycle, then execute:

```text
Parse(named or unnamed statement) -> Sync
Bind(unnamed portal) -> [Describe portal] -> Execute(max_rows=0) -> Sync
```

The statement must be a rule-selected SELECT. Both text and binary parameter
encodings and result formats supported by the existing backend path work.
Zero parameters, NULL parameters and empty values are supported. Preparation,
statement description, validation and closing retain their existing behavior.

The prototype bypasses caching for:

- Parse bundled with execution, multiple Bind/Execute operations per cycle,
  standalone statement descriptions, implicit synchronization and nonzero
  Execute row limits.
- Transactions, locked sessions, untracked startup options, or sessions with
  an attached backend carrying potentially session-local state.
- Query rewrites, forced new connections, explicitly disabled multiplexing,
  replication-lag requirements and a nonempty global `pgsql-init_connect`.
- Locking SELECTs, errors, notices, command-only results, zero-column results,
  partially transferred results and executions detected as creating session
  state by the existing multiplexing-state detector.

Results from a backend with a nonempty `init_connect` are not inserted.
Existing restrictions remain: named portals and heterogeneous per-column
result formats are not newly supported. Unsupported cache cases use the normal
execution path; existing protocol errors are not hidden or changed.

## Key and response

The key contains a distinct extended-cache domain/version, destination
hostgroup and a hash of length-delimited components:

- Exact stored prepared SQL and the parameter-type OID array supplied to Parse.
- The entire Bind suffix after its two NUL-terminated names, including format
  counts/codes, parameter counts, NULL markers, lengths, values and result
  formats. The normal protocol parser still validates messages; cache key
  construction does not decode or render parameter values.
- Whether Describe-portal output was requested.
- Tracked session-variable values and startup values.

The existing cache also incorporates the connection's user/database identity.
Neither client-local statement names nor reusable internal statement IDs are
used as query identity. Identical statements can therefore share entries across
connections. Semantically equivalent but differently encoded Bind messages can
occupy separate entries; no canonicalization is attempted.

Only buffers produced by the execution are cached. Earlier ParseComplete and
BindComplete responses are not copied. Replay preserves the requested
RowDescription shape and result encodings, and ends the supported cycle with
an idle ReadyForQuery. Cached row/affected-row counts feed normal request
accounting. A related routing fix carries Bind's selected hostgroup into
Describe/Execute, including after a simple-query cache hit or rule reload.

## Configuration and limitations

Use a narrowly scoped query rule for an application query known to be safe to
memoize, for example:

```sql
INSERT INTO pgsql_query_rules
  (rule_id, active, match_pattern, cache_ttl, apply)
VALUES
  (100, 1, '^SELECT c FROM sbtest1 WHERE id=', 60000, 1);
LOAD PGSQL QUERY RULES TO RUNTIME;
```

`cache_ttl` is in milliseconds. Existing `cache_empty_result`,
`pgsql-query_cache_stores_empty_result`, `pgsql-query_cache_soft_ttl_pct` and
`pgsql-query_cache_size_MB` retain their meanings. Cache counters are shared
between simple and extended execution; there are no per-protocol counters.

As with the existing TTL cache, writes do not invalidate entries. Rules remain
an administrator assertion that skipping execution is acceptable. The guards
are not a SQL purity checker: arbitrary volatile functions, session-dependent
functions, side effects hidden inside functions, and untracked context are not
made safe by caching. Avoid such queries. In particular, do not infer that all
SELECTs are safe merely because the protocol supports them.

Flush the cache when changing backend session defaults, permissions, schema
semantics or hostgroup initialization settings. A hostgroup-specific
`init_connect` enabled after an entry was warmed does not invalidate that old
entry; insertion checks alone cannot protect a lookup of pre-existing data.

```sql
PROXYSQL FLUSH PGSQL QUERY CACHE;
```

## Tests

`test/tap/tests/pgsql-extended_query_cache-t.cpp` exercises real libpq and raw
wire exchanges, response sequencing, cache counters and backend query counts.
It requires an **isolated ProxySQL instance**: it flushes the PostgreSQL cache,
installs/removes query rule 971004, and temporarily changes the cache size and
result-streaming threshold (restored on normal completion). Use the normal TAP PostgreSQL frontend
and admin environment variables; `PGDATABASE` selects the frontend database.
The database-isolation test additionally connects to `template1`. The backend
user needs permission to create temporary tables and set custom session GUCs.

```sh
make -C test/tap/tests pgsql-extended_query_cache-t
LD_LIBRARY_PATH="$PWD/test/tap/tap" test/tap/tests/pgsql-extended_query_cache-t
```

The existing `pgsql-query_cache_test-t` now expects separately prepared
execution to populate/hit the extended cache while simple execution uses its
own entry. Existing protocol and Bind-format regression tests also apply.

This is a functional prototype, not a performance claim. Benchmark separately
with identical warmup/measurement protocols and measured cache-hit counters.
