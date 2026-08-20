# Real-Traffic TAP Coverage Design

## Goal

Increase coverage of MySQL protocol and query-cache code by making TAP tests
send standard client-library traffic and prove that ProxySQL took the intended
path. No production protocol code and no manually constructed packets are in
scope.

## Context

The merged GCOV collector repair exposed meaningful coverage from existing
tests. It also showed a gap in the EOF/OK query-cache conversion test:
`deprecate_eof_cache-t` sends traffic with two real client implementations,
but its 100 ms cache TTL can expire before the incompatible client reads the
entry. The test checks response contents only, so it can pass without proving
the conversion path or a cache hit.

Codecov also identifies ordinary client paths that are not currently exercised:
COM_FIELD_LIST conversion, one LAST_INSERT_ID variant, version-forwarding
modes with a backend, and prepared-statement metadata/locking cases.

## Alternatives considered

1. Add raw protocol packet tests. This could target parser branches quickly,
   but it would test a bespoke helper as much as ProxySQL and conflicts with
   the requirement to use real traffic for normal behavior.
2. Add isolated unit tests. These are faster and more local, but do not prove
   the client-to-backend protocol path that the coverage gap concerns.
3. Extend and add functional TAP tests using standard MySQL client APIs.
   This exercises ProxySQL in the same way as applications do and lets the
   tests verify counters, digests, result values, and metadata. This is the
   selected approach.

## Design

### EOF/OK query-cache conversion

Strengthen `test/tap/tests_with_deps/deprecate_eof_support/deprecate_eof_cache-t.cpp`.
Keep the existing `fwd_eof_query` (MariaDB client) and `fwd_eof_ok_query`
(Oracle MySQL client) subprocesses. Configure a stable ten-second cache TTL,
flush the cache through the normal admin command between each direction, and
assert that the first client fills the entry while the incompatible client
gets it. The assertions will use query-cache status counters and query-digest
hostgroups in addition to the existing result/status/warning checks.

The two directions are:

- EOF client fills, EOF-deprecation client hits (EOF-to-OK conversion).
- EOF-deprecation client fills, EOF client hits (OK-to-EOF conversion).

Each direction must record exactly one cache fill and one successful cache
get for its query. The test will no longer rely on elapsed time to expire an
entry.

### COM_FIELD_LIST

Add a small TAP test that creates a backend table with varied field types and
calls the normal C client API `mysql_list_fields()` through ProxySQL. It will
assert returned field names/types and show that the translated backend query
appeared in `stats_mysql_query_digest`. It will be registered in the standard
MySQL/legacy groups with the related protocol tests.

### Existing special-query coverage

Extend `mysql-last_insert_id-t.cpp` to execute every declared query variant,
including plain `SELECT @@IDENTITY`.

Extend `mysql-select_version_without_backend-t.cpp` so all four
`mysql-select_version_forwarding` modes are covered. The existing no-backend
mode-2 and mode-3 cases remain. New cases use a live backend and an explicitly
warmed idle connection to distinguish internal (mode 0), forwarding (mode 1),
and smart forwarding behavior (modes 2/3). They verify result values and
backend digests where the query must be forwarded.

### Prepared statements

Extend an existing prepared-statement TAP test using `mysql_stmt_prepare()`
and `mysql_stmt_execute()`. One case has a lock clause beyond 128 bytes of
otherwise valid SQL; another prepares a metadata query, alters the table via
a second real connection, and executes again to verify refreshed metadata.
The test uses ordinary prepared-statement traffic only.

## Error handling and isolation

Every test creates or removes only uniquely named `test` schema tables and
restores runtime configuration it changes. TAP plans match the exact number
of assertions. A failed client call reports its MySQL error before returning.
Cache flushes and stats resets are explicit, eliminating timing-sensitive
cross-test state.

## Validation

Compile every changed TAP binary. Run the focused tests in the existing local
TAP environment when its client headers, ProxySQL binary, and backend services
are available; otherwise run the repository-supported CI groups. Verify the
PR's collected coverage includes hits in the named source functions and that
the tests prove the relevant counter/digest transitions rather than merely
successful client responses.
