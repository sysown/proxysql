# Digest-text merge helper + PgSQL dead MySQL code removal

Issues: [#6437](https://github.com/sysown/proxysql/issues/6437),
[#6453](https://github.com/sysown/proxysql/issues/6453).

Branch: `fix/6437-6453-digest-pgsql-cleanup`.

## 1. Context

### #6437 — digest-text leak

`Query_Processor<QP_DERIVED>::get_query_digests_v2()` swaps the live digest
maps into auxiliary maps, builds the resultset without the lock, then folds the
windows back. When `query_digests_normalize_digest_text=true`, a digest seen in
two windows exists in two text maps, and `unordered_map::insert()` silently
drops the duplicate `char *`, leaking it.

#6440 (already merged, `lib/Query_Processor.cpp`) fixed the leak at both
fold-back sites by replacing `insert(range)` with `emplace()` + `free()` on the
losing key. The remaining gap versus the issue is regression coverage: the fold
logic is inline in a template method and cannot be unit-tested. `#6453`'s
`get_query_digests_reset_v2()` was audited and frees every auxiliary text, so it
has no equivalent leak.

### #6453 — dead MySQL code in the PgSQL classes

`PgSQL_Session` / `PgSQL_Thread` carry MySQL code copied from `MySQL_Session`
that is unreachable for PostgreSQL. Most of it is already `#if 0`-guarded,
including a wrong `SQL_ISOLATION_LEVEL` (a `mysql_variable_name`) reference, plus
a never-entered `match_regexes[2]` slot and four never-entered `SETTING_*`
states in the PgSQL state machine.

## 2. Design

### 2.1 Digest-text merge helper (#6437)

New header `include/digest_text_merge.h` holding one inline function:

```cpp
void merge_digest_text_maps(
    umap_query_digest_text& dst,
    umap_query_digest_text& src,
    std::vector<char*>* duplicates = nullptr);
```

For each `src` entry: `dst.try_emplace(key, value)`. If the key already exists,
`dst` keeps its pointer and the incoming `strdup()`'d duplicate is either
appended to `duplicates` (so the caller can free it after dropping a lock) or
freed immediately. `src` is cleared. The header only depends on
`proxysql_typedefs.h` plus `<vector>`/`<cstdlib>`, which keeps it cheap to
include from the unit test.

`get_query_digests_v2()` calls it at the two fold-back sites:

- First fold (no lock held): free eagerly.
- Second fold (under `digest_rwlock`): collect duplicates in a
  `std::vector<char*>` and free them after `pthread_rwlock_unlock`, matching
  `purge_query_digests_async()`.

The leak fix itself is unchanged; this is a testability refactor plus the
deferred-free improvement.

### 2.2 Regression unit test (#6437)

Extend `test/tap/tests/unit/digest_stats_unit-t.cpp` (group
`unit-tests-g1`). Build `dst={1:"a",2:"b"}` and `src={2:strdup("b"),
3:strdup("c")}`, call the helper, and assert: `dst` has three entries; `dst[2]`
is still the original pointer; `dst[3]` is the pointer taken from `src`; `src`
is empty. Repeat with the deferred `duplicates` vector. Under the ASAN/LSan
build a missing `free()` surfaces as a leak report.

### 2.3 PgSQL dead-code removal (#6453)

Delete, with no behavioural change (all of it is already `#if 0` or
unreachable):

- `lib/PgSQL_Session.cpp`: the three `#if 0` blocks containing the
  `_MYSQL_COM_*` handlers (`__various`, `SET_OPTION`, `PING`, `FIELD_LIST`,
  `PROCESS_KILL`, `INIT_DB`, `QUERY_USE_DB`, `STATISTICS`, `CHANGE_USER`,
  `RESET_CONNECTION`) and `handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET`.
- `include/PgSQL_Session.h`: the matching `#if 0` declaration blocks.
- The dead `SETTING_ISOLATION_LEVEL`, `SETTING_TRANSACTION_READ`,
  `SETTING_NEXT_ISOLATION_LEVEL` and `SETTING_NEXT_TRANSACTION_READ` cases in
  the PgSQL `handler()` switch (keep `SETTING_VARIABLE`). The enum values
  themselves are shared with MySQL and stay.
- `match_regexes[2]` (the MySQL `SET TRANSACTION` regex, already `NULL` after
  #6442): shrink `PgSQL_Thread::match_regexes` from four slots to three and
  renumber the `client_encoding|names` regex from `[3]` to `[2]`, updating the
  init and teardown loops.

After the change the only remaining `match_regexes` consumer in PgSQL is
`[1]` (tracked SET variables), and `PgSQL_Session` no longer references any
`mysql_variable_name`.

## 3. Verification

- Build `digest_stats_unit-t` (reusing the main worktree's built deps/objects,
  `make -j3`) and run it.
- Compile the changed PgSQL translation units as part of the library build.
- Confirm `grep` finds no `mysql_variable_name` reference under
  `lib/PgSQL_*`/`include/PgSQL_*`.

## 4. Out of scope

- Enforcing the "no MySQL variable names in PgSQL" rule in the build (the issue
  files it as a possibility, not a requirement).
- Removing the unused `match_regexes[0]` placeholder or `client_encoding|names`
  regex.
