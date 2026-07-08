# Visible Feedback for Rejected mysql-* Variables

**Date:** 2026-06-14
**Issue:** [#1288](https://github.com/sysown/proxysql/issues/1288)
**Branch:** issue-1288-load-mysql-variables-feedback

## Problem

`LOAD MYSQL VARIABLES TO RUNTIME` silently rejects rows in `global_variables`
whose value fails module-side validation. The user sees `Query OK, 0 rows
affected` while the rejected value is quietly reset (or the row deleted) in
`global_variables`. There is no signal to the client that anything was wrong.
The same silent-rejection behavior exists for `mysql-max_stmts_cache` (issue
[#853](https://github.com/sysown/proxysql/issues/853)) and for the pgSQL,
admin, sqlite3-server, ClickHouse, LDAP, and TSDB modules — six of them
share the generic flush path, and pgSQL has a near-identical duplicated
copy of the same loop.

Example reproduction (mysql client) from issue #1288:

```
mysql> UPDATE global_variables SET variable_value='0'
       WHERE variable_name='mysql-max_connections';
Query OK, 1 row affected (0.00 sec)

mysql> LOAD MYSQL VARIABLES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)        <-- no signal that '0' was rejected
```

The error is only visible in `ProxySQL_Admin`'s error log:

```
[WARNING] Impossible to set variable max_connections with value "0".
          Resetting to current "102400".
```

## Goal

After a `LOAD <module> VARIABLES TO RUNTIME` command, the response visible to
the admin client reports how many variables were accepted and how many were
rejected, in the MySQL OK packet's `info` field. Existing log output and the
reset/delete semantics in `global_variables` are unchanged.

## Design Decision: Option 1 — return-value plumbing

Add a small `FlushVariableStats` struct to the generic flush helper, return it
from the module-specific flush wrappers and the `load_*_variables_to_runtime`
inline helpers, and have `admin_handler_command_load_or_save` format an
`info` string and pass it to the existing `send_ok_msg_to_client`. Both
`MySQL_Protocol::generate_pkt_OK` and `PgSQL_Protocol::generate_ok_packet`
already accept a `msg` argument and write it to the OK packet's `info` field,
so the client-side rendering is free.

Alternatives considered and rejected:

- **Option 2 — out parameter.** Less idiomatic C++17; the inline
  `load_*_variables_to_runtime` helpers in `proxysql_admin.h` would need a
  trailing reference arg, which is awkward in a header.
- **Option 3 — stash stats on `GloAdmin`.** Smallest patch, but introduces
  shared mutable state that has to be mutex-guarded for the (future) case of
  concurrent admin sessions. The data flow is implicit.

## Data Structure

```cpp
// include/proxysql_admin.h
struct FlushVariableStats {
    int records  = 0;  // rows read from global_variables for this module
    int updated  = 0;  // rows where set_variable() returned true
    int rejected = 0;  // rows where the value was out of range / malformed
    int unknown  = 0;  // rows for a variable name the module does not know
};
```

`rejected` and `unknown` are split so the user can tell at a glance whether
the bad row was a typo'd variable name (likely a stale disk file) or a value
that the existing module would have rejected. Read-only rejections (admin
module only) are bucketed into `rejected` for the same reason — the user
typed a valid value, the module just won't accept it.

## Plumbing

### Generic path (mysql, admin, sqliteserver, tsdb, clickhouse, ldap)

```cpp
// lib/Admin_FlushVariables.cpp
FlushVariableStats ProxySQL_Admin::flush_GENERIC_variables__process__database_to_runtime(
    const string& modname, SQLite3DB *db, SQLite3_result* resultset,
    const bool& lock, const bool& replace,
    const unordered_set<string>& variables_read_only,
    const unordered_set<string>& variables_to_delete_silently,
    const unordered_set<string>& variables_deprecated,
    const unordered_set<string>& variables_special_values,
    function<void(const string&, const char *, SQLite3DB *)> special_variable_action
) {
    FlushVariableStats stats;
    for (auto it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
        stats.records++;
        SQLite3_row *r = *it;
        bool rc = /* existing set_variable() dispatch, unchanged */;
        if (rc) {
            stats.updated++;
            /* existing variables_special_values branch, unchanged */
        } else {
            const string v = string(r->fields[0]);
            if (replace) {
                char *val = /* existing get_variable() dispatch, unchanged */;
                if (val) {
                    if (variables_read_only.count(v) > 0) {
                        proxy_warning(/* existing message, unchanged */);
                    } else {
                        proxy_warning(/* existing message, unchanged */);
                    }
                    stats.rejected++;          // NEW
                    /* existing INSERT OR REPLACE, unchanged */
                } else {
                    if (variables_to_delete_silently.count(v) > 0) {
                        stats.rejected++;      // NEW
                    } else if (variables_deprecated.count(v) > 0) {
                        proxy_error(/* existing message, unchanged */);
                        stats.rejected++;      // NEW
                    } else {
                        proxy_warning(/* existing message, unchanged */);
                        stats.unknown++;       // NEW
                    }
                    /* existing DELETE, unchanged */
                }
            }
        }
    }
    return stats;
}
```

The six module-specific wrappers (`flush_mysql_variables___database_to_runtime`,
`flush_admin_variables___database_to_runtime`, `flush_sqliteserver_variables___database_to_runtime`,
`flush_tsdb_variables___database_to_runtime`, `flush_clickhouse_variables___database_to_runtime`,
`flush_ldap_variables___database_to_runtime`) each change from `void` to
`FlushVariableStats` and return what
`flush_GENERIC_variables__process__database_to_runtime` returns. The
`flush_mysql_variables___database_to_runtime` post-processing (the
default-charset / default-collation-connection block) is unchanged; the
generic call's return value is what bubbles up.

```cpp
// include/proxysql_admin.h
FlushVariableStats load_mysql_variables_to_runtime(
    const std::string& checksum = "", const time_t epoch = 0) {
    return flush_mysql_variables___database_to_runtime(admindb, true, checksum, epoch);
}

// and analogously for load_pgsql_variables_to_runtime (in the pgsql-only path below)
```

### PgSQL path (separate, duplicated code)

`flush_pgsql_variables___database_to_runtime` (`lib/Admin_FlushVariables.cpp:870`)
does **not** use the generic helper — it has its own per-row loop. The same
change is applied there: wrap the loop, return `FlushVariableStats`, plumb
through `load_pgsql_variables_to_runtime` in `proxysql_admin.h:870`.

### Admin handler formatting

```cpp
// lib/Admin_Handler.cpp
if (is_admin_command_or_alias(LOAD_MYSQL_VARIABLES_FROM_MEMORY, ...)) {
    ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
    auto stats = SPA->load_mysql_variables_to_runtime();
    proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables to RUNTIME\n");
    char info[160];
    snprintf(info, sizeof(info),
        "Records: %d Updated: %d Rejected: %d Unknown: %d",
        stats.records, stats.updated, stats.rejected, stats.unknown);
    SPA->send_ok_msg_to_client(sess, info, 0, query_no_space);
    return false;
}
```

Same edit for `LOAD_PGSQL_VARIABLES_FROM_MEMORY` (line 2029) and for
`LOAD LDAP VARIABLES TO RUNTIME` (`Admin_Handler.cpp:1925`).

`send_ok_msg_to_client` is unchanged; its third arg is the `msg` string that
flows into `MySQL_Protocol::generate_pkt_OK(..., msg, ...)` at
`lib/ProxySQL_Admin.cpp:6232` and `PgSQL_Protocol::generate_ok_packet(..., msg, ...)`
at `lib/ProxySQL_Admin.cpp:6238`. Both end up in the protocol's OK packet
`info` field, which the `mysql` and `psql` CLIs print on the line after
`Query OK, X rows affected`. No protocol change.

### What stays unchanged

- The per-row `proxy_warning` / `proxy_error` log lines. Operators and
  existing log scrapers keep working unchanged.
- The `replace` semantics in `global_variables`: rejected rows are still
  reset to the current runtime value; unknown rows are still deleted.
- The 3 non-admin call sites of `load_mysql_variables_to_runtime`
  (`ProxySQL_Admin.cpp:9036/9105/9136` bootstrap paths, `ProxySQL_Cluster.cpp:2681`
  checksum sync) ignore the return value.
- The `affected_rows` field of the OK packet (stays at 0; it counts SQL
  `INSERT`/`UPDATE` rows, not the number of variables set).
- `LOAD ... VARIABLES FROM MEMORY` / `LOAD ... VARIABLES TO MEMORY` aliases —
  the same `is_admin_command_or_alias` branch handles them and the user
  sees the same response.

## Out of Scope

- `LOAD MYSQL VARIABLES TO MEMORY` (disk path) — doesn't call `set_variable`.
- `SET mysql-...` shortcut command — different path (`admin_handler_command_set`),
  already logs its own warnings, and the maintainer explicitly rejected
  per-DML validation as too complex.
- `SHOW WARNINGS` integration — the user opted for info-only.
- The full information in the log (variable name, value, current value) is
  not duplicated into the OK packet; that would push the line past the
  1 KiB mark and is not what the mysql client is shaped to display.

## Testing

A new TAP test in `test/tap/tests/`. The file follows the
`reg_test_NNNN-...-t.cpp` convention used by existing issue/regression tests
in the directory. Three scenarios:

1. **All-invalid.** `UPDATE` `mysql-max_connections` to `'0'`,
   `mysql-monitor_ping_interval` to `'foo'`, `mysql-max_stmts_cache` to
   `'1000'`. `LOAD MYSQL VARIABLES TO RUNTIME`. Parse the response's info
   field with `mysql_info()`. Assert it contains
   `Records: 3 Updated: 0 Rejected: 2 Unknown: 1`. Assert
   `runtime_global_variables` shows the values were reset to the runtime
   defaults.

2. **All-valid.** `UPDATE` a known-good value (e.g. `mysql-monitor_ping_interval`
   to `2000`). `LOAD MYSQL VARIABLES TO RUNTIME`. Assert info contains
   `Records: 1 Updated: 1 Rejected: 0 Unknown: 0`.

3. **Mixed.** `UPDATE` one valid and one invalid value. Assert
   `Records: 2 Updated: 1 Rejected: 1 Unknown: 0`.

A second TAP test, `reg_test_1288-load-pgsql-variables-feedback-t.cpp`,
covers the pgsql path the same way (e.g. with `pgsql-max_connections` set
to `'0'` for invalid, `'100'` for valid). The pgsql path is tested
separately because the pgsql flush helper has its own duplicated loop
(see "PgSQL path" above) and exercising it independently guards against
regressions in that copy.

Both tests register in `test/tap/groups/groups.json` and follow the
existing TAP test infrastructure (`make build_tap_tests`,
`run-tests-isolated.bash`).

The test cleans up after itself: restores original `global_variables` rows
and re-runs `LOAD MYSQL VARIABLES TO RUNTIME` so the cluster is in a known
state at exit.

## Compatibility

- No wire protocol change. The OK packet's `info` field is part of the
  standard MySQL/PostgreSQL protocol. Clients that ignore it (e.g.
  `mysql --batch`, libmariadb consumers) keep working.
- No SQL DDL change.
- No SQLite schema change.
- No new admin variable.
- No new mutex.
- No new thread.

## Risk Assessment

- **Low.** The change is additive: a return value and one `snprintf`. The
  existing per-row reset/delete behavior is preserved, so an admin script
  that depended on silent rejection still sees the same end state in
  `global_variables` and `runtime_global_variables`.
- The only behavioral change visible to clients is the extra `Records: N
  Updated: X ...` line after `Query OK`. Any monitoring script that grep'd
  for the exact text `Query OK` on a line by itself will need a small tweak
  to also match the next line — the `mysql` and `psql` clients already do
  this.
- The format string is fixed and human-readable; we do not introduce a new
  machine-readable counter that would have to be documented and parsed.
