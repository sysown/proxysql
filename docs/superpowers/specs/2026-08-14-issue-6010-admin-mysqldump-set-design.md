# Issue #6010: Admin mysqldump SET compatibility

## Goal

Allow MySQL 8 `mysqldump` to back up the ProxySQL Admin interface when invoked
with `--set-gtid-purged=OFF --column-statistics=0`.

## Scope

The supported dump invocation sends:

```sql
SET SESSION NET_READ_TIMEOUT=86400, SESSION NET_WRITE_TIMEOUT=86400;
```

Admin must accept that statement without changing its persistent configuration.
The two command-line options deliberately keep these unsupported statements out
of scope:

- `SELECT @@GLOBAL.gtid_executed`
- queries against `information_schema.COLUMN_STATISTICS`

## Design

`admin_handler_command_set` will recognize and remove an optional `SESSION`,
`LOCAL`, or `GLOBAL` scope token from each assignment before it validates the
variable name. A scoped assignment to a known client-only MySQL variable is a
successful no-op because ProxySQL Admin has no session state to store.

The client-only variable recognition will use the existing `MySQL_Variables`
ignored-variable list, which already includes `net_read_timeout` and
`net_write_timeout`. Existing Admin variables will continue through the current
`UPDATE global_variables` translation. Unknown variables will continue to
produce an error rather than being silently accepted.

The parser will process comma-separated assignments consistently, so a
single-variable statement and a multi-variable statement follow the same
validation rules. The implementation will not special-case one mysqldump query
string.

## Testing

Add a TAP regression test that connects to Admin and verifies that:

1. the exact mysqldump timeout `SET SESSION` statement succeeds;
2. the timeout assignments do not create or alter rows in `global_variables`;
3. scoped normal Admin assignments retain their existing persistent behavior;
4. an unknown scoped assignment returns an error.

The focused test will run with the Admin endpoint in the standard MySQL TAP
test group. A debug build and the focused TAP test will verify the change.
