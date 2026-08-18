# Admin session-autocommit Connector/Python compatibility

## Goal

Allow MySQL Connector/Python 26.7.0 to connect to ProxySQL's classic Admin
interface without treating its session-scoped autocommit setup statement as a
ProxySQL global-variable update.

## Root cause

The 26.7.0 C extension cannot load in the CI base image because it requires
`OPENSSL_3.2.0`. Connector/Python therefore uses its pure-Python connection,
whose post-connect setup issues:

```sql
SET @@session.autocommit = OFF
```

`admin_session_handler()` already consumes `SET AUTOCOMMIT` as an accepted
connect-setup no-op. Its matcher does not recognize the canonical
`@@session.autocommit` spelling, so the command instead reaches
`admin_handler_command_set()`, where it is rejected as an unknown ProxySQL
global variable.

## Design

Extend the existing Admin connect-setup acceptance block to recognize the
case-insensitive `SET @@session.autocommit` form. It will return the same OK
packet and make no configuration or transaction-state change, exactly matching
the current Admin treatment of bare `SET AUTOCOMMIT`.

No attempt will be made to implement stateful MySQL transaction semantics on
the SQLite-backed Admin interface. `SELECT @@session.autocommit` is also out of
scope: the observed connector connection path requires only the `SET` command.

## Regression coverage

Extend the existing Admin connect-setup TAP regression test with the exact
Connector/Python syntax for both `OFF` and `ON`, including a leading SQL-comment
variant. The test will verify an OK packet and no result set, and will continue
to cover the existing bare spelling and unrelated setup statements.

## Verification

Run the focused TAP test after a clean build, then run the MySQLX soak scenario
with Connector/Python 26.7.0 once PR #5984's portable pin-check fix is merged.
The resulting matrix leg must reach the actual soak test without failure
masking.
