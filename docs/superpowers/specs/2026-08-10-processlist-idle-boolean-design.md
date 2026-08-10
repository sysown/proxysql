# MySQL Processlist Idle-Session Boolean Fix

## Problem

`mysql-session_idle_show_processlist` is a boolean MySQL variable. During
`LOAD MYSQL VARIABLES TO RUNTIME`, the processlist-specific admin copy is
updated with `atoi()`. A textual value of `true` therefore becomes `0`, even
though the MySQL thread handler accepts it as enabled. `stats_mysql_processlist`
then omits sessions held by idle maintenance threads.

## Design

Keep the existing processlist configuration boundary and fix only the
special-value synchronization. The MySQL admin flush callback will interpret
the supported boolean spellings (`true`/`1` and `false`/`0`) before assigning
`GloAdmin->variables.mysql_processlist.show_idle_session`. Numeric values will
retain their current behavior.

Add a TAP regression test covering the user-visible path: store the textual
value `true`, load MySQL variables to runtime, create a client session that is
idle long enough to move to an idle thread, and verify that
`stats_mysql_processlist` reports it. The test will also verify the disabled
case so it proves the configuration gate rather than merely finding a session.

## Scope and non-goals

- Modify the MySQL processlist configuration synchronization only.
- Add no unrelated processlist refactoring or changes to session movement.
- Leave the existing PostgreSQL path unchanged unless the same shared helper
  is needed by the implementation.
- Preserve the existing test harness and TAP conventions.

## Validation

- Run the new TAP test through the repository's TAP test runner.
- Build the affected ProxySQL target if the test runner does not build it.
- Run formatting/static checks applicable to the touched files.
