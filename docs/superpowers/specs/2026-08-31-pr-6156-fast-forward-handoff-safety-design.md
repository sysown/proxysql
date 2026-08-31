# PR 6156 Fast-Forward Handoff Safety Design

## Scope

Correct the query-rule transition to permanent MySQL fast-forward mode without
changing the PR's COM_QUERY-only contract. The remediation covers the dangling
query pointer reported in review, the query-processing state that currently
survives the handoff, and the converted COM_FIELD_LIST path.

## Handoff cleanup

Add a dedicated session helper that finalizes only the query-processing state
owned by ProxySQL before the packet is transferred to the permanent
fast-forward state machine. The helper will:

- set the query end time and finalize `CurrentQuery`, releasing parser state and
  updating the normal query counters;
- explicitly clear `QueryPointer`, `QueryLength`, and the command marker even
  when query statistics are disabled and `Query_Info::end()` returns early;
- destroy the populated query-processor output while retaining its reusable
  object;
- clear pending per-query user-variable analysis state.

The helper will not call `RequestEnd()`. At handoff, the backend has not replied,
so logging a successful request or applying normal response-completion state
changes would be inaccurate. The fast-forward state machine remains responsible
for packet ownership and connection/session status.

Cleanup occurs after the complete query-rule chain and mirror creation, but
before the triggering packet is queued for fast-forward. It applies to both
aliased ordinary packets and reconstructed large packets. When reconstruction
allocated a replacement, cleanup happens before the original packet is freed.

## COM_FIELD_LIST exclusion

`generate_COM_QUERY_from_COM_FIELD_LIST()` converts COM_FIELD_LIST into an
internal COM_QUERY and sets `client_myds->com_field_list`. The new action must
also require that flag to be false. Converted field-list requests continue
through the existing normal query path so their response conversion remains
unchanged, even when the generated SQL matches a rule containing
`switch_to_fast_forward=true`.

## Tests

Extend `test_query_rule_fast_forward-t` with two regressions:

1. After an ordinary sub-16 MiB trigger has entered permanent fast-forward and
   subsequent traffic has completed, `stats_mysql_processlist.info` is NULL.
   This fails on the reviewed code because the session retains the packet-backed
   query pointer.
2. Install a matching fast-forward rule for the SQL generated from
   COM_FIELD_LIST, issue `mysql_list_fields()`, verify the rule was hit, verify
   the request succeeds, and verify the session did not enter fast-forward.

The existing large-query, mirror, prepared-statement, compressed-client, and
pipelined-client coverage remains unchanged. Tests modify runtime configuration
only and do not issue `SAVE ... TO DISK` or `LOAD ... FROM DISK`.

## Verification

Use the repository-documented `PROXYSQL31=1` debug build and TAP build commands
only if compilation or runtime testing is requested. Run the focused TAP through
`test/infra/control/run-tests-isolated.bash`; never launch it directly or set up
Docker manually. Always run the repository lint suite before pushing.
