# Admin and STATS prepared statements

This review branch stacks on the DuckDB-only candidate through `4e73d96dd`. It uses the core prepared controllers and the native SQLite adapter. The DuckDB plugin is not required. Start with read-only PostgreSQL and MySQL. Limited MySQL Admin writes require a separate reviewed commit and explicit approval.

## Dispatch and policy

The existing Admin dispatcher owns simple SQL and Cluster commands, including `PROXY_SELECT`. PostgreSQL simple Query payloads are never parsed by the prepared integration. A session that has never created a prepared provider does not enter its registry on a simple Query. With an active provider, PostgreSQL may close unnamed statements and portals before passing the original packet to the existing dispatcher. During extended-query error recovery, the controller discards messages through Sync as the protocol requires.

Create the native provider on the first supported prepared command. The role selects the existing Admin or STATS SQLite connection. Use the existing startup gate and Admin SQL mutex. Check native autocommit under that lock before preparing or executing, so a prepared operation cannot join a transaction opened elsewhere. Preserve the legacy simple-query result whether a transaction command is accepted or refused by the dispatcher. Recheck source policy and authorization immediately before execution, and use the native SQLite authorizer to cover views and native recompilation. The read-only provider does not change the shared connection's query_only setting. Any admitted statistics refresh uses existing code and only the relations proven by the prepared statement's AST.

## Evidence required before requesting review

| Area | Required evidence |
| --- | --- |
| Legacy wire and Cluster | Run the unchanged Admin result protocol test against the DuckDB-only parent and candidate. Verify both `PROXY_SELECT ... CASE ... END` queries, tags, legacy SHOW/LOAD and error recovery. Repeat on the same PostgreSQL connection after successful prepared traffic and after Sync from a rejected prepare. |
| Backward protocol behavior | Run the original #6345 rejection test on the parent. On the candidate, verify one ErrorResponse for an unsupported prepared command, silence through Sync except for the proper ReadyForQuery, and working legacy simple queries afterwards. Compare legacy transaction commands on parent and candidate. |
| Read-only policy | Unit and live driver tests for separate Admin/STATS credentials, rejection of prepared writes, extension calls, unsupported syntax and stats-reset views. Test view dependencies, native recompilation, authorizer lifetime, and deliberate policy/state changes between prepare and execute. |
| Values and lifecycle | Real MySQL and PostgreSQL drivers cover repeated types, NULL/empty/binary values, long data, named/unnamed statements and portals, Flush/Sync, schema drift, disconnect/reset, quotas, and stable result metadata. Verify that prepared failure leaves no effects and the next valid operation recovers. |
| Locking and Cluster liveness | Two owned ProxySQL nodes synchronize configuration with their real Cluster credentials while MySQL and PostgreSQL prepared clients are active. Check both nodes converge, legacy commands stay responsive, and shutdown/disconnect complete with bounded waits. Include the Admin lock regression where infrastructure permits. |
| CI | Run the relevant integration tiers and ASan/TSan. Record the exact candidate and comparison heads. Investigate any failure before treating it as a pre-existing issue. |

The local read-only candidate passes 62 PostgreSQL and 31 MySQL real-driver
checks with DuckDB disabled. PostgreSQL covers a legacy `BEGIN` that leaves
native autocommit enabled, plus a real SQLite savepoint that makes a second
client's prepared operation fail with `25000` until release. MySQL covers
native long data, schema invalidation with `1615`, and recovery after reaching
the 128-statement limit. The legacy result protocol and error/Sync tests pass
23 and 15 checks respectively with DuckDB disabled or enabled. In the combined
build, the DuckDB analytical and native MySQL and PostgreSQL drivers pass 216,
47 and 29 checks respectively.

The two-node Cluster test starts private ProxySQL processes without DuckDB.
It checks that an exact runtime query rule synchronizes in both directions,
that four prepared clients make progress across both protocols and both roles
during the updates, and that both peers exit cleanly with live prepared
statements. It passed ten checks on each of five consecutive local runs.

## Sanitizer comparison

The Admin candidate at `af040de87` passed all 62 PostgreSQL, 31 MySQL, and
10 two-node Cluster checks with the local ASan-instrumented ProxySQL server
and test binaries. This run used the local prebuilt dependency libraries
and disabled leak detection. The existing `reg_test_3847_admin_lock-t`
also passed all three checks in a regular build.

Strict local TSan stopped the candidate and its v3.0 merge base
`663e84aa6` during startup. Both reported the read in
`MySQL_HostGroups_Manager::commit_locked` racing with initialization in
`GTID_syncer_run`. Temporarily suppressing that report for diagnosis
exposed the same second report in libev's `evpipe_write` on both heads.
The repository and CI configuration contain no new suppression from the
comparison.

In local TSan report-only mode, the candidate passed the 62 PostgreSQL and
31 MySQL assertions. The Cluster test passed eight checks, including
bidirectional synchronization, and exceeded the five-second shutdown
deadline on both nodes. A temporary control that used simple queries in
place of prepared statements reproduced the two shutdown timeouts on
both `663e84aa6` and `af040de87`. The control passed the other eight
checks on both heads. Sanitizer integration CI remains pending for the split branch.
Prepared MySQL writes require their own review.

## Authorization and packet regressions

The expanded MySQL and PostgreSQL suites pass 38 and 79 checks respectively
with regular and local ASan builds. Both protocols test ordinary credentials
against their normal frontend and the Admin listener, a wrong Admin
password, and prepared access to a configuration table restricted to Admin.
MySQL checks the exact `1243` response to an unknown statement reset and
verifies that an unknown statement close emits no packet before the next
query. PostgreSQL runs the packet sequence under both Admin and STATS
credentials and checks that simple queries and an existing named statement
work after a rejected Parse and Sync.

## Published PR checks

GitHub's checks for `9098425b6` cover the original mixed PR. SonarCloud's
security condition is CPP S5443 on the private test fixture's temporary
directory helper. The line uses the platform temporary parent, followed
immediately by `mkdtemp` to atomically create a private directory with mode
0700. Review the finding in that context when the split branch is
analyzed. [SonarCloud issue](https://sonarcloud.io/project/issues?id=sysown_proxysql&issues=AaHtpg9ohQbbvofVHdGl&pullRequest=6648)

Codecov separately reported 4.47% patch coverage and 52.26% project
coverage while coverage jobs were still running. Final coverage and
quality-gate results are pending for the split branch.
[Codecov report](https://app.codecov.io/gh/sysown/proxysql/pull/6648)
