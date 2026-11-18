# Admin and STATS prepared statements

This review branch stacks on the DuckDB-only candidate through `4e73d96dd`. It uses the core prepared controllers and the native SQLite adapter. The DuckDB plugin is not required. Start with read-only PostgreSQL and MySQL. Limited MySQL Admin writes require a separate reviewed commit and explicit approval.

## PR #6648 review checkpoints

| Commit | Scope | Local validation |
| --- | --- | --- |
| `0f8d83f74` | Removes the Admin/STATS and standalone SQLite3 Server prepared endpoints and restores the v3.0 Admin wire expectation. Retains the shared controllers, DuckDB adapter, analytical translation and ParserSQL changes. | DuckDB analytical and prepared driver tests passed. The unchanged legacy Admin result and Sync tests passed. |
| `4e73d96dd` | Adds `PROXYSQL_SESSION_DUCKDB` after existing enum values and switches both DuckDB listeners. Covers authorization, dispatch, MySQL database selection and change-user, reset, logging, and teardown. | 216 analytical MySQL, 47 native MySQL, 29 native PostgreSQL, 18 PostgreSQL extended, and 11 schema and cleanup assertions passed. The analytical suite routes back to the DuckDB listener through ordinary ProxySQL query rules. |

The patches can be inspected independently from the published head.

```sh
git show 0f8d83f74
git show 4e73d96dd
git log --oneline 4e73d96dd..review/6648-admin-stats-prepared
```

The DuckDB, Admin/STATS and standalone SQLite3 candidates all apply
cleanly to the current `v3.0` tip `55edc87a8`. I built a temporary tree
containing `55edc87a8` and Admin candidate `fd8e7d0a3` without changing
either branch. All 473 wire assertions passed across the eight DuckDB,
Admin/STATS and two-node Cluster suites. The prospective tree was
`88a686245c783417482373b1134a341f1e2c0afd`.

Review of the published checkpoint found that both DuckDB listeners
accepted monitoring credentials through legacy authentication fallbacks.
`e0a43b209` restricts DuckDB authentication to frontend credentials.
The added checks pass on both protocols and verify that the existing Admin
listeners still accept their monitoring credentials. All 325 DuckDB wire
assertions passed in the CI base container, and all 38 unchanged legacy
PostgreSQL Admin assertions passed with DuckDB disabled.

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

Both unchanged legacy TAP tests passed against a separate build of the
exact v3.0 base `663e84aa6` with DuckDB disabled. Their 38 assertion
messages match the DuckDB-only candidate `4e73d96dd` with DuckDB disabled
and enabled after removing timestamps.

Under the same no-DuckDB fixture, the published head `9098425b6` failed
both legacy Cluster `PROXY_SELECT` queries with `CASE … END`. It also failed
8 of the 15 legacy extended-query rejection and recovery assertions.
This comparison uses the unchanged v3.0 test sources for all heads.

The two-node Cluster test starts private ProxySQL processes without DuckDB.
It checks that an exact runtime query rule synchronizes in both directions,
that four prepared clients make progress across both protocols and both roles
during the updates, and that both peers exit cleanly with live prepared
statements. It passed ten checks on each of five consecutive local runs.

## Sanitizer comparison

The exact DuckDB-only checkpoint `4e73d96dd` passed 321 wire assertions
with an ASan-instrumented ProxySQL core, DuckDB plugin and test clients.
This covers analytical MySQL with ordinary query-rule routing (216),
native MySQL (47), native PostgreSQL (29), PostgreSQL extended query
protocol (18), and prepared schema invalidation and cleanup (11).
It uses prebuilt third-party archives and disables leak detection.

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
checks on both heads.
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

The PostgreSQL suite now passes 100 checks in regular and local ASan builds.
A legacy Admin connection changes a table while a PostgreSQL client holds a
prepared statement. The old statement returns `0A000` without data, and
repreparing returns the new column and its value. Raw tests cover the 128
named statement and 128 named portal limits as both Admin and STATS. They
check `54000` on overflow, capacity recovery after Close, and reuse of the
named statement after Sync releases the portals.

The MySQL suite now passes 42 checks in regular and local ASan builds.
While a separate legacy Admin session holds a SQLite savepoint, MySQL Admin
refuses a new prepare and an execute of a statement prepared earlier. STATS
still reads from its own database. The same Admin statement executes
successfully once the legacy session releases the savepoint.

The original 89-assertion MySQL controller suite is restored in the
Admin candidate because its fixtures use the native SQLite adapter.
It exercises guard failures, provider replacement, reset, long data
and quota recovery. Its synthetic sessions now use the prepared-capable
DuckDB session type so destruction releases the statement ID allocator.
The unchanged fixture failed one quota assertion on the prospective
combined tree. The fixture update restored all 89 assertions there.
The restored suite and the 45-check plugin service suite both also pass
under local ASan and TSan. These runs exercise the controllers and their
ownership and cleanup paths without launching a full server.
All 11 Makefile dependency checks pass with the restored suite registered.

## CI on the published split

- On DuckDB commit `e0a43b209`, the TSan unit job passed and all 76
  `legacy-g4` test programs passed, including the five DuckDB wire suites.
  The integration step exited with code 6 after the tests, during `fastcov`
  collection. The shared `GH-Actions` checkout at `ccf920c95` excludes
  `plugins/duckdb`. Replaying the run's counter artifacts with that checkout
  reproduced the 31 missing-source errors and exit code 6. Adding
  `plugins/duckdb` to the sparse checkout made the same replay exit 0.
  [TSan](https://github.com/sysown/proxysql/actions/runs/44392507558) ·
  [Integration](https://github.com/sysown/proxysql/actions/runs/44392507396)
- The first DuckDB ASan job ran out of runner disk space while linking,
  before running tests. GitHub accepted one retry of the failed job.
  [ASan attempts](https://github.com/sysown/proxysql/actions/runs/44392507382)
- On Admin draft commit `07ec29f59`, the ASan and TSan unit jobs passed,
  including the shared, MySQL, and PostgreSQL prepared suites.
  [ASan](https://github.com/sysown/proxysql/actions/runs/44392535868) ·
  [TSan](https://github.com/sysown/proxysql/actions/runs/44392535796)
- On the same draft commit, all 79 `legacy-g4` test programs passed.
  The artifacts confirm 42 MySQL, 100 PostgreSQL, and 10 two-node Cluster
  assertions. Coverage collection then exited with code 6 and reported the
  same 31 missing DuckDB sources as the DuckDB run.
  [Integration](https://github.com/sysown/proxysql/actions/runs/44392535906)
- Both `legacy-g6` runs failed assertions 341 and 692 of
  `pgsql-query_cache_test-t`. Both had `Query_Cache_count_GET` equal to 1
  where the test expected 0. The v3.0 baseline failed the same assertions
  with the same values. [DuckDB integration](https://github.com/sysown/proxysql/actions/runs/44392506978) ·
  [Admin integration](https://github.com/sysown/proxysql/actions/runs/44392535745)

## Build flag

`PROXYSQL40=1` enables the DuckDB plugin chassis and the MySQL and
PostgreSQL Admin/STATS prepared providers. The default build uses legacy
Admin/STATS command handling. Run both Admin wire suites with
`--expect-legacy` and `TAP_PROXYSQL_BINARY` pointing to a default-build
binary to check prepare rejection and simple-query recovery for both roles.
Run the same suites without that option against a `PROXYSQL40=1` binary
to check prepared execution.

All eight legacy-mode checks passed on the gated 3.0 build and on the
`663e84aa6` baseline. The previous draft failed the four prepare-rejection
checks. A `PROXYSQL40=1` debug build passed 42 MySQL Admin/STATS, 100
PostgreSQL Admin/STATS, 10 two-node Cluster, and 325 DuckDB assertions.

## Proposed MySQL prepared-write slice

The proposed first write change covers parameterized SQLite-native
`INSERT`, `UPDATE`, and `DELETE` on the MySQL Admin listener. For
supported SQL, preparation and execution follow the same access rules
as ordinary Admin SQL. The executing session's role and the current
Admin read-only setting govern execution. `mysql_servers`, `mysql_users`,
and `mysql_query_rules` are representative test targets.

An ordinary-query baseline on v3.0 and the current Admin draft passed
11 checks on each build. In both runs, Admin could create a private test
table and use ordinary DML on it. Read-only mode rejected its update
and preserved the original row. The STATS listener rejected an ordinary
write against an existing statistics table.

Review SQL syntax support separately from authorization parity.
ProxySQL-specific commands such as `LOAD` and `SAVE` use the Admin
dispatcher. They have their own execution and result semantics.
The write change requires explicit approval.

| Review requirement | Validation for the write slice |
| --- | --- |
| Role and targets | Compare ordinary and prepared DML on an isolated test table and representative built-in configuration tables. Verify affected rows and stored values. Use the ordinary dispatcher as the reference for role restrictions and for memory, runtime, and disk schema access. |
| Read-only transition | Prepare an Admin write, switch a separate session to `PROXYSQL READONLY`, and verify execute fails with zero effects. Switch back and verify a retry can succeed. Check prepare is denied while read-only. |
| Transaction and serialization | Keep the startup gate and Admin SQL lock across policy, native execution and result collection. Reject prepare and execute while another legacy session owns a native transaction. Check concurrent legacy readers and prepared writes observe consistent configuration. |
| Native side effects | Authorize the actual SQLite targets again on execution and native recompilation. Test trigger and view dependencies, failed constraints, and lack of side effects after rejection. Verify the operation does not change the shared connection's `query_only` flag. |
| Runtime and disk | Verify prepared edits affect only memory, then exercise the unchanged LOAD and SAVE commands. In the two-node fixture, verify the existing LOAD operation still determines when a rule update synchronizes. |

## Published PR checks

The published head `9098425b6` failed `CI-legacy-g4` in
`pgsql-admin_resultset_protocol-t`. Its artifact records the same two
`PROXY_SELECT … CASE … END` errors reproduced locally. The matching
v3.0 job passed, and the local split candidate passed both queries with
DuckDB disabled and enabled.
[PR CI job](https://github.com/sysown/proxysql/actions/runs/44369848784/job/135034320556)
[v3.0 CI job](https://github.com/sysown/proxysql/actions/runs/43684682414/job/132722628900)

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

The `CI-legacy-g6` job failed in `pgsql-query_cache_test-t` on both
`663e84aa6` and `9098425b6`. The TAP artifacts match. Both passed 700
assertions and failed assertions 341 and 692 with
`Query_Cache_count_GET` equal to 1 where 0 was expected. The published PR
therefore reproduces the existing v3.0 failure.
[PR CI job](https://github.com/sysown/proxysql/actions/runs/44369848911/job/135036256166)
[v3.0 CI job](https://github.com/sysown/proxysql/actions/runs/43684682801/job/132723253159)

The MySQL 5.7 `CI-legacy-g7` run for `9098425b6` passed 22 of 23 tests.
`reg_test_stmt_resultset_err_no_rows_php-t` returned `ETIME` from its
two-second PHP subprocess wrapper without reporting the expected result.
The matching v3.0 CI job for `663e84aa6` ran the same test and passed all 23.
[PR CI job](https://github.com/sysown/proxysql/actions/runs/44369849149/job/135034066140)
[v3.0 CI job](https://github.com/sysown/proxysql/actions/runs/43684682670/job/132723121011)

Locally, an unchanged TAP wrapper and PHP script passed 12 runs per
head against normal builds of exact commits `663e84aa6` and `9098425b6`.
The comparison used one private MySQL 5.7.44 backend, PHP 8.3.6 with
mysqli, and three fresh ProxySQL instances per head. It kept the
wrapper's original timeout. The timeout was not reproduced locally.
Its cause and any relationship to the PR remain open.

## Standalone SQLite3 Server follow-up

The original standalone listener work is preserved locally as
`review/6648-sqlite3-followup` at `8483ab10a`, based on `4e73d96dd`.
Its fixture launches SQLite3 Server with DuckDB disabled. Its live test
passed all 39 checks. The comparison build without standalone prepared
registration started the same fixture and rejected the first prepare.
The three restored SQLite-focused unit suites passed 441 checks, the
existing `sqlite3db` unit suite passed 51, and all 11 Makefile dependency
checks passed.
