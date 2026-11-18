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

Concurrency, the two-node Cluster fixture, and combined integration and
sanitizer CI evidence remain required for the separate draft PR. Prepared
MySQL writes remain outside the read-only candidate.
