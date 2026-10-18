# ProxySQL Product Invariants

These are contracts that ProxySQL makes to operators and clients. They are older than most of
the code that implements them. **Code must be checked against this list, not only against
itself.** A change that is internally consistent can still be wrong.

Rules for agents:

- **Do not break an invariant, weaken it, or add a new way to violate it,** even behind a flag or
  tier, without an explicit maintainer decision. That decision must be recorded in an issue and
  cited in the commit message.
- **A change that touches an invariant is a design change, not a fix.** Do not label it
  `fix(...)`. Stop and ask (see `common-mistakes.md` §19).
- **If you are unsure whether a change touches an invariant, assume it does** and say so in the
  PR description.
- Reviewers, human or bot, should check every PR against this list. **"The code is consistent
  with itself" is not a review result.**

---

## I-1. LOAD ... SERVERS TO RUNTIME never fails or gets vetoed

*Decision: #6448.*

`LOAD MYSQL SERVERS TO RUNTIME` and `LOAD PGSQL SERVERS TO RUNTIME` install the admin tables into
runtime, as they did in v3.0.11:
- They never fail because of internal machinery: install transactions, install locks, generation
  counters, snapshots, or plugin/module state.
- No module or plugin can veto them, block them or reject part of them.
- Admin replies OK.
- Cluster sync never branches on a LOAD outcome.
- A SQLite read error on an admin table is logged and does not turn the LOAD into a failure. As in
  v3.0.11, the affected table is skipped and the tables that were read are applied. This is
  existing behaviour, not an atomicity guarantee. Do not make it worse, and do not "fix" it by
  adding a new failure path. Changing it needs a maintainer decision.

If a plugin needs to know what was installed, it gets a notification *after* the install, and
cannot reject it.

This invariant covers the SERVERS commands only. Whether it extends to the other core
`LOAD ... TO RUNTIME` commands is a pending maintainer decision. Until then, do not add new
internal failure modes to any core LOAD command without one. Plugin-owned LOAD commands report
their own errors; I-3 applies to them only where they would affect a core command.

## I-2. The Stable tier is unchanged by innovative-tier work

*Decisions: #6448, #6411.*

Code written for v3.1 (`PROXYSQL31`, FFTO, TSDB) or v4.0 (`PROXYSQL40`, plugin chassis) must not
change any behaviour of a v3.0 Stable build. This covers:
- control flow, locking, error paths and failure modes;
- performance on hot paths;
- default values;
- the behaviour of dependency libraries (for example, the regex engine).

Code that only exists to serve v3.1/v4.0 features is either tier-gated, or provably inert on
Stable. "Compiled on every tier but only used by plugins" is not inert if it sits on a core path.

The reverse also holds: **a correctness fix must not be confined to v3.1+** unless the bug only
exists there.

## I-3. Plugins extend ProxySQL; they do not hold core admin operations hostage

*Decision: #6448.*

No plugin hook can:
- make a core admin command fail, block, or partially apply;
- change a core command's reply.

Plugins observe core state and add their own tables, commands and listeners. Core does not wait
on plugins to complete its own operations.

## Session and connection-pooling scope

I-4 through I-7 apply to both MySQL and PostgreSQL unless a protocol-specific case is stated.
A frontend session is the client connection to ProxySQL. A backend connection is a session
with the database server. Multiple frontend sessions can use the same backend connection
at different times; a frontend can remain connected while its former backend serves another.

*Decision for I-4 through I-7: maintainer agreement on 2026-10-18 in the session and
connection-pooling invariant discussion. The agreed contracts cover session isolation,
active or uncertain transactions, cleanup outcomes, direct reuse without mandatory reset,
and truthful state tracking after reset. Existing operator overrides retain their specific scope.*

## I-4. Backend sharing preserves session isolation and exclusive ownership

A backend connection executes work for at most one frontend session at a time. Before another
frontend uses it, the previous owner's backend protocol exchange must be complete and all
transaction, session-state and multiplexing release conditions must be satisfied. Results
already buffered by ProxySQL for the previous frontend do not by themselves prevent release.

Backend reuse must not deliver another frontend's results or expose its private session state.
Before executing for the next borrower, establish the supported session state that borrower
requires. If a session depends on backend-local state that ProxySQL cannot safely reproduce,
retain the backend for that session until the dependency ends, or reset/destroy it when that
session no longer needs it.

This separates usability by the current owner from eligibility for another borrower. A backend
inside a transaction can remain usable by its owner while being ineligible for pool return in
either protocol. PostgreSQL's `is_connection_in_reusable_state()` alone is not a pool-release
predicate.

Scope qualifications: session-state detection follows the configured tracking and multiplexing
policy. In MySQL, `mysql-keep_multiplexing_variables` exempts configured variable reads from
disabling multiplexing; query-rule `multiplex=2` skips variable-related disabling for that query
on the applicable detection paths. `mysql-set_query_lock_on_hostgroup` selects the handling of
unparsed SET statements. These settings do not make untracked state automatically replayable.
Query-rule `multiplex=1` clears the explicit no-multiplex flag; it does not clear every independent
pin or bypass transaction safety. Preserve each override's existing scope.

Evidence: `MySQL_Connection::MultiplexDisabled()`, both protocols' query-status tracking and
pool-return paths; PostgreSQL unread-reply regression coverage in
`test/tap/tests/unit/pgsql_native_unread_reply_unit-t.cpp` (motivating issue #6410).

## I-5. Active or uncertain transactions prevent cross-session reuse

A backend with an active transaction, or whose transaction status is uncertain after an error,
must not be lent to another frontend. It becomes eligible only after a confirmed safe transition
or successful reset, subject to the other release conditions. A failed PostgreSQL transaction
remains owned by its frontend until it is resolved; a statement error alone does not release it.

Frontend disconnect does not make its backend safe: cleanup must resolve the transaction safely
or destroy the connection before another frontend can use it. I-6 constrains that cleanup.

MySQL `autocommit=0` alone is treated as a transaction according to
`mysql-autocommit_false_is_transaction`. `mysql-autocommit_false_not_reusable` can impose an
additional reuse restriction. These settings do not authorize sharing an actually active
transaction or one with uncertain status.

Evidence: both protocols' `IsActiveTransaction()` and data-stream `reset_connection()` guards;
`test/tap/tests/unit/pgsql_conn_liveness_unit-t.cpp` covers retained transaction knowledge
after connection failure.

## I-6. Cleanup must not accidentally commit abandoned work

Connection cleanup, reset and pool recovery must preserve the transaction outcome required by
the protocol and the outcome ProxySQL reported to the client. Cleanup must not turn abandoned
work from a rejected batch into a successful commit merely to recover a reusable connection.
This is not a promise that every statement error rolls back an entire transaction or that
ProxySQL can determine whether a commit succeeded after a connection failure.

In PostgreSQL, abandoning an unfinished extended-query batch can require destroying the backend:
sending Sync or a reset command can conclude its implicit transaction and commit writes even
though ProxySQL rejected the batch locally. Destroy it when reset cannot preserve the required
rollback. Conversely, a successfully handled batch still requires its normal protocol completion.

Motivating regression and evidence: `test/tap/tests/pgsql-native_extq_orphaned_sync-t.cpp`
(P2-36, covers native and libpq backend paths) and
`test/tap/tests/unit/pgsql_midbatch_reset_refused_unit-t.cpp`.

## I-7. Safe reuse does not require reset; reset must restore truthful tracked state

An otherwise eligible backend whose identity, connection options and supported session state
meet the next borrower's requirements can be reused directly. Reset is not a prerequisite for
sharing. Differences that ProxySQL supports reconciling can be synchronized before executing
the borrower's operation. Matching settings alone do not override I-4 or I-5.

When a reset is performed, confirm its success and update ProxySQL's tracked backend state to
describe the actual post-reset state before treating the connection as ready for reuse. Restore
the correct reset/startup defaults rather than assuming every setting becomes empty. Failed or
timed-out resets must not return that connection to the reusable pool; destroy it.

Evidence: MySQL's local pool matching, PostgreSQL's
`PgSQL_SrvConnList::get_random_MyConn_inner_search()`, and both protocols' reset handlers.
Motivating reset-tracking regression:
`test/tap/tests/unit/pgsql_native_startup_params_reset_unit-t.cpp` (fix `38408be42`).

## I-8. Query retries respect transaction ownership, execution progress and configured policy

*Decision: maintainer agreement on 2026-10-18 in the retry-policy discussion. Applies to
MySQL and PostgreSQL. Retry eligibility does not guarantee that the original attempt had no effects.*

A backend failure and a failed statement are different events. A backend connection can fail
before a statement executes, during execution, or after execution but before ProxySQL receives
its response. ProxySQL cannot always distinguish these cases. Retry policy governs eligible
failures within that uncertainty.

An interrupted transaction must not be continued by replaying its statement on another backend.
If a frontend's transaction was established on the failed backend, replacing that backend loses
the transaction's context, including earlier statements, locks and snapshot. Replaying only the
interrupted statement could execute it as autocommit or inside a different transaction. Return
an error through the protocol's supported failure handling instead. Losing the backend connection
must not erase transaction knowledge and thereby authorize retry.

A freshly borrowed backend can fail without an established transaction belonging to the borrower.
For example, an idle pooled connection may have been closed by the database before ProxySQL
borrowed it. The borrower's first operation can be retried on another eligible backend when
configuration permits and execution-progress guards allow it. First operation after borrowing
describes an important case; it is not a universal first-query counter requirement.

Retry permission requires all applicable conditions:
- The failure belongs to a retryable error path.
- A retry remains in the configured budget. The protocol's `query_retries_on_failure` supplies
  the budget; an applicable query rule's nonnegative `retries` overrides it.
- Transaction and session-state guards permit replacing the backend.
- Execution has not progressed beyond the retry boundary enforced by that protocol and operation.

Results already delivered to the frontend prevent transparently restarting the operation: the
client must not receive a mixture of two executions. Multi-result and extended-query processing
require their additional progress checks. PostgreSQL also refuses retry once CommandComplete
proves execution completed, even if the response has not yet reached the frontend.

Configured retry is not an exactly-once execution guarantee. For an unanswered operation outside
an established transaction, configuration can permit retry even though the original backend might
have executed it before disconnecting. Preserve that operator-controlled behavior; do not silently
replace it with either unconditional replay or a requirement to prove non-execution.

Evidence: `MySQL_Session::handler_minus1_ClientLibraryError()`,
`PgSQL_Session::query_retry_allowed()`, and the backend-status and error-code retry handlers.
Regression coverage: `test/tap/tests/pgsql-backend_death_query_retry-t.cpp` and
`test/tap/tests/pgsql-retry_guard_in_txn_on_broken_backend-t.cpp`.

---

## Adding an invariant

Invariants are added or changed only by a maintainer. Each one needs:
- a short statement;
- the issue or decision that ratifies it;
- the bug that motivated it, if any.

An agent that thinks a contract is missing may *propose* one in the PR description, but must not
add it here itself.
