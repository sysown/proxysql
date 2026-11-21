# RFC: PostgreSQL session-variable reconciliation during Extended Query pipelines

Status: investigation draft, 2026-10-18. Requested by the maintainer following
[G8](set-behavior-history-questions.md#g8--an-explicit-second-parameter-pipeline-disconnect--march-2026).
Neither retaining the restriction nor removing it has been approved. This RFC
defines the analysis needed to make that decision; it is not an implementation
plan or a runtime reproduction.

Tracking issue: [#6504](https://github.com/sysown/proxysql/issues/6504).

Source endpoint: `a832cbb22be47fffc7a7caf9b82d1f8e76b27171`, reviewed in the
existing documentation [PR #6491](https://github.com/sysown/proxysql/pull/6491).
All source observations below refer to that endpoint. No executable probes were
run; the local integration environment is unavailable as recorded in the
[SET review](set-tracking-review.md#review-validation).

## Problem and impact to establish

The shared PostgreSQL session loop has explicit fatal branches when backend
variable reconciliation encounters either:

1. A second differing tracked parameter during one verification pass, while
   the backend reports an active pipeline and the session is processing an
   Extended Query request.
2. A required parameter change in that condition when the resumed operation is
   not `PROCESSING_STMT_EXECUTE`.

These branches log that the session will be destroyed and return `-1`.
The client-visible frequency and exact reachable wire sequences have not been
established. Two client SET statements, two names in frontend state, and two
differences needing synchronization in this branch are different conditions.
The investigation must not present one as a reproduction of another.

The potential product problem is that valid logical session settings may make
an otherwise valid Extended Query sequence disconnect depending on the
selected backend's state. The question is how ProxySQL should prepare a backend
while preserving client protocol and transaction semantics. It is not whether
to execute client work under mismatched settings.

## Source-confirmed behavior and history

| Evidence | Observation |
| --- | --- |
| [Critical-variable loop](../../lib/PgSQL_Session.cpp#L3435) | A local `pipeline_var_sync_pending` flag begins false. The first differing non-absent variable whose verifier returns true consumes the prior status and requires Execute. A second such difference returns a fatal result. |
| [Dynamic-variable loop](../../lib/PgSQL_Session.cpp#L3469) | Uses the same flag, so the restriction spans both loops rather than allowing one difference in each group. |
| [Verifier](../../lib/PgSQL_Variables.cpp#L298) | Schedules `SETTING_VARIABLE`, records `changing_variable_idx`, pushes the processing status, and updates backend value metadata. Thus planning a synchronization already has state effects; the fatal branches are not a read-only diff check. |
| [Ordinary setting handler](../../lib/PgSQL_Session.cpp#L1355) | Builds an internal SET and drives `async_send_simple_command`, returning to the saved operation after completion. |
| [Connection helper](../../lib/PgSQL_Connection.cpp#L5637) | Runs an internal command through the connection's asynchronous command machinery and consumes its result. Its name alone does not establish the wire encoding in every backend mode/state. |
| [Pipeline predicate](../../include/PgSQL_Connection.h#L640) | libpq uses `PQpipelineStatus`; native mode uses `native_unsynced_work`. These are distinct definitions, not proof of equivalent branch reachability. |

The explicit restrictions were added by
[`96bc66873`](https://github.com/sysown/proxysql/commit/96bc66873514f0578285a8f413f667f7a2f3ea91),
first integrated in March 2026 through
[PR #5444](https://github.com/sysown/proxysql/pull/5444),
[`9d921bdda`](https://github.com/sysown/proxysql/commit/9d921bdda).
Previously the loops used their ordinary `goto handler_again` transition.
Absence of the new fatal check is not evidence that the earlier implementation
correctly supported arbitrary synchronization in an active pipeline.

The originating closed [issue #5432](https://github.com/sysown/proxysql/issues/5432)
explicitly identified simple-query synchronization as incompatible with libpq
pipeline mode. Its proposed approach tracked SET/single RESET on the frontend
and forwarded the original command through Extended Query, with restrictions
on bulk resets. That explains the immediate protocol motivation; it does not
establish a general solution for reconciling several existing desired values on
a selected backend. This investigation follows up on that unresolved scope.

## Protocol constraints

PostgreSQL's Extended Query protocol separates Parse, Bind and Execute; errors
discard later messages up to Sync. Sync is also significant for implicit
transaction completion. Flush is not interchangeable with Sync. Internal
commands must preserve those boundaries and response ownership.
[PostgreSQL 18 message flow](https://www.postgresql.org/docs/18/protocol-flow.html#PROTOCOL-FLOW-EXT-QUERY).

In libpq pipeline mode, `PQsendQuery` is disallowed; pipeline work must use the
permitted asynchronous Extended Query APIs. The server executes requests in
order, and failures affect later work through the next synchronization point.
An implementation must account for these constraints instead of inserting
arbitrary simple-query SET commands.
[PostgreSQL 18 libpq pipeline mode](https://www.postgresql.org/docs/18/libpq-pipeline-mode.html).

These requirements motivate investigation. They do not establish which
existing ProxySQL path violates them or select a repair.

## Investigation questions

1. **Reachability:** At which Prepare/Describe/Bind/Execute transitions can the
   predicate be true? What has already been sent, acknowledged, or queued when
   one or more variables differ? Trace both a warm prepared-statement cache hit
   and the implicit-prepare detour. Include first use of a borrowed backend.
2. **State ownership:** Which differences originate in startup defaults, local
   SET/RESET, backend notifications, or transaction rollback? Which metadata
   represents desired state, verified materialized state, or pending work?
   Audit the verifier's eager metadata changes and restoration on failure.
3. **Backend modes:** What wire/API operations does each internal command
   actually use in libpq and native modes? Can one-difference handling succeed
   without a separate internal setting operation, and where is that work
   recorded? Compare the two pipeline predicates rather than assuming parity.
4. **Placement:** Which settings must be effective before Parse, Bind or
   Execute? Include name resolution and prepared-statement cache compatibility,
   not just execution-time settings. Can all needed synchronization be done
   before backend work begins, and what can become different later in a batch?
5. **Transactions and errors:** Can internal synchronization change transaction
   outcome, failure propagation, savepoint behavior, or client-visible message
   counts? How should setting errors and partial success invalidate metadata?
   Which conditions permit a protocol error with recovery through client Sync,
   and which truly require disconnection?
6. **Lifetime:** Does active/unsynced work retain exclusive backend ownership?
   Can a failed synchronization return a backend to a pool with inaccurate
   state? Retry decisions must retain the existing execution-progress and
   transaction guards; internal work is not permission to replay client SQL.

## Approaches to evaluate, without selecting one

| Approach | Benefit to examine | Main proof obligation / limitation |
| --- | --- | --- |
| Reconcile all required state before dispatching backend batch work | Keeps preparation separate from client command results | Establish the earliest point, preserve Parse/Bind-sensitive settings, and cover changes arising later in a batch. |
| Represent internal synchronization as ordered pipeline operations | May support differences discovered after pipeline entry | Track every internal response/error and metadata commit; preserve client Sync and implicit transaction semantics in both drivers. |
| Restrict only sequences proved unsafe and define protocol recovery | Can retain conservative behavior with a precise documented boundary | Demonstrate which sequences cannot be supported, whether ErrorResponse plus recovery is possible, and why disconnection is necessary when chosen. |

A combination may be appropriate after the traces and probes exist. Removing
the second-variable check, extending its count, or batching a few named
variables alone would not answer the design question. The result must cover the
tracked-variable mechanism rather than a particular pair of parameter names.

## Reproduction and verification plan

First build a deterministic source-level/state-machine test that reaches the
exact branch with known frontend/backend hashes and a known processing status.
Then reproduce with client wire traffic and prove those same conditions with
instrumentation. A synthetic state test establishes branch behavior, not the
reachability of a real client sequence.

For each backend mode, arrange a backend with known parameter values and a
frontend with different desired values. Record actual backend identity, pool
selection, relevant hashes, statement cache identity, pipeline/unsynced state,
status stack and client/backend message order. Do not rely on incidental pool
reuse or on multiple client SETs alone to create the required mismatch.

| Axis | Cases and assertions |
| --- | --- |
| Difference count | Zero, one, two, several; matching values must not spuriously trigger synchronization. |
| Descriptor groups | Critical only, dynamic only, and a difference in each; include absent variables and a zero frontend hash. |
| Phase / cache | Parse, statement/portal Describe, Bind, Execute; explicit and implicit prepare; cache hit/miss; named and unnamed objects. |
| Batch state | No earlier backend work, earlier work pending, completed work before Sync, multiple client Sync boundaries, Flush without Sync. |
| Transaction state | Idle, explicit BEGIN, failed transaction, rollback/savepoint, and an implicit transaction spanning client pipeline steps. |
| Failure | First/later internal setting error, transport failure before/after client dispatch, cancellation, retry allowed/refused. Assert no duplicate client execution. |
| User-visible result | Effective settings at each dependent statement; response order and counts; ErrorResponse/ReadyForQuery boundaries; subsequent client recovery when supported. |
| Pool lifecycle | Exclusive ownership while work remains; no lending after partial/failed preparation until state is truthfully restored or connection retired. |
| Drivers / builds | libpq and native in their supported build tiers; document an unsupported combination explicitly rather than inferring parity. |

Existing tests are starting points, not proof that this case is covered:
[SET through Simple Query, verify through pipeline](../../test/tap/tests/pgsql-set_statement_test-t.cpp#L351)
and [multiple variables within a pipeline transaction](../../test/tap/tests/pgsql-transaction_variable_state_tracking-t.cpp#L931).
They do not, by their names or presence, establish that two differences reach
the fatal verification branch on a deterministically selected backend.

## Decision and completion criteria

Before selecting an implementation, the issue should contain:

- Minimal real-client reproductions or a documented explanation of why the
  suspected state is unreachable in a particular mode, with wire/state traces.
- A before/after integration history and the supported-behavior matrix for
  both backend modes, separating inherited limitations from introduced ones.
- A proposed ordering/state model for all tracked parameters, reviewed against
  transaction, prepared-statement, retry, result ownership and pool invariants.
- A maintainer decision on the supported sequences, any remaining restrictions,
  and the required client-facing failure/recovery behavior.
- An implementation plan and focused regression coverage that demonstrate those
  decisions. No implementation is approved by this RFC alone.

G8 remains deferred while this investigation is open. The maintainer is not
being asked to approve the current fatal behavior as a side effect of accepting
this research document.
