# PostgreSQL session scheduling: previous order, current order, and the completion boundary

**Status:** this document describes the checked-in `PROXYSQL31` implementation through `c94fbe056`, present in PR #6532 at `24f6e3d84`. The later boundary described below is a requested design correction, **not implemented**. The diagnostic yield switch used to investigate performance is not in the PR.

The current implementation can stop processing session A **after its backend request and cleanup have finished but before its completion writeout**, process a waiting session B, and then enter A's handler again to finish response work. Calling that simply “after the request completes” was ambiguous: backend/protocol cleanup is complete, but the response-completion path is not.

The requested boundary is later: finish A's current request handling, attempt its client write, and return to the scheduler **before starting another buffered request from A**. The scheduler can then choose an eligible waiter B. This avoids splitting A's completion work merely to hand off the backend.

## What “finish a session” means here

A session is a long-lived client connection; finishing its current turn does not close that connection. A handler advances that session until it reaches a scheduling boundary or needs I/O. A backend query that is still running cannot be completed synchronously by waiting inside the worker.

For the completed simple-query case discussed here, there are three different boundaries:

| Boundary | What is finished | What can remain |
|---|---|---|
| Backend completion and cleanup | The result has been consumed; protocol/transaction bookkeeping is settled; a reusable backend can be detached | Client output and another buffered client command |
| Current request's completion work | Cleanup plus the normal nonblocking output attempt | Unsent bytes if the socket is full; another buffered client command |
| End of the old handler invocation | Work the handler chose to advance before returning | It may already have started the client's next buffered request |

`writeout()` is nonblocking. “Attempt the client write” does not mean wait for the client to receive every byte. Retained output resumes through `POLLOUT`; a slow client must not block other sessions. Large responses may also have forwarded earlier chunks before the final completion writeout.

## Which previous implementation?

“Previous” must name a revision because the PR already changed scheduling before the recent continuation patch.

| Version | Revision | Scheduling distinction |
|---|---|---|
| Upstream base of this PR | `f02fbf1bb` | After-poll socket processing performs reads. Backend-session scan precedes a separate waiter retry scan and the remaining backendless sessions. |
| Previous phased implementation used as the benchmark control | `9dfe548bc` | Reads are deferred into handlers. Initial waiter service and early frontend dispatch precede backend-session processing. Releases dispatch waiters after a handler returns. No completion-continuation queue. |
| Current PR implementation | `c94fbe056` | Keeps those phases, adds explicit step/checkout outcomes, and can return before completion writeout. A continuation queue finishes that work later. |
| Requested completion boundary | Not implemented | Complete the current request's response work, return before another buffered request, then select the next eligible session. |

These are the development scheduling paths compiled with `PROXYSQL31`; the diagrams do not describe the stable build without that define.

## Worker processing order: upstream, previous phased, and current

These diagrams show normal scheduling phases, not every authentication, maintenance, cancellation or error branch. Eligibility, pauses and deadlines still determine whether a session can run. Partitioning affects scan order when enabled; session names below do not imply permanent array positions.

```mermaid
flowchart LR
    subgraph U["Upstream base f02fbf1bb"]
        direction TB
        U0["poll returns"] --> U1["AfterPoll walks sockets and performs reads / packet framing"]
        U1 --> U2["Scan sessions with backends, each handler runs until it returns"]
        U2 --> U3["Separate retry scan of backend waiters"]
        U3 --> U4["Process remaining backendless sessions"]
        U4 --> U5["Remaining outer-loop work, next poll"]
    end
    subgraph P["Previous phased 9dfe548bc"]
        direction TB
        P0["poll returns"] --> P1["Capture readiness, defer socket reads to handlers"]
        P1 --> P2["Retry existing waiters using available capacity"]
        P2 --> P3["Early frontend dispatch, stop at first established-backend miss"]
        P3 --> P4["Scan backend sessions, AFTER each handler returns, dispatch releases to waiters"]
        P4 --> P5["Waiter recovery / deadlines, remaining backendless sessions"]
        P5 --> P6["Remaining outer-loop work, next poll"]
    end
    subgraph C["Current c94fbe056"]
        direction TB
        C0["poll returns"] --> C1["Capture readiness, defer socket reads to handlers"]
        C1 --> C2["Retry existing waiters using established-only checkout"]
        C2 --> C3["Early frontend dispatch, stop at first established-backend miss"]
        C3 --> C4["Scan backend sessions, completion may return BEFORE writeout, enqueue A and dispatch waiter B"]
        C4 --> C5["Waiter recovery / deadlines, remaining backendless sessions"]
        C5 --> C6["Drain continuation snapshot: enter A again for writeout and buffered-input epilogue"]
        C6 --> C7["Remaining outer-loop work, next poll cannot block if continuations remain"]
    end
```

Both phased versions interleave waiter dispatch with backend-session processing. The recent change is **where A returns** and whether it needs another visit to finish its reply. In the current code, A normally resumes after the remaining scans, not immediately after B has been dispatched. Release dispatch is also checked after initial waiter service, early frontend handlers, recovery, remaining backendless handlers and continuation steps.

## Previous phased order: finish the handler, then dispatch a waiter

In a single worker, assume A has just received the result for query A1, B is waiting for a compatible backend in the same hostgroup, and A may already have another query A2 buffered. The backend is reusable after A1. This example describes a successful normal completion; pinned transactions and other non-reusable backends do not take this release path.

```mermaid
sequenceDiagram
    participant W as Worker
    participant A as Session A
    participant CA as Client A
    participant B as Waiting session B
    W->>A: handler for A1 completion
    activate A
    A->>A: Consume result, finish request/protocol cleanup, release reusable backend
    A->>CA: Attempt A1 reply write
    opt A2 is already buffered
        A->>A: Loop to get_pkts_from_client for A2
        Note over A,B: A2 can reacquire the backend before the worker can dispatch B
    end
    A-->>W: Handler returns
    deactivate A
    W->>B: Dispatch release to eligible waiter, if capacity remains
    B-->>W: Return after progress or when I/O is needed
    Note over W: Continue the session scan
```

There are two cases:

- **No A2 buffered:** A's completion writeout is attempted, the handler returns, and B can be dispatched. A needs no extra visit merely to perform that writeout.
- **A2 buffered:** the handler's tail can jump back to `get_pkts_from_client()` before returning. A2 may consume the released backend ahead of B. Moving to “the next session after handler return” alone did not fix this because the handler could start another request before that return.

This is the distinction between finishing the **current request** and allowing the current handler to drain more work from the same client.

## Current order: split A's completion around other sessions

The current release guard is:

```cpp
if (scheduler_managed && thread && thread->waiter_lists.head(hostgroup))
    yield_after_release = true;
```

It checks for waiters, not for a buffered A2. The handler later reaches its completion label with `status == WAITING_CLIENT_DATA`, sets `resume_after_handoff`, and returns before the normal `writeout()` call. `run_step()` reports `Runnable`, and the worker queues A once.

```mermaid
sequenceDiagram
    participant W as Worker
    participant A as Session A
    participant CA as Client A
    participant B as Waiting session B
    participant O as Other sessions
    W->>A: run_step / handler for A1 completion
    activate A
    A->>A: Consume result, finish request/protocol cleanup, release reusable backend
    A->>A: Waiters exist: save resume_after_handoff
    A-->>W: Return Runnable BEFORE completion writeout
    deactivate A
    W->>W: Enqueue A as a continuation
    W->>B: Acquire released backend and advance B
    B-->>W: Return after dispatch or when I/O is needed
    W->>O: Finish remaining backend scan, recovery and backendless phases
    O-->>W: Return
    W->>A: Continuation drain: enter run_step / handler again
    activate A
    A->>A: Consume pending readiness, resume at completion epilogue
    A->>CA: Attempt A1 reply write
    opt A2 is buffered
        A->>A: Continue into buffered command handling
    end
    A-->>W: Return
    deactivate A
```

“Yield” here is an ordinary function return with saved session state. It is not an operating-system thread yield, coroutine stack switch, or recursive call from A into B. A's handler stack has unwound before B is called. **Nevertheless, it is a logical interruption of A's completion work**, because its completion writeout is still pending.

The pending reply belongs to A; it is not handed to B. The continuation preserves A's unfinished work even if A receives no new socket event. It also adds another handler entry and defers that writeout. New continuations created while draining the bounded snapshot remain for the next iteration, whose poll timeout is forced to zero. Teardown cancels queued entries; idle-thread migration is blocked while a continuation belongs to this worker.

For the small `SELECT 1` response, this postpones the reply itself. For a response that already streamed data, it postpones the completion writeout rather than necessarily the entire response.

## Requested order: switch after current response work, before the next request

**This is the proposed correction, not the current code.** It expresses the requested scheduling boundary without prescribing a new queue implementation or enum value.

```mermaid
sequenceDiagram
    participant W as Worker
    participant A as Session A
    participant CA as Client A
    participant B as Waiting session B
    W->>A: Handle A1 completion
    activate A
    A->>A: Consume result, finish request/protocol cleanup, release reusable backend
    A->>CA: Attempt A1 reply write without blocking
    A->>A: Retain unsent output and remember any buffered A2
    A-->>W: Current request turn complete, return BEFORE starting A2
    deactivate A
    W->>B: Choose eligible waiter, acquire backend and send its query
    B-->>W: Return after progress or when I/O is needed
    Note over W: Select the next eligible session
    opt A has buffered A2 or pending output work
        W->>A: Later scheduled work, with readiness handled appropriately
        Note over A: This is new-command or blocked-output work, not an artificial visit to finish a skipped writeout
    end
```

This separates two decisions that the current patch coupled:

1. **End A's current request turn at the proper boundary.** Cleanup and the normal output attempt belong to that turn. Another buffered command must not silently extend it past an eligible waiter.
2. **Choose the right session next.** The worker can prefer B using the released connection's hostgroup and eligibility. It need not simply advance to the next array element.

There must still be a durable way to schedule an already-buffered A2 without waiting for a new `POLLIN` event. Likewise, a short write must retain its normal writable-event path. These are real pending work; they do not require deliberately skipping the current request's first completion writeout.

This boundary must be defined at a completed protocol operation. Extended-query Sync/portal bookkeeping, transaction pinning, cancellation and error cleanup cannot be bypassed by treating every PostgreSQL message as a completed request. Those details require implementation review before changing the scheduler; this documentation update changes no code.

## What the measurements establish

The initial fresh-instance control/candidate comparison reported 43,346 versus 42,703 TPS. A reversed-order pair changed the sign, so that single pair did not establish the exact net cost of the complete branch.

A later diagnostic used the **same proxy process, client connections and ten established backends**, with only the request-to-yield guard switched ON / OFF / OFF / ON. The workload remained `SELECT 1`, no TLS, five hundred clients, sixteen pgbench jobs, one proxy worker, and native backend protocol.

| Average metric | Yield ON | Yield OFF |
|---|---:|---:|
| TPS | 43,261 | 43,962 |
| CPU cycles/query | 55,248 | 54,378 |
| CPU microseconds/query | 23.045 | 22.684 |
| Full handler entries/query, separate call trace | 4.100 | 3.100 |
| Continuation enqueues/query, separate call trace | 1.000 | 0 |

Both ON windows were slower than both OFF windows; cycles/query increased about 1.60% with yielding, and observed CPU frequency stayed effectively unchanged. All pool snapshots retained ten backends, ConnOK stayed at ten, and no transactions failed. Call probes were attached only after the throughput/cycle windows and are used for call counts, not throughput.

This isolates the cost of the **whole yield path**, including queueing, handler reentry and changed client-write timing. It does not assign all extra CPU time to the queue container. Turning yielding off in a diagnostic is not a complete production fix: the buffered-A2 ordering case still needs the proper request boundary.

## Other implemented contracts

`run_step()` reports waiting for I/O, waiting for a backend, an established-only miss, runnable continuation, or close. Consumed work clears `to_process`; an established-only miss remains eligible for ordinary recovery. The previous dispatched-session vector and its linear membership searches were removed.

Established-only checkout can acquire a compatible, connected, idle backend. It cannot create, warm or evict a connection, park the session, impose a retry delay, or account an ordinary checkout failure. Initial and inline waiter dispatch use this policy; recovery/deadline processing retains normal acquisition. Early frontend dispatch retains its global stop on the first established-only miss.

Retryable plaintext send errors (`EINTR`, `EAGAIN`, `EWOULDBLOCK`) preserve unsent output, including after `POLLOUT`: readiness is not a reservation of socket capacity. Fatal send errors still close the stream.

Allocation ownership is a separate change. Native result-buffer failure remains terminal. Libpq notice callbacks return normally for C cleanup; sticky failure propagates at C++ parser boundaries before successful dispatch or reuse. COPY buffers have scoped cleanup.

## Source map and verification scope

| Behavior | Source |
|---|---|
| Upstream reads and waiter-after-backend scan | [`PgSQL_Thread.cpp` at `f02fbf1bb`](https://github.com/sysown/proxysql/blob/f02fbf1bb/lib/PgSQL_Thread.cpp#L3805) |
| Previous handler writeout then buffered-command loop | [`PgSQL_Session.cpp` at `9dfe548bc`](https://github.com/sysown/proxysql/blob/9dfe548bc/lib/PgSQL_Session.cpp#L4160) |
| Previous release dispatch after handler return | [`PgSQL_Thread.cpp` at `9dfe548bc`](https://github.com/sysown/proxysql/blob/9dfe548bc/lib/PgSQL_Thread.cpp#L4450) |
| Current step outcome and waiter-based release guard | [`PgSQL_Session.cpp` at `c94fbe056`](https://github.com/sysown/proxysql/blob/c94fbe056/lib/PgSQL_Session.cpp#L3251) |
| Current resume before completion epilogue | [`PgSQL_Session.cpp` at `c94fbe056`](https://github.com/sysown/proxysql/blob/c94fbe056/lib/PgSQL_Session.cpp#L3315) |
| Current yield before writeout, then buffered-input loop | [`PgSQL_Session.cpp` at `c94fbe056`](https://github.com/sysown/proxysql/blob/c94fbe056/lib/PgSQL_Session.cpp#L4207) |
| Current phases, release dispatch and continuation drain | [`PgSQL_Thread.cpp` at `c94fbe056`](https://github.com/sysown/proxysql/blob/c94fbe056/lib/PgSQL_Thread.cpp#L4227) |
| Nonblocking output implementation | [`Base_Session.cpp` at `c94fbe056`](https://github.com/sysown/proxysql/blob/c94fbe056/lib/Base_Session.cpp#L192) |

The existing [implementation/benchmark report](../../benchmarks/2026-10-25-pgsql-scheduler-contract.md) records the release build, focused scheduler/allocation/worker checks, native/libpq buffered-request ordering tests and initial comparison. Those tests validate the current implementation; they do not implement or validate the proposed later scheduling boundary.

The causal investigation and raw artifacts are retained on lon104 under `/home/rene/pg-network-bench/scheduler-regression-root-cause.md`, `scheduler-regression-causal-summary.json`, and `scheduler-regression-evidence.tar.gz`.
