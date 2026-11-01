# PostgreSQL scheduler contract implementation plan

> **For agentic workers:** Use superpowers:executing-plans for the scheduler and serialized integration; allocation ownership is an independent delegated task.

**Goal:** Make phased scheduling and backend handoff explicit, preserve progress and cleanup, and measure the single agreed workload.

**Architecture:** Session steps report why execution stopped. Pool acquisition takes an explicit policy. A worker continuation list preserves yielded work while retaining phased dispatch. Allocation errors are contained at ownership boundaries independently.

**Tech Stack:** C++, existing TAP unit harness, native PostgreSQL/libpq, Python benchmark harness, perf only for a separate diagnostic if needed.

**Spec:** ../specs/2026-10-25-pgsql-scheduler-contract.md

## Global Constraints

- Existing PR worktree and branch; preserve original history and staged files in the main worktree.
- Author and committer René Cannaò <rene@proxysql.com>; detailed new commit messages without numerical measurements.
- SELECT 1, no TLS, 500 clients, 10 pre-established backends, 16 pgbench jobs, one proxy worker on CPU zero.
- No new backend connections during warmup or measurement; native protocol for the candidate and control.
- Release builds use the existing compiler, dependencies, feature defines and optimization flags; rebuild consistently when shared layouts change.

## Review Focus

- Buffered requests must not reacquire a released backend ahead of an eligible waiter.
- Partial client output and runnable continuations must survive a poll cycle with no new readable bytes.
- Speculative misses with incompatible connections must neither create connections nor mutate retry/waiter state.
- Connection wait deadlines, recovery, killed sessions and queued-session destruction must make progress.
- Notice and COPY allocation failure must release temporary resources and prevent response completion or pool reuse.

## Task one: established-only checkout and explicit step outcomes

**Files:** include/PgSQL_HostGroups_Manager.h, include/PgSQL_Session.h, lib/PgSQL_HostGroups_Manager.cpp, lib/PgSQL_Session.cpp, lib/PgSQL_Thread.cpp, new scheduler TAP test, unit Makefile/groups registration.

**Interfaces:** pool checkout policy enum; PgSQL_Session::run_step(policy, io_only) returning an explicit result; existing handler callers retain their normal interface.

- [x] Add real pool/session tests asserting speculative miss causes no creation, waiter admission, retry pause or failure-accounting change; observe baseline failure.
- [x] Thread policy through shared-pool checkout and session acquisition, removing thread-local speculative flags and rollback logic.
- [x] Replace scheduler full-handler calls with outcome-aware steps, retaining normal recovery/deadline service.
- [x] Run focused tests and commit the pool/step contract with rationale.

## Task two: safe release yield and continuation ownership

**Files:** include/PgSQL_Session.h, include/PgSQL_Thread.h, lib/PgSQL_Session.cpp, lib/PgSQL_Thread.cpp, lib/PgSQL_Data_Stream.cpp, scheduler TAP test, worker_waiter_unit-t.cpp if its old handler interception requires migration.

**Interfaces:** session completion yield; worker-owned continuation membership/drain; unregister cancellation; pending continuation forces nonblocking poll.

- [x] Add tests with real request completion, queued input, an older waiter and blocked client output; observe missing safe yield on baseline.
- [x] Yield only after cleanup, preserve response and buffered input, and resume through the handler epilogue after handoff.
- [x] Remove dispatched-session linear searches; clear consumed runnable work and explicitly retain yielded work.
- [x] Verify teardown, timeout/recovery, protocol variants and continuation progress; commit.

## Task three: allocation ownership

**Files:** PgSQL_Connection.cpp/.h and existing result allocation TAP test; Protocol.cpp/.h only if required by the audited boundary.

- [x] Exercise notice/COPY allocation failures through real libpq paths; observe failure before the fix.
- [x] Contain callback exceptions, secure owned temporary results, and surface terminal failure before normal completion.
- [x] Run allocation regression tests and commit separately.

## Task four: integration, review and benchmark

- [x] Rebuild the complete affected library and executable coherently; run relevant worker, protocol, scheduler and allocation tests plus required lint.
- [x] Obtain fresh review of the contract and implementation, address concrete correctness findings, and commit verified changes.
- [x] Run only the agreed control/candidate benchmark comparison, validate pool stability and raw latency logs, and record exact binary provenance.
- [x] Document final architecture, verification, measured results and limitations; commit documentation and report to the user.

Results and validation: ../../benchmarks/2026-10-25-pgsql-scheduler-contract.md.
