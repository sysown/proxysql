# PostgreSQL LSN Causal Reads Design

Status: Accepted for implementation planning. This document specifies behavior;
it does not describe an implemented or benchmarked feature.

ProxySQL will provide session read-your-writes consistency across a PostgreSQL
writer and its physical replicas using background LSN sampling. Applications
and PostgreSQL server binaries remain unchanged. One sample covers a batch of
completed writer operations. Reads use replicas only when their replay progress
satisfies the session's dependency; otherwise they wait briefly or use the writer.

The two agreed tuning variables are `pgsql-lsn_poll_interval` and
`pgsql-lsn_wait_timeout`. This draft proposes activation on a writer/reader
hostgroup pair, with protection disabled by default.

## Scope and guarantee

For a protected frontend session, a read admitted to a physical replica must
acquire its snapshot after that replica has replayed the session's preceding
acknowledged writes to WAL-logged data in the same replication group. The LSN
used as a dependency may include unrelated work. This can increase waiting,
but must never weaken the guarantee.

The first version supports one authoritative writer per enabled replication
group, ordinary SQL and extended protocol traffic, and physical replicas on the
same current WAL timeline. Direct, stable server endpoints are required. An
endpoint must not hide independently changing servers behind a load balancer.
HA must fence the old writer; this feature does not resolve split brain.

The guarantee belongs to a frontend connection. It does not provide dependency
propagation across application connections, monotonic reads of other sessions'
writes, logical replication support, or additional commit durability. Existing
handling of temporary objects and other backend-local session state continues
to require backend affinity.

Changing the writer's incarnation or WAL timeline invalidates old dependencies
in version one. Such sessions receive an explicit error when they next need
the affected guarantee. Automatic proof of ancestry and survival across
failover is deferred. Reconnecting starts a new session; it does not prove that
a previous session's writes survived failover.

## Configuration

| Setting | Proposed default | Accepted values | Meaning |
| --- | --- | --- | --- |
| `pgsql-lsn_poll_interval` | 10 ms | 1 through 60000 ms | Minimum interval between probe starts for each server. Shared cadence for writer samples and replica replay polls. |
| `pgsql-lsn_wait_timeout` | 100 ms | 0 through 600000 ms | Maximum time a protected read spends resolving its dependency and waiting for an eligible replica connection. |

These defaults are starting points for measurement. The wait timeout is a single
monotonic deadline, set when the request first enters causal routing. Sampling,
replica catch-up, and repeated checkout attempts do not restart it. Existing
request deadlines and cancellation can end the request earlier. Writer execution
after fallback remains subject to the normal query and connection timeouts.

`pgsql-lsn_wait_timeout=0` checks current eligibility once and immediately falls
back to the valid writer if an eligible replica connection is unavailable.
Polling interval zero is invalid; activation is a separate configuration choice.
Changing variables affects future scheduling and requests, not an existing
request's deadline.

Add `lsn_causal_reads INT NOT NULL DEFAULT 0 CHECK(lsn_causal_reads IN (0,1))` to
`pgsql_replication_hostgroups` and its disk, runtime, and internal equivalents.
The flag protects traffic routed to that row's writer and reader hostgroups.
Existing query rules still decide which traffic targets each hostgroup. This
feature does not classify arbitrary SQL as safe to execute on a replica.

Reject enabled mappings with ambiguous overlapping group membership. Multiple
independent groups are allowed. If an enabled group has zero or multiple
authoritative writers at runtime, it cannot establish new replica dependencies;
never choose an arbitrary writer. Retain normal server health, weight, connection
limits, authentication, and session compatibility checks.

Example configuration after this feature is implemented:

```sql
UPDATE pgsql_replication_hostgroups
SET lsn_causal_reads = 1
WHERE writer_hostgroup = 10 AND reader_hostgroup = 20;

SET pgsql-lsn_poll_interval = 10;
SET pgsql-lsn_wait_timeout = 100;
LOAD PGSQL VARIABLES TO RUNTIME;
LOAD PGSQL SERVERS TO RUNTIME;
```

Fresh sessions start with no write dependency. Enabling protection for an
already connected session whose prior writer history was not tracked requires
reconnection before that session can use the newly protected pair. Return an
explicit initialization error instead of assuming it has no prior writes.
Disabling protection is an explicit opt-out for subsequent requests; already
waiting requests retain their policy until they complete or are cancelled.

## Components and ownership

Introduce `PgSQL_LSN_Manager` with small, testable types for positions, batch
state, server progress, and eligibility. It owns group generations and monitor
publication. It performs no blocking database or network operations.

| Owner | State and responsibility |
| --- | --- |
| Group | Writer identity, generation, one open batch, at most one sealed unresolved batch, reader membership. |
| Frontend session | Per-group dependency: generation, source writer incarnation, maximum resolved required LSN, reference to latest pending batch. |
| Monitor | Dedicated connections, sampling cadence, probe deadlines, role and identity validation, immutable progress publication. |
| Server progress | System identifier, timeline, postmaster start time, monitor connection generation, replay LSN, role, validity, last sample times and error. |
| Worker thread | Request deadlines, pending reads, connection eligibility checks and wakeups. |

Store LSNs as validated unsigned 64-bit values; format them as PostgreSQL `X/Y`
only at SQL and diagnostic boundaries. A missing or malformed LSN is unknown,
not zero. Compare numeric positions only after matching group, identity, and
timeline requirements.

Session dependencies survive backend multiplexing, ordinary transaction
rollback, and backend `DISCARD ALL`. A pool reset must not reset frontend
dependencies. A new frontend connection starts a new consistency scope.

## Writer batching and the ordering proof

All writer completion events and batch rotation are serialized under a small
per-group lock. A completion event is tagged with its actual source backend's
writer incarnation and group generation.

1. At a safe completed writer boundary, attach the session to the current open
   batch before exposing the completed idle boundary to the frontend. Forward
   the normal commit response without waiting for batch resolution.
2. When a writer probe is due, seal the open batch and replace it with a fresh
   open batch under the same lock. Skip writer position probes when no batch
   requires resolution.
3. Dispatch the position query only after sealing. The monitor must contact the
   exact writer incarnation associated with the batch.
4. Validate the response and its identity. Publish the sampled insertion LSN
   once into the sealed batch and notify affected workers.
5. Resolve each session lazily when its worker next needs its dependency. Take
   the maximum with any previous required LSN on the same history.

```text
Observed completion A ---- joins batch 7
Observed completion B ---- joins batch 7
Monitor seals batch 7 ---- installs batch 8 ---- sends sample query
Observed completion C ---- joins batch 8
Sample returns L --------- resolves A and B only
```

For every operation included in batch 7, its committed WAL existed before the
sample query was sent. Consequently its commit-end LSN is at most L. A replica
that has replayed through L has applied those commits before the subsequent
read takes its snapshot.

Do not attach a commit to an earlier sample merely because the sample response
arrives later. Never assign the last cached writer LSN to a newly completed
operation. Unrelated later polling cannot advance an already resolved batch.

If a probe fails transiently, retain its sealed batch for a later retry on the
same writer incarnation. Later operations join the open batch while it waits.
There remain at most two unresolved batch objects per group. After successful
resolution, a subsequent probe can seal the accumulated open batch. Disconnects
release session references; no monitor task retains a raw session pointer.
Resolved objects remain alive only while referenced. Generation invalidation
marks both unresolved objects invalid and wakes waiters.

## Observing transaction completion

Use server response and protocol lifecycle information, not an INSERT/UPDATE
regular expression. A SELECT can invoke a writing function, and a multi-command
message can commit work before a later command fails.

For the first version, conservatively enroll every completed application query
cycle on the writer that returns to idle in a batch, including read-only cycles
and cycles ending in an error or rollback. Extra dependencies are acceptable.
Internally generated connection setup and monitor commands are excluded.

Keep an explicit transaction or an unfinished extended-protocol cycle on its
backend. An Execute completion or Flush is not generally a commit boundary;
an implicit extended transaction normally completes at Sync. A successful
explicit commit can be remembered earlier, but version one can delay enrollment
until the cycle ends because it must not move the cycle to a replica meanwhile.
COMMIT AND CHAIN remains pinned until an idle boundary.

Apply this normalization to both native and libpq backend paths. COPY completion,
simple multi-statement messages, procedures containing transaction control, and
error recovery must produce the same conservative outcome. PREPARE TRANSACTION
does not make its changes visible; a subsequent COMMIT PREPARED observed by this
session is covered by the same completed-cycle fence. There is no cross-session
two-phase transaction dependency transfer.

A lost backend connection with an unknown commit outcome must not be treated as
a successful tracked completion or trigger a blind write retry. Preserve the
existing transaction error behavior and mark the affected dependency unusable
if the frontend is retained.

## Monitor probes and WAL identity

Use a dedicated connection per monitored physical endpoint and monitor identity,
reusing the existing monitor credentials, TLS, DNS, connection timeout, and query
timeout configuration. Each connection uses `replication=database`, which allows
ordinary SQL and replication metadata commands through the simple protocol.
The monitor role therefore needs PostgreSQL replication permission and database
access. No replication slot, WAL stream, logical decoding, or extension is used.
Each persistent connection consumes a WAL sender slot, so deployments need
sufficient `max_wal_senders` capacity for their ProxySQL instances. A provider
that disallows database replication connections cannot use this identity
validation path; version one must report that limitation rather than silently
fall back to unqualified numeric LSN comparisons.

On connection establishment, run `IDENTIFY_SYSTEM` to obtain the system identifier
and current timeline. A normal probe then executes a role-appropriate SQL query:

```sql
-- Writer sample, sent after sealing its batch.
SELECT pg_catalog.pg_postmaster_start_time(),
       pg_catalog.pg_is_in_recovery(),
       CASE WHEN NOT pg_catalog.pg_is_in_recovery()
            THEN pg_catalog.pg_current_wal_insert_lsn()
       END;

-- Replica sample.
SELECT pg_catalog.pg_postmaster_start_time(),
       pg_catalog.pg_is_in_recovery(),
       pg_catalog.pg_last_wal_replay_lsn();
```

Follow each SQL sample with `IDENTIFY_SYSTEM` on that same uninterrupted
connection. Publish only when the identity matches the preceding identity check,
the role is appropriate, and the connection, postmaster, and group generations
are unchanged. The previous identity response acts as the first side of this
check; it is not a timestamp-based inference. A mismatch discards the sample
and invokes the relevant endpoint or writer-group invalidation before further
publication. Establish a fresh initial identity check before resuming probes.

This means two commands per regular probe plus initialization. At a 10 ms
interval the scheduling ceiling is 100 probes, approximately 200 commands per
second per continuously polled server, per ProxySQL instance. Probe duration
and demand can reduce that rate.

Use insertion position for the writer so `synchronous_commit=off` cannot make
the dependency precede an acknowledged commit. Use replay position for a replica:
the flush position returned by `IDENTIFY_SYSTEM` is identity metadata here and
must never substitute for replay progress.

New application backend connections used for protected traffic need a one-time
internal bootstrap check of postmaster start time and recovery role against
the monitor's endpoint identity. Tag validated connections with that incarnation;
check the tag on checkout and before dispatch. This avoids reusing progress
from a server that previously occupied the endpoint. If validation fails or
privileges are missing, report it and withhold replica eligibility.

Only one LSN probe may be outstanding for an endpoint. Both commands share the
existing `pgsql-monitor_replication_lag_timeout` budget; connection setup uses the existing
monitor connection timeout. Keep this monitor connection pool separate from
ordinary SQL monitor connections because their startup modes differ.

Poll replicas while a live session has an unresolved batch, a live resolved
dependency is beyond available certified replay progress, or a request is
waiting for fresh certification. Stop the fast cadence once every relevant
healthy replica satisfies the outstanding dependencies, or those sessions
disconnect. A new dependency or waiting request restarts it. Sampling a pending
writer batch continues even if its sessions have not issued their next reads
yet. Missed intervals are coalesced, never accumulated into a backlog.
Independent server phases can be staggered within the same interval; there is
no extra jitter knob.

Do not reuse the current replication-lag task's `max_replication_lag > 0`
membership filter or its time-based eligibility test. All relevant servers in
an enabled pair need LSN monitoring. Existing lag monitoring remains independent.
If monitoring is disabled, suspend new LSN certification; pending reads use a
provably valid originating writer or return an error.

## Read admission and waiting

Determine the effective replication group after applying routing rules and
before a query-cache lookup or backend dispatch. The same admission check must
cover local cached connections, shared pool connections, already attached idle
backends, new connections, and explicit connection-creation requests.

For a request with a dependency:

1. If the session is already in an active transaction or protocol cycle, keep
   its existing backend. Never migrate an existing snapshot.
2. Resolve any completed batch reference. If it is still pending, wait within
   the request's deadline or use the valid originating writer.
3. A replica is eligible only when its validated identity and timeline match
   the session's dependency and its replay LSN is at least the required LSN.
4. Select among eligible replicas using existing routing and pool constraints.
   Recheck the generation before dispatching any snapshot-taking operation.
5. At the deadline, fall back once to the originating writer if its incarnation
   is still valid. Preserve the dependency for later reads.
6. If neither a replica nor that writer can satisfy the dependency, return an
   error. Never route to an arbitrary reader or substitute a newly promoted writer.

The gate precedes BEGIN when selecting a replica transaction and any extended
protocol operation that might acquire the read snapshot, including Bind. It
must not be deferred until Execute if a portal already has a snapshot. Enabled
groups enforce backend affinity for active transactions even when a user's
ordinary transaction-persistence setting would permit moving statements.

Keep LSN waiters separate from vanilla connection-pool waiters so an unready
replica dependency at the head cannot block an otherwise eligible request.
Use worker-owned wait nodes, monotonic timers, and coalesced notifications when
progress or a batch changes. Lost wakeups are prevented by registering a waiter
and rechecking the published revision before sleeping. Workers never sleep
synchronously waiting for a database probe. Cancellation and disconnect remove
the waiter; one cancelled session cannot cancel a probe shared by others.

Initially bypass query-cache reads and writes for requests with unresolved or
resolved dependencies in the protected pair. An old cached result cannot be
made valid by the backend having caught up later. Sessions without dependencies
retain ordinary cache behavior.

Fast-forward traffic is outside replica admission because its boundaries are
not fully inspected. Within an enabled pair it must stay on the writer; an
attempt to use a reader through that path must be refused. Session locks or
portal affinity that prevent a safe route cause an error rather than a stale read.

## Failure and topology behavior

| Event | Required behavior |
| --- | --- |
| Replica probe timeout or invalid result | Mark its current certification unavailable; do not invent progress. Retry on the normal cadence. |
| Writer sample timeout | Keep the batch unresolved. Reads may still use the validated originating writer. |
| Monitor connection reconnect | Invalidate that endpoint's certification and revalidate before reuse. Never combine identity from one connection with a sample from another. |
| Replica restart or replacement | Discard its old replay watermark, invalidate its backend connection tags, then validate fresh progress. Other replicas can remain eligible. |
| Writer replacement, restart, or timeline change | Advance the group generation and invalidate existing dependencies; never transplant them onto the new writer. |
| Replica on a different timeline | Exclude it in version one even if its numeric LSN is larger. |
| Late monitor reply from an old generation | Discard it. It cannot resolve a batch or make a server eligible. |
| Mapping removed or made ambiguous | Invalidate pending requests for the affected mapping. Weight-only changes preserve identity and dependencies. |
| Cancel or ordinary request deadline | End the wait using existing cancellation/timeout semantics; do not retry after user cancellation. |

Use SQLSTATE `55000` for an unsatisfied dependency caused by invalid or unknown
history, with stable diagnostic reason codes such as `LSN_HISTORY_CHANGED`,
`LSN_TRACKING_NOT_INITIALIZED`, and `LSN_NO_SAFE_BACKEND`. Protocol error framing
and transaction poisoning follow the existing PostgreSQL session rules.
Ordinary request cancellation and connection failures retain their existing
SQLSTATEs. A causal wait timeout followed by successful writer fallback is not
an application error.

## Observability and configuration lifecycle

Expose `stats_pgsql_lsn` as one current row per monitored group/server with
endpoint, role, group generation, system identifier, timeline, postmaster start,
last insert or replay LSN, validity, sample age, last duration, and last error.
Expose per-session required LSN, pending batch ID, generation, and wait state
through existing internal session diagnostics. LSNs and batch IDs are not
Prometheus labels.

Add counters for writer batches and completions covered, successful and failed
probes, replica reads, writer fallbacks, wait timeouts, cancellations, and history
errors. Report current waiter count and total causal wait time. Keep operational
probe history bounded by existing monitor history policy; avoid an SQLite write
on every high-frequency successful probe when current state and counters suffice.

Include the activation column and variables in runtime load/save, disk upgrade,
configuration import/export, admin validation, and ProxySQL Cluster checksums and
sync. Upgrade old configurations with protection disabled. Mixed-version cluster
peers must not silently lose an enabled flag: block incompatible synchronization
of this configuration until peers understand the column.

Live dependencies and batches are process-local and are never synchronized
between ProxySQL instances. A proxy restart ends its frontend connections and
therefore their in-process consistency scopes.

## Repository integration

| Area | Existing entry points and intended change |
| --- | --- |
| Core dependency logic | New `include/PgSQL_LSN_Manager.h` and `lib/PgSQL_LSN_Manager.cpp`; pure batch, identity, and eligibility decisions with narrow synchronization. |
| Completion and protocol | `PgSQL_Connection.cpp`, `PgSQL_Session.cpp`, and their headers; normalize completed cycles, preserve dependencies, gate snapshots and both cache paths. |
| Monitoring | `PgSQL_Monitor.cpp` and its header; add an LSN task with its own persistent connections and scheduling, sharing asynchronous infrastructure. |
| Routing | `PgSQL_HostGroups_Manager.cpp` and `PgSQL_Thread.cpp`; enforce one eligibility predicate across shared and local pool paths. Existing PostgreSQL GTID-shaped arguments are not an implemented LSN path. |
| Waiting | `PgSQL_Thread.cpp`, `PgSQL_Session.h`; dedicated LSN wait membership and wakeups, reusing worker event and cancellation mechanisms. |
| Administration | `ProxySQL_Admin_Tables_Definitions.h`, admin load/save and upgrade code, managed runtime, cluster sync, variable registration, stats and diagnostics. |

Avoid unrelated refactoring. The implementation plan should first establish
the batch and eligibility contract, then connect the monitor and response
boundaries, then integrate admission, administration, and system tests.

## Required validation

Use deterministic unit tests for ordering and state transitions, plus live
PostgreSQL tests with one writer and two physical replicas. Exercise native and
libpq backend paths where both are supported.

1. Pause replay while WAL reception continues. A read following an acknowledged
   write must never return the old row from the paused replica. Verify another
   eligible replica, waiting, writer fallback, and zero-timeout behavior.
2. Resume replay and prove waiting reads become eligible only at their fixed
   required LSN. Continued unrelated writes must not move that target.
3. Force completion immediately before and after batch sealing. Delay sample
   responses to demonstrate that a late response never covers a later commit.
   Many sessions must share a sample; probes must not scale with write count.
4. Exercise `synchronous_commit=off`, multi-statement requests with an earlier
   commit and later error, writing functions, rollback, COPY, savepoints,
   COMMIT AND CHAIN, prepared transactions, and extended pipelines through Sync.
5. Use repeatable-read transactions and portals to verify the gate happens
   before snapshot acquisition and active transactions stay pinned.
6. Seed an old query-cache entry and populate the local connection cache with a
   lagging replica. Neither path may bypass admission. Verify dependencies stay
   with the frontend when backends are reused by different clients.
7. Cancel and disconnect waiting clients; force pool exhaustion, lost wakeup
   interleavings, monitor timeout, and probe retry. Assert no blocked workers,
   stale session pointers, restarted deadlines, or leaked batch references.
8. Restart a replica on the same endpoint; promote a lagging replica; change
   writer identity; deliver old-generation probe results. Larger unrelated LSNs
   must not satisfy old dependencies, and writer fallback must not mask lost data.
9. Validate monitor permissions, identity checks on both sides of samples,
   bootstrap incarnation matching, and refusal of invalid activation mappings.
10. Verify variables and the flag through admin load/save, disk migration,
    runtime reload, feature activation on existing sessions, and cluster sync.
11. Measure commit latency, first-read latency, polling QPS, CPU, waiter memory,
    and batch size at 1, 10, and 100 ms intervals. Confirm idle sampling backs
    off and increasing traffic increases batch size without exceeding cadence.

No implementation tests have been run for this design document. The listed
cases are acceptance criteria for the subsequent implementation.

## Alternatives considered

A hidden post-commit query on each application backend is easier to prototype
but couples sampling cost to transaction throughput and complicates protocol
injection. Shared batches keep SQL work independent of commit count.

An extension reporting exact commit positions would reduce latency and remove
writer sampling. It remains a possible later provider behind the same dependency
and routing contract; it is not a prerequisite for this design.

Using upstream `pg_stat_replication.replay_lsn` can reduce replica polling, but
requires dependable mapping from replication connections to SQL endpoints and
coverage of cascading replicas. Direct replica polling is the first version.

## PostgreSQL references

- [WAL position functions](https://www.postgresql.org/docs/18/functions-admin.html):
  insertion position on the writer and replay position on the replica.
- [Replication protocol](https://www.postgresql.org/docs/18/protocol-replication.html):
  database replication connections, system identity, timeline, and the distinct
  meaning of the flush position returned by `IDENTIFY_SYSTEM`.
- [Protocol flow](https://www.postgresql.org/docs/18/protocol-flow.html):
  simple-query transaction boundaries, extended protocol, and Sync.
- [WAL configuration](https://www.postgresql.org/docs/18/runtime-config-wal.html):
  asynchronous commit behavior.

The bundled `deps/postgresql/postgresql-16.10.tar.gz` was also inspected. Its
`walsender.c` allows a standby to forward received WAL before replay, which is
why a WAL stream cannot substitute for the replay watermark in this design.
