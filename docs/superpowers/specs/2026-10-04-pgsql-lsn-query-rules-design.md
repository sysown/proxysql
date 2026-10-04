# PostgreSQL LSN selection through query rules

Status: revised design for implementation review, 2026-10-04. This replaces
the 2026-10-03 causal-read design and its implementation plan. Existing feature
code and its earlier test results do not establish conformance to this design.

## Agreed behavior

ProxySQL v3.1 and v4.0 add `lsn_from_hostgroup` to PostgreSQL query rules. A
matching rule asks connection selection to use the session's last execution
in that source hostgroup as a dependency. `destination_hostgroup` independently
determines where to select the next connection. This follows the separation
of source and destination in MySQL's `gtid_from_hostgroup` routing.

Each session keeps exactly one record per hostgroup:

```text
last_execution[hostgroup] = {hostname, port, completed_at}
```

Each actual application query-cycle completion replaces that record, even if
it used a different server or was a read. Do not classify SQL into reads and
writes. Do not retain a set of previous source servers, aggregate their LSNs,
or reconstruct earlier dependencies after replacement. The operator is
responsible for a coherent source hostgroup. A later operation on a lagging
server in that same hostgroup may replace an earlier, stronger dependency;
compensating for that configuration is explicitly outside this feature.

Normal queries perform only local completion bookkeeping. They do not look up
LSNs, wait for samples, or enroll in shared batches. The background checker
never reads or updates session records. There are no completion batches.

The PostgreSQL monitor (`PgSQL_Monitor`, using `PgSQL_LSN_Monitor` and its
background probes) schedules the checks, publishes server progress and performs
history cleanup. Session workers resolve timestamps only when backend selection
is reached; the hostgroup manager and pool paths filter candidates using that
in-memory requirement. The monitor never selects a backend for a client query.

All additional SQL runs on background monitor connections. Application sockets
send no additional identity or LSN queries, including on initial connection,
pool checkout, reconnect, COPY or prepared-statement execution. No additional
connection handshake is introduced for LSN verification.

The feature has no writer/reader hostgroup pairing, replication-hostgroup
activation flag, special client LSN wait timeout, or cross-hostgroup fallback.
PostgreSQL recovery status is used only inside the monitor to select the proper
WAL-position function; it does not assign routing roles to hostgroups.

## Versioned configuration

Everything added by this feature is guarded by `PROXYSQL31`. The build already
makes `PROXYSQL40` imply `PROXYSQL31`. A v3.0 build retains its existing rule
schema, query-rule projection, variables, stats schema and execution path.

In v3.1/v4.0, both `pgsql_query_rules` and `runtime_pgsql_query_rules` contain:

```sql
lsn_from_hostgroup INT CHECK (lsn_from_hostgroup >= 0) DEFAULT NULL
```

Its exact position is between `multiplex` and `log`, matching MySQL's placement
of `gtid_from_hostgroup`. Complete tables therefore have 35 columns instead of
34; the active-rule/cluster projection, which omits `active`, has 34 instead of
33. NULL leaves the rule output unchanged, as with MySQL rule chaining; a new
request initializes the output to -1. Zero is a valid hostgroup ID.

For example, `destination_hostgroup=20, lsn_from_hostgroup=10` selects only
within HG20 using the last execution recorded for HG10. A query without an
effective `lsn_from_hostgroup` follows existing behavior. A session with no
previous execution in the requested source hostgroup has no dependency.

The monitor owns all three settings below. Polling names include the requested
`monitor_` prefix. The history name, defaults and ranges are proposed values for
review; `pgsql-monitor_lsn_history` controls in-memory LSN samples independently
of the existing `pgsql-monitor_history` log retention.

| Variable | Default | Range | Meaning |
| --- | --- | --- | --- |
| `pgsql-monitor_lsn_poll_interval` | 10 ms | 1–60000 ms | Minimum interval between background sample starts per physical endpoint. |
| `pgsql-monitor_lsn_poll_timeout` | 100 ms | 1–600000 ms | Deadline for one background sample operation, including its validation commands. |
| `pgsql-monitor_lsn_history` | 60000 ms | 1000–604800000 ms | Retained sample-age window, plus at most one older boundary sample per endpoint. |

Remove the private implementation's `pgsql-lsn_wait_timeout`; do not retain its
client-wait meaning or add a compatibility alias. Zero does not mean fallback
or unlimited polling/history. Replace the draft polling names without aliases.
Existing monitor connection timeouts govern establishing
monitor connections. Existing client query, connection-acquisition and cancel
semantics govern opted-in queries that cannot yet get an eligible backend.

## Session completion records

Use the existing per-session, per-hostgroup `PgSQL_Backend` object to own the
record. It must survive detaching or replacing a pooled physical connection;
ending the frontend session destroys it. Store endpoint strings only on an
endpoint change, not by allocating a new string for every completion.

Record a fresh ProxySQL monotonic timestamp when an actual native application
query cycle completes, before its completion is exposed to the frontend.
Observe ReadyForQuery, including suppressed native ReadyForQuery, extended Sync
and temporary COPY completion. Never timestamp synthetic local responses,
cache hits, internal SET/DISCARD/initialization commands or monitor commands.
Do not use a worker-loop time captured before processing the backend response.

Record ordinary, transactional and error-ending application cycles
conservatively. Explicit commit completion updates the record again. An
intermediate CommandComplete, ParseComplete, BindComplete or PortalSuspended
must not be mistaken for a committed transaction. Existing transaction and
portal affinity remain in force; LSN selection cannot create a fresh snapshot
inside an already-established snapshot or expose uncommitted work elsewhere.

Record completions in native v3.1/v4.0 even when no current rule references the
hostgroup. This keeps enabling a rule on an existing frontend straightforward
and avoids a global configuration lookup on ordinary completion. No old-session
activation/reconnect guard from the rejected design remains.

## Physical sample histories

One `hostname:port` has one monitor connection, latest progress and ordered
sample history, regardless of hostgroup membership. Hostgroup relationships
determine which endpoints are monitored and retained; they do not duplicate
samples. The manager contains no session pointers or hostgroup routing policy.

History entries have two numeric fields:

```text
{sample_started_at, lsn}
```

Timestamp immediately before sending the LSN sampling command, using the same
process-wide monotonic clock as session completions. Publish only after the
complete successful response and background identity checks. Response-arrival
time is not a substitute: a response arriving after a write can contain an LSN
evaluated before that write.

Background sampling uses insertion LSN on a normal server and replay LSN on a
server in recovery. The retained background probe can establish system ID,
timeline and server incarnation with its dedicated connection. PostgreSQL's
insertion, write and flush positions differ; an acknowledged asynchronous
commit must not be fenced using a still-earlier flush position.

Identity metadata belongs to the endpoint history, not each numeric sample.
Only compare positions from the same WAL history. Discard stale connection
results. Detected history changes invalidate old lookups; an old timestamp must
not be resolved against a newly created history's pruning anchor. Direct stable
endpoints and external HA fencing remain assumptions. There is no application
socket identity query and no ancestry or split-brain recovery algorithm.

First discovery is different from an observed history change. If monitoring
starts after a session's completion, its first successful sample may satisfy
that completion when the sample started later. Do not reject this case merely
because no earlier sample exists. A validity boundary is needed when an already
known history changes, not whenever an endpoint is first monitored.

Monitor failures withdraw current eligibility. They must not fabricate zero,
advance timestamps, or publish partial samples. A timeout bounds the background
operation only. Reconnect and retry at the configured cadence; keep at most one
operation outstanding per endpoint and coalesce missed ticks.

Poll configured relevant endpoints without consulting session demand. Reuse the
existing monitor credentials, TLS, resolver and scheduler; disabling the DNS
cache must not silently disable hostname endpoints. Background libpq use does
not imply support for legacy libpq application connections.

## Resolving a causal query

When a query reaches backend connection selection, use its effective query-rule
output and capture the source record once for this request. Ordinary query-cache
processing has already had its opportunity to answer the query. Resolve the
recorded physical endpoint, not whichever server currently occupies the source
hostgroup. Find the first retained published sample satisfying:

```text
sample_started_at > last_execution.completed_at
```

The endpoint identity and that sample's LSN form the fixed request requirement.
Do not move the target forward during later pool retries. If the sample has not
arrived, the request is pending, not unconstrained. No previous source record
is distinct from a missing sample for an existing source record.

Connection selection uses the ordinary destination hostgroup, server health,
weight, authentication and session-compatibility rules, plus:

```text
candidate has valid current progress in the required WAL history
and candidate.lsn >= required_lsn
```

Use the same predicate for local connection caches, shared pools, attached connections and
new connection selection. No routing role is required. Do not stamp application
sockets with independently validated incarnations. If sampling publishes a
change during dispatch, use the normal in-memory recheck without another query.

No eligible server returns through ordinary backend-acquisition retry and
timeout handling. Source history changes produce an explicit causal error;
cancellation keeps the existing cancellation behavior. Never change the
destination or waive the dependency. Apply the gate before snapshot acquisition,
including named Bind. An incompatible pinned transaction/portal fails instead
of moving to another backend. Unconfigured queries retain existing behavior.

Query-cache lookup, insertion and invalidation retain their existing behavior,
including for rules with `lsn_from_hostgroup`. A cache hit returns normally
without resolving an LSN, waiting for the monitor or selecting a backend. It
also leaves the last actual backend-execution record unchanged. Permanent raw
forwarding, which bypasses query-rule execution, is outside per-query LSN
selection; normal forwarding configuration must not be affected merely by
endpoint monitoring.

## History retention

The monitor applies two independent ways to prune prefixes: progress-based
pruning from rule relationships and age-based pruning from
`pgsql-monitor_lsn_history`. Both preserve real samples and the strict lookup
condition `sample_started_at > completed_at`. Pruning may yield a newer,
stronger requirement for an old timestamp; it never removes that requirement.

At LOAD PGSQL QUERY RULES TO RUNTIME, derive the possible source→destination
relationships. Use effective rule behavior: explicit destinations, chained
flags and fast routing. Conservatively include possible destinations where
static resolution is incomplete. Default/dynamic destinations can require all
configured hostgroups. Incomplete inference may prevent progress-based pruning;
it does not prevent age-based cleanup. Recompute endpoint membership when
servers reload.

For a source endpoint, include the endpoints in its relevant source groups and
all destination groups referencing those sources. Within the same valid WAL
history, compute their minimum latest LSN, M. Unknown members must not be
treated as caught up. Keep the source history's newest actual sample below M
and everything newer; delete only the entries preceding that anchor. If no such
sample exists, there is no progress-based prefix to remove. This union handles
one source feeding several destinations and shared endpoint memberships.

Keep the anchor's timestamp. An older session timestamp resolves to the anchor;
a timestamp at or after the anchor still searches for a strictly later sample.
For M=12340, retaining a sampled 12339 is valid; inventing M−1 is unnecessary.
LSNs and samples are not consecutive integers. Always recheck current candidate
progress, including after membership changes. Unknown or incompatible members
block only this progress-based optimization.

Independently, on monitor housekeeping ticks compute
`cutoff = max(0, monotonic_now - history_ms * 1000)`. Keep all samples whose
start time is at or after the cutoff, plus the newest actual sample before it
as the boundary anchor; delete the preceding prefix. Run cleanup even when
probes fail or no LSN advances, without waiting for a successful publication.
Applying both pruning methods retains whichever smaller suffix they permit;
progress pruning may discard more than the age window requires.

An older completion resolves to the first retained sample started after it.
If the retained boundary sample predates that completion, lookup proceeds to
the next sample. If none exists, the request remains pending. When every sample
is older than the cutoff, keep only the newest one; its original timestamp
still applies. Expiration never invents a timestamp, a zero LSN or an
unconstrained result. A resolved request keeps its copied requirement even
after its source sample is pruned. Observed history-change boundaries still
apply before any old-timestamp lookup.

For example, suppose age cleanup leaves a source anchor at LSN 12339 and newer
samples. An old completion before the anchor resolves to 12339. A destination
replica stuck at 12000 cannot satisfy that target; replicas at 12340 and 12341
can. The stuck replica does not prevent cleanup. If none of the destination
replicas meets the retained target, ordinary acquisition waits/timeouts apply.
No separate stale-server classification is needed: an unchanged LSN can also
mean an idle, fully caught-up server.

Consecutive unchanged LSN samples may be replaced with the newer timestamp;
this remains a conservative timestamp-to-LSN mapping. With fixed poll interval
I and history window H, retained records per endpoint are bounded by roughly
`ceil(H/I) + 2` after cleanup, independent of replica lag or client count.
With the proposed 60-second window and 10-ms interval, that is about 6000
two-number samples (about 96 KB of payload before container overhead).
Use storage that releases expired chunks or bounds reusable capacity; erasing
logical entries alone must not leave memory growing indefinitely. Configuration
changes apply on the next housekeeping tick: shrinking the window prunes it,
while enlarging it cannot reconstruct discarded samples. Measure actual memory
and scheduling overhead; no separate entry-count knob is proposed.

## Schema upgrade and cluster behavior

Add a PostgreSQL query-rule disk upgrade before generic schema verification.
Recognize the existing v3.0 layout, create the new ordered layout, and copy all
legacy columns explicitly with `lsn_from_hostgroup=NULL`. Preserve IDs, values,
constraints and AUTOINCREMENT behavior; run transactionally and retain a
recoverable old schema if migration fails. Plain ADD COLUMN puts the field in
the wrong position. Upgrade must be idempotent and precede config disk loading.

The plan's compatibility choice is separate query-rule synchronization between
v3.0 and v3.1/v4.0, even when the new field is NULL. The newer tier uses the new
projection for runtime snapshots, requests, response validation and checksums.
Reject incompatible projections before mutating runtime, memory or disk rules.
Do not silently retry a legacy projection or drop an enabled LSN constraint.
Other cluster modules retain their own existing compatibility behavior.

Supporting mixed-version legacy-only rule synchronization was discussed but not
selected; it would require an explicit projection/checksum compatibility design.

`stats_pgsql_lsn` remains exactly `hostname`, `port`, `lsn`, one row per physical
endpoint, NULL for unavailable current progress. It is absent in v3.0. Historical
timestamps, error strings and logging fields do not belong in this stats table.

## References and implementation status

- [Implementation plan](../plans/2026-10-04-pgsql-lsn-query-rules.md).
- Existing MySQL source selection: `lib/MySQL_Session.cpp`,
  `handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection`.
- [PostgreSQL WAL position functions](https://www.postgresql.org/docs/current/functions-admin.html).
- [PostgreSQL protocol messages](https://www.postgresql.org/docs/current/protocol-message-formats.html).
- [SQLite table reconstruction and column order](https://sqlite.org/lang_altertable.html).

This document records a design, not completed implementation or validation.
