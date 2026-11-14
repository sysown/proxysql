# Native TCP forwarding through existing hostgroup managers

Status: implemented and verified. This revision follows the user's explicit
choices: map TCP groups to MySQL/PostgreSQL groups, use their existing managers
and accounting, model connections after fresh fast-forward connections, always
destroy on release, and use OFFLINE_HARD as the forced-disconnect authority.
Root owns design/review; subagents coordinate OpenCode DeepSeek v4.1 Flash for
implementation, tests and benchmarks. No extra approval pause, commits or pushes.

## Architecture and ownership

Retain the native epoll byte relay. For mapped groups, the existing protocol HGM
selects the backend and owns a real MySQL_Connection or PgSQL_Connection in its
actual ConnectionsUsed list. Pending, queued and established TCP connections all
count as in use and participate in the existing max_connections and statistics.
The HGM's weight/backup/latency/status/creation-throttle policies remain in charge.
The plugin does not copy backend inventory, run a second mapped health monitor,
or keep a second backend capacity authority. Operators are responsible for
choosing hostgroups for SQL or raw TCP traffic. There is no traffic-mixing guard.

The relay owns the OS socket. The HGM protocol object is an accounting/lifetime
object with no protocol socket and no authentication/handshake state. It enters
ConnectionsUsed before the selected connection is queued, stays there through
connect/forwarding, and is removed and deleted on every exit. ConnectionsFree is
never used. Every retry acquires a fresh object. The client/server handshake and
TLS bytes pass unchanged from the first byte. No application replay, protocol
commands, authentication or backend pooling occurs.

A single ABI-18 service getter returns the core-owned V2 table declared in
include/ProxySQL_PluginRawBackend.h. The ABI-17 services prefix remains intact;
old compatible plugins keep loading; unknown ABI19 and mismatched debug builds
are rejected. Phase B returns no backend service. Init/start retain the borrowed
table; all handles/callers are drained before plugin stop returns. Existing
chassis shutdown stops plugins before HGM destruction.

The core service acquires under the actual protocol HGM lock, uses existing
get_random_MySrvC selection without constructing a SQL session, and registers a
fresh protocol object. Native thread-local policy values are copied safely from
the corresponding thread handler and restored on return; no fabricated session
or accidental zero-initialized TLS selection policy. SQL-only capability filters
must guard their session argument. Comparative latency filtering also applies:
the native scoped policy captures min_num_servers_lantency_awareness from the
corresponding handler and supplies it to the existing algorithm when no SQL
session is present. The existing SQL-session policy path remains unchanged. HGM locks never encompass socket operations,
DNS resolution, SQL, plugin callbacks, Admin locks or worker joins.

Numeric addresses are accepted directly. Mapped hostnames use only the existing
protocol monitor DNS cache outside the HGM lock. A cache miss fails acquisition
with a clear diagnostic and releases the in-use object; no blocking resolver or
fabricated database connect error. Static TCP endpoints remain numeric-only.

## Configuration and persistence

Preserve the existing five TCP table definitions. Add a sixth persistent pair:

```sql
CREATE TABLE tcp_hostgroup_mappings (
    hostgroup_id INTEGER PRIMARY KEY CHECK(hostgroup_id >= 0),
    source_protocol TEXT NOT NULL CHECK(source_protocol IN ('MYSQL','PGSQL')),
    source_hostgroup INTEGER NOT NULL CHECK(source_hostgroup >= 0),
    comment TEXT NOT NULL DEFAULT ''
);
```

The hostgroup_id refers to an existing tcp_hostgroups row. Absence of a mapping
means its existing static TCP pool. A mapping names the source protocol namespace
and source hostgroup ID; both protocols may use the same numeric ID. Empty or
currently absent source hostgroups are valid configuration and reject new
connections until eligible backends appear. Duplicate/dangling mappings, invalid
protocols and tcp_servers rows assigned to mapped groups are rejected atomically.
Static balancing/health settings are ignored for mapped groups, whose policy is
inherited from the source HGM.

The new table has config_db and runtime twins, explicit columns and strict row
parsing. All LOAD/SAVE commands atomically copy six tables; source backend
membership, health and counters are never copied into TCP persistent tables.
The Engine Config gains HostgroupMapping and a hostgroup_mappings vector.
Runtime mappings show active configuration; stats_tcp_servers remains static
backend statistics. Existing protocol runtime/pool stats are authoritative for
mapped backend status/counters. TCP listener/rule/global forwarding stats remain.

A separate mapping table is deliberate: the existing core exact-DDL builder can
drop/recreate a changed table. Keeping old TCP DDL intact preserves persisted
configuration and avoids broad schema-migration changes. Old five-table files
restore with an empty new mapping table; new six-table persistence roundtrips.

## Connect outcomes, bytes and disconnect

Successful TCP connect increments the existing connect_OK/connected counters;
failed TCP connect increments the normal connect_ERR/error/shunning machinery
with the proper protocol transport error representation. A connect outcome is
reported once, including pending timeout. Admission rejection, DNS-cache misses
and cancellation before an actual failed connect do not fabricate connect errors.
Destroy balances connected/in-use counts exactly once, including partial failure.
Destroy returns the final hard-offline fence while holding the registry lock
that unregisters the handle, within HGM serialization. Before retrying, the
Engine closes its OS socket, explicitly destroys the old core connection, and
retries only when that atomic result is false. A HARD transition between an
earlier status read and destruction therefore cannot escape into a new backend.
Transitions after actual retirement do not retroactively cancel a new attempt.
BackendConnection exposes this destruction result and its destructor still
cleans any unconsumed handle exactly once. The service's version tag is 2, so
intermediate V1 prototypes fail closed rather than mix void/bool callbacks.

Core protocol query/authentication statistics are untouched: the relay cannot
observe those operations. A connected raw stream never emits COM_QUIT or any
PostgreSQL protocol termination packet.

Existing backend byte counters record actual successful writes to the backend
and actual reads from it, including bytes read but not delivered to a closing
client. Update in bounded batches per I/O turn and flush before handle release;
listener/rule forwarding counters preserve their existing actual-forwarded-byte
meaning. No double reporting on retries, partial sends, EOF or hard close.

The engine's provider interface is core-independent and translates its owned
handle to the ABI service. Accepted transfers ownership to Flow through RAII;
queue rejection, allocation failure, failed start, timeout, stop and retries all
destroy once. No worker callback or plugin-defined object is retained by core.

Workers inspect the handle's actual backend status at most 100ms apart, including
idle and pending flows. OFFLINE_SOFT and SHUNNED prevent fresh selection according
to HGM policy while an established stream remains attached. OFFLINE_HARD closes
both sides, never retries that stream onto another backend. Role migration uses
the existing old writer-entry OFFLINE_HARD transition, and its reader entry can
remain eligible. Membership removal/replacement respects actual HGM object
identity, whose lifetime is pinned by ConnectionsUsed. Applying a TCP remapping
changes new connections; old streams retain their old HGM connection and status.
The core latches an actual OFFLINE_HARD transition on every live raw handle for
that exact server object. A rapid HARD-to-ONLINE change therefore cannot revive
an old stream between polls; new acquisitions after ONLINE get fresh handles.
This records the existing status authority, rather than inventing a role-change
policy. A core-resident registry tracks only live handles, unregisters on destroy,
and never allocates or invokes plugin callbacks while marking HARD. Its storage
outlives global plugin teardown, including fast exit. Lock order is HGM then
registry; marking takes only the registry lock and sets flags.
The TCP control plane's static server IDs must not accidentally target mapped
connections. Global/listener bounded admission and buffer/timeouts still apply.

## Verification and benchmark requirements

Core tests cover real HGM selection, in-use/shared limits, counter balance,
errors/byte directions, native thread policy, DNS-cache success/miss, no SQL
commands/reuse, removal identity, lifecycle and ABI17 prefix compatibility.
Engine/provider tests cover mapped config, no-provider rollback, acquire/retry,
RAII/unwind, pending errors, hard status while idle/pending, remapping and static
regressions. Admin tests cover registration without phase-B DB access, six-table
strict transactional copies/default restoration/runtime separation.

Both protocols require real composed-daemon tests: opaque binary/first-byte/TLS,
ConnUsed transitions, ConnFree zero, fresh connections, shared max_connections,
connect OK/ERR, exact byte deltas, weights/status, SOFT/HARD/removal and restart.
Exercise real monitor-driven role changes with task-owned MySQL and a controlled
PostgreSQL wire endpoint if a physical standby is impractical; label fixtures
honestly and require actual monitor/HGM transitions rather than fake provider
notifications. Preserve standalone static/adversarial and core regression checks.

Benchmark short identical loopback workloads for direct, static daemon, mapped
MySQL daemon, mapped PostgreSQL daemon and adjacent HAProxy. Record full-daemon
resource scope, actual binary/source hashes, payloads, workers, samples, CPU/RSS,
byte reconciliation and idle connections. Old engine-only benchmark stays labeled
engine-only. Update Markdown and HTML user guides/reports/index after validation.
