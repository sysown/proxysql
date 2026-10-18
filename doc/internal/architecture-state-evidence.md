# Architecture evidence: state ownership and publication

Investigated 2026-10-18 against `f8ada9117`, on `docs/invariants-expansion`.
This is supporting research, not a maintainer-ratified design. References describe
the implementation at that revision. Source inspection and history only; no runtime
tests were executed. Scope is system-level state and propagation, not command semantics.

## Principal finding

ProxySQL does not have a single configuration object that all execution contexts read.
It separates editable configuration, persistent configuration, applied runtime state,
published representations, and worker-local copies. These are distinct authorities
for different questions. Calling all of them “configuration” hides the architectural
boundaries an implementer or reviewer needs to respect.

## Verified state map

| State | Owner / principal writers | Principal readers | Publication / transition |
| --- | --- | --- | --- |
| Editable MEMORY configuration | Admin in-memory SQLite database; operator SQL and supported management/Cluster apply paths write it | Configuration loaders, management interfaces | Editing MEMORY and applying to RUNTIME are distinct operations. Server loader selects MEMORY rows unless supplied incoming resultsets. [Database creation](../../lib/Admin_Bootstrap.cpp#L737), [server loader](../../lib/ProxySQL_Admin.cpp#L9123) |
| Persistent DISK configuration | Admin `configdb`, opened at configured on-disk path and attached as `disk` | Bootstrap / explicit configuration copy paths | Generic copy explicitly chooses `disk_to_memory` or `memory_to_disk`; it does not itself install runtime objects. [Open](../../lib/Admin_Bootstrap.cpp#L798), [attach](../../lib/Admin_Bootstrap.cpp#L1160), [copy](../../lib/ProxySQL_Admin.cpp#L6493) |
| Applied backend configuration and operational backend state | Protocol Hostgroup Managers (HGM); Admin supplies configuration, monitor supplies observations/actions | Workers selecting/borrowing backends, monitor target generation, Admin projections | Server loading stages incoming tables then calls HGM commit. HGM applies changes under its lock, refreshes checksums and published data, advances a version, updates monitor targets, signals workers. [Load/commit](../../lib/ProxySQL_Admin.cpp#L9358), [HGM commit](../../lib/MySQL_HostGroups_Manager.cpp#L1735), [version and monitor publication](../../lib/MySQL_HostGroups_Manager.cpp#L2053), [worker signal](../../lib/MySQL_HostGroups_Manager.cpp#L2090) |
| Applied authentication data | Protocol authentication managers; Admin user-installation path refreshes their entries | Protocol authentication / authorization consumers | Admin serializes installation with users mutex; actual users are installed in Auth structures. MEMORY user rows are not themselves the runtime authentication store. [Installation entry](../../lib/ProxySQL_Admin.cpp#L6552), [Auth update](../../lib/ProxySQL_Admin.cpp#L7036) |
| Applied query policy | Shared protocol query processors; Admin installs rules | Worker-local query processor rules | Commit advances a version; a worker notices it at query processing and copies active rules under processor read lock. [Commit](../../lib/Query_Processor.cpp#L1616), [refresh](../../lib/Query_Processor.cpp#L2850) |
| Applied protocol variables | Protocol thread handlers; supported variable installation paths | Protocol workers and other runtime consumers | MySQL handler commit increments global variable version; event loops notice and refresh their thread-local copies. PostgreSQL follows the same version/refresh pattern. [Variable install](../../lib/Admin_FlushVariables.cpp#L584), [MySQL version](../../lib/MySQL_Thread.cpp#L1809), [MySQL observation](../../lib/MySQL_Thread.cpp#L4438), [copy](../../lib/MySQL_Thread.cpp#L5382), [PostgreSQL observation](../../lib/PgSQL_Thread.cpp#L3547) |
| Monitor observations/history | Protocol monitor, including its SQLite observation tables | Monitoring policy and Admin observability | Monitor records observations then invokes HGM actions for role, lag, health and latency. Observation storage and runtime backend availability are separate state. [PostgreSQL role](../../lib/PgSQL_Monitor.cpp#L1839), [lag](../../lib/PgSQL_Monitor.cpp#L1889), [health](../../lib/PgSQL_Monitor.cpp#L1754), [MySQL actions](../../lib/MySQL_Monitor.cpp#L9324) |
| Published Cluster server datasets | Protocol HGM retains resultsets representing last-promoted server configuration and runtime servers | Admin special Cluster queries, then remote Cluster pull paths | `*_servers_v2` returns retained last-promoted configuration; `cluster_*_servers` returns retained runtime resultset. They are not arbitrary live reads of editable MEMORY tables. [MySQL endpoint](../../lib/Admin_Handler.cpp#L3369), [MySQL getters](../../lib/MySQL_HostGroups_Manager.cpp#L3755), [PostgreSQL getters](../../lib/PgSQL_HostGroups_Manager.cpp#L3335) |
| Configuration synchronization metadata | Per-module checksums, epochs and versions, plus peer observations maintained by Cluster | Cluster decision logic and Admin checksums/metrics | Sync is module-specific and threshold-driven; for the inspected variables loop, initial version and epoch comparisons constrain pulling, and equal-epoch conflict is reported instead of resolved by consensus. [Decision loop](../../lib/ProxySQL_Cluster.cpp#L798) |

The owner column denotes responsibility and principal mutation paths, not a promise
that only one class can write any field. Optional managed-runtime paths exist, so an
architecture rule saying “only SQL LOAD can change runtime” would be false. For example,
the managed variable path updates runtime and then refreshes its Admin runtime projection
and checksum. [Managed projection publication](../../lib/ProxySQL_ManagedRuntime.cpp#L928).

## Important architectural consequences

### Editing, activation, persistence and observation are different operations

The verified flows support the following conceptual model:

```text
DISK <---- explicit copy ----> editable MEMORY
                                  |
                           apply / install
                                  v
                        runtime domain owners
                          |              ^
                    publish/copy         | monitor actions
                          v              |
                 worker views and operational projections

peer published configuration --> local Cluster pull --> local apply
                                               \----> optional DISK save
```

This diagram is a synthesis of the cited paths, not a claim of one global transaction.
Published runtime tables are representations of runtime domain state, not an additional
independent authority that should be edited to drive execution.

Configuration-mode Cluster server pulls write local MEMORY, invoke the Admin/HGM installation
path and persist only if configured. Runtime-only server pulls can instead commit HGM directly,
materializing MEMORY when configured persistence requires it. [Runtime-only MySQL path](../../lib/ProxySQL_Cluster.cpp#L2084).
[MySQL configuration apply and optional persistence](../../lib/ProxySQL_Cluster.cpp#L2661),
[PostgreSQL apply and optional persistence](../../lib/ProxySQL_Cluster.cpp#L3892).

### Configuration visibility is versioned and has more than one boundary

Worker variable copies refresh in event loops; query rules refresh at query processing.
HGM-owned strings needed on worker paths now have worker-local copies and a HGM version.
Thus “LOAD completed” must not casually be described as a simultaneous replacement of
every worker's local state. The specific consumer's refresh boundary matters.

The October 15 change is a particularly clear architectural decision: replace shared
string access protected on every use with worker copies refreshed on HGM version change.
HGM copies strings and the corresponding version under the same HGM lock.
[Copy implementation](../../lib/MySQL_HostGroups_Manager.cpp#L1187),
[history `cd243e2b1`](https://github.com/sysown/proxysql/commit/cd243e2b1c9ee3100a1d9f83ef5a91e01ca35701).
This is evidence for domain-owned publication and consumer-owned snapshots, not a
universal instruction to copy all shared state.

### Operational changes are not necessarily edits to desired configuration

Monitor calls HGM actions directly after observations. HGM distinguishes incoming
promoted `*_servers_v2` configuration from the runtime server dataset and has a
runtime-only commit mode. [Separate checksum/publication paths](../../lib/MySQL_HostGroups_Manager.cpp#L1983).
An implementation should identify whether it changes operator intent, observed
conditions, or derived runtime state before deciding which representation to update.
This is an architectural inference supported by the separate stores and paths.

### Peer configuration synchronization is not distributed execution coordination

Cluster compares module metadata, fetches published datasets and applies configuration
locally. The investigated paths do not distribute client session ownership, transaction
execution or backend connection ownership across peers. That latter boundary is already
maintainer-confirmed in the architecture discussion. The inspected epoch/conflict logic
also should not be described as consensus or a globally serializable configuration store.

### Precomputed data does not, by itself, settle lifetime protection

Cluster server endpoints obtain retained HGM resultset pointers. The getters return
members, not fresh copies. Replacement deletes previous resultsets.
[Replacement](../../lib/MySQL_HostGroups_Manager.cpp#L3714).
Therefore the verified fact “pull response uses precomputed resultsets” invalidates
assuming that a live-table read needs protection, but does not alone prove every lock
on that path redundant. The lifetime and publication synchronization must be traced
separately before proposing a lock change. This investigation makes no defect claim
about those existing locks.

## History that constrains architectural claims

| Change | Architectural evidence |
| --- | --- |
| [`cd243e2b1`, October 15](https://github.com/sysown/proxysql/commit/cd243e2b1c9ee3100a1d9f83ef5a91e01ca35701) | Runtime writers publish a version under the same lock as data replacement; workers keep their own string copies. This protects lifetime while avoiding lock contention on every connection-open path. |
| [`4e957ac3f`, October 14](https://github.com/sysown/proxysql/commit/4e957ac3f42b1646d664959a45506c13ef2ef43e) | Server-module table synchronization was removed because no in-tree plugin registered server-module tables. Current architecture must distinguish supported/shipped extension paths from machinery removed for lack of consumers. |
| [`69e13bc3e`, October 14](https://github.com/sysown/proxysql/commit/69e13bc3e2657ab004632aff2859bad96919a44e) | Admin global SQL lock nesting is core-owned per-thread state shared with plugins; hidden plugin-local copies broke ownership. Existing locking protocol is not simply “take a mutex whenever touching configuration.” |

## Remaining questions, rather than implied guarantees

1. **Activation scope:** which configuration families provide atomic replacement, and
   which intentionally apply entries independently? HGM commit and SQLite transactions
   are not evidence of one process-wide atomic configuration transaction.
2. **Visibility guarantee:** whether the product promises a stronger worker visibility
   boundary than the inspected refresh mechanisms demonstrate. Source establishes
   versioned refresh, not the intended operator-facing timing contract.
3. **Snapshot lifetime:** enumerate readers and replacement writers before declaring
   exact resultset lifetime/locking requirements. Published datasets are established;
   a full synchronization proof is outside this note.
4. **Optional runtime writers:** managed runtime and discovery paths require their own
   bounded ownership mapping before making universal claims about core write paths.
5. **Monitor authority:** document, per supported topology, which runtime changes the
   monitor is authorized to make. Source proves direct actions, not a universal rule
   that monitoring can rewrite all configured topology.

## Suggested system-level contract candidates

These are proposals requiring maintainer review, not new ratified invariants:

- Every state-changing feature identifies its authoritative domain owner and whether
  it changes editable configuration, persistence, applied runtime, or operational state.
- Consumers use the owner's published representation or supported access protocol;
  they do not infer current runtime behavior from an unrelated editable copy.
- A runtime installation accounts for all supported derived publications and consumer
  views affected by the change, including Cluster checksums where applicable.
- Configuration synchronization applies supported configuration locally; it creates no
  cross-instance ownership of client sessions or database transactions.
- An additional shared lock, validator or publication path needs a demonstrated input,
  writer/reader relationship or shipped consumer, respecting existing owner guarantees.
