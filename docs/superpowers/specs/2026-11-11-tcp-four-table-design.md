# TCP forwarding with mandatory hostgroup mappings

Status: implemented, integrated and verified on 2026-11-11. Root owns design
and verification. OpenCode DeepSeek v4.1 Flash performs implementation and tests.

## Configuration and ownership

The plugin has exactly four editable/persistent configuration tables:
`tcp_settings`, `tcp_hostgroups`, `tcp_listeners`, `tcp_routing_rules`.
`tcp_hostgroups` is the mandatory mapping definition. It has `hostgroup_id`
(nonnegative signed int32 primary key), `source_protocol` (`MYSQL` or `PGSQL`),
`source_hostgroup` (nonnegative signed int32), and `comment` (non-null text).
No balance/health columns, local backend definitions or fallback mode remain.
The separate mapping table and static server/runtime/stats tables are removed.

Authoritative new hostgroup DDL (spacing is significant to core bootstrap):

```sql
CREATE TABLE tcp_hostgroups ( hostgroup_id INTEGER PRIMARY KEY CHECK(hostgroup_id >= 0), source_protocol TEXT NOT NULL CHECK(source_protocol IN ('MYSQL','PGSQL')), source_hostgroup INTEGER NOT NULL CHECK(source_hostgroup >= 0), comment TEXT NOT NULL DEFAULT '')
```

Keep listener and routing-rule columns, references, actual-peer CIDR matching,
ROUTE/REJECT and first-match semantics. Every default/ROUTE destination must
reference a TCP hostgroup, even in inactive rows. Core source hostgroups may
be empty/absent and later populated by monitoring/Admin. MYSQL/PGSQL namespaces
remain distinct. Several TCP groups may share a core group and its capacity.

Existing HGM alone owns backend selection/limits/status/health/counters/errors.
Keep relay-wide and per-listener FRONTEND admission limits; these do not create
backend reservations. Keep explicit relay connect timeout/retry, idle timeout,
half-close, worker/buffer/shutdown controls. No silently ignored settings.
Actual core Used-list handles, engine socket ownership, actual-byte accounting,
fresh always-destroy lifecycle and atomic OFFLINE_HARD retirement fence are
unchanged. Never reroute an established stream. Native role/monitor changes do
not require another TCP LOAD. Existing ABI18 / raw service V2 remain unchanged.

Remove production Server/ServerStats/HostgroupMapping config types, custom
selection, capacity, health workers and server metrics. A hostgroup type now
contains the mapping fields. Runtime has four config projections plus status;
stats keep listeners/rules; metrics retain relay/listener/rule families. The
core backend provider remains dependency-injected for socket unit tests.

## Persistence and safe upgrade

Keep the existing TCP command names/aliases and make all four-table copies
atomic, with rollback preserving prior runtime and rows. Source protocol server
configuration uses its own existing LOAD/SAVE commands.

Do not rely on plugin init/early_action to migrate: both happen after the core's
destructive exact-DDL builder. Add a generic core preflight for registered
persistent plugin tables BEFORE schema materialization. Missing/current tables
are accepted; mismatching existing DDL is an actionable startup error, and every
such mismatch is detected before ANY registered plugin table is recreated.
The guard shares the builder's existing prefix normalization through a pure
SQLite helper extraction; table names and bodies remain byte-for-byte comparisons.
No TCP-specific knowledge, new plugin ABI, or silent deletion enters the core.

Provide `plugins/tcp_proxy/tools/migrate_tcp_config.py`: explicit offline
`--database FILE --check` / `--database FILE --apply`; read-only check by default.
It recognizes current schema idempotently and the known prior six-table/five-table
schema, validates all rows and references, and refuses unknown layouts,
nonempty tcp_servers, any unmapped old TCP group, dangling/invalid mappings,
malformed rows and conflicting migration leftovers. Embedded NUL is invalid in
all product text/comment fields, matching current LOAD validation; preserve
apostrophes/newlines/tabs/UTF8 with bound SQL and unrelated BLOB values intact. Empty old groups may migrate
only if all existing groups have mappings. Unchanged settings/listeners/rules
and unrelated tables retain every row. Merge mapping and hostgroup comments:
use the nonempty one or one copy if equal; if both differ join with newline.

Application creates an exclusive, non-overwriting SQLite backup, obtains a
write transaction, revalidates the source, replaces only the hostgroup table,
drops the now-empty legacy server and merged mapping tables, checks resulting
schema/rows, commits, and leaves no partial data on failure. Never open a missing
DB by creating it. Document stopping ProxySQL before conversion, backup path,
and rollback with the stopped daemon. The converter's exact DDL must match the
new plugin DDL (asserted by a focused test). No automatic mapping creation for
static endpoints. This is an explicit schema upgrade of saved configuration.

## Approaches and decisions

Retaining two configuration modes was rejected: it preserves duplicate policy
and confusing ignored knobs. Mandatory mapping with separate identity and mapping
tables was rejected: each hostgroup has exactly one required assignment. Merge
into `tcp_hostgroups`, as approved. Explicit offline conversion plus generic
bootstrap protection avoids a new schema-migration ABI and keeps migration code
with its owning plugin. The cost is one operator upgrade step for older DBs.

## Verification and documentation

Add tests before changing behavior for mandatory mappings, protocol validation,
dangling references, absent core groups, four-table transactions/runtime/schema,
removed server metrics, upgrade backup/rollback/idempotency/static rejection,
and preflight no-data-loss across fresh/current/mismatched plugin tables.
Preserve protocol-independent relay regressions using a test backend provider;
remove only tests that exclusively verify deleted standalone selection/health
features, recording each retirement. Keep all mapped ownership/HARD/race tests.
Exercise real-daemon both protocol HGM modes, role changes, shared accounting,
persistence/restart/STOP/START and upgrade refusal/conversion. Build matching
release/debug DSOs, run Engine sanitizers, and independently review final source.
Adapt benchmark tooling to direct/mapped MYSQL/mapped PGSQL/HAProxy. Existing
five-mode benchmark reports remain historical measurements, clearly labeled;
new short measurements must use the changed schema and verified source hashes.
Refresh Markdown and self-contained HTML guide, report index, links and examples.
No commits/pushes, unrelated edits, donor dependency writes or broad process kills.
