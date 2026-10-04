# PostgreSQL LSN-constrained backend selection

ProxySQL 3.1 and 4.0 builds can constrain backend selection with
`pgsql_query_rules.lsn_from_hostgroup`. The feature uses native PostgreSQL
application connections and background PostgreSQL monitor connections. It is
absent from 3.0 builds.

## Configuration

For example, applications normally execute writes in hostgroup 10, and this
rule sends matching reads to hostgroup 20 while depending on the application's
last execution in hostgroup 10:

```sql
INSERT INTO pgsql_query_rules
    (rule_id, active, match_pattern, destination_hostgroup,
     lsn_from_hostgroup, apply)
VALUES (100, 1, '^SELECT', 20, 10, 1);
LOAD PGSQL QUERY RULES TO RUNTIME;
SAVE PGSQL QUERY RULES TO DISK;
```

Use a match appropriate to your application's routing. Hostgroup 0 is a valid
source. NULL leaves the rule's source dependency unset; a later matching rule
with NULL does not clear a dependency set by an earlier rule. The column is
between `multiplex` and `log` in the admin, runtime and disk schemas.

Neither hostgroup has a special writer/reader role in LSN tracking. The
destination remains the query's normal destination hostgroup. No replication
hostgroup pairing is needed and there is no automatic fallback to another
hostgroup. Queries whose effective rules leave `lsn_from_hostgroup` unset use
ordinary backend selection.

The PostgreSQL monitor owns all polling and retention:

| Variable | Default | Range | Meaning |
| --- | ---: | ---: | --- |
| `pgsql-monitor_lsn_poll_interval` | 10 ms | 1–60000 ms | Minimum interval between sample starts per endpoint. |
| `pgsql-monitor_lsn_poll_timeout` | 100 ms | 1–600000 ms | Timeout for a background sample, including its identity validation. |
| `pgsql-monitor_lsn_history` | 60000 ms | 1000–604800000 ms | Retained sample-age window, plus at most one older boundary sample. |

Apply these through `LOAD PGSQL VARIABLES TO RUNTIME`. Background connection
establishment uses the existing monitor connection timeout. A sample timeout
withdraws that endpoint's current eligibility until another successful sample;
it does not set a client query deadline. Causal queries use the ordinary
backend-acquisition retry and timeout settings.

Polling uses the existing monitor credentials, database and TLS configuration.
The monitor account must be able to open a database replication connection and
execute `IDENTIFY_SYSTEM`, `pg_control_init()` and the sampled PostgreSQL
functions. This connection
uses `replication=database`, which permits both replication commands and SQL;
see the [PostgreSQL replication protocol documentation](https://www.postgresql.org/docs/current/protocol-replication.html).
Configure a role with replication permission, appropriate database access and
server authentication rules. Each monitored physical endpoint consumes one
additional replication connection. The monitor creates no replication slot and
does not stream WAL.

## Execution and selection

Each frontend session retains one `{hostname, port, completion timestamp}`
record per hostgroup it has used. A real native application cycle ending at
ReadyForQuery replaces that hostgroup's record. Internal connection setup and
cache hits do not replace it. The record survives returning its backend
connection to the pool.

Permanent fast-forward sessions do not participate in this mechanism.

When an opted-in request needs a backend, ProxySQL looks up the source record.
If the session has never executed in that source hostgroup, selection is
unconstrained. Otherwise it resolves the first retained successful source
sample whose request started strictly after the recorded completion. The
sample's LSN and WAL history become a fixed requirement for that request.
Selection admits only destination servers with valid progress in the same WAL
history at or beyond that LSN. An unresolved sample or lagging destination uses
the usual acquisition retries; it does not relax the requirement.

PostgreSQL does not return the transaction's LSN in its normal completion
packet, so this mapping is conservative: concurrent work can make the required
position newer than the application's transaction. The source uses insertion
LSN and a recovering server uses replay LSN. The monitor never traverses or
updates frontend sessions, and application connections send no additional SQL
or identity requests for this feature.

At a WAL page boundary, PostgreSQL's insertion position can point beyond a
page header while replay is already at the end of the last actual record. The
monitor reads WAL layout metadata once per connection and normalizes these
exact header-only positions for verified PostgreSQL 14–18 layouts. It uses
the server's reported alignment, page size and segment size; ordinary insertion
positions and replica replay positions are unchanged. Unknown layouts retain
the raw conservative position, which can require additional WAL activity before
an idle replica qualifies. The sampler never substitutes a potentially earlier
write or flush LSN for insertion progress.

If the session uses server A and then server B in the same source hostgroup,
B replaces A even if B is behind. Configure source hostgroups accordingly.
This feature intentionally keeps only the most recent server and timestamp;
it does not combine dependencies from every server previously used.

Pinned transactions and portals cannot be moved to satisfy a new dependency.
An incompatible pin produces an error and discards affected backend work;
an explicit transaction remains aborted until the client ends it. An observed
source history change produces an explicit causal error. Stable physical
endpoints and normal external failover fencing remain required; this feature
does not establish timeline ancestry or reconcile divergent clusters.

Query-cache lookup, insertion and invalidation are unchanged. A cache hit is
returned before backend selection and therefore performs no LSN lookup or wait.
An LSN rule does not add a freshness guarantee to cached results.

## History and statistics

`LOAD PGSQL QUERY RULES TO RUNTIME` derives source and destination interests.
Servers are sampled once per hostname/port even when they appear in several
hostgroups. Routing that cannot be inferred completely uses conservative
interests, including SQL-comment destination overrides.

Where all relevant positions are known, progress pruning retains the newest
real source sample below their minimum LSN and all newer samples. Independent
age pruning keeps the configured window and one older anchor, even if a peer
is stuck, down or unknown. For example, progress 12345, 12340 and 12341 permits
removing source samples older than its newest real sample below 12340; it does
not manufacture an LSN of 12339 if that sample was never observed.

An old completion can resolve to a retained newer sample, requiring a stronger
position. A stuck replica stays ineligible while an up-to-date replica can
serve the request. Pruning never changes a requirement already copied into an
in-flight request. Observed identity-change boundaries prevent old completions
from resolving against a replacement history.

```sql
SELECT hostname, port, lsn FROM stats_pgsql_lsn;
```

This table exposes current progress only: one row per tracked physical endpoint
and NULL for unknown or withdrawn progress. It contains no hostgroup duplicates
or historical probe log. Failed or slow probes do not block age cleanup.

## Upgrade and cluster synchronization

The 3.1/4.0 disk upgrade transactionally inserts the nullable column in its
defined position, preserving existing rules, IDs and the autoincrement
watermark. Existing rules remain unconstrained after upgrade.

PostgreSQL query-rule synchronization is allowed within the legacy 3.0 schema
tier and within the 3.1/4.0 schema tier. Synchronization across those tiers is
rejected before replacing local rules. There is no projection that silently
drops `lsn_from_hostgroup`, including when every source value is NULL. Plan
mixed-version deployments around that query-rule synchronization boundary.

The 3.1↔4.0 exception permits only the built-in PostgreSQL query-rule module.
Other modules retain their existing version and plugin compatibility checks.
A peer changing between full compatibility and query-rules-only compatibility
loses its previous donor eligibility immediately and must provide a fresh
checksum snapshot before synchronization resumes.

## Verification

The [validation record](pgsql-lsn-query-rules-validation.md) lists completed
builds, test results, measurements and remaining coverage limits.

Build a supported tier with `make -j4 PROXYSQL31=1 debug` or
`make -j4 PROXYSQL40=1 debug`. The feature's unit targets are
`pgsql_lsn_manager_unit-t`, `pgsql_lsn_probe_unit-t`,
`pgsql_lsn_monitor_unit-t`, `pgsql_lsn_config_unit-t`,
`pgsql_lsn_query_rules_unit-t`, `pgsql_lsn_completion_unit-t`, and
`pgsql_lsn_admission_unit-t` in `test/tap/tests/unit`. Migration, configuration,
cluster, waiter, transaction, portal, cache and framing regression suites also
exercise the affected integration points.

The live scripts create and clean up their own resources and retain logs:

```sh
python3 test/tap/tests/pgsql_lsn_endpoint_smoke.py \
  --proxy /path/to/proxysql31 --artifacts /path/to/native-results
python3 test/tap/tests/pgsql_lsn_cluster_schema_smoke.py \
  --proxy30 /path/to/proxysql30 --proxy31 /path/to/proxysql31 \
  --proxy40 /path/to/proxysql40 --artifacts /path/to/cluster-results
```

The endpoint test requires Docker, the `postgres:17` image, `psycopg2`, and
`pymysql`. It covers native simple and extended queries, COPY, transaction
refusal, cancellation, pool exhaustion, paused replay, rule activation after
an earlier execution, monitor restart, history expiry, the idle WAL boundary,
and unchanged cache behavior. Cluster testing covers ordered schemas, populated
disk upgrades, compatible synchronization and non-mutating rejection across
incompatible schema tiers.
