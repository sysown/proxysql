# AWS Locality-Aware MySQL Backend Selection

**Status:** Approved design

**Date:** 2026-08-13

## Summary

ProxySQL 4.0 will optionally prefer MySQL backends that are in the same AWS
Region or Availability Zone as the ProxySQL process. The feature changes only
the temporary weights used by a server-selection attempt. It never modifies
`mysql_servers.weight`, `runtime_mysql_servers.weight`, the saved
configuration, or ProxySQL Cluster checksums.

The MySQL module owns the feature's configuration and traffic policy. The
general AWS plugin provides asynchronous, normalized AWS metadata and makes no
traffic-routing decisions.

The first version supports RDS and Aurora endpoints. It does not discover
arbitrary MySQL servers on EC2.

## Goals

- Preserve configured server weights while giving operators a bounded local
  Region and local AZ preference.
- Keep all AWS, IMDS, DNS, and credential-provider work out of connection
  selection.
- Keep locality configuration in the MySQL module because MySQL Hostgroup
  Manager consumes it.
- Discover every ProxySQL process's location independently so ProxySQL Cluster
  cannot propagate one process's Region or AZ to another.
- Degrade to ordinary configured weights whenever metadata is unavailable,
  expired, invalid, or unsupported.
- Make every classification and active multiplier observable without changing
  `runtime_mysql_servers`.
- Reuse the general AWS plugin and its statically linked vendored AWS SDK
  runtime alongside the IAM database-authentication capability.

## Non-goals

- Mutating configured or runtime server weights.
- Synchronizing discovered metadata through ProxySQL Cluster.
- Moving, closing, or rebalancing existing backend connections.
- Discovering arbitrary EC2-hosted MySQL servers.
- Resolving custom CNAMEs to infer an RDS or Aurora target.
- Scanning every AWS Region to locate an endpoint.
- Assuming roles into other AWS accounts.
- Managing RDS/Aurora topology or hostgroup membership.
- Supporting RDS Proxy endpoints in the first version.
- Providing PostgreSQL locality awareness in the first version.
- Making real AWS infrastructure mandatory for ordinary CI.

## User-facing configuration

### Global master switch

The MySQL module adds one dynamic global variable:

```text
mysql-aws_locality_awareness = false
```

It is available in the ProxySQL 4.0 build and defaults to `false`.

Changing it follows the normal MySQL-variable lifecycle:

```sql
SET mysql-aws_locality_awareness = true;
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```

There are deliberately no configured Region, AZ, or AWS-account variables.
Such variables could be synchronized to ProxySQL processes in other locations
and would therefore be unsafe.

When the switch is disabled:

- selection uses configured weights exactly as it does today;
- no new locality metadata refreshes are scheduled;
- in-flight locality requests are cancelled or ignored by generation;
- when the AWS plugin is loaded, cached rows remain visible in its diagnostic
  table with status `disabled`, but cannot affect selection.

### Per-hostgroup policy

The existing `mysql_hostgroup_attributes.hostgroup_settings` JSON is the
configuration extension point:

```json
{
  "aws": {
    "locality_awareness": {
      "same_region_multiplier": 2.0,
      "same_az_multiplier": 4.0,
      "refresh_interval_seconds": 300,
      "stale_ttl_seconds": 1800
    }
  }
}
```

Presence of a valid `aws.locality_awareness` object enables locality awareness
for that hostgroup. There is no additional per-hostgroup `enabled` field.

Both multipliers are required and must be finite JSON numbers satisfying:

```text
1.0 <= same_region_multiplier <= same_az_multiplier <= 10.0
```

The timing fields are optional. Their defaults and accepted bounds are:

```text
refresh_interval_seconds = 300
stale_ttl_seconds = 1800

30 <= refresh_interval_seconds <= 86400
refresh_interval_seconds <= stale_ttl_seconds <= 604800
```

An invalid locality object disables locality bias for that hostgroup after the
load. Diagnostics identify the rejected field and hostgroup but never log the
complete JSON document.

The existing `aws_iam_region` key remains an IAM-authentication setting. It is
not required by, or treated as authoritative for, locality discovery.

## Selection semantics

Locality produces a temporary effective weight for an eligible server:

```text
remote or unknown          configured_weight
same Region, different AZ  int(configured_weight * same_region_multiplier)
same AZ                    int(configured_weight * same_az_multiplier)
```

The Region and AZ tiers are mutually exclusive. A same-AZ server receives only
`same_az_multiplier`; the two multipliers are never multiplied together.

Conversion to an integer truncates toward zero. Weight zero remains zero.
Arithmetic uses a wide intermediate and saturates safely before entering the
64-bit weighted-selection accumulator. The current MySQL weight bounds make
saturation unlikely, but the operation must still be defined for every input.

Examples with configured weights `10`, `20`, and `30`, Region multiplier
`2.0`, and AZ multiplier `4.0`:

- first server in the same AZ: effective weight `40`;
- second server in the same Region but another AZ: effective weight `40`;
- third server in another Region: effective weight `30`.

The values `10`, `20`, and `30` remain stored and reported by
`mysql_servers` and `runtime_mysql_servers`.

### Classification rules

The selector classifies a backend from one immutable metadata snapshot:

- `same_az`: local and backend Regions match, local and backend AZ names match,
  and both sides have the same confirmed AWS account ID;
- `same_region`: Regions match, but AZ is different, unavailable, inapplicable,
  or cannot be trusted because account identity is unavailable or different;
- `remote`: both Regions are known and differ;
- `unknown`: either Region required for comparison is unknown.

AZ names can map to different physical zones in different AWS accounts. The
same-AZ multiplier is therefore never applied without a same-account check.
Same-Region preference does not require matching accounts.

### Existing eligibility remains authoritative

Locality changes only the weighted lottery among candidates that have already
passed the existing rules, including:

- ONLINE status and shun recovery;
- `max_connections` capacity;
- latency bounds;
- GTID requirements;
- replication-lag and Aurora-lag requirements;
- session-tracking capability backoff;
- the existing Aurora writer/replica filtering.

Locality never makes a backend healthy, eligible, or available.

### Global and thread-local pool paths

The global path in `MyHGC::get_random_MySrvC()` computes each final
candidate's effective weight and performs its existing weighted selection with
a 64-bit accumulator.

The per-thread local connection cache must also honor locality. Otherwise, a
remote cached connection could repeatedly bypass Hostgroup Manager's weighted
lottery. For locality-enabled hostgroups only, the local-cache path:

1. finds connections that pass all existing compatibility, GTID, lag, health,
   and session-state checks;
2. groups them by parent server, so a server with more idle connections does
   not gain more selection probability;
3. selects a parent server using the same effective server weight helper;
4. returns a compatible cached connection belonging to that parent.

When locality is inactive, the current local-cache first-match fast path stays
unchanged.

One snapshot is retained for an entire selection attempt, preventing a refresh
from mixing classifications within one lottery. Metadata changes affect only
future selections. Existing connections are not migrated or closed.

## Ownership and architecture

### Chosen approach

Core owns locality state and consumes an asynchronous AWS metadata provider.

This was selected over two alternatives:

1. A synchronous cached lookup into the plugin from every selection would add
   plugin ABI calls and lifecycle/synchronization risk to a hot path.
2. A plugin-owned server-selection hook would move MySQL traffic policy into
   the capability provider and violate the intended ownership boundary.

### MySQL core responsibilities

A core `MySQLAwsLocalityManager` owns:

- parsed hostgroup policies;
- registered backend endpoint identities;
- configuration generations;
- refresh scheduling and request coalescing;
- normalized results received from the plugin;
- last-attempt and last-success times;
- per-policy fresh/stale/expired evaluation;
- immutable snapshots used by selection;
- diagnostic snapshot data and redacted failure state.

Core types contain only ProxySQL-owned strings, enums, timestamps, request
IDs, and result structures. They expose no AWS SDK types.

The manager starts work only when the master switch is enabled and at least one
hostgroup has a valid locality policy. `LOAD MYSQL SERVERS TO RUNTIME` rebuilds
the endpoint registration set, advances its generation, and schedules the
necessary asynchronous refreshes. `LOAD MYSQL VARIABLES TO RUNTIME` activates
or bypasses the manager according to the master switch.

### AWS plugin responsibilities

The general `aws` plugin owns:

- AWS SDK initialization and shutdown;
- the default AWS credential-provider chain;
- IMDSv2 access;
- regional RDS clients;
- paginated RDS API calls;
- bounded retries, timeouts, and background execution;
- cancellation and clean shutdown;
- normalization into the core-defined result contract.

It makes no multiplier, eligibility, hostgroup, or traffic decision.

The plugin extends its advertised capabilities beyond `aws_iam`, for example
with local-instance metadata and RDS-topology capabilities. The plugin reuses
the same SDK runtime already used by IAM authentication.

The plugin also registers the `stats_mysql_aws_locality` schema and its
query-time refresh callback. The MySQL module remains the source of the rows;
the plugin registration only makes the AWS-specific diagnostic surface exist
when the AWS capability is actually present.

### Generic asynchronous provider ABI

ProxySQL's plugin services gain a generic AWS metadata-provider installation
contract. The first request kinds are:

- discover the local ProxySQL process's AWS location;
- describe the RDS/Aurora endpoints in one candidate Region.

Requests carry opaque IDs, deadlines, endpoint sets, and core configuration
generations. Results contain normalized endpoint type, Region, AZ where
applicable, account identity for comparison, timestamps, and a redacted status
category.

The provider uses the same lease/drain principle as the IAM token source:

- a plugin module cannot unload while requests or callbacks retain leases;
- shutdown stops accepting work, cancels queued work, and drains active work;
- callbacks target weak/core-owned completion sinks;
- callbacks run without holding plugin or Hostgroup Manager locks;
- core rejects completions from an obsolete configuration generation.

No selection path invokes this ABI.

### Immutable snapshot publication

Core publishes immutable per-hostgroup locality snapshots. A snapshot maps the
current stable backend identity `(hostgroup_id, normalized hostname, port)` to
its classification inputs and metadata timestamps. Publication is atomic; a
selection retains one snapshot for its duration and performs no network calls
or mutable-cache locking.

The optional feature may pay for immutable-map lookups. With the global switch
off or no hostgroup policy, the existing hot path bypasses those lookups.

## Local ProxySQL location discovery

Every ProxySQL process discovers its own location independently. Discovery is
node-local state and is never persisted or cluster-synchronized.

Discovery order:

1. Retrieve the EC2 instance identity document through IMDSv2. It provides
   Region, Availability Zone, and account ID.
2. If IMDSv2 is unavailable, use process environment fallback:
   - Region: `AWS_REGION`, then `AWS_DEFAULT_REGION`;
   - AZ: `AWS_AVAILABILITY_ZONE`;
   - account assertion: optional `AWS_ACCOUNT_ID`.
3. Leave any unavailable field unknown.

An environment AZ is usable only with an environment Region. The same-AZ tier
also requires `AWS_ACCOUNT_ID`; without it, same-Region preference still
works. In Kubernetes, operators can inject the node topology AZ and Region as
pod environment values without adding synchronized ProxySQL settings.

The EC2 instance identity document and fields are documented by AWS at:

<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html>

Local metadata follows the same refresh and stale policy as backend metadata.
If local Region expires, all locality classifications are neutral. If local
Region remains usable but AZ/account becomes unavailable, same-Region
classification remains possible while same-AZ does not.

## Backend endpoint discovery

### Candidate recognition

Core recognizes official RDS/Aurora endpoint DNS forms only to extract a
candidate AWS Region and partition. This is routing for the API request, not
authoritative metadata.

The implementation normalizes endpoint hostnames by lowercasing ASCII and
removing one trailing DNS dot. It does not resolve DNS or follow CNAMEs.
Supported official suffixes include the standard/GovCloud AWS suffix and the
China partition suffix. An unrecognized endpoint remains neutral.

### Authoritative API matching

Requests are coalesced by candidate Region. The plugin performs paginated:

- `rds:DescribeDBInstances`;
- `rds:DescribeDBClusters`;
- `rds:DescribeDBClusterEndpoints`.

Core accepts a result only when the normalized configured hostname exactly
matches an endpoint returned by the AWS APIs. Where the response supplies a
port, a configured port mismatch is rejected. A custom cluster endpoint that
does not expose a distinct port is matched by its exact authoritative
hostname.

The endpoint mappings are:

- RDS DB instance endpoint: `instance`, with Region, instance AZ, and account;
- Aurora DB instance endpoint: `instance`, with Region, instance AZ, and
  account;
- Aurora or Multi-AZ cluster writer endpoint: `cluster`, with Region and
  account but no stable endpoint AZ;
- Aurora reader endpoint: `reader`, with Region and account but no stable
  endpoint AZ;
- Aurora custom endpoint: `custom`, with Region and account but no stable
  endpoint AZ;
- unmatched or unsupported endpoint: `unknown`.

Cluster, reader, and custom endpoints can route to instances in multiple AZs.
They can receive the same-Region multiplier but never the same-AZ multiplier.

`DescribeDBInstances` exposes both an endpoint address and Availability Zone:

<https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html>

`DescribeDBClusters` exposes cluster, reader, and member information:

<https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusters.html>

`DescribeDBClusterEndpoints` exposes custom and managed cluster endpoints:

<https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusterEndpoints.html>

Custom CNAMEs, RDS Proxy endpoints, arbitrary hosts, and AWS-looking hostnames
that do not appear in an authoritative response stay `unknown`.

## Refresh, sharing, and stale data

Successful metadata records include a monotonic success time and a wall-clock
time for diagnostics. A failed refresh records an attempt time and redacted
error but does not immediately discard the last successful value.

Each hostgroup evaluates freshness using its own policy:

- `fresh`: age is no greater than `refresh_interval_seconds`;
- `stale`: a refresh is due or has failed, but age is no greater than
  `stale_ttl_seconds`; the last successful metadata remains active;
- `expired`: age exceeds `stale_ttl_seconds`; metadata becomes unknown and the
  configured weight is used;
- `error`: no usable successful metadata exists for the endpoint;
- `pending`: discovery has not completed yet;
- `disabled`: the global switch is off.

If several hostgroups reference the same endpoint with different intervals,
the endpoint is refreshed at the shortest active interval. The shared result
retains its success timestamp; each hostgroup independently determines whether
that result is fresh, stale, or expired under its own TTL.

Regional API scans are coalesced so one in-flight scan serves all registered
endpoints in that Region. Repeated load operations cancel or supersede older
generations. Late completions cannot attach to removed servers, removed
policies, or a newer generation.

A successful scan that does not contain a configured endpoint records
`endpoint_not_found`. A prior match may remain active only through its bounded
stale TTL, after which the endpoint becomes neutral.

## Failure behavior and security

Every failure is fail-neutral, not fail-closed for database traffic:

- missing AWS plugin;
- plugin unload or shutdown;
- missing credentials;
- IMDS disabled or unreachable;
- Kubernetes without injected location;
- access denied;
- throttling;
- timeout;
- malformed or unsupported endpoint;
- endpoint not found;
- callback cancellation;
- metadata expiration.

In all cases, the backend remains subject to its ordinary eligibility and
configured weight.

Logs are rate-limited by stable endpoint/Region/error-category keys. They never
include credentials, authorization headers, IMDS tokens, raw AWS errors,
account IDs, or the complete hostgroup JSON. Supported fixed categories
include:

```text
access_denied
throttled
provider_unavailable
imds_unavailable
endpoint_not_found
timeout
cancelled
invalid_response
```

The plugin uses the normal AWS SDK credential provider chain. ProxySQL adds no
access-key or secret-key settings. Expected deployments include EC2 instance
profiles, EKS IRSA or Pod Identity, and externally provided standard AWS
credential sources.

The read-only RDS policy required for backend discovery is:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:DescribeDBClusterEndpoints"
      ],
      "Resource": "*"
    }
  ]
}
```

IMDS and environment discovery require no AWS API permission.

## Observability

The AWS plugin registers `stats_mysql_aws_locality` as a read-only table in the
stats database. Its existence follows the plugin lifecycle:

- when the AWS plugin loads successfully, its schema-registration phase adds
  the table before the Admin databases are materialized;
- when the AWS plugin is not configured or does not load successfully, the
  table is not created, and querying it returns the normal SQLite
  `no such table` error;
- ProxySQL does not currently support hot unloading configured plugins. If hot
  unload is introduced, the unload contract must unregister and drop this
  table rather than leave an empty or stale table behind.

The table is a query-time projection of the MySQL locality manager's current
immutable in-memory snapshot. Before a query that references the table is
executed, Admin invokes the registered refresh callback. The callback replaces
the prior SQLite rows in one transaction from one retained manager snapshot,
so a result never mixes locality generations. This is the same materialized-
on-query model used by other runtime and stats views; the SQLite rows are not
the authoritative locality state.

Refreshing the table never performs an IMDS or AWS API request and never waits
for metadata discovery. Network refresh remains bounded asynchronous plugin
work; a table query reports the most recently published state, including
`pending`, `stale`, `expired`, or `error` as applicable.

The projection is non-persistent: it is not saved to disk, loaded to runtime,
included in ProxySQL Cluster checksums, or accepted as configuration. Writes
to it are unsupported. Each refresh emits one row for each backend in a
hostgroup that currently has a valid locality policy:

```text
hostgroup_id
hostname
port
endpoint_type
configured_weight
effective_weight
local_region
local_az
backend_region
backend_az
account_match
locality
active_multiplier
metadata_status
last_success_timestamp
last_attempt_timestamp
last_error_category
```

Definitions:

- `endpoint_type`: `instance`, `cluster`, `reader`, `custom`, or `unknown`;
- `account_match`: `yes`, `no`, `unknown`, or `not_applicable`;
- `locality`: `same_az`, `same_region`, `remote`, or `unknown`;
- `active_multiplier`: the multiplier currently affecting selection, otherwise
  `1.0`;
- `effective_weight`: a diagnostic calculation only; it is never written back
  to a server table;
- timestamps: Unix epoch seconds, or zero if the event has never occurred;
- `metadata_status`: one of the lifecycle states defined above.

Account IDs are never exposed. When the AWS plugin is loaded but the master
switch is disabled, the table remains present and its rows retain cached
location text for diagnosis. Every row has `active_multiplier` equal to `1.0`,
`effective_weight` equal to `configured_weight`, and `metadata_status` equal
to `disabled`. If no hostgroup currently has a valid locality policy, the
table exists but is empty.

## Runtime sequence

1. ProxySQL loads the AWS plugin and installs its generic metadata provider.
2. `LOAD MYSQL VARIABLES TO RUNTIME` enables the global feature.
3. `LOAD MYSQL SERVERS TO RUNTIME` parses locality policies, advances the core
   registration generation, and schedules local and regional discovery.
4. The AWS plugin performs IMDS and RDS work on bounded background workers.
5. Completions return normalized metadata to the core manager.
6. Core validates request ID and generation, updates timestamps/error state,
   and atomically publishes immutable hostgroup snapshots.
7. Global and local-cache selection attempts retain one snapshot and calculate
   temporary effective weights for eligible server parents.
8. Periodic refreshes repeat at the shortest interval required by registered
   hostgroups. Stale and expiration decisions remain per hostgroup.
9. Disabling the global variable immediately bypasses the snapshot and stops
   scheduling new work.

Until step 6 first succeeds, selection behaves exactly as it did before the
feature.

## Verification strategy

### Configuration and arithmetic unit tests

- valid policy with defaults and explicit timing values;
- missing fields, wrong JSON types, NaN/infinity-equivalent rejection,
  multiplier bounds and ordering;
- timing minimum, maximum, and `refresh <= stale` relationship;
- invalid reload removes prior locality influence;
- `1.0` and `10.0` multiplier boundaries;
- integer truncation, zero weight, non-cumulative tiers, and saturation;
- proof that configured/runtime table weights and checksums do not change.

### Classification and discovery unit tests

- IMDSv2 success and every failure phase;
- environment fallback precedence and partial values;
- missing account, matching account, and cross-account AZ-name collision;
- RDS instance and Aurora instance endpoints;
- cluster writer, reader, and custom endpoints;
- Multi-AZ/failover metadata refresh;
- remote Region and unknown local Region;
- custom CNAME, arbitrary host, unsupported RDS Proxy, and false AWS-looking
  endpoint;
- exact normalized API endpoint match and port validation;
- paginated regional responses and duplicated endpoints across hostgroups;
- fixed/redacted errors without secrets or account IDs.

### Cache and lifecycle unit tests

- pending to fresh, fresh to stale, stale to expired, and recovery transitions
  under a fake clock;
- different refresh/TTL policies sharing one endpoint;
- regional request coalescing and bounded queues;
- configuration reload, server removal, late completion, cancellation, and
  generation rejection;
- provider replacement, plugin stop, core shutdown, and callback lifetime;
- enable, disable, and re-enable behavior;
- missing plugin and provider-unavailable neutral fallback;
- TSan coverage for publication, callbacks, reload, and shutdown.

### Selection tests

- deterministic effective-weight selection for the global Hostgroup Manager
  path;
- deterministic parent-server weighting in the thread-local connection cache;
- proof that multiple cached connections do not amplify a server's weight;
- configured-weight relative ratios within each locality tier;
- no multiplier for unknown or expired metadata;
- cluster/reader/custom endpoints receive only same-Region preference;
- existing health, status, latency, lag, GTID, capacity, and backoff filters win
  before locality;
- no locality-specific allocation, lock, plugin call, DNS, or network operation
  in the hot path;
- current fast path remains in use when the feature is inactive.

### Integration and regression tests

- a fake asynchronous AWS provider drives the real MySQL Hostgroup Manager and
  produces deterministic distributions;
- policy reload affects future selections only;
- `mysql_servers`, `runtime_mysql_servers`, saved configuration, and cluster
  checksums remain byte-for-byte unchanged by discovered metadata;
- `stats_mysql_aws_locality` is absent without the AWS plugin and is registered
  only when that plugin loads successfully;
- each table query projects one consistent in-memory snapshot without issuing
  an IMDS or AWS API request, and projected rows are never persisted or
  clustered;
- exact `stats_mysql_aws_locality` rows for fresh, stale, expired, error, and
  disabled states;
- existing IAM database-authentication behavior continues through the shared
  AWS plugin runtime;
- ASan, TSan, plugin lifecycle, static-linkage, SDK-free daemon, and existing
  IAM/pool selection regressions remain green;
- optional externally provisioned AWS integration verifies one RDS/Aurora
  instance endpoint and one cluster or reader endpoint without becoming a
  normal-CI requirement.

## Acceptance criteria

The feature is complete when all of the following are true:

1. The global switch defaults off and inactive builds preserve the existing
   selection fast paths.
2. No locality operation mutates configured/runtime weights or cluster-visible
   state.
3. Valid hostgroups apply bounded, non-cumulative Region/AZ multipliers only at
   selection time.
4. The global pool and thread-local cache use identical server-level effective
   weight semantics.
5. Instance endpoints can receive same-AZ preference; cluster, reader, and
   custom endpoints cannot.
6. Same-AZ preference requires a confirmed same-account identity.
7. AWS/IMDS work is asynchronous, bounded, cancellable, and absent from the
   hot path.
8. Refresh failure retains last-known metadata only through the configured
   stale TTL, then returns to configured weighting.
9. Missing capability, credentials, permissions, or metadata never prevents a
   database connection solely because locality awareness is enabled.
10. The plugin-conditional, query-refreshed diagnostic table explains every
    active or neutral decision without performing network discovery or
    exposing account IDs or sensitive AWS data.
11. Sanitizer, lifecycle, linkage, existing IAM, and selection regression gates
    pass.
