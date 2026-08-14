# AWS locality-aware MySQL backend selection

ProxySQL 4.0 can prefer Amazon RDS and Aurora MySQL backends in the same AWS
Region or Availability Zone (AZ) as the ProxySQL process. The feature changes
only the temporary weights used by a server-selection attempt. It never
changes `mysql_servers.weight`, `runtime_mysql_servers.weight`, saved
configuration, or ProxySQL Cluster checksums.

The MySQL module owns the switch and hostgroup policy. The optional general
AWS plugin provides local-instance and RDS metadata asynchronously. If the
plugin is not loaded, metadata is unavailable, or metadata expires, ProxySQL
continues using the configured weights.

## Load the AWS plugin

The AWS plugin is built and packaged by `PROXYSQL40=1 make -j`, with the
vendored AWS SDK linked statically into `ProxySQL_Aws_Plugin.so`. It is not
loaded automatically. Add its installed path to the `plugins` list in the
ProxySQL configuration and restart ProxySQL:

```ini
plugins = (
  "/usr/lib/proxysql/ProxySQL_Aws_Plugin.so"
)
```

The plugin also provides [AWS IAM database authentication](aws_iam_database_authentication.md).
Both capabilities share one AWS SDK runtime and the standard AWS credential
provider chain.

## Grant discovery permission

Give the ProxySQL workload read-only access to the RDS discovery APIs:

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

No long-lived access keys are required or recommended. On EC2, attach an
instance profile to the instance running ProxySQL. On EKS, use IRSA or EKS Pod
Identity for the ProxySQL pod. ECS task roles and other standard AWS SDK
credential sources also work. ProxySQL adds no access-key, secret-key, or
role-ARN variables.

IMDSv2 local-location discovery itself needs no IAM API permission. RDS API
discovery uses the workload identity above.

## Configure a hostgroup

First add a locality policy to the existing
`mysql_hostgroup_attributes.hostgroup_settings` JSON. Both multipliers are
required:

```sql
INSERT INTO mysql_hostgroup_attributes(hostgroup_id, hostgroup_settings)
VALUES (10, json_object(
  'aws', json_object(
    'locality_awareness', json_object(
      'same_region_multiplier', 2.0,
      'same_az_multiplier', 4.0,
      'refresh_interval_seconds', 300,
      'stale_ttl_seconds', 1800))))
ON CONFLICT(hostgroup_id) DO UPDATE SET
  hostgroup_settings = json_set(
    COALESCE(mysql_hostgroup_attributes.hostgroup_settings, '{}'),
    '$.aws.locality_awareness',
    json_extract(excluded.hostgroup_settings, '$.aws.locality_awareness'));

LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
```

The accepted values are:

```text
1.0 <= same_region_multiplier <= same_az_multiplier <= 10.0

refresh_interval_seconds default: 300
stale_ttl_seconds default:         1800

30 <= refresh_interval_seconds <= 86400
refresh_interval_seconds <= stale_ttl_seconds <= 604800
```

The multipliers are floating-point JSON numbers. For each selection attempt,
ProxySQL calculates:

```text
remote or unknown          configured_weight
same Region, different AZ  int(configured_weight * same_region_multiplier)
same AZ                    int(configured_weight * same_az_multiplier)
```

Conversion to an integer truncates toward zero. The tiers are not cumulative:
a same-AZ backend gets only the AZ multiplier, not the Region multiplier times
the AZ multiplier. Weight zero stays zero.

An invalid `aws.locality_awareness` object disables locality bias for that
hostgroup when servers are loaded. The diagnostic identifies only the
hostgroup and rejected field; it does not print the JSON value.

## Enable the global switch

The one process-wide control is a MySQL module variable. It defaults off:

```sql
SET mysql-aws_locality_awareness = true;
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```

There are deliberately no ProxySQL Region, AZ, or AWS-account variables.
Every ProxySQL process discovers its own location, so ProxySQL Cluster cannot
copy one node's location to another node in a different Region or AZ.

Disabling the variable immediately restores ordinary configured-weight
selection, cancels or supersedes outstanding locality requests, and stops new
refresh scheduling. It does not remove or rebalance existing connections.

## How local location is determined

ProxySQL tries the EC2 IMDSv2 instance identity document first. If IMDSv2 is
unavailable, the AWS plugin uses these process environment values:

1. Region: `AWS_REGION`, then `AWS_DEFAULT_REGION`;
2. AZ: `AWS_AVAILABILITY_ZONE`;
3. account assertion: `AWS_ACCOUNT_ID`.

Region is the only required fallback field. AZ without Region is ignored. A
same-AZ preference also requires the same confirmed account ID on both sides,
because identical AZ names in different accounts may represent different
physical zones. Without an account assertion, same-Region preference remains
available but same-AZ preference does not.

In Kubernetes, inject the node Region and AZ into each ProxySQL pod from the
node's topology labels and inject the account assertion through deployment
configuration. These are per-pod environment values, not clustered ProxySQL
variables.

## Supported backend endpoints

The first release supports official RDS and Aurora endpoints returned by the
AWS APIs:

- RDS DB instance and Aurora DB instance endpoints can receive Region and AZ
  preference;
- Aurora or Multi-AZ cluster writer endpoints receive Region preference only;
- Aurora reader and custom endpoints receive Region preference only.

Cluster, reader, and custom endpoints can route to several AZs, so they never
receive the same-AZ multiplier. ProxySQL normalizes the configured hostname
and requires an exact match in a paginated RDS API response. Where AWS returns
a port, it must also match.

Custom CNAMEs, arbitrary EC2 MySQL hosts, RDS Proxy endpoints, DNS aliases,
and AWS-looking names absent from the authoritative response remain neutral.
ProxySQL does not resolve CNAMEs, scan all Regions, assume roles into other
accounts, or change hostgroup membership.

## Selection and failure behavior

Locality is applied only after all normal eligibility checks, including
server state, capacity, latency, GTID, replication lag, session compatibility,
and existing backoff rules. It cannot make an unhealthy or incompatible
backend eligible.

The global Hostgroup Manager path and the thread-local idle-connection path
use the same temporary effective server weights. The local cache groups
eligible connections by parent server first, so a server does not gain more
probability merely because it has more idle connections.

Metadata states behave as follows:

- `pending`: discovery has not completed; configured weight is used;
- `fresh`: the active Region or AZ multiplier is used;
- `stale`: the last success remains active through the bounded stale TTL;
- `expired`: configured weight is used;
- `error`: no usable value exists, so configured weight is used;
- `disabled`: the master switch is off and configured weight is used.

A failed refresh does not immediately discard a prior success. Once its
`stale_ttl_seconds` expires, locality becomes neutral. Missing credentials,
access denial, throttling, timeout, missing plugin, unsupported endpoint, and
IMDS failure are all fail-neutral for database traffic.

AWS, IMDS, credential-provider, DNS, and network work runs on bounded plugin
workers. No server-selection path calls the plugin or performs network I/O.

## Inspect locality decisions

When—and only when—the AWS plugin is loaded during startup, it registers the
read-only `stats_mysql_aws_locality` table. Querying it materializes one
current immutable manager snapshot into the stats database:

```sql
SELECT *
FROM stats_mysql_aws_locality
ORDER BY hostgroup_id, hostname, port;
```

The columns are:

```text
hostgroup_id              hostname
port                      endpoint_type
configured_weight         effective_weight
local_region              local_az
backend_region            backend_az
account_match             locality
active_multiplier         metadata_status
last_success_timestamp    last_attempt_timestamp
last_error_category
```

`endpoint_type` is `instance`, `cluster`, `reader`, `custom`, or `unknown`.
`account_match` is `same`, `different`, or `unknown`; account IDs themselves
are never exposed. `locality` is `same_az`, `same_region`, `remote`, or
`unknown`. Timestamps are Unix epoch seconds, or zero if no corresponding
event has occurred.

The table query never starts or waits for metadata discovery. It reports the
latest published state and replaces the previous rows in one transaction, so
generations cannot mix. The table is not persisted, loaded to runtime,
clustered, or included in a checksum. If no hostgroup has a valid policy, it
is empty. If the master switch is off, cached location text remains visible,
but every row reports `disabled`, multiplier `1.0`, and the configured weight
as its effective weight.

Without the AWS plugin, the table is not registered and a query returns the
normal `no such table` error. ProxySQL does not currently hot-unload configured
plugins; changing the plugin list requires a restart.

## Roll back

Set `mysql-aws_locality_awareness` to `false` and load MySQL variables to
runtime. This restores the existing selection path immediately without
changing server rows. To remove a policy as well, remove the
`aws.locality_awareness` object from that hostgroup's `hostgroup_settings` and
load MySQL servers to runtime.
