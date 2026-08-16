# AWS locality-aware MySQL backend selection

ProxySQL 4.0 can apply temporary locality multipliers while selecting eligible
Amazon RDS and Aurora MySQL backends. The MySQL module owns the configuration,
policy validation, immutable selection snapshot, and effective-weight
calculation. Locality never changes `mysql_servers.weight`,
`runtime_mysql_servers.weight`, saved configuration, or ProxySQL Cluster
checksums.

Locality metadata is supplied asynchronously by an optional compatible
external provider. Without a provider, or when metadata is unavailable or too
old, selection stays neutral and uses the configured server weights.

## Hostgroup policy

Add `aws.locality_awareness` to the existing
`mysql_hostgroup_attributes.hostgroup_settings` JSON. Both multipliers are
required:

```sql
INSERT INTO mysql_hostgroup_attributes(hostgroup_id, hostgroup_settings)
VALUES (
  10,
  '{
    "aws": {
      "locality_awareness": {
        "same_region_multiplier": 2.0,
        "same_az_multiplier": 4.0,
        "refresh_interval_seconds": 300,
        "stale_ttl_seconds": 1800
      }
    }
  }'
);

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

Multipliers are JSON numbers. An invalid `aws.locality_awareness` object
disables locality bias for that hostgroup when servers are loaded. Diagnostics
identify the rejected field and hostgroup without logging the supplied value.

## Master switch

The process-wide MySQL variable defaults to `false`:

```sql
SET mysql-aws_locality_awareness = true;
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```

Disabling the variable immediately restores configured-weight selection,
cancels or supersedes outstanding locality requests, and stops new refresh
scheduling. It does not change existing backend connections or server rows.

## Selection contract

For each selection attempt, after the normal health, capacity, lag, GTID,
backoff, and session-compatibility checks, ProxySQL calculates:

```text
remote or unknown          configured_weight
same Region, different AZ  int(configured_weight * same_region_multiplier)
same AZ                    int(configured_weight * same_az_multiplier)
```

Conversion to an integer truncates toward zero. The tiers are not cumulative,
and configured weight zero stays zero. Global hostgroup selection and
thread-local idle-connection reuse use the same immutable snapshot and never
perform provider or network work on the selection path.

ProxySQL recognizes eligible RDS and Aurora endpoint shapes to form neutral
metadata requests. A compatible provider is responsible for authoritative
endpoint discovery and normalized Region, Availability Zone, and account
metadata. Custom CNAMEs, arbitrary MySQL hosts, proxy endpoints, malformed
names, and endpoints the provider cannot confirm remain neutral.

## Provider absence and failures

The public provider interface uses retained leases so shutdown rejects new
work, drains active callbacks, joins the locality manager worker, and only then
permits provider destruction and module unload. Provider absence is exposed as
the fixed `provider_unavailable` category.

Metadata states are `pending`, `fresh`, `stale`, `expired`, `error`, and
`disabled`. Only `fresh` and unexpired `stale` values activate a multiplier.
All other states use multiplier `1.0`, so effective weights equal configured
weights. A failed refresh can retain the last successful value through the
bounded stale TTL; it becomes neutral after expiry.

An external provider may register a read-only runtime diagnostics table using
the plugin table/view services and the MySQL-owned projection callback. Public
core does not register `stats_mysql_aws_locality`; without a provider that
registers it, the table does not exist.

## Rollback

Set `mysql-aws_locality_awareness` to `false` and load MySQL variables to
runtime. To remove a policy, delete the `aws.locality_awareness` object from
that hostgroup's `hostgroup_settings`, then load MySQL servers to runtime.
