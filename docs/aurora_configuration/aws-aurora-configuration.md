# AWS Aurora

AWS Aurora is a MySQL compatible proprietary solution developed by AWS for the cloud and differs from MySQL
in several aspects, but for the purpose of this document we will focus only on one aspect: replication. In
Aurora, a writer/master can have multiple replicas: replicas aren't updated using MySQL protocol replication,
but by using a proprietary mechanism developed by AWS, where changes are replicated at the storage layer.
Without going into the technical details, what is important to highlight is that:

- Replication cannot be monitored using queries normally used with MySQL protocol replication like `SHOW SLAVE
  STATUS`.
- Replication is normally in the order of few milliseconds, and rarely above seconds.
- Aurora exports metrics and status using new tables, where it is possible to identify the current
  writer/master, the replicas, and their replication lag.
- Aurora supports auto-provisioning of new replicas, for example in case of the failure of existing replicas.
- Aurora supports automatic-failover.

<!-- -->

ProxySQL counts with an algorithm to monitor the status of AWS Aurora clusters which is able to detect:

- Current topology: Writer/master and replicas
- Failovers
- Replication lag of all the replicas
- Failed replicas
- New replicas - *Enhanced since v2.6.0*

<!-- -->

## Table `mysql_aws_aurora_hostgroups`

In order to monitor AWS Aurora clusters, clusters need to be configured in a new table:
`mysql_aws_aurora_hostgroups`. Table structure:

```
Admin> SHOW CREATE TABLE mysql_aws_aurora_hostgroups\G
*************************** 1. row ***************************
       table: mysql_aws_aurora_hostgroups
Create Table: CREATE TABLE mysql_aws_aurora_hostgroups (
    writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,
    reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0),
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
    aurora_port INT NOT NUlL DEFAULT 3306,
    domain_name VARCHAR NOT NULL CHECK (SUBSTR(domain_name,1,1) = '.'),
    max_lag_ms INT NOT NULL CHECK (max_lag_ms>= 10 AND max_lag_ms <= 600000) DEFAULT 600000,
    check_interval_ms INT NOT NULL CHECK (check_interval_ms >= 100 AND check_interval_ms <= 600000) DEFAULT 1000,
    check_timeout_ms INT NOT NULL CHECK (check_timeout_ms >= 80 AND check_timeout_ms <= 3000) DEFAULT 800,
    writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0,
    new_reader_weight INT CHECK (new_reader_weight >= 0 AND new_reader_weight <=10000000) NOT NULL DEFAULT 1,
    add_lag_ms INT NOT NULL CHECK (add_lag_ms >= 0 AND add_lag_ms <= 600000) DEFAULT 30,
    min_lag_ms INT NOT NULL CHECK (min_lag_ms >= 0 AND min_lag_ms <= 600000) DEFAULT 30,
    lag_num_checks INT NOT NULL CHECK (lag_num_checks >= 1 AND lag_num_checks <= 16) DEFAULT 1,
    comment VARCHAR,
    UNIQUE (reader_hostgroup))
```

Multiple fields define an AWS Aurora Cluster:

- `writer_hostgroup`: The hostgroup that will be assigned to the writer/master. This is also the primary
  key of the table, which means that every `writer_hostgroup` represents a single cluster
- `reader_hostgroup`: The hostgroup that will be assigned to all the replicas in a given cluster. There is
  a `UNIQUE` constraint on this column to ensure that multiple clusters aren't configured with the same
  `reader_hostgroup`.
- `active` allows to toggle the monitoring of a cluster on and off. For example, it is possible to configure a
  cluster but not monitor it (yet).
- `aurora_port`: is the port that Aurora uses to accept connections. All nodes in a cluster use the same port.
  By default this is port 3306, that is the same default port of MySQL.
- `domain_name`: in the AWS Aurora internal table only hostnames are listed. ProxySQL, however, needs the
  fully qualified domain name in `mysql_servers` . When a new server is added in `mysql_servers`, ProxySQL
  will add `domain_name` to the server hostname to obtain the FQDN . For example, if hostname is `serverA` and
  `domain_name` is `.abcde.us-east-1.rds.amazonaws.com` , in `mysql_servers` table the hostname
  `serverA.abcde.us-east-1.rds.amazonaws.com` will be added. Note that `domain_name` **must** start with a
  dot, and table `mysql_aws_aurora_hostgroups` enforces this constraint.
- `max_lag_ms`: replicas that have a replication greater or equal than `max_lag_ms` milliseconds are
  automatically disabled from the cluster until their lag returns below the configured threshold. Also note
  that from empirical results (not documented by AWS) a failed node will have a replication lag of 600000ms,
  that is also the maximum value of `max_lag_ms`: the failed node will be automatically disabled.
- `check_interval_ms`: Defines how frequently ProxySQL's monitor will check the status of the cluster
- `check_timeout_ms`: Defines the timeout for a check.
- `writer_is_also_reader`: This setting defines if writer/master will also be configured as part of the reader
  hostgroup.
- `new_reader_weight`: Weight that will be assigned to new auto-discovered replicas. This takes precedence
  over [servers\_defaults][1] from `mysql_hostgroup_attributes`, yet an entry in `mysql_hostgroup_attributes`
  can still be used for this same purpose.
- `add_lag_ms` , `min_lag_ms` and `lag_num_checks` : Because replication lag is pulled at regular intervals as
  defined in `check_interval_ms` and not in real time, the last measured replication lag could not be
  accurate. These 3 variables perform some tweaks on the last value of replication lag:
    + If replication lag is less than `min_lag_ms`, assume a read of `min_lag_ms`.
    + To any value read, add `add_lag_ms`.
    + If `lag_num_checks` is greater than 1, the current replication lag is computed as the highest of the
      last `lag_num_checks` reads.
- `comment`: Any text that an administrator can assign to an Aurora cluster, for example to note what the
  cluster is used for.

<!-- -->

Following the same convention of other configuration tables, the configuration currently loaded at runtime is
available in table `runtime_mysql_aws_aurora_hostgroups` , that is the *runtime* configuration of
`mysql_aws_aurora_hostgroups` .

## Monitor tables

Monitor module introduces 3 new tables with regards to AWS Aurora:

```
Admin> SHOW TABLES FROM monitor;
+--------------------------------------+
| tables                               |
+--------------------------------------+
| mysql_server_aws_aurora_check_status |
| mysql_server_aws_aurora_failovers    |
| mysql_server_aws_aurora_log          |
...
```

### Table `mysql_server_aws_aurora_log`

```
CREATE TABLE mysql_server_aws_aurora_log (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    time_start_us INT NOT NULL DEFAULT 0,
    success_time_us INT DEFAULT 0,
    error VARCHAR,
    SERVER_ID VARCHAR NOT NULL DEFAULT '',
    SESSION_ID VARCHAR,
    LAST_UPDATE_TIMESTAMP VARCHAR,
    replica_lag_in_milliseconds INT NOT NULL DEFAULT 0,
    estimated_lag_ms INT NOT NULL DEFAULT 0,
    CPU INT NOT NULL DEFAULT 0,
    PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))
```

When an Aurora cluster is enabled, Monitor connects to all the hosts in the cluster (in rotation), querying
one node every `check_interval_ms` milliseconds. Monitor will retrieve cluster information from Aurora table
`information_schema.replica_host_status` . ProxySQL's table `monitor`.`mysql_server_aws_aurora_log` stores
the information retrieved from `information_schema.replica_host_status` (`SERVER_ID`, `SESSION_ID`,
`LAST_UPDATE_TIMESTAMP`, `replica_lag_in_milliseconds`) , together with additional information:

- `hostname`/`port`: The node where the check was performed.
- `time_stamp_us`: When the check was performed.
- `success_time_us`: If the check was successful, how long did it take.
- `error`: If the check was not successful, what was the error message.
- `estimated_lag_ms`: Estimated lag is based on reading `replica_lag_in_milliseconds` and applying configured
  `add_lag_ms` , `min_lag_ms` and `lag_num_checks`.

<!-- -->

Note that ProxySQL determines which one is the writer/master based on `SESSION_ID` : if the value is
`MASTER_SESSION_ID` , the server specific in `SERVER_ID` is the master. All the other servers with
`SESSION_ID` not equal to `MASTER_SESSION_ID` are replicas.

### Table `mysql_server_aws_aurora_check_status`

```
CREATE TABLE mysql_server_aws_aurora_check_status (
    writer_hostgroup INT NOT NULL,
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    last_checked_at VARCHAR,
    checks_tot INT NOT NULL DEFAULT 0,
    checks_ok INT NOT NULL DEFAULT 0,
    last_error VARCHAR,
    PRIMARY KEY (writer_hostgroup, hostname, port))
```

While table `mysql_server_aws_aurora_log` is a log table, table `mysql_server_aws_aurora_check_status`
provides some aggregate information.

- `writer_hostgroup` \+ `hostname` \+ `port` defines a specific server
- `last_checked_at` shows the last time this server was checked
- `checks_tot` counts the number of checks executed against this server
- `checks_ok` counts the number of successful checks
- `last_error` shows the last error returned by this server (if any)

<!-- -->

### Table `mysql_server_aws_aurora_failovers`

```
CREATE TABLE mysql_server_aws_aurora_failovers (
    writer_hostgroup INT NOT NULL,
    hostname VARCHAR NOT NULL,
    inserted_at VARCHAR NOT NULL)
```

This table records all the detected failovers. Every time a failover happens, a new row is inserted into
table `mysql_server_aws_aurora_failovers`:

- `writer_hostgroup` represents the Aurora cluster
- `hostname` shows the newly promoted master
- `inserted_at` is the timestamp of the failover

<!-- -->

## Routing and replication lag

 Since ProxySQL is able to monitor the replication lag of replicas in milliseconds, it is able to determine
 which replicas reads should be sent to, that is the replicas that are up to date within the configured
 thresholds. Most of the configuration is performed in table `mysql_aws_aurora_hostgroups`, specifically on
 columns `max_lag_ms`, `add_lag_ms`, `min_lag_ms`, and `lag_num_checks` . If a query id is configured to be
 sent to a replica, the suitable replicas are determined based on these cluster settings. Furthermore, the
 client is able to specify a more restrictive threshold for `max_lag_ms` sending a comment with setting
 `max_lag_ms` . For example, the Aurora cluster could be configured with
 `mysql_aws_aurora_hostgroups.max_lag_ms=1000` , but a client could send a query like:

```
SELECT /* max_lag_ms=20 */ ...
```

 In this case, only replicas with replication lag less or equal than 20ms will be considered to process the
 query.

#### Hold request when no suitable node is found

 If no replicas are suitable to execute the queries (for example, if none has a lass less than 20ms
 replication lag), ProxySQL is able to hold the requests until it is safe to execute the query. For example,
 if `max_lag_ms` specified by the client is 20, but the replica has a lag of 50ms, ProxySQL can wait 30ms
 before executing the query on the replica.

#### Writer in reader hostgroup

If `mysql_aws_aurora_hostgroups.writer_is_also_reader` is enabled, then the writer is also configured in the
reader hostgroup. This creates some interesting consequences if clients specify a very small value for
`max_lag_ms`. Because the writer always has a lag of 0, ProxySQL may send traffic to it instead of waiting for
replicas to catch up. Similarly, it is possible that a user does not want to use the writer no matter the lag
of the replicas if replicas exist. ProxySQL has a global variable that controls this behavior:
`mysql-aurora_max_lag_ms_only_read_from_replicas`. The variable defines the minimum number of replicas that
need to be present in order to ignore the writer in the reader hostgroup, if the client specifies a value of
`max_lag_ms` in the query it sends.

## Autodiscovery

ProxySQL supports replica autodiscovery for AWS Aurora. This means that ProxySQL is able to retrieve and
configure all *REPLICAS* servers present in the cluster just configuring one of its member, which is assumed
to be the *PRIMARY* instance of the cluster. Since `v2.6.0` this autodicovery also support custom default
values for the discovery severs via `servers_defaults` field from [mysql\_hostgroup\_attributes][1].

### Discovery Procedure

The discovery procedure is performed as part of the regular monitoring operations. ProxySQL is periodically
checking for new `REPLICA` members via `INFORMATION_SCHEMA.REPLICA_HOST_STATUS`. When a new cluster member is
detected:

1. New servers are created using the fetched information, if relevant [mysql\_hostgroup\_attributes][1] are
   found for the target hostgroup of the server, which is assumed to be `reader_hostgroup`, the server will be
   created using this `servers_defaults`, otherwise default values are used.
2. Monitoring thread for the cluster is restarted, targeting the previous and new servers.

Emphasizing the previously stated, the `servers_defaults` used for autodiscovered servers, always assume
`REPLICA` servers are being discovered, which means that the [mysql\_hostgroup\_attributes][1] used are the
ones corresponding to the `reader_hostgroup` configured at
[mysql\_aws\_aurora\_hostgroups](#table-mysql_aws_aurora_hostgroups).

*NOTE*: Every part of this procedure related to [mysql\_hostgroup\_attributes][1] is effective after version
`v2.6.0`. For prior version, the server defaults used for the new discovered replicas were dependent on the
following conventions:

- `max_connections`: Determined by the higher `max_connections` found configured on the other servers present
  in the `reader_hostgroup`. If none is found `10` is set.
- `use_ssl`: By default `0`, but if any other server is found in the `reader_hostgroup` with it enabled, it's
  set to `1`.

### Persistence

The autodiscovered servers are not automatically saved, they take effect as `runtime` configuration. This
means that:

1. If the servers wants to be discarded, issuing `LOAD MYSQL SERVERS TO RUNTIME` will promote the user
   configuration, deleting **any servers** not present in it. Thus, the autodiscovered servers will be
   deleted, if the servers were not present on the configuration but haven't been removed as member of the
   cluster, the autodiscovery process will start again, creating and configuring them again.
2. If the servers wants to be saved, issuing `SAVE MYSQL SERVERS FROM RUNTIME`, will save them to the current
   user configuration. As usual, a subsequent `SAVE MYSQL SERVERS TO DISK` will make the configuration
   persistent.

[1]: https://proxysql.com/main-runtime/#mysql_hostgroup_attributes
