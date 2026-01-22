# Group Replication Configuration

MySQL Group Replication is a MySQL Server Plugin that enables elastic, highly-available, fault-tolerant
replication topologies. Group Replication guarantees that the database service is continuously available.
Nevertheless, this availability refers to the database service at group level, if one of the members of group
becomes unavailable, routing the traffic to the currently available members is required via some form of
middleware, or by the connector itself. This is where ProxySQL enters the picture.

ProxySQL has had native support for Group Replication since `v1.4.0`. Support received multiple enhancements
in version `v2.5.0`, and native support for MySQL 8.0 since `v2.6.0`. Support for MySQL 8 Group Replication
allows:

- Multiple clusters support, ProxySQL can face and monitor multiple Group replication clusters.
- Seamless failover for `SINGLE|MULTI-PRIMARY` modes.
- Replica `SHUNNING` via replication-lag detection.
- Load distribution for `read-write` and `read-only` traffic.
- Replica `autodiscovery` (Since `v2.6.0`).

## Table `mysql_group_replication_hostgroups`

To enable monitoring for Group Replication clusters, they need to be configured via table
`mysql_group_replication_hostgroups`. Table structure:

```
Admin> show create table mysql_group_replication_hostgroups\G
*************************** 1. row ***************************
table: mysql_group_replication_hostgroups
Create Table: CREATE TABLE mysql_group_replication_hostgroups (
    writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,
    backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL,
    reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0),
    offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0),
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
    max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1,
    writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1,2)) NOT NULL DEFAULT 0,
    max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0,
    comment VARCHAR,
    UNIQUE (reader_hostgroup),
    UNIQUE (offline_hostgroup),
    UNIQUE (backup_writer_hostgroup))
1 row in set (0.00 sec)
```

The fields have the following semantics:

- `writer_hostgroup`: Hostgroup to which all traffic should be sent by default. Nodes that have `read_only=0`
  in MySQL will be assigned to this hostgroup.
- `backup_writer_hostgroup`: Writers (`read_only=0`) exceeding `max_writers` will be assigned to this
  hostgroup.
- `reader_hostgroup`: Hostgroup to which read traffic should be sent to, query rules or a separate read only
  user should be defined to route traffic to this hostgroup. Nodes that have `read_only=1` will be assigned to
  this hostgroup.
- `offline_hostgroup`: Hostgroup for nodes detected as `OFFLINE` or unhealthy.
- `active`: Enables ProxySQL Monitoring of the cluster.
- `max_writers`: Maximum number of nodes that should be allowed in the `writer_hostgroup`, nodes in excess of
  this value will assigned to the `backup_writer_hostgroup`.
- `writer_is_also_reader`: Determines if a node should be added to the `reader_hostgroup` as well as to the
  `writer_hostgroup`. The special value `writer_is_also_reader=2` signals that only the nodes in
  `backup_writer_hostgroup` are also in `reader_hostgroup`, excluding the node(s) in the `writer_hostgroup`.
  See [Servers Placement][9].
- `max_transactions_behind`: Determines the maximum number of transactions behind the writers that ProxySQL
  should allow before shunning the node to prevent stale reads. For more details check section [Max
  Transactions Behind][10].
- `comment`: Text field that can be used for any purpose defined by the user. Could be a description of what
  the cluster stores, a reminder of when the hostgroup was added or disabled, or a JSON processed by some
  checker script.

Following the same convention of other configuration tables, the configuration currently loaded at runtime is
available in table `runtime_mysql_group_replication_hostgroups`, that is the _runtime_ configuration of
`mysql_group_replication_hostgroups` .

### Configuration Steps

As for the other monitoring configuration tables, when a user wants to make use of
[mysql_group_replication_hostgroups][11]. He needs to:

1. Insert an entry into `mysql_group_replication_hostgroups` specifying the hostgroups for the cluster
   servers.
2. Add servers to [mysql_servers][8] table, placing them in the hostgroups configured in
   `mysql_group_replication_hostgroups`.

When configuration is _loaded to runtime_ (via `LOAD MYSQL SERVERS TO RUNTIME`). Group Replication monitoring
will be enabled for any servers placed in those hostgroups.

It's important to notice that the configured servers are not required to be in their final hostgroups when
configured by the users, but it's highly recommended doing so, minizing this way the number of
reconfigurations by ProxySQL required when _loading to runtime_. Otherwise, if an user has placed servers in
their not final hostgroups, for example, the `PRIMARY` as a `REPLICA` in the `reader_hostgroup`, each time the
user issues a _LOAD MYSQL SERVERS TO RUNTIME_ the server needs to be **deleted** by Monitor from the
`reader_hostgroup` and placed into the `writer_hostgroup`, when it's detected than in reality it was a
`PRIMARY`. This is the kind of reconfigurations that could be avoided placing the servers correctly.

### Configuration Example

First we add a new entry into [mysql_group_replication_hostgroups][11]:

```
DELETE FROM mysql_group_replication_hostgroups;
INSERT INTO mysql_group_replication_hostgroups (writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind) VALUES (30,34,31,36,1,1,1,0);
```

Then we add a primary and a replica to [mysql_servers][8] table:

```
DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 30 AND 39;
INSERT INTO mysql_servers (hostgroup_id,hostname,port,comment) VALUES (30,'172.20.0.2',3306,'mysql8-gr1');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,comment) VALUES (31,'172.20.0.3',3306,'mysql8-gr2');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,comment) VALUES (31,'172.20.0.4',3306,'mysql8-gr3');
```

And finally we can optionally set some `servers_defaults`, for replica `autodiscovery`:

```
DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id=31;
INSERT INTO mysql_hostgroup_attributes (hostgroup_id,servers_defaults) VALUES (31, '{"max_connections":500,"use_ssl":1}');
```

Then we just promote our new configuration to runtime, and then save it:

```
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
```

After adding a new replica to our cluster, our `runtime_mysql_servers` table should look like:

```
admin> SELECT * FROM runtime_mysql_servers;
+--------------+------------+------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+------------+
| hostgroup_id | hostname   | port | gtid_port | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms | comment    |
+--------------+------------+------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+------------+
| 30           | 172.20.0.2 | 3306 | 0         | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              | mysql8-gr1 |
| 31           | 172.20.0.2 | 3306 | 0         | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              | mysql8-gr1 |
| 31           | 172.20.0.3 | 3306 | 0         | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              | mysql8-gr2 |
| 31           | 172.20.0.4 | 3306 | 0         | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              | mysql8-gr3 |
| 31           | 172.20.0.5 | 3306 | 0         | ONLINE | 1      | 0           | 500             | 0                   | 1       | 0              |            |
+--------------+------------+------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+------------+
5 rows in set (0.00 sec)
```

## Monitor tables

Monitor module has one table regards to _MySQL Group Replication_:

```
Admin> SHOW TABLES FROM monitor;
+--------------------------------------+
| tables                               |
+--------------------------------------+
...
| mysql_server_group_replication_log   |
...
```

### Table `mysql_server_group_replication_log`

```
admin> SHOW CREATE TABLE monitor.mysql_server_group_replication_log\G
*************************** 1. row ***************************
table: mysql_server_group_replication_log
Create Table: CREATE TABLE mysql_server_group_replication_log (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    time_start_us INT NOT NULL DEFAULT 0,
    success_time_us INT DEFAULT 0,
    viable_candidate VARCHAR NOT NULL DEFAULT 'NO',
    read_only VARCHAR NOT NULL DEFAULT 'YES',
    transactions_behind INT DEFAULT 0,
    error VARCHAR,
    PRIMARY KEY (hostname, port, time_start_us))
1 row in set (0.00 sec)
```

When a _MySQL Group Replication_ cluster is enabled via `mysql_group_replication_hostgroups`, ProxySQL spawns
a monitoring thread in a per-cluster basis. This thread will perform a check on each member of the cluster, at
each monitoring interval, querying the following information:

- `viable_candidate`: If the server is considered a viable cluster member candidate, this means, that ProxySQL
  is sure that the server is a rightful member of the cluster, and that's `MEMBER_STATUS` is `ONLINE`. If a
  server isn't considered a viable candidate, it's placed in the `offline_hostgroup`.
- `read_only`: Status of the `READ_ONLY` flag in the instance. A server set in `READ_ONLY` mode, is placed in
  the `reader_hostgroup` defined in `mysql_group_replication_hostgroups`.
- `transactions_behind`: Number of transactions the instance is lagging behind the `PRIMARY`. If a server is
  lagging behind the user defined threshold, the server is set as `SHUNNED`. This state, will prevent the
  server for receiving new queries until replication catches up. For more details see [Max Transactions
  Behind][10].

For extra details about the previous fields check [Infra Setup: Monitoring Data Source][12] section. The table
also provide additional fields, with information about the check operation itself:

- `hostname`/`port`: The node where the check was performed.
- `time_start_us` : When the check was started.
- `success_time_us` : If the check was successful, how long did it take.
- `error`: If the check was not successful, what was the error message.

An example output of the contents of the table:

```
admin> SELECT * FROM monitor.mysql_server_group_replication_log ORDER BY time_start_us LIMIT 4;
+------------+------+------------------+-----------------+------------------+-----------+---------------------+-------+
| hostname   | port | time_start_us    | success_time_us | viable_candidate | read_only | transactions_behind | error |
+------------+------+------------------+-----------------+------------------+-----------+---------------------+-------+
| 172.20.0.2 | 3306 | 1691393274560275 | 1325            | YES              | NO        | 0                   | NULL  |
| 172.20.0.5 | 3306 | 1691393274560776 | 1208            | YES              | NO        | 0                   | NULL  |
| 172.20.0.4 | 3306 | 1691393274560997 | 1252            | YES              | NO        | 0                   | NULL  |
| 172.20.0.3 | 3306 | 1691393274561216 | 1427            | YES              | NO        | 0                   | NULL  |
+------------+------+------------------+-----------------+------------------+-----------+---------------------+-------+
4 rows in set (0.01 sec)
```

## Monitoring Actions

Actions over the servers are overall of two different kinds:

- Servers placement in hostgroups.
- Changes in servers status.

There multiple factors that ProxySQL takes into account for performing these actions. Next sections elaborate
on them.

### Servers Placement

Server placement behavior is always the same for `offline_hostgroup` and `writer_hostgroup`.

#### writer_is_also_reader=0 (Default)

By default, servers are assigned to hostgroups in the following way:

- `writer_hostgroup`: Servers with `read_only=0`, until `max_writers` is reached.
- `backup_writer_hostgroup`: Writers exceeding `max_writers`.
- `reader_hostgroup`: Servers with `read_only=1`.
- `offline_hostgroup`: Hostgroup for nodes detected as `OFFLINE` or unhealthy.

ProxySQL considers that servers are `OFFLINE` or unhealthy when:

- A monitor check has failed with other error than `timeout`.
- Server check reported the node to be `viable_candidate='NO'`.

In both of these cases, ProxySQL will move the server to the `offline_hostgroup`, killing all current
connections to it. If the server is later recovered, a monitoring action will accordingly move it again to the
required information obtained in the monitor check.

#### writer_is_also_reader=1

Writers are now considered as viable readers:

- `writer_hostgroup`: Servers with `read_only=0`, until `max_writers` is reached.
- `backup_writer_hostgroup`: Writers exceeding `max_writers`.
- `reader_hostgroup`: Servers with `read_only=1` and `read_only=0`.

#### writer_is_also_reader=2

Backup writers are now considered viable readers:

- `writer_hostgroup`: Servers with `read_only=0`, until `max_writers` is reached.
- `backup_writer_hostgroup`: Writers exceeding `max_writers`.
- `reader_hostgroup`: Servers with `read_only=1` and servers present in `backup_writer_hostgroup`.

### Servers Status Change: SHUNNING

The `SHUNNED` state is a transitory state that ProxySQL applies for servers that appeart to be overwelmed or
temporarly unavailable. When a server is placed in this state, no new connections will be created, or queries
issued to it, until the state is reverted by ProxySQL. A common cause for a server to be `SHUNNED` is having
too many connections errors in a short period of time, see [mysql-connect_retries_on_failure][3] and
[mysql-shun_on_failures][4].

#### Max Transactions Behind

In addition to this common behavior, monitoring for Group Replication offers the previously described
`max_transactions_behind` configuration field. This setting works in combination with the following global
configuration variables:

- [mysql-monitor_groupreplication_max_transactions_behind_count][1]
- [mysql-monitor_groupreplication_max_transactions_behind_for_read_only][2]

Together they determine when a server that is lagging should be set as `SHUNNED`. Since version `v2.3.0`,
`SHUNNING` is performed in two stages, with the purpose of giving the server an extra grace period to recover:

1. Server is flagged as `SHUNNED` after exceeding `max_transactions_behind_count`.
2. If the server doesn't recover, but exceeds `max_transactions_behind_count * 2`, the server is flagged as
   `SHUNNED_REPLICATION_LAG`, and all its connections are terminated.

## Routing

As for other ProxySQL monitoring modes, ProxySQL performs the placement of the servers in one of the
hostgroups defined by the configuration in `mysql_group_replication_hostgroups`. This means, that your desired
routing will be a combination of the servers placement in these hostgroups, and the `mysql_query_rules` that
you apply. See [mysql_query_rules][6].

As detailed in section [Max Transactions Behind][10], ProxySQL wont perform any hostgroup movements based on
replication lag, only server `SHUNNING`, thus as in other monitoring modes, routing is only affected by
replication lag at hostgroup level, i.e. servers within the target hostgroup marked as `SHUNNED` will be
omitted during server selection.

## Autodiscovery

Since `v2.6.0` ProxySQL supports replica autodiscovery for Group Replication. This means that ProxySQL is able
to retrieve and configure all _REPLICAS_ servers present in the cluster just configuring one of its member,
which is assumed to be the _PRIMARY_ instance of the cluster. This autodicovery also support custom default
values for the discovery severs via `servers_defaults` field from [mysql_hostgroup_attributes][7].

This autodiscovery is not limited to _REPLICAS_ but operates under this assumption, this may be relevant for
user defined defaults, for more information check section [Discovery Procedure][13].

### Discovery Procedure

The discovery procedure is performed as part of the regular monitoring operations. ProxySQL is periodically
checking for new cluster members via `performance_schema.replication_group_members`, the retrieved information
is only valid if the server is considered a `viable_candidate`. When a new cluster member is detected:

1. New servers are created using the fetched information, if relevant [mysql_hostgroup_attributes][7] are
   found for the target hostgroup of the server, which is assumed to be `reader_hostgroup`, the server will be
   created using this `servers_defaults`, otherwise default values are used.
2. Monitoring thread for the cluster is restarted, targeting the previous and new servers.

Emphasizing the previously stated, the `servers_defaults` used for autodiscovered servers, always assume
`REPLICA` servers are being discovered, which means that the [mysql_hostgroup_attributes][7] used are the ones
corresponding to the `reader_hostgroup` configured at [mysql_group_replication_hostgroups][11].

### Persistence

The autodiscovered servers are not automatically saved, they take effect as `runtime` configuration. This
means that:

1. If the servers wants to be discarded, issuing `LOAD MYSQL SERVERS TO RUNTIME` will promote the user
   configuration, deleting **any servers** not present in it. Thus, the autodiscovered servers will be
   deleted, if the servers were not present on the configuration but haven't been removed as member of the
   cluster, the autodiscovery process will start again, creating and configuring them again.
2. If the servers wants to be saved, issuing `SAVE MYSQL SERVERS FROM RUNTIME`, will save them to the current
   user configuration. As usual a subsequent `SAVE MYSQL SERVERS TO DISK` will make the configuration
   persistent.

## Infra Setup: Monitoring Data Source

For older ProxySQL and MySQL versions, ProxySQL relies on table view `sys.gr_member_routing_candidate_status`,
[reference implementation here][14]. This is only required now when monitoring MySQL versions older than
`8.0`. For newer versions, this table **isn't required**. The information that ProxySQL fetches from the
backend, and requires for monitoring is the following:

**`viable_candidate`**:

Wether if the server can be considered a rightful member of the cluster. This check ensures that:

1. Member state is `ONLINE`.
2. Member is part of the _primary cluster partition_, this prevent routing traffic to servers in split-brain
   scenarios.

Both the view and post `v2.5.0` implementation for MySQL 8.0 ensure this.

**`read_only`**:

Status of the `READ_ONLY` flag on the instance.

**`transactions_behind`**:

The number of transactions that are currently waiting in the `applier queue`. Is obtained differently
depending on ProxySQL and MySQL backend versions:

- In pre `v2.5.0` version for `MySQL 5.7` this is obtained via [gr_applier_queue_length][14] function.
- In post `v2.5.0` implementation for `MySQL 8.0`, this is directly obtained from
  `replication_group_member_stats` table. See [COUNT_TRANSACTIONS_REMOTE_APPLIED][3] documentation.

## Reference Implementation: 'sys.gr_member_routing_candidate_status'

Please notice that this table is **no longer required** when using for MySQL versions after `8.0`. This is for
**exclusive use of legacy versions** prior to `8.0`:

```
USE sys;

DELIMITER $$

CREATE FUNCTION IFZERO(a INT, b INT)
RETURNS INT DETERMINISTIC
RETURN IF(a = 0, b, a)$$

CREATE FUNCTION LOCATE2(needle TEXT(10000), haystack TEXT(10000), offset INT)
RETURNS INT DETERMINISTIC
RETURN IFZERO(LOCATE(needle, haystack, offset), LENGTH(haystack) + 1)$$

CREATE FUNCTION GTID_NORMALIZE(g TEXT(10000))
RETURNS TEXT(10000) DETERMINISTIC
RETURN GTID_SUBTRACT(g, '')$$

CREATE FUNCTION GTID_COUNT(gtid_set TEXT(10000))
RETURNS INT DETERMINISTIC
BEGIN
  DECLARE result BIGINT DEFAULT 0;
  DECLARE colon_pos INT;
  DECLARE next_dash_pos INT;
  DECLARE next_colon_pos INT;
  DECLARE next_comma_pos INT;
  SET gtid_set = GTID_NORMALIZE(gtid_set);
  SET colon_pos = LOCATE2(':', gtid_set, 1);

  WHILE colon_pos != LENGTH(gtid_set) + 1 DO
     SET next_dash_pos = LOCATE2('-', gtid_set, colon_pos + 1);
     SET next_colon_pos = LOCATE2(':', gtid_set, colon_pos + 1);
     SET next_comma_pos = LOCATE2(',', gtid_set, colon_pos + 1);

     IF next_dash_pos < next_colon_pos AND next_dash_pos < next_comma_pos THEN
       SET result = result +
         SUBSTR(gtid_set, next_dash_pos + 1,
                LEAST(next_colon_pos, next_comma_pos) - (next_dash_pos + 1)) -
         SUBSTR(gtid_set, colon_pos + 1, next_dash_pos - (colon_pos + 1)) + 1;
     ELSE
       SET result = result + 1;
     END IF;

     SET colon_pos = next_colon_pos;
  END WHILE;
  RETURN result;
END$$

CREATE FUNCTION gr_applier_queue_length() RETURNS INT DETERMINISTIC
BEGIN
  RETURN (
    SELECT
      sys.gtid_count (
        GTID_SUBTRACT(
          (
            SELECT Received_transaction_set
            FROM performance_schema.replication_connection_status
            WHERE Channel_name='group_replication_applier'
          ),
          (SELECT @@global.GTID_EXECUTED)
        )
      )
  );
END$$

CREATE FUNCTION gr_member_in_primary_partition() RETURNS VARCHAR(3) DETERMINISTIC
BEGIN
  RETURN (
    SELECT
      IF(
        MEMBER_STATE = 'ONLINE'
        AND (
          (
            SELECT COUNT(*)
            FROM performance_schema.replication_group_members
            WHERE MEMBER_STATE != 'ONLINE'
          ) >= (
            (
              SELECT COUNT(*)
              FROM performance_schema.replication_group_members
            ) / 2
          ) = 0
        ),
        'YES',
        'NO'
      )
    FROM
      performance_schema.replication_group_members
      JOIN performance_schema.replication_group_member_stats rgms USING (member_id)
    WHERE
      rgms.MEMBER_ID=@@SERVER_UUID
  );
END$$

CREATE FUNCTION gr_transactions_to_cert() RETURNS INT DETERMINISTIC
RETURN (
    SELECT count_transactions_in_queue
    FROM performance_schema.replication_group_member_stats
    WHERE MEMBER_ID=@@SERVER_UUID
);$$

CREATE VIEW
  gr_member_routing_candidate_status AS
SELECT
  sys.gr_member_in_primary_partition() as viable_candidate,
  IF(
    (
      SELECT
        (
          SELECT GROUP_CONCAT(variable_value)
          FROM performance_schema.global_variables
          WHERE variable_name IN ('read_only', 'super_read_only')
        ) != 'OFF,OFF'
    ),
    'YES',
    'NO'
  ) as read_only,
  sys.gr_applier_queue_length() as transactions_behind,
  sys.gr_transactions_to_cert() as transactions_to_cert;$$

DELIMITER ;
```

[1]: https://proxysql.com/documentation/global-variables/mysql-monitor-variables/#mysql-monitor_groupreplication_max_transactions_behind_count
[2]: https://proxysql.com/documentation/global-variables/mysql-monitor-variables/#mysql-monitor_groupreplication_max_transactions_behind_for_read_only
[3]: https://dev.mysql.com/doc/refman/8.0/en/performance-schema-replication-group-member-stats-table.html
[4]: https://proxysql.com/documentation/global-variables/mysql-variables/#mysql-connect_retries_on_failure
[5]: https://proxysql.com/documentation/global-variables/mysql-variables/#mysql-shun_on_failures
[6]: https://proxysql.com/documentation/main-runtime/#mysql_query_rules
[7]: https://proxysql.com/documentation/main-runtime/#mysql_hostgroup_attributes
[8]: https://proxysql.com/documentation/main-runtime/#mysql_servers
[9]: #servers-placement
[10]: #max-transactions-behind
[11]: #table-mysql_group_replication_hostgroups
[12]: #infra-setup-monitoring-data-source
[13]: #discovery-procedure
[14]: #reference-implementation-sysgr_member_routing_candidate_status
