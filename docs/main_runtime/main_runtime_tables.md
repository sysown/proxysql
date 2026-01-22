# Introduction

ProxySQL's Admin stores configuration in tables. If you connect to Admin using [admin-admin_credentials][1]
credentials, you should be able to see a list of configuration and runtime tables like the following. The
exact list of tables may vary depending from the version in use, and if certain modules of ProxySQL are
operating.

```mysql
Admin> SHOW TABLES FROM main;
+----------------------------------------------------+
| tables                                             |
+----------------------------------------------------+
| clickhouse_users                                   |
| coredump_filters                                   |
| debug_filters                                      |
| debug_levels                                       |
| global_variables                                   |
| mysql_aws_aurora_hostgroups                        |
| mysql_collations                                   |
| mysql_firewall_whitelist_rules                     |
| mysql_firewall_whitelist_sqli_fingerprints         |
| mysql_firewall_whitelist_users                     |
| mysql_galera_hostgroups                            |
| mysql_group_replication_hostgroups                 |
| mysql_hostgroup_attributes                         |
| mysql_query_rules                                  |
| mysql_query_rules_fast_routing                     |
| mysql_replication_hostgroups                       |
| mysql_servers                                      |
| mysql_servers_ssl_params                           |
| mysql_users                                        |
| pgsql_firewall_whitelist_rules                     |
| pgsql_firewall_whitelist_sqli_fingerprints         |
| pgsql_firewall_whitelist_users                     |
| pgsql_hostgroup_attributes                         |
| pgsql_ldap_mapping                                 |
| pgsql_query_rules                                  |
| pgsql_query_rules_fast_routing                     |
| pgsql_replication_hostgroups                       |
| pgsql_servers                                      |
| pgsql_users                                        |
| proxysql_servers                                   |
| restapi_routes                                     |
| runtime_checksums_values                           |
| runtime_clickhouse_users                           |
| runtime_coredump_filters                           |
| runtime_global_variables                           |
| runtime_mysql_aws_aurora_hostgroups                |
| runtime_mysql_firewall_whitelist_rules             |
| runtime_mysql_firewall_whitelist_sqli_fingerprints |
| runtime_mysql_firewall_whitelist_users             |
| runtime_mysql_galera_hostgroups                    |
| runtime_mysql_group_replication_hostgroups         |
| runtime_mysql_hostgroup_attributes                 |
| runtime_mysql_query_rules                          |
| runtime_mysql_query_rules_fast_routing             |
| runtime_mysql_replication_hostgroups               |
| runtime_mysql_servers                              |
| runtime_mysql_servers_ssl_params                   |
| runtime_mysql_users                                |
| runtime_pgsql_firewall_whitelist_rules             |
| runtime_pgsql_firewall_whitelist_sqli_fingerprints |
| runtime_pgsql_firewall_whitelist_users             |
| runtime_pgsql_hostgroup_attributes                 |
| runtime_pgsql_ldap_mapping                         |
| runtime_pgsql_query_rules                          |
| runtime_pgsql_query_rules_fast_routing             |
| runtime_pgsql_replication_hostgroups               |
| runtime_pgsql_servers                              |
| runtime_pgsql_users                                |
| runtime_proxysql_servers                           |
| runtime_restapi_routes                             |
| runtime_scheduler                                  |
| scheduler                                          |
+----------------------------------------------------+
62 rows in set (0.03 sec)
```

In the following sections you will find a detailed description of all the configuration tables.

# Key Configuration Tables

<!-- remark-ignore-start -->

| Tablename                                                                   | Configures                                                    |
| --------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [mysql_users](#mysql_users)                                                 | Frontend and Backend MySQL Users                              |
| [mysql_servers](#mysql_servers)                                             | Backend MySQL Servers                                         |
| [mysql_servers_ssl_params](#mysql_servers_ssl_params)                       | Backend MySQL Server specific SSL Parameters                  |
| [mysql_galera_hostgroups](#mysql_galera_hostgroups)                         | MySQL clusters using Galera replication                       |
| [mysql_group_replication_hostgroups](#mysql_group_replication_hostgroups)   | MySQL clusters using Group Replication                        |
| [mysql_hostgroup_attributes](#mysql_hostgroup_attributes)                   | Hostgroup-specific attributes that override global settings   |
| [mysql_replication_hostgroups](#mysql_replication_hostgroups)               | MySQL replication clusters with servers in RW or RO mode      |
| [mysql_query_rules](#mysql_query_rules)                                     | Query Rules for MySQL traffic                                 |
| [mysql_query_rules_fast_routing](#mysql_query_rules_fast_routing)           | Query Rules for MySQL traffic specialized in routing          |
| [global_variables](#global_variables)                                       | All variables                                                 |
| [scheduler](#scheduler)                                                     | Tasks that the Scheduler can executes                         |
| [mysql_collations](#mysql_collations)                                       | Known MySQL charsets and collations                           |
| [proxysql_servers](/proxysql-cluster/#table_proxysql_servers) | List of core nodes in ProxySQL Cluster                        |
| [restapi_routes](#restapi_routes)                                           | RESTAPI endpoints                                             |
| [pgsql_users](#pgsql_users)                                                 | Frontend and Backend PostgreSQL Users                         |
| [pgsql_servers](#pgsql_servers)                                             | Backend PostgreSQL Servers                                    |
| [pgsql_replication_hostgroups](#pgsql_replication_hostgroups)               | PostgreSQL replication clusters with servers in RW or RO mode |
| [pgsql_query_rules](#pgsql_query_rules)                                     | Query Rules for PostgreSQL traffic                            |
| [pgsql_query_rules_fast_routing](#pgsql_query_rules_fast_routing)           | Query Rules for PostgreSQL traffic specialized in routing     |
| [pgsql_hostgroup_attributes](#pgsql_hostgroup_attributes)                   | Hostgroup-specific attributes that override global settings   |

<!-- remark-ignore-end -->

### mysql_servers

Table `mysql_servers` defines all the backend servers that are either MySQL servers or using the MySQL
Protocol (for example, another ProxySQL instance). Servers are grouped into hostgroups, where a hostgroup is a
set of servers that have the same logical functionality. Table `mysql_servers` is defined as following:

```mysql
Admin> SHOW CREATE TABLE mysql_servers\G
*************************** 1. row ***************************
       table: mysql_servers
Create Table: CREATE TABLE mysql_servers (
    hostgroup_id INT CHECK (hostgroup_id>=0) NOT NULL DEFAULT 0,
    hostname VARCHAR NOT NULL,
    port INT CHECK (port >= 0 AND port <= 65535) NOT NULL DEFAULT 3306,
    gtid_port INT CHECK ((gtid_port <> port OR gtid_port=0) AND gtid_port >= 0 AND gtid_port <= 65535) NOT NULL DEFAULT 0,
    status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE',
    weight INT CHECK (weight >= 0 AND weight <=10000000) NOT NULL DEFAULT 1,
    compression INT CHECK (compression IN(0,1)) NOT NULL DEFAULT 0,
    max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000,
    max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0,
    use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0,
    max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0,
    comment VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (hostgroup_id, hostname, port) )
1 row in set (0.01 sec)
```

The fields have the following semantics:

- **hostgroup_id**: the hostgroup in which this backend server is included. Notice that the same instance can
  be part of more than one hostgroup

- **hostname**, **port**: the TCP endpoint at which the backend server can be reached. If `port` is 0, the
  value in `hostname` is interpreted as a Unix Socket file

- **gtid_port**: the backend server port where ProxySQL Binlog Reader listens on for GTID tracking

- **status**: the **configured** of the backend. This does not represent the **current** status, but the
  **configured** one:

  - **ONLINE** - backend server is fully operational
  - **SHUNNED** - backend sever is temporarily taken out of use because of either too many connection errors
    in a time that was too short, or the replication lag exceeded the allowed threshold
  - **OFFLINE_SOFT** - when a server is put into OFFLINE_SOFT mode, no new connections are created toward that
    server, while the existing connections are kept until they are returned to the connection pool or
    destructed. In other words, connections are kept in use until multiplexing is enabled again, for example
    when a transaction is completed. This makes it possible to gracefully detach a backend as long as
    multiplexing is efficient
  - **OFFLINE_HARD** - when a server is put into OFFLINE_HARD mode, no new connections are created toward that
    server and the existing **free** connections are **immediately dropped**, while backend connections
    currently associated with a client session are dropped as soon as the client tries to use them. This is
    equivalent to deleting the server from a hostgroup. Internally, setting a server in OFFLINE_HARD status is
    equivalent to deleting the server

    <!-- -->

- **weight** - the bigger the weight of a server relative to other weights, the higher the probability of the
  server to be chosen from a hostgroup. ProxySQL default load-balancing algorithm is random-weighted

- **compression** - if the value is 1, new connections to that server will use compression. Please note that
  frontend and backend connections do not need to either both use compression or not. Each frontend connection
  can use or not use compression no matter if the backend connection is using or not using compression

- **max_connections** - the maximum number of connections ProxySQL will open to this backend server. Even
  though this server will have the highest weight, no new connections will be opened to it once this limit is
  hit. Please ensure that the backend is configured with a correct value of max_connections to avoid ProxySQL
  trying to go beyond that limit. Furthermore, one of the main features of ProxySQL is multiplexing (the
  ability to use the same backend connection for multiple frontend connections): if efficient, max_connections
  per backend can be configured to a very small value.

- **max_replication_lag** - if greater than 0, ProxySQL will regularly monitor replication lag and if it goes
  beyond the configured threshold it will temporary shun the host until replication catches up

- **use_ssl** - if set to 1, connections to the backend will use SSL. Please note that frontend and backend
  connections do not need to either both use TLS or not. Each frontend connection can use or not use TLS no
  matter if the backend connection is using or not using TLS

- **max_latency_ms** - ping time is regularly monitored. If a host has a ping time greater than
  `max_latency_ms` it is excluded from the connection pool (although the server stays _ONLINE_)

- **comment** - text field that can be used for any purpose defined by the user. Could be a description of
  what the host stores, a reminder of when the host was added or disabled, or a JSON processed by some
  external script.

<!-- -->

_Note:_ in order for a SHUNNED node to be recognized as ONLINE again, it is not enough that the node is
reachable (responding to a ping) - the node is brought back ONLINE only if there is also activity in the
connection pool for the specific hostgroup in which the node is configured.

### mysql_servers_ssl_params

Table `mysql_servers_ssl_params` was introduced in ProxySQL 2.6. Table `mysql_servers_ssl_params` defines SSL
parameters that are specific for each backend MySQL server. The table is defined as following:

```mysql
Admin>SHOW CREATE TABLE mysql_servers_ssl_params\G
*************************** 1. row ***************************
       table: mysql_servers_ssl_params
Create Table: CREATE TABLE mysql_servers_ssl_params (
    hostname VARCHAR NOT NULL,
    port INT CHECK (port >= 0 AND port <= 65535) NOT NULL DEFAULT 3306,
    username VARCHAR NOT NULL DEFAULT '',
    ssl_ca VARCHAR NOT NULL DEFAULT '',
    ssl_cert VARCHAR NOT NULL DEFAULT '',
    ssl_key VARCHAR NOT NULL DEFAULT '',
    ssl_capath VARCHAR NOT NULL DEFAULT '',
    ssl_crl VARCHAR NOT NULL DEFAULT '',
    ssl_crlpath VARCHAR NOT NULL DEFAULT '',
    ssl_cipher VARCHAR NOT NULL DEFAULT '',
    tls_version VARCHAR NOT NULL DEFAULT '',
    comment VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (hostname, port, username) )
1 row in set (0.01 sec)
```

The fields have the following semantics:

- **hostname**, **port**: the TCP endpoint at which the backend server can be reached. If `port` is 0, the
  value in `hostname` is interpreted as a Unix Socket file
- **username**: if not empty, this configuration row applies only for backend connections using the specific
  `username`
- **ssl_ca**: The path name of the Certificate Authority (CA) certificate file
- **ssl_cert**: The path name of the client public key certificate file.
- **ssl_key**: The path name of the client private key file
- **ssl_capath**: The path name of a directory of CA certificate files
- **ssl_crl**: The path name of the file containing certificate revocation lists
- **ssl_crlpath**: The path name of a directory of certificate revocation-list files
- **ssl_cipher**: currently unused
- **tls_version**: currently unused
- **comment**: free format comment, not a parameter for connection

<!-- -->

When creating a new MySQL backend connection , if `mysql_servers.use_ssl` is set to 1 then an SSL connection
is established. Before establishing an SSL connection to the backend, ProxySQL will verify if the backend is
configured in `mysql_servers_ssl_params` , and if so it will use the settings specified in the table
`mysql_servers_ssl_params`. To be more specific, up to two lookups against `mysql_servers_ssl_params` can be
performed:

- lookup for hostname + port + username . If not present:
- lookup for hostname + port

<!-- -->

If the above lookups return any result, then the SSL parameters specified in `mysql_servers_ssl_params` will
be used. If the above lookups do not return any result, then the default SSL parameters will be used:

<!-- remark-ignore-start -->

- [mysql-ssl_p2s_ca](/global-variables/mysql-variables/#mysql-ssl_p2s_ca)
- [mysql-ssl_p2s_capath](/global-variables/mysql-variables/#mysql-ssl_p2s_capath)
- [mysql-ssl_p2s_cert](/global-variables/mysql-variables/#mysql-ssl_p2s_cert)
- [mysql-ssl_p2s_key](/global-variables/mysql-variables/#mysql-ssl_p2s_key)
- [mysql-ssl_p2s_crl](/global-variables/mysql-variables/#mysql-ssl_p2s_crl)
- [mysql-ssl_p2s_crlpath](/global-variables/mysql-variables/#mysql-ssl_p2s_crlpath)

<!-- remark-ignore-end -->

Note that most of the columns/settings accept an empty string as value: in that case, the specific setting is
not used when establishing an SSL connection. The configuration in table `mysql_servers_ssl_params` belongs to
the "MYSQL SERVERS" module, therefore it is:

- Loaded to runtime using `LOAD MYSQL SERVERS TO RUNTIME` or equivalent command
- Saved to disk using `SAVE MYSQL SERVERS TO DISK` or equivalent command
- Automatically replicated in ProxySQL Cluster as part of the synchronization of `mysql_servers` module. Note:
  only the rows in table `mysql_servers_ssl_params` are synchronized, and the actually files are **not
  copied** (they must be already present in the system)

<!-- -->

Trying to create a new connection to the backend will fail if ProxySQL is not able to open the file(s)
specified in `mysql_servers_ssl_params`. The most common reasons for failure are:

- Not existing file
- Incorrect path
- Wrong permission
- Invalid certificate

<!-- -->

### mysql_replication_hostgroups

Table `mysql_replication_hostgroups` defines replication hostgroups for use with traditional master / slave
ASYNC or SEMI-SYNC replication. In case Group Replication / InnoDB Cluster or Galera / Percona XtraDB Cluster
is used for replication the `mysql_group_replication_hostgroups` or `mysql_galera_hostgroups` (available in
version 2.x) should be used instead.

```mysql
Admin> SHOW CREATE TABLE mysql_replication_hostgroups\G
*************************** 1. row ***************************
       table: mysql_replication_hostgroups
Create Table: CREATE TABLE mysql_replication_hostgroups (
    writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,
    reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0),
    check_type VARCHAR CHECK (LOWER(check_type) IN ('read_only','innodb_read_only','super_read_only','read_only|innodb_read_only','read_only&innodb_read_only')) NOT NULL DEFAULT 'read_only',
    comment VARCHAR,
    UNIQUE (reader_hostgroup))
1 row in set (0.00 sec)
```

Each row in mysql_replication_hostgroups represents a pair of `writer_hostgroup` and `reader_hostgroup`.
ProxySQL will monitor the variable(s) specified in `check_type` for all the servers in specified hostgroups,
and based on the value of the variable (or binary operation on 2 variable) it will assign the server to the
writer or reader hostgroups. The field `comment` can be used to store any arbitrary data. The fields have the
following semantics:

- `writer_hostgroup` - the hostgroup where writers are configured. Nodes that have a read only check returning
  0 will be assigned to this hostgroup.
- `reader_hostgroup` - the hostgroup where readers are configured. Read traffic should be sent to this
  hostgroup, assuming query rules or a separate read only user is defined to route traffic to this hostgroup.
  Nodes that have a read only check returning 1 will be assigned to this hostgroup. Please note, however, that
  these nodes **might** **not be the only ones** assigned to this hostgroup. Regarding this behavior, see also
  the monitor variable [mysql-monitor_writer_is_also_reader][2] .
- `check_type` - the MySQL variable(s) checked when executing a Read Only check, and optionally the logical
  binary operation. `read_only` is the default. `innodb_read_only` and `super_read_only` can be used as well.
  Before the introduction of Native Support for AWS Aurora, `innodb_read_only` should be used. Checks on
  `read_only` and `innodb_read_only` can be combined
- `comment` - text field that can be used for any purpose defined by the user. Could be a description of what
  the cluster stores, a reminder of when the hostgroup was added or disabled, or a JSON processed by some
  checker script.

<!-- -->

### mysql_group_replication_hostgroups

Table `mysql_group_replication_hostgroups` defines hostgroups for use with Oracle Group Replication / InnoDB
Cluster

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

- `writer_hostgroup` - the hostgroup that all traffic will be sent to by default. Nodes that have
  `read_only=0` in MySQL will be assigned to this hostgroup.
- `backup_writer_hostgroup` - if the cluster has multiple nodes with `read_only=0` that exceed `max_writers`,
  ProxySQL will put the additional nodes (in excess of `max_writes`) in the `backup_writer_hostgroup`.
- `reader_hostgroup` - the hostgroup that read traffic should be sent to, query rules or a separate read only
  user should be defined to route traffic to this hostgroup. Nodes that have `read_only=1` will be assigned to
  this hostgroup.
- `offline_hostgroup` - when ProxySQL's monitoring determines a node is `OFFLINE` or unhealthy, it will be put
  into the `offline_hostgroup`.
- `active` - when enabled, ProxySQL monitors the hostgroups and moves nodes between the appropriate
  hostgroups.
- `max_writers` - this value determines the maximum number of nodes that should be allowed in
  the`writer_hostgroup`, nodes in excess of this value will be put into the`backup_writer_hostgroup`
- `writer_is_also_reader` - determines if a node should be added to the `reader_hostgroup` as well as the
  `writer_hostgroup`. The special value `writer_is_also_reader=2` signals that only the nodes in
  `backup_writer_hostgroup` are also in `reader_hostgroup`, excluding the node(s) in the `writer_hostgroup`
- `max_transactions_behind` - determines the maximum number of transactions behind the writers that ProxySQL
  should allow before shunning the node to prevent stale reads (this is determined by querying the
  `transactions_behind` field of the `sys.gr_member_routing_candidate_status` table in MySQL).
- `comment` - text field that can be used for any purpose defined by the user. Could be a description of what
  the cluster stores, a reminder of when the hostgroup was added or disabled, or a JSON processed by some
  checker script.

<!-- -->

ProxySQL also offers several configuration variables about monitoring of group replication clusters that can
be consulted in [mysql-monitor-variables doc][3].

### mysql_hostgroup_attributes

Table `mysql_hostgroup_attributes` defines hostgroup-specific settings that override global configuration for
the specific hostgroup. Only available **from ProxySQL v2.5+**

```
admin> SHOW CREATE TABLE mysql_hostgroup_attributes\G
*************************** 1. row ***************************
       table: mysql_hostgroup_attributes
Create Table: CREATE TABLE mysql_hostgroup_attributes (
    hostgroup_id INT NOT NULL PRIMARY KEY,
    max_num_online_servers INT CHECK (max_num_online_servers>=0 AND max_num_online_servers <= 1000000) NOT NULL DEFAULT 1000000,
    autocommit INT CHECK (autocommit IN (-1, 0, 1)) NOT NULL DEFAULT -1,
    free_connections_pct INT CHECK (free_connections_pct >= 0 AND free_connections_pct <= 100) NOT NULL DEFAULT 10,
    init_connect VARCHAR NOT NULL DEFAULT '',
    multiplex INT CHECK (multiplex IN (0, 1)) NOT NULL DEFAULT 1,
    connection_warming INT CHECK (connection_warming IN (0, 1)) NOT NULL DEFAULT 0,
    throttle_connections_per_sec INT CHECK (throttle_connections_per_sec >= 1 AND throttle_connections_per_sec <= 1000000) NOT NULL DEFAULT 1000000,
    ignore_session_variables VARCHAR CHECK (JSON_VALID(ignore_session_variables) OR ignore_session_variables = '') NOT NULL DEFAULT '',
    hostgroup_settings VARCHAR CHECK (JSON_VALID(hostgroup_settings) OR hostgroup_settings = '') NOT NULL DEFAULT '',
    servers_defaults VARCHAR CHECK (JSON_VALID(servers_defaults) OR servers_defaults = '') NOT NULL DEFAULT '',
    comment VARCHAR NOT NULL DEFAULT '')
1 row in set (0.00 sec)
```

The fields have the following semantics:

- `hostgroup_id` - the hostgroup to which the settings specified in the below columns will be applied.
- `max_num_online_servers` - When the number of `ONLINE` servers specified is exceed, no new connections are
  accepted into the hostgroup. Traffic will continue to be denied until the number of `ONLINE` servers goes
  below the threshold. This is a safeguard mechanism that can help with invalid configurations, like for
  example, a misconfigured `READER` being placed in the `WRITER` hostgroup.
- `autocommit` - _not implemented yet_.
- `free_connections_pct` - the percentage of open idle connections from the total maximum number of
  connections for a specific server in a hostgroup. For more information on the related global variable, see
  [mysql-free_connections_pct][4].
- `init_connect` - string containing one or more SQL statements, separated by semicolons, that will be
  executed by the ProxySQL for each backend connection in the specific hostgroup when created or initialised.
  For more information on the related global variable, see [mysql-init_connect][5].
- `multiplex` - per hostgroup value that either enables or disables multiplexing for the specific hostgroup.
  For more information on the related global variable, see [mysql-multiplexing][6].
- `connection_warming` - per hostgroup value that controls whether ProxySQL will keep opening new connections
  in the specific hostgroup until the expected number of warm connections is reached. For more information on
  the related global variable, see [mysql-connection_warming][7].
- `throttle_connections_per_sec` - determines the maximum number of new connections that can be opened per
  second for the specific hostgroup. For more information on the related global variable, see
  [mysql-throttle_connections_per_sec_to_hostgroup][8].
- `ignore_session_variables` - *not implemented yet*.
- `hostgroup_settings` - Allows to specify settings for the hostgroup, if the setting is also globally
  available, a hostgroup setting will override global configuration. Supported values:
  - `handle_warnings`: Analogous to global variable [mysql-handle_warnings][9]. Supports the same values as
    the global setting.
  - `monitor_slave_lag_when_null`: Analogous to global variable [mysql-monitor_slave_lag_when_null][10].
    Supports the same values as the global setting.
- `servers_defaults` - Allows to specify default values for servers when discovered and placed in the
  hostgroup by ProxySQL Monitoring module. Currently supported values are: `weight`, `max_connections`,
  `use_ssl`.
- `comment` - text field that can be used for any purpose defined by the user.

<!-- -->

The table is useful for several scenarios:

1. When there are differences in either the version of the backend servers in different hostgroups.
2. When different behaviors are expected from different hostgroups.
3. When working with Aurora clusters or Group Replication clusters in which autodiscovery is expected.

<!-- -->

As an example of the first scenario, one could have a hostgroup that consists of MySQL 5.7 backend servers,
while a different one has MySQL 8.0 backends configured (or even different database servers, i.e. MySQL in one
hostgroup, TiDB in another). In this case, it is possible to set different types of SQL statements to be
executed on the backends of different hostgroups by tuning the `init_connect` field of the
`mysql_hostgroup_attributes` table so that ProxySQL sets different variables for different hostgroups when
initializing the connection to them. As an example of the second scenario, you might want to have a different
number of new connections that can be opened for different hostgroups based on your workload on a per
hostgroup basis (`throttle_connections_per_sec`), as well as, for example, calculating a different percentage
of idle connections being kept open on backend servers on a per hostgroup basis (`free_connections_pct`). As
per the global variable's documentation: "For each hostgroup/backend pair, the Hostgroup Manager will keep in
the connection pool up to `mysql-free_connections_pct * mysql_servers.max_connections / 100` connections" -
which number can also be overwritten on different hostgroups according to the specific workload they handle.
As an example of the third scenario, we have ProxySQL working with an AWS Aurora cluster, and we have auto
scaling for our replicas. We would like ProxySQL to place these replicas in the proper hostgroup, but we would
also like being able to configure these replicas, not simply having the defaults values from `mysql_servers`,
we can achieve this via `servers_defaults`. E.g:

```
Admin> UPDATE mysql_hostgroup_attributes SET servers_defaults='{"weight":100,"max_connections":500,"use_ssl":1}' WHERE hostgroup_id=100;
Query OK, 0 rows affected (0.00 sec)
```

Now replicas being discovered and placed in hostgroup _100_ will inherit the supplied defaults.

### mysql_galera_hostgroups

Table `mysql_galera_hostgroups` defines hostgroups for use with Galera Cluster / Percona XtraDB Cluster. Each
row in table `mysql_galera_hostgroups` represents a single cluster, and the hostgroups part of that cluster.
The table definition is the following:

```
Admin> show create table mysql_galera_hostgroups\G
*************************** 1. row ***************************
       table: mysql_galera_hostgroups
Create Table: CREATE TABLE mysql_galera_hostgroups (
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

- **writer_hostgroup** - the hostgroup that all traffic will be sent to by default. Healthy nodes that have
  `read_only=0` in MySQL will be assigned to this hostgroup by default.
- **backup_writer_hostgroup** - if the cluster has multiple nodes with `read_only=0` and their number is
  greater than `max_writers`, ProxySQL will automatically move the additional nodes (in excess of
  `max_writes`) in the `backup_writer_hostgroup`.
- **reader_hostgroup** - healthy nodes that have `read_only=1` will be assigned to this hostgroup. Users can
  create query rules to send read traffic to this hostgroup if needed to remove load from the servers in the
  `writer_hostgroup`
- **offline_hostgroup** - unhealthy nodes are moved to `offline_hostgroup` until they become healthy again and
  moved back into a different hostgroup
- **active** - when enabled, ProxySQL monitors the hostgroups and moves servers between the appropriate
  hostgroups. If disabled, Galera monitoring is disabled for the given cluster and ProxySQL doesn't perform
  any reconfiguration, despite the fact that hostgroups and servers are still configured in
  [mysql_servers][11]
- **max_writers** - this value determines the maximum number of nodes that should be allowed in
  the`writer_hostgroup`, nodes in excess of this value will be put into the`backup_writer_hostgroup`
- **writer_is_also_reader** - determines if a node should be added to the `reader_hostgroup` as well as the
  `writer_hostgroup` after changing `read-only` from 1 to 0. The special value `writer_is_also_reader=2`
  signals that only the nodes in `backup_writer_hostgroup` are also in `reader_hostgroup`, excluding the
  node(s) in the `writer_hostgroup`
- **max_transactions_behind** - determines the maximum number of writesets behind the cluster that ProxySQL
  should allow before shunning the node to prevent stale reads (this is determined by querying the
  `wsrep_local_recv_queue` Galera variable).
- **comment** - text field that can be used for any purpose defined by the user. Could be a description of
  what the cluster stores, a reminder of when the hostgroup was added or disabled, or a JSON processed by some
  checker script.

<!-- -->

For further information on how to configure Galera Cluster / Percona XtraDB Cluster, see [Galera
Configuration][12].

### mysql_users

Table `mysql_users` defines MySQL users that clients can use to connect to ProxySQL, and then used to connect
to backends.

```mysql
mysql> SHOW CREATE TABLE mysql_users\G
*************************** 1. row ***************************
       table: mysql_users
Create Table: CREATE TABLE mysql_users (
    username VARCHAR NOT NULL,
    password VARCHAR,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
    use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0,
    default_hostgroup INT NOT NULL DEFAULT 0,
    default_schema VARCHAR,
    schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0,
    transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 1,
    fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0,
    backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1,
    frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1,
    max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000,
    attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',
    comment VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (username, backend),
    UNIQUE (username, frontend))
1 row in set (0.00 sec)
```

The fields have the following semantics:

- **username**, **password** - credentials for connecting to the mysqld or ProxySQL instance. Password can be
  in clear text, or hashed. See also [Password management][13].
- **active** - the users with active = 0 will be tracked in the database, but will never be loaded in the
  in-memory data structures
- `use_ssl` - if set to 1, the user is forced to authenticate with using an SSL certificate. See also [SSL
  Support][14].
- `default_hostgroup` - if there is no matching rule for the queries sent by this user, the traffic it
  generates is sent to the specified hostgroup
- `default_schema` - the schema to which the connection should change by default
- `schema_locked` - not supported yet.
- `transaction_persistent` - if this is set for the user with which the MySQL client is connecting to ProxySQL
  (thus a "frontend" user - see below), transactions started within a hostgroup will remain within that
  hostgroup regardless of any other rules
- `fast_forward` - if set it bypasses the query processing layer (rewriting, caching) and passes through the
  query directly as is to the backend server.
- `frontend` - if set to 1, this (username, password) pair is used for authenticating to the ProxySQL instance
- `backend` - if set to 1, this (username, password) pair is used for authenticating to the mysqld servers
  against any hostgroup
- `max_connections` - defines the maximum number of allowable frontend connections for a specific user.
- `attributes` - JSON field encoding extra configuration parameters for the user:
  - `default-transaction_isolation`: Imposes a default transactions isolation in the backend connections for
    the selected `mysql_user`. Accepted values are: `READ UNCOMMITTED`, `READ COMMITTED`, `REPEATABLE READ`
    and `SERIALIZABLE` - Since `2.3.0`.
  - `additional_password`: Allows to specify a secondary password for an user, this is particularly useful for
    scenarios like password rotations. See also [Password management][13].
- `comment` - text field that can be used for any purpose defined by the user. Could be a description of what
  the cluster stores, a reminder of when the hostgroup was added or disabled, or a JSON processed by some
  checker script.

<!-- -->

Note, currently all users need both "frontend" and "backend" set to 1. Future versions of ProxySQL will
separate the crendentials between frontend and backend. In this way frontend will never know the credential to
connect directly to the backend, forcing all the connections through ProxySQL and increasing the security of
the system. Fast forward notes:

- It doesn't require a different port: Full features proxy logic and "fast forward" logic is implemented in
  the same code/module.
- Fast forward is implemented on a per-user basis: Depending on the user that connects to ProxySQL, fast
  forward is enabled or disabled.
- Fast forward algorithm is enabled after authentication: the client still authenticates to ProxySQL, and
  ProxySQL will create a connection when the client will start sending traffic. This means that the
  connections' errors are still handled during the connect phase.
- Fast forward supports SSL since version `v2.4.6`.
- If using compression, it must be enabled on both ends.

<!-- -->

Note: users in `mysql_users` shouldn't be used also for `admin-admin_credentials` and
`admin-stats_credentials`

### mysql_query_rules

Table `mysql_query_rules` defines routing policies and attributes.

```mysql
Admin> SHOW CREATE TABLE mysql_query_rules\G
*************************** 1. row ***************************
       table: mysql_query_rules
Create Table: CREATE TABLE mysql_query_rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0,
    username VARCHAR,
    schemaname VARCHAR,
    flagIN INT CHECK (flagIN >= 0) NOT NULL DEFAULT 0,
    client_addr VARCHAR,
    proxy_addr VARCHAR,
    proxy_port INT,
    digest VARCHAR,
    match_digest VARCHAR,
    match_pattern VARCHAR,
    negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0,
    re_modifiers VARCHAR DEFAULT 'CASELESS',
    flagOUT INT CHECK (flagOUT >= 0),
    replace_pattern VARCHAR CHECK(CASE WHEN replace_pattern IS NULL THEN 1 WHEN replace_pattern IS NOT NULL AND match_pattern IS NOT NULL THEN 1 ELSE 0 END),
    destination_hostgroup INT DEFAULT NULL,
    cache_ttl INT CHECK(cache_ttl > 0),
    cache_empty_result INT CHECK (cache_empty_result IN (0,1)) DEFAULT NULL,
    cache_timeout INT CHECK(cache_timeout >= 0),
    reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL,
    timeout INT UNSIGNED,
    retries INT CHECK (retries>=0 AND retries <=1000),
    delay INT UNSIGNED,
    next_query_flagIN INT UNSIGNED,
    mirror_flagOUT INT UNSIGNED,
    mirror_hostgroup INT UNSIGNED,
    error_msg VARCHAR,
    OK_msg VARCHAR,
    sticky_conn INT CHECK (sticky_conn IN (0,1)),
    multiplex INT CHECK (multiplex IN (0,1,2)),
    gtid_from_hostgroup INT UNSIGNED,
    log INT CHECK (log IN (0,1)),
    apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0,
    attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',
    comment VARCHAR)
1 row in set (0.00 sec)
```

The fields have the following semantics:

- `rule_id` - the unique id of the rule. Rules are processed in rule_id order
- `active` - only rules with active=1 will be considered by the query processing module and only active rules
  are loaded into runtime.
- `username` - filtering criteria matching username. If it's non-NULL, a query will match only if the
  connection is made with the correct username
- `schemaname` - filtering criteria matching schemaname. If it's non-NULL, a query will match only if the
  connection uses `schemaname` as default schema (in mariadb/mysql schemaname is equivalent to databasename)
- `flagIN`, `flagOUT`, `apply` - these allow us to create "chains of rules" that get applied one after the
  other. An input flag value is set to 0, and only rules with flagIN=0 are considered at the beginning. When a
  matching rule is found for a specific query, flagOUT is evaluated and if NOT NULL the query will be flagged
  with the specified flag in flagOUT. If flagOUT differs from flagIN , the query will exit the current chain
  and a new chain of rules enters having flagIN as the new input flag. If flagOUT matches flagIN, the query
  will be re-evaluated again against the first rule with said flagIN. This happens until there are no more
  matching rules, or apply is set to 1 (which means this is the last rule to be applied)
- `client_addr` - match traffic from a specific source
- `proxy_addr` - match incoming traffic on a specific local IP
- `proxy_port` - match incoming traffic on a specific local port
- `digest` - match queries with a specific digest, as returned by `stats_mysql_query_digest`.`digest`
- `match_digest` - regular expression that matches the query digest. See also
  [mysql-query_processor_regex][15]
- `match_pattern` - regular expression that matches the query text. See also [mysql-query_processor_regex][15]
- `negate_match_pattern` - if this is set to 1, only queries not matching the query text will be considered as
  a match. This acts as a NOT operator in front of the regular expression matching against `match_pattern` or
  `match_digest`
- `re_modifiers` - comma separated list of options to modify the behavior of the RE engine. With `CASELESS`
  the match is case insensitive. With `GLOBAL` the replace is global (replaces all matches and not just the
  first). For backward compatibility, only `CASELESS` is enabled by default. See also
  [mysql-query_processor_regex][15] for more details.
- `replace_pattern` - this is the pattern with which to replace the matched pattern. It's done using
  RE2::Replace, so it's worth taking a look at the online documentation for that:
  [https://github.com/google/re2/blob/master/re2/re2.h#L378][16]. Note that this is optional, and when this is
  missing, the query processor will only cache, route, or set other parameters without rewriting.
- `destination_hostgroup` - route matched queries to this hostgroup. This happens unless there is a started
  transaction and the logged in user has the transaction_persistent flag set to 1 (see `mysql_users` table).
- `cache_ttl` - the number of milliseconds for which to cache the result of the query. Note: in ProxySQL 1.1
  cache_ttl was in seconds
- `cache_empty_result` - controls if resultset without rows will be cached or not
- `cache_timeout` - ToDo
- `reconnect` - feature not used
- `timeout` - the maximum timeout in milliseconds with which the matched or rewritten query should be
  executed. If a query runs for longer than the specific threshold, the query is automatically killed. If
  timeout is not specified, global variable `mysql-default_query_timeout` applies
- `retries` - the maximum number of times a query needs to be re-executed in case of detected failure during
  the execution of the query. If retries is not specified, global variable `mysql-query_retries_on_failure`
  applies
- `delay` - number of milliseconds to delay the execution of the query. This is essentially a throttling
  mechanism and QoS, allowing to give priority to some queries instead of others. This value is added to the
  `mysql-default_query_delay` global variable that applies to all queries. Future versions of ProxySQL will
  provide a more advanced throttling mechanism.
- `mirror_flagOUT` and `mirror_hostgroup` - setting related to [mirroring][17] .
- `error_msg` - query will be blocked, and the specified `error_msg` will be returned to the client
- `OK_msg` - the specified message will be returned for a query that uses the defined rule
- `sticky_conn` - not implemented yet
- `multiplex` - If 0, multiplex will be disabled. If 1, multiplex could be re-enabled if there aren't any
  other conditions preventing this (like user variables or transactions). If 2, multiplexing is not disabled
  for just the current query. See [wiki][18] Default is `NULL`, thus not modifying multiplexing policies
- `gtid_from_hostgroup` - defines which hostgroup should be used as the `leader` for GTID consistent reads
  (typically the defined `WRITER hostgroup` in a replication hostgroup pair)
- `log` - this column can have three values: `1` - matched query will be recorded into the events log; `0` -
  matched query will not be recorded into the events log; `NULL` - matched query log attribute will remain the
  value from the previous match(es). Executed query will be recorded to the events log if its log attribute is
  set to `1` when rule is applied (`apply=1`) or after processing all query rules and its log attribute is set
  to `1`
- `apply` - when set to `1` no further queries will be evaluated after this rule is matched and processed
  (note: `mysql_query_rules_fast_routing` rules will not be evaluated afterwards)
- `attributes` - JSON field to specify load balancing via query rules between hostgroups. See the examples
  below.
- `comment` - free form text field, usable for a descriptive comment of the query rule

<!-- -->

Examples for load balancing with the help of `mysql_query_rules`:

1. In case you’d like to send specific amounts of traffic coming on a specific port to different hostgroups,
   you would need the following rules:First, capture all traffic coming from the port specified, and assign
   weights to your different hostgroups and set different `flagOUT` values for them with the following
   rule:`Admin&gt; INSERT INTO mysql_query_rules (active,proxy_port,attributes) VALUES (1,'60331','{"flagOUTs":[{"id":1,"weight":1000},{"id":2,"weight":3000}]}');`Then,
   insert the two different query rules for your hostgroups with the
   appropriate `flagIN` values:`Admin&gt;&nbsp;INSERT INTO mysql_query_rules (active,flagIN,destination_hostgroup,apply) VALUES (1,1,20,1), (1,2,30,1);`
   This way, after `LOAD`ing and `SAVE`ing your query rules to runtime, the following will happen: traffic
   arriving on the port specified will either be sent to hostgroup 20 (the weight of which is 1000) or to
   hostgroup 30 (the weight of which is 3000 – meaning that the likelihood is three times as much). This way,
   hostgroup 20 will receive 25% of all traffic, while hostgroup 30 will receive 75% of it. In case you’d like
   to make it evenly distributed, you can set the weights to be the same for both hostgroups (in this case,
   the actual backend within the hostgroup will be chosen according to its weight in
   the `runtime_mysql_servers` table). It is important NOT to set `apply=1` in the first query rule, because
   the queries that the first rule captures need to be passed forward according to their `flagOUT` values.
2. In case you’d like to test a specific query rule for a certain amount of your traffic, you can send only 1%
   of the incoming traffic to a specific hostgroup:First, capture all traffic coming from the port specified,
   and assign weights to your different hostgroups and set different `flagOUT` values for them with the
   following
   rule:`Admin&gt; INSERT INTO mysql_query_rules (active,proxy_port,attributes) VALUES (1,'60331','{"flagOUTs":[{"id":1,"weight":1},{"id":2,"weight":99}]}');`Then,
   insert the two different query rules that modify your query or leave it as it was for the two hostgroups
   with the appropriate `flagIN` values:The one for modifying your query (testing the query rule for a query
   rewrite – to see if forcing an index would make it perform better in this specific case):
   `Admin&gt;&nbsp;INSERT INTO mysql_query_rules (active,flagIN,match_pattern,replace_pattern,destination_hostgroup,apply) VALUES (1,1,'FROM table1 WHERE','FROM table1 USE INDEX(index1) WHERE',20,1);`
   The one for leaving the query unmodified:
   `Admin&gt;&nbsp;INSERT INTO mysql_query_rules (active,flagIN,match_pattern,destination_hostgroup,apply) VALUES (1,2,'FROM table1 WHERE',30,1);`

<!-- -->

A general point to keep in mind: it is important **NOT** to set either the `destination_hostgroup` or the
`apply` values in the first query rule that matches incoming traffic - these are to be used only in the ones
that do the actual load balancing later.

### mysql_query_rules_fast_routing

Table `mysql_query_rules_fast_routing` is an extension of mysql_query_rules and is evaluated afterwards for
fast routing policies and attributes (**only available in ProxySQL 1.4.7+**).

```mysql
Admin> SHOW CREATE TABLE mysql_query_rules_fast_routing\G
*************************** 1. row ***************************
       table: mysql_query_rules_fast_routing
Create Table: CREATE TABLE mysql_query_rules_fast_routing (
    username VARCHAR NOT NULL,
    schemaname VARCHAR NOT NULL,
    flagIN INT NOT NULL DEFAULT 0,
    destination_hostgroup INT CHECK (destination_hostgroup >= 0) NOT NULL,
    comment VARCHAR NOT NULL,
    PRIMARY KEY (username, schemaname, flagIN) )
1 row in set (0,00 sec)
```

The fields have the following semantics:

- `username` - filtering criteria matching username, a query will match only if the connection is made with
  the correct username
- `schemaname` - filtering criteria matching schemaname, a query will match only if the connection uses
  `schemaname` as default schema (in mariadb/mysql schemaname this is equivalent to databasename)
- `flagIN` - evaluated in the same way as `flagin` is in `mysql_query_rules` and correlates to the `flagout` /
  `apply` specified in the `mysql_query_rules` table
- `destination_hostgroup` - route matched queries to this hostgroup. This happens unless there is a started
  transaction and the logged in user has the transaction_persistent flag set to 1 (see `mysql_users` table)
- `comment` - free form text field, usable for a descriptive comment of the query rule

<!-- -->

### pgsql_users

The `pgsql_users` table defines PostgreSQL users that clients can use to connect to ProxySQL and then
subsequently connect to backend PostgreSQL servers. It's analogous to the `mysql_users` table for MySQL co
nnections.

**Table Definition:**

```sql
CREATE TABLE pgsql_users (
    username VARCHAR NOT NULL,
    password VARCHAR,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
    use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0,
    default_hostgroup INT NOT NULL DEFAULT 0,
    transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 1,
    fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0,
    backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1,
    frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1,
    max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000,
    attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',
    comment VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (username, backend),
    UNIQUE (username, frontend)
);
```

**Fields:**

Here's a description of each field in the `pgsql_users` table:

- **username:** The username used for authentication to connect to the PostgreSQL server.
- **password:** The password associated with the username. The password can be stored in plain text or hashed.
  See the documentation on password management for more information.
- **active:** Indicates whether the user is active. If set to 0, the user is tracked in the database but not
  loaded into ProxySQL's in-memory data structures.
- **use_ssl:** If set to 1, the user is forced to authenticate using an SSL/TLS certificate.
- **default_hostgroup:** If no matching query rule is found for the user's queries, the traffic will be routed
  to the specified hostgroup.
- **transaction_persistent:** If set to 1 for a frontend user, transactions started within a hostgroup will
  remain within that hostgroup regardless of other rules. This ensures that a transaction stays on the same
  backend server even if other routing rules might apply.
- **fast_forward:** If set to 1, the query processing layer (rewriting, caching) is bypassed, and the query is
  passed directly to the backend PostgreSQL server.
- **backend:** If set to 1, this (username, password) pair is used for authenticating to the backend
  PostgreSQL servers against any hostgroup.
- **frontend:** If set to 1, this (username, password) pair is used for authenticating to the ProxySQL
  instance itself.
- **max_connections:** Defines the maximum number of allowable frontend connections for a specific user.
- **attributes:** A JSON field that can be used to store additional configuration parameters for the user.
  Currently, this field is not used in ProxySQL for PostgreSQL users.
- **comment:** A free-form text field that can be used to store any relevant information about the user, such
  as a description, notes, or metadata.

**Important Notes:**

- Currently, all PostgreSQL users require both `frontend` and `backend` to be set to 1. Future versions of
  ProxySQL may separate frontend and backend credentials for enhanced security.
- Fast forward bypasses query processing, including caching and rewriting.
- SSL/TLS must be enabled on both the frontend and backend if using compression.
- PostgreSQL users defined in `pgsql_users` should not be used for `admin-admin_credentials` or
  `admin-stats_credentials`.

### pgsql_servers

The `pgsql_servers` table defines all the backend PostgreSQL servers that ProxySQL manages. Similar to the
`mysql_servers` table for MySQL, it allows you to configure and manage individual PostgreSQL servers within
hostgroups.

**Table Definition:**

```sql
CREATE TABLE pgsql_servers (
    hostgroup_id INT CHECK (hostgroup_id>=0) NOT NULL DEFAULT 0,
    hostname VARCHAR NOT NULL,
    port INT CHECK (port >= 0 AND port <= 65535) NOT NULL DEFAULT 5432,
    status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE',
    weight INT CHECK (weight >= 0 AND weight <=10000000) NOT NULL DEFAULT 1,
    compression INT CHECK (compression IN(0,1)) NOT NULL DEFAULT 0,
    max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000,
    max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0,
    use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0,
    max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0,
    comment VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (hostgroup_id, hostname, port)
);
```

**Fields:**

Here's a description of each field in the `pgsql_servers` table:

- **hostgroup_id:** The ID of the hostgroup to which this PostgreSQL server belongs. Note that a single server
  can be part of multiple hostgroups.
- **hostname:** The hostname or IP address of the PostgreSQL server.
- **port:** The TCP port number on which the PostgreSQL server is listening. If `port` is 0, the value in
  `hostname` is interpreted as a Unix Socket file.
- **status:** The configured status of the PostgreSQL server. This indicates how ProxySQL should treat the
  server for routing connections. Possible values are:
  - **ONLINE:** The server is fully operational and available for connections.
  - **SHUNNED:** The server is temporarily taken out of use due to connection errors or exceeding the
    configured replication lag threshold.
  - **OFFLINE_SOFT:** No new connections are created to this server, but existing connections are kept until
    they are returned to the connection pool or closed.
  - **OFFLINE_HARD:** No new connections are created and existing free connections are immediately dropped.
    Connections associated with client sessions are dropped when the client tries to use them.
- **weight:** A relative weight assigned to the server within its hostgroup. A higher weight increases the
  probability of the server being selected for a new connection. ProxySQL uses a random-weighted load
  balancing algorithm by default.
- **compression:** If set to 1, new connections to this server will utilize compression. Frontend and backend
  connections can independently use compression.
- **max_connections:** The maximum number of connections ProxySQL will open to this PostgreSQL server. Once
  this limit is reached, no new connections will be created to this server, even if it has the highest weight.
  Multiplexing can greatly reduce the need for high `max_connections` values per backend.
- **max_replication_lag:** If greater than 0, ProxySQL will monitor the replication lag of the server and
  temporarily shun it if the lag exceeds the configured threshold. This helps ensure that clients don't
  connect to servers that are significantly behind in replication.
- **use_ssl:** If set to 1, connections to this PostgreSQL server will use SSL/TLS. Frontend and backend
  connections can independently use SSL/TLS.
- **max_latency_ms:** The maximum acceptable ping time (in milliseconds) for the server. If a server's ping
  time exceeds this value, it is excluded from the connection pool (though it remains in the `ONLINE` status).
- **comment:** A free-form text field that can be used to store any relevant information about the server,
  such as a description, notes, or metadata.

**Important Notes:**

- For a SHUNNED server to be brought back ONLINE, it must be reachable and there must be activity in the
  connection pool for the associated hostgroup.
- The `max_connections` setting should be configured in conjunction with the backend PostgreSQL server's
  `max_connections` setting to avoid exceeding the server's capacity.
- Multiplexing can significantly improve performance by allowing multiple frontend connections to share a
  single backend connection.

### pgsql_hostgroup_attributes

The `pgsql_hostgroup_attributes` table defines hostgroup-specific settings that override global configurations
for a particular PostgreSQL hostgroup. This allows you to fine-tune the behavior of ProxySQL for different
groups of backend PostgreSQL servers.

**Note:** The features in this table are still under development, and some of the settings may not be fully
functional yet.

**Table Definition:**

```sql
CREATE TABLE pgsql_hostgroup_attributes (
    hostgroup_id INT NOT NULL PRIMARY KEY,
    max_num_online_servers INT CHECK (max_num_online_servers>=0 AND max_num_online_servers <= 1000000) NOT NULL DEFAULT 1000000,
    autocommit INT CHECK (autocommit IN (-1, 0, 1)) NOT NULL DEFAULT -1,
    free_connections_pct INT CHECK (free_connections_pct >= 0 AND free_connections_pct <= 100) NOT NULL DEFAULT 10,
    init_connect VARCHAR NOT NULL DEFAULT '',
    multiplex INT CHECK (multiplex IN (0, 1)) NOT NULL DEFAULT 1,
    connection_warming INT CHECK (connection_warming IN (0, 1)) NOT NULL DEFAULT 0,
    throttle_connections_per_sec INT CHECK (throttle_connections_per_sec >= 1 AND throttle_connections_per_sec <= 1000000) NOT NULL DEFAULT 1000000,
    ignore_session_variables VARCHAR CHECK (JSON_VALID(ignore_session_variables) OR ignore_session_variables = '') NOT NULL DEFAULT '',
    hostgroup_settings VARCHAR CHECK (JSON_VALID(hostgroup_settings) OR hostgroup_settings = '') NOT NULL DEFAULT '',
    servers_defaults VARCHAR CHECK (JSON_VALID(servers_defaults) OR servers_defaults = '') NOT NULL DEFAULT '',
    comment VARCHAR NOT NULL DEFAULT ''
);
```

**Fields:**

Here's a description of each field in the `pgsql_hostgroup_attributes` table:

- **hostgroup_id:** The ID of the PostgreSQL hostgroup to which these attributes apply.
- **max_num_online_servers:** When the number of `ONLINE` servers in the hostgroup exceeds this value, no new
  connections are accepted into the hostgroup. This can help prevent issues with misconfigured hostgroups.
- **autocommit:** **(Not yet implemented)**
- **free_connections_pct:** The percentage of open idle connections from the total maximum number of
  connections for a specific server within the hostgroup. This setting is analogous to the global variable
  `pgsql-free_connections_pct`.
- **init_connect:** A string containing one or more SQL statements, separated by semicolons, that will be
  executed by ProxySQL for each backend connection in the specific hostgroup when created or initialized. This
  is analogous to the global variable `pgsql-init_connect`.
- **multiplex:** Controls whether multiplexing is enabled for the specific hostgroup. This is analogous to the
  global variable `pgsql-multiplexing`.
- **connection_warming:** Controls whether ProxySQL will keep opening new connections in the specific
  hostgroup until the expected number of warm connections is reached. This is analogous to the global variable
  `pgsql-connection_warming`.
- **throttle_connections_per_sec:** Determines the maximum number of new connections that can be opened per
  second for the specific hostgroup. This is analogous to the global variable
  `pgsql-throttle_connections_per_sec_to_hostgroup`.
- **ignore_session_variables:** **(Not yet implemented)**
- **hostgroup_settings:** Allows you to specify settings for the hostgroup that override global
  configurations. Supported values may include settings analogous to MySQL's `handle_warnings` and
  `monitor_slave_lag_when_null`.
- **servers_defaults:** Allows you to specify default values for servers when discovered and placed in the
  hostgroup by ProxySQL's monitoring module. Currently supported values may include `weight`,
  `max_connections`, and `use_ssl`.
- **comment:** A free-form text field that can be used to store any relevant information about the hostgroup,
  such as a description, notes, or metadata.

**Usage Examples:**

- **Different Backend Versions:** If you have hostgroups with different versions of PostgreSQL, you can use
  `init_connect` to set different variables for each hostgroup when connections are initialized.
- **Workload-Specific Tuning:** You can adjust settings like `throttle_connections_per_sec` and
  `free_connections_pct` on a per-hostgroup basis to optimize performance for different workloads.
- **Auto-Discovery:** When working with PostgreSQL clusters that use auto-discovery, you can use
  `servers_defaults` to configure the newly discovered servers with specific settings.

**Important Notes:**

- The functionality of this table is still under development, so some settings may not be fully functional
  yet.
- Consult the ProxySQL documentation for the relevant global variables to understand the effect of each
  setting.

### pgsql_replication_hostgroups

Table `pgsql_replication_hostgroups` defines replication hostgroups for use with traditional primary/replica
replication:

```
radmin=# SHOW CREATE TABLE pgsql_replication_hostgroups;
            table             |                                            Create Table
------------------------------+-------------------------------------------------------------------------------------------------------
 pgsql_replication_hostgroups | CREATE TABLE pgsql_replication_hostgroups (                                                          +
                              |     writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,                           +
                              |     reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>=0),+
                              |     check_type VARCHAR ... NOT NULL DEFAULT 'read_only', -- Field NOT used right now,                +
                              |     comment VARCHAR NOT NULL DEFAULT '', UNIQUE (reader_hostgroup))
(1 row)
```

**NOTE**: Right now the only supported _check_type_ is _read_only_, so the field is unused.

Each row in `pgsql_replication_hostgroups` represents a pair of `writer_hostgroup` and `reader_hostgroup`.
ProxySQL will monitor all the servers present in the specified hostgroups using the check specified in the
column `check_type` (right now only `read_only` is supported), and based on the result of the check, it will
assign the server to the writer or reader hostgroups. The field `comment` can be used to store any arbitrary
data. The fields have the following semantics:

- `writer_hostgroup` - the hostgroup where writers are configured. Nodes that have a read only check returning
  0 will be assigned to this hostgroup.
- `reader_hostgroup` - the hostgroup where readers are configured. Read traffic should be sent to this
  hostgroup, assuming query rules or a separate `read_only` user is defined to route traffic to this
  hostgroup. Nodes that have a `read_only` check returning `1` will be assigned to this hostgroup. Please
  note, however, that these nodes **might not be the only ones** assigned to this hostgroup. Regarding this
  behavior, see also the monitor variable [pgsql-monitor_writer_is_also_reader][2] .
- `check_type` - type of check to perform. Right now only `read_only` is supported, so the field is unused.
- `comment` - text field that can be used for any purpose defined by the user. Could be a description of what
  the cluster stores, a reminder of when the hostgroup was added or disabled, or a JSON processed by some
  checker script.

### pgsql_query_rules

The `pgsql_query_rules` table defines routing policies and attributes for PostgreSQL queries handled by
ProxySQL. It's analogous to the `mysql_query_rules` table used for MySQL queries. This table allows you to
control how ProxySQL routes PostgreSQL queries to different backend servers based on various criteria.

**Table Definition:**

```sql
CREATE TABLE pgsql_query_rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0,
    username VARCHAR,
    database VARCHAR,
    flagIN INT CHECK (flagIN >= 0) NOT NULL DEFAULT 0,
    client_addr VARCHAR,
    proxy_addr VARCHAR,
    proxy_port INT CHECK (proxy_port >= 0 AND proxy_port <= 65535),
    digest VARCHAR,
    match_digest VARCHAR,
    match_pattern VARCHAR,
    negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0,
    re_modifiers VARCHAR DEFAULT 'CASELESS',
    flagOUT INT CHECK (flagOUT >= 0),
    replace_pattern VARCHAR CHECK(CASE WHEN replace_pattern IS NULL THEN 1 WHEN replace_pattern IS NOT NULL AND match_pattern IS NOT NULL THEN 1 ELSE 0 END),
    destination_hostgroup INT DEFAULT NULL,
    cache_ttl INT CHECK(cache_ttl > 0),
    cache_empty_result INT CHECK (cache_empty_result IN (0,1)) DEFAULT NULL,
    cache_timeout INT CHECK(cache_timeout >= 0),
    reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL,
    timeout INT UNSIGNED CHECK (timeout >= 0),
    retries INT CHECK (retries>=0 AND retries <=1000),
    delay INT UNSIGNED CHECK (delay >=0),
    next_query_flagIN INT UNSIGNED,
    mirror_flagOUT INT UNSIGNED,
    mirror_hostgroup INT UNSIGNED,
    error_msg VARCHAR,
    OK_msg VARCHAR,
    sticky_conn INT CHECK (sticky_conn IN (0,1)),
    multiplex INT CHECK (multiplex IN (0,1,2)),
    log INT CHECK (log IN (0,1)),
    apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0,
    attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',
    comment VARCHAR
);
```

**Fields:**

Here's a description of each field in the `pgsql_query_rules` table:

- **rule_id:** The unique ID of the query rule. Rules are processed in ascending order of `rule_id`.
- **active:** Indicates whether the rule is active. If set to 0, the rule is not considered by the query
  processing module.
- **username:** Filters queries based on the username of the connected client.
- **database:** Filters queries based on the database (schema) being accessed.
- **flagIN:** Used to create chains of rules. The initial flag value is 0. Only rules with `flagIN` = 0 are
  considered initially. When a rule is matched, the `flagOUT` value is evaluated. If `flagOUT` is different
  from `flagIN`, the query exits the current chain, and a new chain of rules is processed with the new
  `flagIN` value. If `flagOUT` is the same as `flagIN`, the query is re-evaluated against the first rule with
  that `flagIN` value. This process continues until no more matching rules are found or `apply` is set to 1,
  indicating the last rule in the chain.
- **client_addr:** Filters queries based on the source IP address of the client.
- **proxy_addr:** Filters queries based on the local IP address of ProxySQL where the query is received.
- **proxy_port:** Filters queries based on the local port number of ProxySQL where the query is received.
- **digest:** Filters queries based on a query digest (a hash of the query).
- **match_digest:** A regular expression that matches the query digest.
- **match_pattern:** A regular expression that matches the query text.
- **negate_match_pattern:** If set to 1, only queries that _do not_ match the `match_pattern` or
  `match_digest` are considered a match. Acts as a NOT operator for the regular expression matching.
- **re_modifiers:** A comma-separated list of options that modify the behavior of the regular expression
  engine. `CASELESS` makes the match case-insensitive. `GLOBAL` replaces all occurrences of a pattern, not
  just the first one.
- **flagOUT:** The flag value to assign to a query after a rule is matched.
- **replace_pattern:** The pattern to use to replace a matched pattern. Uses RE2::Replace (see RE2
  documentation for details).
- **destination_hostgroup:** Routes matched queries to the specified hostgroup.
- **cache_ttl:** The time-to-live (in milliseconds) for caching the results of a query.
- **cache_empty_result:** Controls whether to cache empty result sets.
- **cache_timeout:** **(Not yet implemented)**
- **reconnect:** **(Not yet implemented)**
- **timeout:** The maximum time (in milliseconds) allowed for a query to execute. If a query takes longer than
  this, it's automatically killed.
- **retries:** The maximum number of times a query can be retried if a failure is detected.
- **delay:** The number of milliseconds to delay the execution of a query. This can be used for throttling or
  QoS.
- **next_query_flagIN:** **(Not yet implemented)**
- **mirror_flagOUT:** **(Not yet implemented)**
- **mirror_hostgroup:** **(Not yet implemented)**
- **error_msg:** Blocks a query and returns the specified error message to the client.
- **OK_msg:** Returns the specified message for a query that matches the rule.
- **sticky_conn:** **(Not yet implemented)**
- **multiplex:** Controls whether multiplexing is disabled or not for the current query.
- **log:** Controls whether to log the query to the events log.
- **apply:** If set to 1, no further query rules are evaluated after this rule is matched and processed.
- **attributes:** A JSON field that can be used to specify load balancing between hostgroups based on query
  rules.
- **comment:** A free-form text field that can be used to store any relevant information about the rule, such
  as a description, notes, or metadata.

**Usage Examples:**

- **Route Queries to Specific Hostgroups:** You can create rules to route specific queries to different
  hostgroups based on username, database, or query patterns.
- **Load Balancing:** The `attributes` field allows you to configure weighted load balancing between
  hostgroups for specific queries.
- **Query Rewriting:** You can use `replace_pattern` to rewrite queries before sending them to the backend.
- **Query Caching:** Use `cache_ttl` and other caching-related settings to cache query results and improve
  performance.

**Important Notes:**

- The `destination_hostgroup` or `apply` settings should not be used in the first query rule that captures
  incoming traffic.
- Consult the ProxySQL documentation for more information on regular expressions, query caching, and other
  features.

This concludes the basic documentation for the `pgsql_query_rules` table. I'm ready to move on to the next
table if you have any further requests. Let me know if you have any questions or want to refine this
documentation further.

### pgsql_query_rules_fast_routing

The `pgsql_query_rules_fast_routing` table is an extension of `pgsql_query_rules` and is evaluated _after_ the
`pgsql_query_rules` table for fast routing policies and attributes. It provides a way to quickly route queries
based on specific criteria, potentially bypassing more complex rule evaluations in `pgsql_query_rules`.

**Table Definition:**

```sql
CREATE TABLE pgsql_query_rules_fast_routing (
    username VARCHAR NOT NULL,
    database VARCHAR NOT NULL,
    flagIN INT NOT NULL DEFAULT 0,
    destination_hostgroup INT CHECK (destination_hostgroup >= 0) NOT NULL,
    comment VARCHAR NOT NULL,
    PRIMARY KEY (username, database, flagIN)
);
```

**Fields:**

Here's a description of each field in the `pgsql_query_rules_fast_routing` table:

- **username:** Filters queries based on the username of the connected client.
- **database:** Filters queries based on the database (schema) being accessed.
- **flagIN:** Evaluated in the same way as `flagIN` in `pgsql_query_rules` and correlates to the `flagOUT` /
  `apply` settings specified in the `pgsql_query_rules` table. This allows for chaining rules between the two
  tables.
- **destination_hostgroup:** Routes matched queries to the specified hostgroup.
- **comment:** A free-form text field that can be used to store any relevant information about the rule, such
  as a description, notes, or metadata.

**How it Works:**

1. **`pgsql_query_rules` Evaluation:** ProxySQL first evaluates the rules in the `pgsql_query_rules` table.
2. **`flagOUT` and `apply`:** If a rule in `pgsql_query_rules` has a `flagOUT` value that differs from its
   `flagIN` value or if `apply` is set to 1, the query exits the chain of rules in `pgsql_query_rules`.
3. **`pgsql_query_rules_fast_routing` Evaluation:** ProxySQL then checks if there are any matching rules in
   the `pgsql_query_rules_fast_routing` table based on the `flagIN` value determined by the
   `pgsql_query_rules` evaluation.
4. **Fast Routing:** If a matching rule is found in `pgsql_query_rules_fast_routing`, the query is routed to
   the specified `destination_hostgroup`.

**Usage Examples:**

- **Fast Routing for Common Cases:** You can create rules in `pgsql_query_rules_fast_routing` to quickly route
  frequently used queries or queries from specific users to their target hostgroups.
- **Optimization:** By using `pgsql_query_rules_fast_routing`, you can reduce the number of complex rule
  evaluations needed in `pgsql_query_rules`, improving performance.
- **Chaining Rules:** Combine rules in `pgsql_query_rules` with `pgsql_query_rules_fast_routing` to create
  more complex routing logic.

**Important Notes:**

- `pgsql_query_rules_fast_routing` rules are only evaluated _after_ `pgsql_query_rules`.
- The `flagIN` value in `pgsql_query_rules_fast_routing` must align with the `flagOUT` or `apply` settings in
  `pgsql_query_rules` to ensure proper chaining.

### global_variables

The table `global_variables` defines [Global variables][19]. This is a much simpler table, essentially a
key-value store. These are global variables used by ProxySQL and are useful in order to tweak its behaviour.
Global variables are grouped in classes based on their prefix. Currently there are 2 classes of global
variables, although more classes are in the roadmap:

- variables prefixed with `admin-` are relevant for Admin module and allow tweaking of the admin interface
  E.G. changing the admin interface (`admin-mysql_ifaces`) or admin credentials (`admin-admin_credentials`)
- variables prefixed with `mysql-` are relevant for MySQL modules and allow tweaking of MySQL-related
  features. Specifically they include tuning of variables related to:

  - handling of MySQL traffic
  - monitor operatations (further prefixed with `mysql-monitor_`)
  - query caching

    <!-- -->

<!-- -->

For more information about particular variables, please see the dedicated section on [global variables][19]

```mysql
Admin> SHOW CREATE TABLE global_variables\G
*************************** 1. row ***************************
       table: global_variables
Create Table: CREATE TABLE global_variables (
    variable_name VARCHAR NOT NULL PRIMARY KEY,
    variable_value VARCHAR NOT NULL)
1 row in set (0.00 sec)
```

For reference, an example of how `global_variables` looks at the time of writing (version 1.2.4):

```mysql
Admin> SELECT * FROM global_variables ORDER BY variable_name;
+-----------------------------------------------------+------------------------+
| variable_name                                       | variable_value         |
+-----------------------------------------------------+------------------------+
| admin-admin_credentials                             | admin:admin            |
| admin-checksum_mysql_query_rules                    | true                   |
| admin-checksum_mysql_servers                        | true                   |
| admin-checksum_mysql_users                          | true                   |
| admin-cluster_check_interval_ms                     | 1000                   |
| admin-cluster_check_status_frequency                | 10                     |
| admin-cluster_mysql_query_rules_diffs_before_sync   | 3                      |
| admin-cluster_mysql_query_rules_save_to_disk        | true                   |
| admin-cluster_mysql_servers_diffs_before_sync       | 3                      |
| admin-cluster_mysql_servers_save_to_disk            | true                   |
| admin-cluster_mysql_users_diffs_before_sync         | 3                      |
| admin-cluster_mysql_users_save_to_disk              | true                   |
| admin-cluster_password                              |                        |
| admin-cluster_proxysql_servers_diffs_before_sync    | 3                      |
| admin-cluster_proxysql_servers_save_to_disk         | true                   |
| admin-cluster_username                              |                        |
| admin-hash_passwords                                | true                   |
| admin-mysql_ifaces                                  | 0.0.0.0:6032           |
| admin-read_only                                     | false                  |
| admin-refresh_interval                              | 2000                   |
| admin-stats_credentials                             | stats:stats            |
| admin-stats_mysql_connection_pool                   | 60                     |
| admin-stats_mysql_connections                       | 60                     |
| admin-stats_mysql_query_cache                       | 60                     |
| admin-stats_system_cpu                              | 60                     |
| admin-stats_system_memory                           | 60                     |
| admin-telnet_admin_ifaces                           | (null)                 |
| admin-telnet_stats_ifaces                           | (null)                 |
| admin-version                                       | v2.0.0-rc1-17-g832aa48 |
| admin-web_enabled                                   | false                  |
| admin-web_port                                      | 6080                   |
| mysql-autocommit_false_is_transaction               | false                  |
| mysql-autocommit_false_not_reusable                 | false                  |
| mysql-binlog_reader_connect_retry_msec              | 3000                   |
| mysql-client_found_rows                             | true                   |
| mysql-client_multi_statements                       | true                   |
| mysql-commands_stats                                | true                   |
| mysql-connect_retries_delay                         | 1                      |
| mysql-connect_retries_on_failure                    | 10                     |
| mysql-connect_timeout_server                        | 3000                   |
| mysql-connect_timeout_server_max                    | 10000                  |
| mysql-connection_delay_multiplex_ms                 | 0                      |
| mysql-connection_max_age_ms                         | 0                      |
| mysql-connpoll_reset_queue_length                   | 50                     |
| mysql-default_charset                               | utf8                   |
| mysql-default_max_latency_ms                        | 1000                   |
| mysql-default_query_delay                           | 0                      |
| mysql-default_query_timeout                         | 36000000               |
| mysql-default_reconnect                             | true                   |
| mysql-default_schema                                | information_schema     |
| mysql-default_sql_mode                              |                        |
| mysql-default_time_zone                             | SYSTEM                 |
| mysql-enforce_autocommit_on_reads                   | false                  |
| mysql-eventslog_filename                            |                        |
| mysql-eventslog_filesize                            | 104857600              |
| mysql-forward_autocommit                            | false                  |
| mysql-free_connections_pct                          | 10                     |
| mysql-have_compress                                 | true                   |
| mysql-have_ssl                                      | false                  |
| mysql-hostgroup_manager_verbose                     | 1                      |
| mysql-init_connect                                  |                        |
| mysql-interfaces                                    | 0.0.0.0:6033           |
| mysql-kill_backend_connection_when_disconnect       | true                   |
| mysql-long_query_time                               | 1000                   |
| mysql-max_allowed_packet                            | 4194304                |
| mysql-max_connections                               | 2048                   |
| mysql-max_stmts_cache                               | 10000                  |
| mysql-max_stmts_per_connection                      | 20                     |
| mysql-max_transaction_time                          | 14400000               |
| mysql-mirror_max_concurrency                        | 16                     |
| mysql-mirror_max_queue_length                       | 32000                  |
| mysql-monitor_connect_interval                      | 60000                  |
| mysql-monitor_connect_timeout                       | 600                    |
| mysql-monitor_enabled                               | true                   |
| mysql-monitor_galera_healthcheck_interval           | 5000                   |
| mysql-monitor_galera_healthcheck_timeout            | 800                    |
| mysql-monitor_groupreplication_healthcheck_interval | 5000                   |
| mysql-monitor_groupreplication_healthcheck_timeout  | 800                    |
| mysql-monitor_history                               | 600000                 |
| mysql-monitor_password                              | monitor                |
| mysql-monitor_ping_interval                         | 10000                  |
| mysql-monitor_ping_max_failures                     | 3                      |
| mysql-monitor_ping_timeout                          | 1000                   |
| mysql-monitor_query_interval                        | 60000                  |
| mysql-monitor_query_timeout                         | 100                    |
| mysql-monitor_read_only_interval                    | 1500                   |
| mysql-monitor_read_only_max_timeout_count           | 3                      |
| mysql-monitor_read_only_timeout                     | 500                    |
| mysql-monitor_replication_lag_interval              | 10000                  |
| mysql-monitor_replication_lag_timeout               | 1000                   |
| mysql-monitor_replication_lag_use_percona_heartbeat |                        |
| mysql-monitor_slave_lag_when_null                   | 60                     |
| mysql-monitor_threads_max                           | 128                    |
| mysql-monitor_threads_min                           | 8                      |
| mysql-monitor_threads_queue_maxsize                 | 128                    |
| mysql-monitor_username                              | monitor                |
| mysql-monitor_wait_timeout                          | true                   |
| mysql-monitor_writer_is_also_reader                 | true                   |
| mysql-multiplexing                                  | true                   |
| mysql-ping_interval_server_msec                     | 120000                 |
| mysql-ping_timeout_server                           | 500                    |
| mysql-poll_timeout                                  | 2000                   |
| mysql-poll_timeout_on_failure                       | 100                    |
| mysql-query_cache_size_MB                           | 256                    |
| mysql-query_cache_stores_empty_result               | true                   |
| mysql-query_digests                                 | true                   |
| mysql-query_digests_lowercase                       | false                  |
| mysql-query_digests_max_digest_length               | 2048                   |
| mysql-query_digests_max_query_length                | 65000                  |
| mysql-query_processor_iterations                    | 0                      |
| mysql-query_processor_regex                         | 1                      |
| mysql-query_retries_on_failure                      | 1                      |
| mysql-reset_connection_algorithm                    | 2                      |
| mysql-server_capabilities                           | 45578                  |
| mysql-server_version                                | 5.5.30                 |
| mysql-servers_stats                                 | true                   |
| mysql-session_idle_ms                               | 1000                   |
| mysql-session_idle_show_processlist                 | true                   |
| mysql-sessions_sort                                 | true                   |
| mysql-shun_on_failures                              | 5                      |
| mysql-shun_recovery_time_sec                        | 10                     |
| mysql-ssl_p2s_ca                                    |                        |
| mysql-ssl_p2s_cert                                  |                        |
| mysql-ssl_p2s_cipher                                |                        |
| mysql-ssl_p2s_key                                   |                        |
| mysql-stacksize                                     | 1048576                |
| mysql-stats_time_backend_query                      | false                  |
| mysql-stats_time_query_processor                    | false                  |
| mysql-threads                                       | 4                      |
| mysql-threshold_query_length                        | 524288                 |
| mysql-threshold_resultset_size                      | 4194304                |
| mysql-throttle_connections_per_sec_to_hostgroup     | 1000000                |
| mysql-throttle_max_bytes_per_second_to_client       | 2147483647             |
| mysql-throttle_ratio_server_to_client               | 0                      |
| mysql-verbose_query_error                           | false                  |
| mysql-wait_timeout                                  | 28800000               |
+-----------------------------------------------------+------------------------+
136 rows in set (0.01 sec)
```

### scheduler

Table `scheduler` defines jobs to be executed at regular intervals.

```mysql
Admin> SHOW CREATE TABLE scheduler\G
*************************** 1. row ***************************
       table: scheduler
Create Table: CREATE TABLE scheduler (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
    interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL,
    filename VARCHAR NOT NULL,
    arg1 VARCHAR,
    arg2 VARCHAR,
    arg3 VARCHAR,
    arg4 VARCHAR,
    arg5 VARCHAR,
    comment VARCHAR NOT NULL DEFAULT '')
1 row in set (0.00 sec)
```

Further details about the scheduler can be found [here][20]

### restapi_routes

Table `restapi_routes` defines endpoints that a remote client can call using a REST API endpoint using HTTP in
order to trigger the execution of a task by ProxySQL. The following is the table definition:

```sql
mysql> SHOW CREATE TABLE restapi_routes\G
*************************** 1. row ***************************
table: restapi_routes
Create Table: CREATE TABLE restapi_routes (
id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
timeout_ms INTEGER CHECK (timeout_ms>=100 AND timeout_ms<=100000000) NOT NULL,
method VARCHAR NOT NULL CHECK (UPPER(method) IN ('GET','POST')),
uri VARCHAR NOT NULL,
script VARCHAR NOT NULL,
comment VARCHAR NOT NULL DEFAULT '')
1 row in set (0,03 sec)
```

The table defines:

- **id**: unique identifier of the endpoint
- **active**: a REST API endpoint can be either active or not. An endpoint is active by default, and it is
  possible to disable it setting to 0 without the need to delete it
- **timeout_ms**: this defines the maximum execution time for the job that will be called by proxysql when
  that endpoint is reached
- **method**: a REST API endpoint can be called with either a GET or POST method. This defines what method
  must be used
- **uri**: this defines the URI (Uniform Resource Identifier) of the endpoint
- **script**: this is the script (or other executable) that proxysql will executes at the specified endpoint
- **comment**: text field that can be used for any purpose defined by the user, for example to describe the
  endpoint

<!-- -->

### mysql_collations

Here is the table definition for the `mysql_collations` table:

```sql
Admin> show create table mysql_collations\G
*************************** 1. row ***************************
       table: mysql_collations
Create Table: CREATE TABLE mysql_collations (
    Id INTEGER NOT NULL PRIMARY KEY,
    Collation VARCHAR NOT NULL,
    Charset VARCHAR NOT NULL,
    `Default` VARCHAR NOT NULL)
1 row in set (0.01 sec)
```

The table `mysql_collations` is a representation of all the known and available `(charset, collation)` pairs
supported by ProxySQL. Column `Id` represents the numeric value of the collation as defined in MySQL itself.
Column `Default` defines if the given collation is the default collation for the collation it belongs to.
Please note that at time MySQL changes the default collation for a given charset, and ProxySQL may be using a
default different than what specified in the backend. For example, in MySQL 5.7 and ProxySQL the default
collation for `utf8mb4` is `utf8mb4_general_ci` , while in MySQL 8.0 the default collation is
`utf8mb4_0900_ai_ci`. If the client specifies a collation during connection phase or later using
`SET NAMES ... COLLATE ...`, proxysql will track the right collation and use it. In principle, ProxySQL will
validate that incoming connections have a supported charset and collation, and will make sure that the pooled
backend connections are switched to the correct charset and collation before using them.

# Runtime tables

All the configuration tables listed above have a matching `runtime_` table:

<!-- remark-ignore-start -->

- runtime_global_variables : runtime version of [global_variables](#global_variables)
- runtime_mysql_replication_hostgroups : runtime version of
  [mysql_replication_hostgroups](#mysql_replication_hostgroups)
- runtime_mysql_galera_hostgroups : runtime version of
  [mysql_replication_hostgroups](#mysql_galera_hostgroups)
- runtime_mysql_group_replication_hostgroups : runtime version of
  [mysql_replication_hostgroups](#mysql_group_replication_hostgroups)
- runtime_mysql_hostgroup_attributes : runtime version of
  [mysql_hostgroup_attributes](#mysql_hostgroup_attributes)
- runtime_mysql_query_rules : runtime version of [mysql_query_rules](#mysql_query_rules)
- runtime_mysql_query_rules_fast_routing : runtime version of
  [mysql_query_rules_fast_routing](#mysql_query_rules_fast_routing)
- runtime_mysql_servers : runtime version of [mysql_servers](#mysql_servers)
- runtime_mysql_users : runtime version of [mysql_users](#mysql_users)
- runtime_proxysql_servers : runtime version of
  [proxysql_servers](/proxysql-cluster#table_proxysql_servers)
- runtime_scheduler : runtime version of [scheduler](/main-runtime#scheduler)
- runtime_pgsql_replication_hostgroups: runtime version of
  [pgsql_replication_hostgroups](#pgsql_replication_hostgroups)
- runtime_pgsql_hostgroup_attributes:\*\* runtime version of
  [pgsql_hostgroup_attributes](#pgsql_hostgroup_attributes)
- runtime_pgsql_query_rules: runtime version of [pgsql_query_rules](#pgsql_query_rules)
- runtime_pgsql_query_rules_fast_routing: runtime version of
  [pgsql_query_rules_fast_routing](#pgsql_query_rules_fast_routing)
- runtime_pgsql_servers: runtime version of [pgsql_servers](#pgsql_servers)
- runtime_pgsql_users: runtime version of [pgsql_users](#pgsql_users)

<!-- remark-ignore-end -->

#### A note on `main` schema

Note that all the content of the in-memory tables (main database) are _lost_ when ProxySQL is restarted if
their content wasn't saved on disk database.

## Debug config

### debug_filters

The table `debug_filters` defines filters that can be used to suppress specific information from the error log
when 'debug_levels' is enabled in a ProxySQL 'DEBUG' build.

```mysql
Admin> SHOW CREATE TABLE debug_filters\G
*************************** 1. row ***************************
       table: debug_filters
Create Table: CREATE TABLE debug_filters (
    filename VARCHAR NOT NULL,
    line INT NOT NULL,
    funct VARCHAR NOT NULL,
    PRIMARY KEY (filename, line, funct) )
1 row in set (0.00 sec)
```

For reference, an example showing how a 'debug_filter' entry looks at the time of writing (v2.3.2):

```mysql
Admin> SELECT * FROM debug_filters;\G
+------------+------+--------+
| filename   | line | funct  |
+------------+------+--------+
| set_parser | 26   | parse1 |
+------------+------+--------+
1 row in set (0.00 sec)
```

Only mandatory field for specifying a functional filter is 'filename'. The other fields are used for narrowing
the scope of the filter. These fields can be specified in any of the following combinations:

- 'filename' + 'line' + 'funct'
- 'filename' + 'line'
- 'filename' + 'funct'
- 'filename'

<!-- -->

In order to apply filters it's required to:

1. Insert a new filter in the 'debug_filters' table, e.g:
   `INSERT INTO debug_filters (filename,line,funct) VALUES ('set_parser', 26, 'parse1');`
2. Load the new configuration: `LOAD DEBUG TO RUNTIME`

<!-- -->

### debug_levels

The table `debug_levels` defines a series of verbosity levels that can be enabled for ProxySQL when compiled
in 'DEBUG' mode.

```mysql
Admin> SHOW CREATE TABLE debug_levels\G
*************************** 1. row ***************************
       table: debug_levels
Create Table: CREATE TABLE debug_levels (
    module VARCHAR NOT NULL PRIMARY KEY,
    verbosity INT NOT NULL DEFAULT 0)
1 row in set (0.00 sec)
```

For reference, an example showing how 'debug_levels' looks at the time of writing (v2.3.2):

```mysql
Admin> SELECT * FROM debug_levels;\G
+-----------------------------+-----------+
| module                      | verbosity |
+-----------------------------+-----------+
| debug_generic               | 0         |
| debug_net                   | 0         |
| debug_pkt_array             | 0         |
| debug_poll                  | 0         |
| debug_mysql_com             | 0         |
| debug_mysql_server          | 0         |
| debug_mysql_connection      | 0         |
| debug_mysql_connpool        | 0         |
| debug_mysql_rw_split        | 0         |
| debug_mysql_auth            | 0         |
| debug_mysql_protocol        | 0         |
| debug_mysql_query_processor | 0         |
| debug_memory                | 0         |
| debug_admin                 | 0         |
| debug_sqlite                | 0         |
| debug_ipc                   | 0         |
| debug_query_cache           | 0         |
| debug_query_statistics      | 0         |
+-----------------------------+-----------+
18 rows in set (0.00 sec)
```

In order to change theses values it's required to:

1. Set a new value for any of the variables, e.g:
   `UPDATE debug_levels SET verbosity=9 WHERE module='debug_mysql_com'`
2. Load the new configuration: `LOAD DEBUG TO RUNTIME`
3. Enable debugging via `admin-debug` variable, i.e:
   `SET admin-debug='true'; LOAD ADMIN VARIABLES TO RUNTIME;`

<!-- -->

## Disk database

The "disk" database has exactly the same tables as the "main" database (minus the `runtime_` tables), with the
same semantics. The only major difference is that these tables are stored on disk, instead of being stored
in-memory. Whenever ProxySQL is restarted, the in-memory "main" database will be populated starting from this
database. Note that all the content of the in-memory tables (main database) are _lost_ when ProxySQL is
restarted if their content wasn't saved on disk database.

[1]: /global-variables/admin-variables/#admin-admin_credentials
[2]: https://proxysql.com/global-variables/mysql-monitor-variables/#mysql-monitor_writer_is_also_reader
[3]: https://proxysql.com/global-variables/mysql-monitor-variables/
[4]: /global-variables/mysql-variables/#mysql-free_connections_pct
[5]: /global-variables/mysql-variables/#mysql-init_connect
[6]: /global-variables/mysql-variables/#mysql-multiplexing
[7]: /global-variables/mysql-variables/#mysql-connection_warming
[8]: /global-variables/mysql-variables/#mysql-throttle_connections_per_sec_to_hostgroup
[9]: documentation/global-variables/mysql-variables/#mysql-handle_warnings
[10]: /global-variables/mysql-monitor-variables/#mysql-monitor_slave_lag_when_null
[11]: #mysql_servers
[12]: https://proxysql.com/galera-configuration/
[13]: /Password-management
[14]: https://proxysql.com/SSL-Support/
[15]: https://proxysql.com/global-variables/mysql-variables/#mysql-query_processor_regex
[16]: https://github.com/google/re2/blob/master/re2/re2.h#L378
[17]: /mirroring
[18]: /Multiplexing#ad-hoc-enabledisable-of-multiplexing
[19]: /Global-variables
[20]: /Scheduler
