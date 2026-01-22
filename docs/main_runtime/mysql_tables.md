# MySQL Tables

This section documents all tables related to the MySQL protocol in ProxySQL, including configuration, runtime, and collations.

## List of MySQL Tables

| Tablename | Description |
| :--- | :--- |
| [mysql_users](#mysql_users) | Frontend and Backend MySQL Users |
| [mysql_servers](#mysql_servers) | Backend MySQL Servers |
| [mysql_servers_ssl_params](#mysql_servers_ssl_params) | Backend MySQL Server specific SSL Parameters |
| [mysql_replication_hostgroups](#mysql_replication_hostgroups) | MySQL replication clusters |
| [mysql_group_replication_hostgroups](#mysql_group_replication_hostgroups) | MySQL clusters using Group Replication |
| [mysql_hostgroup_attributes](#mysql_hostgroup_attributes) | Hostgroup-specific overrides |
| [mysql_galera_hostgroups](#mysql_galera_hostgroups) | MySQL clusters using Galera replication |
| [mysql_query_rules](#mysql_query_rules) | Query Rules for MySQL traffic |
| [mysql_query_rules_fast_routing](#mysql_query_rules_fast_routing) | Specialized fast routing rules |
| [mysql_collations](#mysql_collations) | Known MySQL charsets and collations |

---

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

### mysql_replication_hostgroups

Table `mysql_replication_hostgroups` defines replication hostgroups for use with traditional master / slave
ASYNC or SEMI-SYNC replication.

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
  Nodes that have a read only check returning 1 will be assigned to this hostgroup. Regarding this behavior,
  see also the monitor variable [mysql-monitor_writer_is_also_reader][2] .
- `check_type` - the MySQL variable(s) checked when executing a Read Only check, and optionally the logical
  binary operation. `read_only` is the default. `innodb_read_only` and `super_read_only` can be used as well.
- `comment` - text field that can be used for any purpose defined by the user.

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
- `reader_hostgroup` - the hostgroup that read traffic should be sent to.
- `offline_hostgroup` - when ProxySQL's monitoring determines a node is `OFFLINE` or unhealthy, it will be put
  into the `offline_hostgroup`.
- `active` - when enabled, ProxySQL monitors the hostgroups and moves nodes between the appropriate
  hostgroups.
- `max_writers` - this value determines the maximum number of nodes that should be allowed in
  the`writer_hostgroup`.
- `writer_is_also_reader` - determines if a node should be added to the `reader_hostgroup` as well as the
  `writer_hostgroup`.
- `max_transactions_behind` - determines the maximum number of transactions behind the writers that ProxySQL
  should allow before shunning the node.
- `comment` - text field that can be used for any purpose defined by the user.

### mysql_hostgroup_attributes

Table `mysql_hostgroup_attributes` defines hostgroup-specific settings that override global configuration for
the specific hostgroup.

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

### mysql_galera_hostgroups

Table `mysql_galera_hostgroups` defines hostgroups for use with Galera Cluster / Percona XtraDB Cluster.

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

### mysql_query_rules_fast_routing

Table `mysql_query_rules_fast_routing` is an extension of mysql_query_rules and is evaluated afterwards for
fast routing policies and attributes.

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

### mysql_collations

Table `mysql_collations` is a representation of all the known and available `(charset, collation)` pairs
supported by ProxySQL.

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

## Runtime Tables

All configuration tables have a corresponding `runtime_` version:

- `runtime_mysql_users`
- `runtime_mysql_servers`
- `runtime_mysql_servers_ssl_params`
- `runtime_mysql_replication_hostgroups`
- `runtime_mysql_galera_hostgroups`
- `runtime_mysql_group_replication_hostgroups`
- `runtime_mysql_hostgroup_attributes`
- `runtime_mysql_query_rules`
- `runtime_mysql_query_rules_fast_routing`

[2]: https://proxysql.com/global-variables/mysql-monitor-variables/#mysql-monitor_writer_is_also_reader
