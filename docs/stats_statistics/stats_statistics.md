## The `stats` database

This database contains metrics gathered by ProxySQL with respect to its internal functioning. Here you will
find information on how often certain counters get triggered and the execution times of the queries that pass
through ProxySQL.

- A user that connects to Admin with `admin-stats_credentials` credentials can only access this schema.
- Generally, the tables from this database are populated on the fly when the SQL query against them is
  executed, by examining in-memory data structures.

<!-- -->

Here are the tables from the "stats" database:

```sql
Admin> show tables from stats;
+---------------------------------------+
| tables                                |
+---------------------------------------+
| global_variables                      |
| stats_memory_metrics                  |
| stats_mysql_client_host_cache         |
| stats_mysql_client_host_cache_reset   |
| stats_mysql_commands_counters         |
| stats_mysql_connection_pool           |
| stats_mysql_connection_pool_reset     |
| stats_mysql_errors                    |
| stats_mysql_errors_reset              |
| stats_mysql_free_connections          |
| stats_mysql_global                    |
| stats_mysql_gtid_executed             |
| stats_mysql_prepared_statements_info  |
| stats_mysql_processlist               |
| stats_mysql_query_digest              |
| stats_mysql_query_digest_reset        |
| stats_mysql_query_rules               |
| stats_mysql_users                     |
| stats_proxysql_servers_checksums      |
| stats_proxysql_servers_metrics        |
| stats_proxysql_servers_status         |
+---------------------------------------+
24 rows in set (0.00 sec)
```

## Stats Tables

<!-- remark-ignore-start -->

- [global_variables](#mysql_global_variables)
- [stats_memory_metrics](#stats_mysql_memory_metrics)
- [stats_mysql_commands_counters](#stats_mysql_commands_counters)
- [stats_mysql_client_host_cache](#stats_mysql_client_host_cache)
- [stats_mysql_client_host_cache_reset](#stats_mysql_client_host_cache_reset)
- [stats_mysql_connection_pool](#stats_mysql_connection_pool)
- [stats_mysql_connection_pool_reset](#stats_mysql_connection_pool_reset)
- [stats_mysql_errors](#stats_mysql_errors)
- [stats_mysql_errors_reset](#stats_mysql_errors_reset)
- [stats_mysql_free_connections](#stats_mysql_free_connections)
- [stats_mysql_global](#stats_mysql_global)
- [stats_mysql_gtid_executed](#stats_mysql_gtid_executed)
- [stats_mysql_prepared_statements_info](#stats_mysql_prepared_statements_info)
- [stats_mysql_processlist](#stats_mysql_processlist)
- [stats_mysql_query_digest](#stats_mysql_query_digest)
- [stats_mysql_query_digest_reset](#stats_mysql_query_digest_reset)
- [stats_mysql_query_rules](#stats_mysql_query_rules)
- [stats_mysql_users](#stats_mysql_users)
- [stats_proxysql_servers_checksums](#stats_proxysql_servers_checksums)
- [stats_proxysql_servers_metrics](#stats_proxysql_servers_metrics)
- [stats_proxysql_servers_status](#stats_proxysql_servers_status)

<!-- remark-ignore-end -->

### `global_variables`

Table `stats.global_variables` exists only to facilitate connections from libraries that issues
`SELECT @@max_allowed_packet` or similar. Its content can be ignored:

```
Admin> SELECT * FROM stats.global_variables;
+--------------------------+----------------+
| variable_name            | variable_value |
+--------------------------+----------------+
| mysql-max_allowed_packet | 4194304        |
+--------------------------+----------------+
1 row in set (0.00 sec)
```

### `stats_memory_metrics`

```
Admin> SELECT * FROM stats.stats_memory_metrics;
+------------------------------+----------------+
| Variable_Name                | Variable_Value |
+------------------------------+----------------+
| SQLite3_memory_bytes         | 3002992        |
| jemalloc_resident            | 10342400       |
| jemalloc_active              | 8142848        |
| jemalloc_allocated           | 7124360        |
| jemalloc_mapped              | 39845888       |
| jemalloc_metadata            | 2459072        |
| jemalloc_retained            | 0              |
| Auth_memory                  | 690            |
| query_digest_memory          | 0              |
| mysql_query_rules_memory     | 1380           |
| mysql_firewall_users_table   | 0              |
| mysql_firewall_users_config  | 0              |
| mysql_firewall_rules_table   | 0              |
| mysql_firewall_rules_config  | 329            |
| stack_memory_mysql_threads   | 8388608        |
| stack_memory_admin_threads   | 8388608        |
| stack_memory_cluster_threads | 0              |
+------------------------------+----------------+
17 rows in set (0.01 sec)
```

This table is meant to display memory usage of various structures inside ProxySQL. Currently, only a few
structures are tracked: SQLite, Auth module, Query Digests. But in the future more internal structures will be
tracked. The most important values to monitor in this table are the ones related to `jemalloc` (the memory
allocator built inside ProxySQL). A detailed description of the various values is available at the [jemalloc
website][1]. Jemalloc metrics:

- `jemalloc_allocated` : bytes allocated by the application
- `jemalloc_active`: bytes in pages allocated by the application
- `jemalloc_mapped`: bytes in extents mapped by the allocator
- `jemalloc_metadata`: bytes dedicated to metadata
- `jemalloc_resident`: bytes in physically resident data pages mapped by the allocator

<!-- -->

Other memory metrics:

- `Auth_memory` : memory used by the authentication module to store user credentials and attributes
- `SQLite3_memory_bytes` : memory used by the embedded SQLite
- `query_digest_memory` : memory used to store data related to _stats_mysql_query_digest_
- `mysql_query_rules_memory` : memory used by query rules
- `mysql_firewall_users_table` : memory used for the lookup table of firewall users
- `mysql_firewall_users_config` : memory used for configuration of firewall users
- `mysql_firewall_rules_table` : memory used for the lookup table of firewall rules
- `mysql_firewall_rules_config` : memory used for configuration of firewall users
- `stack_memory_mysql_threads` : memory of MySQL worker threads \* stack size
- `stack_memory_admin_threads` : memory of admin connections \* stack size
- `stack_memory_cluster_threads` : memory of ProxySQL Cluster threads \* stack size

<!-- -->

_Note:_ stack size is 8MB by default

### `stats_mysql_client_host_cache`

Table `stats_mysql_client_host_cache` keeps records of all the failed connection attempts performed by clients
when 'client error limit' feature is enabled, i.e. when 'mysql-client_host_cache_size' is set to a value
bigger than '0': Here is the statement used to create the `stats_mysql_client_host_cache` table:

```
CREATE TABLE stats_mysql_client_host_cache (
    client_address VARCHAR NOT NULL,
    error_count INT NOT NULL,
    last_updated BIGINT NOT NULL)
```

The fields have the following semantics:

- `client_address`: the client address from which the connection failure was detected.
- `error_count`: the total number of consecutive connections errors originated from client address.
- `last_updated`: the time of the last connection error in microseconds.

<!-- -->

Example:

```
Admin> SELECT * FROM stats_mysql_client_host_cache;
+----------------+-------------+--------------+
| client_address | error_count | last_updated |
+----------------+-------------+--------------+
| 10.200.1.2     | 1           | 104099605807 |
+----------------+-------------+--------------+
1 row in set (0.00 sec)
```

### `stats_mysql_client_host_cache_reset`

Querying the `stats_mysql_client_host_cache_reset` table is equivalent to querying
`stats_mysql_client_host_cache`, with the only difference that client host cache is cleared at the end of the
`SELECT` statement.

### `stats_mysql_commands_counters`

Table `stats_mysql_commands_counters` keeps records of all types of queries executed, and collects statistics
based on their execution time, grouping them into buckets:

```
Admin> SELECT * FROM stats_mysql_commands_counters ORDER BY Total_cnt DESC LIMIT 1G
*************************** 1. row ***************************
      Command: SELECT
Total_Time_us: 347608868191
    Total_cnt: 9246385
    cnt_100us: 1037
    cnt_500us: 2316761
      cnt_1ms: 2710036
      cnt_5ms: 2728904
     cnt_10ms: 457001
     cnt_50ms: 655136
    cnt_100ms: 146379
    cnt_500ms: 179698
       cnt_1s: 19157
       cnt_5s: 21705
      cnt_10s: 4663
     cnt_INFs: 5908
1 row in set (0.01 sec)
```

The fields have the following semantics:

- `command` : the type of SQL command that has been executed. Examples: _FLUSH_, _INSERT_, _KILL_, _SELECT FOR
  UPDATE_, etc.
- `Total_Time_us` : the total time spent executing commands of that type, in microseconds
- `total_cnt` : the total number of commands of that type executed
- `cnt_100us,cnt_500us, ..., cnt_10s, cnt_INFs` : the total number of commands of the given type which
  executed within the specified time limit and the previous one. For example, _cnt_500us_ is the number of
  commands which executed within 500 microseconds, but more than 100 microseconds because there's also a
  _cnt_100us_ field. _cnt_INFs_ is the number of commands whose execution exceeded 10 seconds.

<!-- -->

Note: statistics for table _stats_mysql_commands_counters_ are processed only if global variable
_mysql-commands_stats_ is set to _true_ . This is the default, and used for other queries processing. It is
recommended to _NOT_ disable it.

### `stats_mysql_connection_pool`

This table exports statistics on backend servers. Servers are identified based on their hostgroup, address and
port, and the information available is related to connections, queries and traffic. Here is the statement used
to create the `stats_mysql_connection_pool` table:

```sql
CREATE TABLE stats_mysql_connection_pool (
    hostgroup VARCHAR,
    srv_host VARCHAR,
    srv_port VARCHAR,
    status VARCHAR,
    ConnUsed INT,
    ConnFree INT,
    ConnOK INT,
    ConnERR INT,
    MaxConnUsed INT,
    Queries INT,
    Queries_GTID_sync INT,
    Bytes_data_sent INT,
    Bytes_data_recv INT,
    Latency_us INT)
```

Each row represents a backend server within a hostgroup. The fields have the following semantics:

- `hostgroup` : the hostgroup in which the backend server belongs. Note that a single backend server can
  belong to more than one hostgroup
- `srv_host, srv_port` : the TCP endpoint on which the mysqld backend server is listening for connections
- `status` : the status of the backend server. Can be _ONLINE, SHUNNED, OFFLINE_SOFT, OFFLINE_HARD_. See the
  description of the [`mysql_servers`][2] table for more details about what each status means
- `ConnUsed` : how many connections are currently used by ProxySQL for sending queries to the backend server
- `ConnFree` : how many connections are currently free. They are kept open in order to minimize the time cost
  of sending a query to the backend server
- `ConnOK` : how many connections were established successfully.
- `ConnERR` : how many connections weren't established successfully.
- `MaxConnUsed` : high water mark of connections used by ProxySQL for sending queries to the backend server
- `Queries` : the number of queries routed towards this particular backend server
- `Queries_GTID_sync`: ToDo
- `Bytes_data_sent` : the amount of data sent to the backend. This does not include metadata (packets'
  headers)
- `Bytes_data_recv` : the amount of data received from the backend. This does not include metadata (packets'
  headers, OK/ERR packets, fields' description, etc)
- `Latency_us` : the current ping time in microseconds, as reported from Monitor

<!-- -->

In the following output, it is possible to note how efficient ProxySQL is by using few connections.

```
Admin> SELECT hostgroup hg, srv_host, status, ConnUsed, ConnFree, ConnOK, ConnERR FROM stats_mysql_connection_pool WHERE ConnUsed+ConnFree > 0 ORDER BY hg, srv_host;
+----+-------------------+--------+----------+----------+--------+---------+
| hg | srv_host          | status | ConnUsed | ConnFree | ConnOK | ConnERR |
+----+-------------------+--------+----------+----------+--------+---------+
| 10 | back001-db-master | ONLINE | 69       | 423      | 524    | 0       |
| 11 | back001-db-master | ONLINE | 0        | 1        | 1      | 0       |
| 11 | back001-db-reader | ONLINE | 0        | 11       | 11     | 0       |
| 20 | back002-db-master | ONLINE | 9        | 188      | 197    | 2       |
| 21 | back002-db-reader | ONLINE | 0        | 1        | 1      | 0       |
| 31 | back003-db-master | ONLINE | 0        | 3        | 3      | 0       |
| 31 | back003-db-reader | ONLINE | 1        | 70       | 71     | 0       |
+----+-------------------+--------+----------+----------+--------+---------+
7 rows in set (0.00 sec)

Admin> SELECT hostgroup hg, srv_host, Queries, Bytes_data_sent, Bytes_data_recv, Latency_us FROM stats_mysql_connection_pool WHERE ConnUsed+ConnFree > 0 ORDER BY hg, srv_host;
+----+-------------------+---------+-----------------+-----------------+------------+
| hg | srv_host          | Queries | Bytes_data_sent | Bytes_data_recv | Latency_us |
+----+-------------------+---------+-----------------+-----------------+------------+
| 10 | back001-db-master | 8970367 | 9858463664      | 145193069937    | 17684      |
| 11 | back001-db-master | 69      | 187675          | 2903            | 17684      |
| 11 | back001-db-reader | 63488   | 163690013       | 4994101         | 113        |
| 20 | back002-db-master | 849461  | 1086994186      | 266034339       | 101981     |
| 21 | back002-db-reader | 8       | 6992            | 984             | 230        |
| 31 | back003-db-master | 3276    | 712803          | 81438709        | 231        |
| 31 | back003-db-reader | 2356904 | 411900849       | 115810708275    | 230        |
+----+-------------------+---------+-----------------+-----------------+------------+
7 rows in set (0.00 sec)
```

### `stats_mysql_connection_pool_reset`

Querying the `stats_mysql_connection_pool_reset` table is equivalent to querying
`stats_mysql_connection_pool`, with the only difference that all statistics are reset to 0 at the end of the
`SELECT` statement.

### `stats_mysql_errors`

This table tracks errors reported by the backend servers during query execution. Servers are identified based
on their hostgroup, address and port. Here is the statement used to create the `stats_mysql_errors` table:

```sql
CREATE TABLE stats_mysql_errors (
    hostgroup INT NOT NULL,
    hostname VARCHAR NOT NULL,
    port INT NOT NULL,
    username VARCHAR NOT NULL,
    client_address VARCHAR NOT NULL,
    schemaname VARCHAR NOT NULL,
    errno INT NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    last_error VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (hostgroup, hostname, port, username, schemaname, errno) )
```

Each row represents a backend server within a hostgroup. The fields have the following semantics:

- `hostgroup` : the hostgroup in which the backend server belongs. Note that a single backend server can
  belong to more than one hostgroup
- `srv_host, srv_port` : the TCP endpoint on which the mysqld backend server is listening for connections
- `username` : the username of the backend server user
- `client_address` : the frontend address connecting to ProxySQL
- `schemaname` : the schema the query was using when the error was generated
- `errno` : the error number generated by the backend server
- `count_star` : the number of times this error was seen for the user/schema/hostgroup/hostname/port
  combination since the last reset of mysql error statistics
- `first_seen` : when this entry was first seen since the last reset of mysql error statistics
- `last_seen` : when this entry was last seen
- `last_error` : exact error text for the last error of this entry

<!-- -->

### `stats_mysql_errors_reset`

Querying the `stats_mysql_errors_reset` table is equivalent to querying `stats_mysql_errors`, with the only
difference that all statistics are reset to 0 at the end of the `SELECT` statement.

### `stats_mysql_free_connections`

This table provides information about free connections in ProxySQL's connection pool. Here is the statement
used to create the table:

```sql
CREATE TABLE stats_mysql_free_connections (
    fd INT NOT NULL,
    hostgroup INT NOT NULL,
    srv_host VARCHAR NOT NULL,
    srv_port INT NOT NULL,
    user VARCHAR NOT NULL,
    schema VARCHAR,
    init_connect VARCHAR,
    time_zone VARCHAR,
    sql_mode VARCHAR,
    autocommit VARCHAR,
    idle_ms INT,
    statistics VARCHAR,
    mysql_info VARCHAR)
```

Each row represents a connection to a backend server within a hostgroup. The fields have the following
semantics:

- `fd` : the file descriptor of ProxySQL's connection to the backend server
- `hostgroup` : the hostgroup in which the backend server belongs. Note that a single backend server can
  belong to more than one hostgroup
- `srv_host, srv_port` : the TCP endpoint to which mysqld backend server the connection is made
- `username` : the username of the backend server user
- `schema` : the schema the connection is using
- `init_connect` : init_connect instruction used when the connection was created, if any
- `time_zone` : the time_zone that was specified on connection, if any
- `sql_mode` : the current sql_mode of the connection
- `autocommit` : the current autocommit setting of the connection
- `idle_ms` : how long, in milliseconds, since the connection was used
- `statistics` : json object of statistics related to the connection, containing information of how much query
  traffic the connection has handled, how old the connection is, and how much usage it has received as part of
  the connection pool
- `mysql_info` : additional metadata about the connection to the backend, such as the server version and
  character set in use.

<!-- -->

### `stats_mysql_global`

One of the most important tables in the _stats_ schema is _stats_mysql_global_, which exports counters related
to various ProxySQL internals. Here is the statement used to create the `stats_mysql_global` table:

```sql
CREATE TABLE stats_mysql_global (
    Variable_Name VARCHAR NOT NULL PRIMARY KEY,
    Variable_Value VARCHAR NOT NULL
)
```

Each row represents a global statistic at the proxy level related to MySQL including:

- Key Memory Usage
- Prepared Statements
- Query Cache
- Processing Time
- Global Connections
- Threads / Workers
- Connection Pooling
- Transactions
- SQL Statements

<!-- -->

The same output is available using the **SHOW MYSQL STATUS** command. Example:

```sql
Admin> select * from stats.stats_mysql_global limit 5;
+------------------------------+----------------+
| Variable_Name                | Variable_Value |
+------------------------------+----------------+
| ProxySQL_Uptime              | 93382          |
| Active_Transactions          | 0              |
| Client_Connections_aborted   | 0              |
| Client_Connections_connected | 4              |
| Client_Connections_created   | 4              |
+------------------------------+----------------+
```

#### Variable description:

- `ProxySQL_Uptime`: the total uptime of ProxySQL in seconds
- `Active_Transactions`: provides a count of how many client connections are currently processing a
  transaction
- `Client_Connections_aborted`: client failed connections (or closed improperly)
- `Client_Connections_connected`: client connections that are currently connected
- `Client_Connections_created`: total number of client connections created
- `Client_Connections_non_idle`: number of client connections that are currently handled by the main worker
  threads. If ProxySQL isn't running with "--idle-threads", `Client_Connections_non_idle` is always equal to.
  `Client_Connections_connected`.
- `Client_Connections_hostgroup_locked`: ToDo
- `Server_Connections_aborted`: backend failed connections (or closed improperly)
- `Server_Connections_connected`: backend connections that are currently connected
- `Server_Connections_created`: total number of backend connections created
- `Server_Connections_delayed`: ToDo
- `Servers_table_version`: ToDo
- `Backend_query_time_nsec`: time spent making network calls to communicate with the backends
- `Queries_backends_bytes_recv`: ToDo
- `Queries_backends_bytes_sent`: ToDo
- `Queries_frontends_bytes_recv`: ToDo
- `Queries_frontends_bytes_sent`: ToDo
- `backend_lagging_during_query`: ToDo
- `backend_offline_during_query`: ToDo
- `mysql_backend_buffers_bytes`: buffers related to backend connections if "fast_forward" is used (0 means
  `fast_forward` is not used)
- `mysql_frontend_buffers_bytes`: buffers related to frontend connections (read/write buffers and other
  queues)
- `mysql_killed_backend_connections`: ToDo
- `mysql_killed_backend_queries`: ToDo
- `mysql_unexpected_frontend_com_quit`: ToDo
- `mysql_unexpected_frontend_packets`: ToDo
- `client_host_error_killed_connections`: ToDo
- `hostgroup_locked_queries`: ToDo
- `hostgroup_locked_set_commands`: ToDo
- `max_connect_timeouts`: ToDo
- `new_req_conns_count`: ToDo
- `automatic_detected_sql_injection`: ToDo
- `whitelisted_sqli_fingerprint`: ToDo
- `generated_error_packets`: ToDo
- `Selects_for_update__autocommit0`: ToDo
- `mysql_session_internal_bytes`: other memory used by ProxySQL to handle MySQL Sessions
- `Com_autocommit`: ToDo
- `Com_autocommit_filtered`: ToDo
- `Com_backend_change_user`: ToDo
- `Com_backend_init_db`: ToDo
- `Com_backend_set_names`: ToDo
- `Com_commit`: ToDo
- `Com_commit_filtered`: ToDo
- `Com_frontend_init_db`: ToDo
- `Com_frontend_set_names`: ToDo
- `Com_frontend_use_db`: ToDo
- `Com_rollback`: ToDo
- `Com_rollback_filtered`: ToDo
- `Com_frontend_stmt_prepare / Com_frontend_stmt_execute / Com_frontend_stmt_close`: represent the number of
  “PREPARE / EXECUTE / CLOSE” executed by clients. It is common for clients to prepare a statement, execute
  the statement once, and then close it so these 3 metrics' values are often almost identical.
- `Com_backend_stmt_prepare / Com_backend_stmt_execute / Com_backend_stmt_close`: represent the number of
  “PREPARE” / “EXECUTE” / “CLOSE” executed by ProxySQL against the backends. Com_backend_stmt_execute should
  roughly match Com_frontend_stmt_execute. ProxySQL tracks and re-uses prepared statements across connections
  where possible so Com_backend_stmt_prepare is generally much smaller than Com_frontend_stmt_prepare.
  Com_backend_stmt_close is always 0 in the current implementation as ProxySQL never closes prepared
  statements as it is inefficient (a network round trip would be wasted). Instead, when
  "mysql-max_stmts_per_connection" is reached in a backend connection and the connection returns to the
  connection pool and is reset (implicitly closing all prepared statements)
- `MySQL_Thread_Workers`: number of MySQL Thread workers i.e. “mysql-threads”
- `MySQL_Monitor_Workers`: The number of monitor threads. By default it is twice the number of worker threads,
  initially capped to 16 yet more threads will be created checks are being queued. Monitor threads perform
  blocking network operations and do not consume much CPU
- `MySQL_Monitor_Workers_Aux`: ToDo
- `MySQL_Monitor_Workers_Started`: ToDo
- `MySQL_Monitor_connect_check_ERR`: ToDo
- `MySQL_Monitor_connect_check_OK`: ToDo
- `MySQL_Monitor_ping_check_ERR`: ToDo
- `MySQL_Monitor_ping_check_OK`: ToDo
- `MySQL_Monitor_read_only_check_ERR`: ToDo
- `MySQL_Monitor_read_only_check_OK`: ToDo
- `MySQL_Monitor_replication_lag_check_ERR`: ToDo
- `MySQL_Monitor_replication_lag_check_OK`: ToDo
- `ConnPool_get_conn_success`: number of requests where a connection was already available in the connection
  pool
- `ConnPool_get_conn_failure`: number of requests where a connection was not available in the connection pool
  and either a new connection had to be created or no backend was available
- `ConnPool_get_conn_immediate`: number of connections that a MySQL Thread obtained from its own local
  connection pool cache. This value tends to be large only when there is high concurrency.
- `ConnPool_get_conn_latency_awareness`: ToDo
- `Questions`: the total number of client requests / statements executed
- `Slow_queries`: the total number of queries with an execution time greater than "mysql-long_query_time"
  milliseconds
- `GTID_consistent_queries`: ToDo
- `GTID_session_collected`: ToDo
- `Mirror_concurrency:` ToDo
- `Mirror_que_length`: ToDo
- `queries_with_max_lag_ms`: ToDo
- `queries_with_max_lag_ms__delayed`: ToDo
- `queries_with_max_lag_ms__total_wait_time_us`: ToDo
- `get_aws_aurora_replicas_skipped_during_query`: ToDo
- `Access_Denied_Max_Connections`: ToDo
- `Access_Denied_Max_User_Connections`: ToDo
- `Access_Denied_Wrong_Password`: ToDo
- `MyHGM_myconnpoll_get`: the number of requests made to the connection pool
- `MyHGM_myconnpoll_get_ok`: the number of successful requests to the connection pool (i.e. where a connection
  was available)
- `MyHGM_myconnpoll_push`: the number of connections returned to the connection pool
- `MyHGM_myconnpoll_destroy`: the number of connections considered unhealthy and therefore closed
- `MyHGM_myconnpoll_reset`: the number of connections that have been reset / re-initialized using
  "COM_CHANGE_USER"
- `SQLite3_memory_bytes`: memory used by SQLite
- `ConnPool_memory_bytes`: memory used by the connection pool to store connections metadata
- `Stmt_Client_Active_Total`: the total number of prepared statements that are in use by clients
- `Stmt_Client_Active_Unique`: this variable tracks the number of unique prepared statements currently in use
  by clients
- `Stmt_Server_Active_Total`: the total number of prepared statements currently available across all backend
  connections
- `Stmt_Server_Active_Unique`: the number of unique prepared statements currently available across all backend
  connections
- `Stmt_Cached`: this is the number of global prepared statements for which ProxySQL has metadata
- `Stmt_Max_Stmt_id`: when a new global prepared statement is created, a new "stmt_id" is used.
  Stmt_Max_Stmt_id represents the maximum "stmt_id" ever used. When metadata for a prepared statement is
  dropped, the "stmt_id" may be reused
- `Query_Cache_Memory_bytes`: memory currently used by the query cache (more details later)
- `Query_Cache_Entries`: number of entries currently stored in the query cache
- `Query_Cache_Memory_bytes`: memory usage of the query cache
- `Query_Cache_Purged`: number of entries purged by the Query Cache due to TTL expiration
- `Query_Cache_bytes_IN`: number of bytes sent into the Query Cache
- `Query_Cache_bytes_OUT`: number of bytes read from the Query Cache
- `Query_Cache_count_GET`: number of read requests
- `Query_Cache_count_GET_OK`: number of successful read requests
- `Query_Cache_count_SET`: number of write requests
- `Query_Processor_time_nsec`: the time spent inside the Query Processor to determine what action needs to be
  taken with the query (internal module)

<!-- -->

### `stats_mysql_gtid_executed`

The _stats_mysql_gtid_executed_ table provides statistics related to GTID tracking for consistent reads. The
table shows the GTID sets and number of events executed on each backend node.

```
Admin> show create table stats.stats_mysql_gtid_executedG
*************************** 1. row ***************************
       table: stats_mysql_gtid_executed
Create Table: CREATE TABLE stats_mysql_gtid_executed (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    gtid_executed VARCHAR,
    events INT NOT NULL)
1 row in set (0.00 sec)
```

For example, here we can see a difference in GTID sets between the source (mysql1) and replicas (mysql2,
mysql3):

```
Admin> select * from stats_mysql_gtid_executed where hostname='mysql1’G
*************************** 1. row ***************************
     hostname: mysql1
         port: 3306
gtid_executed: 85c17137-4258-11e8-8090-0242ac130002:1-65588
       events: 65581

# After a few moments...

Admin> select hostname,gtid_executed from stats_mysql_gtid_executed order by hostnameG
*************************** 1. row ***************************
     hostname: mysql1
gtid_executed: 85c17137-4258-11e8-8090-0242ac130002:1-146301
*************************** 2. row ***************************
     hostname: mysql2
gtid_executed: 85c17137-4258-11e8-8090-0242ac130002:1-146300,8a093f5f-4258-11e8-8037-0242ac130004:1-5
*************************** 3. row ***************************
     hostname: mysql3
gtid_executed: 85c17137-4258-11e8-8090-0242ac130002:1-146301,8a0ac961-4258-11e8-8003-0242ac130003:1-5
```

### `stats_mysql_prepared_statements_info`

Because of multiplexing, it is possible that a client prepares a prepared statement(PS) in a backend
connection but that connection is not free when that same client wants to execute the PS. Furthermore, it is
possible that multiple clients prepare the same PS. ProxySQL addresses these issues in the following ways:

- for every unique PS , a global `stmt_id` is generated and its metadata are stored internally in a global
  cache
- each client preparing a PS gets a `stmt_id` that is local to that client, but mapped to the global `stmt_id`
- on every backend connection where a PS is prepared, the `stmt_id` returned by the backend is mapped to the
  global `stmt_id`

<!-- -->

```
CREATE TABLE stats_mysql_prepared_statements_info (
    global_stmt_id INT NOT NULL, hostgroup INT NOT NULL,
    schemaname VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    digest VARCHAR NOT NULL,
    ref_count_client INT NOT NULL,
    ref_count_server INT NOT NULL,
    num_columns INT NOT NULL, num_params INT NOT NULL, query VARCHAR NOT NULL)
1 row in set (0.00 sec)
```

- `global_stmt_id` : the global stmt_id to be used across clients and backend servers
- `schemaname` : the schema the prepared statement is associated with
- `username` : the username of the associated with the prepared statement
- `digest` : digest of the query
- `ref_count_client` : the number of reference counters for client connections
- `ref_count_server` : the number of references to backend connections
- `num_columns` : ToDo
- `num_params` : ToDo
- `query` : query used for the prepared statement

<!-- -->

### `stats_mysql_processlist`

The `stats_mysql_processlist` provides information on what ProxySQL connections are doing

```sql
CREATE TABLE stats_mysql_processlist (
    ThreadID INT NOT NULL,
    SessionID INTEGER PRIMARY KEY,
    user VARCHAR,
    db VARCHAR,
    cli_host VARCHAR,
    cli_port VARCHAR,
    hostgroup VARCHAR,
    l_srv_host VARCHAR,
    l_srv_port VARCHAR,
    srv_host VARCHAR,
    srv_port VARCHAR,
    command VARCHAR,
    time_ms INT NOT NULL,
    info VARCHAR,
    status_flags INT,
    extended_info VARCHAR)
```

The fields have the following semantics:

- `ThreadID` : the internal ID of the thread within ProxySQL. This is a 0-based numbering of the threads
- `SessionID` : the internal global numbering of the ProxySQL sessions, or clients' connections (frontend).
  It's useful to be able to uniquely identify such a session, for example in order to be able to kill it, or
  monitor a specific session only.
- `user` : the user with which the MySQL client connected to ProxySQL in order to execute this query
- `db` : the schema currently selected
- `cli_host`, `cli_port` - the (host, port) pair of the TCP connection between the MySQL client and ProxySQL
- `hostgroup` : the current hostgroup. If a query is being processed, this is the hostgroup towards which the
  query was or will be routed, or the default hostgroup. The routing is done by default in terms of the
  default destination hostgroup for the username with which the MySQL client connected to ProxySQL (based on
  `mysql_users` table, but it can be modified on a per-query basis by using the query rules in
  `mysql_query_rules`
- `l_srv_host`, `l_srv_port` : the local (host, port) pair of the TCP connection between ProxySQL and the
  backend MySQL server from the current hostgroup
- `srv_host`, `srv_port` : the (host, port) pair on which the backend MySQL server is listening for TCP
  connections
- `command` : the type of MySQL query being executed (the MySQL command verb)
- `time_ms` : the time in millisecond for which the query has been in the specified command state so far
- `info` : the actual query being executed
- `status_flags`: ToDo
- `extended_info`: JSON object holding additional information. An example:

<!-- -->

```sql
{
"extended_info": {
"autocommit": true,
"autocommit_on_hostgroup": -1,
"backends": [
{
"conn": {
"MultiplexDisabled": false,
"autocommit": true,
"init_connect": "",
"init_connect_sent": true,
"last_set_autocommit": -1,
"mysql": {
"affected_rows": 18446744073709551615,
"charset": 8,
"db": "test",
"host": "127.0.0.1",
"host_info": "127.0.0.1 via TCP/IP",
"insert_id": 0,
"net": {
"fd": 28,
"last_errno": 0,
"max_packet_size": 1073741824,
"sqlstate": "00000"
},
"options": {
"charset_name": "utf8",
"use_ssl": 0
},
"port": 13308,
"server_status": 16386,
"server_version": "5.7.24-log",
"unix_socket": "",
"user": "root"
},
"no_backslash_escapes": false,
"ps": {
"backend_stmt_to_global_ids": [],
"global_stmt_to_backend_ids": []
},
"sql_log_bin": 1,
"sql_mode": "",
"status": {
"found_rows": false,
"get_lock": false,
"lock_tables": false,
"no_multiplex": false,
"temporary_table": false,
"user_variable": false
},
"time_zone": "SYSTEM"
},
"hostgroup_id": 11
}
],
"client": {
"client_addr": {
"address": "127.0.0.1",
"port": 37810
},
"encrypted": false,
"proxy_addr": {
"address": "0.0.0.0",
"port": 6033
},
"stream": {
"bytes_recv": 111,
"bytes_sent": 89,
"pkts_recv": 2,
"pkts_sent": 2
},
"userinfo": {
"password": "*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B",
"username": "root"
}
},
"conn": {
"autocommit": true,
"charset": 8,
"no_backslash_escapes": false,
"ps": {
"client_stmt_to_global_ids": []
},
"sql_log_bin": 1,
"sql_mode": "",
"status": {
"compression": false,
"transaction": false
},
"time_zone": "SYSTEM"
},
"current_hostgroup": 11,
"default_hostgroup": 10,
"default_schema": "",
"last_HG_affected_rows": -1,
"last_insert_id": 0,
"thread_session_id": 5,
"transaction_persistent": true
}
}
```

Please note that this is just a snapshot in time of the actual MySQL queries being run. There is no guarantee
that the same queries will be running a fraction of a second later. Here is what the results look like without
`extended_info`:

```sql
mysql> select * from stats_mysql_processlist;
+----------+-----------+------+------+-----------+----------+-----------+------------+------------+-----------+----------+---------+---------+---------------------------------------+
| ThreadID | SessionID | user | db   | cli_host  | cli_port | hostgroup | l_srv_host | l_srv_port | srv_host  | srv_port | command | time_ms | info                                  |
+----------+-----------+------+------+-----------+----------+-----------+------------+------------+-----------+----------+---------+---------+---------------------------------------+
| 3        | 1         | root | test | 127.0.0.1 | 51831    | 0         | 127.0.0.1  | 55310      | 127.0.0.1 | 3306     | Query   | 0       | SELECT c FROM sbtest1 WHERE id=198898 |
| 0        | 2         | root | test | 127.0.0.1 | 51832    | 0         | 127.0.0.1  | 55309      | 127.0.0.1 | 3306     | Query   | 0       | SELECT c FROM sbtest3 WHERE id=182586 |
| 2        | 3         | root | test | 127.0.0.1 | 51833    | 0         | 127.0.0.1  | 55308      | 127.0.0.1 | 3306     | Query   | 0       | SELECT c FROM sbtest1 WHERE id=199230 |
| 1        | 4         | root | test | 127.0.0.1 | 51834    | 0         | 127.0.0.1  | 55307      | 127.0.0.1 | 3306     | Query   | 0       | SELECT c FROM sbtest2 WHERE id=201110 |
+----------+-----------+------+------+-----------+----------+-----------+------------+------------+-----------+----------+---------+---------+---------------------------------------+
4 rows in set (0.02 sec)
```

You can also query contents of the `extended_info` by using `JSON_EXTRACT` the following way (in this example
only `age_ms` is queried, but you can add further items to the query):

```sql
mysql> SELECT ThreadID, SessionID, user, db, hostgroup, JSON_EXTRACT(extended_info, '$.age_ms') age_ms FROM stats_mysql_processlistG
*************************** 1. row ***************************
 ThreadID: 5
SessionID: 8
     user: root
       db: test
hostgroup: 0
   age_ms: 839878
1 row in set (0.03 sec)
```

**Note:** ProxySQL also supports the commands **SHOW PROCESSLIST** and **SHOW FULL PROCESSLIST** to
return information related to current sessions.

### `stats_mysql_query_digest`

p>The `stats_mysql_query_digest` table provides information about queries that have been processed by
ProxySQL. It is very useful for identifying queries that can be routed to readers, rewritten or cached.

```sql
CREATE TABLE stats_mysql_query_digest (
hostgroup INT,
schemaname VARCHAR NOT NULL,
username VARCHAR NOT NULL,
client_address VARCHAR NOT NULL,
digest VARCHAR NOT NULL,
digest_text VARCHAR NOT NULL,
count_star INTEGER NOT NULL,
first_seen INTEGER NOT NULL,
last_seen INTEGER NOT NULL,
sum_time INTEGER NOT NULL,
min_time INTEGER NOT NULL,
max_time INTEGER NOT NULL,
sum_rows_affected INTEGER NOT NULL,
sum_rows_sent INTEGER NOT NULL,
PRIMARY KEY(hostgroup, schemaname, username, client_address, digest)
)
```

Each row represents a class of queries all having the same parameters (but with different values) routed
through ProxySQL. Here's what a typical result looks like:

```bash
mysql> select * from stats_mysql_query_digest order by count_star desc limit 2;
+------------+----------+--------------------+----------------------------------+------------+------------+------------+------------+----------+----------+
| schemaname | username | digest             | digest_text                      | count_star | first_seen | last_seen  | sum_time   | min_time | max_time |
+------------+----------+--------------------+----------------------------------+------------+------------+------------+------------+----------+----------+
| test       | root     | 0x7721D69250CB40   | SELECT c FROM sbtest3 WHERE id=? | 8122800    | 1441091306 | 1441101551 | 7032352665 | 1010     | 117541   |
| test       | root     | 0x3BC2F7549D058B6F | SELECT c FROM sbtest4 WHERE id=? | 8100134    | 1441091306 | 1441101551 | 7002512958 | 101      | 102285   |
+------------+----------+--------------------+----------------------------------+------------+------------+------------+------------+----------+----------+
```

The fields have the following semantics:

- `hostgroup` : the hostgroup where the query was sent. A value of `-1` represent a query hitting the Query
  Cache
- `schemaname` : the schema that is currently being queried
- `username` : the username with which the MySQL client connected to ProxySQL
- `client_address` : the address of the client if `mysql-query_digests_track_hostname=true`
- `digest` : a hexadecimal hash that uniquely represents a query with its parameters stripped
- `digest_text` : the actual text with its parameters stripped
- `count_star` : the total number of times the query has been executed (with different values for the
  parameters)
- `first_seen` : unix timestamp, the first moment when the query was routed through the proxy
- `last_seen` : unix timestamp, the last moment (so far) when the query was routed through the proxy
- `sum_time` : the total time in microseconds spent executing queries of this type. This is particularly
  useful to figure out where the most time is spent in your application's workload, and provides a good
  starting point for where to improve
- `min_time, max_time` : the range of durations to expect when executing such a query. min_time is the minimal
  execution time seen so far, while max_time represents the maximal execution time, both in microseconds.
- `sum_rows_affected` : the total number of rows affected
- `sum_rows_sent` : the total number of rows sent. This doesn't currently count the number of rows returned
  from the Query Cache

<!-- -->

The time in this table refers to the time elapsed between the time in which ProxySQL receives the query from
the client, and the time in which ProxySQL is ready to send the query to the client. Therefore these times
represent the elapsed time as close as possible as seen from the client. To be more precise, it is possible
that before executing a query, ProxySQL needs to change charset or schema, find a new backend if the current
one is not available anymore, run the query on a different backend if the current one fails, or wait for a
connection to become free because currently all the connections are in use. **Note:** statistics for table
`stats_mysql_query_digest` are processed only if global variables `mysql-commands_stats` and
`mysql-query_digests` are set to `true` . This is the default, and used for other queries processing. It is
recommended to **NOT** disable them.

### `stats_mysql_query_digest_reset`

Table `stats_mysql_query_digest_reset` is identical to `stats_mysql_query_digest`, but reading from
`stats_mysql_query_digest_reset` causes all statistics to be reset at the end of the `SELECT`.

### `stats_mysql_query_rules`

The `stats_mysql_query_rules` table exports how many times query rules were matching traffic.

```sql
CREATE TABLE stats_mysql_query_rules (
    rule_id INTEGER PRIMARY KEY,
    hits INT NOT NULL
)
```

The fields have the following semantics:

- `rule_id` : the id of the rule, can be joined with the `main.mysql_query_rules` table on the `rule_id`
  field.
- `hits` : the total number of hits for this rule. One hit is registered if the current incoming query matches
  the rule. Each time a new query that matches the rule is processed, the number of hits is increased.

<!-- -->

Note that the `hits` value is reset every time query rules are loaded to runtime, either through explicit
`LOAD MYSQL QUERY RULES TO RUNTIME` or through implicit re-sync via ProxySQL Cluster.

### `stats_mysql_users`

The `stats_mysql_users` table reports a list of users, their current number of frontend connections, and the
total number of frontend connections they can create (as defined in `mysql_users.max_connections`).

```sql
CREATE TABLE stats_mysql_users (
    username VARCHAR PRIMARY KEY,
    frontend_connections INT NOT NULL,
    frontend_max_connections INT NOT NULL)
```

The fields have the following semantics:

- `username` : the username from the _mysql_users_ table
- `frontend_connections` : the number of connections currently used by this user
- `frontend_max_connections` : the maximum number of connections this user is allowed to use, as configured in
  the _mysql_users_ table

<!-- -->

```
Admin> SELECT username, frontend_connections conns, frontend_max_connections max_conns  FROM stats_mysql_users WHERE frontend_connections > 0;
+----------------+-------+-----------+
| username       | conns | max_conns |
+----------------+-------+-----------+
| proxyab_rw_001 | 138   | 20000     |
| proxyab_ro     | 4     | 20000     |
| proxyab_rw     | 406   | 20000     |
| main_ro        | 4316  | 20000     |
| main_rw        | 800   | 20000     |
| test_rw        | 2     | 5000      |
| test_ro        | 1     | 5000      |
+----------------+-------+-----------+
7 rows in set (0.00 sec)
```

### `stats_proxysql_servers_checksums`

ProxySQL instances that are part of a Cluster regularly monitor each other to understand if a reconfiguration
needs to be triggered. It is possible to query the current view of the Cluster through the table
`stats_proxysql_servers_checksums`:

```sql
CREATE TABLE stats_proxysql_servers_checksums (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 6032,
    name VARCHAR NOT NULL,
    version INT NOT NULL,
    epoch INT NOT NULL,
    checksum VARCHAR NOT NULL,
    changed_at INT NOT NULL,
    updated_at INT NOT NULL,
    diff_check INT NOT NULL,
    PRIMARY KEY (hostname, port, name) )
```

The fields have the following semantics:

- `hostname` : address of the proxy (remote or local)
- `port` : port of the proxy (remote or local)
- `name` : name of the module being synchronized
- `version`: every time a configuration is loaded (locally), its version number is increased by 1
- `epoch`: this is the time when the specific configuration was created (either locally, or remotely before
  being imported)
- `checksum`: the checksum of the configuration itself. This is the information that proxies use to detect
  configuration changes
- `changed_at`: this is the time when the specific configuration was loaded locally. Note that it is different
  than `epoch`, which represents when the configuration was created
- `updated_at`: this is the last time the local ProxySQL checked the checksum of the remote ProxySQL instance.
  If this value is not increased, it means that the local ProxySQL cannot fetch data from the remote ProxySQL
- `diff_check`: the number of checks in a row in which it was detected that the remote configuration is
  different than the local one. When a threshold is reached, an automatic reconfiguration is triggered

<!-- -->

```sql
Admin> SELECT 'proxy'||SUBSTR(hostname,11,12) hostname,name,version v, epoch,SUBSTR(checksum,0,10)||'...' checksum, changed_at, updated_at, diff_check diff FROM stats_proxysql_servers_checksums WHERE version > 0 ORDER BY name, hostname;
+----------+-------------------+---+------------+--------------+------------+------------+------+
| hostname | name              | v | epoch      | checksum     | changed_at | updated_at | diff |
+----------+-------------------+---+------------+--------------+------------+------------+------+
| proxy01  | mysql_query_rules | 1 | 1543750277 | 0x8CE2200... | 1543750278 | 1543761243 |    0 |
| proxy02  | mysql_query_rules | 1 | 1542709023 | 0x8CE2200... | 1543750277 | 1543761244 |    0 |
| proxy03  | mysql_query_rules | 1 | 1542709056 | 0x8CE2200... | 1543750277 | 1543761244 |    0 |
| proxy01  | mysql_servers     | 2 | 1543754137 | 0xBB56542... | 1543754137 | 1543761243 |    0 |
| proxy02  | mysql_servers     | 7 | 1543754141 | 0xBB56542... | 1543754140 | 1543761244 |    0 |
| proxy03  | mysql_servers     | 6 | 1543754142 | 0xBB56542... | 1543754137 | 1543761244 |    0 |
| proxy01  | mysql_users       | 1 | 1543750277 | 0xA9533E6... | 1543750278 | 1543761243 |    0 |
| proxy02  | mysql_users       | 1 | 1542709023 | 0xA9533E6... | 1543750277 | 1543761244 |    0 |
| proxy03  | mysql_users       | 1 | 1542709056 | 0xA9533E6... | 1543750277 | 1543761244 |    0 |
| proxy01  | proxysql_servers  | 1 | 1543750277 | 0xA87C55F... | 1543750278 | 1543761243 |    0 |
| proxy02  | proxysql_servers  | 1 | 1542709023 | 0xA87C55F... | 1543750277 | 1543761244 |    0 |
| proxy03  | proxysql_servers  | 1 | 1542709056 | 0xA87C55F... | 1543750277 | 1543761244 |    0 |
+----------+-------------------+---+------------+--------------+------------+------------+------+
12 rows in set (0.00 sec)
```

### `stats_proxysql_servers_metrics`

ProxySQL instances in a Cluster regularly exchange global statuses. Some of these statuses are visible in the
`stats_proxysql_servers_metrics` table:

```sql
CREATE TABLE stats_proxysql_servers_metrics (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 6032,
    weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0,
    comment VARCHAR NOT NULL DEFAULT '',
    response_time_ms INT NOT NULL,
    Uptime_s INT NOT NULL,
    last_check_ms INT NOT NULL,
    Queries INT NOT NULL,
    Client_Connections_connected INT NOT NULL,
    Client_Connections_created INT NOT NULL,
    PRIMARY KEY (hostname, port) )
```

The fields have the following semantics:

- `hostname` : address of the Cluster node, defined in the `proxysql_servers` table
- `port` : port of the Cluster node, defined in the `proxysql_servers` table
- `weight` : weight of the Cluster node, defined in the `proxysql_servers` table
- `comment`: comment associated with the the Cluster node, defined in the `proxysql_servers` table
- `response_time_ms`: the latest time to respond to Cluster checks, in milliseconds
- `Uptime_s`: the current uptime of the Cluster node, in seconds
- `last_check_ms`: the latest time to process Cluster checks, in milliseconds
- `Queries`: how many queries the Cluster node has processed
- `Client_Connections_connected`: the number of frontend client connections currently open on the Cluster node
- `Client_Connections_created`: the number of frontend client connections created over time on the Cluster
  node

<!-- -->

Example:

```sql
Admin> SELECT 'proxy'||SUBSTR(hostname,11,12) hostname , response_time_ms rtt_ms, Uptime_s, last_check_ms, Queries, Client_Connections_connected c_conn, Client_Connections_created c_created FROM stats_proxysql_servers_metrics ORDER BY hostname;
+----------+--------+----------+---------------+-----------+--------+-----------+
| hostname | rtt_ms | Uptime_s | last_check_ms | Queries   | c_conn | c_created |
+----------+--------+----------+---------------+-----------+--------+-----------+
| proxy01  | 0      | 12111    | 18494         | 52475036  | 9095   | 14445     |
| proxy02  | 0      | 1053365  | 18047         | 199072024 | 13552  | 456759    |
| proxy03  | 2      | 1053333  | 16950         | 248707015 | 9891   | 471200    |
+----------+--------+----------+---------------+-----------+--------+-----------+
3 rows in set (0.00 sec)
```

### `stats_proxysql_servers_status`

Currently unused - this table was created to show general statistics related to all the services configured in
the `proxysql_servers` table.

```sql
CREATE TABLE stats_proxysql_servers_status (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 6032,
    weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0,
    master VARCHAR NOT NULL,
    global_version INT NOT NULL,
    check_age_us INT NOT NULL,
    ping_time_us INT NOT NULL, checks_OK INT NOT NULL,
    checks_ERR INT NOT NULL,
    PRIMARY KEY (hostname, port) )
```

[1]: http://jemalloc.net/jemalloc.3.html
[2]: https://proxysql.com/main-runtime/#mysql_servers
