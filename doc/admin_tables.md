Admin tables
============

ProxySQL admin interface is an interface that uses the MySQL protocol, making it very easy to be configured by any client able to send commands through such interface.
ProxySQL parses the queries sent through this interface for any command specific to ProxySQL, and if not send them to an embedded SQLite3 engine to run the queries.

Please note that SQL syntax used by SQLite3 and MySQL differs, therefore not all commands working on MySQL will work on SQLite3 .
For example, although the USE command is accepted by the admin interface, it doesn't change the default schema as this feature is no available in SQLite3.

Connecting to the ProxySQL admin interface, we see that there are a few databases available.
ProxySQL converts SHOW DATABASES command in the equivalent for SQLite3.

```bash
mysql> show databases;
+-----+---------+------------------+
| seq | name    | file             |
+-----+---------+------------------+
| 0   | main    |                  |
| 2   | disk    | /tmp/proxysql.db |
| 3   | stats   |                  |
| 4   | monitor |                  |
| 5   | myhgm   |                  |
+-----+---------+------------------+
5 rows in set (0.00 sec)

```

The purposes of these databases are as follows:
* main: the in-memory configuration database. Using this database, it's easy to query and update the configuration of ProxySQL in an automated manner. Using the LOAD MYSQL USERS FROM MEMORY and similar commands, the configuration stored in here can be propagated to the in-memory data structures used by ProxySQL at runtime.
* disk: the disk-based mirror of "main". Across restarts, "main" is not persisted and is loaded either from the "disk" database or from the config file, based on startup flags and the existence of not of an on-disk database.
* stats: contains runtime metrics collected from the internal functioning of the proxy. Example metrics include the number of times each query rule was matched, the currently running queries, etc.
* monitor: contains monitoring metrics related to the backend servers to which ProxySQL connects. Example metrics include the minimal and maximal time for connecting to a backend server or for pinging it.
* myhgm: only enabled in debug builds

Also, the access to the admin database is done using two types of users, with these default credentials:
* user: admin/password: admin -- with read-write access to all the tables
* user: stats/password: stats -- with read-only access to statistics tables. This is used for pulling metrics out of ProxySQL, without exposing too much of the database

# main database

Here are the tables from the "main" database (ProxySQL converts SHOW TABLES FROM command in the equivalent for SQLite3):

```bash
mysql> show tables from main;
+-------------------+
| tables            |
+-------------------+
| mysql_servers     |
| mysql_users       |
| mysql_query_rules |
| global_variables  |
| mysql_collations  |
| debug_levels      |
+-------------------+
6 rows in set (0.01 sec)
```

## `mysql_servers`

Here is the statement used to create the `mysql_servers` table:

```sql
CREATE TABLE mysql_servers (
    hostgroup_id INT NOT NULL DEFAULT 0,
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE',
    weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1,
    compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0,
    max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000,
    max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0,
    PRIMARY KEY (hostgroup_id, hostname, port) )
```

The fields have the following semantics:
* hostgroup_id: the hostgroup in which this mysqld instance is included. Notice that the same instance can be part as more than one hostgroup
* hostname, port: the TCP endpoint at which the mysqld instance can be contacted
* status: 
  * ONLINE - backend server is fully operational
  * SHUNNED - backend sever is temporarily taken out of use because of either too many connection errors in a time that was too short, or replication lag exceeded the allowed threshold
  * OFFLINE_SOFT - when a server is put into OFFLINE_SOFT mode, new incoming connections aren't accepted anymore, while the existing connections are kept until they became inactive. In other words, connections are kept in use until the current transaction is completed. This allows to greacefully detach a backend 
  * OFFLINE_HARD - when a server is put into OFFLINE_HARD mode, the existing connections are dropped, while new incoming connections aren't accepted either. This is equivalent to deleting the server from a hostgroup, or temporarily taking it out of the hostgroup for maintenance work
* weight - the bigger the weight of a server relative to other weights, the higher the probability of the server to be chosen from a hostgroup
* compression - not supported yet, feature being rededigned
* max_connections - the maximum number of connections ProxySQL will open to this backend server. Even though this server will have the highest weight, no new connections will be opened to it once this limit is hit. Please ensure that the backend is configured with a correct value of max_connections to avoid that ProxySQL will try to go beyond that limit
* max_replication_lag - if greater and 0, ProxySQL will reguarly monitor replication lag and if it goes beyond such threshold it will temporary shun the host until replication catch ups


## `mysql_users`

Here is the statement used to create the `mysql_users` table:

```sql
CREATE TABLE mysql_users (
    username VARCHAR NOT NULL,
    password VARCHAR,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
    use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0,
    default_hostgroup INT NOT NULL DEFAULT 0,
    default_schema VARCHAR,
    schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0,
    transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0,
    fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0,
    backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1,
    frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1,
    max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000,
    PRIMARY KEY (username, backend),
    UNIQUE (username, frontend)
)
```

The fields have the following semantics:
* username, password - credentials for connecting to the mysqld or ProxySQL instance
* active - the users with active = 0 will be tracked in the database, but will be never loaded in the in-memory data structures
* default_hostgroup - if there is no matching rule for the queries send by this users, the traffic is generates is sent to the specified hostgroup
* default_schema - the schema to which the connection should change by default
* schema_locked - not supported yet (TODO: check)
* transaction_persistent - if this is set for the user with which the MySQL client is connecting to ProxySQL (thus a "frontend" user - see below), transactions started within a hostgroup will remain within that hostgroup regardless of any other rules
* fast_forward - feature currently disabled. Originally, it set it bypass the query processing layer (rewriting, caching) and pass through the query directly as is to the backend server. Users flagged as such 
* frontend - if set to 1, this (username, password) pair is used for authenticating to the ProxySQL instance
* backend - if set to 1, this (username, password) pair is used for authenticating to the mysqld servers against any hostgroup

Note, currently all users need both "frontend" and "backend" set to 1 . Future versions of ProxySQL will separate the crendentials between frontend and backend. In this way frontend will never know the credential to connect directly to the backend, forcing all the connection through ProxySQL and increasing the security of the system.

## `mysql_query_rules`

Here is the statement used to create the `mysql_users` table:

```sql
CREATE TABLE mysql_query_rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0,
    username VARCHAR,
    schemaname VARCHAR,
    flagIN INT NOT NULL DEFAULT 0,
    match_pattern VARCHAR,
    negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0,
    flagOUT INT,
    replace_pattern VARCHAR,
    destination_hostgroup INT DEFAULT NULL,
    cache_ttl INT CHECK(cache_ttl > 0),
    reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL,
    timeout INT UNSIGNED,
    delay INT UNSIGNED,
    apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0
)
```

The fields have the following semantics:
* rule_id - the unique id of the rule. Rules are processed in rule_id order
* active - only rules with active=1 will be considered by the query processing module
* username, schemaname - filtering criteria for the rules. If these are non-NULL, a query will match only if the connection is made with the correct username and/or schemaname.
* flagIN, flagOUT, apply - these allow us to create "chains of rules" that get applied one after the other. An input flag value is set to 0, and only rules with flagIN=0 are considered at the beginning. When a matching rule is found for a specific query, flagOUT is evaluated and if NOT NULL the query will be flagged with the specified flag in flagOUT. If flagOUT differs from flagIN , the query will exit the current chain and enters a new chain of rules having flagIN as the new input flag. This happens until there are no more matching rules, or apply is set to 1 (which means this is the last rule to be applied)
* match_pattern - regular expression that matches the query text. The dialect of regular expressions used is that of re2 - https://github.com/google/re2
* negate_match_pattern - if this is set to 1, only queries not matching the query text will be considered as a match. This acts as a NOT operator in front of the regular expression matching against match_pattern.
* replace_pattern - this is the pattern with which to replace the matched pattern. It's done using RE2::Replace, so it's worth taking a look at the online documentation for that: https://github.com/google/re2/blob/master/re2/re2.h#L378. Note that this is optional, and when this is missing, the query processor will only cache/route this query without rewriting.
* destination_hostgroup - route matched queries to this hostgroup. This happens unless there is a started transaction, and the logged in user has the transaction_persistent flag set to 1 (see `mysql_users` table).
* cache_ttl - the number of seconds for which to cache the result of the query 
* reconnect - feature not used
* timeout - the maximum timeout in milliseconds with which the matched or rewritten query should be executed. If a query run for longer than the specific threshold, the query is automatically killed. If timeout is not specified, global variable mysql-default_query_timeout applies 
* delay - number of milliseconds to delay the execution of the query. This is essentially a throttling mechanism and QoS, allowing to give priority to some queries instead of others. This value is added to the `mysql-default_query_delay` global variable that applies to all queries. Future version of ProxySQL will provide a more advanced throttling mechanism.


## `global_variables`

Here is the statement used to create the `global_variables` table:

```sql
CREATE TABLE global_variables (
    variable_name VARCHAR NOT NULL PRIMARY KEY,
    variable_value VARCHAR NOT NULL
)
```

This is a much simpler table, essentially a key-value store. These are global variables used by ProxySQL and are useful in order to tweak its behaviour.

Global variables are grouped in classes based on their prefix.
Currently there are 2 classes of global variables, although more classes are in the roadmap:
* those whose name begins with `mysql-`. They will tweak the behaviour of MySQL-related features. Examples:
    * `mysql-shun_on_failures` - number of connect failures allowed per second before the backend server is taken out of use temporarily
    * `mysql-max_connections` - maximal number of connections that the proxy
* those whose name begins with `admin-`. They will tweak the behaviour of the admin interface. Examples:
    * `admin-admin_credentials` - double-colon separated username and password for accessing the admin interface with read-write rights
    * `admin-mysql_ifaces` - TCP hostname and port on which to listen for incoming connections for the admin interface

For more information about particular variables, please see the dedicated section on ![global variables][http://todo]

# `mysql_collations`

```CREATE TABLE mysql_collations (
    Id INTEGER NOT NULL PRIMARY KEY,
    Collation VARCHAR NOT NULL,
    Charset VARCHAR NOT NULL,
    `Default` VARCHAR NOT NULL
)```

The available (charset, collation) pairs supported by ProxySQL. In principle, ProxySQL will validate that incoming connections have a supported charset, and will make sure that the pooled backend connections are switched to the correct charset before using them.

Note that all the content of the in-memory tables (main database) are *lost* when ProxySQL is restarted if their content wasn't saved on disk database.

# disk database

The "disk" database has exactly the same tables as the "main" database, with the same semantics. The only major difference is that these tables are stored on disk, instead of being stored in-memory. Whenever ProxySQL is restarted, the in-memory "main" database will be populated starting from this database.

Note that all the content of the in-memory tables (main database) are *lost* when ProxySQL is restarted if their content wasn't saved on disk database.

# stats database

This database contains metrics gathered by ProxySQL with respect to its internal functioning. Here you will find information on how often certain counters get triggered and the execution times of the queries that pass through ProxySQL.

Generally, the tables from this database are populated on the fly when the SQL query against them is ran, by examining in-memory data structures.

Here are the tables from the "stats" database:

```bash
mysql> mysql> show tables from stats;
+--------------------------------+
| tables                         |
+--------------------------------+
| stats_mysql_query_rules        |
| stats_mysql_commands_counters  |
| stats_mysql_processlist        |
| stats_mysql_connection_pool    |
| stats_mysql_query_digest       |
| stats_mysql_query_digest_reset |
| stats_mysql_global             |
+--------------------------------+
7 rows in set (0.00 sec)
```

The purposes of the tables are as follows:
* `stats_mysql_query_rules` - counts how many times each query rule was matched by queries
* `stats_mysql_commands_counters` - counts how many times each type of SQL command was executed (e.g. UPDATE, DELETE, TRUNCATE, etc.) and how much time those executions took
* `stats_mysql_processlist` - a table that simulates the results of the "SHOW PROCESSLIST" mysqld command. This table will contain similar information aggregated across all backends
* `stats_mysql_connection_pool` - a table that contains the statistics related to the usage of the connection pool for each backend server in each hostgroup
* `stats_mysql_query_digest` - a table that contains statistics related to the queries routed through the ProxySQL server. How many times each query was executed, and the total execution time are just several provided stats. Here the queries are stripped from their numerical and literal parameters, which are replaced with a question mark, in order to be able to group all queries of the same type under the same row.
* `stats_mysql_query_digest_reset` - identical to `stats_mysql_query_digest`, but querying it also atomically resets the internal statistics to zero. This can be used, for example, before making a change, to be able to compare the statistics before and after the change. This table can also be queried at regular interval to understand how workload change over time. Since ProxySQL has an internal database, it is also possible to save the result into an internal table.
* `stats_mysql_global` - global statistics such as total number of queries, total number of successful connections, etc. The list of variables is expected to grow in future release.

## `stats_mysql_query_rules`

Here is the statement used to create the `stats_mysql_query_rules` table:

```sql
CREATE TABLE stats_mysql_query_rules (
    rule_id INTEGER PRIMARY KEY,
    hits INT NOT NULL
)
```

The fields have the following semantics:
* rule_id - the id of the rule, can be joined with the `main.mysql_query_rules` table on the `rule_id` field.
* hits - the total number of hits for this rule. One hit is registered if the current incoming query matches the rule. Each time a new query that matches the rule is processed, the number of hits is increased.

## `stats_mysql_commands_counters`

Here is the statement used to create the `stats_mysql_commands_counters` table:

```sql
CREATE TABLE stats_mysql_commands_counters (
    Command VARCHAR NOT NULL PRIMARY KEY,
    Total_Time_us INT NOT NULL,
    Total_cnt INT NOT NULL,
    cnt_100us INT NOT NULL,
    cnt_500us INT NOT NULL,
    cnt_1ms INT NOT NULL,
    cnt_5ms INT NOT NULL,
    cnt_10ms INT NOT NULL,
    cnt_50ms INT NOT NULL,
    cnt_100ms INT NOT NULL,
    cnt_500ms INT NOT NULL,
    cnt_1s INT NOT NULL,
    cnt_5s INT NOT NULL,
    cnt_10s INT NOT NULL,
    cnt_INFs
)
```

The fields have the following semantics:
* command - the type of SQL command that has been executed. Examples: FLUSH, INSERT, KILL, SELECT FOR UPDATE, etc.
* total_time - the total time spent executing commands of that time
* total_cnt - the total number of commands of that type executed
* cnt_100us, cnt_500us, ..., cnt_10s, cnt_INFs - the total number of commands of the given type which executed within the specified time limit and the previous one. For example, cnt_500us is the number of commands which executed within 500 microseconds, but more than 100 microseconds (because there's also a cnt_100us field). cnt_INFs is the number of commands whose execution exceeded 10 seconds.

Note: statistics for table `stats_mysql_commands_counters` are processed only if global variable `mysql-commands_stats` is set to TRUE .

## `stats_mysql_processlist`

Here is the statement used to create the `stats_mysql_processlist` table:

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
    info VARCHAR
)
```

The fields have the following semantics:
* ThreadID - the internal ID of the thread within ProxySQL. This is a 0-based numbering of the threads
* SessionID - the internal global numbering of the ProxySQL sessions, or clients' connections (frontend). It's useful to be able to uniquely identify such a session, for example in order to be able to kill it, or monitor a specific session only.
* user - the user with which the MySQL client connected to ProxySQL in order to execute this query
* db - the schema currently selected
* cli_host, cli_port - the (host, port) pair of the TCP connection between the MySQL client and ProxySQL
* hostgroup - the currenct hostgroup. If a query being processed, this is the hostgroup towards which the query was or will be routed, or the default hostgroup. The routing is done by default in terms of the default destination hostgroup for the username with which the MySQL client connected to ProxySQL (based on `mysql_users` table, but it can be modified on a per-query basis by using the query rules in `mysql_query_rules`
* l_srv_host, l_srv_port - the local (host, part) pair of the TCP connection between ProxySQL and the backend MySQL server from the current hostgroup
* srv_host, srv_port - the (host, port) pair on which the backend MySQL server is listening for TCP connections
* command - the type of MySQL query being executed (the MySQL command verb)
* time_ms - the time in millisecond for which the query has been in the specified command state so far
* info - the actual query being executed

Please note that this is just a snapshot in time of the actual MySQL queries being ran. There is no guarantee that the same queries will be running a fraction of a second later.
Here is how the results look like:

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

**Note:** ProxySQL also support the commands **SHOW PROCESSLIST** and **SHOW FULL PROCESSLIST** to return information related to current sessions.


## `stats_mysql_connection_pool`

Here is the statement used to create the `stats_mysql_connection_pool` table:
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
    Queries INT,
    Bytes_data_sent INT,
    Bytes_data_recv INT
)
```

Each row represents a backend server within a hostgroup. The fields have the following semantics:
* hostgroup - the hostgroup in which the backend server belongs. Note that a single backend server can belong to more than one hostgroup
* srv_host, srv_port - the TCP endpoint on which the mysqld backend server is listening for connections
* status - the status of the backend server. Can be ONLINE, SHUNNED, OFFLINE_SOFT, OFFLINE_HARD. See the description of the `mysql_servers` table above for more details about what each status means
* ConnUsed - how many connections are currently used by ProxySQL for sending queries to the backend server
* ConnFree - how many connections are currently free. They are kept open in order to minimize the time cost of sending a query to the backend server
* ConnOK - how many connections were established successfully.
* ConnERR - how many connections weren't established successfully.
* Queries - the number of queries routed towards this particular backend server
* Bytes_data_sent - the amount of data sent to the backend. This does not include metadata (packets' headers)
* Bytes_data_recv - the amount of data received from the backend. This does not include metadata (packets' headers, OK/ERR packets, fields' description, etc)


## `stats_mysql_query_digest` and `stats_mysql_query_digest_reset`

Here is the statement used to create the `stats_mysql_query_digest` table:

```sql
CREATE TABLE stats_mysql_query_digest (
    schemaname VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    digest VARCHAR NOT NULL,
    digest_text VARCHAR NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    sum_time INTEGER NOT NULL,
    min_time INTEGER NOT NULL,
    max_time INTEGER NOT NULL,
    PRIMARY KEY(schemaname, username, digest)
)
```

Each row represents a class of queries all having the same parameters (but with different values) routed through ProxySQL. Here's how a typical result looks like:

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
* schemaname - the schema that is currently being queried
* username - the username with which the MySQL client connected to ProxySQL
* digest - a hexadecimal hash that uniquely represents a query with its parameters stripped
* digest_text - the actual text with its parameters stripped
* count_star - the total number of times the query has been executed (with different values for the parameters)
* first_seen - unix timestamp, the first moment when the query was routed through the proxy
* last_seen - unix timestamp, the last moment (so far) when the query was routed through the proxy
* sum_time - the total time in microseconds spent executing queries of this type. This is particularly useful to figure out where the most time is spent in your application's workload, and provides a good starting point for where to improve
* min_time, max_time - the range of durations to expect when executing such a query. min_time is the minimal execution time seen so far, while max_time represents the maximal execution time, both in microseconds.

Note that the times in this table refers to the time elapsed between the time in which ProxySQL receives the query from the client, and the time in which ProxySQL is ready to send the query to the client. Therefore these timers represent the elapsted time as close as possible as seen from the client. To be more precise, it is possible that before executing a query, ProxySQL needs to change charset or schema, find a new backend if the current one is not available anymore, run the query on a different backend if the current one fails, or wait a connection to become free because currently all the connection are in use.

**Note:** statistics for table `stats_mysql_query_digest` are processed only if global variable `mysql-query_digests` is set to TRUE .


The `stats_mysql_query_digest_reset` table is identical in content and structure, but querying it also atomically resets the internal statistics to zero.


## `stats_mysql_global`

Here is the statement used to create the `stats_mysql_query_global` table:

```sql
CREATE TABLE stats_mysql_global (
    Variable_Name VARCHAR NOT NULL PRIMARY KEY,
    Variable_Value VARCHAR NOT NULL
)
```

Each row represents a global statistic at the proxy level related to MySQL. Currently, the available variables are:
* Client_Connections_aborted - number of frontend connections aborted due to invalid credential or max_connections reached
* Client_Connections_connected - number of frontend connections currently connected
* Client_Connections_created - number of frontend connections created so far
* Questions - total number of queries sent from frontends
* Slow_queries - number of queries that ran for longer than the threshold in milliseconds defined in global variable `mysql-long_query_time`

The same output is available using the **SHOW MYSQL STATUS** command.

Example:
```bash
mysql> select * from stats.stats_mysql_global;
+------------------------------+----------------+
| Variable_Name                | Variable_Value |
+------------------------------+----------------+
| Client_Connections_aborted   | 0              |
| Client_Connections_connected | 4              |
| Client_Connections_created   | 4              |
| Questions                    | 36337716       |
| Slow_queries                 | 0              |
+------------------------------+----------------+
```
