# Initial Configuration

This guide describes how to configure the basic components of ProxySQL for MySQL step by step. The guide assumes you
understand ProxySQL's overall architecture, that the MySQL client and ProxySQL is already installed on your
operating system with the default configuration and MySQL servers are already running and reachable on the
IP/ports we'll be configuring. ProxySQL's internals can be reconfigured using the standard SQL ProxySQL Admin
interface, accessible via any MySQL command line client (available by default on port 6032):

```
$ mysql -u admin -padmin -h 127.0.0.1 -P6032 --prompt 'ProxySQL Admin> '
```

Verify that the configuration is empty by checking that there are no entries in the `mysql_servers`,
`mysql_replication_hostgroups` and `mysql_query_rules` tables.

```
ProxySQL Admin> SELECT * FROM mysql_servers;
Empty set (0.00 sec)

ProxySQL Admin> SELECT * from mysql_replication_hostgroups;
Empty set (0.00 sec)

ProxySQL Admin> SELECT * from mysql_query_rules;
Empty set (0.00 sec)
```

### Add backends

For the purpose of this guide, 3x MySQL server backends will be configured. This is achieved by adding them to
the `mysql_servers` table. When configuring remote backend MySQL servers it is ONLY required to specify `port`
if it is non-default (i.e. not 3306):

```
ProxySQL Admin> INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES (1,'10.0.0.1',3306);
Query OK, 1 row affected (0.01 sec)

ProxySQL Admin> INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES (1,'10.0.0.2',3306);
Query OK, 1 row affected (0.01 sec)

ProxySQL Admin> INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES (1,'10.0.0.3',3306);
Query OK, 1 row affected (0.00 sec)

ProxySQL Admin> SELECT * FROM mysql_servers;
+--------------+-----------+------+--------+--------+-------------+-----------------+---------------------+
| hostgroup_id | hostname  | port | status | weight | compression | max_connections | max_replication_lag |
+--------------+-----------+------+--------+--------+-------------+-----------------+---------------------+
| 1            | 10.10.0.1 | 3306 | ONLINE | 1      | 0           | 1000            | 0                   |
| 1            | 10.10.0.1 | 3306 | ONLINE | 1      | 0           | 1000            | 0                   |
| 1            | 10.10.0.1 | 3306 | ONLINE | 1      | 0           | 1000            | 0                   |
+--------------+-----------+------+--------+--------+-------------+-----------------+---------------------+
3 rows in set (0.00 sec)
```

_NOTE: The backend MySQL servers have `read_only = 1` configured on all replicas. ProxySQL considers backend
instances with a `read_only = 0` as WRITER instances so this should only be set on your primary MySQL servers
(or all primaries in case of multi-primary replication). Make sure this is properly set by running
`set global read_only = 1` and configuring this in the `my.cnf` file as ProxySQL will make routing decisions
based on this value._

### Configure monitoring

ProxySQL constantly monitors the MySQL server backends configured to identify the health status. The
credentials for monitoring the backends need to be created in MySQL and also configured in ProxySQL along with
the environment specific check intervals. To create the user in MySQL connect to the PRIMARY and execute:

```
mysql> CREATE USER 'monitor'@'%' IDENTIFIED BY 'monitor';
Query OK, 1 row affected (0.00 sec)
```

The user needs only `USAGE` privilege to connect, ping and check `read_only` which is granted by default. The
user needs also `REPLICATION CLIENT` privilege if it needs to monitor replication lag. In this case execute:

```
mysql> GRANT USAGE, REPLICATION CLIENT ON *.* TO 'monitor'@'%';
Query OK, 0 rows affected (0.00 sec)
```

Then add the credentials of the monitor user to ProxySQL:

```
ProxySQL Admin> UPDATE global_variables SET variable_value='monitor' WHERE variable_name='mysql-monitor_username';
Query OK, 1 row affected (0.00 sec)

ProxySQL Admin> UPDATE global_variables SET variable_value='monitor' WHERE variable_name='mysql-monitor_password';
Query OK, 1 row affected (0.00 sec)
```

Then configure the various monitoring intervals:

```
ProxySQL Admin> UPDATE global_variables SET variable_value='2000' WHERE variable_name IN ('mysql-monitor_connect_interval','mysql-monitor_ping_interval','mysql-monitor_read_only_interval');
Query OK, 3 rows affected (0.00 sec)

ProxySQL Admin> SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-monitor_%';
+----------------------------------------+---------------------------------------------------+
| variable_name                          | variable_value                                    |
+----------------------------------------+---------------------------------------------------+
| mysql-monitor_history                  | 600000                                            |
| mysql-monitor_connect_interval         | 2000                                              |
| mysql-monitor_connect_timeout          | 200                                               |
| mysql-monitor_ping_interval            | 2000                                              |
| mysql-monitor_ping_timeout             | 100                                               |
| mysql-monitor_read_only_interval       | 2000                                              |
| mysql-monitor_read_only_timeout        | 100                                               |
| mysql-monitor_replication_lag_interval | 10000                                             |
| mysql-monitor_replication_lag_timeout  | 1000                                              |
| mysql-monitor_username                 | monitor                                           |
| mysql-monitor_password                 | monitor                                           |
| mysql-monitor_query_variables          | SELECT * FROM INFORMATION_SCHEMA.GLOBAL_VARIABLES |
| mysql-monitor_query_status             | SELECT * FROM INFORMATION_SCHEMA.GLOBAL_STATUS    |
| mysql-monitor_query_interval           | 60000                                             |
| mysql-monitor_query_timeout            | 100                                               |
| mysql-monitor_timer_cached             | true                                              |
| mysql-monitor_writer_is_also_reader    | true                                              |
+----------------------------------------+---------------------------------------------------+
17 rows in set (0.00 sec)
```

Changes made to the MySQL Monitor in table `global_variables` will be applied after executing the
`LOAD MYSQL VARIABLES TO RUNTIME` statement. To persist the configuration changes across restarts the
`SAVE MYSQL VARIABLES TO DISK` must also be executed.

```
ProxySQL Admin> LOAD MYSQL VARIABLES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

ProxySQL Admin> SAVE MYSQL VARIABLES TO DISK;
Query OK, 54 rows affected (0.02 sec)
```

### Backend's health check

Once the previous configuration is active, it's time to promote the servers to runtime to enable monitoring:

```
ProxySQL Admin> LOAD MYSQL SERVERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

ProxySQL Admin> SELECT * FROM mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
| 1            | 10.10.0.1 | 3306  | ONLINE | 1      | 0           | 1000            | 0                   |
| 1            | 10.10.0.2 | 3306  | ONLINE | 1      | 0           | 1000            | 0                   |
| 1            | 10.10.0.3 | 3306  | ONLINE | 1      | 0           | 1000            | 0                   |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
3 rows in set (0.00 sec)
```

Once the configuration is active, it's possible to verify the status of the MySQL backends in the `monitor`
database tables in ProxySQL Admin:

```
ProxySQL Admin> SHOW TABLES FROM monitor;
+----------------------------------+
| tables                           |
+----------------------------------+
| mysql_server_connect             |
| mysql_server_connect_log         |
| mysql_server_ping                |
| mysql_server_ping_log            |
| mysql_server_read_only_log       |
| mysql_server_replication_lag_log |
+----------------------------------+
6 rows in set (0.00 sec)
```

Each check type has a dedicated logging table, each should be checked individually:

```
ProxySQL Admin> SELECT * FROM monitor.mysql_server_connect_log ORDER BY time_start_us DESC LIMIT 3;
+-----------+------+------------------+----------------------+---------------+
| hostname  | port | time_start_us    | connect_success_time | connect_error |
+-----------+------+------------------+----------------------+---------------+
| 10.10.0.1 | 3306 | 1456968814253432 | 562                  | NULL          |
| 10.10.0.2 | 3306 | 1456968814253432 | 309                  | NULL          |
| 10.10.0.3 | 3306 | 1456968814253432 | 154                  | NULL          |
+-----------+------+------------------+----------------------+---------------+
3 rows in set (0.00 sec)

ProxySQL Admin> SELECT * FROM monitor.mysql_server_ping_log ORDER BY time_start_us DESC LIMIT 3;
+-----------+------+------------------+-------------------+------------+
| hostname  | port | time_start_us    | ping_success_time | ping_error |
+-----------+------+------------------+-------------------+------------+
| 10.10.0.1 | 3306 | 1456968828686787 | 124               | NULL       |
| 10.10.0.2 | 3306 | 1456968828686787 | 62                | NULL       |
| 10.10.0.3 | 3306 | 1456968828686787 | 57                | NULL       |
+-----------+------+------------------+-------------------+------------+
3 rows in set (0.01 sec)
```

This way we can verify that the servers are being monitored correctly and are healthy.

## MySQL replication hostgroups

Cluster topology changes are monitored based on MySQL replication hostgroups configured in ProxySQL.
ProxySQL
understands the replication topology by monitoring the value of 

`read_only`
on servers configured in hostgroups that are configured in 

`mysql_replication_hostgroups`.


This
table is empty by default and should be configured by specifying a pair of READER and WRITER hostgroups,
although the MySQL backends might all be right now in a single hostgroup. For example:

```
ProxySQL Admin> SHOW CREATE TABLE mysql_replication_hostgroupsG
*************************** 1. row ***************************
       table: mysql_replication_hostgroups
Create Table: CREATE TABLE mysql_replication_hostgroups (
writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,
reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0),
check_type VARCHAR CHECK (LOWER(check_type) IN ('read_only','innodb_read_only','super_read_only','read_only|innodb_read_only','read_only&innodb_read_only')) NOT NULL DEFAULT 'read_only',
comment VARCHAR,
UNIQUE (reader_hostgroup))
1 row in set (0.00 sec)

ProxySQL Admin> INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) VALUES (1,2,'cluster1');
Query OK, 1 row affected (0.00 sec)
```

Now, all the MySQL backend servers that are either configured in hostgroup 1 or 2 will be placed into their
respective hostgroup based on their read_only value:

- If they have `read_only=0` , they will be moved to hostgroup 1
- If they have `read_only=1` , they will be moved to hostgroup 2

<!-- -->

To enable the replication
hostgroup&nbsp;load


`mysql_replication_hostgroups`
to runtime using the same 

`LOAD`
command used for MySQL servers since 

`LOAD MYSQL SERVERS TO RUNTIME`
processes both 

`mysql_servers`
and 

`mysql_replication_hostgroups`
tables.

```
ProxySQL Admin> LOAD MYSQL SERVERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

The `read_only` check results are logged to the `mysql_servers_read_only_log` table in the `monitor` database:

```
ProxySQL Admin> SELECT * FROM monitor.mysql_server_read_only_log ORDER BY time_start_us DESC LIMIT 3;
+-----------+-------+------------------+--------------+-----------+-------+
| hostname  | port  | time_start_us    | success_time | read_only | error |
+-----------+-------+------------------+--------------+-----------+-------+
| 10.10.0.1 | 3306  | 1456969634783579 | 762          | 0         | NULL  |
| 10.10.0.2 | 3306  | 1456969634783579 | 378          | 1         | NULL  |
| 10.10.0.3 | 3306  | 1456969634783579 | 317          | 1         | NULL  |
+-----------+-------+------------------+--------------+-----------+-------+
3 rows in set (0.01 sec)
```

Allright, ProxySQL is monitoring the `read_only` value for the servers. And it also created hostgroup2 to
where it has moved servers with `read_only=1` (readers) from hostgroup1.

```
ProxySQL Admin> SELECT * FROM mysql_servers;
+--------------+-----------+------+--------+--------+-------------+-----------------+---------------------+
| hostgroup_id | hostname  | port | status | weight | compression | max_connections | max_replication_lag |
+--------------+-----------+------+--------+--------+-------------+-----------------+---------------------+
| 1            | 10.10.0.1 | 3306 | ONLINE | 1      | 0           | 1000            | 0                   |
| 2            | 10.10.0.2 | 3306 | ONLINE | 1      | 0           | 1000            | 0                   |
| 2            | 10.10.0.3 | 3306 | ONLINE | 1      | 0           | 1000            | 0                   |
+--------------+-----------+------+--------+--------+-------------+-----------------+---------------------+
3 rows in set (0.00 sec)
```

As a final step, persist the configuration to disk.

```
ProxySQL Admin> SAVE MYSQL SERVERS TO DISK;
Query OK, 0 rows affected (0.01 sec)

ProxySQL Admin> SAVE MYSQL VARIABLES TO DISK;
Query OK, 54 rows affected (0.00 sec)
```

## MySQL Users

After configuring the MySQL server backends in `mysql_servers` the next step is to configure mysql users. For
the purpose of this example, we are creating a MySQL user with no particular restrictions: this is not a good
practice and the user should be configured with proper connection restrictions and privileges according to the
setup and the application needs. To create the user in MySQL connect to the PRIMARY and execute:

```
mysql> CREATE USER 'stnduser'@'%' IDENTIFIED BY 'stnduser';
Query OK, 1 row affected (0.00 sec)
```

Let's grant all privileges to this user. In this case execute:

```
mysql> GRANT ALL PRIVILEGES ON *.* TO 'stnduser'@'%';
Query OK, 0 rows affected (0.00 sec)
```

Time to configure the user into ProxySQL: this is performed by adding entries to the `mysql_users` table:

```
ProxySQL Admin> SHOW CREATE TABLE mysql_usersG
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
transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0,
fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0,
backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1,
frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1,
max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000,
PRIMARY KEY (username, backend),
UNIQUE (username, frontend))
1 row in set (0.00 sec)
```

The table is initially empty, to add users specify the `username`, `password` and `default_hostgroup` for
basic configuration:

```
ProxySQL Admin> INSERT INTO mysql_users(username,password,default_hostgroup) VALUES ('stnduser','stnduser',1);
Query OK, 1 row affected (0.00 sec)

ProxySQL Admin> SELECT * FROM mysql_users;
+----------+----------+--------+---------+-------------------+----------------+---------------+------------------------+--------------+---------+----------+-----------------+
| username | password | active | use_ssl | default_hostgroup | default_schema | schema_locked | transaction_persistent | fast_forward | backend | frontend | max_connections |
+----------+----------+--------+---------+-------------------+----------------+---------------+------------------------+--------------+---------+----------+-----------------+
| stnduser | stnduser | 1      | 0       | 1                 | NULL           | 0             | 0                      | 0            | 1       | 1        | 10000           |
+----------+----------+--------+---------+-------------------+----------------+---------------+------------------------+--------------+---------+----------+-----------------+
1 row in set (0.00 sec)
```

By defining the `default_hostgroup` we are specifying which backend servers a user should connect to BY
DEFAULT (i.e. this will be the default route for traffic coming from the specific user, additional rules can
be configured to re-route however in their absence all queries will go to the specific hostgroup).

```
ProxySQL Admin> LOAD MYSQL USERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
ProxySQL Admin> SAVE MYSQL USERS TO DISK;
Query OK, 0 rows affected (0.01 sec)
```

ProxySQL is now ready to serve traffic on port 6033 (by default):

```bashmysql -u stnduser -pstnduser -h 127.0.0.1 -P6033 -e"SELECT @@port"
Warning: Using a password on the command line interface can be insecure.
+--------+
| @@port |
+--------+
|&nbsp; 3306&nbsp; |
+--------+
```

This query was sent to the server listening on port 3306 , the primary, as this is the server configured on
hostgroup1 and is the default for user `stnduser`.

## Functional tests

Sysbench is a useful tool to verify that ProxySQL is functional and benchmark system performance. Assuming you
have already configured sysbench ([see Sysbench info here](https://github.com/akopytov/sysbench)), you can run
a load test against ProxySQL locally using the following command:

```
sysbench --report-interval=5 --num-threads=4 --num-requests=0 --max-time=20 --test=tests/db/oltp.lua --mysql-user='stnduser' --mysql-password='stnduser' --oltp-table-size=10000 --mysql-host=127.0.0.1 --mysql-port=6033 run

[ output omitted ]
```

_Note: For older versions of sysbench, `report-interval` should be removed and `--db-ps-mode=disable` added._

```
sysbench --num-threads=4 --max-requests=0 --max-time=20 --test=tests/db/oltp.lua --mysql-user='stnduser' --mysql-password='stnduser' --oltp-table-size=10000 --mysql-host=10.10.0.1 --mysql-port=6033 --db-ps-mode=disable run

[ output omitted ]
```

## ProxySQL Statistics, the foundation for Query Rules

ProxySQL collects a lot of real time statistics in the `stats` schema, each table provides specific
information about the behavior of ProxySQL and the workload being processed:

```
ProxySQL Admin> SHOW TABLES FROM stats;
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

### stats_mysql_connection_pool

```
ProxySQL Admin> SELECT * FROM stats.stats_mysql_connection_pool;
+-----------+-----------+----------+--------------+----------+----------+--------+---------+---------+-----------------+-----------------+
| hostgroup | srv_host  | srv_port | status       | ConnUsed | ConnFree | ConnOK | ConnERR | Queries | Bytes_data_sent | Bytes_data_recv |
+-----------+-----------+----------+--------------+----------+----------+--------+---------+---------+-----------------+-----------------+
| 1         | 10.10.0.1 | 3306     | ONLINE       | 0        | 4        | 5      | 0       | 144982  | 7865186         | 278734683       |
| 2         | 10.10.0.1 | 3306     | ONLINE       | 0        | 0        | 0      | 0       | 0       | 0               | 0               |
| 2         | 10.10.0.2 | 3306     | ONLINE       | 0        | 0        | 0      | 0       | 0       | 0               | 0               |
| 2         | 10.10.0.3 | 3306     | ONLINE       | 0        | 0        | 0      | 0       | 0       | 0               | 0               |
+-----------+-----------+----------+--------------+----------+----------+--------+---------+---------+-----------------+-----------------+
4 rows in set (0.00 sec)
```

The `stats_mysql_connection_pool` table shows information related to the MySQL backends and the connection and
overall traffic. The status of each server is tracked based on the health check results. Healthy servers will
have a status of `ONLINE`, servers termporarily removed are `SHUNNED` and when a server is removed (completely
removed, or moved away from a hostgroup), it is internally marked as `OFFLINE_HARD`.

### stats_mysql_commands_counters

The `stats_mysql_commands_counters` table returns detailed information about the type of statements executed,
and the distribution of execution time:

```
ProxySQL Admin> SELECT * FROM stats_mysql_commands_counters WHERE Total_cnt;
+---------+---------------+-----------+-----------+-----------+---------+---------+----------+----------+-----------+-----------+--------+--------+---------+----------+
| Command | Total_Time_us | Total_cnt | cnt_100us | cnt_500us | cnt_1ms | cnt_5ms | cnt_10ms | cnt_50ms | cnt_100ms | cnt_500ms | cnt_1s | cnt_5s | cnt_10s | cnt_INFs |
+---------+---------------+-----------+-----------+-----------+---------+---------+----------+----------+-----------+-----------+--------+--------+---------+----------+
| BEGIN   | 1921940       | 7249      | 4214      | 2106      | 570     | 340     | 14       | 5        | 0         | 0         | 0      | 0      | 0       | 0        |
| COMMIT  | 5986400       | 7249      | 119       | 3301      | 1912    | 1864    | 44       | 8        | 1         | 0         | 0      | 0      | 0       | 0        |
| DELETE  | 2428829       | 7249      | 325       | 5856      | 585     | 475     | 5        | 3        | 0         | 0         | 0      | 0      | 0       | 0        |
| INSERT  | 2260129       | 7249      | 356       | 5948      | 529     | 408     | 6        | 2        | 0         | 0         | 0      | 0      | 0       | 0        |
| SELECT  | 40461204      | 101490    | 12667     | 69530     | 11919   | 6943    | 268      | 149      | 13        | 1         | 0      | 0      | 0       | 0        |
| UPDATE  | 6635032       | 14498     | 333       | 11149     | 1597    | 1361    | 42       | 16       | 0         | 0         | 0      | 0      | 0       | 0        |
+---------+---------------+-----------+-----------+-----------+---------+---------+----------+----------+-----------+-----------+--------+--------+---------+----------+
6 rows in set (0.00 sec)
```

### stats_mysql_query_digest

Query information is tracked in the `stats_mysql_query_digest` which provides query counts per backend,
reponse times per query as well as the actual query text as well as the query digest which is a unique
identifier for every query type:

```
ProxySQL Admin> SELECT * FROM stats_mysql_query_digest ORDER BY sum_time DESC;
+-----------+--------------------+----------+--------------------+----------------------------------------------------------------------+------------+------------+------------+----------+----------+----------+
| hostgroup | schemaname         | username | digest             | digest_text                                                          | count_star | first_seen | last_seen  | sum_time | min_time | max_time |
+-----------+--------------------+----------+--------------------+----------------------------------------------------------------------+------------+------------+------------+----------+----------+----------+
| 1         | sbtest             | stnduser | 0x13781C1DBF001A0C | SELECT c FROM sbtest1 WHERE id=?                                     | 72490      | 1456971810 | 1456971830 | 17732590 | 23       | 58935    |
| 1         | sbtest             | stnduser | 0x704822A0F7D3CD60 | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c | 7249       | 1456971810 | 1456971830 | 9629225  | 20       | 121604   |
| 1         | sbtest             | stnduser | 0xADF3DDF2877EEAAF | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c          | 7249       | 1456971810 | 1456971830 | 6650716  | 26       | 76159    |
| 1         | sbtest             | stnduser | 0x5DBEB0DD695FBF25 | COMMIT                                                               | 7249       | 1456971810 | 1456971830 | 5986400  | 64       | 59229    |
| 1         | sbtest             | stnduser | 0xCCB481C7C198E52B | UPDATE sbtest1 SET k=k+? WHERE id=?                                  | 7249       | 1456971810 | 1456971830 | 3948930  | 44       | 47860    |
| 1         | sbtest             | stnduser | 0x7DD56217AF7A5197 | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?                     | 7249       | 1456971810 | 1456971830 | 3235986  | 22       | 24624    |
| 1         | sbtest             | stnduser | 0xE75DB8313E268CF3 | SELECT SUM(K) FROM sbtest1 WHERE id BETWEEN ? AND ?+?                | 7249       | 1456971810 | 1456971830 | 3211197  | 51       | 29569    |
| 1         | sbtest             | stnduser | 0x5A23CA36FB239BC9 | UPDATE sbtest1 SET c=? WHERE id=?                                    | 7249       | 1456971810 | 1456971830 | 2686102  | 23       | 27779    |
| 1         | sbtest             | stnduser | 0x55319B9EE365BEB5 | DELETE FROM sbtest1 WHERE id=?                                       | 7249       | 1456971810 | 1456971830 | 2428829  | 29       | 11676    |
| 1         | sbtest             | stnduser | 0x10634DACE52A0A02 | INSERT INTO sbtest1 (id, k, c, pad) VALUES (?, ?, ?, ?)              | 7249       | 1456971810 | 1456971830 | 2260129  | 61       | 13711    |
| 1         | sbtest             | stnduser | 0x4760CBDEFAD1519E | BEGIN                                                                | 7249       | 1456971810 | 1456971830 | 1921940  | 30       | 39871    |
| 1         | information_schema | stnduser | 0x9DD5A40E1C46AE52 | SELECT ?                                                             | 1          | 1456970758 | 1456970758 | 1217     | 1217     | 1217     |
| 1         | information_schema | stnduser | 0xA90D80E5831B091B | SELECT @@port                                                        | 1          | 1456970769 | 1456970769 | 273      | 273      | 273      |
| 1         | information_schema | stnduser | 0x52A2BA0B226CD90D | select @@version_comment limit ?                                     | 2          | 1456970758 | 1456970769 | 0        | 0        | 0        |
+-----------+--------------------+----------+--------------------+----------------------------------------------------------------------+------------+------------+------------+----------+----------+----------+
14 rows in set (0.00 sec)
```

Key query information can be filtered out to analyze the core traffic workload with a simple query:

```
ProxySQL Admin> SELECT hostgroup hg, sum_time, count_star, digest_text FROM stats_mysql_query_digest ORDER BY sum_time DESC;
+----+----------+------------+----------------------------------------------------------------------+
| hg | sum_time | count_star | digest_text                                                          |
+----+----------+------------+----------------------------------------------------------------------+
| 1  | 17732590 | 72490      | SELECT c FROM sbtest1 WHERE id=?                                     |
| 1  | 9629225  | 7249       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
| 1  | 6650716  | 7249       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c          |
| 1  | 5986400  | 7249       | COMMIT                                                               |
| 1  | 3948930  | 7249       | UPDATE sbtest1 SET k=k+? WHERE id=?                                  |
| 1  | 3235986  | 7249       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?                     |
| 1  | 3211197  | 7249       | SELECT SUM(K) FROM sbtest1 WHERE id BETWEEN ? AND ?+?                |
| 1  | 2686102  | 7249       | UPDATE sbtest1 SET c=? WHERE id=?                                    |
| 1  | 2428829  | 7249       | DELETE FROM sbtest1 WHERE id=?                                       |
| 1  | 2260129  | 7249       | INSERT INTO sbtest1 (id, k, c, pad) VALUES (?, ?, ?, ?)              |
| 1  | 1921940  | 7249       | BEGIN                                                                |
| 1  | 1217     | 1          | SELECT ?                                                             |
| 1  | 273      | 1          | SELECT @@port                                                        |
| 1  | 0        | 2          | select @@version_comment limit ?                                     |
+----+----------+------------+----------------------------------------------------------------------+
14 rows in set (0.00 sec)
```

In the information provided it is clear that all traffic is sent to the primary instance on hostgroup1, in
order to re-route this workload to a replica in hostgroup2 query rules are required.

## MySQL Query Rules

Query rules are a very powerful vehicle to control traffic passing through ProxySQL and are configured in the
`mysql_query_rules` table:

```
ProxySQL Admin> SHOW CREATE TABLE mysql_query_rulesG
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

To configure ProxySQL to send the top 2 queries to the replica hostgroup2, and everything else to the primary
the following rules would be required required:

```
ProxySQL Admin> INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (10,1,'stnduser','^SELECT c FROM sbtest1 WHERE id=?',2,1);
Query OK, 1 row affected (0.00 sec)

ProxySQL Admin> INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (20,1,'stnduser','DISTINCT c FROM sbtest1',2,1);
Query OK, 1 row affected (0.00 sec)
```

Key points about these query rules (and query rules in general):

- Query rules are processed as ordered by `rule_id`
- Only rules that have `active=1` are processed
- The first rule example uses caret (`^`) and dollar (`$`) : these are special regex characters that mark the
  beginning and the end of a pattern i.e. in this case `match_digest`or`match_pattern` should completely match
  the query
- The second rule in the example doesn't use caret or dollar : the match could be anywhere in the query
- The
  question mark is escaped as it has a special meaning in regex

- `apply=1` means that no further rules should be evaluated if the current rule was matched

<!-- -->

The current rule configuration can be checked in the `mysql_query_rules`, note: this configuration is not yet
active:

```
ProxySQL Admin> SELECT match_digest,destination_hostgroup FROM mysql_query_rules WHERE active=1 AND username='stnduser' ORDER BY rule_id;
+-------------------------------------+-----------------------+
| match_digest                        | destination_hostgroup |
+-------------------------------------+-----------------------+
| ^SELECT c FROM sbtest1 WHERE id=?$ | 2                     |
| DISTINCT c FROM sbtest1             | 2                     |
+-------------------------------------+-----------------------+
2 rows in set (0.00 sec)
```

For these 2 specific rules, queries will be sent to slaves. If no rules match the query, the
`default_hostgroup` configured for the user applies (that is 1 for user stnduser).
The


`stats_mysql_query_digest_reset`
can be queried to retrieve the previous workload and clear the contents of the 

`stats_mysql_query_digest`
table , and truncate it, this is recommended before activating query rules to easily review the
changes.

Load the query rules to runtime to activate changes :

```
ProxySQL Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

After
traffic passes through the new configuration the 

`stats_mysql_query_digest`
will reflect the changes in routing per query:

```
ProxySQL Admin> SELECT hostgroup hg, sum_time, count_star, digest_text FROM stats_mysql_query_digest ORDER BY sum_time DESC;
+----+----------+------------+----------------------------------------------------------------------+
| hg | sum_time | count_star | digest_text                                                          |
+----+----------+------------+----------------------------------------------------------------------+
<strong>| 2  | 14520738 | 50041      | SELECT c FROM sbtest1 WHERE id=?                                     |
| 2  | 3203582  | 5001       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |</strong>
| 1  | 3142041  | 5001       | COMMIT                                                               |
| 1  | 2270931  | 5001       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c          |
| 1  | 2021320  | 5003       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?                     |
| 1  | 1768748  | 5001       | UPDATE sbtest1 SET k=k+? WHERE id=?                                  |
| 1  | 1697175  | 5003       | SELECT SUM(K) FROM sbtest1 WHERE id BETWEEN ? AND ?+?                |
| 1  | 1346791  | 5001       | UPDATE sbtest1 SET c=? WHERE id=?                                    |
| 1  | 1263259  | 5001       | DELETE FROM sbtest1 WHERE id=?                                       |
| 1  | 1191760  | 5001       | INSERT INTO sbtest1 (id, k, c, pad) VALUES (?, ?, ?, ?)              |
| 1  | 875343   | 5005       | BEGIN                                                                |
+----+----------+------------+----------------------------------------------------------------------+
11 rows in set (0.00 sec)
```

The top 2 queries identified are sent to the hostgroup2 replicas. Aggregated results can also be viewed in the
`stats_mysql_query_digest` table, for example:

```
ProxySQL Admin> SELECT hostgroup hg, SUM(sum_time), SUM(count_star) FROM stats_mysql_query_digest GROUP BY hostgroup;
+----+---------------+-----------------+
| hg | SUM(sum_time) | SUM(count_star) |
+----+---------------+-----------------+
| 1  | 21523008      | 59256           |
| 2  | 23915965      | 72424           |
+----+---------------+-----------------+
2 rows in set (0.00 sec)
```

## Query Caching

A popular use-case for ProxySQL is to act as a query cache. By default, queries aren't cached, this is enabled
by setting `cache_ttl` (in milliseconds) on a rule defined in `mysql_query_rules` . To cache all the queries
sent to replicas for 5 seconds update the cache_ttl on the query rules defined in the previous example:

```
ProxySQL Admin> UPDATE mysql_query_rules set cache_ttl=5000 WHERE active=1 AND destination_hostgroup=2;
Query OK, 2 rows affected (0.00 sec)

ProxySQL Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

ProxySQL Admin> SELECT 1 FROM stats_mysql_query_digest_reset LIMIT 1; -- we reset the counters
+---+
| 1 |
+---+
| 1 |
+---+
1 row in set (0.00 sec)
```

After
traffic passes through the new configuration the stats_mysql_query_digest will show the cached
queries with a hostgroup value of "-1":

```
ProxySQL Admin> SELECT hostgroup hg, sum_time, count_star, digest_text FROM stats_mysql_query_digest ORDER BY sum_time DESC;
+----+----------+------------+----------------------------------------------------------------------+
| hg | sum_time | count_star | digest_text                                                          |
+----+----------+------------+----------------------------------------------------------------------+
| 1  | 7457441  | 5963       | COMMIT                                                               |
| 1  | 6767681  | 5963       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c          |
| 2  | 4891464  | 8369       | SELECT c FROM sbtest1 WHERE id=?                                     |
| 1  | 4573513  | 5963       | UPDATE sbtest1 SET k=k+? WHERE id=?                                  |
| 1  | 4531319  | 5963       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?                     |
| 1  | 3993283  | 5963       | SELECT SUM(K) FROM sbtest1 WHERE id BETWEEN ? AND ?+?                |
| 1  | 3482242  | 5963       | UPDATE sbtest1 SET c=? WHERE id=?                                    |
| 1  | 3209088  | 5963       | DELETE FROM sbtest1 WHERE id=?                                       |
| 1  | 2959358  | 5963       | INSERT INTO sbtest1 (id, k, c, pad) VALUES (?, ?, ?, ?)              |
| 1  | 2415318  | 5963       | BEGIN                                                                |
| 2  | 2266662  | 1881       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
<strong>| -1 | 0        | 4082       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
| -1 | 0        | 51261      | SELECT c FROM sbtest1 WHERE id=?                                     |</strong>
+----+----------+------------+----------------------------------------------------------------------+
13 rows in set (0.00 sec)
```

## Query Rewrite

To match the text of a query ProxySQL provides 2 mechanisms:

- `match_digest` : match the regular expression against the digest of the query which strips SQL query data
  (e.g. \`SELECT c FROM sbtest1 WHERE id=?\` as represented in `stats_mysql_query_digest.query_digest`
- `match_pattern` : match the regular expression against the actual text of the query (e.g. \`SELECT c FROM
  sbtest1 WHERE id=2\`

<!-- -->

The
digest is always smaller than the query itself, running a regex against a smaller string is faster and it is
recommended (for performance) to use 

`match_digest`.


To rewrite queries or match against the query text itself use `match_pattern`. For example:

```
ProxySQL Admin> INSERT INTO mysql_query_rules (rule_id,active,username,match_pattern,replace_pattern,apply) VALUES (30,1,'stnduser','DISTINCT(.*)ORDER BY c','DISTINCT1',1);
Query OK, 1 row affected (0.00 sec)


ProxySQL Admin> SELECT rule_id, match_digest, match_pattern, replace_pattern, cache_ttl, apply FROM mysql_query_rules ORDER BY rule_id;
+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| rule_id | match_digest                        | match_pattern          | replace_pattern | cache_ttl | apply |
+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| 10      | ^SELECT c FROM sbtest1 WHERE id=?$  | NULL                   | NULL            | 5000      | 1     |
| 20      | DISTINCT c FROM sbtest1             | NULL                   | NULL            | 5000      | 1     |
| 30      | NULL                                | DISTINCT(.*)ORDER BY c | DISTINCT1       | NULL      | 1     |
+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
3 rows in set (0.00 sec)

ProxySQL Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

This configuration would result in the following behavior:

```
ProxySQL Admin> SELECT hits, mysql_query_rules.rule_id, match_digest, match_pattern, replace_pattern, cache_ttl, apply FROM mysql_query_rules NATURAL JOIN stats.stats_mysql_query_rules ORDER BY mysql_query_rules.rule_id;
+-------+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| hits  | rule_id | match_digest                        | match_pattern          | replace_pattern | cache_ttl | apply |
+-------+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| 48560 | 10      | ^SELECT c FROM sbtest1 WHERE id=?   | NULL                   | NULL            | 5000      | 1     |
| 4856  | 20      | DISTINCT c FROM sbtest1             | NULL                   | NULL            | 5000      | 0     |
| 4856  | 30      | NULL                                | DISTINCT(.*)ORDER BY c | DISTINCT1       | NULL      | 1     |
+-------+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
3 rows in set (0.01 sec)
```

##### Feel confident to move on to more advanced configuration, here is a link on **[How to set up ProxySQL Read/Write Split](https://proxysql.com/documentation/proxysql-read-write-split-howto/)**

