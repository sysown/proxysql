# Mini HOW TO on ProxySQL Configuration

This mini HOWTO described how to configure some of the component of ProxySQL step by step.
_This is not an complete guide_.

We assume you are already aware of ProxySQL architecture, and this HOWTO assumes that ProxySQL is being reconfigured using the stardard SQL admin interface, available by default connecting to port 6032 using trivial (changable) credentials:

```
$ mysql -u admin -padmin -h 127.0.0.1 -P6032
```

First, let's verify that there is nothing configured. No entries in `mysql_servers`, nor in `mysql_replication_hostgroups` or `mysql_query_rules` tables.

``` sql
mysql> \R Admin>
PROMPT set to 'Admin> '
Admin> SELECT * FROM mysql_servers;
Empty set (0.00 sec)

Admin> SELECT * from mysql_replication_hostgroups;
Empty set (0.00 sec)

Admin> SELECT * from mysql_query_rules;
Empty set (0.00 sec)
```

### Add backends

For this demo, I started 3 mysql servers locally using MySQL Sandbox.
Let’s add them to ProxySQL.

``` sql
Admin> INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES (1,'127.0.0.1',21891);
Query OK, 1 row affected (0.01 sec)

Admin> INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES (1,'127.0.0.1',21892);
Query OK, 1 row affected (0.01 sec)

Admin> INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES (1,'127.0.0.1',21893);
Query OK, 1 row affected (0.00 sec)

Admin> SELECT * FROM mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
| 1            | 127.0.0.1 | 21891 | ONLINE | 1      | 0           | 1000            | 0                   |
| 1            | 127.0.0.1 | 21892 | ONLINE | 1      | 0           | 1000            | 0                   |
| 1            | 127.0.0.1 | 21893 | ONLINE | 1      | 0           | 1000            | 0                   |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
3 rows in set (0.00 sec)
```

All looks good so far.

> NOTE: By default, MySQL sandbox will set read_only = 0 on slaves. Set `set global read_only = 1` on the slaves.


### Configure monitoring

ProxySQL constantly monitors the servers it has configured. To do so, it is important to configure some variables.
Let’s configure them.

Add the credentials of the users required to monitor the backend (the user needs to be already created in mysql server):

``` sql
Admin> UPDATE global_variables SET variable_value='monitor' WHERE variable_name='mysql-monitor_username';
Query OK, 1 row affected (0.00 sec)

Admin> UPDATE global_variables SET variable_value='monitor' WHERE variable_name='mysql-monitor_password';
Query OK, 1 row affected (0.00 sec)
```

Then we configure the various monitoring intervals:

``` sql
Admin> UPDATE global_variables SET variable_value='2000' WHERE variable_name IN ('mysql-monitor_connect_interval','mysql-monitor_ping_interval','mysql-monitor_read_only_interval');
Query OK, 3 rows affected (0.00 sec)

Admin> SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-monitor_%';
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

There are a lot of variables, and some are not used (yet) or not relevant for this howto. For now consider only the ones I listed before.
Changes related to MySQL Monitor in table `global_variables` take places only after running the command `LOAD MYSQL VARIABLES TO RUNTIME`, and they are permanently stored to disk after running `SAVE MYSQL VARIABLES TO DISK` .
Details [here](https://github.com/sysown/proxysql/blob/v1.1.1/doc/configuration_system.md) .

``` sql
Admin> LOAD MYSQL VARIABLES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

Admin> SAVE MYSQL VARIABLES TO DISK;
Query OK, 54 rows affected (0.02 sec)
```

### Backend's health check

Now, let’s see if ProxySQL is able to communicate with these hosts.
ProxySQL has several tables where stores monitoring information.

``` sql
Admin> SHOW DATABASES;
+-----+---------+-------------------------------+
| seq | name    | file                          |
+-----+---------+-------------------------------+
| 0   | main    |                               |
| 2   | disk    | /var/lib/proxysql/proxysql.db |
| 3   | stats   |                               |
| 4   | monitor |                               |
+-----+---------+-------------------------------+
4 rows in set (0.00 sec)

Admin> SHOW TABLES FROM monitor;
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

Not all the tables in monitor are currently used.
For now we can check the relevant tables with the follow queries:

``` sql
Admin> SELECT * FROM monitor.mysql_server_connect_log ORDER BY time_start_us DESC LIMIT 10;
+-----------+-------+------------------+----------------------+---------------+
| hostname  | port  | time_start_us       | connect_success_time | connect_error |
+-----------+-------+------------------+----------------------+---------------+
| 127.0.0.1 | 21891 | 1456968814253432 | 562                  | NULL          |
| 127.0.0.1 | 21892 | 1456968814253432 | 309                  | NULL          |
| 127.0.0.1 | 21893 | 1456968814253432 | 154                  | NULL          |
| 127.0.0.1 | 21891 | 1456968812252146 | 689                  | NULL          |
| 127.0.0.1 | 21892 | 1456968812252146 | 424                  | NULL          |
| 127.0.0.1 | 21893 | 1456968812252146 | 174                  | NULL          |
| 127.0.0.1 | 21891 | 1456968810251585 | 569                  | NULL          |
| 127.0.0.1 | 21892 | 1456968810251585 | 316                  | NULL          |
| 127.0.0.1 | 21893 | 1456968810251585 | 155                  | NULL          |
| 127.0.0.1 | 21891 | 1456968808250762 | 570                  | NULL          |
+-----------+-------+------------------+----------------------+---------------+
10 rows in set (0.00 sec)

Admin> SELECT * FROM monitor.mysql_server_ping_log ORDER BY time_start_us DESC LIMIT 10;
+-----------+-------+------------------+-------------------+------------+
| hostname  | port  | time_start_us       | ping_success_time | ping_error |
+-----------+-------+------------------+-------------------+------------+
| 127.0.0.1 | 21891 | 1456968828686787 | 124               | NULL       |
| 127.0.0.1 | 21892 | 1456968828686787 | 62                | NULL       |
| 127.0.0.1 | 21893 | 1456968828686787 | 57                | NULL       |
| 127.0.0.1 | 21891 | 1456968826686385 | 99                | NULL       |
| 127.0.0.1 | 21892 | 1456968826686385 | 46                | NULL       |
| 127.0.0.1 | 21893 | 1456968826686385 | 42                | NULL       |
| 127.0.0.1 | 21891 | 1456968824685162 | 135               | NULL       |
| 127.0.0.1 | 21892 | 1456968824685162 | 61                | NULL       |
| 127.0.0.1 | 21893 | 1456968824685162 | 57                | NULL       |
| 127.0.0.1 | 21891 | 1456968822684689 | 215               | NULL       |
+-----------+-------+------------------+-------------------+------------+
10 rows in set (0.01 sec)
```

We can conclude that all of the configured servers are healthy.
One important thing to note here is that monitoring on connect and ping is performed based on the content of the table `mysql_servers`, even before this is loaded to RUNTIME. This approach is intentional: in this way it is possible to perform basic health checks before adding the nodes in production.

Now that we know that the servers are correctly monitored and alive, let’s enable them.

``` sql
Admin> LOAD MYSQL SERVERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

Admin> SELECT * FROM mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
| 1            | 127.0.0.1 | 21891 | ONLINE | 1      | 0           | 1000            | 0                   |
| 1            | 127.0.0.1 | 21892 | ONLINE | 1      | 0           | 1000            | 0                   |
| 1            | 127.0.0.1 | 21893 | ONLINE | 1      | 0           | 1000            | 0                   |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
3 rows in set (0.00 sec)
```


## MySQL replication hostgroups

Let's check another table in the monitor schema , `monitor.mysql_server_read_only_log`:

``` sql
Admin> SELECT * FROM monitor.mysql_server_read_only_log ORDER BY time_start_us DESC LIMIT 10;
Empty set (0.00 sec)
```

This table is currently empty.
The reason is that ProxySQL checks the value of `read_only` only for servers configured in hostgroups that are configured in `mysql_replication_hostgroups`. This table is currently empty:

``` sql
Admin> SELECT * FROM mysql_replication_hostgroups;
Empty set (0.00 sec)
```

But what is the functionality of this table?
With this table, the listed hostgroups can be configured in pairs of writer and reader hostgroups.
ProxySQL will monitor the value of `read_only` for all the servers in specified hostgroups, and based on the value of `read_only` will assign the server to the writer or reader hostgroups.
To make an example:

``` sql
Admin> SHOW CREATE TABLE mysql_replication_hostgroups\G
*************************** 1. row ***************************
       table: mysql_replication_hostgroups
Create Table: CREATE TABLE mysql_replication_hostgroups (
writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,
reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0),
comment VARCHAR,
UNIQUE (reader_hostgroup))
1 row in set (0.00 sec)

Admin> INSERT INTO mysql_replication_hostgroups VALUES (1,2,'group comment');
Query OK, 1 row affected (0.00 sec)
```

Now, all the servers that are either configured in hostgroup 1 or 2 will be moved to the correct hostgroup:
* If they have `read_only=0` , they will be moved to hostgroup 1
* If they have `read_only=1` , they will be moved to hostgroup 2

But at this moment, the algorithm is still not running, because the new table isn't loaded at runtime. In fact:

``` sql
Admin> SELECT * FROM mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
| 1            | 127.0.0.1 | 21891 | ONLINE | 1      | 0           | 1000            | 0                   |
| 1            | 127.0.0.1 | 21892 | ONLINE | 1      | 0           | 1000            | 0                   |
| 1            | 127.0.0.1 | 21893 | ONLINE | 1      | 0           | 1000            | 0                   |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
3 rows in set (0.00 sec)
```

Let's load `mysql_replication_hostgroups` at runtime using the same `LOAD` command for MYSQL SERVERS : in fact `LOAD MYSQL SERVERS TO RUNTIME` processes both `mysql_servers` and `mysql_replication_hostgroups` tables.

``` sql
Admin> LOAD MYSQL SERVERS TO RUNTIME;                                                                                                              Query OK, 0 rows affected (0.00 sec)
```

Wait few seconds, and check again the status:

``` sql
Admin> SELECT * FROM monitor.mysql_server_read_only_log ORDER BY time_start_us DESC LIMIT 10;                                                         +-----------+-------+------------------+--------------+-----------+-------+
| hostname  | port  | time_start_us       | success_time | read_only | error |
+-----------+-------+------------------+--------------+-----------+-------+
| 127.0.0.1 | 21891 | 1456969634783579 | 762          | 0         | NULL  |
| 127.0.0.1 | 21892 | 1456969634783579 | 378          | 1         | NULL  |
| 127.0.0.1 | 21893 | 1456969634783579 | 317          | 1         | NULL  |
| 127.0.0.1 | 21891 | 1456969632783364 | 675          | 0         | NULL  |
| 127.0.0.1 | 21892 | 1456969632783364 | 539          | 1         | NULL  |
| 127.0.0.1 | 21893 | 1456969632783364 | 550          | 1         | NULL  |
| 127.0.0.1 | 21891 | 1456969630783159 | 493          | 0         | NULL  |
| 127.0.0.1 | 21892 | 1456969630783159 | 626          | 1         | NULL  |
| 127.0.0.1 | 21893 | 1456969630783159 | 572          | 1         | NULL  |
| 127.0.0.1 | 21891 | 1456969628782328 | 433          | 0         | NULL  |
+-----------+-------+------------------+--------------+-----------+-------+
10 rows in set (0.01 sec)
```

Allright, ProxySQL is monitoring the `read_only` value for the servers.
And also created hostgroup2 where it moved servers with `read_only=1` (readers) from hostgroup1 .

``` sql
Admin> SELECT * FROM mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
| 1            | 127.0.0.1 | 21891 | ONLINE | 1      | 0           | 1000            | 0                   |
| 2            | 127.0.0.1 | 21892 | ONLINE | 1      | 0           | 1000            | 0                   |
| 2            | 127.0.0.1 | 21893 | ONLINE | 1      | 0           | 1000            | 0                   |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+
3 rows in set (0.00 sec)
```


All looks good. It is time to save the configuration to disk:

``` sql
Admin> SAVE MYSQL SERVERS TO DISK;
Query OK, 0 rows affected (0.01 sec)

Admin> SAVE MYSQL VARIABLES TO DISK;
Query OK, 54 rows affected (0.00 sec)
```


## MySQL Users

After we configure the servers in `mysql_servers`, we also need to configure mysql users.
This is performed using table `mysql_users`:

``` sql
Admin> SELECT * FROM mysql_users;
Empty set (0.00 sec)

Admin> SHOW CREATE TABLE mysql_users\G
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

Table is initially empty.
Let's start configuring users.

``` sql
Admin> INSERT INTO mysql_users(username,password,default_hostgroup) VALUES ('root','',1);
Query OK, 1 row affected (0.00 sec)

Admin> INSERT INTO mysql_users(username,password,default_hostgroup) VALUES ('msandbox','msandbox',1);
Query OK, 1 row affected (0.00 sec)

Admin> SELECT * FROM mysql_users;                                                                                                                      +----------+----------+--------+---------+-------------------+----------------+---------------+------------------------+--------------+---------+----------+-----------------+
| username | password | active | use_ssl | default_hostgroup | default_schema | schema_locked | transaction_persistent | fast_forward | backend | frontend | max_connections |
+----------+----------+--------+---------+-------------------+----------------+---------------+------------------------+--------------+---------+----------+-----------------+
| root     |          | 1      | 0       | 1                 | NULL           | 0             | 0                      | 0            | 1       | 1        | 10000           |
| msandbox | msandbox | 1      | 0       | 1                 | NULL           | 0             | 0                      | 0            | 1       | 1        | 10000           |
+----------+----------+--------+---------+-------------------+----------------+---------------+------------------------+--------------+---------+----------+-----------------+
2 rows in set (0.00 sec)
```

We left most fields with the default value. The most important fields we configured are :
* `username`
* `password`
* `default_hostgroup`

The meaning of `username` and `password` should be very clear.
`default_hostgroup` is the hostgroup that will be used to send traffic generated by that specific user if there is no matching query rules for a specific query (more details later on).


Again, load configuration to runtime to make it live, and save it to disk to make it persistent across restart.

``` sql
Admin> LOAD MYSQL USERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

Admin> SAVE MYSQL USERS TO DISK;
Query OK, 0 rows affected (0.01 sec)
```

We can now try to connect from a different terminal:

```
vagrant@ubuntu-14:~$ mysql -u msandbox -pmsandbox -h 127.0.0.1 -P6033 -e "SELECT 1"
Warning: Using a password on the command line interface can be insecure.
+---+
| 1 |
+---+
| 1 |
+---+
vagrant@ubuntu-14:~$ mysql -u msandbox -pmsandbox -h 127.0.0.1 -P6033 -e "SELECT @@port"
Warning: Using a password on the command line interface can be insecure.
+--------+
| @@port |
+--------+
|  21891 |
+--------+
```

It seems it worked, and not surprisingly the query was sent to the server listening on port 21891, the master, because it is configured on hostgroup1 and is the default for user msandbox.



## Functional tests

Now we can try some "benchmark" to verify that ProxySQL is functional.

Assuming you already created sysbench table, you can run a load test using:

```
vagrant@ubuntu-14:~/sysbench/sysbench-0.5/sysbench$ ./sysbench --report-interval=5 --num-threads=4 --num-requests=0 --max-time=20 --test=tests/db/oltp.lua --mysql-user='msandbox' --mysql-password='msandbox' --oltp-table-size=10000 --mysql-host=127.0.0.1 --mysql-port=6033 run

[ output omitted ]
```

All run correctly through ProxySQL . Does ProxySQL exports metrics about what was running? Yes...

> For older versions of sysbench, `report-interval` should be removed and `--db-ps-mode=disable` added.

```
sysbench --num-threads=4 --max-requests=0 --max-time=20 --test=tests/db/oltp.lua --mysql-user='msandbox' --mysql-password='msandbox' --oltp-table-size=10000 --mysql-host=127.0.0.1 --mysql-port=6033 --db-ps-mode=disable run

[ output omitted ]
```


## ProxySQL Statistics

ProxySQL collects a lot of real time statistics in the `stats` schema:

``` sql
Admin> SHOW SCHEMAS;
+-----+---------+-------------------------------+
| seq | name    | file                          |
+-----+---------+-------------------------------+
| 0   | main    |                               |
| 2   | disk    | /var/lib/proxysql/proxysql.db |
| 3   | stats   |                               |
| 4   | monitor |                               |
+-----+---------+-------------------------------+
4 rows in set (0.00 sec)

Admin> SHOW TABLES FROM stats;
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

A lot of tables are present the stats schema. We will analyze the all.

#### stats.stats_mysql_connection_pool

``` sql
Admin> SELECT * FROM stats.stats_mysql_connection_pool;
+-----------+-----------+----------+--------------+----------+----------+--------+---------+---------+-----------------+-----------------+
| hostgroup | srv_host  | srv_port | status       | ConnUsed | ConnFree | ConnOK | ConnERR | Queries | Bytes_data_sent | Bytes_data_recv |
+-----------+-----------+----------+--------------+----------+----------+--------+---------+---------+-----------------+-----------------+
| 1         | 127.0.0.1 | 21891    | ONLINE       | 0        | 4        | 5      | 0       | 144982  | 7865186         | 278734683       |
| 1         | 127.0.0.1 | 21892    | OFFLINE_HARD | 0        | 0        | 0      | 0       | 0       | 0               | 0               |
| 2         | 127.0.0.1 | 21893    | ONLINE       | 0        | 0        | 0      | 0       | 0       | 0               | 0               |
| 2         | 127.0.0.1 | 21892    | ONLINE       | 0        | 0        | 0      | 0       | 0       | 0               | 0               |
+-----------+-----------+----------+--------------+----------+----------+--------+---------+---------+-----------------+-----------------+
4 rows in set (0.00 sec)
```

A small parenthesis: currently, when a server is removed (completely removed, or moved away from a hostgroup) , it is internally marked as `OFFLINE_HARD` and not really removed.
This is why it shows server on port 21892 as `OFFLINE_HARD` for hostgroup1 .

This table returns a lot of information about the traffic sent to each server.
As expected, all traffic was sent to server on port 21891 , the master.

#### stats_mysql_commands_counters

What type of queries were exactly? Table `stats_mysql_commands_counters` anwswers this question:
``` sql
Admin> SELECT * FROM stats_mysql_commands_counters WHERE Total_cnt;
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

Table `stats_mysql_commands_counters` returns detailed information about the type of statements executed, and the distribution of execution time!

### stats_mysql_query_digest

Table `stats_mysql_commands_counters` provides very useful information.
Can we get more details about the query that were executed? Table `stats_mysql_query_digest` helps in this:

``` sql
Admin> SELECT * FROM stats_mysql_query_digest ORDER BY sum_time DESC;
+-----------+--------------------+----------+--------------------+----------------------------------------------------------------------+------------+------------+------------+----------+----------+----------+
| hostgroup | schemaname         | username | digest             | digest_text                                                          | count_star | first_seen | last_seen  | sum_time | min_time | max_time |
+-----------+--------------------+----------+--------------------+----------------------------------------------------------------------+------------+------------+------------+----------+----------+----------+
| 1         | sbtest             | msandbox | 0x13781C1DBF001A0C | SELECT c FROM sbtest1 WHERE id=?                                     | 72490      | 1456971810 | 1456971830 | 17732590 | 23       | 58935    |
| 1         | sbtest             | msandbox | 0x704822A0F7D3CD60 | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c | 7249       | 1456971810 | 1456971830 | 9629225  | 20       | 121604   |
| 1         | sbtest             | msandbox | 0xADF3DDF2877EEAAF | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c          | 7249       | 1456971810 | 1456971830 | 6650716  | 26       | 76159    |
| 1         | sbtest             | msandbox | 0x5DBEB0DD695FBF25 | COMMIT                                                               | 7249       | 1456971810 | 1456971830 | 5986400  | 64       | 59229    |
| 1         | sbtest             | msandbox | 0xCCB481C7C198E52B | UPDATE sbtest1 SET k=k+? WHERE id=?                                  | 7249       | 1456971810 | 1456971830 | 3948930  | 44       | 47860    |
| 1         | sbtest             | msandbox | 0x7DD56217AF7A5197 | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?                     | 7249       | 1456971810 | 1456971830 | 3235986  | 22       | 24624    |
| 1         | sbtest             | msandbox | 0xE75DB8313E268CF3 | SELECT SUM(K) FROM sbtest1 WHERE id BETWEEN ? AND ?+?                | 7249       | 1456971810 | 1456971830 | 3211197  | 51       | 29569    |
| 1         | sbtest             | msandbox | 0x5A23CA36FB239BC9 | UPDATE sbtest1 SET c=? WHERE id=?                                    | 7249       | 1456971810 | 1456971830 | 2686102  | 23       | 27779    |
| 1         | sbtest             | msandbox | 0x55319B9EE365BEB5 | DELETE FROM sbtest1 WHERE id=?                                       | 7249       | 1456971810 | 1456971830 | 2428829  | 29       | 11676    |
| 1         | sbtest             | msandbox | 0x10634DACE52A0A02 | INSERT INTO sbtest1 (id, k, c, pad) VALUES (?, ?, ?, ?)              | 7249       | 1456971810 | 1456971830 | 2260129  | 61       | 13711    |
| 1         | sbtest             | msandbox | 0x4760CBDEFAD1519E | BEGIN                                                                | 7249       | 1456971810 | 1456971830 | 1921940  | 30       | 39871    |
| 1         | information_schema | msandbox | 0x9DD5A40E1C46AE52 | SELECT ?                                                             | 1          | 1456970758 | 1456970758 | 1217     | 1217     | 1217     |
| 1         | information_schema | msandbox | 0xA90D80E5831B091B | SELECT @@port                                                        | 1          | 1456970769 | 1456970769 | 273      | 273      | 273      |
| 1         | information_schema | msandbox | 0x52A2BA0B226CD90D | select @@version_comment limit ?                                     | 2          | 1456970758 | 1456970769 | 0        | 0        | 0        |
+-----------+--------------------+----------+--------------------+----------------------------------------------------------------------+------------+------------+------------+----------+----------+----------+
14 rows in set (0.00 sec)
```

Too much information makes it hard to format it here.
Let get only important metrics:

``` sql
Admin> SELECT hostgroup hg, sum_time, count_star, digest_text FROM stats_mysql_query_digest ORDER BY sum_time DESC;
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

All traffic is sent to hostgroup1. Let's assume that now we want to send specific queries to slaves...


## MySQL Query Rules

Table `mysql_query_rules` has a lot of fields and it is a very powerful vehicle to control the traffic passing through ProxySQL.
Its table definition is as follows:

``` sql
Admin> SHOW CREATE TABLE mysql_query_rules\G
*************************** 1. row ***************************
       table: mysql_query_rules
Create Table: CREATE TABLE mysql_query_rules (
rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0,
username VARCHAR,
schemaname VARCHAR,
flagIN INT NOT NULL DEFAULT 0,
match_digest VARCHAR,
match_pattern VARCHAR,
negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0,
flagOUT INT,
replace_pattern VARCHAR,
destination_hostgroup INT DEFAULT NULL,
cache_ttl INT CHECK(cache_ttl > 0),
reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL,
timeout INT UNSIGNED,
delay INT UNSIGNED,
error_msg VARCHAR,
apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0)
1 row in set (0.01 sec)
```

We can now configure ProxySQL to send the top 2 queries to slaves, and everything else to the masters

``` sql
Admin> INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (10,1,'msandbox','^SELECT c FROM sbtest1 WHERE id=\?$',2,1);
Query OK, 1 row affected (0.00 sec)

Admin> INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (20,1,'msandbox','DISTINCT c FROM sbtest1',2,1);
Query OK, 1 row affected (0.00 sec)
```

Few notes:
* query rules are processed ordered by `rule_id`
* only rules that have `active=1` are processed. Because query rules are a very powerful tool and if misconfigured can lead to difficult debugging (we all love regex, right?) , by default active is 0 (`active=0`) . You should double check rules regexes before enabling them!
* the first rule example uses caret (`^`) and dollar (`$`) : these are special regex characters that mark the beginning and the end of a pattern. In that case it means that `match_digest` or `match_pattern` should completely match the query
* by contrast of the first rule example, the second rule example doesn't use caret or dollar : the match could be anywhere in the query
* pay a lot of attention to regex to avoid that some rule matches what it shouldn't !
* you probably notice that the question mark is escaped. It has a special meaning in regex, so as said, pay really a lot of attention to regex syntax !
* `apply=1` means that no further rules are checked if there is a match

Table `mysql_query_rules` looks like:

``` sql
Admin> SELECT match_digest,destination_hostgroup FROM mysql_query_rules WHERE active=1 AND username='msandbox' ORDER BY rule_id;
+-------------------------------------+-----------------------+
| match_digest                        | destination_hostgroup |
+-------------------------------------+-----------------------+
| ^SELECT c FROM sbtest1 WHERE id=\?$ | 2                     |
| DISTINCT c FROM sbtest1             | 2                     |
+-------------------------------------+-----------------------+
2 rows in set (0.00 sec)
```

For these 2 specific rules, queries will be sent to slaves.
If no rules match a query, `default_hostgroup` applies (that is 1 for user msandbox).

Next, let's reset the content of the table `stats_mysql_query_digest` . To achieve this we can simply run any query against `stats_mysql_query_digest_reset` , for example:
``` sql
SELECT * FROM stats_mysql_query_digest_reset LIMIT 1;
```

Querying `stats_mysql_query_digest_reset` allows to atomically get the content of the `stats_mysql_query_digest` table , and truncate it!

Now we can load the query rules at runtime : 
``` sql
Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

And finally we re-execute the sysbench load: 
```
vagrant@ubuntu-14:~/sysbench/sysbench-0.5/sysbench$ ./sysbench --report-interval=5 --num-threads=4 --max-requests=0 --max-time=20 --test=tests/db/oltp.lua --mysql-user='msandbox' --mysql-password='msandbox' --oltp-table-size=10000 --mysql-host=127.0.0.1 --mysql-port=6033 run
```

And let's verify the content of table `stats_mysql_query_digest` :
``` sql
Admin> SELECT hostgroup hg, sum_time, count_star, digest_text FROM stats_mysql_query_digest ORDER BY sum_time DESC;
+----+----------+------------+----------------------------------------------------------------------+
| hg | sum_time | count_star | digest_text                                                          |
+----+----------+------------+----------------------------------------------------------------------+
| 2  | 14520738 | 50041      | SELECT c FROM sbtest1 WHERE id=?                                     |
| 2  | 3203582  | 5001       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
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

As expected, the top 2 queries are not sent to hostgroup2 (the slaves).
Table `stats_mysql_query_digest` allows to aggregate results, for example:

``` sql
Admin> SELECT hostgroup hg, SUM(sum_time), SUM(count_star) FROM stats_mysql_query_digest GROUP BY hostgroup;
+----+---------------+-----------------+
| hg | SUM(sum_time) | SUM(count_star) |
+----+---------------+-----------------+
| 1  | 21523008      | 59256           |
| 2  | 23915965      | 72424           |
+----+---------------+-----------------+
2 rows in set (0.00 sec)
```

## Query Caching

A popular use of ProxySQL is to act as a query cache. By default, queries aren't cached, but it can be enabled setting `cache_ttl` (in milliseconds) in `mysql_query_rules` .

Assume we want to also cache for 5 seconds all the queries sent to slaves.

``` sql
Admin> UPDATE mysql_query_rules set cache_ttl=5000 WHERE active=1 AND destination_hostgroup=2;
Query OK, 2 rows affected (0.00 sec)

Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

Admin> SELECT 1 FROM stats_mysql_query_digest_reset LIMIT 1; -- we reset the counters
+---+
| 1 |
+---+
| 1 |
+---+
1 row in set (0.00 sec)
```

Now, we can run again the load test:

```
vagrant@ubuntu-14:~/sysbench/sysbench-0.5/sysbench$ ./sysbench --report-interval=5 --num-threads=4 --max-requests=0 --max-time=20 --test=tests/db/oltp.lua --mysql-user='msandbox' --mysql-password='msandbox' --oltp-table-size=10000 --mysql-host=127.0.0.1 --mysql-port=6033 run
```

We can now verify the content of table `stats_mysql_query_digest` :
``` sql
Admin> SELECT hostgroup hg, sum_time, count_star, digest_text FROM stats_mysql_query_digest ORDER BY sum_time DESC;
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
| -1 | 0        | 4082       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
| -1 | 0        | 51261      | SELECT c FROM sbtest1 WHERE id=?                                     |
+----+----------+------------+----------------------------------------------------------------------+
13 rows in set (0.00 sec)
```


It is possible to see that what used to be the top 2 queries and being sent to the hostgroup2 , now:
* they are still sent to hostgroup2
* if they present in the query cache, they aren’t sent to any hostgroup and marked with a special hostgroup -1
* tthe total execution time for the queries cached is 0 (this means that the request was served within the same events loop

Note: currently it is not possible to define the maximum amount of memory used by the query cache, neither is possible to force a selective or complete flush of the query cache.
Right now, it is possible to control the memory footprint and the life of result set only through `cache_ttl` in `mysql_query_rules` : choose `cache_ttl` wisely until more control over query cache will be available.


## Query Rewrite


ProxySQL supports multiple ways to match a query, like `flagIN`, `username`, `schemaname`.

The most common way to match a query is writing a regular expression that matches the text of the query itself.
To match the text of a query ProxySQL provides 2 mechanisms, using 2 different fields:
- `match_digest` : it matches the regular expression again the digest of the query, as represented in `stats_mysql_query_digest.query_digest`
- `match_pattern` : it matches the regular expression again the unmodified text of the query

Why those different mechanism? The digest of a query can be extremely smaller than the query itself (for example, an `INSERT` statement with several MB of data), thus running a regex against a smaller string is surely faster.
So, in case you aren't trying to match a specific literal in the query, it is recommended (faster) to use `match_digest` .

Although, if you want to rewrite queries, you must match against the original query (using `match_pattern`), because it is the original query that needs to be rewritten.



An example:
``` sql
Admin> INSERT INTO mysql_query_rules (rule_id,active,username,match_pattern,replace_pattern,apply) VALUES (30,1,'msandbox','DISTINCT(.*)ORDER BY c','DISTINCT\1',1);
Query OK, 1 row affected (0.00 sec)


Admin> SELECT rule_id, match_digest, match_pattern, replace_pattern, cache_ttl, apply FROM mysql_query_rules ORDER BY rule_id;
+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| rule_id | match_digest                        | match_pattern          | replace_pattern | cache_ttl | apply |
+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| 10      | ^SELECT c FROM sbtest1 WHERE id=\?$ | NULL                   | NULL            | 5000      | 1     |
| 20      | DISTINCT c FROM sbtest1             | NULL                   | NULL            | 5000      | 1     |
| 30      | NULL                                | DISTINCT(.*)ORDER BY c | DISTINCT\1      | NULL      | 1     |
+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
3 rows in set (0.00 sec)


Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

Let's try this new rules.

``` sql
Admin> SELECT 1 FROM stats_mysql_query_digest_reset LIMIT 1;
```

```
vagrant@ubuntu-14:~/sysbench/sysbench-0.5/sysbench$ ./sysbench --report-interval=5 --num-threads=4 --max-requests=0 --max-time=20 --test=tests/db/oltp.lua  --mysql-user='msandbox' --mysql-password='msandbox' --oltp-table-size=10000 --mysql-host=127.0.0.1 --mysql-port=6033 run
```

``` sql
Admin> SELECT hostgroup hg, sum_time, count_star, digest_text FROM stats_mysql_query_digest ORDER BY sum_time DESC;
+----+----------+------------+----------------------------------------------------------------------+
| hg | sum_time | count_star | digest_text                                                          |
+----+----------+------------+----------------------------------------------------------------------+
| 1  | 8150528  | 5307       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c          |
| 1  | 7341765  | 5304       | COMMIT                                                               |
| 2  | 5717866  | 7860       | SELECT c FROM sbtest1 WHERE id=?                                     |
| 1  | 4807609  | 5307       | UPDATE sbtest1 SET k=k+? WHERE id=?                                  |
| 1  | 4164131  | 5308       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?                     |
| 1  | 3731299  | 5307       | SELECT SUM(K) FROM sbtest1 WHERE id BETWEEN ? AND ?+?                |
| 1  | 3156638  | 5305       | DELETE FROM sbtest1 WHERE id=?                                       |
| 1  | 3074430  | 5306       | UPDATE sbtest1 SET c=? WHERE id=?                                    |
| 2  | 2857863  | 1705       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
| 1  | 2732332  | 5304       | INSERT INTO sbtest1 (id, k, c, pad) VALUES (?, ?, ?, ?)              |
| 1  | 2165367  | 5310       | BEGIN                                                                |
| -1 | 0        | 3602       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
| -1 | 0        | 45235      | SELECT c FROM sbtest1 WHERE id=?                                     |
+----+----------+------------+----------------------------------------------------------------------+
13 rows in set (0.00 sec)
```


Something looks wrong, as no rewrite seems to have happened.
This is intentional, so we can now troubleshoot.
A very useful table for troubleshooting is `stats.stats_mysql_query_rules` :

``` sql
Admin> SELECT hits, mysql_query_rules.rule_id, match_digest, match_pattern, replace_pattern, cache_ttl, apply FROM mysql_query_rules NATURAL JOIN stats.stats_mysql_query_rules ORDER BY mysql_query_rules.rule_id;
+-------+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| hits  | rule_id | match_digest                        | match_pattern          | replace_pattern | cache_ttl | apply |
+-------+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| 54670 | 10      | ^SELECT c FROM sbtest1 WHERE id=\?$ | NULL                   | NULL            | 5000      | 1     |
| 5467  | 20      | DISTINCT c FROM sbtest1             | NULL                   | NULL            | 5000      | 1     |
| 0     | 30      | NULL                                | DISTINCT(.*)ORDER BY c | DISTINCT\1      | NULL      | 1     |
+-------+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
3 rows in set (0.01 sec)
```

It seems clear something is wrong: rule with `rule_id=30` has 0 hits!

The problem is that rule with `rule_id=20` also matches queries that would match in `rule_id=30` , although `apply=1` in rule number 20 will prevent to reach rule number 30.
Let fix this:

``` sql
Admin> UPDATE mysql_query_rules SET apply=0 WHERE rule_id=20;
Query OK, 1 row affected (0.00 sec)

Admin> SELECT rule_id, match_digest, match_pattern, replace_pattern, cache_ttl, apply FROM mysql_query_rules ORDER BY rule_id;
+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| rule_id | match_digest                        | match_pattern          | replace_pattern | cache_ttl | apply |
+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| 10      | ^SELECT c FROM sbtest1 WHERE id=\?$ | NULL                   | NULL            | 5000      | 1     |
| 20      | DISTINCT c FROM sbtest1             | NULL                   | NULL            | 5000      | 0     |
| 30      | NULL                                | DISTINCT(.*)ORDER BY c | DISTINCT\1      | NULL      | 1     |
+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
3 rows in set (0.00 sec)
```

Now should work!
Let's load the rules again:

``` sql
Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

Note: when running `LOAD MYSQL QUERY RULES TO RUNTIME` not only internal query processing structures are reset, but also the counters in `stats.stats_mysql_query_rules` :
``` sql
Admin> SELECT * FROM stats.stats_mysql_query_rules;
+---------+------+
| rule_id | hits |
+---------+------+
| 10      | 0    |
| 20      | 0    |
| 30      | 0    |
+---------+------+
3 rows in set (0.00 sec)
```

Let's try again:

``` sql
Admin> SELECT 1 FROM stats_mysql_query_digest_reset LIMIT 1;
```

```
vagrant@ubuntu-14:~/sysbench/sysbench-0.5/sysbench$ ./sysbench --report-interval=5 --num-threads=4 --max-requests=0 --max-time=20 --test=tests/db/oltp.lua --mysql-user='msandbox' --mysql-password='msandbox' --oltp-table-size=10000 --mysql-host=127.0.0.1 --mysql-port=6033 run
```

And now we can verify:

``` sql
Admin> SELECT hits, mysql_query_rules.rule_id, match_digest, match_pattern, replace_pattern, cache_ttl, apply FROM mysql_query_rules NATURAL JOIN stats.stats_mysql_query_rules ORDER BY mysql_query_rules.rule_id;
+-------+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| hits  | rule_id | match_digest                        | match_pattern          | replace_pattern | cache_ttl | apply |
+-------+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
| 48560 | 10      | ^SELECT c FROM sbtest1 WHERE id=\?$ | NULL                   | NULL            | 5000      | 1     |
| 4856  | 20      | DISTINCT c FROM sbtest1             | NULL                   | NULL            | 5000      | 0     |
| 4856  | 30      | NULL                                | DISTINCT(.*)ORDER BY c | DISTINCT\1      | NULL      | 1     |
+-------+---------+-------------------------------------+------------------------+-----------------+-----------+-------+
3 rows in set (0.01 sec)
```

There are rewrites, looks good :-)

What about query execution ?
``` sql
Admin> SELECT hostgroup hg, sum_time, count_star, digest_text FROM stats_mysql_query_digest ORDER BY sum_time DESC;
+----+----------+------------+-------------------------------------------------------------+
| hg | sum_time | count_star | digest_text                                                 |
+----+----------+------------+-------------------------------------------------------------+
| 1  | 7240757  | 4856       | COMMIT                                                      |
| 1  | 6127168  | 4856       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
| 2  | 4264263  | 7359       | SELECT c FROM sbtest1 WHERE id=?                            |
| 1  | 4081063  | 4856       | UPDATE sbtest1 SET k=k+? WHERE id=?                         |
| 1  | 3497644  | 4856       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?            |
| 1  | 3270527  | 4856       | DELETE FROM sbtest1 WHERE id=?                              |
| 1  | 3193123  | 4856       | SELECT SUM(K) FROM sbtest1 WHERE id BETWEEN ? AND ?+?       |
| 1  | 3124698  | 4856       | UPDATE sbtest1 SET c=? WHERE id=?                           |
| 1  | 2866474  | 4856       | INSERT INTO sbtest1 (id, k, c, pad) VALUES (?, ?, ?, ?)     |
| 1  | 2538840  | 4856       | BEGIN                                                       |
| 2  | 1889996  | 1633       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?   |
| -1 | 0        | 3223       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?   |
| -1 | 0        | 41201      | SELECT c FROM sbtest1 WHERE id=?                            |
+----+----------+------------+-------------------------------------------------------------+
13 rows in set (0.00 sec)
```

Note:
Rules with `rule_id=20` and `rule_id=30` can be merged together into a single rule.
They are separated to describe the importance of `apply` field, and that not only multiple rules can match the same query, but multiple rules can transform and apply settings to the same query.





Few more example of query rewrite.

We want to rewrite queries like:
``` sql
SELECT c FROM sbtest1 WHERE id=?
```
into:
``` sql
SELECT c FROM sbtest2 WHERE id=?
```
But only for ids between 1000 and 3999 ...
I know, this makes no sense, it is just to show some potentials, including the ability some complex sharding!!

How this looks in regex? :-)

``` sql
Admin> INSERT INTO mysql_query_rules (rule_id,active,username,match_pattern,replace_pattern,apply) VALUES (5,1,'msandbox','^SELECT (c) FROM sbtest(1) WHERE id=(1|2|3)(...)$','SELECT c FROM sbtest2 WHERE id=\3\4',1);
Query OK, 1 row affected (0.00 sec)
```

Note that "c" and "1" (in sbtest1) are selected just to show the syntax

``` sql
Admin> SELECT rule_id, match_digest, match_pattern, replace_pattern, cache_ttl, apply FROM mysql_query_rules ORDER BY rule_id;
+---------+-------------------------------------+---------------------------------------------+------------------------------------+-----------+-------+
| rule_id | match_digest                        | match_pattern                               | replace_pattern                    | cache_ttl | apply |
+---------+-------------------------------------+---------------------------------------------+------------------------------------+-----------+-------+
| 5       | NULL                                | ^SELECT (c) FROM sbtest(1) WHERE id=1(...)$ | SELECT c FROM sbtest2 WHERE id=1\3 | NULL      | 1     |
| 10      | ^SELECT c FROM sbtest1 WHERE id=\?$ | NULL                                        | NULL                               | 5000      | 1     |
| 20      | DISTINCT c FROM sbtest1             | NULL                                        | NULL                               | 5000      | 0     |
| 30      | NULL                                | DISTINCT(.*)ORDER BY c                      | DISTINCT\1                         | NULL      | 1     |
+---------+-------------------------------------+---------------------------------------------+------------------------------------+-----------+-------+
4 rows in set (0.00 sec)
```

Let's try it.

``` sql
Admin> SELECT 1 FROM stats_mysql_query_digest_reset LIMIT 1;

Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

```
vagrant@ubuntu-14:~/sysbench/sysbench-0.5/sysbench$ ./sysbench --report-interval=5 --num-threads=4 --max-requests=0 --max-time=20 --test=tests/db/oltp.lua --mysql-user='msandbox' --mysql-password='msandbox' --oltp-table-size=10000 --mysql-host=127.0.0.1 --mysql-port=6033 run
```


Did it work? Apparently yes :)

``` sql
Admin> SELECT hits, mysql_query_rules.rule_id, match_digest, match_pattern, replace_pattern, cache_ttl, apply FROM mysql_query_rules NATURAL JOIN stats.stats_mysql_query_rules;                                              +-------+---------+-------------------------------------+---------------------------------------------------+-------------------------------------+-----------+-------+
| hits  | rule_id | match_digest                        | match_pattern                                     | replace_pattern                     | cache_ttl | apply |
+-------+---------+-------------------------------------+---------------------------------------------------+-------------------------------------+-----------+-------+
| 2579  | 5       | NULL                                | ^SELECT (c) FROM sbtest(1) WHERE id=(1|2|3)(...)$ | SELECT c FROM sbtest2 WHERE id=\3\4 | NULL      | 1     |
| 83091 | 10      | ^SELECT c FROM sbtest1 WHERE id=\?$ | NULL                                              | NULL                                | 5000      | 1     |
| 8567  | 20      | DISTINCT c FROM sbtest1             | NULL                                              | NULL                                | 5000      | 0     |
| 8567  | 30      | NULL                                | DISTINCT(.*)ORDER BY c                            | DISTINCT\1                          | NULL      | 1     |
+-------+---------+-------------------------------------+---------------------------------------------------+-------------------------------------+-----------+-------+
4 rows in set (0.00 sec)

Admin> SELECT hostgroup hg, sum_time, count_star, digest_text FROM stats_mysql_query_digest ORDER BY sum_time DESC;
+----+----------+------------+-------------------------------------------------------------+
| hg | sum_time | count_star | digest_text                                                 |
+----+----------+------------+-------------------------------------------------------------+
| 1  | 9417428  | 8567       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
| 1  | 6282654  | 8567       | COMMIT                                                      |
| 1  | 5560850  | 8567       | UPDATE sbtest1 SET k=k+? WHERE id=?                         |
| 1  | 5360637  | 8567       | SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?            |
| 1  | 4447573  | 8567       | SELECT SUM(K) FROM sbtest1 WHERE id BETWEEN ? AND ?+?       |
| 1  | 4040300  | 8567       | UPDATE sbtest1 SET c=? WHERE id=?                           |
| 1  | 3378990  | 8567       | DELETE FROM sbtest1 WHERE id=?                              |
| 1  | 3046664  | 8567       | INSERT INTO sbtest1 (id, k, c, pad) VALUES (?, ?, ?, ?)     |
| 1  | 2974559  | 8596       | SELECT c FROM sbtest1 WHERE id=?                            |
| 2  | 2805758  | 2376       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?   |
| 1  | 2480409  | 8567       | BEGIN                                                       |
| 1  | 1152803  | 2579       | SELECT c FROM sbtest2 WHERE id=?                            |
| -1 | 0        | 6191       | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+?   |
| -1 | 0        | 74495      | SELECT c FROM sbtest1 WHERE id=?                            |
+----+----------+------------+-------------------------------------------------------------+
14 rows in set (0.01 sec)
```


