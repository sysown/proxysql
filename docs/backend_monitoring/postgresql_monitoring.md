# PostgreSQL Monitor Module

## Feature Overview

`ProxySQL` aims to deliver a comprehensive monitoring solution for `PostgreSQL` servers. It leverages
asynchronous connections and a multi-threaded architecture to efficiently perform ping and connection checks
on a set of servers.

**Solution Architecture:**

- **Multi-threaded:** Utilizes multiple worker threads to parallelize monitoring tasks.
- **Asynchronous Connections:** Employs asynchronous `PostgreSQL` connections for efficient handling of
  multiple servers.
- **Connection Pooling:** Maintains a pool of connections to reduce connection overhead.
- **Scheduler Thread:** Manages task scheduling, configuration updates, and thread management.

**Core Functionality:**

Currently monitoring checks supported are:

- **Ping Checks:** Regularly pings `PostgreSQL` servers to assess their responsiveness.
  - **Server Shunning:** Automatically identifies and "shuns" unresponsive servers, preventing further
    connections to them.
  - **Latency Tracking:** Tracks the average latency of successful ping operations for each server.
- **Connection Checks:** Attempts to establish connections to servers to verify their availability and assess
  connection latency.
- **Read-Only Checks:** Check if the server is a `read-only` server (`replica`) or a `primary` which is able
  to receive write traffic. Checks are performed via `pg_is_in_recovery()`.

Any monitoring check also offers a common set of features:

- **Error Logging:** Records ping and connection attempts, including success/failure status, latency, and
  error messages.
- **History Management:** Maintains a configurable history of ping and connection logs, allowing for trend
  analysis.

If you are new to `ProxySQL`, refer to the [User Guide][11] section for a deeper and more guided explanation
of the listed features.

## Configuration Variables

The variables listed below provide a quick reference for the concepts discussed in this document. For a
complete list and detailed descriptions, please refer to [PgSQL Monitor Variables][14]:

- **`pgsql-monitor_enabled`:** (boolean, default: true) Enables or disables the monitoring system.
- **`pgsql-monitor_threads`:** (integer, default: 2) Specifies the number of worker threads to use for
  monitoring.
- **`pgsql-monitor_ping_interval`:** (integer, default: 8000ms) Sets the interval between checks.
- **`pgsql-monitor_ping_interval_window`:** (integer, default: 10) Sets the target window, expressed as a
  percentage of the interval, in which the checks should be completed.
- **`pgsql-monitor_ping_timeout`:** (integer, default: 1000ms) Sets the timeout for ping checks.
- **`pgsql-monitor_ping_max_failures`:** (integer, default: 3) Specifies the maximum number of consecutive
  ping failures before a server is shunned.
- **`pgsql-monitor_connect_interval`:** (integer, default: 120000ms) Sets the interval between checks.
- **`pgsql-monitor_connect_interval_window`:** (integer, default: 50) Sets the target window, expressed as a
  percentage of the interval, in which the checks should be completed.
- **`pgsql-monitor_connect_timeout`:** (integer, default: 600ms) Sets the timeout for connection checks.
- **`pgsql-monitor_username`:** (string) Specifies the username used for connecting to `PostgreSQL` servers.
- **`pgsql-monitor_password`:** (string) Specifies the password used for connecting to `PostgreSQL` servers.
- **`pgsql-monitor_history`:** (integer, default: 7200000s) Sets the maximum age of ping and connection logs
  to keep.
- **`pgsql-monitor_read_only_interval`:** (integer, default: 1000ms) Sets the interval between checks.
- **`pgsql-monitor_read_only_interval_window`:** (integer, default: 10) Sets the target window, expressed as a
  percentage of the interval, in which the checks should be completed.
- **`pgsql-monitor_read_only_timeout`:** Sets the timeout for read_only checks.
- **`pgsql-monitor_read_only_max_timeout_count`:** Sets the maximum number of consecutive `read_only` checks
  timeouts before a server is considered `read_only`.

Outside these variables, the monitor module could also be disabled via the command line flag `-M`. For more
information on command line flags check [startup-options][12].

**Configuration Method:**

The previously specified variables can be configured via either [Configuration File][9] or via [Admin
Interface][2].

## Server Monitoring

### Basic

Monitor module is enabled by default, and is controlled by config variable `pgsql-monitor_enabled`. If the
module is enabled, basic monitoring for servers, which includes `connect` and `ping` checks, starts as soon as
the servers are configured, i.e. inserted in the table `pgsql_servers`, and command
`LOAD PGSQL SERVERS TO RUNTIME` command is issued against the [Admin Interface][2].

### Read-Only

For enabling `read-only` monitoring, we need to specify the hostgroups that will be target by these checks in
table `pgsql_replication_hostgroups`. This table is defined as:

```sql
radmin=# SHOW CREATE TABLE pgsql_replication_hostgroups;
            table             |                                                                                          Create Table
------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 pgsql_replication_hostgroups | CREATE TABLE pgsql_replication_hostgroups (                                                                                                                                                   +
                              |     writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,                                                                                                                    +
                              |     reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>=0),                                                                                         +
                              |     check_type VARCHAR CHECK (LOWER(check_type) IN ('read_only','innodb_read_only','super_read_only','read_only|innodb_read_only','read_only&innodb_read_only')) NOT NULL DEFAULT 'read_only',+
                              |     comment VARCHAR NOT NULL DEFAULT '', UNIQUE (reader_hostgroup))
(1 row)
```

To do this, it's enough to insert an entry in the table that holds the corresponding hostgroup in which the
server was configured in `pgsql_servers` table, and issue the command `LOAD PGSQL SERVERS TO RUNTIME` against
the admin interface.

**All** servers configured in both `hostgroups`, `writer_hostgroup` and `reader_hostgroup`, will be from that
moment monitored by `read-only` checks.

## Log Tables

The following tables contain the monitor log data and are managed by the monitor module:

```sql
radmin=# SHOW CREATE TABLE monitor.pgsql_server_connect_log;
          table           |                   Create Table
--------------------------+--------------------------------------------------
 pgsql_server_connect_log | CREATE TABLE pgsql_server_connect_log (         +
                          |     hostname VARCHAR NOT NULL,                  +
                          |     port INT NOT NULL DEFAULT 3306,             +
                          |     time_start_us INT NOT NULL DEFAULT 0,       +
                          |     connect_success_time_us INT DEFAULT 0,      +
                          |     connect_error VARCHAR,                      +
                          |     PRIMARY KEY (hostname, port, time_start_us))
(1 row)

radmin=# SHOW CREATE TABLE monitor.pgsql_server_ping_log;
         table         |                   Create Table
-----------------------+--------------------------------------------------
 pgsql_server_ping_log | CREATE TABLE pgsql_server_ping_log (            +
                       |      hostname VARCHAR NOT NULL,                 +
                       |     port INT NOT NULL DEFAULT 3306,             +
                       |     time_start_us INT NOT NULL DEFAULT 0,       +
                       |     ping_success_time_us INT DEFAULT 0,         +
                       |     ping_error VARCHAR,                         +
                       |     PRIMARY KEY (hostname, port, time_start_us))
(1 row)

radmin=# SHOW CREATE TABLE monitor.pgsql_server_read_only_log;
           table            |                   Create Table
----------------------------+--------------------------------------------------
 pgsql_server_read_only_log | CREATE TABLE pgsql_server_read_only_log (       +
                            |      hostname VARCHAR NOT NULL,                 +
                            |     port INT NOT NULL DEFAULT 3306,             +
                            |     time_start_us INT NOT NULL DEFAULT 0,       +
                            |     success_time_us INT DEFAULT 0,              +
                            |     read_only INT DEFAULT 1,                    +
                            |     error VARCHAR,                              +
                            |     PRIMARY KEY (hostname, port, time_start_us))
(1 row)
```

Once monitoring is enabled for a server, both tables `connect` and `ping` will be updated at the configured
intervals of the checks, recording their results. The `read_only` table will be updated with each `read-only`
check once table `pgsql_replication_hostgroups` table has been configured.

## User Guide

**Configuration Method:**

The previously specified variables can be configured via either [Configuration File][9] or via [Admin
Interface][2].

### Basic Configuration

If you are new to `ProxySQL`, a good starting points for getting familiar with several core concepts that are
shared for `MySQL` and `PostgreSQL` servers:

- Multi-Layer Configuration System: [https://proxysql.com/configuring-proxysql/][1]
- Admin CLI Interface: [https://proxysql.com/the-admin-schemas/][2]
- Backend Server Configuration: [https://proxysql.com/backend-server-configuration/][3]

Once familiar with these basic concepts, let's configure `ProxySQL` with a minimal setup making use of it's
monitoring capabilities for `PostgreSQL`.

First, lets create and analyze an example configuration file:

```cnf
# Location to store the database file, logs and generated data.
datadir="$PATH"

# Administration variables
admin_variables=
{
    # Credentials to logging to `ProxySQL` Admin CLI Interface - https://proxysql.com/the-admin-schemas/.
    # IMPORTANT: Remember that default 'admin:admin' credentials can only be used from localhost. These are
    # sample defaults and should be changed for your configuration.
	admin_credentials="admin:admin;radmin:radmin"
    # Port for accessing Admin interface using MySQL Protocol
	mysql_ifaces="0.0.0.0:6032"
    # Port for accessing Admin interface using `PostgreSQL` Protocol
	pgsql_ifaces="0.0.0.0:6132"
}

pgsql_variables=
{
    # Number of threads used to serve traffic
	threads=2
    # Maximum global number of client connections for `PostgreSQL` interface
	max_connections=2048
    # A defaultly imposed query delay
	default_query_delay=0
    # The default query timeout for backend queries
	default_query_timeout=36000000
    # Retries to perform when failing to create a connection for serving traffic
	connect_retries_on_failure=10
    # Minimal timeout used to detect incoming/outgoing traffic via the `poll` syscall
	poll_timeout=2000
    # Interface to be used for serving traffic
	interfaces="0.0.0.0:6133"
    # Server version that `ProxySQL` will advertise to the client
	server_version="16.1"
    # Timeout to use when creating backend server connections
	connect_timeout_server=3000
    # History to be retained for Monitoring purposes on 'monitor' schema tables
	monitor_history=600000
    # Interval used for Monitor Connect checks
	monitor_connect_interval=60000
    # Timeout used for Monitor Connect checks
    monitor_connect_timeout=600
    # Interval used for Monitor Ping checks
	monitor_ping_interval=8000
    # Timeout used for Monitor Ping checks
	monitor_ping_timeout=1000
    # Interval used for Monitor read_only checks
	monitor_read_only_interval=1000
    # Timeout used for Monitor read_only checks
	monitor_read_only_timeout=800
    # Create stats about the received commands - https://proxysql.com/stats-statistics/#stats_mysql_commands_counters
	commands_stats=true
}
```

`ProxySQL` uses this configuration file to initialize a database file in the supplied `datadir`. It's very
important to remember that this file will only be used in an [initial bootstrap][4], i.e. no database file is
found, in an [initial startup][5] or in a [reload startup][6], for more information see [Configuration Life
Cycle][7].

It's also important to remember that the configuration file isn't recommended for complex configurations, it
should only be used as a way to bootstrap `ProxySQL` with minimal/basic configuration. The recommended way to
supply/deploy your configuration is via the database file. See [Configuration file vs Database file][8]. For
more details about the configuration file semantics please check [Configuration File][9] docs.

We store this configuration in a file (`proxysql.cnf`) and then we proceed to launch `ProxySQL`. In this
example we would be launching `ProxySQL` as a foreground process:

```bash
proxysql --clickhouse-server --sqlite3-server --idle-threads -f -c $CONFIG_PATH/proxysql.cnf -D $DATADIR_PATH
```

Once `launched` we are going to login to `ProxySQL` [Admin interface][2], and check our current configuration.
Remember that we have the option of doing this from a `MySQL` client and from a `PostgreSQL` client.

From `MySQL`:

```sql
mysql --prompt="admin> " -uradmin -pradmin -h127.0.0.1 -P6032
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 1
Server version: 8.0.11 (ProxySQL Admin Module)

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

admin>
```

From `PostgreSQL`:

```sql
PGPASSWORD='radmin' psql -h127.0.0.1 -p6132 -Uradmin
psql (16.3, server 16.1)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
Type "help" for help.

radmin=#
```

Let's follow using the `psql` client for the purpose of this guide. Let's check the databases which exposes us
the current `ProxySQL` modules and configuration:

```sql
radmin=# show databases;
 seq |       name       |        file
-----+------------------+----------------------------
 0   | main             |
 2   | disk             | /$DATADIR/proxysql.db
 3   | stats            |
 4   | monitor          |
 5   | stats_history    | /$DATADIR/proxysql_stats.db
 6   | myhgm            |
 7   | monitor_internal |
(7 rows)
```

For a how to on how to perform an initial servers and users configuration you can refer to the guide [first
time PostgreSQL configuration][10]. We are going to configure just one server, our monitoring user and verify
that monitoring is working as expected. Later, we will also configure a user for serving traffic and check
that we can perform queries to our monitored server.

First, let's insert our `PostgreSQL` server, for doing that, we could always check the table definition if we
don't remember the required fields:

```sql
radmin=# SHOW CREATE TABLE pgsql_servers;
     table     |                                                        Create Table
---------------+----------------------------------------------------------------------------------------------------------------------------
 pgsql_servers | CREATE TABLE pgsql_servers (                                                                                              +
               |     hostgroup_id INT CHECK (hostgroup_id>=0) NOT NULL DEFAULT 0,                                                          +
               |     hostname VARCHAR NOT NULL,                                                                                            +
               |     port INT CHECK (port >= 0 AND port <= 65535) NOT NULL DEFAULT 5432,                                                   +
               |     status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE',+
               |     weight INT CHECK (weight >= 0 AND weight <=10000000) NOT NULL DEFAULT 1,                                              +
               |     compression INT CHECK (compression IN(0,1)) NOT NULL DEFAULT 0,                                                       +
               |     max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000,                                                +
               |     max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0,     +
               |     use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0,                                                               +
               |     max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0,                                             +
               |     comment VARCHAR NOT NULL DEFAULT '',                                                                                  +
               |     PRIMARY KEY (hostgroup_id, hostname, port) )
(1 row)
```

Let's insert our first server entry:

```sql
radmin=# INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_connections, comment) VALUES (0, '127.0.0.1', 15432, 500, 'first_server');
INSERT 0 1
radmin=# SELECT * FROM pgsql_servers;
 hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |   comment
--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+--------------
 0            | 127.0.0.1 | 15432 | ONLINE | 1      | 0           | 500             | 0                   | 0       | 0              | first_server
(1 row)
```

Now we should configure our monitoring user, but first we are going to check our current monitoring config,
and to `LOAD PGSQL SERVERS TO RUNTIME` our current changes, so we can check the monitoring errors that would
take place with a misconfigured monitoring user.

```sql
radmin=# SHOW VARIABLES LIKE 'pgsql-%monitor%';
          Variable_name          |  Value
---------------------------------+---------
 pgsql-monitor_enabled           | true
 pgsql-monitor_ping_max_failures | 3
 pgsql-monitor_ping_timeout      | 1000
 pgsql-monitor_username          | monitor
 pgsql-monitor_password          | monitor
 pgsql-monitor_threads           | 2
 pgsql-monitor_history           | 600000
 pgsql-monitor_connect_interval  | 60000
 pgsql-monitor_connect_timeout   | 600
 pgsql-monitor_ping_interval     | 8000
(10 rows)
```

Our `PostgreSQL` instance is unlikely to have configured this credentials for a monitoring user, let's try to
promote our changes to the servers to runtime and inspect the `monitor` tables for errors:

```sql
radmin=# LOAD PGSQL SERVERS TO RUNTIME;
LOAD
radmin=# SELECT * FROM runtime_pgsql_servers;
 hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |   comment
--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+--------------
 0            | 127.0.0.1 | 15432 | ONLINE | 1      | 0           | 500             | 0                   | 0       | 0              | first_server
(1 row)
```

Immediately we can see `ProxySQL` error log start getting populated with errors:

```
2024-09-30 19:13:07 PgSQL_Monitor.cpp:463:handle_pg_event(): [ERROR] Monitor connect FAILED   error='FATAL:  password authentication failed for user "monitor"'
2024-09-30 19:13:11 PgSQL_Monitor.cpp:463:handle_pg_event(): [ERROR] Monitor connect FAILED   error='FATAL:  password authentication failed for user "monitor"'
2024-09-30 19:13:19 PgSQL_Monitor.cpp:463:handle_pg_event(): [ERROR] Monitor connect FAILED   error='FATAL:  password authentication failed for user "monitor"'
2024-09-30 19:14:15 PgSQL_Monitor.cpp:463:handle_pg_event(): [ERROR] Monitor connect FAILED   error='FATAL:  password authentication failed for user "monitor"'
```

And so they do the relevant tables from `monitor` schema:

```sql
radmin=# SELECT * FROM monitor.pgsql_server_ping_log LIMIT 4;
 hostname  | port  |  time_start_us   | ping_success_time_us |                        ping_error
-----------+-------+------------------+----------------------+-----------------------------------------------------------
 127.0.0.1 | 15432 | 1727716391082567 | 0                    | FATAL:  password authentication failed for user "monitor"
 127.0.0.1 | 15432 | 1727716399134066 | 0                    | FATAL:  password authentication failed for user "monitor"
 127.0.0.1 | 15432 | 1727716407185601 | 0                    | FATAL:  password authentication failed for user "monitor"
 127.0.0.1 | 15432 | 1727716415237181 | 0                    | FATAL:  password authentication failed for user "monitor"
(4 rows)

radmin=# SELECT * FROM monitor.pgsql_server_connect_log LIMIT 4;
 hostname  | port  |  time_start_us   | connect_success_time_us |                       connect_error
-----------+-------+------------------+-------------------------+-----------------------------------------------------------
 127.0.0.1 | 15432 | 1727716387031634 | 0                       | FATAL:  password authentication failed for user "monitor"
 127.0.0.1 | 15432 | 1727716447443701 | 0                       | FATAL:  password authentication failed for user "monitor"
 127.0.0.1 | 15432 | 1727716507856513 | 0                       | FATAL:  password authentication failed for user "monitor"
 127.0.0.1 | 15432 | 1727716568269249 | 0                       | FATAL:  password authentication failed for user "monitor"
(4 rows)
```

Now let's configure a monitoring user in our `PostgreSQL` instance. `ProxySQL` doesn't allow to set right now
a custom database for the monitoring user, so **for now** you should create a custom database this user. This
is likely to change in near the future, stay tuned for updates:

```sql
$ PGPASSWORD='postgres' psql -h127.0.0.1 -p15432 -Upostgres
psql (16.3, server 16.4 (Debian 16.4-1.pgdg120+1))
Type "help" for help.

postgres=# CREATE USER 'proxymon' WITH PASSWORD 'proxymon';
postgres=# CREATE DATABASE 'proxymon';
```

Let's change the monitoring variables in `ProxySQL`:

```sql
radmin=# SET pgsql-monitor_username='proxymon';
UPDATE 1
radmin=# SET pgsql-monitor_password='proxymon';
UPDATE 1
radmin=# LOAD PGSQL VARIABLES TO RUNTIME;
LOAD
```

Errors should stop being written in `ProxySQL` error log and monitoring tables should show operations
succeeding:

```sql
radmin=# SELECT * FROM monitor.pgsql_server_ping_log ORDER BY time_start_us DESC LIMIT 4;
 hostname  | port  |  time_start_us   | ping_success_time_us | ping_error
-----------+-------+------------------+----------------------+------------
 127.0.0.1 | 15432 | 1727717357683130 | 322                  |
 127.0.0.1 | 15432 | 1727717349580977 | 372                  |
 127.0.0.1 | 15432 | 1727717341529226 | 314                  |
 127.0.0.1 | 15432 | 1727717333477716 | 353                  |
(4 rows)

radmin=# SELECT * FROM monitor.pgsql_server_connect_log ORDER BY time_start_us DESC LIMIT 4;
 hostname  | port  |  time_start_us   | connect_success_time_us |                       connect_error
-----------+-------+------------------+-------------------------+-----------------------------------------------------------
 127.0.0.1 | 15432 | 1727717293219532 | 9882                    |
 127.0.0.1 | 15432 | 1727717232806648 | 0                       | FATAL:  password authentication failed for user "monitor"
 127.0.0.1 | 15432 | 1727717172394225 | 0                       | FATAL:  password authentication failed for user "monitor"
 127.0.0.1 | 15432 | 1727717111981411 | 0                       | FATAL:  password authentication failed for user "monitor"
(4 rows)
```

We can can also check the current server status from the same interface via `runtime_pgsql_servers`:

```sql
radmin=# SELECT * FROM runtime_pgsql_servers;
 hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |   comment
--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+--------------
 0            | 127.0.0.1 | 15432 | ONLINE | 1      | 0           | 500             | 0                   | 1       | 0              | first_server
(1 row)
```

Let's create some unexpected errors, and check that `ProxySQL` detects the issue and `SHUNN` our server due to
monitoring errors. We can do this by simply blocking the traffic to our server IP (if using docker we could
just `pause` our docker container):

```bash
$ sudo iptables -I OUTPUT 1 -p tcp -d 127.0.0.1 --dport 15432 -j DROP

$ PGPASSWORD='radmin' psql -h127.0.0.1 -p6132 -Uradmin
psql (16.3, server 16.1)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
Type "help" for help.

radmin=# SELECT * FROM monitor.pgsql_server_ping_log ORDER BY time_start_us DESC LIMIT 4;
 hostname  | port  |  time_start_us   | ping_success_time_us |     ping_error
-----------+-------+------------------+----------------------+---------------------
 127.0.0.1 | 15432 | 1727717953708241 | 0                    | Operation timed out
 127.0.0.1 | 15432 | 1727717945656487 | 0                    | Operation timed out
 127.0.0.1 | 15432 | 1727717937604824 | 0                    | Operation timed out
 127.0.0.1 | 15432 | 1727717929553071 | 0                    | Operation timed out
(4 rows)
```

As a response to this, we should see in the error log an entry notifying that the server has been shunned due
to unresponsiveness:

```
2024-09-30 19:37:37 PgSQL_Monitor.cpp:1236:shunn_non_resp_srvs(): [ERROR] Server 127.0.0.1:15432 missed 3 heartbeats, shunning it and killing all the connections. Disabling other checks until the node comes back online.
```

We can also verify that the server status have changed in the `runtime_pgsql_servers` table:

```sql
radmin=# SELECT * FROM runtime_pgsql_servers;
 hostgroup_id | hostname  | port  | status  | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |   comment
--------------+-----------+-------+---------+--------+-------------+-----------------+---------------------+---------+----------------+--------------
 0            | 127.0.0.1 | 15432 | SHUNNED | 1      | 0           | 500             | 0                   | 1       | 0              | first_server
(1 row)
```

If we revert this scenario, monitoring checks should start working again:

```bash
$ sudo iptables -D OUTPUT 1
$ PGPASSWORD='radmin' psql -h127.0.0.1 -p6132 -Uradmin
psql (16.3, server 16.1)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
Type "help" for help.

radmin=# SELECT * FROM monitor.pgsql_server_ping_log ORDER BY time_start_us DESC LIMIT 4;
 hostname  | port  |  time_start_us   | ping_success_time_us | ping_error
-----------+-------+------------------+----------------------+------------
 127.0.0.1 | 15432 | 1727718171204999 | 370                  |
 127.0.0.1 | 15432 | 1727718163153198 | 410                  |
 127.0.0.1 | 15432 | 1727718155101422 | 375                  |
 127.0.0.1 | 15432 | 1727718147049801 | 356                  |
(4 rows)
```

Yet if we inspect the runtime table, our server `SHUNNED` condition won't have changed:

```sql
radmin=# SELECT * FROM runtime_pgsql_servers;
 hostgroup_id | hostname  | port  | status  | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |   comment
--------------+-----------+-------+---------+--------+-------------+-----------------+---------------------+---------+----------------+--------------
 0            | 127.0.0.1 | 15432 | SHUNNED | 1      | 0           | 500             | 0                   | 1       | 0              | first_server
(1 row)
```

This is not because our server is still unavailable, but because `ProxySQL` updates this table in a lazy way.
Only when traffic is routed to the server, it will be bring back `ONLINE` and the value will change from this
table. For this, we are going to configure a user for `PostgreSQL` and `ProxySQL` that let's us exercise
traffic through the server.

First we create a user in our `PostgreSQL` database and a database that will be target by `ProxySQL`
connections:

```sql
stgres=# CREATE USER 'proxyuser' WITH PASSWORD 'proxypass';
```

Let's create the user for `ProxySQL`, first let's see the table definition as for `pgsql_servers`:

```sql
radmin=# SHOW CREATE TABLE pgsql_users;
    table    |                                         Create Table
-------------+-----------------------------------------------------------------------------------------------
 pgsql_users | CREATE TABLE pgsql_users (                                                                   +
             |     username VARCHAR NOT NULL,                                                               +
             |     password VARCHAR,                                                                        +
             |     active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,                                   +
             |     use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0,                                 +
             |     default_hostgroup INT NOT NULL DEFAULT 0,                                                +
             |     transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 1,   +
             |     fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0,                       +
             |     backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1,                                 +
             |     frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1,                               +
             |     max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000,                  +
             |     attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',+
             |     comment VARCHAR NOT NULL DEFAULT '',                                                     +
             |     PRIMARY KEY (username, backend),                                                         +
             |     UNIQUE (username, frontend))
(1 row)
```

Let's now insert the user and promote the changes to `RUNTIME`:

```sql
radmin=# INSERT INTO pgsql_users (username,password,default_hostgroup,max_connections,comment) VALUES ('proxyuser','proxypass',0,400,'first_user');
INSERT 0 1
radmin=# LOAD PGSQL USERS TO RUNTIME;
oLOAD
```

Let's perform a connection to `ProxySQL` and a dummy query, this should update our server status in
`runtime_pgsql_servers` table:

```sql
$ PGPASSWORD='proxypass' psql -h127.0.0.1 -p6133 -Uproxyuser -dpostgres
psql (16.3, server 16.1)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
Type "help" for help.

postgres=> do $$ BEGIN NULL; END $$;
DO

$ PGPASSWORD='radmin' psql -h127.0.0.1 -p6132 -Uradmin
psql (16.3, server 16.1)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
Type "help" for help.

radmin=# SELECT * FROM runtime_pgsql_servers;
 hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |   comment
--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+--------------
 0            | 127.0.0.1 | 15432 | ONLINE | 1      | 0           | 500             | 0                   | 0       | 0              | first_server
(1 row)
```

### Read-Only Configuration

To configure `read_only` checks, it's not only required to configure our servers in `pgsql_servers` table, we
also need to make use of table `pgsql_replication_hostgroups`:

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

_NOTE: Right now the only supported `check_type` is `read_only`, so the field is unused._

The final server placement in the configured hostgroups, will be dependent from the config in
`pgsql_replication_hostgroups`, the hostgroups in which the server is configured and the config variable
`pgsql-monitor_writer_is_also_reader`. For breaking down it's interactions, let's exemplify with a scenario.

First, let's explain the relationship between `pgsql_servers` and `pgsql_replication_hostgroups`, assuming the
default value for `pgsql-monitor_writer_is_also_reader`. Let's assume that we have a replication setup with
two servers, one primary and one replica. Let's configure our servers in `pgsql_servers`:

```sql
radmin=# INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_connections, comment) VALUES (0, '127.0.0.1', 15432, 500, 'primary-1');
INSERT 0 1
radmin=# INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_connections, comment) VALUES (0, '127.0.0.1', 15433, 500, 'replica-1');
INSERT 0 1
radmin=# INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_connections, comment) VALUES (2, '127.0.0.1', 15432, 500, 'primary-2');
INSERT 0 1
radmin=# INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_connections, comment) VALUES (2, '127.0.0.1', 15433, 500, 'replica-2');
INSERT 0 1
radmin=# LOAD PGSQL SERVERS TO RUNTIME;
LOAD
```

_NOTE: The order of these steps is not relevant, the `read_only` checks will take place when both tables are
configured, no matter the order_

We have duplicated our servers in two `hostgroups`, `0` and `2`. Right now, if we check the
`runtime_pgsql_servers`, we will see that the placement is exactly the one we have specified:

```sql
radmin=# SELECT hostgroup_id,hostname,port,status,comment FROM runtime_pgsql_servers;
 hostgroup_id | hostname  | port  | status | comment
--------------+-----------+-------+--------+---------
 0            | 127.0.0.1 | 15432 | ONLINE | primary-1
 0            | 127.0.0.1 | 15433 | ONLINE | replica-1
 2            | 127.0.0.1 | 15432 | ONLINE | primary-2
 2            | 127.0.0.1 | 15433 | ONLINE | replica-2
(4 rows)
```

This is expected, since we haven't yet defined any `read_hostgroup` or `writer_hostgroup` (via
`pgsql_replication_hostgroups`). Let's do it for taking advantage of `ProxySQL` automatic server placement via
`read_only` checks:

```sql
radmin=# INSERT INTO pgsql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) VALUES (0,1,'pg-repl');
INSERT 0 1
```

After modifying the table it's **required** to promote the configuration to `RUNTIME`:

```sql
radmin=# LOAD PGSQL SERVERS TO RUNTIME;
LOAD
```

Let's recheck the server placement, via `runtime_pgsql_servers` table:

```sql
radmin=# SELECT hostgroup_id,hostname,port,status,comment FROM runtime_pgsql_servers;
 hostgroup_id | hostname  | port  | status | comment
--------------+-----------+-------+--------+---------
 0            | 127.0.0.1 | 15432 | ONLINE | primary-1
 1            | 127.0.0.1 | 15433 | ONLINE | replica-1
 2            | 127.0.0.1 | 15432 | ONLINE | primary-2
 2            | 127.0.0.1 | 15433 | ONLINE | replica-2
(4 rows)
```

Our servers originally in hostgroup `0` are now placed on both `0` (`writer_hostgroup`) and `1`
(`reader_hostgroup`) automatically. This placement is based on the value they returned for the `read_only`
checks `Monitor` is performing. The other two servers, the ones we configured in hostgroup `2`, haven't
suffered any hostgroup changes as their hostgroup isn't present in any `pgsql_replication_hostgroups` entry,
and thus, it's not subject to `read_only` monitoring.

Everytime `ProxySQL` performs monitoring actions, these actions will be reflected in the error log. Let's take
a brief look to it by parts, just to confirm how our configuration promotion lead to the `read_only` actions
handling the automatic server placement:

```
2025-05-15 10:14:41 Admin_Handler.cpp:284:is_admin_command_or_alias(): [INFO] Received LOAD PGSQL SERVERS TO RUNTIME command
... // Promotion of the servers configuration tables, checksums computations, etc...
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:1209:commit(): [INFO] Generating runtime pgsql servers and pgsql servers v2 records.
... // Detection of the new 'replication_hostgroups' table config
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:1672:generate_pgsql_replication_hostgroups_table(): [INFO] New pgsql_replication_hostgroups table
writer_hostgroup: 0 , reader_hostgroup: 1, check_type read_only, comment: pg-repl
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:4248:generate_pgsql_hostgroup_attributes_table(): [INFO] New pgsql_hostgroup_attributes table
... // Info on internal table rebuilding and checksums recomputations
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:1428:commit(): [INFO] Checksum for table pgsql_servers is 0xBB35D4E09A942177
... // Rebuilding of internal structures
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:956:update_hostgroup_manager_mappings(): [INFO] Rebuilding 'Hostgroup_Manager_Mapping' due to checksums change - pgsql_servers { old: 0x9A942177BB35D4E0, new: 0x9A942177BB35D4E0 }, pgsql_replication_hostgroups { old:0x0, new:0x2B58B3A1746ED7AB }
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:1464:commit(): [INFO] PgSQL_HostGroups_Manager::commit() locked for 4ms
... // Read-Only actions taking place due to the new config on `pgsql_replication_hostgroups`
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:3673:read_only_action_v2(): [INFO] read_only_action_v2() detected RO=0 on server 127.0.0.1:15432 for the first time after commit(), but no need to reconfigure
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:3701:read_only_action_v2(): [INFO] Server '127.0.0.1:15433' found with 'read_only=1', but not found as reader
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:4588:insert_HGM(): [INFO] Creating new server in HG 1 : 127.0.0.1:15433 , weight=1, status=0
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:4603:remove_HGM(): [WARNING] Removed server at address 0x50e00016a280, hostgroup 0, address 127.0.0.1 port 15433. Setting status OFFLINE HARD and immediately dropping all free connections. Used connections will be dropped when trying to use them
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:3709:read_only_action_v2(): [INFO] Regenerating table 'pgsql_servers' due to actions on server '127.0.0.1:15433'
2025-05-15 10:14:41 PgSQL_HostGroups_Manager.cpp:3736:read_only_action_v2(): [INFO] Checksum for table pgsql_servers is 0xC89E7F64AF5EEF70
```

Changing the servers original placement, from hostgroup `0` to `1` will affect their final positions, this was
to do with the definition of [pgsql-monitor_writer_is_also_reader][15]:

> When a node changes its read_only value from `1` to `0`, this variable determines if the node should be
> present in both hostgroups or not: ...

Let's check using the replication setup:

```sql
radmin=# UPDATE pgsql_servers SET hostgroup_id=1 WHERE comment LIKE "%-1%";
UPDATE 2
radmin=# LOAD PGSQL SERVERS TO RUNTIME;
LOAD
radmin=# SELECT hostgroup_id,hostname,port,status,comment FROM runtime_pgsql_servers;
 hostgroup_id | hostname  | port  | status |  comment
--------------+-----------+-------+--------+-----------
 0            | 127.0.0.1 | 15432 | ONLINE | primary-1
 1            | 127.0.0.1 | 15432 | ONLINE | primary-1
 1            | 127.0.0.1 | 15433 | ONLINE | replica-1
 2            | 127.0.0.1 | 15432 | ONLINE | primary-2
 2            | 127.0.0.1 | 15433 | ONLINE | replica-2
(5 rows)
```

As expected per the current default value for [pgsql-monitor_writer_is_also_reader][15] (`true`), our writer,
`primary-1` has been placed in both hostgroups, since it has been moved from hostgroup `1` to `0`. Changing
the value for [pgsql-monitor_writer_is_also_reader][15], we can check the other behavior:

```sql
radmin=# SET pgsql-monitor_writer_is_also_reader=false;
UPDATE 1
radmin=# LOAD PGSQL VARIABLES TO RUNTIME;
LOAD
radmin=# LOAD PGSQL SERVERS TO RUNTIME;
LOAD
radmin=# SELECT hostgroup_id,hostname,port,status,comment FROM runtime_pgsql_servers;
 hostgroup_id | hostname  | port  | status |  comment
--------------+-----------+-------+--------+-----------
 0            | 127.0.0.1 | 15432 | ONLINE | primary-1
 1            | 127.0.0.1 | 15433 | ONLINE | replica-1
 2            | 127.0.0.1 | 15432 | ONLINE | primary-2
 2            | 127.0.0.1 | 15433 | ONLINE | replica-2
(4 rows)
```

This concludes the essentials of `read-only` checks configuration using `pgsql_replication_hostgroups`.

### Extended Configuration

In the previous section we have explored a replication setup, with all the basic configuration required for
it. In this section, we will briefly comment about the monitoring model that `ProxySQL` uses for `PostgreSQL`,
and how we can tune monitoring actions processing and resources. Let's recheck the available config variables:

```sql
radmin=# SHOW VARIABLES LIKE 'pgsql-%monitor%';
               Variable_name               |  Value
-------------------------------------------+----------
 pgsql-monitor_enabled                     | true
 pgsql-monitor_connect_interval_window     | 50
 pgsql-monitor_ping_interval_window        | 10
 pgsql-monitor_ping_max_failures           | 3
 pgsql-monitor_ping_timeout                | 1000
 pgsql-monitor_read_only_interval          | 1000
 pgsql-monitor_read_only_interval_window   | 10
 pgsql-monitor_read_only_timeout           | 800
 pgsql-monitor_read_only_max_timeout_count | 3
 pgsql-monitor_username                    | proxymon
 pgsql-monitor_password                    | proxymon
 pgsql-monitor_threads                     | 2
 pgsql-monitor_writer_is_also_reader       | true
 pgsql-monitor_history                     | 600000
 pgsql-monitor_connect_interval            | 60000
 pgsql-monitor_connect_timeout             | 600
 pgsql-monitor_ping_interval               | 8000
 pgsql-monitor_dbname                      | postgres
(17 rows)
```

Most of the variables, are self explanatory or we have briefly revisit them. Let's focus on the variables that
allows us to control **how** and **when** the processing of the monitoring checks takes place:

```sql
radmin=# SELECT * FROM global_variables WHERE variable_name='pgsql-monitor_threads' OR variable_name LIKE 'pgsql-monitor%_window';
              variable_name              | variable_value
-----------------------------------------+----------------
 pgsql-monitor_connect_interval_window   | 50
 pgsql-monitor_ping_interval_window      | 10
 pgsql-monitor_read_only_interval_window | 10
 pgsql-monitor_threads                   | 2
(4 rows)
```

These variables let's us control the number of worker threads (`pgsql-monitor_threads`) used to process the
operations, and the percentages of the intervals that the scheduler thread uses for spacing the operations,
thus allowing to define a "processing rate" for them. So, for example, for the default
`pgsql-monitor_connect_interval`, of `60s` and the default `pgsql-monitor_connect_interval_window` of `50%`.
The scheduler will equally space the operations during the first `30s` of the interval.

As mentioned in the [Feature Overview][16] `ProxySQL` monitoring solution for `PostgreSQL` is based on:

- Asynchronous operations: Performed by a set of worker threads (specified by `pgsql-monitor_threads`). At
  this moment, only _DNS resolution_ imposes a blocking operation.
- Tasks scheduling: The monitoring tasks are scheduled for the workers within a subset of the interval. This
  gives the user control on the burstiness and desired responsiveness of these operations.
- Connection Pooling: All monitoring operations but **CONNECT** make use of a dedicated connection pool, this
  helps to reduce the cost of monitoring checks and perform more accurate measurements. This connection pool
  is kept automatically, and it only retain connections that were used within the past **three** ping
  intervals.

Being able to modify the processing rate is an important feature that we can use to give priority to some
operations over others. For example, as the [documentation][16] mentions, `ProxySQL` only uses connects
operations as _availability checks_. They provide evidence (via table logging) that the server is reachable,
and allows to assess connection latency, but connection-establishment make them the more expensive checks. In
that sense, `ping` checks are much more relevant since `ProxySQL` uses them for `Server Shunning`, if server
is found unresponsive, and for tracking server latency (that could be used for latency awareness routing).
They are also much faster and lighter checks because no connection establishment is required, so normally we
can afford a higher processing rate for them. Finally for `read-only` checks we could also be interested in
fast-processing and responsiveness, since failover detection is directly related to them, and they are also
`faster` and `lighter` checks than `connect`.

When thinking in the responsiveness of these operations, we must take into consideration that we are only
imposing a medium delay as big as the interval percentage we are specifying for the processing window. Which
most of the time will be negligible over the interval itself.

[1]: https://proxysql.com/configuring-proxysql/
[2]: https://proxysql.com/the-admin-schemas/
[3]: https://proxysql.com/backend-server-configuration/
[4]: https://proxysql.com/configuring-proxysql/#lifecycle
[5]: https://proxysql.com/configuring-proxysql/#initialstartup
[6]: https://proxysql.com/configuring-proxysql/#reloadstartup
[7]: https://proxysql.com/configuring-proxysql/#lifecycle
[8]: https://proxysql.com/configuration-file/#configuration-file-vs-database-file
[9]: https://proxysql.com/configuration-file/
[10]: https://proxysql.com/proxysql-configuration-postgresql/
[11]: #user-guide
[12]: https://proxysql.com/startup-options/
[13]: https://github.com/ProxySQL/non-prod-demo-infras/postgres-primary-replica
[14]: https://proxysql.com/global-variables/pgsql-monitor-variables/
[15]: https://proxysql.com/global-variables/pgsql-monitor-variables/#pgsql-monitor_writer_is_also_reader
[16]: #feature-overview
