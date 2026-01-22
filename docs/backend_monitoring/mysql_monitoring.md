# MySQL Monitor Module

## Overview

The Monitor Module is responsible for a series of checks against the backends. It currently supports 4 types
of checks:

- **connect** : it connects to all the backends, and success/failure is logged in table
  `mysql_server_connect_log`;
- **ping** : it pings to all the backends, and success/failure is logged in table `mysql_server_ping_log` . In
  the case of `mysql-monitor_ping_max_failures` missing a heartbeat, it sends a signal to
  MySQL_Hostgroups_Manager to kill all connections;
- **replication lag** : it checks `Seconds_Behind_Master` to all backends configured with
  `max_replication_lag` greater than 0, and the check is logged in table `mysql_server_replication_lag_log`.
  If `Seconds_Behind_Master`\ > `max_replication_lag` the server is shunned until `Seconds_Behind_Master` <
  `max_replication_lag` ;
- **read only** : it checks `read_only` for all hosts in the hostgroups in table
  `mysql_replication_hostgroups`, and the check is logged in table `mysql_server_read_only_log` . If
  `read_only=1` the host is copied/moved to the `reader_hostgroup`, while if `read_only=0` the host is
  copied/moved to the `writer_hostgroup` .

<!-- -->

# Tables

These tables contain the monitor log data and are managed by the monitor module.

```mysql
Admin> SHOW CREATE TABLE monitor.mysql_server_connect_log\G
*************************** 1. row ***************************
       table: mysql_server_connect_log
Create Table: CREATE TABLE mysql_server_connect_log (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    time_start_us INT NOT NULL DEFAULT 0,
    connect_success_time_us INT DEFAULT 0,
    connect_error VARCHAR,
    PRIMARY KEY (hostname, port, time_start_us))
1 row in set (0.00 sec)
```

```mysql
Admin> SHOW CREATE TABLE monitor.mysql_server_ping_log\G
*************************** 1. row ***************************
       table: mysql_server_ping_log
Create Table: CREATE TABLE mysql_server_ping_log (
     hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    time_start_us INT NOT NULL DEFAULT 0,
    ping_success_time_us INT DEFAULT 0,
    ping_error VARCHAR,
    PRIMARY KEY (hostname, port, time_start_us))
1 row in set (0.00 sec)
```

```mysql
Admin> SHOW CREATE TABLE monitor.mysql_server_replication_lag_log\G
*************************** 1. row ***************************
       table: mysql_server_replication_lag_log
Create Table: CREATE TABLE mysql_server_replication_lag_log (
     hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    time_start_us INT NOT NULL DEFAULT 0,
    success_time_us INT DEFAULT 0,
    repl_lag INT DEFAULT 0,
    error VARCHAR,
    PRIMARY KEY (hostname, port, time_start_us))
1 row in set (0.00 sec)
```

```mysql
Admin> SHOW CREATE TABLE monitor.mysql_server_read_only_log\G
*************************** 1. row ***************************
       table: mysql_server_read_only_log
Create Table: CREATE TABLE mysql_server_read_only_log (
     hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    time_start_us INT NOT NULL DEFAULT 0,
    success_time_us INT DEFAULT 0,
    read_only INT DEFAULT 1,
    error VARCHAR,
    PRIMARY KEY (hostname, port, time_start_us))
1 row in set (0.01 sec)
```

See variable _mysql-monitor_history_

# Variables

General variables:

- _mysql-monitor_username_ - Specifies the username that the Monitor module will use to connect to the
  backend. The user needs only `USAGE` privileges to connect, ping and check `read_only`. The user needs also
  `REPLICATION CLIENT` privilege if it needs to monitor replication lag.
- _mysql-monitor_password_ - Password for user _mysql-monitor_username_
- _mysql-monitor_enabled_ - It enables or disables MySQL Monitor. Since MySQL Monitor can interfere with
  changes applied directly on the Admin interface, this variable allows to temporary disable it.

<!-- -->

Connect variables:

- _mysql-monitor_connect_interval_ - How frequently a connect check is performed, in milliseconds.
- _mysql-monitor_connect_timeout_ - Connection timeout in milliseconds. The current implementation rounds up
  this value to an integer number of seconds less or equal to the original interval, with 1 second as minimum.
  This lazy rounding is done because SSL connections are blocking calls.

<!-- -->

Ping variables:

- _mysql-monitor_ping_interval_ - How frequently a ping check is performed, in milliseconds.
- _mysql-monitor_ping_timeout_ - Ping timeout in milliseconds.
- _mysql-monitor_ping_max_failures_ - If a host misses _mysql-monitor_ping_max_failures_ pings in a row,
  MySQL_Monitor informs MySQL_Hostgroup_Manager that the node is unreachable and that it should immediately
  kill all connections. It is important to note that in case a connection to the backend is not available,
  MySQL_Monitor will first try to connect in order to ping, therefore the time to detect that a node is down
  could be one of these two:

  - _mysql-monitor_ping_max_failures_ \* _mysql-monitor_connect_timeout_
  - _mysql-monitor_ping_max_failures_ \* _mysql-monitor_ping_timeout_

    <!-- -->

<!-- -->

Read only variables:

- _mysql-monitor_read_only_interval_ - How frequently a read only check is performed, in milliseconds.
- _mysql-monitor_read_only_timeout_ - Read only check timeout in milliseconds.
- _mysql-monitor_writer_is_also_reader_ - When a node changes its `read_only` value from 1 to 0, this variable
  determines if the node should be present in both hostgroups or not:

  - _false_ : node will be moved into `writer_hostgroup` and removed from `reader_hostgroup`
  - _true_ : node will be copied into `writer_hostgroup` and stay also in `reader_hostgroup`

    <!-- -->

<!-- -->

Replication lag variables:

- _mysql-monitor_replication_lag_interval_ - How frequently a replication lag check is performed, in
  milliseconds.
- _mysql-monitor_replication_lag_timeout_ - Replication lag check timeout in milliseconds.

<!-- -->

Other variables:

- _mysql-monitor_history_ - To prevent log tables from growing without limits, Monitor Module will
  automatically purge records older than _mysql-monitor_history_ milliseconds. Since ping checks relies on the
  history table to determine if a node is missing heartbeats, the value of _mysql-monitor_history_ is
  automatically adjusted to the following if it's less than that:

  - (_mysql-monitor_ping_max_failures_ + 1 ) \* _mysql-monitor_ping_timeout_

    <!-- -->

<!-- -->

# Main Threads

The Monitor Module has several internal threads. There are currently 5 main threads:

- Monitor: master thread, responsible for starting and coordinating all the others
- monitor_connect_thread: main thread and scheduler for the connect checks
- monitor_ping_thread: main thread and scheduler for the ping checks
- monitor_read_only_thread: main thread and scheduler for the read only checks
- monitor_replication_lag_thread: main thread and scheduler for the replication lag checks Up to version
  v1.2.0 the above threads, excluding _Monitor_, were also responsible to perform the checks

<!-- -->

# Thread Pool

The implementation in v1.2.0 has a limitation with SSL implementation: with SSL, `connect()` is a blocking
call, causing the threads to stall while performing the connect phase. Version v1.2.1 tries to overcome this
limitation with a new implementation. Now:

- _Monitor_ initializes a Thread Pool of workers and creates a queue;
- _monitor_connect_thread_, _monitor_ping_thread_, _monitor_read_only_thread_ and
  _monitor_replication_lag_thread_ are producers that generate tasks and send them to the workers using the
  queue;
- the workers process the tasks and perform the required actions;
- if _Monitor_ detects that the queue is growing too fast, it creates new temporary worker threads

<!-- -->

# Connection purging

Monitor implements its own connection pool. Connections that are alive for more than
`3 * mysql_thread___monitor_ping_interval` milliseconds are automatically purged.

## wait_timeout

To prevent backends from terminating connections, Monitor module automatically configures
`wait_timeout = mysql_thread___monitor_ping_interval * 10`
