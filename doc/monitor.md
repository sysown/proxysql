Monitor Module
==============

This section focus on Monitor v1.3, as it introduces multiple improved compared to v1.2


Variables removed as unused or deprecated:
* mysql-monitor_query_variables
* mysql-monitor_query_status
* mysql-monitor_timer_cached

Variables currently not in use:
* mysql-monitor_query_interval
* mysql-monitor_query_timeout

Overview
--------
Monitor Module is responsible for a series of check against the backends.
It currently supports 4 types of checks:
* **connect** : it connects to all the backends, and success/failure is logged in table `mysql_server_connect_log`;
* **ping** : it pings to all the backends, and success/failure is logged in table `mysql_server_ping_log` . In case of `mysql-monitor_ping_max_failures` missed heartbeat, sends a signal to MySQL_Hostgroups_Manager to kill all connections;
* **replication lag** : it checks `Seconds_Behind_Master` to all backends configured with `max_replication_lag` greater than 0, and check is logged in table `mysql_server_replication_lag_log`. If `Seconds_Behind_Master` > `max_replication_lag` the server is shunned until `Seconds_Behind_Master` < `max_replication_lag` ;
* **read only** : it checks `read_only` for all hosts in the hostgroups in table `mysql_replication_hostgroups`, and check is logged in table `mysql_server_read_only_log` . If `read_only=1` the host is copied/moved to the `reader_hostgroup`, while if `read_only=0` the host is copied/moved to the `writer_hostgroup` .


Variables
=========
General variables:
* *mysql-monitor_username*

  Specifies the username that the Monitor module will use to connect to the backend. The user needs only `USAGE` privileges to connect, ping and check `read_only`. The user needs also `REPLICATION CLIENT` if it needs to monitor replication lag.
  
* *mysql-monitor_password*

  Password for user *mysql-monitor_username*
  
Connect variables:
* *mysql-monitor_connect_interval*

  How frequently a connect check is performed, in milliseconds.

* *mysql-monitor_connect_timeout*

  Connection timeout in milliseconds. The current implementation rounds this value to an integer number of seconds less or equal to the original interval, with 1 second as minimum. This lazy rouding is done because SSL connections are blocking calls.

Ping variables:
* *mysql-monitor_ping_interval*

  How frequently a ping check is performed, in milliseconds.

* *mysql-monitor_ping_timeout*

  Ping timeout in milliseconds.

* *mysql-monitor_ping_max_failures*

  If a host misses *mysql-monitor_ping_max_failures* pings in a row, MySQL_Monitor informs MySQL_Hostgroup_Manager that the node is unreacheable and that should immediately kill all connections.
  It is important to note that in case a connection to the backend is not available, MySQL_Monitor will first try to connect in order to ping, therefore the time to detect a node down could be one of the two:
  * *mysql-monitor_ping_max_failures* * *mysql-monitor_connect_timeout*
  * *mysql-monitor_ping_max_failures* * *mysql-monitor_ping_timeout*

Read only variables:

* *mysql-monitor_read_only_interval*

  How frequently a read only check is performed, in milliseconds.

* *mysql-monitor_read_only_timeout*

  Read only check timeout in milliseconds.

* *mysql-monitor_writer_is_also_reader*

  When a node change its `read_only` value from 1 to 0, this variable determines if the node should be present in both hostgroups or not:
  * *false* : node will be moved in `writer_hostgroup` and removed from `reader_hostgroup`
  * *true* : node will be copied in `writer_hostgroup` and stay also in `reader_hostgroup`

Replication lag variables:

* *mysql-monitor_replication_lag_interval*

  How frequently a replication lag check is performed, in milliseconds.

* *mysql-monitor_replication_lag_timeout*

  Replication lag check timeout in milliseconds.

Other variables:

* *mysql-monitor_history*

  To prevent that log tables grow without limit, Monitor Module will automatically purge records older than *mysql-monitor_history* milliseconds. Since ping checks relies on history table to determine if a node is missing heartbeats, the value of *mysql-monitor_history* is automatically adjusted to the follows if less than it:
  * (*mysql-monitor_ping_max_failures* + 1 ) * *mysql-monitor_ping_timeout*


Main Threads
============
The Monitor Module has several internal threads. There are currently 5 main threads:
* Monitor: master thread, responsible to start and coordinate all the others
* monitor_connect_thread: main thread and scheduler for the connect checks
* monitor_ping_thread: main thread and scheduler for the ping checks
* monitor_read_only_thread: main thread and scheduler for the read only checks
* monitor_replication_lag_thread: main thread and scheduler for the replication lag checks
Up to version v1.2 the above threads but *Monitor* were also responsible to perform the checks

Thread Pool
===========
The implementation in v1.2 has a limitation with SSL implementation: with SSL, `connect()` is a blocking call, causing the threads to stall while performing the connect phase.
Version v1.3 tries to overcome this limitation with a new implementation. Now:
* *Monitor* initializes a Thread Pool of workers and creates a queue;
* *monitor_connect_thread*, *monitor_ping_thread*, *monitor_read_only_thread* and *monitor_replication_lag_thread* are producers that generate tasks and sent them to the workers using the queue;
* the workers process the tasks and perform the requires actions;
* if *Monitor* detects that the queue is growing too fast, it creates new temporary worker threads 
