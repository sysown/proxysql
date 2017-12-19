Release date: 2017-12-20

Stable release v1.4.4 , released on 2017-12-20

Compared to v1.4.3, it has the following new features / bugs fixes / enhancements :

New features:
* Admin Module now regularly collects historical statistics of various metrics
* introduced a new web interface to export simple statistics
* added bandwidth throttling for resultsets sent from ProxySQL to client, or from MySQL server to ProxySQL: see [wiki](https://github.com/sysown/proxysql/wiki/Bandwidth-throttling)
* Added watchdog to automatically restart proxysql if MySQL threads are not reporting heartbeat: see [wiki](https://github.com/sysown/proxysql/wiki/Watchdog)
* It is now possible to configure ProxySQL to call an external script in case proxysql daemon terminates not gracefully. See [execute_on_exit_failure](https://github.com/sysown/proxysql/wiki/Configuration-file#general-variables)
* added support for `utf8mb4_0900_ai_ci` (MySQL 8)
* added new algorithm to limit the number of new connections per second to backends, controlled by variable variable `mysql-throttle_connections_per_sec_to_hostgroup`


Bug fixes:
* Connection Pool: do not terminate connections in case of errors due to read-only variable #1194
* General: Fixed compiling issue on FreeBSD #1216
* General: Fixed few anomalies detected with valgrind
* Connection poll: initialize `time_zone` in client connection #1253 
* Prepared statements: reset PS metadata if they change after a DDL #965
* Prepared statements: fixed memory corruption #1197
* Protocol: do not use autcommit from backend if set: this could lead to situation in which client believe autocommit is on, while it is not
* Query Processor: track also unknown queries #1100
* Query Processor: ignore parenthesis from queries when determining type #1100
* Prepared statements: do not send cursor. #1128 , #892 and #961
* ProxySQL Cluster: reduced the probability of a race condition while converging #1188
* ProxySQL Cluster: several minor bugs
* Monitor: added mutex in `replication_lag_action()` to avoid race conditions between two or more checks
* Admin: when parsing from config file, use port 3306 as default for servers in mysql_servers
* Admin: Allows hashed password for Admin #1221 (regression bug introduced in 1.4.3)
* Protocol: added support for collations #780 #554 #1219
* Admin: table definitions was different for `mysql_query_rules` and `runtime_mysql_query_rules` #1233
* Admin: configured mysql_users.transaction_persistent=1 if users are read from config file #1236
* Connection poll: initialize time_zone in client connection #1253 
* Connection poll: clean up query metadata when set autocommit fails #1257 
* General: do not report in error log replication hostgroups information if `hostgroup_manager_verbose=0` #1204
* Admin: configure mysql_query_rules.re_modifiers=CASELESS if mysql_query_rules are read from config file #1124
* Protocol: added support for utf8mb4_0900_ai_ci (MySQL 8) #1129
* Global variables: fixed some incorrect input validation
* MySQL Server: added contraint hostgroup_id >= 0 #1244 and #1270
* Eventlog: Persist eventlog file across restarts #1201 and #1269
* Connection Pool: disable multiplexing for `auto_increment_increment`, `auto_increment_offset` and `group_concat_max_len` #1290

Performance improvements:
* General: introduced several optimizations to reduce memory allocation overhead for small resultsets
* Query Processor: changed the default value for `mysql-stats_time_backend_query` and `mysql-stats_time_query_processor` from `true` to `false`. Depending from the workload, this can drastically boost performance
* Prepared statements: ported from 1.3 the reuse of prepared statements IDs #1198
* Prepared statements: incorrect format in Decimal fields #1192
* Connection Poll: reset connections using the current username instead of monitor user #1186
* Connection Poll: limit the size of connections reset queue #1185
* Connection Poll: added new variable `mysql-throttle_connections_per_sec_to_hostgroup` to limit the number of new connections per second to backends

General:
* added support for Darwin (although not recommended for production)
* added IPv6 support for Admin and localhost: allow to connect locally using user admin
* when dropping a systemd unit file, do not use daemon-reload
* report Admin's mysql_servers when executing loading to runtime #1255
* in Admin, filter commands specific to MySQL and/or transactions #1047
* removed tables mysql_server_connect and mysql_server_ping from monitor, because unused #1252
