## Overview

`Error Log` was introduced in ProxySQL since version `0.1`. This feature allows messages produced by ProxySQL
to be logged into a file. When ProxySQL is launched with the `-f` option, all messages go to `stdout`. To
enable this feature, set the variable [errorlog][1] in the [config file][2] to a file where the logging will
be performed. This must be an **absolute path**. Relative paths lead to unexpected results. When enabled, the
following events are logged:

- Startup messages
- Exit messages
- Loaded plugins
- Error messages
- Warning messages
- Info messages
- Debug messages
- Variable setting

## Variables

- [errorlog][1]: this variable defines the base name of the error log where events are logged. The default
  value of this variable is `[datadir]/proxysql.log` where [datadir][1] is set in the config file or by the
  `-D` option. This must be an **absolute path**. Relative paths lead to unexpected results.
- [mysql-verbose_query_error][3]: this variable controls the verbosity of query errors. Set to `true` to
  increase the verbosity.

<!-- -->

Future versions may enable runtime `errorlog` configuration.

## Logging format

The current implementation supports only one logging format: syslog like plain text Attributes:

- `date`: Date as YYYY-MM-DD.
- `time`: Time as HH:MM:SS localtime.
- `file:line:function:`: Urace to message producing source code line.
- `[loglevel]`: info, warn, error, debug levels.
- `message`: Detailed message, can contain multiple lines.

<!-- -->

## Log rotation

To rotate the log, first rename the logfile to a new name, and issue the ProxySQL command

```
PROXYSQL FLUSH LOGS;
```

To rotate logs using logrotate, use this config in `/etc/logrotate.d/proxysql`:

```
/var/lib/proxysql/proxysql.log {
daily
rotate 7
missingok
notifempty
compress
postrotate
/usr/bin/mysql --login-path=logrotate -e "PROXYSQL FLUSH LOGS"
endscript
create 0600 root root
}
```

Also add credentials to the mysql credentials store:

```
mysql_config_editor set --login-path=logrotate --host=localhost --user=logrotate --password
```

And set up the user in ProxySQL:

```
INSERT INTO mysql_users (username,password,active) values ('logrotate','SecretPass123',1)
```

## Errorlog vs stdout

Messages that are produced before error log is initialized are not captured. This affects only a few early
initialization messages. If you want to capture also these early messages, running ProxySQL in foreground with
stdout and stderr redirection is advised:

```
proxysql -f --idle-threads -D /var/lib/proxysql -c /etc/proxysql.cnf &> /var/log/proxysql/proxysql-error.log
```

## Error Log example

Below is an error log example.

```
2022-06-10 17:11:36 [INFO] ProxySQL version 2.4.1-12-g3afcc12
2022-06-10 17:11:36 [INFO] Detected OS: Linux trx 5.17.11-xanmod1-x64v2 #0~git20220525.9ffe6c5 SMP Wed May 25 21:27:30 UTC 2022 x86_64
2022-06-10 17:11:36 [INFO] ProxySQL SHA1 checksum: 760ce855664901607cd41b883b386bffda88b3f2
2022-06-10 17:11:36 [INFO] Starting ProxySQL
2022-06-10 17:11:36 [INFO] Successfully started
2022-06-10 17:11:36 [INFO] Angel process started ProxySQL process 3939546
2022-06-10 17:11:36 [INFO] Loaded built-in SQLite3
Standard ProxySQL MySQL Logger rev. 2.0.0714 -- MySQL_Logger.cpp -- Mon May 30 07:00:09 2022
Standard ProxySQL Cluster rev. 0.4.0906 -- ProxySQL_Cluster.cpp -- Mon May 30 07:00:09 2022
Standard ProxySQL Statistics rev. 1.4.1027 -- ProxySQL_Statistics.cpp -- Mon May 30 07:00:09 2022
Standard ProxySQL HTTP Server Handler rev. 1.4.1031 -- ProxySQL_HTTP_Server.cpp -- Mon May 30 07:00:09 2022
2022-06-10 17:11:36 [INFO] Using UUID: 9588556d-fc2d-48ac-9c48-201abab06768 . Writing it to database
2022-06-10 17:11:36 ProxySQL_Admin.cpp:6605:flush_mysql_variables___database_to_runtime(): [WARNING] Impossible to set not existing variable ping_interval_server with value "10000". Deleting. If the variable name is correct, this version doesn't support it
Standard ProxySQL Admin rev. 2.0.6.0805 -- ProxySQL_Admin.cpp -- Mon May 30 07:00:09 2022
2022-06-10 17:11:36 [INFO] ProxySQL SHA1 checksum: 760ce855664901607cd41b883b386bffda88b3f2
Standard MySQL Threads Handler rev. 0.2.0902 -- MySQL_Thread.cpp -- Mon May 30 07:00:09 2022
Standard MySQL Authentication rev. 0.2.0902 -- MySQL_Authentication.cpp -- Mon May 30 07:00:09 2022
2022-06-10 17:11:36 [INFO] Dumping mysql_servers_incoming
+--------------+-----------+------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+-------------+
| hostgroup_id | hostname | port | gtid_port | weight | status | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms | comment |
+--------------+-----------+------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+-------------+
| 0 | 127.0.0.1 | 3306 | 0 | 1 | 0 | 0 | 200 | 0 | 0 | 0 | test server |
+--------------+-----------+------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+-------------+
2022-06-10 17:11:36 [INFO] Dumping mysql_servers LEFT JOIN mysql_servers_incoming
+-------------+--------------+----------+------+
| mem_pointer | hostgroup_id | hostname | port |
+-------------+--------------+----------+------+
+-------------+--------------+----------+------+
2022-06-10 17:11:36 [INFO] Dumping mysql_servers JOIN mysql_servers_incoming
+--------------+-----------+------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+-------------+-------------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+-------------+
| hostgroup_id | hostname | port | gtid_port | weight | status | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms | comment | mem_pointer | gtid_port | weight | status | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms | comment |
+--------------+-----------+------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+-------------+-------------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+-------------+
| 0 | 127.0.0.1 | 3306 | 0 | 1 | 0 | 0 | 200 | 0 | 0 | 0 | test server | 0 | 0 | 1 | 0 | 0 | 200 | 0 | 0 | 0 | test server |
+--------------+-----------+------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+-------------+-------------+-----------+--------+--------+-------------+-----------------+---------------------+---------+----------------+-------------+
2022-06-10 17:11:36 [INFO] Creating new server in HG 0 : 127.0.0.1:3306 , gtid_port=0, weight=1, status=0
2022-06-10 17:11:36 [INFO] New mysql_group_replication_hostgroups table
2022-06-10 17:11:36 [INFO] New mysql_galera_hostgroups table
2022-06-10 17:11:36 [INFO] New mysql_aws_aurora_hostgroups table
2022-06-10 17:11:36 [INFO] Checksum for table mysql_servers is 17518514293925156575
2022-06-10 17:11:36 [INFO] Checksum for table mysql_replication_hostgroups is 13209726424736073806
2022-06-10 17:11:36 [INFO] MySQL_HostGroups_Manager::commit() locked for 1ms
Standard Query Processor rev. 2.0.6.0805 -- Query_Processor.cpp -- Mon May 30 07:00:09 2022
In memory Standard Query Cache (SQC) rev. 1.2.0905 -- Query_Cache.cpp -- Mon May 30 07:00:09 2022
Standard MySQL Monitor (StdMyMon) rev. 2.0.1226 -- MySQL_Monitor.cpp -- Mon May 30 07:00:09 2022
2022-06-10 17:11:36 [INFO] For information about products and services visit: https://proxysql.com/
2022-06-10 17:11:36 [INFO] For online documentation visit: https://proxysql.com/
2022-06-10 17:11:36 [INFO] For support visit: https://proxysql.com/services/support/
2022-06-10 17:11:36 [INFO] For consultancy visit: https://proxysql.com/services/consulting/
2022-06-10 17:11:36 MySQL_Monitor.cpp:968:monitor_connect_thread(): [ERROR] Server 127.0.0.1:3306 is returning "Access denied" for monitoring user
2022-06-10 17:11:36 [INFO] Latest ProxySQL version available: 2.4.1-1-g1ea371d
```

[1]: https://proxysql.com/configuration-file/#general-variables
[2]: https://proxysql.com/configuration-file/
[3]: https://proxysql.com/global-variables/mysql-variables/#mysql-verbose_query_error
