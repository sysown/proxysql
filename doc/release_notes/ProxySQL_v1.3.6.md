## ProxySQL v1.3.6

Release date: 2017-04-22

Stable release v1.3.6 , released on 2017-04-22

Compared to v1.3.5, has the following bugs fixed / enhancements:

* General: automatically enable `SO_REUSEPORT` if kernel supports it #997
* Connection Pool: tracking `sql_log_bin`, `sql_mode` and `time_zone`, backported from 1.4 #972
* Mirror: mirroring commit could cause a crash
* Mirror: `SHOW PROCESSLIST` on Admin could cause a crash
* Connection Pool: crash on connection timeout and fast forward #979
* Admin: coverted several variables errors into warnings #992
* Query Processor: suppot for `-- ` comments #995
* Connection pool: fixed unbalanced traffic in case of high weights #975
* Connection pool: fixed infinite loop in case of broken connection, that could lead to high CPU usage #990
* Query Processor: query retry during `STMT_EXECUTE` causes a crash #998
* Query Processor: in some circumstances, error packets were malformed #1001
