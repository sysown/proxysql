## ProxySQL v1.3.6

Release date: 2017-04-xx

Stable release v1.3.6 , released on 2017-04-xx

Compared to v1.3.4, has the following bugs fixed / enhancements:

* General: automatically enable `SO_REUSEPORT` is kernel supports it
* Connection Pool: tracking `sql_log_bin`, `sql_mode` and `time_zone`, backported from 1.4 #972
* Mirror: mirroring commit could cause a crash
* Mirror: `SHOW PROCESSLIST` on Admin could cause a crash
* Connection Pool: crash on connection timeout and fast forward #979
* Admin: coverted several variables errors into warnings #992

