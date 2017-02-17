## ProxySQL v1.3.4

Release date: 2017-xx-xx

Stable release v1.3.4 , released on 2017-xx-xx

Compared to v1.3.3, has the following bugs fixed / enhancements:

* Connection Pool: variable `mysql-connect_retries_on_failure` was hardcoded to 0 for COM_STMT_EXECUTE [#919](../../../../issues/919)
* MySQL Protocol: when variable `mysql-init_connect` was set, some prepared statements were interpreted as normal queries [#906](../../../../issues/906) 
* General: if Admin port was already in use, Admin would run in a lot consuming a lot of CPU [#895](../../../../issues/895)
* Admin: variable `admin-mysql_ifaces` had priority over cmdline option `--admin-socket` . Now `--admin-socket` has priority [#894](../../../../issues/894)
* MySQL Protocol: variable `mysql-enforce_autocommit_on_reads` was not evaluated for prepared statements [#899](../../../../issues/899)
* MySQL Protocol: `COM_CHANGE_USER` could try to reset prepared statements already invalidated from the PS manager [#897](../../../../issues/897)
