## ProxySQL v1.3.5

Release date: 2017-03-26

Stable release v1.3.5 , released on 2017-03-26

Compared to v1.3.4, has the following bugs fixed / enhancements:

* General: uninitialized struct addrinfo could cause bind() to fail
* Query processor: Disable multiplexing for SQL_CALC_FOUND_ROWS #732
* Connection Pool: Fixed more crashes when using multiple users #897
* Authentication: Ensure that users num_connections_used does not get increment if connection rejected #942
* Authentication: Fixed a leak in the number of users connections (wrong counters)
* MySQL Protocol: Error in fast_forward causes a crash #733
* Admin: Allow keywords in mysql_users #911
* Admin: Added status variable ProxySQL_Uptime #947
* General: double free when handling COM_CHANGE_USER in MariaDB Async Client Library #950
* MySQL Protocolo: Incorrect processing on date/times and prepared statements #958
* Monotor: Fix edge case during master/slave promotion #959
* General: Compile eventslog_reader_sample on CentOS #964
* Query Processor: Crash on mysql-query_digests=false, mysql-commands_stats=true, and short query #970
