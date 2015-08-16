v0.3.0-beta1
============= 

* using libdaemon to daemonize the ProxySQL process
* added angel process that is able to monitor and restart ProxySQL
* added separate error log
* using MariaDB client library + libevent for connecting and querying backend MySQL servers
* added a per-user:
  * max_connection value that limits the number of connections from the same user
  * transaction_persistent flag that keeps transactions within the same hostgroup for a certain user 
* add debug build target (make debug will now build a binary with vs. make)
* introduce support for packets larger than 16 MB (the maximal single packet size from MySQL binary protocol)
* handling in-memory stats database locking errors gracefully by retrying (this leads to less errors when gathering stats under load)
* added SHOW PROCESSLIST command for admin interface that aggregates running queries from all backends
* added possibility of killing a query from a remote backend server
* implemented LOAD MYSQL QUERY RULES FROM CONFIG
* implemented SAVE MYSQL USERS FROM RUNTIME
* implemented PROXYSQL FLUSH LOGS that makes log rotation possible
* implemented some new admin interface queries
  * select @@version_comment limit 1
  * show charset
  * show collation
  * show tables from
* added new admin tables
  * stats_mysql_processlist
  * stats_mysql_connection_pool
  * stats_mysql_query_digest
  * stats_mysql_query_digest_reset
* added new variables for config file
  * connect_timeout_server_max
  * free_connections_pct
  * connect_retries_delay
  * max_transaction_time
  * max_connections
  * default_query_delay
  * default_query_timeout
  * sessions_sort
  * default_reconnect
* improved logging
* support for 2 different config files
  * proxysql.cfg
  * proxysql.cnf