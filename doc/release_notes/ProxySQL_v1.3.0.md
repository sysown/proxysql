# ProxySQL v1.3.0

Release date: 2016-10-19

## Performance improvement

* support for millions of connections. It is also able to handle workloads with hundreds thousands client connections, but only few connections are active. For example, 100k total connections, but only 100 active connections.
* use of pthread_mutex for connection pool
* several performance improvements


## Usability improvement

* Packaging: version number now includes commit hash
* Monitor: limit the number of Monitor thread to 16


## New features

* EXPERIMENTAL support for proepared statements
* Connection Pool: each MySQL_Thread now has a pair thread, therefore the number of threads executed are mysql-threads x 2 . The second set of MySQL_Threads are responsible to only handle idle connections.  
  It also introduced two new global variables and a new global status:
  * `mysql-session_idle_ms` (default 1000) : when a session is idle for that long, it is moved to a thread responsible to handle idle connections
  * `mysql-session_idle_show_processlist` (default false) : specifies if idle connections are displayed on SHOW PROCESSLIST or on any query against `stats_mysql_processlist`  
  * `Client_Connections_non_idle` : returns the number of client connections that are not idle, therefore handled by the main MySQL_Threads and not moved to the second set of MySQL_Threads responsible to only handle idle connections
* Network: add support for IPv6 [#726](../../../../issues/726) and [#460](../../../../issues/460), thanks to @ton31337
* Connection Pool: support for SO_REUSEPORT, it can be only enabled on the command line with -r or --reuseport at startup
* Query Processor: added new variable mysql-digests_lowercase to always set digest to lowercase [#725](../../../../issues/725)


## Bug fixes

* Query Processor: rules with only digest were matching everything [#717](../../../../issues/717)
* Query Processor: rules without digest where incorrectly displayed [#719](../../../../issues/719)
* General: Unix Socket Domain file was not removed at shutdown [#714](../../../../issues/714)
* MySQL Protocol: upgrade from mariadb-connector-c 2.1.0 to 2.3.1 due to several bugs
* Connection Pool: server is not shunned if max_user_connections is reached for user [#737](../../../../issues/737)

