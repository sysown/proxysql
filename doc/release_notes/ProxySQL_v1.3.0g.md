# ProxySQL v1.3.0 , v1.3.0f v1.3.0g

## ProxySQL v1.3.0

Release date: 2016-10-19

### Performance improvement

* support for millions of connections. It is also able to handle workloads with hundreds thousands client connections, but only few connections are active. For example, 100k total connections, but only 100 active connections.
* use of pthread_mutex for connection pool
* several performance improvements


### Usability improvement

* Packaging: version number now includes commit hash
* Monitor: limit the number of Monitor thread to 16


### New features

* EXPERIMENTAL support for proepared statements
* Connection Pool: each MySQL_Thread now has a pair thread, therefore the number of threads executed are mysql-threads x 2 . The second set of MySQL_Threads are responsible to only handle idle connections.  
  It also introduced two new global variables and a new global status:
  * `mysql-session_idle_ms` (default 1000) : when a session is idle for that long, it is moved to a thread responsible to handle idle connections
  * `mysql-session_idle_show_processlist` (default false) : specifies if idle connections are displayed on SHOW PROCESSLIST or on any query against `stats_mysql_processlist`  
  * `Client_Connections_non_idle` : returns the number of client connections that are not idle, therefore handled by the main MySQL_Threads and not moved to the second set of MySQL_Threads responsible to only handle idle connections
* Network: add support for IPv6 [#726](../../../../issues/726) and [#460](../../../../issues/460), thanks to @ton31337
* Connection Pool: support for SO_REUSEPORT, it can be only enabled on the command line with -r or --reuseport at startup
* Query Processor: added new variable mysql-digests_lowercase to always set digest to lowercase [#725](../../../../issues/725)


### Bug fixes

* Query Processor: rules with only digest were matching everything [#717](../../../../issues/717)
* Query Processor: rules without digest where incorrectly displayed [#719](../../../../issues/719)
* General: Unix Socket Domain file was not removed at shutdown [#714](../../../../issues/714)
* MySQL Protocol: upgrade from mariadb-connector-c 2.1.0 to 2.3.1 due to several bugs
* Connection Pool: server is not shunned if max_user_connections is reached for user [#737](../../../../issues/737)


## ProxySQL v1.3.0f


Release date: 2016-10-29  
Compared to v1.3.0:

### New features

* killed query because of query_timeout returns error 1907 [#750](../../../../issues/750)
* removes any lower limit for query_timeout (before was 300ms)
* added support for `STMT_SEND_LONG_DATA` [#764](../../../../issues/764)
* new customer error codes for `Max connect timeout` [#761](../../../../issues/761) and [wiki](https://github.com/sysown/proxysql/wiki/Error-codes)

### Bug fixes

* `mysql_query_rules`.`log` not working [#723](../../../../issues/723)
* clients are disconnected if server is running for less than 8 hours [#744](../../../../issues/744)
* remove annoying error from Admin when running `\s` [#745](../../../../issues/745)
* escaping errors on `INSERT INTO stats_mysql_processlist` [#746](../../../../issues/746)
* kill threads were using wrong credentials due to encrypted passwords
* on slow network, client connections could become stall
* `session_idle_ms` was processed as us instead of ms
* `mysql_close` was trying to close prepared statements on already closed connection [#765](../../../../issues/765)



## ProxySQL v1.3.0g

Release date: 2016-11-14  
Compared to v1.3.0f

### New features

* when a connection attempts receive error 1226, retry mechanism is disabled [#786](../../../../issues/786)
* better support for IPv6
* more verbose message on connection timeout [#776](../../../../issues/776)
* removed some race conditions during `PROXYSQL RESTART`
* `Access denied` message reports source (client) [#795](../../../../issues/795)
* `SHOW TABLES FROM xxx` is now sorted [#788](../../../../issues/788)
* allows rules on proxy_port without proxy_addr [#712](../../../../issues/712)
* Monitor threads are started without arena cache
* Monitor threads are started with 64KB stack

### Bug fixes

* validate `mysql` state before calling `mysql_stmt_free_result()` [#779](../../../../issues/779)
* `SHUNNED_REPLICATION_LAG` does not stop queries [#774](../../../../issues/774)
* `mysql_servers`.`comment` not loaded at runtime [#787](../../../../issues/787)
* fixed two memory leak in Monitor , reported in [#766](../../../../issues/766) and [#796](../../../../issues/796)

### Others

* upgraded jemalloc from 4.2.1 to 4.3.1
* jemalloc is compiled with `--enable-prof`
* added few memory sanitizers

