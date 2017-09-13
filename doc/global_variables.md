# Global Variables

The behaviour of ProxySQL can be tweaked using global variables. These can be configured in 2 ways:
* at runtime, using the admin interface (preferred)
* at startup, using the dedicated section in the configuration file

ProxySQL supports maximal uptime by allowing most variables to change at runtime and take effect immediately, without having to restart the daemon. There are only 2 variables that cannot be changed at runtime - `mysql-threads` and `mysql-stacksize`.

Also, there are 2 types of global variables, depending on which part of ProxySQL they control:
* admin variables, which control the behaviour of the admin interface. Their names begin with the token "admin-"
* mysql variables, which control the MySQL functionality of the proxy. Their names begin with the token "mysql-"

These global variables are stored in a per-thread fashion inside of the proxy in order to speed up access to them, as they are used extremely frequently. They control the behaviour of the proxy in terms of memory footprint or the number of connections accepted, and other essential aspects. Whenever a `LOAD MYSQL VARIABLES TO RUNTIME` command is issued (see the [configuration system documentation](https://github.com/sysown/proxysql-0.2/blob/master/doc/configuration_system.md) for details on that command), all the threads using the variables are notified that they have to update their values.

To change the value of a global variable either use an `UPDATE` statement:
```
UPDATE global_variables SET variable_value=1900 WHERE variable_name='admin-refresh_interval';
```
or the shorter `SET` statement, similar to MySQL's:
```
SET admin-refresh_interval = 1700;
SET admin-version = '1.1.1beta8';
```

Next, we're going to explain each type of variable in detail.

## Admin Variables

### `admin-admin_credentials`

This is a colon separated user:password pair, that can be used to authenticate to the admin interface with read-write rights. For read-only credentials that can be used to connect to the admin, see the variable `admin-stats_credentials`. Note that the admin interface listens on a separate port from the main ProxySQL thread. This port is controlled through the variable `admin-mysql_ifaces`. You can specify multiple username and password pairings seprated by a semicolon ";"

Default value: `admin:admin`.

### `admin-mysql_ifaces`

Semicolon-separated list of hostname:port entries for interfaces on which the admin interface should listen on. Note that this also supports UNIX domain sockets for the cases where the connection is done from an application on the same machine.

Default value: `127.0.0.1:6032`.

Example: `SET admin-mysql_ifaces='127.0.0.1:6032;/tmp/proxysql_admin.sock'`

### `admin-read_only`

When this variable is set to true and loaded at runtime, the Admin module does not accept write anymore. This is useful to ensure that ProxySQL is not reconfigured.
When `admin-read_only=true`, the only way to revert it to false at runtime (and make the Admin module writable again) is to run the command `PROXYSQL READWRITE`.

Default value: `false`

### `admin-refresh_interval`

The refresh interval (in microseconds) for updates to the query rules statistics and commands counters statistics. Be careful about tweaking this to a value that is:
* too low, because it might affect the overall performance of the proxy
* too high, because it might affect the correctness of the results

Default value: `2000` (microseconds)

### `admin-stats_credentials`

The read-only credentials for connecting to the admin interface. These are not allowed updates to internal data structures such as the list of MySQL backend servers (or hostgroups), query rules, etc. They only allow readings from the statistics and monitoring tables (the other tables are not only even visible).

Default value: `stats:stats`

### `admin-telnet_admin_ifaces`

Not currently used (planned usage in a future version).

### `admin-telnet_stats_ifaces`

Not currently used (planned usage in a future version).

### `admin-version`

This variable displays ProxySQL version. This variable is read only.

## MySQL Variables

### `mysql-client_found_rows`

When set to `true`, client flag `CLIENT_FOUND_ROWS` is set when connecting to MySQL backends.

Default value: `true`

### `mysql-commands_stats`

Enable per-command MySQL query statistics. A command is a type of SQL query that is being executed. Some examples are: SELECT, INSERT or ALTER TABLE. See the `stats_mysql_commands_counters` section in the [admin tables documentation](https://github.com/sysown/proxysql-0.2/blob/master/doc/admin_tables.md#stats_mysql_commands_counters) in order to see more details about what kind of statistics are gathered.

Default value: `true`

### `mysql-connect_retries_delay`

The delay (in milliseconds) before trying to reconnect after a failed attempt to a backend MySQL server. Failed attempts can take place due to numerous reasons: too busy, timed out for the current attempt, etc. This will be retried for `mysql-connect_retries_on_failure` times.

Default value: `1` (milliseconds)

### `mysql-connect_retries_on_failure`

The number of times for which a reconnect should be attempted in case of an error, timeout, or any other event that led to an unsuccessful connection to a backend MySQL server. After the number of attempts is depleted, if a connection still couldn't be established, an error is returned. The error returned is either the last connection attempt error or a generic error ("Max connect failure while reaching hostgroup" with error code 28000).

Be careful about tweaking this parameter - a value that is too high can significantly increase the latency which with an unresponsive hostgroup is reported to the MySQL client.

Default value: `5` (reconnect times)

### `mysql-connect_timeout_server`

The timeout for a single attempt at connecting to a backend server from the proxy. If this fails, according to the other parameters, the attempt will be retried until too many errors per second are generated (and the server is automatically shunned) or until the final cut-off is reached and an error is returned to the client (see `mysql-connect_timeout_server_max`).

Default value: `1000` (miliseconds, the equivalent of 1 second)

### `mysql-connect_timeout_server_max`

The timeout for connecting to a backend server from the proxy. When this timeout is reached, an error is returned to the client with code #28000 and the message "Max connect timeout reached while reaching hostgroup...".

Default value: `10000` (miliseconds, the equivalent of 10 seconds)

### `mysql-connection_max_age_ms`

When `mysql-connection_max_age_ms` is set to a value greater than 0, inactive connections in the connection pool (therefore not currently used by any session) are closed if they were created more than `mysql-connection_max_age_ms` milliseconds ago. By default, connections aren't closed based on their age.

Default value: 0 (milliseconds)

### `mysql-default_charset`

The default server charset to be used in the communication with the MySQL clients. Note that this is the defult for client connections, not for backend connections.

Default value: `utf8`

### `mysql-default_max_latency_ms`

ProxySQL uses a mechanism to automatically ignore hosts if their latency is excessive. Note that hosts are not disabled, but only ignored: in other words, ProxySQL will prefer hosts with a smaller latency. It is possible to configure the maximum latency for each backend from `mysql_users` table, column `max_latency_ms`. If `mysql_users`.`max_latency_ms` is 0, the default value `mysql-default_max_latency_ms` applies.

Default: 1000 (millisecond)

Note: due to a limitation in SSL implementation, it is recommended to increase `mysql-default_max_latency_ms` if using SSL.

### `mysql-default_query_delay`

Simple throttling mechanism for queries to the backends. Setting this variable to a non-zero value (in miliseconds) will delay the execution of all queries, globally. There is a more fine-grained throttling mechanism in the admin table `mysql_query_rules`, where for each rule there can be one delay that is applied to all queries matching the rule. That extra delay is added on top of the default, global one.

Default value: `0` (miliseconds)

### `mysql-default_query_timeout`

Mechanism for specifying the maximal duration of queries to the backend MySQL servers until ProxySQL should return an error to the MySQL client. Whenever ProxySQL detects that a query has timed out, it will spawn a separate thread that runs a KILL query against the specific MySQL backend in order to stop the query from running in the backend. Because the query is killed, an error will be returned to the MySQL client.

Default value: `86400000` (miliseconds - the equivalent of 1 day = 24 hours)

### `mysql-default_reconnect`

Not used for now.

### `mysql-default_schema`

The default schema to be used for incoming MySQL client connections which do not specify a schema name. This is required because ProxySQL doesn't allow connection without a schema.

Default value: `information_schema`

### `mysql-enforce_autocommit_on_reads`

ProxySQL tracks the status of `autocommit` as specified by the client, and ensures that `autocommit` is set correct on backend connections. This implementation is problematic if a client starts a transaction using autocommit, and read/write split is implemented via query rules. In fact, if a read is sent to a slave and ProxySQL sets `autocommit=0` on slave, this will result in 2 transactions (one on master and one on slave). To prevent this to happen, if `mysql-enforce_autocommit_on_reads=false` (the default), ProxySQL won't change the value of `autocommit` on backend connections for `SELECT` stataments.

Default value: `false`

### `mysql-autocommit_false_not_reusable`

If this variable is set, ProxySQL will not put the connection with `autocommit=false` back to the pool. Should be used with `mysql-enforce_autocommit_on_reads=false` for those who have not implemented read/write split to avoid the `SELECT` statements getting a connection previously used by a statement with `autocommit=false` set.

Default value: `false`

### `mysql-eventslog_filename`

If this variable is set, ProxySQL will log all traffic to the specified filename. Note that the log file is not a text file, but a binary log with encodided traffic.

Default value: empty string, not set

### `mysql-eventslog_filesize`

This variable specifies the maximum size of files created by ProxySQL logger as specified in `mysql-eventslog_filename`. When the maximum size is reached, the file is rotated.

Default value: 104857600 (100MB)

### `mysql-free_connections_pct`

ProxySQL uses a connection pool to connect to backend servers. As part of this, it sometimes decides to keep some connections open and ready to use for future queries. It does this by pinging them once in a while. This variable controls the percentage of open idle connections from the total maximal number of connections open to that server.

A connection is idle if it hasn't used since the last round of pings. The time interval between two such rounds of pings for idle connections is controlled by the variable `mysql-processing_idles`.

Default value: `10` (percent)

### `mysql-have_compress`
Currently unused.

### `mysql-interfaces`

The TCP interfaces on which ProxySQL should listen for incoming MySQL traffic. As is obvious from the default value, this also supports UNIX sockets for faster local traffic.

Default value: `0.0.0.0:6033;/tmp/proxysql.sock`

### `mysql-long_query_time`

Threshold for counting queries passing through the proxy as 'slow'. The total number of slow queries can be found in the `stats_mysql_global` table, in the variable named `Slow_queries` (each row in that table represents one variable).

Default value: `1000` (ms)

### `mysql-max_connections`

The maximal number of TCP connections that the proxy can handle. After this number is reached, new connections will be rejected with the `#HY000` error, and the error message `Too many connections`.

Default value: `10000` (connections)

### `mysql-max_transaction_time`

Sessions with active transactions running more than this timeout are killed.

Default value: `14400000` (miliseconds - the equivalent of 4 hours)

### `mysql-monitor_connect_interval`

The interval at which the Monitor module of the proxy will try to connect to all the MySQL servers in order to check whether they are available or not.

Default value: `120000` (miliseconds - the equivalent of 2 minutes)

### `mysql-monitor_connect_timeout`

Connection timeout in milliseconds. The current implementation rounds this value to an integer number of seconds less or equal to the original interval, with 1 second as minimum. This lazy rouding is done because SSL connections are blocking calls.

Default value: `200` (miliseconds)

### `mysql-monitor_enabled`

It enables or disables MySQL Monitor.

Defaut value: `true`

### `mysql-monitor_history`

The duration for which the events for the checks made by the Monitor module are kept. Such events include connecting to backend servers (to check for connectivity issues), querying them with a simple query (in order to check that they are running correctly) or checking their replication lag. These logs are kept in the following admin tables:
* `mysql_server_connect_log`
* `mysql_server_ping_log`
* `mysql_server_replication_lag_log`

Default value: `600000` (miliseconds - the equivalent of 100 seconds)

### `mysql-monitor_username`, `mysql-monitor_password`

The (username, password) combination with which the Monitor module will connect to the backend servers in order to check their health. Note that ProxySQL does not make any automated decisions based on these checks, but the data can be used in external scripts.

It is also very important to note that `mysql-monitor_username` must not be a user in `mysql_users` table.
Although, ProxySQL does not enforce this restriction.

Default values: `monitor` / `monitor`

### `mysql-monitor_ping_interval`

The interval at which the Monitor module should ping the backend servers by using the [mysql_ping](https://dev.mysql.com/doc/refman/5.0/en/mysql-ping.html) API.

Default value: `60000` (miliseconds, the equivalent of 1 minute)

### `mysql-monitor_ping_timeout`

Currently unused.

Default value: `100` (miliseconds)

### `mysql-monitor_query_interval`

Currently unused. Will be used by the Monitor module in order to collect data about the global status of the backend servers.

Default value: `60000` (miliseconds, the equivalent of 1 minute)

### `mysql-monitor_query_status`

Currently unused. Will be used by the Monitor module in order to collect data about the global status of the backend servers.

Default value: `SELECT * FROM INFORMATION_SCHEMA.GLOBAL_STATUS`

### `mysql-monitor_query_timeout`

Currently unused. Will be used by the Monitor module in order to collect data about the global status of the backend servers.

Default value: `100` (miliseconds)

### `mysql-monitor_query_variables`

Currently unused. Will be used by the Monitor module in order to collect data about the global status of the backend servers.

Default value: `SELECT * FROM INFORMATION_SCHEMA.GLOBAL_VARIABLES`

### `mysql-monitor_replication_lag_interval`

The interval at which the proxy should connect to the backend servers in order to monitor the replication lag between those that are slaves and their masters. Slaves can be temporarily shunned if the replication lag is too large. This setting is controlled by the `mysql_servers`.`max_replication_lag` column in the admin interface, at a per-hostgroup level.

Default value: `10000` (miliseconds, the equivalent of 10 seconds)

### `mysql-monitor_replication_lag_timeout`

Currently unused.

Default value: `1000` (miliseconds)

### `mysql-monitor_timer_cached`

This variable controls whether ProxySQL should use a cached (and less accurate) value of wall clock time, or not. The actual API used for this is described [here](http://stuff.onse.fi/man?program=event_base_gettimeofday_cached&section=3).

Default value: `true`

### `mysql-ping_interval_server_msec`

The interval at which the proxy should ping backend connections in order to maintain them alive, even though there is no outgoing traffic. The purpose here is to keep some connections alive in order to reduce the latency of new queries towards a less frequently used destination backend server.

Default value: `10000` (miliseconds, the equivalent of 10 seconds)

### `mysql-ping_timeout_server`

The proxy internally pings the connections it has opened in order to keep them alive. This elliminates the cost of opening a new connection towards a hostgroup when a query needs to be routed, at the cost of additional memory footprint inside the proxy and some extra traffic. This is the timeout allowed for those pings to succeed.

Default value: `200` (miliseconds)

### `mysql-poll_timeout`

The minimal timeout used by the proxy in order to detect incoming/outgoing traffic via the `poll()` system call. If the proxy determines that it should stick to a higher timeout because of its internal computations, it will use that one, but it will never use a value less than this one.

Default value: `2000` (miliseconds, the equivalent of 2 seconds)

### `mysql-poll_timeout_on_failure`

The timeout used in order to detect incoming/outgoing traffic after a connection error has occured. The proxy automatically tweaks its timeout to a lower value in such an event in order to be able to quickly respond with a valid connection.

Default value: `100` (miliseconds)

### `mysql-query_digests`

When this variable is set to true, the proxy analyzes the queries passing through it and divides them into classes of queries having different values for the same parameters. It computes a couple of metrics for these classes of queries, all found in the `stats_mysql_query_digest` table. For more details, please refer to the [admin tables documentation](https://github.com/sysown/proxysql-0.2/blob/master/doc/admin_tables.md).

Default value: `true` (query digests are enabled)

### `mysql-server_capabilities`

The bitmask of MySQL capabilities (encoded as bits) with which the proxy will respond to clients connecting to it. This is useful in order to prevent certain features from being used. The default capabilities are:

```c++
server_capabilities = CLIENT_FOUND_ROWS | CLIENT_PROTOCOL_41 | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB | CLIENT_SSL;
```

More details about server capabilities in the [official documentation](https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags).

Default value: `47626`

### `mysql-server_version`

The server version with which the proxy will respond to the clients. Note that regardless of the versions of the backend servers, the proxy will respond with this.

Default value: `5.5.30`

### `mysql-servers_stats`

Currently unused. Will be removed in a future version.

Default value: `true`

### `mysql-session_debug`

Currently unused. Will be removed in a future version.

Default value: `true`

### `mysql-sessions_sort`

Sessions are conversations between a MySQL client and a backend server in the proxy. Sessions are generally processed in a stable order but in certain scenarios (like using a transaction workload, which makes sessions bind to certain MySQL connections from the pool), processing them in the same order leads to starvation.

This variable controls whether sessions should be processed in the order of waiting time, in order to have a more balanced distribution of traffic among sessions.

Default value: `true`

### `mysql-shun_on_failures`

The number of connection errors tolerated to the same server within an interval of 1 second until it is automatically shunned temporarily. For now, this can not be disabled by setting it to a special value, so if you want to do that, you can increase it to a very large value.

Default value: `5`

### `mysql-shun_recovery_time`

A backend server that has been automatically shunned will be recovered after at least this amount of time. Note that there is no actual hard guarantee of the exact timing, but in practice it shouldn't exceed this value by more than a couple of seconds.

Default value: `10` (seconds)

### `mysql-stacksize`

The stack size to be used with the background threads that the proxy uses to handle MySQL traffic and connect to the backends. Note that changing this value has no effect at runtime, if you need to change it you have to restart the proxy.

Default value: `1048576` (bytes, the equivalent of 1 MB)

### `mysql-threads`

The number of background threads that ProxySQL uses in order to process MySQL traffic. Note that there are other "administrative" threads on top of these, such as:
* the admin interface thread
* the monitoring module threads that interact with the backend servers (one for monitoring connectivity, one for pinging the servers and one for monitoring the replication lag)
* occasional temporary threads created in order to kill long running queries that have become unresponsive
* background threads used by the libmariadbclient library in order to make certain interactions with MySQL servers async

Note that changing this value has no effect at runtime, if you need to change it you have to restart the proxy.

Default value: `4` (background threads to process MySQL traffic)

### `mysql-threshold_query_length`

The maximal size of an incoming SQL query to the proxy that will mark the background MySQL connection as non-reusable. This will force the proxy to open a new connection to the backend server, in order to make sure that the memory footprint of the server stays within reasonable limits.

More details about it here: https://dev.mysql.com/doc/refman/5.6/en/memory-use.html

Relevant quote from the mysqld documentation: "The connection buffer and result buffer each begin with a size equal to net_buffer_length bytes, but are dynamically enlarged up to max_allowed_packet bytes as needed. The result buffer shrinks to net_buffer_length bytes after each SQL statement."

Default value: `524288` (bytes, the equivalent of 0.5 MB)

### `mysql-threshold_resultset_size`

If a resultset returned by a backend server is bigger than this, proxysql will start sending the result to the MySQL client that was requesting the result in order to limit its memory footprint.

Default value: `4194304` (bytes, the equivalent of 4 MB)

### `mysql-wait_timeout`

If a proxy session (which is a conversation between a MySQL client and a backend MySQL server) has been idle for more than this threshold, the proxy will kill the session.

Default value: `28800000` (miliseconds, the equivalent of 8 hours)
