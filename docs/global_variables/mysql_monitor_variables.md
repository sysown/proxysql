# MySQL Monitor Variables

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## List of MySQL Monitor Variables

NOTE: You can click on the variable name to jump to its definition

<!-- remark-ignore-start -->

| Variable Name                                                                                                                                | Default Value |
| -------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| [mysql-monitor_connect_interval](#mysql-monitor_connect_interval)                                                                            | 60000         |
| [mysql-monitor_connect_timeout](#mysql-monitor_connect_timeout)                                                                              | 600           |
| [mysql-monitor_local_dns_cache_refresh_interval](#mysql-monitor_local_dns_cache_refresh_interval)                                            | 60000         |
| [mysql-monitor_local_dns_cache_ttl](#mysql-monitor_local_dns_cache_ttl)                                                                      | 300000        |
| [mysql-monitor_local_dns_resolver_queue_maxsize](#mysql-monitor_local_dns_resolver_queue_maxsize)                                            | 128           |
| [mysql-monitor_enabled](#mysql-monitor_enabled)                                                                                              | true          |
| [mysql-monitor_galera_healthcheck_interval](#mysql-monitor_galera_healthcheck_interval)                                                      | 5000          |
| [mysql-monitor_galera_healthcheck_max_timeout_count](#mysql-monitor_galera_healthcheck_max_timeout_count)                                    | 3             |
| [mysql-monitor_galera_healthcheck_timeout](#mysql-monitor_galera_healthcheck_timeout)                                                        | 800           |
| [mysql-monitor_groupreplication_healthcheck_interval](#mysql-monitor_groupreplication_healthcheck_interval)                                  | 5000          |
| [mysql-monitor_groupreplication_healthcheck_max_timeout_count](#mysql-monitor_groupreplication_healthcheck_max_timeout_count)                | 3             |
| [mysql-monitor_groupreplication_healthcheck_timeout](#mysql-monitor_groupreplication_healthcheck_timeout)                                    | 800           |
| [mysql-monitor_groupreplication_max_transactions_behind_count](#mysql-monitor_groupreplication_max_transactions_behind_count)                | 3             |
| [mysql-monitor_groupreplication_max_transactions_behind_for_read_only](#mysql-monitor_groupreplication_max_transaction_behind_for_read_only) | 1             |
| [mysql-monitor_history](#mysql-monitor_history)                                                                                              | 600000        |
| [mysql-monitor_password](#mysql-monitor_password)                                                                                            | monitor       |
| [mysql-monitor_ping_interval](#mysql-monitor_ping_interval)                                                                                  | 8000          |
| [mysql-monitor_ping_max_failures](#mysql-monitor_ping_max_failures)                                                                          | 3             |
| [mysql-monitor_ping_timeout](#mysql-monitor_ping_timeout)                                                                                    | 1000          |
| [mysql-monitor_query_interval](#mysql-monitor_query_interval)                                                                                | 60000         |
| [mysql-monitor_query_timeout](#mysql-monitor_query_timeout)                                                                                  | 100           |
| [mysql-monitor_read_only_interval](#mysql-monitor_read_only_interval)                                                                        | 1000          |
| [mysql-monitor_read_only_max_timeout_count](#mysql-monitor_read_only_max_timeout_count)                                                      | 3             |
| [mysql-monitor_read_only_timeout](#mysql-monitor_read_only_timeout)                                                                          | 800           |
| [mysql-monitor_replication_lag_count](#mysql-monitor_replication_lag_count)                                                                  | 1             |
| [mysql-monitor_replication_lag_group_by_host](#mysql-monitor_replication_lag_group_by_host)                                                  | false         |
| [mysql-monitor_replication_lag_interval](#mysql-monitor_replication_lag_interval)                                                            | 10000         |
| [mysql-monitor_replication_lag_timeout](#mysql-monitor_replication_lag_timeout)                                                              | 1000          |
| [mysql-monitor_replication_lag_use_percona_heartbeat](#mysql-monitor_replication_lag_use_percona_heartbeat)                                  |               |
| [mysql-monitor_slave_lag_when_null](#mysql-monitor_slave_lag_when_null)                                                                      | 60            |
| [mysql-monitor_threads_max](#mysql-monitor_threads_max)                                                                                      | 128           |
| [mysql-monitor_threads_min](#mysql-monitor_threads_min)                                                                                      | 8             |
| [mysql-monitor_threads_queue_maxsize](#mysql-monitor_threads_queue_maxsize)                                                                  | 128           |
| [mysql-monitor_username](#mysql-monitor_username)                                                                                            | monitor       |
| [mysql-monitor_wait_timeout](#mysql-monitor_wait_timeout)                                                                                    | true          |
| [mysql-monitor_writer_is_also_reader](#mysql-monitor_writer_is_also_reader)                                                                  | true          |

<!-- remark-ignore-end -->

### `mysql-monitor_connect_interval`

The interval at which the Monitor module of the proxy will try to connect to all the MySQL servers in order to
check whether they are available or not.

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | mysql-monitor_connect_interval |
|                      | **Dynamic** | Yes                            |
| **Permitted Values** | **Type**    | Integer (milliseconds)         |
|                      | **Default** | 120000 (2 mins)                |
|                      | **Minimum** | 100                            |
|                      | **Maximum** | 604800000                      |

### `mysql-monitor_connect_timeout`

Connection timeout in milliseconds. The current implementation rounds this value to an integer number of
seconds less or equal to the original interval, with 1 second as minimum. This lazy rounding is done because
SSL connections are blocking calls.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_connect_timeout |
|                      | **Dynamic** | Yes                           |
| **Permitted Values** | **Type**    | Integer (milliseconds)        |
|                      | **Default** | 200                           |
|                      | **Minimum** | 100                           |
|                      | **Maximum** | 600000                        |

### `mysql-monitor_enabled`

It enables or disables MySQL Monitor.

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | mysql-monitor_enabled |
|                      | **Dynamic** | Yes                   |
| **Permitted Values** | **Type**    | Boolean               |
|                      | **Default** | true                  |

### `mysql-monitor_galera_healthcheck_interval`

The interval at which the proxy should connect to the backend servers in order to monitor the Galera status of
a node. Nodes can be temporarily shunned if their status is not available which is controlled by the
`mysql_galera_hostgroups`.`max_transactions_behind` column in the admin interface, on a per-hostgroup level
(introduced in ProxySQL v2.0).

|                      |             |                                           |
| -------------------- | ----------- | ----------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_galera_healthcheck_interval |
|                      | **Dynamic** | Yes                                       |
| **Permitted Values** | **Type**    | Integer (milliseconds)                    |
|                      | **Default** | 5000                                      |
|                      | **Minimum** | 50                                        |
|                      | **Maximum** | 604800000                                 |

### `mysql-monitor_galera_healthcheck_max_timeout_count`

Sets the max number of times ProxySQL has timeout checking on a Galera Node before declaring it OFFLINE.

|                      |             |                                                    |
| -------------------- | ----------- | -------------------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_galera_healthcheck_max_timeout_count |
|                      | **Dynamic** | Yes                                                |
| **Permitted Values** | **Type**    | Integer                                            |
|                      | **Default** | 3                                                  |

### `mysql-monitor_galera_healthcheck_timeout`

How long the Monitor module will wait for a Galera status check reply (introduced in ProxySQL v2.0).

|                      |             |                                          |
| -------------------- | ----------- | ---------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_galera_healthcheck_timeout |
|                      | **Dynamic** | Yes                                      |
| **Permitted Values** | **Type**    | Integer (milliseconds)                   |
|                      | **Default** | 800                                      |
|                      | **Minimum** | 50                                       |
|                      | **Maximum** | 600000                                   |

### `mysql-monitor_groupreplication_healthcheck_interval`

The interval at which the proxy should connect to the backend servers in order to monitor the Group
Replication status of a node. Nodes can be temporarily shunned if their status is not available which is
controlled by the `mysql_group_replication_hostgroups`.`max_transactions_behind` column in the admin
interface, on a per-hostgroup level.

|                      |             |                                                     |
| -------------------- | ----------- | --------------------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_groupreplication_healthcheck_interval |
|                      | **Dynamic** | Yes                                                 |
| **Permitted Values** | **Type**    | Integer (milliseconds)                              |
|                      | **Default** | 5000                                                |
|                      | **Minimum** | 50                                                  |
|                      | **Maximum** | 604800000                                           |

### `mysql-monitor_groupreplication_healthcheck_max_timeout_count`

Sets the max number of times ProxySQL has timeout checking on a Group Replication Node before declaring it
OFFLINE.

|                      |             |                                                              |
| -------------------- | ----------- | ------------------------------------------------------------ |
| **System Variable**  | **Name**    | mysql-monitor_groupreplication_healthcheck_max_timeout_count |
|                      | **Dynamic** | Yes                                                          |
| **Permitted Values** | **Type**    | Integer                                                      |
|                      | **Default** | 3                                                            |

### `mysql-monitor_groupreplication_healthcheck_timeout`

How long the Monitor module will wait for a Group Replication status check reply.

|                      |             |                                                    |
| -------------------- | ----------- | -------------------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_groupreplication_healthcheck_timeout |
|                      | **Dynamic** | Yes                                                |
| **Permitted Values** | **Type**    | Integer (milliseconds)                             |
|                      | **Default** | 800                                                |
|                      | **Minimum** | 50                                                 |
|                      | **Maximum** | 600000                                             |

### `mysql-monitor_groupreplication_max_transactions_behind_count`

Sets the number of times that a server needs to fail a 'max_transactions_behind' check before an action is
performed. If the number of failed checks exceeds this number:

- _Pre v2.3.0_ If the server has **read_only=1** it's set to 'OFFLINE' until replication catches up.
- _After v2.3.0_ Servers are placed as 'SHUNNED' depending on the value of variable
  '[mysql-monitor_groupreplication_max_transaction_behind_for_read_only][2]'.

<!-- -->

_NOTE: After v2.3.0 ProxySQL SHUNNED status is executed in two stages in order to allow a grace time before
terminating all the connections_

|                      |             |                                                              |
| -------------------- | ----------- | ------------------------------------------------------------ |
| **System Variable**  | **Name**    | mysql-monitor_groupreplication_max_transactions_behind_count |
|                      | **Dynamic** | Yes                                                          |
| **Permitted Values** | **Type**    | Integer                                                      |
|                      | **Default** | 3                                                            |
|                      | **Minimum** | 1                                                            |
|                      | **Maximum** | 10                                                           |

### `mysql-monitor_groupreplication_max_transactions_behind_for_read_only`

Determines which action is going to be performed over a server when
'[mysql-monitor_groupreplication_max_transactions_behind_count][3]' is exceeded. Possible values are:

- _'0'_: Only servers with read_only=0 are placed as 'SHUNNED'.
- _'1'_: Only servers with read_only=1 are placed as 'SHUNNED' (default).
- _'2'_: Both servers with read_only=1 and read_only=0 are placed as 'SHUNNED'.

<!-- -->

|                      |             |                                                                      |
| -------------------- | ----------- | -------------------------------------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_groupreplication_max_transactions_behind_for_read_only |
|                      | **Dynamic** | Yes                                                                  |
| **Permitted Values** | **Type**    | Integer (milliseconds)                                               |
|                      | **Default** | 1                                                                    |
|                      | **Minimum** | 0                                                                    |
|                      | **Maximum** | 2                                                                    |

### `mysql-monitor_history`

The duration for which the events for the checks made by the Monitor module are kept. Such events include
connecting to backend servers (to check for connectivity issues), querying them with a simple query (in order
to check that they are running correctly) or checking their replication lag. These logs are kept in the
following admin tables:

- `mysql_server_connect_log`
- `mysql_server_ping_log`
- `mysql_server_replication_lag_log`

<!-- -->

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | mysql-monitor_history  |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | Integer (milliseconds) |
|                      | **Default** | 600000 (60 seconds)    |
|                      | **Minimum** | 1000                   |
|                      | **Maximum** | 604800000              |

### `mysql-monitor_local_dns_cache_refresh_interval`

|                      |             |                                                |
| -------------------- | ----------- | ---------------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_local_dns_cache_refresh_interval |
|                      | **Dynamic** | Yes                                            |
| **Permitted Values** | **Type**    | Integer (milliseconds)                         |
|                      | **Default** | 60000 (60 seconds)                             |
|                      | **Minimum** | 0 (DNS Cache disabled)                         |
|                      | **Maximum** | 604800000                                      |

Specifies the refresh interval at which monitor DNS cache entries, ‘mysql_servers’ and ‘proxysql_servers’ will
be re-check for new records. If expired entries are found, i.e entries with higher lifetimes than
[mysql-monitor_local_dns_cache_ttl][4], a new resolution attempt will be placed in the DNS resolver queue.

### `mysql-monitor_local_dns_cache_ttl`

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_local_dns_cache_ttl |
|                      | **Dynamic** | Yes                               |
| **Permitted Values** | **Type**    | Integer (milliseconds)            |
|                      | **Default** | 300000 (300 seconds)              |
|                      | **Minimum** | 0 (DNS Cache disabled)            |
|                      | **Maximum** | 604800000                         |

Specifies the expiration time for DNS cache entries for monitor. Once a entry outlives this threshold, a new
resolution attempt will be placed in the DNS resolver queue when re-checked at the next [refresh interval][5].

### `mysql-monitor_local_dns_resolver_queue_maxsize`

|                      |             |                                                |
| -------------------- | ----------- | ---------------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_local_dns_resolver_queue_maxsize |
|                      | **Dynamic** | Yes                                            |
| **Permitted Values** | **Type**    | Integer                                        |
|                      | **Default** | 128                                            |
|                      | **Minimum** | 16                                             |
|                      | **Maximum** | 1024                                           |

Determines how much the DNS resolver queue can grow before starting new monitoring helper threads. The number
of threads is dynamically scaled, starting with `1` helper thread, up to `32` threads. Whenever this scaling
is found necessary, a message is placed in the [error log][1].

### `mysql-monitor_password`

Specifies the password that the Monitor module will use to connect to the backends.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | mysql-monitor_password |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | String                 |
|                      | **Default** | monitor                |

### `mysql-monitor_ping_interval`

The interval at which the Monitor module should ping the backend servers by using the [mysql_ping][6] API.
Before version 1.4.14, the default was 60000 (1 minute).

|                      |             |                             |
| -------------------- | ----------- | --------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_ping_interval |
|                      | **Dynamic** | Yes                         |
| **Permitted Values** | **Type**    | Integer (milliseconds)      |
|                      | **Default** | 8000                        |
|                      | **Minimum** | 100                         |
|                      | **Maximum** | 604800000                   |

### `mysql-monitor_ping_max_failures`

The maximum number of ping failures the Monitor module should tolerate before sending a signal to
MySQL_Hostgroups_Manager to kill all connections to the backend server.

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_ping_max_failures |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Integer                         |
|                      | **Default** | 3                               |
|                      | **Minimum** | 1                               |
|                      | **Maximum** | 1000000                         |

### `mysql-monitor_ping_timeout`

How long the Monitor module will wait for a ping reply.

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_ping_timeout |
|                      | **Dynamic** | Yes                        |
| **Permitted Values** | **Type**    | Integer (milliseconds)     |
|                      | **Default** | 1000                       |
|                      | **Minimum** | 100                        |
|                      | **Maximum** | 600000                     |

### `mysql-monitor_query_interval`

Currently unused. Will be used by the Monitor module in order to collect data about the global status of the
backend servers.

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_query_interval |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer (milliseconds)       |
|                      | **Default** | 60000 (1 min)                |
|                      | **Minimum** | 100                          |
|                      | **Maximum** | 604800000                    |

### `mysql-monitor_query_timeout`

Currently unused. Will be used by the Monitor module in order to collect data about the global status of the
backend servers.

|                      |             |                             |
| -------------------- | ----------- | --------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_query_timeout |
|                      | **Dynamic** | Yes                         |
| **Permitted Values** | **Type**    | Integer (milliseconds)      |
|                      | **Default** | 100                         |

### `mysql-monitor_read_only_interval`

Defines the frequency to check the Read Only status of a backend server (in milliseconds).

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_read_only_interval |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Integer (milliseconds)           |
|                      | **Default** | 1000 (1 sec)                     |
|                      | **Minimum** | 100                              |
|                      | **Maximum** | 604800000                        |

### `mysql-monitor_read_only_max_timeout_count`

If the number of consecutive `read_only` checks timeouts (each exceeding `pgsql-monitor_read_only_timeout`)
surpasses this value, the server is assumed to be `read_only=1`. This triggers `hostgroup` placement
operations, **if required**, for all the `hostgroups` in which the server is configured, and that are present
in the current `pgsql_replication_hostgroups` configuration.

|                      |             |                                           |
| -------------------- | ----------- | ----------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_read_only_max_timeout_count |
|                      | **Dynamic** | Yes                                       |
| **Permitted Values** | **Type**    | Integer (milliseconds)                    |
|                      | **Default** | 3                                         |
|                      | **Minimum** | 1                                         |
|                      | **Maximum** | 999999                                    |

### `mysql-monitor_read_only_timeout`

The timeout for a single attempt at checking the Read Only status on a backend server from the proxy.

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_read_only_timeout |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Integer (milliseconds)          |
|                      | **Default** | 800                             |
|                      | **Minimum** | 100                             |
|                      | **Maximum** | 600000                          |

### `mysql-monitor_replication_lag_count`

Defines the count at which a server is going to be `SHUNNED` due to replication lag if it's currently found
replication lag exceeds the specified `max_replication_lag` for the server.

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_replication_lag_count |
|                      | **Dynamic** | Yes                                 |
| **Permitted Values** | **Type**    | Integer (milliseconds)              |
|                      | **Default** | 1                                   |
|                      | **Minimum** |                                     |
|                      | **Maximum** |                                     |

### `mysql-monitor_replication_lag_group_by_host`

Introduced in v2.4.0. Allows to control how monitor performs replication lag checks over servers in
hostgroups. Possible values are:

- `true`: Monitor will perform 1 replication lag check per server per hostgroup.
- `false`: Monitor will perform 1 replication lag check per server.

<!-- -->

**NOTE:** This variable need to be set only in setups in which the same server is configured in many
hostgroups, thus reducing the number of checks.

|                      |             |                                             |
| -------------------- | ----------- | ------------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_replication_lag_group_by_host |
|                      | **Dynamic** | Yes                                         |
| **Permitted Values** | **Type**    | Boolean                                     |
|                      | **Default** | false                                       |

### `mysql-monitor_replication_lag_interval`

The interval at which the proxy should connect to the backend servers in order to monitor the replication lag
between those that are slaves and their masters. Slaves can be temporarily shunned if the replication lag is
too large. This setting is controlled by the `mysql_servers`.`max_replication_lag` column in the admin
interface, at a per-hostgroup level.

|                      |             |                                        |
| -------------------- | ----------- | -------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_replication_lag_interval |
|                      | **Dynamic** | Yes                                    |
| **Permitted Values** | **Type**    | Integer (milliseconds)                 |
|                      | **Default** | 10000                                  |
|                      | **Minimum** | 100                                    |
|                      | **Maximum** | 604800000                              |

### `mysql-monitor_replication_lag_timeout`

How long the Monitor module will wait for the output of `SHOW SLAVE STATUS` to be returned from the database.

|                      |             |                                       |
| -------------------- | ----------- | ------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_replication_lag_timeout |
|                      | **Dynamic** | Yes                                   |
| **Permitted Values** | **Type**    | Integer (milliseconds)                |
|                      | **Default** | 1000                                  |
|                      | **Minimum** | 100                                   |
|                      | **Maximum** | 600000                                |

### `mysql-monitor_replication_lag_use_percona_heartbeat`

This variable defines the `.` where `pt-heartbeat` information is written, when this variable is defined
replication lag checks are determined based on the values in this table rather than `SHOW SLAVE STATUS`. This
is empty by default, when using `pt-heartbeat` the value is typically defined as `percona.heartbeat`.

|                      |             |                                                     |
| -------------------- | ----------- | --------------------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_replication_lag_use_percona_heartbeat |
|                      | **Dynamic** | Yes                                                 |
| **Permitted Values** | **Type**    | String                                              |
|                      | **Default** |                                                     |

### `mysql-monitor_slave_lag_when_null`

When replication check returns that `Seconds_Behind_Master=NULL`, the value of
`mysql-monitor_slave_lag_when_null` (in seconds) is assumed to be the current replication lag. This allows to
either shun or keep online a server where replication is broken/stopped.

|                      |                                  |                                   |
| -------------------- | -------------------------------- | --------------------------------- |
| **System Variable**  | **Name**                         | mysql-monitor_slave_lag_when_null |
|                      | **Dynamic**                      | Yes                               |
| **Permitted Values** | **Type**                         | Integer (seconds)                 |
|                      | **Default**                      | 60                                |
|                      | **Minimum (up to 1.3.1)**        | 100                               |
|                      | **Minimum (from 1.3.2 onwards)** | 0                                 |
|                      | **Maximum**                      | 604800 (1 week)                   |

### `mysql-monitor_threads_max`

Controls the maximum number of threads within the Monitor Module thread pool. Introduced in ProxySQL v2.0.
From 1.3.2 and before 2.0 the minimum value was hardcoded.

|                      |                                  |                           |
| -------------------- | -------------------------------- | ------------------------- |
| **System Variable**  | **Name**                         | mysql-monitor_threads_max |
|                      | **Dynamic**                      | Yes                       |
| **Permitted Values** | **Type**                         | Integer                   |
|                      | **Default**                      | 128                       |
|                      | **Minimum (from 1.3.2 onwards)** | 4                         |
|                      | **Maximum**                      | 256                       |

### `mysql-monitor_threads_min`

Controls the minimum number of threads within the Monitor Module thread pool. Introduced in ProxySQL v2.0.
From 1.3.2 and before 2.0 the minimum value was hardcoded.

|                      |                                  |                           |
| -------------------- | -------------------------------- | ------------------------- |
| **System Variable**  | **Name**                         | mysql-monitor_threads_min |
|                      | **Dynamic**                      | Yes                       |
| **Permitted Values** | **Type**                         | Integer                   |
|                      | **Default**                      | 8                         |
|                      | **Minimum (from 1.3.2 onwards)** | 2                         |
|                      | **Maximum**                      | 16                        |

### `mysql-monitor_threads_queue_maxsize`

The variable controls how many checks are queued before starting new monitor threads.

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_threads_queue_maxsize |
|                      | **Dynamic** | Yes                                 |
| **Permitted Values** | **Type**    | Integer                             |
|                      | **Default** | 128                                 |
|                      | **Minimum** | 16                                  |
|                      | **Maximum** | 1024                                |

### `mysql-monitor_timer_cached`

`DEPRECATED` This variable controls whether ProxySQL should use a cached (and less accurate) value of wall
clock time, or not.

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_timer_cached |
|                      | **Dynamic** | Yes                        |
| **Permitted Values** | **Type**    | Boolean                    |
|                      | **Default** | true                       |

### `mysql-monitor_username`

Specifies the username that the Monitor module will use to connect to the backends. The user needs only
`USAGE` privileges to connect, ping and check read_only. The user needs also `REPLICATION CLIENT` if it needs
to monitor replication lag. The user specified in mysql-monitor_username CANNOT be used in mysql_users.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | mysql-monitor_username |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | String                 |
|                      | **Default** | monitor                |

### `mysql-monitor_wait_timeout`

In order to avoid being disconnected the Monitor Module tunes wait_timeout on its connections to backends.
This is generally a good thing, however it could become a problem if ProxySQL is acting as a "forwarder". When
`mysql-monitor_wait_timeout` is set to `false` the feature is disabled.

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_wait_timeout |
|                      | **Dynamic** | Yes                        |
| **Permitted Values** | **Type**    | Boolean                    |
|                      | **Default** | true                       |

### `mysql-monitor_writer_is_also_reader`

When a node changes its read_only value from 1 to 0, this variable determines if the node should be present in
both hostgroups or not:

- `false` : the node will be moved in writer_hostgroup and removed from reader_hostgroup
- `true` : the node will be copied in writer_hostgroup and it will also stay in reader_hostgroup

<!-- -->

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_writer_is_also_reader |
|                      | **Dynamic** | Yes                                 |
| **Permitted Values** | **Type**    | Boolean                             |
|                      | **Default** | true                                |

[1]: /error-log
[2]: #mysql-monitor_groupreplication_max_transaction_behind_for_read_only
[3]: #mysql-monitor_groupreplication_max_transactions_behind_count
[4]: #mysql-monitor_local_dns_cache_ttl
[5]: #mysql-monitor_local_dns_cache_refresh_interval
[6]: https://dev.mysql.com/doc/refman/5.0/en/mysql-ping.html

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
