# PostgreSQL Monitor Variables

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## List of PostgreSQL Monitor Variables

NOTE: You can click on the variable name to jump to its definition

<!-- remark-ignore-start -->

| Variable Name                                                                           | Default Value |
| --------------------------------------------------------------------------------------- | ------------- |
| [pgsql-monitor_connect_interval](#pgsql-monitor_connect_interval)                       | 120000        |
| [pgsql-monitor_connect_interval_window](#pgsql-monitor_connect_interval_window)         | 50            |
| [pgsql-monitor_connect_timeout](#pgsql-monitor_connect_timeout)                         | 600           |
| [pgsql-monitor_enabled](#pgsql-monitor_enabled)                                         | true          |
| [pgsql-monitor_history](#pgsql-monitor_history)                                         | 7200000       |
| [pgsql-monitor_local_dns_cache_refresh_interval](#pgsql-monitor_local_dns_cache_refresh_interval) | 60000 |
| [pgsql-monitor_local_dns_cache_ttl](#pgsql-monitor_local_dns_cache_ttl)                 | 300000        |
| [pgsql-monitor_local_dns_resolver_queue_maxsize](#pgsql-monitor_local_dns_resolver_queue_maxsize) | 128 |
| [pgsql-monitor_password](#pgsql-monitor_password)                                       | monitor       |
| [pgsql-monitor_ping_interval](#pgsql-monitor_ping_interval)                             | 8000          |
| [pgsql-monitor_ping_interval_window](#pgsql-monitor_ping_interval_window)               | 10            |
| [pgsql-monitor_ping_max_failures](#pgsql-monitor_ping_max_failures)                     | 3             |
| [pgsql-monitor_ping_timeout](#pgsql-monitor_ping_timeout)                               | 1000          |
| [pgsql-monitor_read_only_interval](#pgsql-monitor_read_only_interval)                   | 1000          |
| [pgsql-monitor_read_only_interval_window](#pgsql-monitor_read_only_interval_window)     | 10            |
| [pgsql-monitor_read_only_max_timeout_count](#pgsql-monitor_read_only_max_timeout_count) | 3             |
| [pgsql-monitor_read_only_timeout](#pgsql-monitor_read_only_timeout)                     | 800           |
| [pgsql-monitor_threads](#pgsql-monitor_threads)                                         | 2             |
| [pgsql-monitor_username](#pgsql-monitor_username)                                       | monitor       |
| [pgsql-monitor_writer_is_also_reader](#pgsql-monitor_writer_is_also_reader)             | true          |

<!-- remark-ignore-end -->

### `pgsql-monitor_connect_interval`

The interval at which the Monitor module of the proxy will try to connect to all the PostgreSQL servers in
order to check whether they are available or not.

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | pgsql-monitor_connect_interval |
|                      | **Dynamic** | Yes                            |
| **Permitted Values** | **Type**    | Integer (milliseconds)         |
|                      | **Default** | 120000                         |
|                      | **Minimum** | 100                            |
|                      | **Maximum** | 604800000                      |

### `pgsql-monitor_connect_interval_window`

Sets the target completion window, expressed as a percentage of the interval, in which the checks should be
completed. In other words, allows to configure the tasks batching, defining the burstiness of the scheduling.

|                      |             |                                       |
| -------------------- | ----------- | ------------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_connect_interval_window |
|                      | **Dynamic** | Yes                                   |
| **Permitted Values** | **Type**    | Integer (pct)                         |
|                      | **Default** | 50                                    |
|                      | **Minimum** | 0                                     |
|                      | **Maximum** | 100                                   |

### `pgsql-monitor_connect_timeout`

Connection timeout in milliseconds.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_connect_timeout |
|                      | **Dynamic** | Yes                           |
| **Permitted Values** | **Type**    | Integer (milliseconds)        |
|                      | **Default** | 600                           |
|                      | **Minimum** | 100                           |
|                      | **Maximum** | 600000                        |

### `pgsql-monitor_enabled`

It enables or disables PostgreSQL Monitor.

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_enabled |
|                      | **Dynamic** | Yes                   |
| **Permitted Values** | **Type**    | Boolean               |
|                      | **Default** | true                  |

### `pgsql-monitor_history`

The duration for which the events for the checks made by the Monitor module are kept. Such events include
connecting to backend servers (to check for connectivity issues), querying them with a simple query (in order
to check that they are running correctly) or checking their replication lag. These logs are kept in the
following admin tables:

- `pgsql_server_connect_log`
- `pgsql_server_ping_log`
- `pgsql_server_replication_lag_log`

<!-- -->

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_history  |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | Integer (milliseconds) |
|                      | **Default** | 7200000 (2h)           |
|                      | **Minimum** | 1000                   |
|                      | **Maximum** | 604800000              |

### `pgsql-monitor_password`

Specifies the password that the Monitor module will use to connect to the backends.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_password |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | String                 |
|                      | **Default** | monitor                |

### `pgsql-monitor_ping_interval`

The interval at which the Monitor module of the proxy will try to connect to all the PostgreSQL servers in
order to check whether they are available or not.

|                      |             |                             |
| -------------------- | ----------- | --------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_ping_interval |
|                      | **Dynamic** | Yes                         |
| **Permitted Values** | **Type**    | Integer (milliseconds)      |
|                      | **Default** | 8000                        |
|                      | **Minimum** | 100                         |
|                      | **Maximum** | 604800000                   |

### `pgsql-monitor_ping_interval_window`

Sets the target completion window, expressed as a percentage of the interval, in which the checks should be
completed. In other words, allows to configure the tasks batching, defining the burstiness of the scheduling.

|                      |             |                                    |
| -------------------- | ----------- | ---------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_ping_interval_window |
|                      | **Dynamic** | Yes                                |
| **Permitted Values** | **Type**    | Integer (pct)                      |
|                      | **Default** | 10                                 |
|                      | **Minimum** | 0                                  |
|                      | **Maximum** | 100                                |

### `pgsql-monitor_ping_max_failures`

The maximum number of ping failures the Monitor module should tolerate before sending a signal to
`PgSQL_Hostgroups_Manager` to kill all connections to the backend server.

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_ping_max_failures |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Integer                         |
|                      | **Default** | 3                               |
|                      | **Minimum** | 1                               |
|                      | **Maximum** | 1000000                         |

### `pgsql-monitor_ping_timeout`

How long the Monitor module will wait for a ping reply.

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_ping_timeout |
|                      | **Dynamic** | Yes                        |
| **Permitted Values** | **Type**    | Integer (milliseconds)     |
|                      | **Default** | 1000                       |
|                      | **Minimum** | 100                        |
|                      | **Maximum** | 600000                     |

### `pgsql-monitor_read_only_interval`

Defines the frequency to perform the `read_only` check of a backend server (in milliseconds).

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_read_only_interval |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Integer (milliseconds)           |
|                      | **Default** | 1000                             |
|                      | **Minimum** | 100                              |
|                      | **Maximum** | 604800000                        |

### `pgsql-monitor_read_only_interval_window`

Sets the target completion window, expressed as a percentage of the interval, in which the checks should be
completed. In other words, allows to configure the tasks batching, defining the burstiness of the scheduling.

|                      |             |                                         |
| -------------------- | ----------- | --------------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_read_only_interval_window |
|                      | **Dynamic** | Yes                                     |
| **Permitted Values** | **Type**    | Integer (pct)                           |
|                      | **Default** | 10                                      |
|                      | **Minimum** | 0                                       |
|                      | **Maximum** | 100                                     |

### `pgsql-monitor_read_only_max_timeout_count`

If the number of consecutive `read_only` checks timeouts (each exceeding `pgsql-monitor_read_only_timeout`)
surpasses this value, the server is assumed to be `read_only=1`. This triggers `hostgroup` placement
operations, **if required**, for all the `hostgroups` in which the server is configured, and that are present
in the current `pgsql_replication_hostgroups` configuration.

|                      |             |                                           |
| -------------------- | ----------- | ----------------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_read_only_max_timeout_count |
|                      | **Dynamic** | Yes                                       |
| **Permitted Values** | **Type**    | Integer (milliseconds)                    |
|                      | **Default** | 3                                         |
|                      | **Minimum** | 1                                         |
|                      | **Maximum** | 999999                                    |

### `pgsql-monitor_read_only_timeout`

The timeout for a single attempt at performing the `read_only` check on a backend server.

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_read_only_timeout |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Integer (milliseconds)          |
|                      | **Default** | 800                             |
|                      | **Minimum** | 100                             |
|                      | **Maximum** | 600000                          |

### `pgsql-monitor_threads`

Controls the number of threads within the Monitor Module thread pool. This variable **isn't dynamic** right
now, which means that the value is fixed at startup. Due to the async nature of the monitoring design, and the
control the module offers over the checks batching, a very small number of threads should be capable of
monitoring a very large number of backend servers, without any compromises. For more information refer to the
module [general documentation][1].

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_threads |
|                      | **Dynamic** | No                    |
| **Permitted Values** | **Type**    | Integer               |
|                      | **Default** | 2                     |
|                      | **Minimum** | 2                     |
|                      | **Maximum** | 256                   |

### `pgsql-monitor_username`

Specifies the username that the Monitor module will use to connect to the backends. The user needs only
`USAGE` privileges to connect, ping and check `read_only`. For `read_only` this means that the user is
required to have `pg_monitor` privileges.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_username |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | String                 |
|                      | **Default** | monitor                |

### `pgsql-monitor_writer_is_also_reader`

When a node changes its `read_only` value from `1` to `0`, this variable determines if the node should be
present in both hostgroups or not:

- `false`: the node will be moved in `writer_hostgroup` and removed from `reader_hostgroup`.
- `true`: the node will be copied in `writer_hostgroup` and it will also stay in `reader_hostgroup`.

<!-- -->

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_writer_is_also_reader |
|                      | **Dynamic** | Yes                                 |
| **Permitted Values** | **Type**    | Boolean                             |
|                      | **Default** | true                                |

### `pgsql-monitor_local_dns_cache_ttl`

Time-to-live in milliseconds for cached DNS lookups in the monitor.

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_local_dns_cache_ttl |
|                      | **Dynamic** | Yes                               |
| **Permitted Values** | **Type**    | Integer                           |
|                      | **Default** | 300000                            |
|                      | **Minimum** | 0                                 |
|                      | **Maximum** | 604800000                         |

**Description**: Duration for which DNS resolution results are cached by the monitor.

### `pgsql-monitor_local_dns_cache_refresh_interval`

Interval in milliseconds to refresh the local DNS cache.

|                      |             |                                               |
| -------------------- | ----------- | --------------------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_local_dns_cache_refresh_interval |
|                      | **Dynamic** | Yes                                           |
| **Permitted Values** | **Type**    | Integer                                       |
|                      | **Default** | 60000                                         |
|                      | **Minimum** | 0                                             |
|                      | **Maximum** | 604800000                                     |

**Description**: Frequency at which the monitor refreshes its internal DNS cache.

### `pgsql-monitor_local_dns_resolver_queue_maxsize`

Maximum size of the DNS resolver queue.

|                      |             |                                               |
| -------------------- | ----------- | --------------------------------------------- |
| **System Variable**  | **Name**    | pgsql-monitor_local_dns_resolver_queue_maxsize |
|                      | **Dynamic** | Yes                                           |
| **Permitted Values** | **Type**    | Integer                                       |
|                      | **Default** | 128                                           |
|                      | **Minimum** | 16                                            |
|                      | **Maximum** | 1024                                          |

**Description**: The maximum number of pending DNS resolution requests allowed in the monitor's queue.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.

[1]: https://proxysql.com/postgresql-backend-monitoring/