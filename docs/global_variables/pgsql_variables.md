# PostgreSQL Variables

## List of PostgreSQL Variables

NOTE: You can click on the variable name to jump to its definition

<!-- remark-ignore-start -->

| Variable Name                                                         | Default Value |
| --------------------------------------------------------------------- | ------------- |
| [pgsql-have_ssl](#pgsql-have_ssl)                                     | true          |
| [pgsql-max_connections](#pgsql-max_connections)                       | 2048          |
| [pgsql-interfaces](#pgsql-interfaces)                                 | 0.0.0.0:6132  |
| [pgsql-connect_timeout_client](#pgsql-connect_timeout_client)         | 10000         |
| [pgsql-connect_timeout_server](#pgsql-connect_timeout_server)         | 1000          |
| [pgsql-connect_timeout_server_max](#pgsql-connect_timeout_server_max) | 10000         |
| [pgsql-server_version](#pgsql-server_version)                         | 16.1          |
| [pgsql-server_encoding](#pgsql-server_encoding)                       | UTF8          |
| [pgsql-shun_on_failures](#pgsql-shun_on_failures)                     | 5             |
| [pgsql-shun_recovery_time_sec](#pgsql-shun_recovery_time_sec)         | 10            |
| [pgsql-query_retries_on_failure](#pgsql-query_retries_on_failure)     | 1             |
| [pgsql-free_connections_pct](#pgsql-free_connections_pct)             | 10            |
| [pgsql-connection_delay_multiplex_ms](#pgsql-connection_delay_multiplex_ms) | 0             |
| [pgsql-connection_max_age_ms](#pgsql-connection_max_age_ms)           | 0             |
| [pgsql-monitor_enabled](#pgsql-monitor_enabled)                       | true          |
| [pgsql-monitor_history](#pgsql-monitor_history)                       | 7200000       |
| [pgsql-monitor_connect_interval](#pgsql-monitor_connect_interval)     | 120000        |
| [pgsql-monitor_ping_interval](#pgsql-monitor_ping_interval)           | 8000          |

<!-- remark-ignore-end -->

### `pgsql-have_ssl`

Indicates PostgreSQL SSL support availability and configuration status.

|                      |             |                |
| -------------------- | ----------- | -------------- |
| **System Variable**  | **Name**    | pgsql-have_ssl |
|                      | **Dynamic** | No             |
| **Permitted Values** | **Type**    | Boolean        |
|                      | **Default** | true           |

**Description**: Read-only variable indicating whether ProxySQL was compiled with SSL support for PostgreSQL
connections. This variable serves as a gateway indicator that must be true for all PostgreSQL SSL
functionality to operate, including client-to-proxy and proxy-to-server encryption.

### `pgsql-max_connections`

Maximum number of concurrent client connections for PostgreSQL protocol.

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | pgsql-max_connections |
|                      | **Dynamic** | Yes                   |
| **Permitted Values** | **Type**    | Integer               |
|                      | **Default** | 2048                  |
|                      | **Minimum** | 1                     |
|                      | **Maximum** | 1000000               |

**Description**: Maximum number of concurrent PostgreSQL client connections that ProxySQL will accept and
maintain. This critical limit protects both ProxySQL and backend PostgreSQL servers from resource exhaustion
while providing predictable system capacity.

### `pgsql-interfaces`

Network interfaces to listen on for PostgreSQL client connections.

|                      |             |                    |
| -------------------- | ----------- | ------------------ |
| **System Variable**  | **Name**    | `pgsql-interfaces` |
|                      | **Dynamic** | Yes                |
| **Permitted Values** | **Type**    | String             |
|                      | **Default** | `0.0.0.0:6132`     |
|                      | **Minimum** | N/A                |
|                      | **Maximum** | N/A                |

**Description**: Comma-separated list of IP addresses and ports that ProxySQL should listen on for PostgreSQL
client connections. This variable controls the PostgreSQL protocol listener interfaces and is **dynamic**,
meaning changes take effect immediately without requiring a ProxySQL restart.

### `pgsql-connect_timeout_client`

Timeout in milliseconds for client connections to ProxySQL during PostgreSQL protocol handshake establishment.

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | pgsql-connect_timeout_client |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer (milliseconds)       |
|                      | **Default** | 10000                        |
|                      | **Minimum** | 500                          |
|                      | **Maximum** | 3600000                      |

**Description**: The maximum time ProxySQL will wait for a client to complete the PostgreSQL protocol
handshake and establish a connection. This timeout is enforced when a client connection is in
`CONNECTING_CLIENT` status and encompasses the entire connection establishment process, including SSL
negotiation if enabled.

### `pgsql-connect_timeout_server`

Default timeout in milliseconds for connecting to PostgreSQL backend servers.

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | pgsql-connect_timeout_server |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer (milliseconds)       |
|                      | **Default** | 1000                         |
|                      | **Minimum** | 100                          |
|                      | **Maximum** | 100000000                    |

**Description**: The default timeout for establishing connections from ProxySQL to PostgreSQL backend servers.
This timeout applies to all new connections initiated by ProxySQL and can be overridden per-hostgroup or
per-server configuration.

### `pgsql-connect_timeout_server_max`

Maximum timeout in milliseconds for connecting to PostgreSQL backend servers. This variable enforces an
absolute upper limit on connection attempts to prevent indefinite blocking.

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | pgsql-connect_timeout_server_max |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Integer (milliseconds)           |
|                      | **Default** | 10000                            |
|                      | **Minimum** | 100                              |
|                      | **Maximum** | 100000000                        |

**Description**: The maximum timeout for connecting from ProxySQL to PostgreSQL backends in a hostgroup. When
ProxySQL tries to establish a connection to a backend, individual attempts can timeout after
`pgsql-connect_timeout_server` milliseconds, and ProxySQL will retry according to
`pgsql-connect_retries_on_failure` and `pgsql-connect_retries_delay`. However, when the cumulative time
reaches `pgsql-connect_timeout_server_max` milliseconds, all retry attempts cease and an error is returned to
the client with code 9001 and message "Max connect timeout reached while reaching hostgroup...".

### `pgsql-server_version`

The PostgreSQL server version that ProxySQL will report to clients.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | `pgsql-server_version` |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | String                 |
|                      | **Default** | `16.1`                 |

**Description**: This variable sets the version string that ProxySQL reports to clients during the handshake. It defaults to `16.1`.

### `pgsql-server_encoding`

The default encoding that ProxySQL assumes for the server.

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | `pgsql-server_encoding` |
|                      | **Dynamic** | Yes                     |
| **Permitted Values** | **Type**    | String                  |
|                      | **Default** | `UTF8`                  |

**Description**: Sets the default server encoding. ProxySQL uses `UTF8` by default.

### `pgsql-shun_on_failures`

The number of connection failures allowed before a backend server is shunned.

|                      |             |                          |
| -------------------- | ----------- | ------------------------ |
| **System Variable**  | **Name**    | `pgsql-shun_on_failures` |
|                      | **Dynamic** | Yes                      |
| **Permitted Values** | **Type**    | Integer                  |
|                      | **Default** | 5                        |
|                      | **Minimum** | 0                        |
|                      | **Maximum** | 10000000                 |

**Description**: If a backend server fails to respond to connection attempts this many times consecutively, it will be temporarily shunned (marked as OFFLINE) to prevent further traffic from being sent to it.

### `pgsql-shun_recovery_time_sec`

The duration in seconds a backend server remains shunned.

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | `pgsql-shun_recovery_time_sec` |
|                      | **Dynamic** | Yes                            |
| **Permitted Values** | **Type**    | Integer                        |
|                      | **Default** | 10                             |
|                      | **Minimum** | 0                              |
|                      | **Maximum** | 31536000                       |

**Description**: The time in seconds that a backend server will remain in the shunned state before ProxySQL attempts to use it again.

### `pgsql-query_retries_on_failure`

The number of times a query is retried upon failure.

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | `pgsql-query_retries_on_failure` |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Integer                          |
|                      | **Default** | 1                                |
|                      | **Minimum** | 0                                |
|                      | **Maximum** | 1000                             |

**Description**: Defines how many times ProxySQL will attempt to re-execute a query if it fails due to a connection error with the backend.

### `pgsql-free_connections_pct`

The percentage of open idle connections to keep in the connection pool.

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | `pgsql-free_connections_pct` |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer                      |
|                      | **Default** | 10                           |
|                      | **Minimum** | 0                            |
|                      | **Maximum** | 100                          |

**Description**: Controls the percentage of idle connections that ProxySQL maintains in the connection pool relative to `max_connections`. This helps in managing resource usage while keeping enough connections ready for new requests.

### `pgsql-connection_delay_multiplex_ms`

Delay in milliseconds before enabling multiplexing for a new connection.

|                      |             |                                       |
| -------------------- | ----------- | ------------------------------------- |
| **System Variable**  | **Name**    | `pgsql-connection_delay_multiplex_ms` |
|                      | **Dynamic** | Yes                                   |
| **Permitted Values** | **Type**    | Integer                               |
|                      | **Default** | 0                                     |
|                      | **Minimum** | 0                                     |
|                      | **Maximum** | 300000                                |

**Description**: Specifies a delay (in milliseconds) after a connection is established before it can be used for multiplexing. This can be useful for applications that set session variables immediately after connecting.

### `pgsql-connection_max_age_ms`

Maximum age in milliseconds for a backend connection.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | `pgsql-connection_max_age_ms` |
|                      | **Dynamic** | Yes                           |
| **Permitted Values** | **Type**    | Integer                       |
|                      | **Default** | 0                             |
|                      | **Minimum** | 0                             |
|                      | **Maximum** | 86400000                      |

**Description**: The maximum time (in milliseconds) a backend connection can stay open. Once this limit is reached, the connection is closed and a new one is established. A value of `0` disables this feature.

### `pgsql-monitor_enabled`

Enables or disables the PostgreSQL monitor module.

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | `pgsql-monitor_enabled` |
|                      | **Dynamic** | Yes                     |
| **Permitted Values** | **Type**    | Boolean                 |
|                      | **Default** | `true`                  |

**Description**: Master switch to enable or disable monitoring for PostgreSQL backends. When set to `false`, all monitoring activities are suspended.

### `pgsql-monitor_history`

Duration in milliseconds to keep monitoring history.

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | `pgsql-monitor_history` |
|                      | **Dynamic** | Yes                     |
| **Permitted Values** | **Type**    | Integer                 |
|                      | **Default** | 7200000                 |
|                      | **Minimum** | 1000                    |
|                      | **Maximum** | 604800000               |

**Description**: Time in milliseconds for which monitoring history is retained in the internal database. The default is 2 hours (7200000 ms).

### `pgsql-monitor_connect_interval`

Interval in milliseconds for checking backend connectivity.

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | `pgsql-monitor_connect_interval` |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Integer                          |
|                      | **Default** | 120000                           |
|                      | **Minimum** | 100                              |
|                      | **Maximum** | 604800000                        |

**Description**: How often (in milliseconds) the monitor checks connectivity to the backend servers. Default is 2 minutes.

### `pgsql-monitor_ping_interval`

Interval in milliseconds for sending ping checks to backends.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | `pgsql-monitor_ping_interval` |
|                      | **Dynamic** | Yes                           |
| **Permitted Values** | **Type**    | Integer                       |
|                      | **Default** | 8000                          |
|                      | **Minimum** | 100                           |
|                      | **Maximum** | 604800000                     |

**Description**: The frequency (in milliseconds) at which ProxySQL sends a ping to backend servers to verify they are alive and responsive. Default is 8 seconds.
