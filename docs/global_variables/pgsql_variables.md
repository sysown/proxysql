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
