# PostgreSQL Variables

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## List of PostgreSQL Variables

NOTE: You can click on the variable name to jump to its definition

<!-- remark-ignore-start -->

| Variable Name                                                         | Default Value |
| --------------------------------------------------------------------- | ------------- |
| [pgsql-auditlog_filename](#pgsql-auditlog_filename)                   | NULL          |
| [pgsql-auditlog_filesize](#pgsql-auditlog_filesize)                   | 104857600     |
| [pgsql-aurora_max_lag_ms_only_read_from_replicas](#pgsql-aurora_max_lag_ms_only_read_from_replicas) | 2 |
| [pgsql-authentication_method](#pgsql-authentication_method)           | 3             |
| [pgsql-auto_increment_delay_multiplex](#pgsql-auto_increment_delay_multiplex) | 5     |
| [pgsql-auto_increment_delay_multiplex_timeout_ms](#pgsql-auto_increment_delay_multiplex_timeout_ms) | 10000 |
| [pgsql-autocommit_false_is_transaction](#pgsql-autocommit_false_is_transaction) | false |
| [pgsql-autocommit_false_not_reusable](#pgsql-autocommit_false_not_reusable) | false   |
| [pgsql-automatic_detect_sqli](#pgsql-automatic_detect_sqli)           | false         |
| [pgsql-binlog_reader_connect_retry_msec](#pgsql-binlog_reader_connect_retry_msec) | 3000 |
| [pgsql-client_host_cache_size](#pgsql-client_host_cache_size)         | 0             |
| [pgsql-client_host_error_counts](#pgsql-client_host_error_counts)     | 0             |
| [pgsql-commands_stats](#pgsql-commands_stats)                         | true          |
| [pgsql-connect_retries_delay](#pgsql-connect_retries_delay)           | 1             |
| [pgsql-connect_retries_on_failure](#pgsql-connect_retries_on_failure) | 10            |
| [pgsql-connect_timeout_client](#pgsql-connect_timeout_client)         | 10000         |
| [pgsql-connect_timeout_server](#pgsql-connect_timeout_server)         | 1000          |
| [pgsql-connect_timeout_server_max](#pgsql-connect_timeout_server_max) | 10000         |
| [pgsql-connection_delay_multiplex_ms](#pgsql-connection_delay_multiplex_ms) | 0             |
| [pgsql-connection_max_age_ms](#pgsql-connection_max_age_ms)           | 0             |
| [pgsql-connection_warming](#pgsql-connection_warming)                 | false         |
| [pgsql-default_max_latency_ms](#pgsql-default_max_latency_ms)         | 1000          |
| [pgsql-default_query_delay](#pgsql-default_query_delay)               | 0             |
| [pgsql-default_query_timeout](#pgsql-default_query_timeout)           | 86400000      |
| [pgsql-default_reconnect](#pgsql-default_reconnect)                   | true          |
| [pgsql-default_schema](#pgsql-default_schema)                         | information_schema |
| [pgsql-enforce_autocommit_on_reads](#pgsql-enforce_autocommit_on_reads) | false       |
| [pgsql-eventslog_default_log](#pgsql-eventslog_default_log)           | 0             |
| [pgsql-eventslog_filename](#pgsql-eventslog_filename)                 | NULL          |
| [pgsql-eventslog_filesize](#pgsql-eventslog_filesize)                 | 104857600     |
| [pgsql-eventslog_format](#pgsql-eventslog_format)                     | 1             |
| [pgsql-firewall_whitelist_enabled](#pgsql-firewall_whitelist_enabled) | false         |
| [pgsql-free_connections_pct](#pgsql-free_connections_pct)             | 10            |
| [pgsql-handle_unknown_charset](#pgsql-handle_unknown_charset)         | 1             |
| [pgsql-have_compress](#pgsql-have_compress)                           | true          |
| [pgsql-have_ssl](#pgsql-have_ssl)                                     | true          |
| [pgsql-hostgroup_manager_verbose](#pgsql-hostgroup_manager_verbose)   | 1             |
| [pgsql-init_connect](#pgsql-init_connect)                             | NULL          |
| [pgsql-interfaces](#pgsql-interfaces)                                 | 0.0.0.0:6132  |
| [pgsql-kill_backend_connection_when_disconnect](#pgsql-kill_backend_connection_when_disconnect) | false |
| [pgsql-log_unhealthy_connections](#pgsql-log_unhealthy_connections)   | true          |
| [pgsql-long_query_time](#pgsql-long_query_time)                       | 1000          |
| [pgsql-max_allowed_packet](#pgsql-max_allowed_packet)                 | 67108864      |
| [pgsql-max_connections](#pgsql-max_connections)                       | 2048          |
| [pgsql-max_stmts_cache](#pgsql-max_stmts_cache)                       | 10000         |
| [pgsql-max_stmts_per_connection](#pgsql-max_stmts_per_connection)     | 20            |
| [pgsql-max_transaction_idle_time](#pgsql-max_transaction_idle_time)   | 14400000      |
| [pgsql-max_transaction_time](#pgsql-max_transaction_time)             | 14400000      |
| [pgsql-min_num_servers_lantency_awareness](#pgsql-min_num_servers_lantency_awareness) | 1000 |
| [pgsql-mirror_max_concurrency](#pgsql-mirror_max_concurrency)         | 16            |
| [pgsql-mirror_max_queue_length](#pgsql-mirror_max_queue_length)       | 32000         |
| [pgsql-multiplexing](#pgsql-multiplexing)                             | true          |
| [pgsql-ping_interval_server_msec](#pgsql-ping_interval_server_msec)   | 10000         |
| [pgsql-ping_timeout_server](#pgsql-ping_timeout_server)               | 200           |
| [pgsql-poll_timeout](#pgsql-poll_timeout)                             | 2000          |
| [pgsql-poll_timeout_on_failure](#pgsql-poll_timeout_on_failure)       | 100           |
| [pgsql-query_cache_handle_warnings](#pgsql-query_cache_handle_warnings) | 0           |
| [pgsql-query_cache_size_mb](#pgsql-query_cache_size_mb)               | 256           |
| [pgsql-query_cache_soft_ttl_pct](#pgsql-query_cache_soft_ttl_pct)     | 0             |
| [pgsql-query_cache_stores_empty_result](#pgsql-query_cache_stores_empty_result) | true |
| [pgsql-query_digests](#pgsql-query_digests)                           | true          |
| [pgsql-query_digests_grouping_limit](#pgsql-query_digests_grouping_limit) | 1000       |
| [pgsql-query_digests_keep_comment](#pgsql-query_digests_keep_comment) | false         |
| [pgsql-query_digests_lowercase](#pgsql-query_digests_lowercase)       | false         |
| [pgsql-query_digests_max_digest_length](#pgsql-query_digests_max_digest_length) | 2048 |
| [pgsql-query_digests_max_query_length](#pgsql-query_digests_max_query_length) | 65000 |
| [pgsql-query_digests_no_digits](#pgsql-query_digests_no_digits)       | false         |
| [pgsql-query_digests_normalize_digest_text](#pgsql-query_digests_normalize_digest_text) | false |
| [pgsql-query_digests_replace_null](#pgsql-query_digests_replace_null) | false         |
| [pgsql-query_digests_track_hostname](#pgsql-query_digests_track_hostname) | false       |
| [pgsql-query_processor_iterations](#pgsql-query_processor_iterations) | 0             |
| [pgsql-query_processor_regex](#pgsql-query_processor_regex)           | 1             |
| [pgsql-query_retries_on_failure](#pgsql-query_retries_on_failure)     | 1             |
| [pgsql-server_encoding](#pgsql-server_encoding)                       | UTF8          |
| [pgsql-server_version](#pgsql-server_version)                         | 16.1          |
| [pgsql-sessions_sort](#pgsql-sessions_sort)                           | false         |
| [pgsql-set_parser_algorithm](#pgsql-set_parser_algorithm)             | 2             |
| [pgsql-set_query_lock_on_hostgroup](#pgsql-set_query_lock_on_hostgroup) | 1           |
| [pgsql-shun_on_failures](#pgsql-shun_on_failures)                     | 5             |
| [pgsql-shun_recovery_time_sec](#pgsql-shun_recovery_time_sec)         | 10            |
| [pgsql-stats_time_backend_query](#pgsql-stats_time_backend_query)     | false         |
| [pgsql-stats_time_query_processor](#pgsql-stats_time_query_processor) | false         |
| [pgsql-tcp_keepalive_time](#pgsql-tcp_keepalive_time)                 | 120           |
| [pgsql-threshold_query_length](#pgsql-threshold_query_length)         | 524288        |
| [pgsql-threshold_resultset_size](#pgsql-threshold_resultset_size)     | 4194304       |
| [pgsql-throttle_connections_per_sec_to_hostgroup](#pgsql-throttle_connections_per_sec_to_hostgroup) | 1000000 |
| [pgsql-throttle_max_bytes_per_second_to_client](#pgsql-throttle_max_bytes_per_second_to_client) | 0 |
| [pgsql-throttle_ratio_server_to_client](#pgsql-throttle_ratio_server_to_client) | 0 |
| [pgsql-unshun_algorithm](#pgsql-unshun_algorithm)                     | 0             |
| [pgsql-use_tcp_keepalive](#pgsql-use_tcp_keepalive)                   | true          |
| [pgsql-verbose_query_error](#pgsql-verbose_query_error)               | false         |
| [pgsql-wait_timeout](#pgsql-wait_timeout)                             | 28800000      |

<!-- remark-ignore-end -->

### `pgsql-auditlog_filename`

Base filename for the PostgreSQL audit log.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | `pgsql-auditlog_filename` |
| **Dynamic**          | **Yes**     |                        |
| **Permitted Values** | **Type**    | String                 |
|                      | **Default** | NULL                   |

**Description**: The full path and base name for the files where PostgreSQL audit logs will be stored.

### `pgsql-auditlog_filesize`

Maximum size of the PostgreSQL audit log file.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | `pgsql-auditlog_filesize` |
| **Dynamic**          | **Yes**     |                        |
| **Permitted Values** | **Type**    | Integer (bytes)        |
|                      | **Default** | 104857600              |
|                      | **Minimum** | 1048576                |
|                      | **Maximum** | 1073741824             |

**Description**: Specifies the size limit for individual PostgreSQL audit log files before they are rotated.

### `pgsql-aurora_max_lag_ms_only_read_from_replicas`

**Description**: Not supported.

### `pgsql-authentication_method`

Defines the authentication method ProxySQL should use for backend connections.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | `pgsql-authentication_method` |
| **Dynamic**          | **Yes**     |                               |
| **Permitted Values** | **Type**    | Integer                       |
|                      | **Default** | 3                             |
|                      | **Minimum** | 1                             |
|                      | **Maximum** | 3                             |

**Description**: Configures the authentication protocol used between ProxySQL and backend PostgreSQL servers. Common values: `1` (No Password), `2` (Clear Text), `3` (SASL/SCRAM).

### `pgsql-auto_increment_delay_multiplex`

Number of queries to disable multiplexing after an insert with auto-increment.

|                      |             |                                        |
| -------------------- | ----------- | -------------------------------------- |
| **System Variable**  | **Name**    | `pgsql-auto_increment_delay_multiplex` |
| **Dynamic**          | **Yes**     |                                        |
| **Permitted Values** | **Type**    | Integer                                |
|                      | **Default** | 5                                      |
|                      | **Minimum** | 0                                      |
|                      | **Maximum** | 1000000                                |

**Description**: Temporarily disables multiplexing for a session after an auto-increment value is generated, ensuring subsequent queries see the new value.

### `pgsql-auto_increment_delay_multiplex_timeout_ms`

**Description**: Not supported.

### `pgsql-autocommit_false_is_transaction`

**Description**: Not supported.

### `pgsql-autocommit_false_not_reusable`

**Description**: Not supported.

### `pgsql-automatic_detect_sqli`

Enables automatic detection of SQL injection attempts for PostgreSQL.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | `pgsql-automatic_detect_sqli` |
| **Dynamic**          | **Yes**     |                               |
| **Permitted Values** | **Type**    | Boolean                       |
|                      | **Default** | `false`                       |

**Description**: When enabled, ProxySQL analyzes PostgreSQL queries for potential SQL injection patterns and takes action based on configured rules.

### `pgsql-binlog_reader_connect_retry_msec`

**Description**: Not supported.

### `pgsql-client_host_cache_size`

Size of the cache for PostgreSQL client host information.

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | `pgsql-client_host_cache_size` |
| **Dynamic**          | **Yes**     |                              |
| **Permitted Values** | **Type**    | Integer                      |
|                      | **Default** | 0                            |
|                      | **Minimum** | 0                            |
|                      | **Maximum** | 1048576                      |

**Description**: Configures the maximum number of entries in the client host cache, used for tracking client-specific errors and connection attempts.

### `pgsql-client_host_error_counts`

Threshold for consecutive errors from a client host before taking action.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | `pgsql-client_host_error_counts` |
| **Dynamic**          | **Yes**     |                               |
| **Permitted Values** | **Type**    | Integer                       |
|                      | **Default** | 0                             |
|                      | **Minimum** | 0                             |
|                      | **Maximum** | 1048576                       |

**Description**: Specifies the number of connection errors allowed from a specific client host before ProxySQL begins blocking or limiting further connections from that source.

### `pgsql-commands_stats`

Enables collection of command-level statistics for PostgreSQL.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | `pgsql-commands_stats` |
| **Dynamic**          | **Yes**     |                        |
| **Permitted Values** | **Type**    | Boolean                |
|                      | **Default** | `true`                 |

**Description**: Controls whether ProxySQL tracks performance metrics for individual PostgreSQL command types.

### `pgsql-connect_retries_delay`

Delay in milliseconds between connection retry attempts.

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | `pgsql-connect_retries_delay` |
| **Dynamic**          | **Yes**     |                                |
| **Permitted Values** | **Type**    | Integer (milliseconds)         |
|                      | **Default** | 1                              |
|                      | **Minimum** | 0                              |
|                      | **Maximum** | 10000                          |

**Description**: Sets the pause time between consecutive attempts to connect to a PostgreSQL backend server.

### `pgsql-connect_retries_on_failure`

The number of times ProxySQL will retry connecting to a backend server before giving up.

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | `pgsql-connect_retries_on_failure` |
| **Dynamic**          | **Yes**     |                                   |
| **Permitted Values** | **Type**    | Integer                           |
|                      | **Default** | 10                                |
|                      | **Minimum** | 0                                 |
|                      | **Maximum** | 1000                              |

**Description**: Defines the maximum number of retry attempts for establishing a new connection to a backend server.

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

**Description**: The maximum timeout for connecting from ProxySQL to PostgreSQL backends in a hostgroup. When ProxySQL tries to establish a connection to a backend, individual attempts can timeout after `pgsql-connect_timeout_server` milliseconds, and ProxySQL will retry according to `pgsql-connect_retries_on_failure` and `pgsql-connect_retries_delay`. However, when the cumulative time reaches `pgsql-connect_timeout_server_max` milliseconds, all retry attempts cease and an error is returned to the client with the message "Max connect timeout reached while reaching hostgroup...".

### `pgsql-connection_delay_multiplex_ms`

Delay in milliseconds before enabling multiplexing for a new connection.

|                      |             |                                       |
| -------------------- | ----------- | ------------------------------------- |
| **System Variable**  | **Name**    | `pgsql-connection_delay_multiplex_ms` |
| **Dynamic**          | **Yes**     |                                       |
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
| **Dynamic**          | **Yes**     |                               |
| **Permitted Values** | **Type**    | Integer                       |
| **Default**          | **0**       |                               |
| **Minimum**          | **0**       |                               |
| **Maximum**          | **86400000** |                               |

**Description**: The maximum time (in milliseconds) a backend connection can stay open. Once this limit is reached, the connection is closed and a new one is established. A value of `0` disables this feature. Connections are only checked and removed when they become idle; active connections are not interrupted regardless of age.

### `pgsql-connection_warming`

Enables background connection establishment to keep the connection pool "warm".

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | `pgsql-connection_warming` |
| **Dynamic**          | **Yes**     |                            |
| **Permitted Values** | **Type**    | Boolean                    |
| **Default**          | **false**   |                            |

**Description**: When enabled, ProxySQL will proactively open connections to backend servers to ensure a minimum number of connections are always ready for incoming requests.

### `pgsql-default_max_latency_ms`

Default maximum latency for backend PostgreSQL servers.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | `pgsql-default_max_latency_ms` |
| **Dynamic**          | **Yes**     |                               |
| **Permitted Values** | **Type**    | Integer (milliseconds)        |
|                      | **Default** | 1000                          |
|                      | **Minimum** | 0                             |
|                      | **Maximum** | 1728000000                    |

**Description**: The default maximum latency allowed for a PostgreSQL backend server before it is considered too far and excluded from the routing pool.

### `pgsql-default_query_delay`

**Description**: Not supported.

### `pgsql-default_query_timeout`

Default timeout in milliseconds for PostgreSQL queries.

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | `pgsql-default_query_timeout` |
| **Dynamic**          | **Yes**     |                              |
| **Permitted Values** | **Type**    | Integer                      |
|                      | **Default** | 86400000                     |
|                      | **Minimum** | 1000                         |
|                      | **Maximum** | 1728000000                   |

**Description**: The default maximum time ProxySQL will wait for a query to complete if no timeout is specified in the query rules. When exceeded, the running query is terminated on the backend server and the client receives a query error. This limit applies per-query, measured from when the query is sent to the backend.

### `pgsql-default_reconnect`

**Description**: Not supported.

### `pgsql-default_schema`

**Description**: Not supported.

### `pgsql-enforce_autocommit_on_reads`

**Description**: Not supported.

### `pgsql-eventslog_default_log`

**Description**: Not supported.

### `pgsql-eventslog_filename`

Base filename for the PostgreSQL events log.

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | `pgsql-eventslog_filename` |
| **Dynamic**          | **Yes**     |                         |
| **Permitted Values** | **Type**    | String                  |
|                      | **Default** | NULL                    |

**Description**: The full path and base name for the files where PostgreSQL event logs will be stored.

### `pgsql-eventslog_filesize`

Maximum size of the PostgreSQL events log file.

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | `pgsql-eventslog_filesize` |
| **Dynamic**          | **Yes**     |                         |
| **Permitted Values** | **Type**    | Integer (bytes)         |
|                      | **Default** | 104857600               |
|                      | **Minimum** | 1048576                 |
|                      | **Maximum** | 1073741824              |

**Description**: Defines the maximum size allowed for PostgreSQL event log files before rotation.

### `pgsql-eventslog_format`

Format of the PostgreSQL events log.

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | `pgsql-eventslog_format` |
| **Dynamic**          | **Yes**     |                       |
| **Permitted Values** | **Type**    | Integer               |
|                      | **Default** | 1                     |
|                      | **Minimum** | 1                     |
| **Maximum**          | **1**       |                       |

**Description**: Sets the logging format for PostgreSQL events. Currently, only format `1` (Binary) is supported.

### `pgsql-firewall_whitelist_enabled`

Enables the firewall whitelist for PostgreSQL.

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | `pgsql-firewall_whitelist_enabled` |
| **Dynamic**          | **Yes**     |                                     |
| **Permitted Values** | **Type**    | Boolean                             |
|                      | **Default** | `false`                             |

**Description**: When enabled, ProxySQL enforces a whitelist of allowed PostgreSQL queries, blocking any that are not explicitly permitted.

### `pgsql-free_connections_pct`

The percentage of open idle connections to keep in the connection pool.

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | `pgsql-free_connections_pct` |
| **Dynamic**          | **Yes**     |                              |
| **Permitted Values** | **Type**    | Integer                      |
|                      | **Default** | 10                           |
|                      | **Minimum** | 0                            |
|                      | **Maximum** | 100                          |

**Description**: Controls the percentage of idle connections that ProxySQL maintains in the connection pool relative to `max_connections`. This helps in managing resource usage while keeping enough connections ready for new requests. ProxySQL will remove excess free connections when the idle pool exceeds this percentage threshold, ensuring that backend connections are available for reuse without consuming unnecessary resources.

### `pgsql-handle_unknown_charset`

**Description**: Not supported.

### `pgsql-have_compress`

**Description**: Not supported.

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

### `pgsql-hostgroup_manager_verbose`

Enables verbose logging for the PostgreSQL hostgroup manager.

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | `pgsql-hostgroup_manager_verbose` |
| **Dynamic**          | **Yes**     |                                |
| **Permitted Values** | **Type**    | Integer                        |
|                      | **Default** | 1                              |
|                      | **Minimum** | 0                              |
|                      | **Maximum** | 3                              |

**Description**: Controls the verbosity of logs generated by the PostgreSQL hostgroup management module. Higher values provide more detailed information.

### `pgsql-init_connect`

SQL strings to be executed when a new backend connection is established.

|                      |             |                      |
| -------------------- | ----------- | -------------------- |
| **System Variable**  | **Name**    | `pgsql-init_connect` |
| **Dynamic**          | **Yes**     |                      |
| **Permitted Values** | **Type**    | String               |
|                      | **Default** | NULL                 |

**Description**: A string of one or more SQL statements to be executed by ProxySQL for each PostgreSQL client that connects.

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

### `pgsql-kill_backend_connection_when_disconnect`

Kills the backend connection immediately upon client disconnect.

|                      |             |                                               |
| -------------------- | ----------- | --------------------------------------------- |
| **System Variable**  | **Name**    | `pgsql-kill_backend_connection_when_disconnect` |
| **Dynamic**          | **Yes**     |                                               |
| **Permitted Values** | **Type**    | Boolean                                       |
|                      | **Default** | `false`                                       |

**Description**: If enabled, ProxySQL will close the associated backend connection as soon as the client disconnects, rather than returning it to the pool. When disabled (default), backend connections remain available in the pool for reuse by other clients, which improves performance through connection reuse. When enabled, each client gets a fresh backend connection, which may increase connection overhead to the backend servers.

### `pgsql-log_unhealthy_connections`

Controls whether ProxySQL logs unhealthy connections to PostgreSQL backends.

|                      |             |                                    |
| -------------------- | ----------- | ---------------------------------- |
| **System Variable**  | **Name**    | `pgsql-log_unhealthy_connections` |
| **Dynamic**          | **Yes**     |                                    |
| **Permitted Values** | **Type**    | Boolean                            |
|                      | **Default** | `true`                             |

**Description**: When enabled, ProxySQL logs details about connection attempts to backend servers that fail or are deemed unhealthy.

### `pgsql-long_query_time`

Threshold in milliseconds for slow query logging.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | `pgsql-long_query_time` |
| **Dynamic**          | **Yes**     |                        |
| **Permitted Values** | **Type**    | Integer (milliseconds) |
|                      | **Default** | 1000                   |
|                      | **Minimum** | 0                      |
|                      | **Maximum** | 1728000000             |

**Description**: If a query takes longer than this value to execute, it is considered a slow query and the slow query counter is incremented. This only affects statistics collection visible in `stats_pgsql_query_digest`; queries are NOT terminated based on this threshold. Use `pgsql-default_query_timeout` or query rule timeouts to terminate long-running queries.

### `pgsql-max_allowed_packet`

Maximum size of a single network packet for PostgreSQL.

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | `pgsql-max_allowed_packet` |
| **Dynamic**          | **Yes**     |                            |
| **Permitted Values** | **Type**    | Integer                    |
|                      | **Default** | 67108864                   |
|                      | **Minimum** | 8192                       |
|                      | **Maximum** | 1073741824                 |

**Description**: Sets the upper limit for the size of a single PostgreSQL protocol packet that ProxySQL will handle.

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

### `pgsql-max_stmts_cache`

Maximum number of prepared statements to cache per thread.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | `pgsql-max_stmts_cache` |
| **Dynamic**          | **Yes**     |                        |
| **Permitted Values** | **Type**    | Integer                |
|                      | **Default** | 10000                  |
|                      | **Minimum** | 128                    |
|                      | **Maximum** | 1048576                |

**Description**: Limits the total number of PostgreSQL prepared statements that can be cached across all backend connections within a single thread.

### `pgsql-max_stmts_per_connection`

Maximum number of prepared statements per backend connection.

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | `pgsql-max_stmts_per_connection`  |
| **Dynamic**          | **Yes**     |                                   |
| **Permitted Values** | **Type**    | Integer                           |
|                      | **Default** | 20                                |
|                      | **Minimum** | 1                                 |
|                      | **Maximum** | 1024                              |

**Description**: Limits how many unique prepared statements a single backend connection can maintain simultaneously.

### `pgsql-max_transaction_idle_time`

Maximum time a transaction can be idle in PostgreSQL.

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | `pgsql-max_transaction_idle_time` |
| **Dynamic**          | **Yes**     |                                  |
| **Permitted Values** | **Type**    | Integer (milliseconds)           |
|                      | **Default** | 14400000                         |
|                      | **Minimum** | 1000                             |
|                      | **Maximum** | 1728000000                       |

**Description**: Specifies the maximum duration (in milliseconds) a PostgreSQL transaction can remain idle before ProxySQL terminates the connection. When a transaction is idle longer than this threshold, the client connection is terminated to prevent resource leaks. Only applies to sessions with active transactions; sessions without active transactions are controlled by `pgsql-wait_timeout` instead.

### `pgsql-max_transaction_time`

Maximum duration for a PostgreSQL transaction.

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | `pgsql-max_transaction_time` |
| **Dynamic**          | **Yes**     |                              |
| **Permitted Values** | **Type**    | Integer (milliseconds)       |
|                      | **Default** | 14400000                     |
|                      | **Minimum** | 1000                         |
|                      | **Maximum** | 1728000000           |

**Description**: Sets the absolute maximum time (in milliseconds) a PostgreSQL transaction is allowed to run before being terminated. This is a hard limit that applies to the total duration of a transaction, measured from when the first statement begins. When exceeded, the client connection is terminated regardless of whether the transaction is currently active or idle.

### `pgsql-min_num_servers_lantency_awareness`

**Description**: Not supported.

### `pgsql-mirror_max_concurrency`

Maximum concurrent requests for mirrored sessions.

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | `pgsql-mirror_max_concurrency` |
| **Dynamic**          | **Yes**     |                                |
| **Permitted Values** | **Type**    | Integer                        |
|                      | **Default** | 16                             |
|                      | **Minimum** | 1                              |
|                      | **Maximum** | 8192                           |

**Description**: Limits the number of simultaneous mirrored sessions to prevent resource exhaustion during traffic mirroring.

### `pgsql-mirror_max_queue_length`

Maximum number of queries queued for mirroring.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | `pgsql-mirror_max_queue_length` |
| **Dynamic**          | **Yes**     |                               |
| **Permitted Values** | **Type**    | Integer                       |
|                      | **Default** | 32000                         |
|                      | **Minimum** | 0                             |
|                      | **Maximum** | 1048576                       |

**Description**: Sets the upper limit for the number of PostgreSQL queries waiting in the mirror queue. New mirroring requests are dropped if this limit is reached.

### `pgsql-multiplexing`

Global switch for PostgreSQL connection multiplexing.

|                      |             |                      |
| -------------------- | ----------- | -------------------- |
| **System Variable**  | **Name**    | `pgsql-multiplexing` |
| **Dynamic**          | **Yes**     |                      |
| **Permitted Values** | **Type**    | Boolean              |
|                      | **Default** | `true`               |

**Description**: Master toggle for PostgreSQL multiplexing. When enabled, ProxySQL can reuse backend connections for different client sessions when they are in an idle state.

### `pgsql-ping_interval_server_msec`

Interval in milliseconds for sending ping checks to PostgreSQL backends.

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | `pgsql-ping_interval_server_msec` |
| **Dynamic**          | **Yes**     |                                   |
| **Permitted Values** | **Type**    | Integer (milliseconds)            |
|                      | **Default** | 10000                             |
|                      | **Minimum** | 1000                              |
|                      | **Maximum** | 604800000                         |

**Description**: The frequency at which ProxySQL sends internal pings to PostgreSQL backend servers to maintain connection health.

### `pgsql-ping_timeout_server`

Timeout in milliseconds for internal PostgreSQL backend pings.

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | `pgsql-ping_timeout_server` |
| **Dynamic**          | **Yes**     |                            |
| **Permitted Values** | **Type**    | Integer (milliseconds)     |
|                      | **Default** | 200                        |
|                      | **Minimum** | 10                         |
|                      | **Maximum** | 600000                     |

**Description**: The maximum time ProxySQL will wait for a response to an internal ping before considering the backend connection timed out.

### `pgsql-poll_timeout`

**Description**: Controls how frequently the worker thread checks for network activity on client and backend connections. This is the maximum time the thread will wait for new events before processing queued tasks and performing maintenance. Lower values reduce latency at the cost of increased CPU usage; higher values improve CPU efficiency but may delay response to network events.

### `pgsql-poll_timeout_on_failure`

Wait time in milliseconds after a polling error.

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | `pgsql-poll_timeout_on_failure` |
| **Dynamic**          | **Yes**     |                              |
| **Permitted Values** | **Type**    | Integer (milliseconds)       |
|                      | **Default** | 100                          |
|                      | **Minimum** | 10                           |
|                      | **Maximum** | 20000                        |

**Description**: The duration ProxySQL will wait before re-polling after a connection or network failure occurs during PostgreSQL traffic handling. When backend connections cannot be established, the poll timeout is temporarily reduced to this value to detect connection establishment or failure more quickly. Once connections are established, the normal `pgsql-poll_timeout` is restored.

### `pgsql-query_cache_handle_warnings`

Controls whether queries that generate warnings are cached.

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | `pgsql-query_cache_handle_warnings` |
| **Dynamic**          | **Yes**     |                                   |
| **Permitted Values** | **Type**    | Integer                           |
|                      | **Default** | 0                                 |
|                      | **Minimum** | 0                                 |
|                      | **Maximum** | 1                                 |

**Description**: When set to `1`, ProxySQL will cache query results even if they include warnings. If set to `0`, queries with warnings are not cached.

### `pgsql-query_cache_size_mb`

Size of the PostgreSQL query cache in megabytes.

|                      |             |                           |
| -------------------- | ----------- | ------------------------- |
| **System Variable**  | **Name**    | `pgsql-query_cache_size_mb` |
| **Dynamic**          | **Yes**     |                           |
| **Permitted Values** | **Type**    | Integer (MB)              |
|                      | **Default** | 256                       |
|                      | **Minimum** | 0                         |
|                      | **Maximum** | 10240                     |

**Description**: Configures the total amount of memory allocated for caching PostgreSQL query results.

### `pgsql-query_cache_soft_ttl_pct`

**Description**: Not supported.

### `pgsql-query_cache_stores_empty_result`

Controls whether the PostgreSQL query cache should store empty resultsets.

|                      |             |                                      |
| -------------------- | ----------- | ------------------------------------ |
| **System Variable**  | **Name**    | `pgsql-query_cache_stores_empty_result` |
| **Dynamic**          | **Yes**     |                                      |
| **Permitted Values** | **Type**    | Boolean                              |
|                      | **Default** | `true`                               |

**Description**: When enabled, ProxySQL will cache query results that return zero rows. This can be beneficial for reducing backend load for queries that frequently return no data.

### `pgsql-query_digests`

Enables or disables PostgreSQL query digest collection.

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | `pgsql-query_digests` |
| **Dynamic**          | **Yes**     |                       |
| **Permitted Values** | **Type**    | Boolean               |
|                      | **Default** | `true`                |

**Description**: When enabled, ProxySQL collects query digests for PostgreSQL traffic, which are visible in the `stats_pgsql_query_digest` table.

### `pgsql-query_digests_grouping_limit`

Limit for the number of parameters to group in a single query digest.

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | `pgsql-query_digests_grouping_limit` |
| **Dynamic**          | **Yes**     |                                     |
| **Permitted Values** | **Type**    | Integer                             |
|                      | **Default** | 1000                                |
|                      | **Minimum** | 1                                   |
|                      | **Maximum** | 2089                                |

**Description**: Controls the maximum number of parameters ProxySQL will consolidate when generating a normalized query digest for PostgreSQL.

### `pgsql-query_digests_keep_comment`

**Description**: Not supported.

### `pgsql-query_digests_lowercase`

Converts queries to lowercase before digest calculation.

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | `pgsql-query_digests_lowercase` |
| **Dynamic**          | **Yes**     |                                 |
| **Permitted Values** | **Type**    | Boolean                         |
|                      | **Default** | `false`                         |

**Description**: If set to `true`, PostgreSQL queries are normalized to lowercase before generating their digest.

### `pgsql-query_digests_max_digest_length`

Maximum length of the generated query digest text.

|                      |             |                                         |
| -------------------- | ----------- | --------------------------------------- |
| **System Variable**  | **Name**    | `pgsql-query_digests_max_digest_length` |
| **Dynamic**          | **Yes**     |                                         |
| **Permitted Values** | **Type**    | Integer                                 |
|                      | **Default** | 2048                                    |
|                      | **Minimum** | 16                                      |
|                      | **Maximum** | 1048576                                 |

**Description**: Defines the maximum number of characters ProxySQL will store for a normalized PostgreSQL query digest.

### `pgsql-query_digests_max_query_length`

Maximum query length to be considered for digest calculation.

|                      |             |                                       |
| -------------------- | ----------- | ------------------------------------- |
| **System Variable**  | **Name**    | `pgsql-query_digests_max_query_length` |
| **Dynamic**          | **Yes**     |                                       |
| **Permitted Values** | **Type**    | Integer                               |
|                      | **Default** | 65000                                 |
|                      | **Minimum** | 16                                    |
|                      | **Maximum** | 1048576                               |

**Description**: Queries longer than this value will be truncated before being processed for digest generation.

### `pgsql-query_digests_no_digits`

**Description**: Not supported.

### `pgsql-query_digests_normalize_digest_text`

**Description**: Not supported.

### `pgsql-query_digests_replace_null`

**Description**: Not supported.

### `pgsql-query_digests_track_hostname`

**Description**: Not supported.

### `pgsql-query_processor_iterations`

**Description**: Not supported.

### `pgsql-query_processor_regex`

**Description**: Not supported.

### `pgsql-query_retries_on_failure`

The number of times a query is retried upon failure.

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | `pgsql-query_retries_on_failure` |
| **Dynamic**          | **Yes**     |                                  |
| **Permitted Values** | **Type**    | Integer                          |
|                      | **Default** | 1                                |
|                      | **Minimum** | 0                                |
|                      | **Maximum** | 1000                             |

**Description**: Defines how many times ProxySQL will attempt to re-execute a query if it fails due to a connection error with the backend. When a query fails on a connection error, ProxySQL automatically retries the query on a new backend connection up to this many times before returning an error to the client. Query rules can override this default value by specifying a custom retry count.

### `pgsql-server_encoding`

The default encoding that ProxySQL assumes for the server.

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | `pgsql-server_encoding` |
| **Dynamic**          | **Yes**     |                         |
| **Permitted Values** | **Type**    | String                  |
|                      | **Default** | `UTF8`                  |

**Description**: Sets the default server encoding. ProxySQL uses `UTF8` by default.

### `pgsql-server_version`

The PostgreSQL server version that ProxySQL will report to clients.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | `pgsql-server_version` |
| **Dynamic**          | **Yes**     |                        |
| **Permitted Values** | **Type**    | String                 |
|                      | **Default** | `16.1`                 |

**Description**: This variable sets the version string that ProxySQL reports to clients during the handshake. It defaults to `16.1`.

### `pgsql-sessions_sort`

Enables sorting of PostgreSQL sessions for processing.

|                      |             |                      |
| -------------------- | ----------- | -------------------- |
| **System Variable**  | **Name**    | `pgsql-sessions_sort` |
| **Dynamic**          | **Yes**     |                      |
| **Permitted Values** | **Type**    | Boolean              |
|                      | **Default** | `false`              |

**Description**: When enabled, ProxySQL sorts active PostgreSQL sessions before processing them, which can optimize performance by improving CPU cache locality on systems with many concurrent connections. Sessions are sorted by their connection timeout status to prioritize sessions that are closer to their timeout limits. This does not affect routing behavior or query execution order.

### `pgsql-set_parser_algorithm`

**Description**: Not supported.

### `pgsql-set_query_lock_on_hostgroup`

Controls routing locks when a session variable is set.

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | `pgsql-set_query_lock_on_hostgroup` |
| **Dynamic**          | **Yes**     |                                     |
| **Permitted Values** | **Type**    | Integer                             |
|                      | **Default** | 1                                   |
|                      | **Minimum** | 0                                   |
|                      | **Maximum** | 1                                   |

**Description**: When enabled (1), setting a session variable will "lock" the session to the current hostgroup to ensure consistency for subsequent queries.

### `pgsql-shun_on_failures`

The number of connection failures allowed before a backend server is shunned.

|                      |             |                          |
| -------------------- | ----------- | ------------------------ |
| **System Variable**  | **Name**    | `pgsql-shun_on_failures` |
| **Dynamic**          | **Yes**     |                          |
| **Permitted Values** | **Type**    | Integer                  |
|                      | **Default** | 5                        |
|                      | **Minimum** | 0                        |
|                      | **Maximum** | 10000000                 |

**Description**: If a backend server fails to respond to connection attempts this many times consecutively, it will be temporarily shunned (marked as OFFLINE) to prevent further traffic from being sent to it. During the shun period, new connections are automatically directed to other healthy backends in the same hostgroup. The server will be automatically returned to service after `pgsql-shun_recovery_time_sec` seconds.

### `pgsql-shun_recovery_time_sec`

The duration in seconds a backend server remains shunned.

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | `pgsql-shun_recovery_time_sec` |
| **Dynamic**          | **Yes**     |                                |
| **Permitted Values** | **Type**    | Integer                        |
|                      | **Default** | 10                             |
|                      | **Minimum** | 0                              |
|                      | **Maximum** | 31536000                       |

**Description**: The time in seconds that a backend server will remain in the shunned state before ProxySQL attempts to use it again. After this time elapses, the server is automatically returned to ONLINE status and new connections will be directed to it again. Existing connections to the server are allowed to complete naturally during the shun period.

### `pgsql-stats_time_backend_query`

**Description**: Not supported.

### `pgsql-stats_time_query_processor`

**Description**: Not supported.

### `pgsql-tcp_keepalive_time`

Sets the TCP keepalive idle time for PostgreSQL client connections.

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | `pgsql-tcp_keepalive_time` |
| **Dynamic**          | **Yes**     |                            |
| **Permitted Values** | **Type**    | Integer (seconds)          |
|                      | **Default** | 120                        |
|                      | **Minimum** | 0                          |
|                      | **Maximum** | 7200                       |

**Description**: Defines the time (in seconds) the connection must be idle before TCP starts sending keepalive probes.

### `pgsql-threshold_query_length`

**Description**: Not supported.

### `pgsql-threshold_resultset_size`

Threshold in bytes for PostgreSQL resultset buffering.

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | `pgsql-threshold_resultset_size` |
| **Dynamic**          | **Yes**     |                                  |
| **Permitted Values** | **Type**    | Integer (bytes)                  |
|                      | **Default** | 4194304                          |
|                      | **Minimum** | 0                                |
|                      | **Maximum** | 2147483647                       |

**Description**: Determines the maximum amount of data (in bytes) that ProxySQL will buffer for a single PostgreSQL resultset before it begins streaming results to the client.

### `pgsql-throttle_connections_per_sec_to_hostgroup`

Limits the number of new backend connections per second per hostgroup.

|                      |             |                                               |
| -------------------- | ----------- | --------------------------------------------- |
| **System Variable**  | **Name**    | `pgsql-throttle_connections_per_sec_to_hostgroup` |
| **Dynamic**          | **Yes**     |                                               |
| **Permitted Values** | **Type**    | Integer                                       |
|                      | **Default** | 1000000                                       |
|                      | **Minimum** | 1                                             |
|                      | **Maximum** | 100000000                                     |

**Description**: Controls the rate at which ProxySQL opens new connections to PostgreSQL backends in a specific hostgroup to prevent connection storms.

### `pgsql-throttle_max_bytes_per_second_to_client`

Maximum network bandwidth per second for a client connection.

|                      |             |                                               |
| -------------------- | ----------- | --------------------------------------------- |
| **System Variable**  | **Name**    | `pgsql-throttle_max_bytes_per_second_to_client` |
| **Dynamic**          | **Yes**     |                                               |
| **Permitted Values** | **Type**    | Integer (bytes/sec)                           |
|                      | **Default** | 0                                             |
|                      | **Minimum** | 0                                             |
|                      | **Maximum** | 2147483647                                    |

**Description**: Limits the outgoing traffic rate (bytes per second) from ProxySQL to each PostgreSQL client. A value of `0` disables throttling.

### `pgsql-throttle_ratio_server_to_client`

Ratio for network bandwidth throttling between backend and client.

|                      |             |                                      |
| -------------------- | ----------- | ------------------------------------ |
| **System Variable**  | **Name**    | `pgsql-throttle_ratio_server_to_client` |
| **Dynamic**          | **Yes**     |                                      |
| **Permitted Values** | **Type**    | Integer                              |
|                      | **Default** | 0                                    |
|                      | **Minimum** | 0                                    |
| **Maximum**          | **100**     |                                      |

**Description**: Defines the bandwidth allocation ratio between backend connections and client connections when throttling is active.

### `pgsql-unshun_algorithm`

Defines the algorithm used to decide when a shunned server should be moved back ONLINE.

|                      |             |                          |
| -------------------- | ----------- | ------------------------ |
| **System Variable**  | **Name**    | `pgsql-unshun_algorithm` |
| **Dynamic**          | **Yes**     |                          |
| **Permitted Values** | **Type**    | Integer                  |
|                      | **Default** | 0                        |
|                      | **Minimum** | 0                        |
|                      | **Maximum** | 1                        |

**Description**: Determines the recovery logic for backend servers that were previously shunned due to errors.

### `pgsql-use_tcp_keepalive`

Enables TCP keepalive for PostgreSQL client connections.

|                      |             |                           |
| -------------------- | ----------- | ------------------------- |
| **System Variable**  | **Name**    | `pgsql-use_tcp_keepalive` |
| **Dynamic**          | **Yes**     |                           |
| **Permitted Values** | **Type**    | Boolean                   |
|                      | **Default** | `true`                    |

**Description**: Enables the SO_KEEPALIVE socket option for PostgreSQL frontend connections.

### `pgsql-verbose_query_error`

Provides detailed PostgreSQL error messages to the client.

|                      |             |                             |
| -------------------- | ----------- | --------------------------- |
| **System Variable**  | **Name**    | `pgsql-verbose_query_error` |
| **Dynamic**          | **Yes**     |                             |
| **Permitted Values** | **Type**    | Boolean                     |
|                      | **Default** | `false`                     |

**Description**: When enabled, ProxySQL returns more descriptive error information to PostgreSQL clients when a query fails.

### `pgsql-wait_timeout`

Timeout in milliseconds for idle client connections.

|                      |             |                      |
| -------------------- | ----------- | -------------------- |
| **System Variable**  | **Name**    | `pgsql-wait_timeout` |
| **Dynamic**          | **Yes**     |                      |
| **Permitted Values** | **Type**    | Integer              |
|                      | **Default** | 28800000             |
|                      | **Minimum** | 0                    |
|                      | **Maximum** | 1728000000           |

**Description**: The maximum time (in milliseconds) a PostgreSQL client connection can remain idle before ProxySQL closes it. This limit only applies to connections with no active transaction. Connections with idle transactions are controlled by `pgsql-max_transaction_idle_time` instead.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
