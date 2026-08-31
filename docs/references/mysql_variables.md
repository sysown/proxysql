# MySQL Variables

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## List of MySQL Variables

NOTE: You can click on the variable name to jump to its definition

<!-- remark-ignore-start -->

| Variable Name                                                                                           | Default Value               |
| ------------------------------------------------------------------------------------------------------- | --------------------------- |
| [mysql-add_ldap_user_comment](#mysql-add_ldap_user_comment)                                             |                             |
| [mysql-auditlog_filename](#mysql-auditlog_filename)                                                     |                             |
| [mysql-auditlog_filesize](#mysql-auditlog_filename)                                                     | 100MB                       |
| [mysql-aurora_max_lag_ms_only_read_from_replicas](#mysql-aurora_max_lag_ms_only_read_from_replicas)     | 2                           |
| [mysql-auto_increment_delay_multiplex](#mysql-auto_increment_delay_multiplex)                           | 5                           |
| [mysql-auto_increment_delay_multiplex_timeout_ms](#mysql-auto_increment_delay_multiplex_timeout_ms)     | 10000                       |
| [mysql-autocommit_false_is_transaction](#mysql-autocommit_false_is_transaction)                         | false                       |
| [mysql-autocommit_false_not_reusable](#mysql-autocommit_false_not_reusable)                             | false                       |
| [mysql-automatic_detect_sqli](#mysql-automatic_detect_sqli)                                             | false                       |
| [mysql-binlog_reader_connect_retry_msec](#mysql-binlog_reader_connect_retry_msec)                       | 3000                        |
| [mysql-client_host_cache_size](#mysql-client_host_cache_size)                                           | 0                           |
| [mysql-client_host_error_counts](#mysql-client_host_error_counts)                                       | 0                           |
| [mysql-client_found_rows](#mysql-client_found_rows)                                                     | true                        |
| [mysql-client_multi_statements](#mysql-client_multi_statements)                                         | true                        |
| [mysql-client_session_track_gtid](#mysql-client_session_track_gtid)                                     | true                        |
| [mysql-commands_stats](#mysql-commands_stats)                                                           | true                        |
| [mysql-connect_retries_delay](#mysql-connect_retries_delay)                                             | 1                           |
| [mysql-connect_retries_on_failure](#mysql-connect_retries_on_failure)                                   | 10                          |
| [mysql-connect_timeout_client](#mysql-connect_timeout_client)                                           | 10000                       |
| [mysql-connect_timeout_server](#mysql-connect_timeout_server)                                           | 3000                        |
| [mysql-connect_timeout_server_max](#mysql-connect_timeout_server_max)                                   | 10000                       |
| [mysql-connection_delay_multiplex_ms](#mysql-connection_delay_multiplex_ms)                             | 0                           |
| [mysql-connection_max_age_ms](#mysql-connection_max_age_ms)                                             | 0                           |
| [mysql-connection_warming](#mysql-connection_warming)                                                   | false                       |
| [mysql-connpoll_reset_queue_length](#mysql-connpoll_reset_queue_length)                                 | 50                          |
| [mysql-protocol_compression_level](#mysql-protocol_compression_level)                                   | 3                           |
| [mysql-default_authentication_plugin](#mysql-default_authentication_plugin)                             | mysql_native_password       |
| [mysql-default_character_set_results](#mysql-default_character_set_results)                             | NULL                        |
| [mysql-default_charset](#mysql-default_charset)                                                         | utf8                        |
| [mysql-default_collation_connection](#mysql-default_collation_connection)                               |                             |
| [mysql-default_isolation_level](#mysql-default_isolation_level)                                         | READ COMMITTED              |
| [mysql-default_max_join_size](#mysql-default_max_join_size)                                             | 18446744073709551615        |
| [mysql-default_max_latency_ms](#mysql-default_max_latency_ms)                                           | 1000                        |
| [mysql-default_net_write_timeout](#mysql-default_net_write_timeout)                                     | 60                          |
| [mysql-default_query_delay](#mysql-default_query_delay)                                                 | 0                           |
| [mysql-default_query_timeout](#mysql-default_query_timeout)                                             | 86400000                    |
| [mysql-default_reconnect](#mysql-default_reconnect)                                                     | true                        |
| [mysql-default_schema](#mysql-default_schema)                                                           | information_schema          |
| [mysql-default_session_track_gtids](#mysql-default_session_track_gtids)                                 | OFF                         |
| [mysql-ignore_min_gtid_annotations](#mysql-ignore_min_gtid_annotations)                                 | false                       |
| [mysql-default_sql_auto_is_null](#mysql-default_sql_auto_is_null)                                       | OFF                         |
| [mysql-default_sql_mode](#mysql-default_sql_mode)                                                       |                             |
| [mysql-default_sql_safe_updates](#mysql-default_sql_safe_updates)                                       | OFF                         |
| [mysql-default_sql_select_limit](#mysql-default_sql_select_limit)                                       | DEFAULT                     |
| [mysql-default_time_zone](#mysql-default_time_zone)                                                     | SYSTEM                      |
| [mysql-default_transaction_read](#mysql-default_transaction_read)                                       | WRITE                       |
| [mysql-default_tx_isolation](#mysql-default_tx_isolation)                                               | READ-COMMITTED              |
| [mysql-enable_client_deprecate_eof](#mysql-enable_client_deprecate_eof)                                 | true                        |
| [mysql-enable_load_data_local_infile](#mysql-enable_load_data_local_infile)                             | false                       |
| [mysql-enable_server_deprecate_eof](#mysql-enable_server_deprecate_eof)                                 | true                        |
| [mysql-enforce_autocommit_on_reads](#mysql-enforce_autocommit_on_reads)                                 | false                       |
| [mysql-evaluate_replication_lag_on_servers_load](#evaluate_replication_lag_on_servers_load)             | 1                           |
| [mysql-eventslog_default_log](#mysql-eventslog_default_log)                                             | 0                           |
| [mysql-eventslog_filename](#mysql-eventslog_filename)                                                   |                             |
| [mysql-eventslog_filesize](#mysql-eventslog_filesize)                                                   | 104857600                   |
| [mysql-eventslog_format](#mysql-eventslog_format)                                                       | 1                           |
| [mysql-eventslog_stmt_parameters](#mysql-eventslog_stmt_parameters)                                     | 0                           |
| [mysql-firewall_whitelist_enabled](#mysql-firewall_whitelist_enabled)                                   | false                       |
| [mysql-firewall_whitelist_errormsg](#mysql-firewall_whitelist_errormsg)                                 | Firewall blocked this query |
| [mysql-forward_autocommit](#mysql-forward_autocommit)                                                   | false                       |
| [mysql-free_connections_pct](#mysql-free_connections_pct)                                               | 10                          |
| [mysql-handle_unknown_charset](#mysql-handle_unknown_charset)                                           | 1                           |
| [mysql-handle_warnings](#mysql-handle_warnings)                                                         | 1                           |
| [mysql-have_compress](#mysql-have_compress)                                                             | true                        |
| [mysql-have_ssl](#mysql-have_ssl)                                                                       | true (since v2.6.0)         |
| [mysql-hostgroup_manager_verbose](#mysql-hostgroup_manager_verbose)                                     | 1                           |
| [mysql-init_connect](#mysql-init_connect)                                                               |                             |
| [mysql-interfaces](#mysql-interfaces)                                                                   | 0.0.0.0:6033                |
| [mysql-keep_multiplexing_variables](#mysql-keep_multiplexing_variables)                                 | tx_isolation,version        |
| [mysql-kill_backend_connection_when_disconnect](#mysql-kill_backend_connection_when_disconnect)         | true                        |
| [mysql-ldap_user_variable](#mysql-ldap_user_variable)                                                   |                             |
| [mysql-log_mysql_warnings_enabled](#mysql-log_mysql_warnings_enabled)                                   | false                       |
| [mysql-log_unhealthy_connections](#mysql-log_unhealthy_connections)                                     | true                        |
| [mysql-long_query_time](#mysql-long_query_time)                                                         | 1000                        |
| [mysql-max_allowed_packet](#mysql-max_allowed_packet)                                                   | 4194304                     |
| [mysql-max_connections](#mysql-max_connections)                                                         | 2048                        |
| [mysql-max_stmts_cache](#mysql-max_stmts_cache)                                                         | 10000                       |
| [mysql-max_stmts_per_connection](#mysql-max_stmts_per_connection)                                       | 20                          |
| [mysql-max_transaction_idle_time](#mysql-max_transaction_idle_time)                                     | 14400000                    |
| [mysql-max_transaction_time](#mysql-max_transaction_time)                                               | 14400000                    |
| [mysql-min_num_servers_lantency_awareness](#mysql-min_num_servers_lantency_awareness)                   | 1000                        |
| [mysql-monitor_aws_rds_topology_discovery_interval](#mysql-monitor_aws_rds_topology_discovery_interval) | 0                           |
| [mysql-proxy_protocol_networks](#mysql-proxy_protocol_networks)                                         | ''                          |
| [mysql-mirror_max_concurrency](#mysql-mirror_max_concurrency)                                           | 16                          |
| [mysql-mirror_max_queue_length](#mysql-mirror_max_queue_length)                                         | 32000                       |
| [mysql-multiplexing](#mysql-multiplexing)                                                               | true                        |
| [mysql-ping_interval_server_msec](#mysql-ping_interval_server_msec)                                     | 120000                      |
| [mysql-ping_timeout_server](#mysql-ping_timeout_server)                                                 | 500                         |
| [mysql-poll_timeout](#mysql-poll_timeout)                                                               | 2000                        |
| [mysql-poll_timeout_on_failure](#mysql-poll_timeout_on_failure)                                         | 100                         |
| [mysql-query_cache_handle_warnings](#mysql-query_cache_handle_warnings)                                 | 0                           |
| [mysql-query_cache_size_MB](#mysql-query_cache_size_MB)                                                 | 256                         |
| [mysql-query_cache_soft_ttl_pct](#mysql-query_cache_soft_ttl_pct)                                       | 0                           |
| [mysql-query_cache_stores_empty_result](#mysql-query_cache_stores_empty_result)                         | true                        |
| [mysql-query_digests](#mysql-query_digests)                                                             | true                        |
| [mysql-query_digests_grouping_limit](#mysql-query_digests_grouping_limit)                               | 3                           |
| [mysql-query_digests_groups_grouping_limit](#mysql-query_digests_groups_grouping_limit)                 | 0                           |
| [mysql-query_digests_keep_comment](#mysql-query_digests_keep_comment)                                   | false                       |
| [mysql-query_digests_lowercase](#mysql-query_digests_lowercase)                                         | false                       |
| [mysql-query_digests_max_digest_length](#mysql-query_digests_max_digest_length)                         | 2048                        |
| [mysql-query_digests_max_query_length](#mysql-query_digests_max_query_length)                           | 65000                       |
| [mysql-query_digests_no_digits](#mysql-query_digests_no_digits)                                         | false                       |
| [mysql-query_digests_normalize_digest_text](#mysql-query_digests_normalize_digest_text)                 | false                       |
| [mysql-query_digests_replace_null](#mysql-query_digests_replace_null)                                   | false                       |
| [mysql-query_digests_track_hostname](#mysql-query_digests_track_hostname)                               | false                       |
| [mysql-query_processor_iterations](#mysql-query_processor_iterations)                                   | 0                           |
| [mysql-query_processor_regex](#mysql-query_processor_regex)                                             | 1                           |
| [mysql-data_packets_history_size](#mysql-data_packets_history_size)                                     | 0                           |
| [mysql-parse_failure_logs_digest](#mysql-parse_failure_logs_digest)                                     | false                       |
| [mysql-processlist_max_query_length](#mysql-processlist_max_query_length)                               | 2097152                     |
| [mysql-query_rules_fast_routing_algorithm](#mysql-query_rules_fast_routing_algorithm)                   | 1                           |
| [mysql-query_retries_on_failure](#mysql-query_retries_on_failure)                                       | 1                           |
| [mysql-reset_connection_algorithm](#mysql-reset_connection_algorithm)                                   | 2                           |
| [mysql-server_capabilities](#mysql-server_capabilities)                                                 | 569867                      |
| [mysql-server_version](#mysql-server_version)                                                           | 5.5.30                      |
| [mysql-servers_stats](#mysql-servers_stats)                                                             | true                        |
| [mysql-session_idle_ms](#mysql-session_idle_ms)                                                         | 1                           |
| [mysql-session_idle_show_processlist](#mysql-session_idle_show_processlist)                             | true                        |
| [mysql-sessions_sort](#mysql-sessions_sort)                                                             | true                        |
| [mysql-set_parser_algorithm](#mysql-set_parser_algorithm)                                               | 2                           |
| [mysql-set_query_lock_on_hostgroup](#mysql-set_query_lock_on_hostgroup)                                 | 1                           |
| [mysql-show_processlist_extended](#mysql-show_processlist_extended)                                     | 0                           |
| [mysql-shun_on_failures](#mysql-shun_on_failures)                                                       | 5                           |
| [mysql-shun_recovery_time_sec](#mysql-shun_recovery_time_sec)                                           | 10                          |
| [mysql-ssl_p2s_ca](#mysql-ssl_p2s_ca)                                                                   |                             |
| [mysql-ssl_p2s_capath](#mysql-ssl_p2s_capath)                                                           |                             |
| [mysql-ssl_p2s_cert](#mysql-ssl_p2s_cert)                                                               |                             |
| [mysql-ssl_p2s_cipher](#mysql-ssl_p2s_cipher)                                                           |                             |
| [mysql-ssl_p2s_key](#mysql-ssl_p2s_key)                                                                 |                             |
| [mysql-ssl_p2s_crl](#mysql-ssl_p2s_crl)                                                                 |                             |
| [mysql-ssl_p2s_crlpath](#mysql-ssl_p2s_crlpath)                                                         |                             |
| [mysql-stacksize](#mysql-stacksize)                                                                     | 1048576                     |
| [mysql-stats_time_backend_query](#mysql-stats_time_backend_query)                                       | false                       |
| [mysql-stats_time_query_processor](#mysql-stats_time_query_processor)                                   | false                       |
| [mysql-tcp_keepalive_time](#mysql-tcp_keepalive_time)                                                   | 0                           |
| [mysql-fast_forward_grace_close_ms](#mysql-fast_forward_grace_close_ms)                                 | 5000                        |
| [mysql-threads](#mysql-threads)                                                                         | 4                           |
| [mysql-threshold_query_length](#mysql-threshold_query_length)                                           | 524288                      |
| [mysql-threshold_resultset_size](#mysql-threshold_resultset_size)                                       | 4194304                     |
| [mysql-throttle_connections_per_sec_to_hostgroup](#mysql-throttle_connections_per_sec_to_hostgroup)     | 1000000                     |
| [mysql-throttle_max_bytes_per_second_to_client](#mysql-throttle_max_bytes_per_second_to_client)         | 0                           |
| [mysql-throttle_ratio_server_to_client](#mysql-throttle_ratio_server_to_client)                         | 0                           |
| [mysql-unshun_algorithm](#mysql-unshun_algorithm)                                                       | 0                           |
| [mysql-use_tcp_keepalive](#mysql-use_tcp_keepalive)                                                     | false                       |
| [mysql-verbose_query_error](#mysql-verbose_query_error)                                                 | false                       |

<!-- remark-ignore-end -->

### `mysql-add_ldap_user_comment`

|                      |                  |                             |
| -------------------- | ---------------- | --------------------------- |
| **MySQL Variable**   | **Name**         | mysql-add_ldap_user_comment |
|                      | **Dynamic**      | Yes                         |
| **Permitted Values** | **Type**         | String                      |
|                      | **Default**      | NULL                        |
|                      | **Valid values** |                             |

If mysql-add_ldap_user_comment is set, a comment like the following will be added on the query:

```
valueof_mysql-add_ldap_user_comment=frontend_username
```

### `mysql-ldap_user_variable`

|                      |                  |                          |
| -------------------- | ---------------- | ------------------------ |
| **MySQL Variable**   | **Name**         | mysql-ldap_user_variable |
|                      | **Dynamic**      | Yes                      |
| **Permitted Values** | **Type**         | String                   |
|                      | **Default**      | NULL                     |
|                      | **Valid values** |                          |

When set, sessions will have a variable set with the user_name value, ie:
`SET @mysql-ldap_user_variable:='username'` The use of this variable can be for auditing purposed backend
side. For example, if a trigger on a table will use that session variable.

### `mysql-auditlog_filename`

|                      |                  |                         |
| -------------------- | ---------------- | ----------------------- |
| **MySQL Variable**   | **Name**         | mysql-auditlog_filename |
|                      | **Dynamic**      | Yes                     |
| **Permitted Values** | **Type**         | String                  |
|                      | **Default**      | NULL                    |
|                      | **Valid values** |                         |

Setting this variable automatically enables [Audit Log][3] . This variable defines the base name of the audit
log where audit events are logged. The filename of the log file will be the base name followed by an 8 digits
progressive number. Files are automatically rotated based on the value of [mysql-auditlog_filesize][4] .

### `mysql-auditlog_filesize`

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | mysql-auditlog_filesize |
|                      | **Dynamic** | Yes                     |
| **Permitted Values** | **Type**    | Integer (count)         |
|                      | **Default** | 104857600               |
|                      | **Minimum** | 1MB                     |
|                      | **Maximum** | 1GB                     |

This variable defines the maximum file size of the audit log file (see [mysql-auditlog_filename][5]) when the
current file will be closed and a new file will be created. The default value is 104857600 (100MB)

### `mysql-aurora_max_lag_ms_only_read_from_replicas`

|                      |             |                                                 |
| -------------------- | ----------- | ----------------------------------------------- |
| **System Variable**  | **Name**    | mysql-aurora_max_lag_ms_only_read_from_replicas |
|                      | **Dynamic** | Yes                                             |
| **Permitted Values** | **Type**    | Integer (count)                                 |
|                      | **Default** | 2                                               |
|                      | **Minimum** | 0                                               |
|                      | **Maximum** |                                                 |

If `max_lag_ms` is used for the query, send traffic only to replicas if at least N replicas are good
candidates.

### `mysql-auto_increment_delay_multiplex`

|                      |             |                                      |
| -------------------- | ----------- | ------------------------------------ |
| **System Variable**  | **Name**    | mysql-auto_increment_delay_multiplex |
|                      | **Dynamic** | Yes                                  |
| **Permitted Values** | **Type**    | Integer (count)                      |
|                      | **Default** | 5                                    |
|                      | **Minimum** | 0                                    |
|                      | **Maximum** | 1000000                              |

Several applications rely, explicitly or implicitly, on the value returned by `LAST_INSERT_ID()`. If
multiplexing is not configured correctly, or if the queries pattern is really unpredictable (for example if
new queries are often deployed), it is possible that the query using `LAST_INSERT_ID()` uses a connection
different than the connection where an auto-increment was used. If `mysql-auto_increment_delay_multiplex` is
set, after an OK packet with `last_insert_id` is received, multiplexing is temporarily disabled for the same
number of queries as specified in `mysql-auto_increment_delay_multiplex`. Note that disabling multiplexing
doesn't disable routing, so it is important to configure read/write split correctly. Furthermore, please note
that ProxySQL is able to handle these queries correctly even if `mysql-auto_increment_delay_multiplex` is set
to 0:

-   `SELECT LAST_INSERT_ID()`
-   `SELECT LAST_INSERT_ID() LIMIT 1`
-   `SELECT @@IDENTITY`

<!-- -->

Therefore you should configure `mysql-auto_increment_delay_multiplex` greater than 0 only if your application
relies on `LAST_INSERT_ID()` in some way other than the queries listed above. As the name suggests,
`mysql-auto_increment_delay_multiplex` disables [multiplexing][6]: one of the most important and advanced
feature of ProxySQL. If your application doesn't use `LAST_INSERT_ID()` it is recommended to lower
`mysql-auto_increment_delay_multiplex` to 0.

### `mysql-auto_increment_delay_multiplex_timeout_ms`

Introduced in v2.4.0. Specifies the timeout in milliseconds after which
[mysql-auto_increment_delay_multiplex][7] gets invalidated (i.e. set back to '0'), thus re-enabling
multiplexing.

|                      |             |                                                 |
| -------------------- | ----------- | ----------------------------------------------- |
| **System Variable**  | **Name**    | mysql-auto_increment_delay_multiplex_timeout_ms |
|                      | **Dynamic** | Yes                                             |
| **Permitted Values** | **Type**    | Integer (milliseconds)                          |
|                      | **Default** | 10000                                           |
|                      | **Minimum** | 0                                               |
|                      | **Maximum** | 3600000 (1 hour)                                |

### `mysql-autocommit_false_is_transaction`

|                      |             |                                       |
| -------------------- | ----------- | ------------------------------------- |
| **System Variable**  | **Name**    | mysql-autocommit_false_is_transaction |
|                      | **Dynamic** | Yes                                   |
| **Permitted Values** | **Type**    | Boolean                               |
|                      | **Default** | false                                 |

If `mysql-autocommit_false_is_transaction=true` (false by default), a connection with `autocommit=0` is
treated as a transaction and it is not returned to the connection pool. That is, `autocommit=0` disables
multiplexing. Please note that `autocommit=0` isn't enough to start a transaction: at the database level, a
transaction is started when a query is executed against a transactional table. It is recommended to not change
this variable.

### `mysql-autocommit_false_not_reusable`

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | mysql-autocommit_false_not_reusable |
|                      | **Dynamic** | Yes                                 |
| **Permitted Values** | **Type**    | Boolean                             |
|                      | **Default** | false                               |

When set to `true`, a connection with `autocommit=0` is not re-used and is destroyed when the connection is
returned to the connection pool. It is recommended to not change this variable.

### `mysql-automatic_detect_sqli`

|                      |             |                             |
| -------------------- | ----------- | --------------------------- |
| **System Variable**  | **Name**    | mysql-automatic_detect_sqli |
|                      | **Dynamic** | Yes                         |
| **Permitted Values** | **Type**    | Boolean                     |
|                      | **Default** | false                       |

When set to `true`, automatic detection of SQL injection is enabled. For further reference, please also see
[SQL Injection Engine][8].

### `mysql-binlog_reader_connect_retry_msec`

Controls the connect retry timeout for the binlog reader (introduced in ProxySQL 2.0).

|                      |             |                                        |
| -------------------- | ----------- | -------------------------------------- |
| **System Variable**  | **Name**    | mysql-binlog_reader_connect_retry_msec |
|                      | **Dynamic** | Yes                                    |
| **Permitted Values** | **Type**    | Integer (milliseconds)                 |
|                      | **Default** | 3000                                   |
|                      | **Minimum** | 200                                    |
|                      | **Maximum** | 120000                                 |

### `mysql-client_found_rows`

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | mysql-client_found_rows |
|                      | **Dynamic** | Yes                     |
| **Permitted Values** | **Type**    | Boolean                 |
|                      | **Default** | true                    |

This variable is deprecated since 2.0.6 . For older versions: when set to `true`, client flag
`CLIENT_FOUND_ROWS` is set when connecting to MySQL backends. Since ProxySQL version 2.0.6 , ProxySQL matches
flag `CLIENT_FOUND_ROWS` in frontend and backend connections.

### `mysql-client_host_cache_size`

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | mysql-client_host_cache_size |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer                      |
|                      | **Default** | 0                            |
|                      | **Minimum** | 0                            |
|                      | **Maximum** | 1048576                      |

In combination with [mysql-client_host_error_counts][9] offers control over Client Error Limit feature. This
variable specifies the maximum size of the cache to be used for storing client addresses which have previously
performed invalid connections attempts.

### `mysql-client_host_error_counts`

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | mysql-client_host_error_counts |
|                      | **Dynamic** | Yes                            |
| **Permitted Values** | **Type**    | Integer                        |
|                      | **Default** | 0                              |
|                      | **Minimum** | 0                              |
|                      | **Maximum** | 1048576                        |

In combination with [mysql-client_host_cache_size][10] offers control over 'Client Error Limit' feature. This
variable specifies the maximum number of consecutive unsuccessful connections attempts that can be performed
from a particular address before any further connections attempts are dropped.

### `mysql-client_multi_statements`

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | mysql-client_multi_statements |
|                      | **Dynamic** | Yes                           |
| **Permitted Values** | **Type**    | Boolean                       |
|                      | **Default** | true                          |

This variable is deprecated since 2.0.6 . For older versions: when set to `true`, client flag
`CLIENT_MULTI_STATEMENTS` is set when connecting to MySQL backends. Since ProxySQL version 2.0.6 , ProxySQL
matches flag `CLIENT_MULTI_STATEMENTS` in frontend and backend connections.

### `mysql-client_session_track_gtid`

When activated ProxySQL will keep track of the GTID status on the backend serves in the
stats_mysql_gtid_executed table.

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-client_session_track_gtid |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Boolean                         |
|                      | **Default** | true                            |

### `mysql-commands_stats`

|                      |             |                      |
| -------------------- | ----------- | -------------------- |
| **System Variable**  | **Name**    | mysql-commands_stats |
|                      | **Dynamic** | Yes                  |
| **Permitted Values** | **Type**    | Boolean              |
|                      | **Default** | true                 |

Enable per-command MySQL query statistics. A command is a type of SQL query that is being executed. Some
examples are: `SELECT<code>, </code>INSERT` or `ALTER TABLE`. All the statistics can be retrieved querying
table [stats_mysql_commands_counters][11]. Disabling this variable also disables the population of table
`stats_mysql_query_digest`.

### `mysql-connect_retries_delay`

|                      |             |                             |
| -------------------- | ----------- | --------------------------- |
| **System Variable**  | **Name**    | mysql-connect_retries_delay |
|                      | **Dynamic** | Yes                         |
| **Permitted Values** | **Type**    | Integer (milliseconds)      |
|                      | **Default** | 1                           |
|                      | **Minimum** | 0                           |
|                      | **Maximum** | 10000                       |

The delay (in milliseconds) before trying to reconnect after a failed attempt to a backend MySQL server.
Failed attempts can take place due to numerous reasons: too busy backend, timed out for the current attempt,
etc. Connections will be retried for [mysql-connect_retries_on_failure][12] times.

### `mysql-connect_retries_on_failure`

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | mysql-connect_retries_on_failure |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Integer                          |
|                      | **Default** | 10                               |
|                      | **Minimum** | 0                                |
|                      | **Maximum** | 1000                             |

The number of times for which a reconnect should be attempted in case of an error, timeout, or any other event
that led to an unsuccessful connection to a backend MySQL server. After the number of attempts is depleted, if
a connection still couldn't be established, an error is returned. The error returned is either the last
connection attempt error or a generic error ("Max connect failure while reaching hostgroup" with error code
28000\). See also [mysql-connect_retries_delay][13]. Be careful about tweaking this parameter - a value that
is too high can significantly increase the latency with which an unresponsive hostgroup is reported to the
MySQL client.

### `mysql-connect_timeout_client`

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | mysql-connect_timeout_client |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer (milliseconds)       |
|                      | **Default** | 10000                        |
|                      | **Minimum** |                              |
|                      | **Maximum** |                              |

Maximum time to wait for a client connection to be established before closing it.

### `mysql-connect_timeout_server`

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | mysql-connect_timeout_server |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer (milliseconds)       |
|                      | **Default** | 1000                         |
|                      | **Minimum** | 10                           |
|                      | **Maximum** | 120000                       |

The timeout for a single attempt at connecting to a backend server from proxysql. If this fails, proxysql will
try to reconnect according to parameters [mysql-connect_retries_on_failure][12] and
[mysql-connect_retries_delay][13] . If none of the server in the destination hostgroup is reachable after
[mysql-connect_timeout_server_max][14] milliseconds, an error is returned to the client. See
[mysql-connect_timeout_server_max][14] for further details. We believe that the default value of 1000
milliseconds is already a big value: if proxysql and a backend aren't able to fully establish a connection
after 1000 milliseconds, there is either a network issue or the backend is overloaded and unable to quickly
create a connection. Therefore if a connection isn't established quickly it is a warning signal. Nonetheless,
some users prefer to increase `mysql-connect_timeout_server` a bit higher, allowing connections to be
established to a generally slow backend.

### `mysql-connect_timeout_server_max`

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | mysql-connect_timeout_server_max |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Integer (milliseconds)           |
|                      | **Default** | 10000                            |
|                      | **Minimum** | 10                               |
|                      | **Maximum** | 3600000                          |

The maximum timeout for connecting from ProxySQL to a backend in a hostgroup. When ProxySQL tried to establish
a connection to a backend, the attempts can timeout after [mysql-connect_timeout_server][15] milliseconds and
ProxySQL will retry to establish a new connection (against the same backend or another backend in the same
hostgroup) according to parameters [mysql-connect_retries_on_failure][12] and
[mysql-connect_retries_delay][13] . Connection attempts are not retried anymore when a final timeout of
[mysql-connect_timeout_server_max][14] milliseconds is reached, and an error is returned to the client with
code 9001 and the message "Max connect timeout reached while reaching hostgroup...". See also
[mysql-shun_recovery_time_sec][16] Due to a bug fixed in version 2.0.7, for all previous releases it is
recommended to not set this value higher than 10 minutes.

### `mysql-connection_delay_multiplex_ms`

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | mysql-connection_delay_multiplex_ms |
|                      | **Dynamic** | Yes                                 |
| **Permitted Values** | **Type**    | Integer (milliseconds)              |
|                      | **Default** | 0                                   |
|                      | **Minimum** | 0                                   |
|                      | **Maximum** | 300000                              |

After executing a query on a backend connection, if ProxySQL determines that the same backend connection can
be safely assigned to another client ([multiplexing][17] is enabled, or in other words there is no need to
keep the backend connection linked to a specific frontend connection), the backend connection is immediately
returned to the connection pool. Variable [mysql-connection_delay_multiplex_ms][18] modifies this behavior,
and instead of return the backend connection immediately to the connection pool, it will keep multiplexing
disabled for a short period of time on a connection. This will allow a frontend connection to re-use the same
backend connection for successive queries (e.g. when batching queries). The delay is measured for the time
there is no activity on the connection. Please note that this variable temporary disable only multiplexing:
query routing it is not affected by it. This is important because if the application run a query that is
destinated to a different target hostgroup, it will not use the same backend connection.

### `mysql-connection_max_age_ms`

|                      |             |                             |
| -------------------- | ----------- | --------------------------- |
| **System Variable**  | **Name**    | mysql-connection_max_age_ms |
|                      | **Dynamic** | Yes                         |
| **Permitted Values** | **Type**    | Integer (milliseconds)      |
|                      | **Default** | 0                           |
|                      | **Minimum** | 0                           |
|                      | **Maximum** | 86400000                    |

When `mysql-connection_max_age_ms` is set to a value greater than 0, inactive connections in the connection
pool (therefore not currently used by any session) are closed if they were created more than
`mysql-connection_max_age_ms` milliseconds ago. By default, connections aren't closed based on their age. When
`mysql-connection_max_age_ms` is reached, connections are simply disconnected, without sending `COM_QUIT`
command to the server, so this might result in `Aborted connection` warnings showing up in your MySQL server
logs (this behaviour is intended, see [GH #1861][19]).

### `mysql-connection_warming`

|                      |             |                          |
| -------------------- | ----------- | ------------------------ |
| **System Variable**  | **Name**    | mysql-connection_warming |
|                      | **Dynamic** | Yes                      |
| **Permitted Values** | **Type**    | Boolean                  |
|                      | **Default** | false                    |

<div>When enabled, ProxySQL will keep opening new connections for all servers in all hostgroups, until the expected number of warm connections is reached. This number can be computed as: <code><a href="#mysql-free_connections_pct">mysql-free_connections_pct</a> * mysql_servers.max_connections / 100</code></div>

### `mysql-connpoll_reset_queue_length`

PoxySQL 1.4.0 introduced a background thread (`HGCU_thread_run()`) responsible for resetting connections
instead of dropping them when `MySQL_HostGroups_Manager::destroy_MyConn_from_pool()` is called. There could be
cases in which this behavior is not beneficial. In ProxySQL 1.4.4 `mysql-connpoll_reset_queue_length` allows
this behavior to be configurable by destroying the connection when the defined threshold is reached.

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | mysql-connpoll_reset_queue_length |
|                      | **Dynamic** | Yes                               |
| **Permitted Values** | **Type**    | Integer                           |
|                      | **Default** | 50                                |
|                      | **Minimum** | 0                                 |
|                      | **Maximum** | 1000                              |

### `mysql-protocol_compression_level`

Introduced in `2.7.2`. Specifies the compression level to be used for fronted connections with compression.
When changing this value, it should be taken into account that higher compression levels translate into higher
CPU usage, and that finding the right balance is up to the user and specific use case. The special value `-1`
sets the default internal value used by the library (`zlib`).

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | mysql-protocol_compression_level |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Integer                          |
|                      | **Default** | 3                                |
|                      | **Minimum** | -1                               |
|                      | **Maximum** | 9                                |

### `mysql-default_authentication_plugin`

|                      |                  |                                                                                 |
| -------------------- | ---------------- | ------------------------------------------------------------------------------- |
| **System Variable**  | **Name**         | mysql-default_authentication_plugin                                             |
|                      | **Dynamic**      | Yes                                                                             |
| **Permitted Values** | **Type**         | String                                                                          |
|                      | **Default**      | mysql_native_password                                                           |
|                      | **Valid Values** | mysql_clear_password<br/> mysql_native_password<br/> caching_sha2_password<br/> |

Introduced in `2.6.0`, allows selecting the authentication plugin that ProxySQL announces to the client in the
[Initial Handshake Packet][20]. This option **doesn't** disable any of the [authentication methods][21]
supported by ProxySQL, just allows to optimize the client-server communication during handshake by making the
default authentication announced by the server, match the authentication the client is expected to request.
Thus avoiding unnecessary `AuthSwitchRequests`.

This variable overrides [mysql-have_ssl][22], enabling SSL for fronted connections when set to
`caching_sha2_password`. This is because `caching_sha2_password` requires a safe channel for performing [full
authentication][23], due to clear text password sharing. If a user password is stored as a hashed
`caching_sha2_password`, yet no secure channel (SSL connection) is able to be created between client and
ProxySQL, authentication is expected to fail, this is a requirement of `caching_sha2_password` itself.

### `mysql-default_character_set_results`

Deprecated in version 2.0.11.

### `mysql-default_charset`

|                      |                  |                                                                                    |
| -------------------- | ---------------- | ---------------------------------------------------------------------------------- |
| **System Variable**  | **Name**         | mysql-default_charset                                                              |
|                      | **Dynamic**      | Yes                                                                                |
| **Permitted Values** | **Type**         | String                                                                             |
|                      | **Default**      | utf8                                                                               |
|                      | **Valid Values** | Run `select * from mysql_collations;` in the Admin interface to view the full list |

The default server charset to be used in the communication with the MySQL clients. Note that this is the
default for client connections, not for backend connections. To be more specific, during the handshake with a
client, ProxySQL will advertise this as its default charset. Values for [mysql-default_charset][24] and
[mysql-default_collation_connection][25] must be compatible to each other. If they are not, ProxySQL will
configure `mysql-default_charset` using the default charset of collation `mysql-default_collation_connection`.
The default charset for a given collation can be found in table [mysql_collations][26].

### `mysql-default_collation_connection`

|                      |                  |                                                                                    |
| -------------------- | ---------------- | ---------------------------------------------------------------------------------- |
| **System Variable**  | **Name**         | mysql-default_collation_connection                                                 |
|                      | **Dynamic**      | Yes                                                                                |
| **Permitted Values** | **Type**         | String                                                                             |
|                      | **Default**      | NULL                                                                               |
|                      | **Valid Values** | Run `select * from mysql_collations;` in the Admin interface to view the full list |

The default server collation to be used in the communication with the MySQL clients. Note that this is the
default for client connections, not for backend connections. To be more specific, during the handshake with a
client, ProxySQL will advertise this as its default charset. Values for [mysql-default_charset][24] and
[mysql-default_collation_connection][25] must be compatible to each other. If they are not, ProxySQL will
configure `mysql-default_charset` using the charset of collation `mysql-default_collation_connection`.

### `mysql-default_isolation_level`

Deprecated in version 2.0.11.

### `mysql-default_max_join_size`

Deprecated in version 2.0.11.

### `mysql-default_max_latency_ms`

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | mysql-default_max_latency_ms |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer (milliseconds)       |
|                      | **Default** | 1000                         |
|                      | **Minimum** | 0                            |
|                      | **Maximum** | 1728000000                   |

ProxySQL uses a mechanism to automatically ignore backend servers if their latency is excessive. Note that
backend servers are not disabled, but only ignored: in other words, ProxySQL will prefer hosts with a smaller
latency. This feature is useful to provide a basic location awareness in which ProxySQL will prefer servers
that are closer, avoiding sending traffic to servers that are physically far or simply slow. It is possible to
configure the maximum latency for each backend in [mysql_servers][27], column `max_latency_ms`. If
`mysql_servers`.`max_latency_ms` is 0, the default value `mysql-default_max_latency_ms` applies. Note:
establishing a connection using TLS is more time consuming because of extra handshake and authentication
performed by both ProxySQL and the backend, therefore it is recommended to increase
`mysql-default_max_latency_ms` to take into consideration the extra cost of establishing a connection using
TLS.

### `mysql-default_net_write_timeout`

Deprecated in version 2.0.11.

### `mysql-default_query_delay`

|                      |             |                           |
| -------------------- | ----------- | ------------------------- |
| **System Variable**  | **Name**    | mysql-default_query_delay |
|                      | **Dynamic** | Yes                       |
| **Permitted Values** | **Type**    | Integer (milliseconds)    |
|                      | **Default** | 0                         |
|                      | **Minimum** | 0                         |
|                      | **Maximum** | 3600000                   |

This variable allows to create a simple throttling mechanism, delaying the excution of queries to the
backends. Setting this variable to a non-zero value (in miliseconds) will delay the execution of all queries,
globally. There is a more fine-grained throttling mechanism in the admin table [mysql_query_rules][28], where
for each rule there can be one delay that is applied to all queries matching the rule. If a delay is specified
in `mysql_query_rules.delay`, the global value [mysql-default_query_delay][29] is ignored. This variable can
be useful in emergency situation when a user can decide to back-off traffic from backends simply delaying the
execution of every query.

### `mysql-default_query_timeout`

|                      |             |                             |
| -------------------- | ----------- | --------------------------- |
| **System Variable**  | **Name**    | mysql-default_query_timeout |
|                      | **Dynamic** | Yes                         |
| **Permitted Values** | **Type**    | Integer (milliseconds)      |
|                      | **Default** | 86400000                    |
|                      | **Minimum** | 1000                        |
|                      | **Maximum** | 1728000000                  |

ProxySQL is able to track the execution time of every query that has sent to the backend, and is able to
timeout such queries if they run for too long. There are two ways to configure the timeout (maximum execution
time) of a query:

-   configuring a query rule in table [mysql_query_rules][28] , column `timeout`
-   if a query doesn't have a timeout assigned in `mysql_query_rules.timeout`, the global value
    [mysql-default_query_timeout][30] applies

<!-- -->

The default value for `mysql-default_query_timeout` is 86400000 milliseconds, equivalent to 24 hours. When the
timeout is reached, ProxySQL spawn a separate thread that connects to the backend and runs a `KILL` query in
order to stop the query from running in the backend. After that, ProxySQL will return an error to the client.
Please note that when ProxySQL interrupts the execution of a query because of a timeout, the retry mechanism
for queries is automatically disabled and ProxySQL will not retry to execute the killed query.

### `mysql-default_reconnect`

Not used for now.

### `mysql-default_schema`

|                      |                  |                      |
| -------------------- | ---------------- | -------------------- |
| **System Variable**  | **Name**         | mysql-default_schema |
|                      | **Dynamic**      | Yes                  |
| **Permitted Values** | **Type**         | String               |
|                      | **Default**      | information_schema   |
|                      | **Valid Values** | Any existing schema  |

The default schema to be used for incoming MySQL client connections which do not specify a schema name. This
variable is required because ProxySQL doesn't allow connections without a schema. Please note that this is a
important difference compared to connecting directly to a MySQL server: MySQL allows a client to be connected
without a default schema, while ProxySQL doesn't allow that, therefore it needs a default one.

### `mysql-default_session_track_gtids`

Controls whether the server tracks GTIDs within the current session and returns them to the client. Depending
on the variable value, at the end of executing each transaction, the server GTIDs are captured by the tracker.
The GTID value is also returned to the client if required.

|                      |                  |                                                                                                                                          |
| -------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **System Variable**  | **Name**         | mysql-default_session_track_gtids                                                                                                        |
|                      | **Dynamic**      | Yes                                                                                                                                      |
| **Permitted Values** | **Type**         |                                                                                                                                          |
|                      | **Default**      | OFF                                                                                                                                      |
|                      | **Valid Values** | valid only at SESSION scope: Note: ALL_GTIDS is not supported by ProxySQL; attempting to set ALL_GTIDS will set the variable to OWN_GTID |

### `mysql-ignore_min_gtid_annotations`

Controls whether ProxySQL processes or ignores `min_gtid` query annotations in SQL comments. These annotations
are used in MySQL/MariaDB GTID-based replication systems to specify the minimum Global Transaction ID that
should be executed for a query.

For detailed information about query annotations, see [Query Annotations][59].

The `min_gtid` annotation format is: `min_gtid=uuid:transaction_id`

When this variable is set to `true`, ProxySQL will ignore `min_gtid` annotations and allow queries to execute
normally without GTID validation. When set to `false`, ProxySQL will process `min_gtid` annotations, validate
the GTID format, and store the values for session management.

**Algorithm Behavior:**

**When `mysql-ignore_min_gtid_annotations = true` (Ignore):**

-   ProxySQL skips all `min_gtid` annotations found in SQL comments
-   No GTID validation is performed
-   Debug logging shows: "Ignoring min_gtid=value"
-   Queries execute regardless of GTID annotation validity

**When `mysql-ignore_min_gtid_annotations = false` (Process - Default):**

-   ProxySQL processes all `min_gtid` annotations
-   Validates GTID format using `_is_valid_gtid()` function
-   Validates that GTID follows proper format: `uuid:transaction_id`
-   Stores valid GTID values for MySQL session management
-   Logs warnings for invalid GTID values
-   May affect query execution based on GTID consistency

**GTID Validation Requirements:**

-   Minimum 3 characters total
-   Must contain colon separator (`:`)
-   UUID component must be at least 1 character
-   Total length sufficient for complete UUID and transaction ID
-   Must follow MySQL UUID format conventions

**Configuration:**

```sql
-- Enable ignoring min_gtid annotations
SET mysql-ignore_min_gtid_annotations = true;
LOAD MYSQL VARIABLES TO RUNTIME;

-- Disable ignoring min_gtid annotations (process normally)
SET mysql-ignore_min_gtid_annotations = false;
LOAD MYSQL VARIABLES TO RUNTIME;
```

This variable provides fine-grained control over GTID annotation processing, allowing administrators to
balance strict GTID compliance with operational flexibility when dealing with complex GTID annotation
scenarios.

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | mysql-ignore_min_gtid_annotations |
|                      | **Dynamic** | Yes                               |
| **Permitted Values** | **Type**    | Boolean                           |
|                      | **Default** | false                             |

### `mysql-default_sql_auto_is_null`

Deprecated in version 2.0.11. See [`mysql-default_variables`][31] . If this variable is enabled, then after a
statement that successfully inserts an automatically generated AUTO_INCREMENT value, you can find that value
by issuing a statement of the following form: `SELECT * FROM tbl_name WHERE auto_col IS NULL` If the statement
returns a row, the value returned is the same as if you invoked the LAST_INSERT_ID() function. If no
AUTO_INCREMENT value was successfully inserted, the SELECT statement returns no rows.

|                      |                  |                                |
| -------------------- | ---------------- | ------------------------------ |
| **System Variable**  | **Name**         | mysql-default_sql_auto_is_null |
|                      | **Dynamic**      | Yes                            |
| **Permitted Values** | **Type**         | String                         |
|                      | **Default**      | OFF                            |
|                      | **Valid Values** | ON\|OFF                        |

### `mysql-default_sql_mode`

Deprecated in version 2.0.11. See [`mysql-default_variables`][31] When a client requires a different
`sql_mode`, ProxySQL needs to track the change to ensure that the needed `sql_mode` is the same on every
backend connection used by that specific client. When ProxySQL establishes a new connection to a backend it
doesn't know the current `sql_mode`. Although it is possible to query the backend to retrieve `sql_mode` and
other variables, querying the backend has a latency cost. For this reason ProxySQL doesn't query the backend
to know the value of `sql_mode`, and instead it assumes that all the backend connections have by default the
`sql_mode` defined in `mysql-default_sql_mode`. If a client changes `sql_mode` to a value different than
`mysql-default_sql_mode`, ProxySQL will ensure to change `sql_mode` on every connection used by that client.
On the other hand, if a client sets `sql_mode` to the same value specified in `mysql-default_sql_mode`,
ProxySQL won't change the `sql_mode` on the backend connection because it assumes that the `sql_mode` is
already correct. A misconfigured `mysql-default_sql_mode` can lead to unexpected results. For example, if
`mysql-default_sql_mode=''` (the default in ProxySQL, and also the default for MySQL \&lt;= 5.6.5) while the
backend has `sql_mode` different than `''`, if a client executes `set session sql_mode=''` ProxySQL won't
change the `sql_mode` on the backend. This variable needs to be configured as the default `sql_mode` across
all backends. If backends have different `sql_mode` or if you want ProxySQL to always enforce the `sql_mode`
specified by the client, `mysql-default_sql_mode` can be configured using an invalid `sql_mode`. This will
force ProxySQL to always change the `sql_mode` on the backend to whatever value is specified by the client.

|                      |                  |                               |
| -------------------- | ---------------- | ----------------------------- |
| **System Variable**  | **Name**         | mysql-default_sql_mode        |
|                      | **Dynamic**      | Yes                           |
| **Permitted Values** | **Type**         | String                        |
|                      | **Default**      | ''                            |
|                      | **Valid Values** | Any valid or invalid sql_mode |

### `mysql-default_sql_safe_updates`

Deprecated in version 2.0.11. See [`mysql-default_variables`][31] If this variable is enabled, UPDATE and
DELETE statements that do not use a key in the WHERE clause or a LIMIT clause produce an error. This makes it
possible to catch UPDATE and DELETE statements where keys are not used properly and that would probably change
or delete a large number of rows.

|                      |                  |                                |
| -------------------- | ---------------- | ------------------------------ |
| **System Variable**  | **Name**         | mysql-default_sql_safe_updates |
|                      | **Dynamic**      | Yes                            |
| **Permitted Values** | **Type**         | String                         |
|                      | **Default**      | OFF                            |
|                      | **Valid Values** | ON\|OFF                        |

### `mysql-default_sql_select_limit`

Deprecated in version 2.0.11. See [`mysql-default_variables`][31] The maximum number of rows to return from
SELECT statements. The default value for a new connection is the maximum number of rows that the server
permits per table. Typical default values are (232)−1 or (264)−1. If you have changed the limit, the default
value can be restored by assigning a value of DEFAULT. If a SELECT has a LIMIT clause, the LIMIT takes
precedence over the value of sql_select_limit.

|                      |                  |                                                                                                                                                                                                                                                          |
| -------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **System Variable**  | **Name**         | mysql-default_sql_select_limit                                                                                                                                                                                                                           |
|                      | **Dynamic**      | Yes                                                                                                                                                                                                                                                      |
| **Permitted Values** | **Type**         | Integer                                                                                                                                                                                                                                                  |
|                      | **Default**      | DEFAULT                                                                                                                                                                                                                                                  |
|                      | **Valid Values** | The default value for a new connection is the maximum number of rows that the server permits per table. Typical default values are (232)−1 or (264)−1. If you have changed the limit, the default value can be restored by assigning a value of DEFAULT. |

### `mysql-default_time_zone`

Deprecated in version 2.0.11. See [`mysql-default_variables`][31] If a client doesn't specify any time_zone,
the time zone assigned to the client is whatever time zone is currently assigned to `mysql-default_time_zone`.
When a client requires a different `time_zone`, ProxySQL needs to track the change to ensure that the needed
`time_zone` is the same on every backend connection used by that specific client. When ProxySQL establishes a
new connection to a backend it doesn't know the current `time_zone`. Although it is possible to query the
backend to retrieve `time_zone` and other variables, querying the backend has a latency cost. For this reason
ProxySQL doesn't query the backend to know the value of `time_zone`, and instead it assumes that all the
backend connections have by default the `time_zone` defined in `mysql-default_time_zone`. If a client changes
`time_zone` to a value different than `mysql-default_time_zone`, ProxySQL will ensure to change `time_zone` on
every connection used by that client. On the other hand, if a client sets `time_zone` to the same value
specified in `mysql-default_time_zone`, ProxySQL won't change the `time_zone` on the backend connection
because it assumes that the `time_zone` is already correct. A misconfigured `mysql-default_time_zone` can lead
to unexpected results so this variable needs to be configured as the default `time_zone` across all backends.
If backends have different `time_zone` or if you want ProxySQL to always enforce the `time_zone` specified by
the client, `mysql-default_time_zone` can be configured using an invalid `time_zone`. This will force ProxySQL
to always change the `time_zone` on the backend to whatever value is specified by the client.

|                      |                  |                                      |
| -------------------- | ---------------- | ------------------------------------ |
| **System Variable**  | **Name**         | mysql-default_time_zone              |
|                      | **Dynamic**      | Yes                                  |
| **Permitted Values** | **Type**         | String                               |
|                      | **Default**      | SYSTEM                               |
|                      | **Valid Values** | Any valid or invalid MySQL time_zone |

### `mysql-default_transaction_read`

Deprecated in version 2.0.11. See [`mysql-default_variables`][31] ProxySQL tracks the transaction access
modes, READ WRITE or READ ONLY clause. If manually set what is mandatory for ProxySQL is the SESSION scope
definition:

```
- SET SESSION TRANSACTION READ WRITE
- SET SESSION TRANSACTION READ ONLY
```

SET TRANSACTION READ (WRITE|ONLY) is not supported, and it will automatically disable multiplexing. In MySQL
by default, a transaction takes place in read/write mode, with both reads and writes permitted to tables used
in the transaction. This mode may be specified explicitly using `SET **SESSION** TRANSACTION` with an access
mode of READ WRITE.

|                      |                  |                                |
| -------------------- | ---------------- | ------------------------------ |
| **System Variable**  | **Name**         | mysql-default_transaction_read |
|                      | **Dynamic**      | Yes                            |
| **Permitted Values** | **Type**         | String                         |
|                      | **Default**      | WRITE                          |
|                      | **Valid Values** | READ\|WRITE                    |

### `mysql-default_tx_isolation`

Variable deprecated in 2.1.1 .\
ProxySQL supports the change of the Transaction Isolation level ONLY at **SESSION** level. Any attempts to run
a command like `SET TRANSACTION ISOLATION LEVEL value` are not supported, and it will automatically disable
multiplexing. Correct syntax is: `SET SESSION TRANSACTION ISOLATION LEVEL value`

|                      |                  |                                                   |
| -------------------- | ---------------- | ------------------------------------------------- |
| **System Variable**  | **Name**         | mysql-default_tx_isolation                        |
|                      | **Dynamic**      | Yes                                               |
| **Permitted Values** | **Type**         | String                                            |
|                      | **Default**      | READ-COMMITTED                                    |
|                      | **Valid Values** | READ COMMITTED, REPEATABLE READ, and SERIALIZABLE |

### `mysql-log_mysql_warnings_enabled`

Introduced in ProxySQL v2.1.1. If enabled, all generated MySQL warnings will be logged to ProxySQL log.

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | mysql-log_mysql_warnings_enabled |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Boolean                          |
|                      | **Default** | false                            |

### `mysql-log_unhealthy_connections`

If a client disconnects in a not graceful way and if `mysql-log_unhealthy_connections` is enabled (default),
ProxySQL will log a warning `Closing unhealthy client connection IP:port`. The most common reasons for a
client to disconnect not gracefully are client just closing the socket without sending any `QUIT` packet, or a
client disconnecting without even starting the MySQL authentication (action performed mostly by monitoring
tools that are only checking if the port is open and accepting TCP connections)

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-log_unhealthy_connections |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Boolean                         |
|                      | **Default** | true                            |

### `mysql-multiplexing`

If `mysql-multiplexing` is enabled (true by default) multiplexing is globally enabled. We recommend to keep
multiplexing enabled (the default). Please note that even if multiplexing is globally enabled, it can still be
disabled for [other reasons][32] If `mysql-multiplexing` is disabled globally, multiplexing is never enabled.

|                      |             |                    |
| -------------------- | ----------- | ------------------ |
| **System Variable**  | **Name**    | mysql-multiplexing |
|                      | **Dynamic** | Yes                |
| **Permitted Values** | **Type**    | Boolean            |
|                      | **Default** | true               |

### `mysql-enable_client_deprecate_eof`

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | mysql-enable_client_deprecate_eof |
|                      | **Dynamic** | Yes                               |
| **Permitted Values** | **Type**    | Boolean                           |
|                      | **Default** | true                              |

<div>Enables ProxySQL support for MySQL <a href="https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html#gaad8e6e886899e90e820d6c2e0248469d">CLIENT_DEPRECATE_EOF</a> for client connections.</div>

### `mysql-enable_load_data_local_infile`

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | mysql-enable_load_data_local_infile |
|                      | **Dynamic** | Yes                                 |
| **Permitted Values** | **Type**    | Boolean                             |
|                      | **Default** | false                               |

ProxySQL doesn't support remote execution of `LOAD DATA LOCAL INFILE` command, that is, when using
`LOAD DATA LOCAL INFILE` command against ProxySQL the target file needs to be in the local filesystem of the
machine running ProxySQL, _not in the client filesystem_. To avoid this confusion, the command is disabled and
listed as unsupported by default.

### `mysql-enable_server_deprecate_eof`

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | mysql-enable_server_deprecate_eof |
|                      | **Dynamic** | Yes                               |
| **Permitted Values** | **Type**    | Boolean                           |
|                      | **Default** | true                              |

Enables ProxySQL support for MySQL [CLIENT_DEPRECATE_EOF][33] for backend connections.

### `mysql-enforce_autocommit_on_reads`

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | mysql-enforce_autocommit_on_reads |
|                      | **Dynamic** | Yes                               |
| **Permitted Values** | **Type**    | Boolean                           |
|                      | **Default** | false                             |

In MySQL it is possible to start a transaction in two ways:

-   explictly starting a transaction with `BEGIN`, `START TRANSACTION` or similar
-   setting `autocommit=0` and run a query against a transactional table

<!-- -->

A lot of drivers and applications use the second approach, setting `autocommit=0` . This can create a problem
if some form of read/write split is configured. In fact, if a `SELECT` statement is executed immediately after
`SET autcommit=0` , a transaction could be started on a reader server and any DML query will therefore fail.
`mysql-enforce_autocommit_on_reads` controls if `autocommit=0` is set on the backend connection if a
transaction is not yet started and a `SELECT` statement is executed:

-   `false` : (default) `SELECT` statement is executed with `autocommit=1` . This prevents to start a
    transaction on a reader server potentially configured in `read_only=ON` mode
-   `true` : `SELECT` statement is executed with `autocommit=0` . If the `SELECT` statement is routed to a
    reader node, this will start a transaction there

<!-- -->

The majority of applications work will with `mysql-enforce_autocommit_on_read=false` , and it is the default
configuration. If an application requires `mysql-enforce_autocommit_on_read=true` to start a transaction with
a `SELECT` statement following `SET autocommit=0` , it is likely that more complex query rules are needed to
ensure that certain `SELECT` statements are executed on the writer node. It is also important to remember that
`mysql-enforce_autocommit_on_reads` applies only to `SELECT` statements when a transaction is not started yet:
this means that when `mysql-enforce_autocommit_on_read=false` and `autocommit=0`, a transaction will start on
the first DML.

### `mysql-eventslog_filename`

If this variable is set, ProxySQL will log all traffic to the specified filename. Note that the log file is
not a text file, but a binary log with encoded traffic. The value of this variable can be set to an absolute
pathname (e.g. `/data/events_log/events_log` or else a filename (e.g. `events_log`) will be written to the
defined data directory. A sequential number will always be suffixed in the file's extension (e.g.
`events_log.00000001`).

|                      |                  |                             |
| -------------------- | ---------------- | --------------------------- |
| **System Variable**  | **Name**         | mysql-eventslog_filename    |
|                      | **Dynamic**      | Yes                         |
| **Permitted Values** | **Type**         | String                      |
|                      | **Default**      | empty string, not set       |
|                      | **Valid Values** | A filename or absolute path |

### `mysql-eventslog_filesize`

This variable specifies the maximum size of files created by ProxySQL logger as specified in
`mysql-eventslog_filename`. When the maximum size is reached, the file is rotated.

|                      |             |                          |
| -------------------- | ----------- | ------------------------ |
| **System Variable**  | **Name**    | mysql-eventslog_filesize |
|                      | **Dynamic** | Yes                      |
| **Permitted Values** | **Type**    | Integer (bytes)          |
|                      | **Default** | 104857600 (100MB)        |
|                      | **Minimum** | 1048576                  |
|                      | **Maximum** | 1073741824               |

### `mysql-evaluate_replication_lag_on_servers_load`

|                      |             |                                                |
| -------------------- | ----------- | ---------------------------------------------- |
| **System Variable**  | **Name**    | mysql-evaluate_replication_lag_on_servers_load |
|                      | **Dynamic** | Yes                                            |
| **Permitted Values** | **Type**    | Boolean                                        |
|                      | **Default** | True                                           |

Prior to `2.6.0` when a replica server was in `SHUNNED_REPLICATION_LAG` state and a user triggered a servers
reconfiguration via command `LOAD MYSQL USERS TO RUNTIME`, the server status will be updated to the one
specified by the user, including `ONLINE` state, the transitory state `SHUNNED_REPLICATION_LAG` **was not
preserved** in this case. After `2.6.0`, it's possible to control this behavior using this configuration
variable. When `true` (default value) the replica server transitory state `SHUNNED_REPLICATION_LAG` will be
preserved when users trigger servers reconfiguration and the target status specified by the user is `ONLINE`,
when `false` the behavior will be the one prior to `2.6.0`, the server won't preserve the state no matter the
target state specified by the user.

### `mysql-eventslog_default_log`

ProxySQL is able to log queries that pass through. If there is no definition for `Log` in a matching rule in
mysql_query_rules, mysql-eventslog_default_log applies. See also [Query Logging][34]

|                      |             |                             |
| -------------------- | ----------- | --------------------------- |
| **System Variable**  | **Name**    | mysql-eventslog_default_log |
|                      | **Dynamic** | Yes                         |
| **Permitted Values** | **Type**    | Boolean                     |
|                      | **Default** | false                       |

### `mysql-eventslog_format`

|                      |                  |                                                                                                                                  |
| -------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **System Variable**  | **Name**         | mysql-eventslog_format                                                                                                           |
|                      | **Dynamic**      | Yes                                                                                                                              |
| **Permitted Values** | **Type**         | Integer                                                                                                                          |
|                      | **Default**      | 1                                                                                                                                |
|                      | **Valid Values** | 1 : this is the default: queries are logged in binary format (like before 2.0.6)<br/> 2 : the queries are logged in JSON format. |

From version 2.0.6 ProxySQL can handle two different log formats:

-   1 : this is the default: queries are logged in binary format (like before 2.0.6)
-   2 : the queries are logged in JSON format

<!-- -->

See also [Query Logging][34]

### `mysql-eventslog_stmt_parameters`

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-eventslog_stmt_parameters |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Boolean                         |
|                      | **Default** | false                           |

Due to the potential overhead of logging prepared statements parameters, especially in `JSON` format and in
the presence of large blobs, this variable controls if parameters need to be logged or not.

### `mysql-firewall_whitelist_enabled`

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | mysql-firewall_whitelist_enabled |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Boolean                          |
|                      | **Default** | false                            |

This variable globally toggles the firewall whitelist algorithm on or off. For more information on firewall
whitelisting, see also [Firewall Whitelist][35].

### `mysql-firewall_whitelist_errormsg`

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | mysql-firewall_whitelist_errormsg |
|                      | **Dynamic** | Yes                               |
| **Permitted Values** | **Type**    | String                            |
|                      | **Default** | Firewall blocked this query       |

The error message that will be returned to the client, unless `mysql_query_rules.error_msg` has already set
one. See also [Firewall Whitelist][35].

### `mysql-forward_autocommit`

Deprecated in ProxySQL version 2.1.1 . See [GH #3253][36] When `mysql-forward_autocommit=false` (the default),
ProxySQL will track (and remember) the autocommit value that the client wants and change `autocommit` on a
backend connection as needed. For example, if a client sends `set autocommit=0`, ProxySQL will just reply OK.
When the client sends a DDL, ProxySQL will get a connection to target hostgroup, and change `autocommit`
before running the DDL. If `mysql-forward_autocommit=true`, `SET autocommit=0` is forwarded to the backend.
`SET autocommit=0` doesn't start any transaction, the connection is set in the connection pool, and queries
may execute on a different connection. If you set `mysql-forward_autocommit=true`, you should also set
`mysql-autocommit_false_not_reusable=true` to prevent the connection to be returned to the connection pool. In
other words, setting `mysql-forward_autocommit=false` will prevent this behaviour since the autocommit state
is tracked.

|                      |             |                          |
| -------------------- | ----------- | ------------------------ |
| **System Variable**  | **Name**    | mysql-forward_autocommit |
|                      | **Dynamic** | Yes                      |
| **Permitted Values** | **Type**    | Boolean                  |
|                      | **Default** | false                    |

### `mysql-free_connections_pct`

ProxySQL uses a connection pool to connect to backend servers. Connections to backend are never pre-allocated
if there is no need, so at start up there will be 0 connections to the backend. When an application starts
sending traffic to ProxySQL, this identifies to which backend it needs to send traffic. If there is a
connection in the connection pool for that backend, that connection is used, otherwise a new connection is
created. When the connection completes serving the client's request, it is sent back to the the Hostgroup
Manager. If the Hostgroup Manager determines that the connection is safe to share and the connection pool
isn't full, it will place it in the connection pool. Although, not all the unused connections are kept in the
connection pool. This variable controls the percentage of open idle connections from the total maximum number
of connections for a specific server in a hostgroup. For each hostgroup/backend pair, the Hostgroup Manager
will keep in the connection pool up to `mysql-free_connections_pct * mysql_servers.max_connections / 100`
connections . Connections are kept open with periodic pings. A connection is idle if it hasn't been used since
the last round of pings. The time interval between two such rounds of pings for idle connections is controlled
by the variable `mysql-ping_interval_server_msec`.

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | mysql-free_connections_pct |
|                      | **Dynamic** | Yes                        |
| **Permitted Values** | **Type**    | Integer (percentage)       |
|                      | **Default** | 10                         |
|                      | **Minimum** | 0                          |
|                      | **Maximum** | 100                        |

### `mysql-handle_unknown_charset`

Allows to select between different behaviors on how ProxySQL should handle the situation of finding a charset
in a client connection that \*can't\* be set for the backend connection as it's unknown for the server.

|                      |                  |                                                                                                                                                                                                                                                                  |
| -------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **System Variable**  | **Name**         | mysql-handle_unknown_charset                                                                                                                                                                                                                                     |
|                      | **Dynamic**      | Yes                                                                                                                                                                                                                                                              |
| **Permitted Values** | **Type**         | Integer                                                                                                                                                                                                                                                          |
|                      | **Default**      | 1                                                                                                                                                                                                                                                                |
|                      | **Valid Values** | 0 : DISCONNECT_CLIENT: Disconnect client and log error message.<br/> 1 : REPLACE_WITH_DEFAULT_VERBOSE: Replace with default character set and log that target one couldn't be found.<br/> 2 : REPLACE_WITH_DEFAULT: Replace with default character set silently. |

### `mysql-handle_warnings`

When enabled, if a warning is generated for a query execution, multiplexing is temporarily disabled in the
connection until a new query is received. If the new query happens to be `SHOW WARNINGS` or
`SHOW COUNT(*) FROM WARNINGS` it will be executed in the same connection as the previous query, however, if
any other query is executed, multiplexing is re-enabled.

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | mysql-handle_warnings |
|                      | **Dynamic** | Yes                   |
| **Permitted Values** | **Type**    | Integer               |
|                      | **Default** | 1                     |

An analogous flag `handle_warnings` exists for `mysql_hostgroup_attributes` table, at column
`hostgroup_settings`. This per-hostgroup flag holds priority over this global variable and will override it.
For more information about this per-hostgroup flag please refer to [mysql_hostgroup_attributes][37] table.
Important remarks about the feature:

-   Dependent on query digests, so [mysql-query_digests][38] is required.
-   Compatible with [mysql-log_mysql_warnings_enabled][39].
-   Potential incompatibility with [mysql-query_digests_keep_comment][40]. If queries `SHOW WARNINGS` and
    `SHOW COUNT(*) FROM WARNINGS` hold comments, query detection could fail.
-   No support for query `SELECT @@warning_count`. If executed, multiplexing will be disabled and remain
    disabled for that connection.

### `mysql-have_compress`

Currently unused.

### `mysql-have_ssl`

|                      |             |                     |
| -------------------- | ----------- | ------------------- |
| **System Variable**  | **Name**    | mysql-have_ssl      |
|                      | **Dynamic** | Yes                 |
| **Permitted Values** | **Type**    | Boolean             |
|                      | **Default** | true (since v2.6.0) |

Introduced in ProxySQL `v2.0`, it enables frontend SSL support (see [SSL Support][41] for more information).
Previous to `v2.6.0` was disabled by default for performance considerations, enabled by default since
`v2.6.0`.

This variable is overridden when [mysql-default_authentication_plugin][42] is set to `caching_sha2_password`.
See variable documentation for further details.

### `mysql-hostgroup_manager_verbose`

Enable verbose logging of hostgroup manager details in ProxySQL logs (e.g. when running
`LOAD MYSQL SERVERS TO RUNTIME`).

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-hostgroup_manager_verbose |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Integer                         |
|                      | **Default** | 1                               |
|                      | **Minimum** | 0                               |
|                      | **Maximum** | 2                               |

### `mysql-init_connect`

String containing one or more SQL statements, separated by semicolons, that will be executed by the ProxySQL
for each backend connection when created or initialised e.g. `SET WAIT_TIMEOUT=28800` (works similarly to
MySQL's `init_connect` variable).

|                      |                  |                                                                       |
| -------------------- | ---------------- | --------------------------------------------------------------------- |
| **System Variable**  | **Name**         | mysql-init_connect                                                    |
|                      | **Dynamic**      | Yes                                                                   |
| **Permitted Values** | **Type**         | String                                                                |
|                      | **Default**      | empty string, not set                                                 |
|                      | **Valid Values** | String containing one or more SQL statements, separated by semicolons |

### `mysql-interfaces`

Semicolon-separated list of `hostname:port` entries for interfaces for incoming MySQL traffic. Note that this
also supports UNIX domain sockets for the cases where the connection is done from an application on the same
machine. Note that changing this value has no effect at runtime, if you need to change it you have to restart
the proxy. After changing `mysql-interfaces`, you should not run `LOAD MYSQL VARIABLES TO RUNTIME` because
this variable cannot be loaded at runtime. Attempt to load them at runtime will cause their reset. In other
words, after changing `mysql-interfaces`, you need to run `SAVE MYSQL VARIABLES TO DISK` and then restart
ProxySQL (for example using `PROXYSQL RESTART`).

|                      |                  |                                                                         |
| -------------------- | ---------------- | ----------------------------------------------------------------------- |
| **System Variable**  | **Name**         | mysql-interfaces                                                        |
|                      | **Dynamic**      | No                                                                      |
| **Permitted Values** | **Type**         | String                                                                  |
|                      | **Default**      | 0.0.0.0:6033;/tmp/proxysql.sock                                         |
|                      | **Valid Values** | IP / hostname with ':' seperated port and ';' separated socket filename |

### `mysql-keep_multiplexing_variables`

|                      |                  |                                   |
| -------------------- | ---------------- | --------------------------------- |
| **System Variable**  | **Name**         | mysql-keep_multiplexing_variables |
|                      | **Dynamic**      | Yes                               |
| **Permitted Values** | **Type**         | String                            |
|                      | **Default**      | trx_isolation,version             |
|                      | **Valid Values** | any variables separated by commas |

Defines a comma separated list of variables that do not cause multiplexing to be disabled if queried. For
example, a query like `SELECT @@version`, by default would disable multiplexing. But because `version` is
listed in `mysql-keep_multiplexing_variables`, multiplexing is not disabled.

### `mysql-max_stmts_cache`

Set the total maximum number of statements that can be cached when using Prepared Statements.

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | mysql-max_stmts_cache |
|                      | **Dynamic** | Yes                   |
| **Permitted Values** | **Type**    | Integer               |
|                      | **Default** | 10000                 |
|                      | **Minimum** | 1024                  |
|                      | **Maximum** | 1048576               |

### `mysql-kill_backend_connection_when_disconnect`

When enabled the backend connection for a client connection is killed when the client disconnects (introduced
in ProxySQL v2.0).

|                      |             |                                               |
| -------------------- | ----------- | --------------------------------------------- |
| **System Variable**  | **Name**    | mysql-kill_backend_connection_when_disconnect |
|                      | **Dynamic** | Yes                                           |
| **Permitted Values** | **Type**    | Boolean                                       |
|                      | **Default** | true                                          |

### `mysql-long_query_time`

Threshold for counting queries passing through the proxy as 'slow'. The total number of slow queries can be
found in the `stats_mysql_global` table, in the variable named `Slow_queries` (each row in that table
represents one variable).

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | mysql-long_query_time  |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | Integer (milliseconds) |
|                      | **Default** | 1000                   |
|                      | **Minimum** | 0                      |
|                      | **Maximum** | 1728000000             |

### `mysql-max_allowed_packet`

`mysql-max_allowed_packet` defines the maximum size of a single packet/command received by the client. It
mimics the behavior of mysqld's [max_allowed_packet][43]

|                      |             |                          |
| -------------------- | ----------- | ------------------------ |
| **System Variable**  | **Name**    | mysql-max_allowed_packet |
|                      | **Dynamic** | Yes                      |
| **Permitted Values** | **Type**    | Integer (bytes)          |
|                      | **Default** | 4194304 (4MB)            |
|                      | **Minimum** | 8192 (8KB)               |
|                      | **Maximum** | 1073741824 (1GB)         |

### `mysql-max_connections`

The maximum number of client connections that the proxy can handle. After this number is reached, new
connections will be rejected with the `#HY000` error, and the error message `Too many connections`.

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | mysql-max_connections |
|                      | **Dynamic** | Yes                   |
| **Permitted Values** | **Type**    | Integer               |
|                      | **Default** | 2048                  |
|                      | **Minimum** | 1                     |
|                      | **Maximum** | 1000000               |

### `mysql-max_stmts_per_connection`

The threshold for the number of statements that can be prepared on a backend connection before that connection
is closed (prior to version 1.4.3) or reset (starting version 1.4.4). This is evaluated when a connection is
returned to the connection pool.

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | mysql-max_stmts_per_connection |
|                      | **Dynamic** | Yes                            |
| **Permitted Values** | **Type**    | Integer                        |
|                      | **Default** | 20                             |
|                      | **Minimum** | 1                              |
|                      | **Maximum** | 1024                           |

### `mysql-max_transaction_idle_time`

The maximum waiting time for a connection to have a transaction detected as `idle` before killing the client
connection.

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-max_transaction_idle_time |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Integer (milliseconds)          |
|                      | **Default** | 14400000 (4 hours)              |
|                      | **Minimum** |                                 |
|                      | **Maximum** |                                 |

### `mysql-max_transaction_time`

Sessions with active transactions running more than this timeout are killed.

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | mysql-max_transaction_time |
|                      | **Dynamic** | Yes                        |
| **Permitted Values** | **Type**    | Integer (milliseconds)     |
|                      | **Default** | 14400000 (4 hours)         |
|                      | **Minimum** | 1000                       |
|                      | **Maximum** | 1728000000                 |

### `mysql-min_num_servers_lantency_awareness`

Latency awareness is an algorithm used to send traffic only to the closest backends. IE: In case of slaves in
multiple AZs, ProxySQL will send traffic only to the slaves on the same AZ. But to trigger this algorithm, a
minimum number of servers is required. In case of 3 slaves in 3 AZs, and application/ProxySQL is in one AZ,
you MAY not want to send almost all the traffic to only one slave.

|                      |             |                                         |
| -------------------- | ----------- | --------------------------------------- |
| **System Variable**  | **Name**    | mysql-min_num_servers_lantency_awarenes |
|                      | **Dynamic** | Yes                                     |
| **Permitted Values** | **Type**    | Integer                                 |
|                      | **Default** | 1000                                    |

### `mysql-monitor_aws_rds_topology_discovery_interval`

Controls the frequency of AWS RDS topology discovery checks for Multi-AZ DB Clusters. This variable determines
how often ProxySQL queries the `mysql.rds_topology` table on AWS RDS endpoints to automatically discover and
configure additional cluster members.

This feature is specifically designed for AWS RDS Multi-AZ DB Clusters with reader endpoints, allowing
ProxySQL to automatically detect and add new cluster members to the configuration without manual intervention.

**Topology Discovery Behavior:**

**When `mysql-monitor_aws_rds_topology_discovery_interval = 0` (Disabled - Default):**

-   No automatic topology discovery is performed
-   Only read-only status checks are conducted during monitoring
-   AWS RDS cluster members must be manually configured in `mysql_servers`
-   Minimal monitoring overhead for read-only checks

**When `mysql-monitor_aws_rds_topology_discovery_interval > 0` (Enabled):**

-   Topology discovery runs every N monitoring cycles (where N = interval value)
-   Discovery only occurs for servers with `rds.amazonaws.com` hostnames
-   Queries `mysql.rds_topology` table to discover cluster topology
-   Automatically adds discovered cluster members to `runtime_mysql_servers`
-   Works in combination with regular read-only status monitoring

**Discovery Process:**

1. **Endpoint Detection**: Identifies AWS RDS endpoints by hostname matching `*.rds.amazonaws.com`
2. **Topology Query**: Executes
   `SELECT @@global.read_only read_only, id, endpoint, port from mysql.rds_topology`
3. **Cluster Analysis**: Determines if the topology represents an AWS RDS Multi-AZ DB Cluster
4. **Auto-Configuration**: Automatically adds discovered members to the runtime server configuration
5. **Integration**: Works seamlessly with existing replication hostgroup configurations

**Usage Scenarios:**

**Enable Discovery (>0) for:**

-   AWS RDS Multi-AZ DB Cluster deployments
-   Dynamic cluster scaling scenarios
-   Automated failover and load balancing configurations
-   Environments with frequent cluster topology changes
-   Production deployments requiring high availability

**Keep Disabled (0) for:**

-   Non-AWS RDS deployments (MySQL on-premises, other cloud providers)
-   Static cluster configurations with fixed topology
-   Development or testing environments
-   Single-instance deployments
-   When manual server configuration is preferred

**Configuration:**

```sql
-- Disable topology discovery (default)
SET mysql-monitor_aws_rds_topology_discovery_interval = 0;
LOAD MYSQL VARIABLES TO RUNTIME;

-- Enable topology discovery every 100 monitoring cycles
SET mysql-monitor_aws_rds_topology_discovery_interval = 100;
LOAD MYSQL VARIABLES TO RUNTIME;

-- Frequent discovery for dynamic clusters
SET mysql-monitor_aws_rds_topology_discovery_interval = 10;
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Important Notes:**

-   Only works with AWS RDS endpoints ending in `rds.amazonaws.com`
-   Discovery frequency is in monitoring cycles, not time units
-   Actual time between discoveries depends on `monitor_read_only_interval`
-   Requires `monitor_enabled` to be active for topology discovery to work
-   Automatically maintains server group assignments from original configuration

**Performance Considerations:**

-   Each discovery query adds minimal overhead to the monitoring cycle
-   Discovery frequency should be balanced against cluster change frequency
-   Too frequent discovery may generate unnecessary query load on RDS instances
-   Recommended interval: 100-1000 cycles for most production environments

|                      |             |                                                   |
| -------------------- | ----------- | ------------------------------------------------- |
| **System Variable**  | **Name**    | mysql-monitor_aws_rds_topology_discovery_interval |
|                      | **Dynamic** | Yes                                               |
| **Permitted Values** | **Type**    | Integer                                           |
|                      | **Default** | 0                                                 |
|                      | **Minimum** | 0                                                 |
|                      | **Maximum** | 100000                                            |

### `mysql-proxy_protocol_networks`

Specifies which networks are allowed to send PROXY protocol headers to ProxySQL. This is a critical security
variable that controls which client connections can include PROXY protocol information for preserving original
client IP addresses through proxies and load balancers.

The PROXY protocol enables ProxySQL to extract real client connection information (IP address, port) from
connections that pass through TCP proxies, load balancers, or other network intermediaries. This is essential
for accurate logging, security policies, and compliance requirements.

**Network List Format:**

-   Empty string `''`: Disable PROXY protocol (default, most secure)
-   Asterisk `'*'`: Accept PROXY headers from any network (least secure)
-   Comma-separated CIDR notation for IPv4 and IPv6 networks
-   Networks are evaluated in order; first match determines acceptance

**PROXY Protocol Behavior:**

**When `mysql-proxy_protocol_networks = ''` (Disabled - Default):**

-   PROXY protocol headers are ignored and treated as regular data
-   All client connections use the direct TCP connection information
-   Maximum security against PROXY header spoofing attacks
-   Load balancers must be configured without PROXY protocol

**When `mysql-proxy_protocol_networks = '*'` (Accept All - Insecure):**

-   Accept PROXY headers from any client network
-   **Security Risk**: Malicious clients can spoof client information
-   Only appropriate in trusted, isolated network environments
-   Not recommended for production deployments

**When `mysql-proxy_protocol_networks = 'specific_networks'` (Recommended):**

-   Accept PROXY headers only from specified network ranges
-   Networks defined in CIDR notation (IPv4/IPv6)
-   Prevents unauthorized clients from spoofing client information
-   Secure deployment behind trusted load balancers

**Configuration Examples:**

```sql
-- Disable PROXY protocol (default, most secure)
SET mysql-proxy_protocol_networks = '';
LOAD MYSQL VARIABLES TO RUNTIME;

-- Accept from any network (insecure - not recommended for production)
SET mysql-proxy_protocol_networks = '*';
LOAD MYSQL VARIABLES TO RUNTIME;

-- Accept from specific IPv4 load balancer networks
SET mysql-proxy_protocol_networks = '10.0.1.0/24,192.168.100.0/24,172.16.0.0/12';
LOAD MYSQL VARIABLES TO RUNTIME;

-- Accept from specific IPv6 networks
SET mysql-proxy_protocol_networks = '2001:db8::/32,fe80::/10';
LOAD MYSQL VARIABLES TO RUNTIME;

-- Mixed IPv4 and IPv6 networks
SET mysql-proxy_protocol_networks = '10.0.1.0/24,2001:db8::/32,192.168.1.0/24';
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Security Considerations:**

-   **Always specify trusted networks** instead of using wildcards
-   **Load balancer IP ranges** should be as specific as possible
-   **Regular monitoring** of unexpected connection patterns
-   **Network segmentation** to protect against spoofed headers
-   **Audit trails** to verify PROXY header usage

**Integration with Load Balancers:**

**HAProxy Configuration:**

```haproxy
backend mysql_servers
    mode tcp
    server proxysql1 10.0.1.100:6033 check send-proxy
```

**Required ProxySQL Configuration:**

```sql
-- Accept only from HAProxy network
SET mysql-proxy_protocol_networks = '10.0.1.0/24';
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Information Preservation:** When PROXY headers are processed, ProxySQL stores:

-   **Original client IP address** (replaces proxy IP in logs)
-   **Original client port**
-   **Proxy IP address** (for debugging)
-   **Connection metadata** (available in `stats_mysql_processlist.extended_info` when
    `mysql-show_processlist_extended` is enabled)

**Usage Scenarios:**

**Enable PROXY Protocol for:**

-   Deployments behind TCP load balancers (HAProxy, AWS NLB, etc.)
-   Multi-tier architectures with reverse proxies
-   Cloud load balancer deployments (DigitalOcean, AWS, GCP)
-   Requirements for accurate client IP logging
-   Security policies based on client location
-   Compliance requirements for client identification

**Keep Disabled for:**

-   Direct client connections without proxies
-   Untrusted network environments
-   Development or testing environments
-   When load balancers are configured without PROXY protocol

**Debugging and Monitoring:**

```sql
-- Check current PROXY protocol settings
SHOW VARIABLES LIKE 'proxy_protocol_networks';

-- Monitor connections with PROXY information
SELECT * FROM stats_mysql_connection_pool;

-- View detailed connection metadata in exports
-- PROXY information appears in JSON exports
```

**Performance Impact:**

-   Minimal processing overhead for PROXY header parsing
-   Small memory footprint for storing connection metadata
-   No impact on query performance or routing
-   Negligible latency increase (microseconds)

**For comprehensive PROXY protocol documentation, see [PROXY Protocol Support][60].**

|                      |                      |                                    |
| -------------------- | -------------------- | ---------------------------------- |
| **System Variable**  | **Name**             | mysql-proxy_protocol_networks      |
|                      | **Dynamic**          | Yes                                |
| **Permitted Values** | **Type**             | String                             |
|                      | **Default**          | '' (empty string, disabled)        |
|                      | **Permitted Values** | CIDR notation networks, '\*' or '' |

### `mysql-mirror_max_concurrency`

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | mysql-mirror_max_concurrency |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer                      |
|                      | **Default** | 16                           |
|                      | **Minimum** | 1                            |
|                      | **Maximum** | 8192                         |

Limits the number of concurrent mirror sessions handled by a MySQL_Thread. The mirror sessions to be processed
are extracted randomly from a processing queue until reaching this limit. The maximum size of this queue is
determined by variable [mysql-mirror_max_queue_length][44].

### `mysql-mirror_max_queue_length`

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | mysql-mirror_max_queue_length |
|                      | **Dynamic** | Yes                           |
| **Permitted Values** | **Type**    | Integer                       |
|                      | **Default** | 32000                         |
|                      | **Minimum** | 0                             |
|                      | **Maximum** | 1048576                       |

Determines the maximum size for the mirror sessions processing queue. Mirror sessions are placed in this queue
when a 'MySQL_Thread' is either already handling the allowed maximum of concurrent mirrors sessions, limited
by [mysql-mirror_max_concurrency][45], or the processing queue for the 'MySQL_Thread' already contains mirror
sessions.

### `mysql-ping_interval_server_msec`

The interval at which the proxy should ping backend connections in order to maintain them alive, even though
there is no outgoing traffic. The purpose here is to keep some connections alive in order to reduce the
latency of new queries towards a less frequently used destination backend server.

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-ping_interval_server_msec |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Integer (milliseconds)          |
|                      | **Default** | 10000                           |
|                      | **Minimum** | 1000                            |
|                      | **Maximum** | 604800000                       |

### `mysql-ping_timeout_server`

The proxy internally pings the connections it has opened in order to keep them alive. This eliminates the cost
of opening a new connection towards a hostgroup when a query needs to be routed, at the cost of additional
memory footprint inside the proxy and some extra traffic. This is the timeout allowed for those pings to
succeed.

|                      |             |                           |
| -------------------- | ----------- | ------------------------- |
| **System Variable**  | **Name**    | mysql-ping_timeout_server |
|                      | **Dynamic** | Yes                       |
| **Permitted Values** | **Type**    | Integer (milliseconds)    |
|                      | **Default** | 200                       |
|                      | **Minimum** | 10                        |
|                      | **Maximum** | 600000                    |

### `mysql-poll_timeout`

The minimal timeout used by the proxy in order to detect incoming/outgoing traffic via the `poll()` system
call. If the proxy determines that it should stick to a higher timeout because of its internal computations,
it will use that one, but it will never use a value less than this one.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | mysql-poll_timeout     |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | Integer (milliseconds) |
|                      | **Default** | 2000                   |
|                      | **Minimum** | 10                     |
|                      | **Maximum** | 20000                  |

### `mysql-poll_timeout_on_failure`

The timeout used in order to detect incoming/outgoing traffic after a connection error has occurred. The proxy
automatically tweaks its timeout to a lower value in such an event in order to be able to quickly respond with
a valid connection.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | mysql-poll_timeout_on_failure |
|                      | **Dynamic** | Yes                           |
| **Permitted Values** | **Type**    | Integer (milliseconds)        |
|                      | **Default** | 100                           |
|                      | **Minimum** | 10                            |
|                      | **Maximum** | 20000                         |

### `mysql-query_cache_handle_warnings`

Determines how the query cache should interact with resultset from queries that have generated warnings.
Depending on the value, if a query **has produced** a warning:

-   `0`: The `resultset` will **not** be saved in the query cache.
-   `1`: The `resultset` **will be** saved in the query cache, but its warning count will be reset to `0`.

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | mysql-query_cache_handle_warnings |
|                      | **Dynamic** | Yes                               |
| **Permitted Values** | **Type**    | Integer                           |
|                      | **Default** | 0                                 |
|                      | **Minimum** | 0                                 |
|                      | **Maximum** | 1                                 |

### `mysql-query_cache_size_MB`

The total amount of memory used by the Query Cache, note: the current implementation of
mysql-query_cache_size_MB doesn't impose a hard limit . Instead, it is used as an argument by the purging
thread.

|                      |             |                           |
| -------------------- | ----------- | ------------------------- |
| **System Variable**  | **Name**    | mysql-query_cache_size_MB |
|                      | **Dynamic** | Yes                       |
| **Permitted Values** | **Type**    | Integer (MB)              |
|                      | **Default** | 256                       |
|                      | **Minimum** | 0                         |
|                      | **Maximum** | 10485760                  |

### `mysql-query_cache_soft_ttl_pct`

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | mysql-query_cache_soft_ttl_pct |
|                      | **Dynamic** | Yes                            |
| **Permitted Values** | **Type**    | Integer (percentage)           |
|                      | **Default** | 0                              |
|                      | **Minimum** | 0                              |
|                      | **Maximum** | 100                            |

If `Query Cache` entry reaches this soft-TTL, and havent yet reached the `cache_ttl`, the next query received
wont hit the `Query Cache` entry, but the backend server, refreshing the entry resultset and TTL itself.

### `mysql-query_cache_stores_empty_result`

The variable controls if resultset without rows will be cached or not (introduced in ProxySQL v2.0).

|                      |             |                                       |
| -------------------- | ----------- | ------------------------------------- |
| **System Variable**  | **Name**    | mysql-query_cache_stores_empty_result |
|                      | **Dynamic** | Yes                                   |
| **Permitted Values** | **Type**    | Boolean                               |
|                      | **Default** | true                                  |

### `mysql-query_digests`

When this variable is set to true, the proxy analyzes the queries passing through it and divides them into
classes of queries having different values for the same parameters. It computes a couple of metrics for these
classes of queries, all found in the `stats_mysql_query_digest` table. For more details, please refer to the
[admin tables documentation][46]. It is also very important to note that query digest is required to determine
when multiplexing needs to be disabled, for example in case of `TEMPORARY` tables, `SQL_CALC_FOUND_ROWS` ,
`GET_LOCK`, etc. Do not disable `mysql-query_digests` unless you are really sure it won't break your
application.

|                      |             |                     |
| -------------------- | ----------- | ------------------- |
| **System Variable**  | **Name**    | mysql-query_digests |
|                      | **Dynamic** | Yes                 |
| **Permitted Values** | **Type**    | Boolean             |
|                      | **Default** | true                |

### `mysql-query_digests_keep_comment`

When set to 'true', comments of the kind '/\* \*/' are not stripped from the query digest.

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | mysql-query_digests_keep_comment |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Boolean                          |
|                      | **Default** | false                            |

### `mysql-query_digests_lowercase`

When this variable is set to true, query digest is automatically converted to lowercase otherwise when false,
query digests are case sensitive.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | mysql-query_digests_lowercase |
|                      | **Dynamic** | Yes                           |
| **Permitted Values** | **Type**    | Boolean                       |
|                      | **Default** | false                         |

### `mysql-query_digests_max_digest_length`

Defines the maximum length of `digest_text` as then reported in `stats_mysql_query_digest`. **It's important**
to note that this variable doesn't affect the size of the `digest_text` generated when processing the query,
and it's only relevant for determining the maximum length for `stats_mysql_query_digest`, for modifying the
maximum size of the `digest_text` generated please refer to [mysql-query_digests_max_query_length][47].

|                      |                                  |                                       |
| -------------------- | -------------------------------- | ------------------------------------- |
| **System Variable**  | **Name**                         | mysql-query_digests_max_digest_length |
|                      | **Dynamic**                      | Yes                                   |
| **Permitted Values** | **Type**                         | Integer                               |
|                      | **Default**                      | 2048                                  |
|                      | **Minimum**                      | 16                                    |
|                      | **Maximum (up to 1.3.1)**        | 65000                                 |
|                      | **Maximum (from 1.3.2 onwards)** | 1048576                               |

### `mysql-query_digests_max_query_length`

Defines the maximum size of the buffer being used when computing query's `digest` and `digest_text`.
**DETAILS:** This variable effectively limits the size of the generated `digest_text`, **but**, it's important
to note that this **doesn't mean** than a query larger than the size specified by this variable **wont** fit
in the generated `digest_text`. This is due to the multiple compressions that are performed during the digest
computation, e.g: 'numbers', 'strings', 'comments', etc... or even grouping of values, like the specified by
'mysql-query_digests_grouping_limit'. These compressions allows ProxySQL to be able to fit larger queries in
smaller buffers for the generated `digest_texts`.

|                      |                                  |                                      |
| -------------------- | -------------------------------- | ------------------------------------ |
| **System Variable**  | **Name**                         | mysql-query_digests_max_query_length |
|                      | **Dynamic**                      | Yes                                  |
| **Permitted Values** | **Type**                         | Integer                              |
|                      | **Default**                      | 65000                                |
|                      | **Minimum**                      | 16                                   |
|                      | **Maximum (up to 1.3.1)**        | 65000                                |
|                      | **Maximum (from 1.3.2 onwards)** | 16777216                             |

### `mysql-query_digests_grouping_limit`

Introduced in v2.1.0. Defines the maximum number of replacements in a digest by the placeholder `?`. Elements
in a digest will be replaced by the placeholder `?`, until reaching element number `N`, after which all the
elements will be compressed into `...`. E.g: let the `mysql-query_digests_grouping_limit=3` the following
digest:

```
SELECT * FROM tablename WHERE id IN (1,2,3,4,5,6,7,8,9,10)
```

will be compressed into:

```
SELECT * FROM tablename WHERE id IN (?,?,?,...)
```

|                      |             |                                    |
| -------------------- | ----------- | ---------------------------------- |
| **System Variable**  | **Name**    | mysql-query_digests_grouping_limit |
|                      | **Dynamic** | Yes                                |
| **Permitted Values** | **Type**    | Integer                            |
|                      | **Default** | 3                                  |
|                      | **Minimum** | 1                                  |
|                      | **Maximum** | 2089                               |

### `mysql-query_digests_groups_grouping_limit`

Introduced in v2.4.0. Defines the maximum number of consecutive **compressed** value groups present in a
digest, group compression is performed via `mysql-query_digests_grouping_limit`. After this number is reached,
the exceeding **compressed** value groups are replaced by `...`. E.g: with
`mysql-query_digests_groups_grouping_limit=1` and `mysql-query_digests_groups_grouping_limit=2` the following
digest:

```
INSERT INTO tablename (a,b,c) VALUES (1,2,3),(4,5,6,),(7,8,9),(9,8,9)
```

will be compressed into:

```
INSERT INTO tablename (a,b,c) VALUES (?,...),(?,...),...
```

|                      |             |                                           |
| -------------------- | ----------- | ----------------------------------------- |
| **System Variable**  | **Name**    | mysql-query_digests_groups_grouping_limit |
|                      | **Dynamic** | Yes                                       |
| **Permitted Values** | **Type**    | Integer                                   |
|                      | **Default** | 0                                         |
|                      | **Minimum** | 0                                         |
|                      | **Maximum** | 2089                                      |

### `mysql-query_digests_no_digits`

When active ProxySQL will replace all numbers in the query to '?' signs for generating digest. This
functionality can be controlled by configuring the value of `mysql-query_digests_no_digits`.

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | mysql-query_digests_no_digits |
|                      | **Dynamic** | Yes                           |
| **Permitted Values** | **Type**    | Boolean                       |
|                      | **Default** | false                         |

### `mysql-query_digests_normalize_digest_text`

When set to FALSE (default), ProxySQL will cache the SQL digest and related information in the table
stats.stats_mysql_query_digest by schema. When this variable is TRUE, queries statistics store digest_text on
a different internal hash table. In this way ProxySQL will be able to normalize data, digest_text is
internally stored elsewhere, and it deduplicates data. When you query stats_mysql_query_digest, the data is
merged together. This drastically reduces memory usage on setups with many schemas but similar queries
patterns.

|                      |             |                                           |
| -------------------- | ----------- | ----------------------------------------- |
| **System Variable**  | **Name**    | mysql-query_digests_normalize_digest_text |
|                      | **Dynamic** | Yes                                       |
| **Permitted Values** | **Type**    | Boolean                                   |
|                      | **Default** | false                                     |

### `mysql-query_digests_replace_null`

When TRUE, ProxySQL will replace NULLs when creating the Query digest with '?'. This approach will normalize
statements like the following:

```SQL
SQL                                       Digest
    INSERT INTO tablename(id) VALUES (1);     INSERT INTO tablename(id) VALUES (?);
    INSERT INTO tablename(id) VALUES (NULL);  INSERT INTO tablename(id) VALUES (?);
    CALL spa(NULL, null, NULL, null);         CALL spa(?, ?, ?, ?);
    CALL spa(1, null, NULL, 4);               CALL spa(?, ?, ?, ?);
    CALL spa(1, 2, 3, 4);                     CALL spa(?, ?, ?, ?);
```

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | mysql-query_digests_replace_null |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Boolean                          |
|                      | **Default** | false                            |

### `mysql-query_digests_track_hostname`

If active it reports the original client address in the table stats_mysql_query_digest See also
[stats_mysql_query_digest][48]

|                      |             |                                    |
| -------------------- | ----------- | ---------------------------------- |
| **System Variable**  | **Name**    | mysql-query_digests_track_hostname |
|                      | **Dynamic** | Yes                                |
| **Permitted Values** | **Type**    | Boolean                            |
|                      | **Default** | false                              |

### `mysql-query_processor_iterations`

If `mysql_query_rules`.`flagOUT` is set and `mysql-query_processor_iterations` is greater than 0, a matching
rule will set `flagIN` and starts processing rules from the beginning up to `mysql-query_processor_iterations`
iterations. Therefore, mysql-query_processor_iterations allows to jump back to previous `mysql_query_rules`.

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | mysql-query_processor_iterations |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Integer                          |
|                      | **Default** | 0                                |
|                      | **Minimum** | 0                                |
|                      | **Maximum** | 1000000                          |

### `mysql-query_processor_regex`

This variable defines which regex engine to use:

-   1 : [PCRE][49]
-   2 : [RE2][50]

<!-- -->

Before version v1.4.0, only RE2 was available, _CASELESS_ was always enabled, and _GLOBAL_ was always
disabled. Starting from v1.4.0, both PCRE and RE2 are available. Now both PCRE and RE2 support _CASELESS_ and
_GLOBAL_ using [re_modifiers][46]. Although, RE2 doesn't support both _CASELESS_ and _GLOBAL_ at the same time
if they are both configured in [re_modifiers][46]. For this reason, the default regex engine was changed to
PCRE.

|                      |                  |                             |     |
| -------------------- | ---------------- | --------------------------- | --- |
| **System Variable**  | **Name**         | mysql-query_processor_regex |     |
|                      | **Dynamic**      | Yes                         |     |
| **Permitted Values** | **Type**         | Integer                     |     |
|                      | **Default**      | **PCRE**                    | 1   |
|                      | **Valid Values** | **PCRE**                    | 1   |
|                      |                  | **RE2**                     | 2   |

### `mysql-data_packets_history_size`

Controls the size of data packet history buffers maintained by ProxySQL for troubleshooting network
communication issues. This feature stores incoming and outgoing MySQL packets in circular buffers to help
debug complex protocol problems.

This variable was introduced in v2.5.3 as a troubleshooting feature to capture and analyze raw MySQL protocol
traffic between clients and servers through ProxySQL.

**Packet History Behavior:**

**When `mysql-data_packets_history_size = 0` (Disabled - Default):**

-   No packet history is maintained
-   Minimal memory overhead
-   Normal ProxySQL operation without debugging capabilities
-   Packets are processed and discarded immediately after use

**When `mysql-data_packets_history_size > 0` (Enabled):**

-   Maintains two circular buffers: `data_packets_history_IN` and `data_packets_history_OUT`
-   IN buffer stores packets received from clients (queries, commands)
-   OUT buffer stores packets sent to clients (resultsets, responses, errors)
-   Each buffer stores up to the specified number of packets
-   When buffer is full, oldest packets are overwritten (FIFO behavior)

**Usage Scenarios:**

**Enable Packet History (>0) for:**

-   Debugging protocol-level communication issues
-   Analyzing malformed packets or protocol violations
-   Troubleshooting connection drops or timeouts
-   Investigating data corruption during transmission
-   Development and testing of MySQL client compatibility

**Keep Disabled (0) for:**

-   Production environments with normal operation
-   Memory-constrained deployments
-   When packet-level debugging is not needed

**Configuration:**

```sql
-- Disable packet history (default, production recommended)
SET mysql-data_packets_history_size = 0;
LOAD MYSQL VARIABLES TO RUNTIME;

-- Enable with 1000 packets buffer for debugging
SET mysql-data_packets_history_size = 1000;
LOAD MYSQL VARIABLES TO RUNTIME;

-- Large buffer for extensive troubleshooting
SET mysql-data_packets_history_size = 10000;
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Memory Impact:**

-   Memory usage varies significantly between IN and OUT buffers
-   IN packets are typically small (queries, commands)
-   OUT packets can be large (resultsets, bulk data transfers)
-   Memory = `(history_size × average_IN_packet_size) + (history_size × average_OUT_packet_size)`
-   Each packet requires additional overhead for storage metadata
-   Memory is allocated dynamically as packets are processed
-   Consider your specific query patterns and resultset sizes when determining buffer size

**Note:** This is primarily a debugging feature. The packet history data is primarily accessible through core
dump analysis or specialized debugging tools, not through standard ProxySQL administrative interfaces.

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-data_packets_history_size |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Integer                         |
|                      | **Default** | 0                               |
|                      | **Minimum** | 0                               |
|                      | **Maximum** | 2147483647                      |

### `mysql-parse_failure_logs_digest`

Controls whether ProxySQL logs query digests or full query text when parsing failures occur. This variable
determines what information is included in error logs and warning messages when ProxySQL encounters queries it
cannot parse.

When parsing fails, ProxySQL generates error code 10002 with the message "Unable to parse query. If correct,
report it as a bug". This setting controls whether the query text shown in this message is the full original
query or a computed digest.

**Logging Behavior:**

**When `mysql-parse_failure_logs_digest = true` (Log Digest):**

-   Logs the computed query digest instead of full query text
-   Query digests are normalized, simplified representations of the query
-   Hides sensitive data like literal values, user-specific information
-   Consistent logging format for similar queries
-   Useful for identifying query patterns in parsing failures

**When `mysql-parse_failure_logs_digest = false` (Log Full Query - Default):**

-   Logs the complete original query text as received
-   Shows exact query that caused the parsing failure
-   Includes all literal values, comments, and formatting
-   Useful for debugging specific query issues
-   May expose sensitive information in logs

**Usage Scenarios:**

**Enable Digest Logging (`true`) for:**

-   Production environments where query privacy is important
-   Log analysis to identify patterns in parsing failures
-   Reducing log volume and storage requirements
-   Avoiding exposure of sensitive data in error logs

**Enable Full Query Logging (`false`) for:**

-   Development and debugging environments
-   Troubleshooting specific parsing issues
-   Bug reports to ProxySQL developers
-   Understanding exact query syntax causing failures

**Configuration:**

```sql
-- Log query digests for privacy (production recommended)
SET mysql-parse_failure_logs_digest = true;
LOAD MYSQL VARIABLES TO RUNTIME;

-- Log full queries for debugging (default)
SET mysql-parse_failure_logs_digest = false;
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Security Considerations:**

-   Full query logging may expose sensitive data (passwords, personal information)
-   Query digests normalize literals, providing better privacy
-   Consider compliance requirements (GDPR, PCI-DSS) when choosing setting
-   Digest logs are sufficient for identifying query patterns without exposing data

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-parse_failure_logs_digest |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Boolean                         |
|                      | **Default** | false                           |

### `mysql-query_rules_fast_routing_algorithm`

Controls how ProxySQL manages fast routing rule hashmaps across multiple threads. Fast routing rules are
special query rules that provide high-performance routing decisions without the overhead of full rule
processing.

This variable determines the memory allocation strategy for fast routing rule hashmaps, balancing memory usage
against concurrent access performance.

**Algorithm Behavior:**

**When `mysql-query_rules_fast_routing_algorithm = 1` (Per-Thread Hashmaps - Default):**

-   Creates separate hashmaps for each processing thread
-   Each thread has its own copy of fast routing rules
-   Higher memory usage but eliminates thread contention
-   Optimal for high-concurrency environments
-   Uses additional memory: `rules_size × num_threads × memory_overhead`

**When `mysql-query_rules_fast_routing_algorithm = 2` (Global Shared Hashmaps):**

-   Uses single shared hashmap across all threads
-   All threads access the same fast routing rule data
-   Lower memory usage but potential contention under heavy load
-   Optimal for memory-constrained environments or lower concurrency
-   Uses baseline memory only: `rules_size × memory_overhead`

**Configuration:**

```sql
-- Use per-thread hashmaps (default, better for high concurrency)
SET mysql-query_rules_fast_routing_algorithm = 1;
LOAD MYSQL VARIABLES TO RUNTIME;

-- Use shared hashmaps (lower memory usage)
SET mysql-query_rules_fast_routing_algorithm = 2;
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Performance Considerations:**

-   **Algorithm 1** is recommended for production environments with high concurrent query volumes
-   **Algorithm 2** is suitable for development, testing, or memory-constrained deployments
-   Memory usage difference can be significant with many fast routing rules and multiple threads
-   Performance impact is most noticeable under heavy concurrent load

|                      |             |                                          |
| -------------------- | ----------- | ---------------------------------------- |
| **System Variable**  | **Name**    | mysql-query_rules_fast_routing_algorithm |
|                      | **Dynamic** | Yes                                      |
| **Permitted Values** | **Type**    | Integer                                  |
|                      | **Default** | 1                                        |
|                      | **Minimum** | 1                                        |
|                      | **Maximum** | 2                                        |

### `mysql-processlist_max_query_length`

Controls the maximum length of query text displayed in the `SHOW PROCESSLIST` output and
`stats_mysql_processlist` table. This variable limits how much of the query string is stored and displayed for
monitoring and debugging purposes.

When a query exceeds this length, it will be truncated to fit within the specified limit. This helps control
memory usage while still providing useful diagnostic information.

**Query Length Behavior:**

-   Queries shorter than the limit are stored and displayed in full
-   Queries longer than the limit are truncated to the maximum specified length
-   The truncation happens when the query is recorded in the processlist
-   Both regular queries and prepared statement text are subject to this limit

**Usage Context:** This variable affects the following monitoring interfaces:

-   `SHOW PROCESSLIST` command execution
-   `stats_mysql_processlist` table content
-   Processlist information returned to monitoring tools

**Configuration:**

```sql
-- Set to 1MB (default)
SET mysql-processlist_max_query_length = 1048576;
LOAD MYSQL VARIABLES TO RUNTIME;

-- Increase to 4MB for better debugging with long queries
SET mysql-processlist_max_query_length = 4194304;
LOAD MYSQL VARIABLES TO RUNTIME;

-- Set to minimum (1KB) to save memory
SET mysql-processlist_max_query_length = 1024;
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Memory Considerations:**

-   Memory is allocated dynamically based on actual query lengths, not pre-allocated per connection
-   Most queries use minimal memory regardless of this setting
-   Memory spikes occur only for unusually long queries that exceed normal limits
-   Consider the likelihood of very long queries in your workload when setting this value
-   Balance debugging visibility for anomaly queries against potential memory usage during rare events

|                      |             |                                    |
| -------------------- | ----------- | ---------------------------------- |
| **System Variable**  | **Name**    | mysql-processlist_max_query_length |
|                      | **Dynamic** | Yes                                |
| **Permitted Values** | **Type**    | Integer                            |
|                      | **Default** | 2097152                            |
|                      | **Minimum** | 1024                               |
|                      | **Maximum** | 33554432                           |

### `mysql-query_retries_on_failure`

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | mysql-query_retries_on_failure |
|                      | **Dynamic** | Yes                            |
| **Permitted Values** | **Type**    | Integer                        |
|                      | **Default** | 1                              |
|                      | **Minimum** | 0                              |
|                      | **Maximum** | 1000                           |

In case of failures while running a query, the same can be retried `mysql-query_retries_on_failure` times.
This variable is related with [mysql-threshold_resultset_size][51], since this setting doesn't take effect for
queries whose resultsets have started to be streamed to the fronted connection, in that stage, a failed query
**is not retried**.

### `mysql-reset_connection_algorithm`

When `reset_connection_algorithm = 2`, MySQL_Thread itself tries to reset connections instead of relying on
connections purger HGCU_thread_run() (introduced in ProxySQL v2.0), `reset_connection_algorithm` can be set
to:

-   `1` = legacy algorithm used in ProxySQL v1.x
-   `2` = algorithm new since ProxySQL v2.0 (new default)

<!-- -->

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | mysql-reset_connection_algorithm |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Integer                          |
|                      | **Default** | 2                                |
|                      | **Minimum** | 1                                |
|                      | **Maximum** | 2                                |

### `mysql-server_capabilities`

The bitmask of MySQL capabilities (encoded as bits) with which the proxy will respond to clients connecting to
it. This is useful in order to prevent certain features from being used, although it is planned to be
deprecated in the future. The default capabilities are:

```c++
server_capabilities = CLIENT_FOUND_ROWS | CLIENT_PROTOCOL_41 | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB | CLIENT_SSL;
```

More details about server capabilities in the [official documentation][52].

|                      |             |                           |
| -------------------- | ----------- | ------------------------- |
| **System Variable**  | **Name**    | mysql-server_capabilities |
|                      | **Dynamic** | Yes                       |
| **Permitted Values** | **Type**    | Integer                   |
|                      | **Default** | 47626                     |
|                      | **Minimum** | 10                        |
|                      | **Maximum** | 65535                     |

### `mysql-server_version`

The server version with which the proxy will respond to the clients. Note that regardless of the versions of
the backend servers, the proxy will respond with this.

|                      |             |                      |
| -------------------- | ----------- | -------------------- |
| **System Variable**  | **Name**    | mysql-server_version |
|                      | **Dynamic** | Yes                  |
| **Permitted Values** | **Type**    | String               |
|                      | **Default** | 5.5.30               |

### `mysql-servers_stats`

Currently unused. Will be removed in a future version.

|                      |             |                     |
| -------------------- | ----------- | ------------------- |
| **System Variable**  | **Name**    | mysql-servers_stats |
|                      | **Dynamic** | Yes                 |
| **Permitted Values** | **Type**    | Boolean             |
|                      | **Default** | true                |

### `mysql-session_debug`

`DEPRECATED`

|                      |             |                     |
| -------------------- | ----------- | ------------------- |
| **System Variable**  | **Name**    | mysql-session_debug |
|                      | **Dynamic** | Yes                 |
| **Permitted Values** | **Type**    | Boolean             |
|                      | **Default** | true                |

### `mysql-session_idle_ms`

Starting from v1.3.0 , each MySQL_Thread has an auxiliary thread that is responsible to handle idle sessions
(client connections). `mysql-session_idle_ms` defines when a session is idle and is passed from the main
thread to the auxiliary thread.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | mysql-session_idle_ms  |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | Integer (milliseconds) |
|                      | **Default** | 1                      |
|                      | **Minimum** | 1                      |
|                      | **Maximum** | 3600000                |

### `mysql-session_idle_show_processlist`

`mysql-session_idle_show_processlist` defines if an idle session (as defined by `mysql-session_idle_ms`)
should be listed in `SHOW PROCESSLIST` (or in general, in `stats_mysql_processlist` table). For performance
reasons, idle sessions are not listed by default.

|                      |             |                                     |
| -------------------- | ----------- | ----------------------------------- |
| **System Variable**  | **Name**    | mysql-session_idle_show_processlist |
|                      | **Dynamic** | Yes                                 |
| **Permitted Values** | **Type**    | Boolean                             |
|                      | **Default** | false                               |

### `mysql-sessions_sort`

Sessions are conversations between a MySQL client and a backend server in the proxy. Sessions are generally
processed in a stable order but in certain scenarios (like using a transaction workload, which makes sessions
bind to certain MySQL connections from the pool), processing them in the same order leads to starvation. This
variable controls whether sessions should be processed in the order of waiting time, in order to have a more
balanced distribution of traffic among sessions.

|                      |             |                     |
| -------------------- | ----------- | ------------------- |
| **System Variable**  | **Name**    | mysql-sessions_sort |
|                      | **Dynamic** | Yes                 |
| **Permitted Values** | **Type**    | Boolean             |
|                      | **Default** | true                |

### `mysql-set_parser_algorithm`

Controls which parsing algorithm ProxySQL uses to process MySQL `SET` statements for session variable
tracking. This variable determines how ProxySQL parses and handles client `SET` commands.

ProxySQL supports two parsing algorithms for handling `SET` statements:

-   **Value `1`**: Legacy parser algorithm using a simple hardcoded regular expression pattern
-   **Value `2`**: Enhanced parser algorithm using a dynamically generated comprehensive pattern (default)

**Algorithm Comparison:**

**Legacy Algorithm (1):**

-   Uses a simple hardcoded regex pattern
-   Compiles regex fresh for each parse
-   Fast for simple statements
-   May fail on complex `SET` statements with function calls or nested expressions

**Enhanced Algorithm (2):**

-   Uses dynamically generated regex pattern built at runtime
-   Pre-compiles regex pattern per thread for better performance
-   Handles complex `SET` statements including:
    -   Function calls: `REPLACE()`, `IFNULL()`, `CONCAT()`, etc.
    -   Nested function calls
    -   Various quoting styles and escape sequences
    -   Session variables (`@@variablename`, `@variablename`)
    -   Multi-word values with commas and parentheses
-   Better compatibility with modern MySQL `SET` statement syntax

**Use Cases:**

Both algorithms handle simple statements like:

```sql
SET character_set_client='utf8mb4';
SET names latin1;
SET sql_mode='STRICT_TRANS_TABLES';
SET @@session.tx_isolation='READ-COMMITTED';
```

However, Algorithm 2 is required for complex statements like:

```sql
SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT'));
SET sql_mode=REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', '');
SET session_track_gtids=OWN_GTID;
```

**Migration Note:** The default changed from `1` to `2` in ProxySQL 2.6.0. Most users should use the default
value (2) unless experiencing specific compatibility issues with complex `SET` statements.

|                      |               |                            |
| -------------------- | ------------- | -------------------------- |
| **System Variable**  | **Name**      | mysql-set_parser_algorithm |
|                      | **Dynamic**   | Yes                        |
| **Permitted Values** | **Type**      | Integer                    |
|                      | **Default**   | 2                          |
|                      | **Min Value** | 1                          |
|                      | **Max Value** | 2                          |

### `mysql-set_query_lock_on_hostgroup`

ProxySQL tries to track all the session variables configured by the client using `SET` statements. If the
tracking of session variables is successful, ProxySQL is able to configure the same session variables on all
the backend connections that will run queries by that specific client. ProxySQL is unable to track variables
in the following conditions:

-   multi-statements commands. Example: `SET variable=value; SELECT ...`
-   user defined variables (all)
-   session variables not tracked by ProxySQL

<!-- -->

`mysql-set_query_lock_on_hostgroup` determines the behavior of ProxySQL if unable to parse a `SET` statement,
or to track all of its variables.

-   `1`: (default since version 2.0.6) both multiplexing and query routing is disabled. The client will remain
    bound to a single backend connection. ProxySQL does it for safety purposes, making the connection to
    ProxySQL works exactly the same as it was connected direct to MySQL, so it avoids many unexpected
    behaviors. In other words, any `SET` statement that ProxySQL doesn't understand or is unable to parse, it
    will disable multiplexing and routing. It is important to remember that routing is disabled: if a query
    rule tries to route traffic to a hostgroup different than the hostgroup where the client is locked into,
    an error will arise.
-   `0`: this is the legacy behavior, and generally less safe. Because multiplexing and routing are not
    disabled, this creates a problem if a future query relies on a previously set variable. In fact, the
    variable is unlikely to be present in the backend connection because multiplexing and routing were enabled
    but ProxySQL was not able to track the needed variable

Note: this variable only disables query routing and multiplexing. This means that the queries' destination
hostgroup will be fixed to the current session hostgroup. No other features of ProxySQL are impacted.

<!-- -->

|                      |             |                                   |
| -------------------- | ----------- | --------------------------------- |
| **System Variable**  | **Name**    | mysql-set_query_lock_on_hostgroup |
|                      | **Dynamic** | Yes                               |
| **Permitted Values** | **Type**    | Boolean                           |
|                      | **Default** | true                              |

### `mysql-show_processlist_extended`

Configured to 1 or 2, ProxySQL will show extended information in JSON format about the processes running.
Information will be available in stats_mysql_processlist.extended_info . With value 2 the JSON output will be
indented.

|                      |             |                                 |
| -------------------- | ----------- | ------------------------------- |
| **System Variable**  | **Name**    | mysql-show_processlist_extended |
|                      | **Dynamic** | Yes                             |
| **Permitted Values** | **Type**    | Integer                         |
|                      | **Default** | 0                               |
|                      | **Minimum** | 0                               |
|                      | **Maximum** | 2                               |

### `mysql-shun_on_failures`

The number of connection errors tolerated to the same server within an interval of 1 second until it is
automatically shunned temporarily. For now, this cannot be disabled by setting it to a special value, so if
you want to do that, you can increase it to a very large value.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | mysql-shun_on_failures |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | Integer                |
|                      | **Default** | 5                      |
|                      | **Minimum** | 0                      |
|                      | **Maximum** | 10000000               |

### `mysql-shun_recovery_time_sec`

A backend server that has been automatically shunned will be recovered after at least this amount of time.
ProxySQL will not retry to use such a server again until at least the amount of time specified has passed.
Note that a server will only be recognized as `ONLINE` again by ProxySQL if it starts handling client traffic:
when a server is `ONLINE`, it is considered to be absolutely healthy - something that a connection check (via
ping) alone cannot determine. However, once the amount of time specified has passed, the server will be
automatically recognized as `ONLINE` again right before it starts serving at least one client connection. Self
tuning:

-   `mysql-shun_recovery_time_sec` should always be less than `mysql-connect_timeout_server_max/1000`, in
    order to prevent that a server is taken out for so long that an error is returned to the client. If
    `mysql-shun_recovery_time_sec` > `mysql-connect_timeout_server_max/1000`, the smaller of the two is used.
    (See #530)
-   if only one server is present in a hostgroup and `mysql-shun_recovery_time_sec` > `1`, the server is
    automatically brought back online after 1 second

<!-- -->

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | mysql-shun_recovery_time_sec |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer (seconds)            |
|                      | **Default** | 10                           |
|                      | **Minimum** | 0                            |
|                      | **Maximum** | 31536000                     |

### `mysql-ssl_p2s_ca`

SSL CA to be used for backend connections.

|                      |             |                  |
| -------------------- | ----------- | ---------------- |
| **System Variable**  | **Name**    | mysql-ssl_p2s_ca |
|                      | **Dynamic** | Yes              |
| **Permitted Values** | **Type**    | String           |
|                      | **Default** |                  |

### `mysql-ssl_p2s_capath`

Defines a path to a directory containing the PEM files that holds one x509 certificate for a Certificate
Authority (CA) to use for backend connections.

|                      |             |                      |
| -------------------- | ----------- | -------------------- |
| **System Variable**  | **Name**    | mysql-ssl_p2s_capath |
|                      | **Dynamic** | Yes                  |
| **Permitted Values** | **Type**    | String               |
|                      | **Default** |                      |

### `mysql-ssl_p2s_cert`

SSL Certificate to be used for backend connections.

|                      |             |                    |
| -------------------- | ----------- | ------------------ |
| **System Variable**  | **Name**    | mysql-ssl_p2s_cert |
|                      | **Dynamic** | Yes                |
| **Permitted Values** | **Type**    | String             |
|                      | **Default** |                    |

### `mysql-ssl_p2s_cipher`

SSL Cipher to be used for backend connections (MySQL CIPHER list can be found [here][53]).

|                      |             |                      |
| -------------------- | ----------- | -------------------- |
| **System Variable**  | **Name**    | mysql-ssl_p2s_cipher |
|                      | **Dynamic** | Yes                  |
| **Permitted Values** | **Type**    | String               |
|                      | **Default** |                      |

### `mysql-ssl_p2s_key`

SSL Key to be used for backend connections.

|                      |             |                   |
| -------------------- | ----------- | ----------------- |
| **System Variable**  | **Name**    | mysql-ssl_p2s_key |
|                      | **Dynamic** | Yes               |
| **Permitted Values** | **Type**    | String            |
|                      | **Default** |                   |

### `mysql-ssl_p2s_crl`

Path to a PEM file that should contain one or more revoked X509 certificates for backend connections.

|                      |             |                   |
| -------------------- | ----------- | ----------------- |
| **System Variable**  | **Name**    | mysql-ssl_p2s_crl |
|                      | **Dynamic** | Yes               |
| **Permitted Values** | **Type**    | String            |
|                      | **Default** |                   |

### `mysql-ssl_p2s_crlpath`

Defines a path to a directory containing the PEM files that holds one x509 certificate revoked for backend
connections.

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | mysql-ssl_p2s_crlpath |
|                      | **Dynamic** | Yes                   |
| **Permitted Values** | **Type**    | String                |
|                      | **Default** |                       |

### `mysql-stacksize`

The stack size to be used with the background threads that the proxy uses to handle MySQL traffic and connect
to the backends. Note that changing this value has no effect at runtime, if you need to change it you have to
restart the proxy.

|                      |             |                 |
| -------------------- | ----------- | --------------- |
| **System Variable**  | **Name**    | mysql-stacksize |
|                      | **Dynamic** | Yes             |
| **Permitted Values** | **Type**    | Integer (bytes) |
|                      | **Default** | 1048576         |
|                      | **Minimum** | 262144          |
|                      | **Maximum** | 4194304         |

### `mysql-stats_time_backend_query`

Enables / disables collection of backend query CPU time statistics.

|                      |                                  |                                |
| -------------------- | -------------------------------- | ------------------------------ |
| **System Variable**  | **Name**                         | mysql-stats_time_backend_query |
|                      | **Dynamic**                      | Yes                            |
| **Permitted Values** | **Type**                         | Boolean                        |
|                      | **Default (up to 1.4.3)**        | true                           |
|                      | **Default (from 1.4.4 onwards)** | false                          |

### `mysql-stats_time_query_processor`

Enables / disables collection of query processor CPU time statistics.

|                      |                                  |                                  |
| -------------------- | -------------------------------- | -------------------------------- |
| **System Variable**  | **Name**                         | mysql-stats_time_query_processor |
|                      | **Dynamic**                      | Yes                              |
| **Permitted Values** | **Type**                         | Boolean                          |
|                      | **Default (up to 1.4.3)**        | true                             |
|                      | **Default (from 1.4.4 onwards)** | false                            |

### `mysql-tcp_keepalive_time`

When mysql-use_tcp_keepalive is active, ProxySQL will start sending KeepAlive to the destination after the
connection has been idle for tcp_keepalive_time seconds

|                      |             |                          |
| -------------------- | ----------- | ------------------------ |
| **System Variable**  | **Name**    | mysql-tcp_keepalive_time |
|                      | **Dynamic** | Yes                      |
| **Permitted Values** | **Type**    | Integer (seconds)        |
|                      | **Default** | 0                        |

### `mysql-fast_forward_grace_close_ms`

Configures the grace period timeout in milliseconds for fast forward mode session closure. When a backend
connection closes unexpectedly during fast forward mode, this variable controls how long ProxySQL will wait to
allow pending client output buffers to drain before forcibly closing the session.

This prevents data loss that can occur when clients are still receiving query results but the backend
connection terminates abruptly.

|                      |               |                                   |
| -------------------- | ------------- | --------------------------------- |
| **System Variable**  | **Name**      | mysql-fast_forward_grace_close_ms |
|                      | **Dynamic**   | Yes                               |
| **Permitted Values** | **Type**      | Integer                           |
|                      | **Default**   | 5000                              |
|                      | **Min Value** | 0                                 |
|                      | **Max Value** | 3600000                           |

### `mysql-use_tcp_keepalive`

When active ProxySQL will send KeepAlive signal during the client open session.

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | mysql-use_tcp_keepalive |
|                      | **Dynamic** | Yes                     |
| **Permitted Values** | **Type**    | Boolean                 |
|                      | **Default** | false                   |

### `mysql-unshun_algorithm`

Introduced in v2.4.0. Allows to specify the behavior for how servers that have been automatically shunned
should be unshunned. This variable relates to [mysql-shun_recovery_time_sec][16]. Current values are:

-   `0` = default behavior, only servers from hostgroup handling traffic are unshunned.
-   `1` = when a server is unshunned in one particular hostgroup, it's also unshunned in all the other
    hostgroups.

<!-- -->

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | mysql-unshun_algorithm |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | Integer                |
|                      | **Default** | 0                      |
|                      | **Minimum** | 0                      |
|                      | **Maximum** | 1                      |

### `mysql-threads`

The number of background threads that ProxySQL uses in order to process MySQL traffic. Note that there are
other "administrative" threads on top of these, such as:

-   the admin interface thread
-   the monitoring module threads that interact with the backend servers (one for monitoring connectivity, one
    for pinging the servers and one for monitoring the replication lag)
-   occasional temporary threads created in order to kill long running queries that have become unresponsive
-   background threads used by the libmariadbclient library in order to make certain interactions with MySQL
    servers async

<!-- -->

Note that changing this value has no effect at runtime, if you need to change it you have to restart the
proxy. After changing `mysql-threads`, you should not run `LOAD MYSQL VARIABLES TO RUNTIME` because this
variable cannot be loaded at runtime. Attempt to load them at runtime will cause their reset. In other words,
after changing `mysql-threads`, you need to run `SAVE MYSQL VARIABLES TO DISK` and then restart ProxySQL (for
example using `PROXYSQL RESTART`).

|                      |             |               |
| -------------------- | ----------- | ------------- |
| **System Variable**  | **Name**    | mysql-threads |
|                      | **Dynamic** | No            |
| **Permitted Values** | **Type**    | Integer       |
|                      | **Default** | 4             |
|                      | **Minimum** | 1             |
|                      | **Maximum** | 255           |

### `mysql-threshold_query_length`

The maximal size of an incoming SQL query to the proxy that will mark the background MySQL connection as
non-reusable. This will force the proxy to open a new connection to the backend server, in order to make sure
that the memory footprint of the server stays within reasonable limits. More details about it here:
[https://dev.mysql.com/doc/refman/5.6/en/memory-use.html][54] Relevant quote from the mysqld documentation:
"The connection buffer and result buffer each begin with a size equal to net_buffer_length bytes, but are
dynamically enlarged up to max_allowed_packet bytes as needed. The result buffer shrinks to net_buffer_length
bytes after each SQL statement."

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | mysql-threshold_query_length |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Integer (bytes)              |
|                      | **Default** | 524288                       |
|                      | **Minimum** | 1024                         |
|                      | **Maximum** | 1073741824                   |

### `mysql-threshold_resultset_size`

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | mysql-threshold_resultset_size |
|                      | **Dynamic** | Yes                            |
| **Permitted Values** | **Type**    | Integer (bytes)                |
|                      | **Default** | 4194304 (4MB)                  |
|                      | **Minimum** | 1024                           |
|                      | **Maximum** | 1073741824                     |

Default value: `4194304` (bytes, the equivalent of 4 MB).

If a resultset returned by a backend server is bigger than this, ProxySQL will start sending the result to the
MySQL client that was requesting the result in order to limit its memory footprint.

This threshold is also used to throttle data reading from backend connections. If this threshold is exceeded
**8 times** during resultset reading in a backend connection, resultset reading will be temporarily paused.
Pausing will continue until the buffered data by the session is less than **4 times** this threshold. When
this buffered data (to be sent to the client) goes below the previously mentioned threshold (**4 times** this
threshold), resultset reading from the session backend connection will be resumed.

**Considerations**:

-   [Query Cache][2] wont take effect for any resultsets that exceed this value. Since the resultset is never
    fully retain, but streamed to the client it's not possible to store it in the cache.
-   [mysql-query_retries_on_failure][55] wont take effect for resultsets that exceed this value. Query
    retrying is disabled for resultsets that have already started streaming to the frontend connection.
    Setting the value of this setting too low is not recommended for this reason.

### `mysql-throttle_connections_per_sec_to_hostgroup`

|                      |             |                                                 |
| -------------------- | ----------- | ----------------------------------------------- |
| **System Variable**  | **Name**    | mysql-throttle_connections_per_sec_to_hostgroup |
|                      | **Dynamic** | Yes                                             |
| **Permitted Values** | **Type**    | Integer                                         |
|                      | **Default** | 1000000                                         |

This variable limits the number of new connections per hostgroup, and not per specific node, for its
per-hostgroup counterpart see `throttle_connections_per_sec` field in [mysql_hostgroup_attributes][1]. For
example, if `mysql-throttle_connections_per_sec_to_hostgroup` is set to `100`, no more than `100` new
connections can be created on any hostgroup no matter the number of servers in that hostgroup. The default is
very high (1000000) thus not changing default behaviour. Tuning this variable allows to control and throttle
connections spikes to the backend servers. This variable is also related with the status variable
_Server_Connections_delayed_, which is a counter on how many times the `Hostgroups Manager` didn't return a
connection because the limit was reached. It is worth to note that a single client request could make multiple
requests, therefore this variable counts the number of times a new connection wasn't created and not how many
requests were delayed.

Whenever this limit is exceeded in a hostgroup, the client connection will wait at most
[mysql-connect_timeout_server_max][14]. Passed that threshold the client connection will be disconnected if it
wasn't able to obtain a connection.

### `mysql-throttle_max_bytes_per_second_to_client`

|                      |             |                                               |
| -------------------- | ----------- | --------------------------------------------- |
| **System Variable**  | **Name**    | mysql-throttle_max_bytes_per_second_to_client |
|                      | **Dynamic** | Yes                                           |
| **Permitted Values** | **Type**    | Integer                                       |
|                      | **Default** | 0                                             |

Imposes a threshold with the maximum number of bytes that can be sent to a client, per second. The sending of
the remaining bytes will be resumed the next second. When imposing a maximum number of bytes to send to the
client is interesting to also impose a ratio of the memory being read from backend connections, see
[mysql-throttle_ratio_server_to_client][56].

### `mysql-throttle_ratio_server_to_client`

|                      |             |                                       |
| -------------------- | ----------- | ------------------------------------- |
| **System Variable**  | **Name**    | mysql-throttle_ratio_server_to_client |
|                      | **Dynamic** | Yes                                   |
| **Permitted Values** | **Type**    | Integer                               |
|                      | **Default** | 0                                     |

**Important**: Takes effect only when enabled together with variable
[mysql-throttle_max_bytes_per_second_to_client][57], otherwise this variable has no effect.

Imposes a throttling ratio in the number of bytes that ProxySQL reads at once from backend connections. This
offers a way to control the amount of memory that `ProxySQL` retains when throttling is imposed for client
connections, allowing to prevent spikes in memory usage. This ratio is determined by the following expression:

```
processed_bytes > (throttle_max_bytes_per_second_to_client/(10 * throttle_ratio_server_to_client))
```

Whenever the number of bytes found while reading from a resultset in a backend connection exceeds the imposed
ratio, further processing of the async store operation will be pause until newer sockets events or poll
timeout, see [mysql-poll_timeout][58]. When imposing a `throttle_ratio_server_to_client` of `1`, this ratio
would be `1/10` of `throttle_max_bytes_per_second_to_client`.

### `mysql-verbose_query_error`

When active ProxySQL will print additional information in case of error like: user, schema,digest_text,
address, port.

|                      |             |                           |
| -------------------- | ----------- | ------------------------- |
| **System Variable**  | **Name**    | mysql-verbose_query_error |
|                      | **Dynamic** | Yes                       |
| **Permitted Values** | **Type**    | Boolean                   |
|                      | **Default** | false                     |

### `mysql-wait_timeout`

If a proxy session (which is a conversation between a MySQL client and a ProxySQL) has been idle for more than
this threshold, the proxy will kill the session.

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | mysql-wait_timeout     |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | Integer (milliseconds) |
|                      | **Default** | 28800000 (8 hours)     |
|                      | **Minimum** | 0                      |
|                      | **Maximum** | 1728000000             |

[1]: /main-runtime/#mysql_hostgroup_attributes
[2]: /query-cache
[3]: /audit-log/
[4]: #mysql-auditlog_filesize
[5]: #mysql-auditlog_filename
[6]: /multiplexing/
[7]: #mysql-auto_increment_delay_multiplex
[8]: https://proxysql.com/sql-injection-engine/
[9]: #mysql-client_host_error_counts
[10]: #mysql-client_host_cache_size
[11]: /stats-statistics/#stats_mysql_commands_counters
[12]: #mysql-connect_retries_on_failure
[13]: #mysql-connect_retries_delay
[14]: #mysql-connect_timeout_server_max
[15]: #mysql-connect_timeout_server
[16]: #mysql-shun_recovery_time_sec
[17]: /multiplexing/
[18]: #mysql-connection_delay_multiplex_ms
[19]: https://github.com/sysown/proxysql/issues/1861
[20]: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake.html
[21]: /authentication-methods
[22]: #mysql-have_ssl
[23]: https://dev.mysql.com/doc/dev/mysql-server/latest/page_caching_sha2_authentication_exchanges.html
[24]: #mysql-default_charset
[25]: #mysql-default_collation_connection
[26]: /main-runtime/#mysql_collations
[27]: /main-runtime/#mysql_servers
[28]: /main-runtime/#mysql_query_rules
[29]: #mysql-default_query_delay
[30]: #mysql-default_query_timeout
[31]: #mysql-default_variables
[32]: /Multiplexing
[33]: https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html#gaad8e6e886899e90e820d6c2e0248469d
[34]: https://proxysql.com/Documentation/Query-Logging/
[35]: https://proxysql.com/firewall-whitelist/
[36]: https://github.com/sysown/proxysql/issues/3253
[37]: https://proxysql.com/main-runtime/#mysql_hostgroup_attributes
[38]: #mysql-query_digests
[39]: #mysql-log_mysql_warnings_enabled
[40]: #mysql-query_digests_keep_comment
[41]: /SSL-Support
[42]: #mysql-default_authentication_plugin
[43]: http://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_max_allowed_packet
[44]: #mysql-mirror_max_queue_length
[45]: #mysql-mirror_max_concurrency
[46]: /main-runtime#mysql_query_rules
[47]: #mysql-query_digests_max_query_length
[48]: https://proxysql.com/stats-statistics/#stats_mysql_query_digest
[49]: http://www.pcre.org/
[50]: https://github.com/google/re2
[51]: #mysql-threshold_resultset_size
[52]: https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags
[53]: https://dev.mysql.com/doc/refman/8.0/en/encrypted-connection-protocols-ciphers.html
[54]: https://dev.mysql.com/doc/refman/5.6/en/memory-use.html
[55]: #mysql-query_retries_on_failure
[56]: #mysql-throttle_ratio_server_to_client
[57]: #mysql-throttle_max_bytes_per_second_to_client
[58]: #mysql-poll_timeout
[59]: /query_annotations/
[60]: /proxy-protocol/

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
