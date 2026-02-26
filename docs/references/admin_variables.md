# Admin Variables

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## List of Admin Variables

NOTE: You can click on the variable name to jump to its definition

<!-- remark-ignore-start -->

| Variable Name                                                                                           | Default Value     |
| ------------------------------------------------------------------------------------------------------- | ----------------- |
| [admin-admin_credentials](#admin-admin_credentials)                                                     | admin:admin       |
| [admin-checksum_admin_variables](#admin-checksum_admin_variables)                                       | true              |
| [admin-checksum_ldap_variables](#admin-checksum_ldap_variables)                                         | true              |
| [admin-checksum_mysql_query_rules](#admin-checksum_mysql_query_rules)                                   | true              |
| [admin-checksum_mysql_servers](#admin-checksum_mysql_servers)                                           | true              |
| [admin-checksum_mysql_users](#admin-checksum_mysql_users)                                               | true              |
| [admin-checksum_mysql_variables](#admin-checksum_mysql_variables)                                       | true              |
| [admin-cluster_admin_variables_diffs_before_sync](#admin-cluster_admin_variables_diffs_before_sync)     | 3                 |
| [admin-cluster_admin_variables_save_to_disk](#admin-cluster_admin_variables_save_to_disk)               | true              |
| [admin-cluster_check_interval_ms](#admin-cluster_check_interval_ms)                                     | 1000              |
| [admin-cluster_check_status_frequency](#admin-cluster_check_status_frequency)                           | 10                |
| [admin-cluster_ldap_variables_diffs_before_sync](#admin-cluster_ldap_variables_diffs_before_sync)       | 3                 |
| [admin-cluster_ldap_variables_save_to_disk](#admin-cluster_ldap_variables_save_to_disk)                 | true              |
| [admin-cluster_mysql_query_rules_diffs_before_sync](#admin-cluster_mysql_query_rules_diffs_before_sync) | 3                 |
| [admin-cluster_mysql_query_rules_save_to_disk](#admin-cluster_mysql_query_rules_save_to_disk)           | true              |
| [admin-cluster_mysql_servers_diffs_before_sync](#admin-cluster_mysql_servers_diffs_before_sync)         | 3                 |
| [admin-cluster_mysql_servers_save_to_disk](#admin-cluster_mysql_servers_save_to_disk)                   | true              |
| [admin-cluster_mysql_users_diffs_before_sync](#admin-cluster_mysql_users_diffs_before_sync)             | 3                 |
| [admin-cluster_mysql_users_save_to_disk](#admin-cluster_mysql_users_save_to_disk)                       | true              |
| [admin-cluster_mysql_variables_diffs_before_sync](#admin-cluster_mysql_variables_diffs_before_sync)     | 3                 |
| [admin-cluster_mysql_variables_save_to_disk](#admin-cluster_mysql_variables_save_to_disk)               | true              |
| [admin-cluster_password](#admin-cluster_password)                                                       |                   |
| [admin-cluster_proxysql_servers_diffs_before_sync](#admin-cluster_proxysql_servers_diffs_before_sync)   | 3                 |
| [admin-cluster_proxysql_servers_save_to_disk](#admin-cluster_proxysql_servers_save_to_disk)             | true              |
| [admin-cluster_username](#admin-cluster_username)                                                       |                   |
| [admin-debug](#admin-debug)                                                                             | false             |
| [admin-pgsql_ifaces](#admin-pgsql_ifaces)                                                               | 0.0.0.0:6132      |
| [admin-hash_passwords (deprecated)](#admin-hash_passwords-deprecated)                                   | true              |
| [admin-mysql_ifaces](#admin-mysql_ifaces)                                                               | 0.0.0.0:6032      |
| [admin-prometheus_memory_metrics_interval](#admin-prometheus_memory_metrics_interval)                   | 61                |
| [admin-read_only](#admin-read_only)                                                                     | false             |
| [admin-refresh_interval](#admin-refresh_interval)                                                       | 2000              |
| [admin-restapi_enabled](#admin-restapi_enabled)                                                         | false             |
| [admin-restapi_port](#admin-restapi_enabled)                                                            | 6070              |
| [admin-stats_credentials](#admin-stats_credentials)                                                     | stats:stats       |
| [admin-stats_mysql_connection_pool](#admin-stats_mysql_connection_pool)                                 | 60                |
| [admin-stats_mysql_connections](#admin-stats_mysql_connections)                                         | 60                |
| [admin-stats_mysql_query_cache](#admin-stats_mysql_query_cache)                                         | 60                |
| [admin-stats_mysql_query_digest_to_disk](#admin-stats_mysql_query_digest_to_disk)                       | 0                 |
| [admin-stats_system_cpu](#admin-stats_system_cpu)                                                       | 60                |
| [admin-stats_system_memory](#admin-stats_system_memory)                                                 | 60                |
| [admin-telnet_admin_ifaces](#admin-telnet_admin_ifaces)                                                 | (null)            |
| [admin-telnet_stats_ifaces](#admin-telnet_stats_ifaces)                                                 | (null)            |
| [admin-vacuum_stats](#admin-vacuum_stats)                                                               | true              |
| [admin-version](#admin-version)                                                                         | X.Y.Z-N-gXXXXXXXX |
| [admin-web_enabled](#admin-web_enabled)                                                                 | false             |
| [admin-web_port](#admin-web_port)                                                                       | 6080              |

<!-- remark-ignore-end -->

### `admin-admin_credentials`

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | admin-admin_credentials |
|                      | **Dynamic** | Yes                     |
| **Permitted Values** | **Type**    | String                  |
|                      | **Default** | admin:admin             |

This is a list of semi-colon separated `user:password` pairs, that can be used to authenticate to the admin
interface with read-write rights. For read-only credentials that can be used to connect to the admin, see the
variable [admin-stats_credentials][1]. It is important to note that:

- the admin interface listens on separate IPs/ports than the main ProxySQL worker threads. Those IPs/ports are
  controlled through the variable [admin-mysql_ifaces][2]
- ProxySQL Cluster connects to Admin using the credentials defined in [admin-cluster_username][3] and
  [admin-cluster_password][4]. To allow Cluster to connect to this instance, the credentials need to also be
  present in [admin-admin_credentials][5]
- To connect to Web UI, one should use credentials defined either in [admin-admin_credentials][5] or
  [admin-stats_credentials][1]

<!-- -->

- For security reasons, the default `admin` user can only connect locally, regardless of its password. In
  order to connect remotely a secondary user needs to be created by defining this in the
  [admin-admin_credentials][5] variable E.G. `admin-admin_credentials="admin:admin;radminuser:radminpass"`.
- users defined in [admin-admin_credentials][5] or [admin-stats_credentials][1] cannot be used also in
  [mysql_users][6] table.

<!-- -->

### `admin-checksum_admin_variables`

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | admin-checksum_admin_variables |
|                      | **Dynamic** | Yes                            |
| **Permitted Values** | **Type**    | Boolean                        |
|                      | **Default** | true                           |

If enabled, [Admin variables][7] will be synchronized by ProxySQL Cluster. See [ProxySQL Cluster][8] for
further details.

### `admin-checksum_ldap_variables`

|                      |             |                               |
| -------------------- | ----------- | ----------------------------- |
| **System Variable**  | **Name**    | admin-checksum_ldap_variables |
|                      | **Dynamic** | Yes                           |
| **Permitted Values** | **Type**    | Boolean                       |
|                      | **Default** | true                          |

If enabled, LDAP variables will be synchronized by ProxySQL Cluster. Note that this variable is meaningful
only if LDAP Plugin is enabled. See [ProxySQL Cluster][8] for further details.

### `admin-checksum_mysql_query_rules`

|                      |             |                                  |
| -------------------- | ----------- | -------------------------------- |
| **System Variable**  | **Name**    | admin-checksum_mysql_query_rules |
|                      | **Dynamic** | Yes                              |
| **Permitted Values** | **Type**    | Boolean                          |
|                      | **Default** | true                             |

If enabled, tables [mysql_query_rules][9] and [mysql_query_rules_fast_routing][10] will be synchronized by
ProxySQL Cluster. See [ProxySQL Cluster][8] for further details.

### `admin-checksum_mysql_servers`

|                      |             |                              |
| -------------------- | ----------- | ---------------------------- |
| **System Variable**  | **Name**    | admin-checksum_mysql_servers |
|                      | **Dynamic** | Yes                          |
| **Permitted Values** | **Type**    | Boolean                      |
|                      | **Default** | true                         |

If enabled, tables [mysql_servers][11], [mysql_aws_aurora_hostgroups][12], [mysql_galera_hostgroups][13],
[mysql_group_replication_hostgroups][14] and [mysql_replication_hostgroups][15] will be synchronized by
ProxySQL Cluster. See [ProxySQL Cluster][8] for further details.

### `admin-checksum_mysql_users`

|                      |             |                            |
| -------------------- | ----------- | -------------------------- |
| **System Variable**  | **Name**    | admin-checksum_mysql_users |
|                      | **Dynamic** | Yes                        |
| **Permitted Values** | **Type**    | Boolean                    |
|                      | **Default** | true                       |

If enabled, table [mysql_users][16] will be synchronized by ProxySQL Cluster. See [ProxySQL Cluster][8] for
further details.

### `admin-checksum_mysql_variables`

|                      |             |                                |
| -------------------- | ----------- | ------------------------------ |
| **System Variable**  | **Name**    | admin-checksum_mysql_variables |
|                      | **Dynamic** | Yes                            |
| **Permitted Values** | **Type**    | Boolean                        |
|                      | **Default** | true                           |

If enabled, MySQL variables (both [General MySQL Variables][17] and [MySQL Monitor Variables][18] will be
synchronized by ProxySQL Cluster. See [ProxySQL Cluster][8] for further details.

### `admin-cluster_admin_variables_diffs_before_sync`

|                      |             |                                                 |
| -------------------- | ----------- | ----------------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_admin_variables_diffs_before_sync |
|                      | **Dynamic** | Yes                                             |
| **Permitted Values** | **Type**    | Integer (count)                                 |
|                      | **Default** | 3                                               |
|                      | **Minimum** | 0                                               |
|                      | **Maximum** | 1000                                            |

This variable defines how many mismatching checks will trigger the synchronization of Admin variables. See
[admin-checksum_admin_variables][19] and [ProxySQL Cluster][8] for further details.

### `admin-cluster_ldap_variables_save_to_disk`

|                      |             |                                            |
| -------------------- | ----------- | ------------------------------------------ |
| **System Variable**  | **Name**    | admin-cluster_admin_variables_save_to_disk |
|                      | **Dynamic** | Yes                                        |
| **Permitted Values** | **Type**    | Boolean                                    |
|                      | **Default** | true                                       |

If enabled (default), after ProxySQL Cluster synchronizes Admin variables \*\*from\*\* a remote node, the
configuration is also locally persisted to disk. See [admin-checksum_admin_variables][19] and [ProxySQL
Cluster][8] for further details.

### `admin-cluster_check_interval_ms`

See [ProxySQL Cluster][8]

### `admin-cluster_check_status_frequency`

See [ProxySQL Cluster][8]

### `admin-cluster_ldap_variables_diffs_before_sync`

|                      |             |                                                |
| -------------------- | ----------- | ---------------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_ldap_variables_diffs_before_sync |
|                      | **Dynamic** | Yes                                            |
| **Permitted Values** | **Type**    | Integer (count)                                |
|                      | **Default** | 3                                              |
|                      | **Minimum** | 0                                              |
|                      | **Maximum** | 1000                                           |

This variable defines how many mismatching checks will trigger the synchronization of LDAP variables. See
[admin-checksum_ldap_variables][20] and [ProxySQL Cluster][8] for further details. Note: this variable is
relevant only if LDAP Plugin is enabled.

### `admin-cluster_ldap_variables_save_to_disk`

|                      |             |                                           |
| -------------------- | ----------- | ----------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_ldap_variables_save_to_disk |
|                      | **Dynamic** | Yes                                       |
| **Permitted Values** | **Type**    | Boolean                                   |
|                      | **Default** | true                                      |

If enabled (default), after ProxySQL Cluster synchronizes LDAP variables \*\*from\*\* a remote node, the
configuration is also locally persisted to disk. See [admin-checksum_ldap_variables][20] and [ProxySQL
Cluster][8] for further details. Note: this variable is relevant only if LDAP Plugin is enabled.

### `admin-cluster_mysql_query_rules_diffs_before_sync`

|                      |             |                                                   |
| -------------------- | ----------- | ------------------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_mysql_query_rules_diffs_before_sync |
|                      | **Dynamic** | Yes                                               |
| **Permitted Values** | **Type**    | Integer (count)                                   |
|                      | **Default** | 3                                                 |
|                      | **Minimum** | 0                                                 |
|                      | **Maximum** | 1000                                              |

This variable defines how many mismatching checks will trigger the synchronization of MySQL Query Rules
related tables. See [admin-checksum_mysql_query_rules][21] and [ProxySQL Cluster][8] for further details.

### `admin-cluster_mysql_query_rules_save_to_disk`

|                      |             |                                              |
| -------------------- | ----------- | -------------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_mysql_query_rules_save_to_disk |
|                      | **Dynamic** | Yes                                          |
| **Permitted Values** | **Type**    | Boolean                                      |
|                      | **Default** | true                                         |

If enabled (default), after ProxySQL Cluster synchronizes MySQL Query Rules tables \*\*from\*\* a remote node,
the configuration is also locally persisted to disk. See [admin-checksum_mysql_query_rules][21] and [ProxySQL
Cluster][8] for further details.

### `admin-cluster_mysql_servers_diffs_before_sync`

|                      |             |                                               |
| -------------------- | ----------- | --------------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_mysql_servers_diffs_before_sync |
|                      | **Dynamic** | Yes                                           |
| **Permitted Values** | **Type**    | Integer (count)                               |
|                      | **Default** | 3                                             |
|                      | **Minimum** | 0                                             |
|                      | **Maximum** | 1000                                          |

This variable defines how many mismatching checks will trigger the synchronization of MySQL Servers related
tables. See [admin-checksum_mysql_servers][22] and [ProxySQL Cluster][8] for further details.

### `admin-cluster_mysql_servers_save_to_disk`

|                      |             |                                          |
| -------------------- | ----------- | ---------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_mysql_servers_save_to_disk |
|                      | **Dynamic** | Yes                                      |
| **Permitted Values** | **Type**    | Boolean                                  |
|                      | **Default** | true                                     |

If enabled (default), after ProxySQL Cluster synchronizes MySQL Servers tables \*\*from\*\* a remote node, the
configuration is also locally persisted to disk. See [admin-checksum_mysql_servers][22] and [ProxySQL
Cluster][8] for further details.

### `admin-cluster_mysql_users_diffs_before_sync`

|                      |             |                                             |
| -------------------- | ----------- | ------------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_mysql_users_diffs_before_sync |
|                      | **Dynamic** | Yes                                         |
| **Permitted Values** | **Type**    | Integer (count)                             |
|                      | **Default** | 3                                           |
|                      | **Minimum** | 0                                           |
|                      | **Maximum** | 1000                                        |

This variable defines how many mismatching checks will trigger the synchronization of MySQL Users related
tables. See [admin-checksum_mysql_servers][23] and [ProxySQL Cluster][8] for further details.

### `admin-cluster_mysql_users_save_to_disk`

|                      |             |                                        |
| -------------------- | ----------- | -------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_mysql_users_save_to_disk |
|                      | **Dynamic** | Yes                                    |
| **Permitted Values** | **Type**    | Boolean                                |
|                      | **Default** | true                                   |

If enabled (default), after ProxySQL Cluster synchronizes MySQL Users tables \*\*from\*\* a remote node, the
configuration is also locally persisted to disk. See [admin-checksum_mysql_users][23] and [ProxySQL
Cluster][8] for further details.

### `admin-cluster_password`

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | admin-cluster_password |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | String                 |
|                      | **Default** | (empty string)         |

In order for [ProxySQL Cluster][24] to work, instances need to connect to each other to perform checks and
eventually pull new configuration(s). Credentials defined in [admin-cluster_username][3] and
[admin-cluster_password][4] are used to connect to the remote ProxySQL nodes that are part of the cluster.
Note that the same credentials must also be present in the variable [admin-admin_credentials][5] of the remote
ProxySQL nodes, or the current node won't be able to connect.

### `admin-cluster_proxysql_servers_diffs_before_sync`

|                      |             |                                                  |
| -------------------- | ----------- | ------------------------------------------------ |
| **System Variable**  | **Name**    | admin-cluster_proxysql_servers_diffs_before_sync |
|                      | **Dynamic** | Yes                                              |
| **Permitted Values** | **Type**    | Integer (count)                                  |
|                      | **Default** | 3                                                |
|                      | **Minimum** | 0                                                |
|                      | **Maximum** | 1000                                             |

This variable defines how many mismatching checks will trigger the synchronization of [proxysql_servers][25]
table. See [ProxySQL Cluster][8] for further details.

### `admin-cluster_mysql_servers_save_to_disk`

|                      |             |                                             |
| -------------------- | ----------- | ------------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_proxysql_servers_save_to_disk |
|                      | **Dynamic** | Yes                                         |
| **Permitted Values** | **Type**    | Boolean                                     |
|                      | **Default** | true                                        |

If enabled (default), after ProxySQL Cluster synchronizes [ProxySQL Servers table][25] \*\*from\*\* a remote
node, the configuration is also locally persisted to disk. See [ProxySQL Cluster][8] for further details.

### `admin-cluster_mysql_variables_diffs_before_sync`

|                      |             |                                                 |
| -------------------- | ----------- | ----------------------------------------------- |
| **System Variable**  | **Name**    | admin-cluster_mysql_variables_diffs_before_sync |
|                      | **Dynamic** | Yes                                             |
| **Permitted Values** | **Type**    | Integer (count)                                 |
|                      | **Default** | 3                                               |
|                      | **Minimum** | 0                                               |
|                      | **Maximum** | 1000                                            |

This variable defines how many mismatching checks will trigger the synchronization of MySQL variables. See
[admin-checksum_mysql_variables][26] and [ProxySQL Cluster][8] for further details.

### `admin-cluster_mysql_variables_save_to_disk`

|                      |             |                                            |
| -------------------- | ----------- | ------------------------------------------ |
| **System Variable**  | **Name**    | admin-cluster_mysql_variables_save_to_disk |
|                      | **Dynamic** | Yes                                        |
| **Permitted Values** | **Type**    | Boolean                                    |
|                      | **Default** | true                                       |

If enabled (default), after ProxySQL Cluster synchronizes MySQL variables \*\*from\*\* a remote node, the
configuration is also locally persisted to disk. See [admin-checksum_mysql_variables][26] and [ProxySQL
Cluster][8] for further details.

### `admin-cluster_username`

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | admin-cluster_username |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | String                 |
|                      | **Default** | (empty string)         |

In order for [ProxySQL Cluster][24] to work, instances need to connect to each other to perform checks and
eventually pull new configuration(s). Credentials defined in [admin-cluster_username][3] and
[admin-cluster_password][4] are used to connect to the remote ProxySQL nodes that are part of the cluster.
Note that the same credentials must also be present in the variable [admin-admin_credentials][5] of the remote
ProxySQL nodes, or the current node won't be able to connect. If [admin-cluster_username][3] is empty (the
default) , [ProxySQL Cluster][24] cannot start because there is no defined user to connect to remote ProxySQL
nodes.

### `admin-debug`

|                      |             |             |
| -------------------- | ----------- | ----------- |
| **System Variable**  | **Name**    | admin-debug |
|                      | **Dynamic** | Yes         |
| **Permitted Values** | **Type**    | Boolean     |
|                      | **Default** | false       |

This variable enables the debugging in `proxysql` binaries built in debug mode. Note that this variable is
only present in debug builds, therefore you shouldn't see this variable in a production environment.

### `admin-pgsql_ifaces`

|                      |             |                    |
| -------------------- | ----------- | ------------------ |
| **System Variable**  | **Name**    | admin-pgsql_ifaces |
|                      | **Dynamic** | Yes                |
| **Permitted Values** | **Type**    | String             |
|                      | **Default** | 0.0.0.0:6132       |

Semicolon-separated list of `hostname:port` entries for interfaces on which the `Admin` interface should
listen for `PostgreSQL` clients. It also supports UNIX domain sockets for the cases where the connection is
done from an application on the same machine: in this case the full path of the socket must be specified. For
example: `SET admin-pgsql_ifaces='127.0.0.1:6132;/tmp/proxysql_admin.sock'`.

Please note that the default `admin` user can only connect locally for security reasons. In order to connect
remotely a secondary user needs to be created by defining this in the [admin-admin_credentials][5] variable,
for example `admin-admin_credentials="admin:admin;radminuser:radminpass"`.

### `admin-hash_passwords` (deprecated)

Deprecated in `2.6.0`. Prior to this version:

|                      |             |                      |
| -------------------- | ----------- | -------------------- |
| **System Variable**  | **Name**    | admin-hash_passwords |
|                      | **Dynamic** | Yes                  |
| **Permitted Values** | **Type**    | Boolean              |
|                      | **Default** | true                 |

When `admin-hash_passwords=true` (enabled by default), passwords are automatically hashed at RUNTIME when
running `LOAD MYSQL USERS TO RUNTIME`. Passwords in [mysql_users][16] table are not automatically hashed (they
are hashed only in [runtime_mysql_users][27]) and require you to run `SAVE MYSQL USERS FROM RUNTIME`. Also
note that if on the backend the user is configured to use `caching_sha2_password`, passwords in
`mysql_users.password` need to be in clear text (not hashed), therefore variable [admin-hash_passwords][28]
needs to be set to `false`. See [Password Management][29] for further details.

Since version `2.6.0` users should be able set the passwords as they prefer, either `hashed` or in
`clear text` in `mysql_users` table. For furhter details on how this is achieved please refer to [Password
Management][29].

### `admin-mysql_ifaces`

|                      |                                  |                    |
| -------------------- | -------------------------------- | ------------------ |
| **System Variable**  | **Name**                         | admin-mysql_ifaces |
|                      | **Dynamic**                      | Yes                |
| **Permitted Values** | **Type**                         | String             |
|                      | **Default (up to 1.4.0)**        | 127.0.0.1:6032     |
|                      | **Default (from 1.4.1 onwards)** | 0.0.0.0:6032       |

Semicolon-separated list of `hostname:port` entries for interfaces on which the `Admin` interface should
listen for `MySQL` clients. It also supports UNIX domain sockets for the cases where the connection is done
from an application on the same machine: in this case the full path of the socket must be specified. For
example: `SET admin-mysql_ifaces='127.0.0.1:6132;/tmp/proxysql_admin.sock'`.

Please note that the default `admin` user can only connect locally for security reasons. In order to connect
remotely a secondary user needs to be created by defining this in the [admin-admin_credentials][5] variable,
for example `admin-admin_credentials="admin:admin;radminuser:radminpass"`.

### `admin-prometheus_memory_metrics_interval`

**Minimum**61**Maximum**61

|                      |             |                                          |
| -------------------- | ----------- | ---------------------------------------- |
| **System Variable**  | **Name**    | admin-prometheus_memory_metrics_interval |
|                      | **Dynamic** | Yes                                      |
| **Permitted Values** | **Type**    | Integer (seconds)                        |
|                      | **Default** | 61                                       |
|                      | **Minimum** | 0                                        |
|                      | **Maximum** |                                          |

ProxySQL has a built-in [Prometheus Exporter][30] that is able to export statistics when the [REST API][31] is
enabled. Metrics are collected all the time no matter if the REST API is enabled or not. While some metrics
are collected and refreshed in real time, some metrics (currently only memory metrics) are collected and
refreshed only at regular intervals defined by [admin-prometheus_memory_metrics_interval][32] .

### `admin-read_only`

|                      |             |                 |
| -------------------- | ----------- | --------------- |
| **System Variable**  | **Name**    | admin-read_only |
|                      | **Dynamic** | Yes             |
| **Permitted Values** | **Type**    | Boolean         |
|                      | **Default** | false           |

When this variable is set to true and loaded at runtime, the Admin module does not accept writes anymore. This
is useful to ensure that ProxySQL cannot be further configured. When ProxySQL Admin is in read-only mode, the
only way to revert it to read-write and set [admin-read_only][33] to false at runtime (and therefore also make
the Admin module writable again) is to run the command `PROXYSQL READWRITE`. Note that this feature is mostly
useful for future development of new features, and you shouldn't normally configure ProxySQL Admin to be in
read-only mode.

### `admin-refresh_interval`

|                      |             |                        |
| -------------------- | ----------- | ---------------------- |
| **System Variable**  | **Name**    | admin-refresh_interval |
|                      | **Dynamic** | Yes                    |
| **Permitted Values** | **Type**    | Integer (milliseconds) |
|                      | **Default** | 2000                   |
|                      | **Minimum** | 100                    |
|                      | **Maximum** | 100000                 |

In very old versions this variable defined the refresh interval (in milliseconds) for updates to the query
rules statistics and commands counters statistics. Now this variable only defines the timeout for `poll()`
calls, thus for how long an Admin connection can be blocked waiting for a network event. Be careful about
tweaking this to a value that is:

- too low, because it might affect the overall performance of the proxy if there are a a lot (several
  thousands) of Admin connections
- too high, because it might affect the graceful shutdown of proxysql if some Admin connections are blocked
  for a long time

<!-- -->

This variable is likely to be deprecated in the future.

### `admin-restapi_enabled`

|                      |             |                       |
| -------------------- | ----------- | --------------------- |
| **System Variable**  | **Name**    | admin-restapi_enabled |
|                      | **Dynamic** | Yes                   |
| **Permitted Values** | **Type**    | Boolean               |
|                      | **Default** | false                 |

It allows users to create new [REST API][34] endpoints and execute scripts on behalf of ProxySQL. If
`admin-restapi_enabled` is set to `true`, the REST-API is automatically enabled and the module is listening on
port [admin-restapi_port][35]

### `admin-restapi_port`

|                      |             |                    |
| -------------------- | ----------- | ------------------ |
| **System Variable**  | **Name**    | admin-restapi_port |
|                      | **Dynamic** | Yes                |
| **Permitted Values** | **Type**    | Integer            |
|                      | **Default** | 6070               |

This variable defines on which port the [REST API][34] is listening if the REST API module is enabled.
([admin-restapi_enabled][36]='true') .

### `admin-stats_credentials`

|                      |             |                         |
| -------------------- | ----------- | ----------------------- |
| **System Variable**  | **Name**    | admin-stats_credentials |
|                      | **Dynamic** | Yes                     |
| **Permitted Values** | **Type**    | String                  |
|                      | **Default** | stats:stats             |

This is a list of semi-colon separated `user:password` pairs that defines the read-only credentials for
connecting to the admin interface. These are not allowed to update internal data structures such as the list
of MySQL backend servers (or hostgroups), query rules, etc., neither to read configuration tables. They are
only allowed to read from the statistics and monitoring tables. Note: there are several restrictions on use of
users in `admin-stats_credentials` : the restrictions are the same as those listed in
[admin-admin_credentials][5]

### `admin-telnet_admin_ifaces`

Not currently used (planned usage in a future version).

### `admin-telnet_stats_ifaces`

Not currently used (planned usage in a future version).

### `admin-version`

|                      |               |               |
| -------------------- | ------------- | ------------- |
| **System Variable**  | **Name**      | admin-version |
|                      | **Dynamic**   | No            |
| **Permitted Values** | **Type**      | String        |
|                      | **Read Only** | true          |

This variable displays ProxySQL version. This variable is read only: do not attempt to change it.

## Admin historical statistics

Since ProxySQL Admin stores historical metrics in a new database named `proxysql_stats.db` in the datadir.
Tables structures may be subject to future changes.

### `admin-stats_mysql_connection_pool`

|                      |                  |                                   |
| -------------------- | ---------------- | --------------------------------- |
| **System Variable**  | **Name**         | admin-stats_mysql_connection_pool |
|                      | **Dynamic**      | Yes                               |
| **Permitted Values** | **Type**         | Integer (seconds)                 |
|                      | **Default**      | 60                                |
|                      | **Valid values** | 5, 10, 30, 60, 120, 300           |

The refresh interval (in seconds) to update the historical statistics of the connection pool.

### `admin-stats_mysql_connections`

|                      |                  |                               |
| -------------------- | ---------------- | ----------------------------- |
| **System Variable**  | **Name**         | admin-stats_mysql_connections |
|                      | **Dynamic**      | Yes                           |
| **Permitted Values** | **Type**         | Integer (seconds)             |
|                      | **Default**      | 60                            |
|                      | **Valid values** | 5, 10, 30, 60, 120, 300       |

The refresh interval (in seconds) to update the historical statistics of MySQL connections, both frontends and
backends.

### `admin-stats_mysql_query_cache`

|                      |                  |                               |
| -------------------- | ---------------- | ----------------------------- |
| **System Variable**  | **Name**         | admin-stats_mysql_query_cache |
|                      | **Dynamic**      | Yes                           |
| **Permitted Values** | **Type**         | Integer (seconds)             |
|                      | **Default**      | 60                            |
|                      | **Valid values** | 5, 10, 30, 60, 120, 300       |

The refresh interval (in seconds) to update the historical statistics of MySQL Query Cache.

### `admin-stats_mysql_digest_to_disk`

**Maximum**86400 (24 hours)

|                      |             |                                        |
| -------------------- | ----------- | -------------------------------------- |
| **System Variable**  | **Name**    | admin-stats_mysql_query_digest_to_disk |
|                      | **Dynamic** | Yes                                    |
| **Permitted Values** | **Type**    | Integer (seconds)                      |
|                      | **Default** | 0                                      |
|                      | **Minimum** | 0                                      |

The refresh interval (in seconds) to dump the content of [stats_mysql_query_digest][37] into
`stats_history.history_mysql_query_digest` , and reset `stats_mysql_query_digest` . A value of 0 (default)
disables this feature. If the feature is enabled, please be very careful on how frequently the dump is
performed and how many distinct query patterns your application is generating: the size of the database on
disk can potentially grow quickly.

### `admin-stats_system_cpu`

|                      |                  |                              |
| -------------------- | ---------------- | ---------------------------- |
| **System Variable**  | **Name**         | admin-stats_system_cpu       |
|                      | **Dynamic**      | Yes                          |
| **Permitted Values** | **Type**         | Integer (seconds)            |
|                      | **Default**      | 60                           |
|                      | **Valid values** | 5, 10, 30, 60, 120, 300, 600 |

The refresh interval (in seconds) to update the historical statistics of CPU usage.

### `admin-stats_system_memory`

|                      |                  |                              |
| -------------------- | ---------------- | ---------------------------- |
| **System Variable**  | **Name**         | admin-stats_system_memory    |
|                      | **Dynamic**      | Yes                          |
| **Permitted Values** | **Type**         | Integer (seconds)            |
|                      | **Default**      | 60                           |
|                      | **Valid values** | 5, 10, 30, 60, 120, 300, 600 |

The refresh interval (in seconds) to update the historical statistics of memory usage. _Note_: These
statistics are not available if ProxySQL is not compiled with jemalloc. Note that all official packages are
compiled with jemalloc.

### `admin-vacuum_stats`

|                      |                  |                    |
| -------------------- | ---------------- | ------------------ |
| **System Variable**  | **Name**         | admin-vacuum_stats |
|                      | **Dynamic**      | Yes                |
| **Permitted Values** | **Type**         | Boolean (seconds)  |
|                      | **Default**      | true               |
|                      | **Valid values** | true, false        |

This parameter enables or disables the vacuum operation on the SQLite database storing the statistics tables.
VACUUM command cleans and eliminates free pages, aligns table data to be contiguous, and otherwise cleans up
the database memory structure. This allows to free memory when large statistics tables are queried. Note that
this applies only to statistics tables: all the tables with name starting with `stats_` and stored in memory.

# Admin web interface

ProxySQL embeds an HTTP web server from where it is possible to gather certain metrics. Credentials to access
the web interfaces are the same as those defined in [admin-stats_credentials][38]. When Web UI plugin is
enabled, the HTTP web server can be used to reconfigure ProxySQL itself, and the credentials configured in
[admin-admin_credentials][39] can be used to access the web interface.

### `admin-web_enabled`

|                      |             |                   |
| -------------------- | ----------- | ----------------- |
| **System Variable**  | **Name**    | admin-web_enabled |
|                      | **Dynamic** | Yes               |
| **Permitted Values** | **Type**    | Boolean           |
|                      | **Default** | false             |

If `admin-web_enabled` is set to `true`, the web server is automatically enabled and listening on port
[admin-web_port][40]. The web server can be turned on and off at runtime.

### `admin-web_port`

|                      |             |                |
| -------------------- | ----------- | -------------- |
| **System Variable**  | **Name**    | admin-web_port |
|                      | **Dynamic** | Yes            |
| **Permitted Values** | **Type**    | Integer        |
|                      | **Default** | 6080           |

This variable defines on which port the web server is listening if [admin-web_enabled][41] is set to `true`

### `admin-web_verbosity`

|                      |             |                     |
| -------------------- | ----------- | ------------------- |
| **System Variable**  | **Name**    | admin-web_verbosity |
|                      | **Dynamic** | Yes                 |
| **Permitted Values** | **Type**    | Integer             |
|                      | **Default** | 0                   |
| **Minimum**          | 0           |                     |
| **Maximum**          | 10          |                     |

This variable defines the verbosity level of the web server if it is active ([admin-web_enabled][41] is set to
`true`) . The verbosity level is used for debugging purposes only.

[1]: #admin-stats_credentials
[2]: #admin-mysql_ifaces
[3]: #admin-cluster_username
[4]: #admin-cluster_password
[5]: #admin-admin_credentials
[6]: /mysql_users
[7]: /global-variables/admin-variables/
[8]: /Proxysql-Cluster
[9]: /main-runtime/#mysql_query_rules
[10]: /main-runtime/#mysql_query_rules_fast_routing
[11]: /main-runtime/#mysql_servers
[12]: /main-runtime/#mysql_aws_aurora_hostgroups
[13]: /main-runtime/#mysql_galera_hostgroups
[14]: /main-runtime/#mysql_group_replication_hostgroups
[15]: /main-runtime/#mysql_replication_hostgroups
[16]: /main-runtime/#mysql_users
[17]: /global-variables/mysql-variables/
[18]: /global-variables/mysql-monitor-variables/
[19]: #admin-checksum_admin_variables
[20]: #admin-checksum_ldap_variables
[21]: #admin-checksum_mysql_query_rules
[22]: #admin-checksum_mysql_servers
[23]: #admin-checksum_mysql_users
[24]: /ProxySQL-Cluster
[25]: /main-runtime/#proxysql_servers
[26]: #admin-checksum_mysql_variables
[27]: /main-runtime/#runtime_mysql_users
[28]: #admin-hash_password
[29]: /Password-management#variable_admin_hash_passwords
[30]: /prometheus-exporter/
[31]: /REST-API/
[32]: #admin-prometheus_memory_metrics_interval
[33]: #admin-read_only
[34]: /REST-API
[35]: #admin_restapi_port
[36]: #admin_restapi_enabled
[37]: /stats-statistics/#stats_mysql_query_digest
[38]: #admin_stats_credentials
[39]: #admin_admin_credentials
[40]: #admin-web_port
[41]: #admin_web_enabled

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
