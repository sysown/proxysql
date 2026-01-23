# Admin Cluster Variables

ProxySQL Cluster is managed through a set of specialized variables within the **Admin** module. Because they belong to the Admin module, any changes to these variables must be activated using the standard Admin module commands.

:::info
**Critical Note**: Cluster variables are part of the Admin variables group. Moving them between layers (Memory, Disk, and Runtime) is performed using the `LOAD ADMIN VARIABLES TO RUNTIME` and `SAVE ADMIN VARIABLES TO DISK` commands.
:::

## inter-node Credentials

In order for ProxySQL Cluster to work, instances need to connect to each other to perform health checks and pull configuration updates.

| Variable Name | Default Value | Description |
| :--- | :--- | :--- |
| [admin-cluster_username](#admin-cluster_username) | (empty) | Username for inter-node communication. |
| [admin-cluster_password](#admin-cluster_password) | (empty) | Password for inter-node communication. |

### `admin-cluster_username`
### `admin-cluster_password`
These credentials are used by the current node to authenticate against other ProxySQL nodes in the cluster.
**Requirement**: These same credentials **must** be present in the `admin-admin_credentials` list of every node in the cluster.

---

## Checks & Intervals

| Variable Name | Default Value | Description |
| :--- | :--- | :--- |
| [admin-cluster_check_interval_ms](#admin-cluster_check_interval_ms) | 1000 | Interval between checksum comparisons. |
| [admin-cluster_check_status_frequency](#admin-cluster_check_status_frequency) | 10 | Frequency of detailed status checks. |

### `admin-cluster_check_interval_ms`
Defines how often (in milliseconds) the cluster module compares configuration checksums with its peers.

### `admin-cluster_check_status_frequency`
Defines after how many checksum checks a detailed `status check` (`SHOW MYSQL STATUS`) is performed on peers.

---

## Synchronization Thresholds

These variables define the "grace period" before a local node decides to synchronize a module from a peer.

| Variable | Default | Module Affected |
| :--- | :--- | :--- |
| `admin-cluster_mysql_servers_diffs_before_sync` | 3 | MySQL Servers & Hostgroups |
| `admin-cluster_mysql_users_diffs_before_sync` | 3 | MySQL Users |
| `admin-cluster_mysql_query_rules_diffs_before_sync` | 3 | MySQL Query Rules |
| `admin-cluster_mysql_variables_diffs_before_sync` | 3 | MySQL Global Variables |
| `admin-cluster_admin_variables_diffs_before_sync` | 3 | Admin Variables |
| `admin-cluster_proxysql_servers_diffs_before_sync` | 3 | ProxySQL Cluster Nodes |

---

## Configuration Persistence

| Variable | Default | Description |
| :--- | :--- | :--- |
| `admin-cluster_<module>_save_to_disk` | true | Automatically persist synced data to local DISK. |

If enabled, ProxySQL will automatically execute a `SAVE <MODULE> TO DISK` after successfully fetching and loading a new configuration from a peer.

---
**Apply your changes**: Remember to use the appropriate **[Admin Commands](../the_admin_schemas/admin_commands)** to activate and persist your cluster configuration.