# Cluster Commands

Managing the list of nodes in a ProxySQL Cluster is handled through the `proxysql_servers` table and a specific set of Admin commands.

## Managing Cluster Nodes

The `proxysql_servers` table defines the **Core** nodes of the cluster. Unlike other modules, managing these nodes requires specific commands to move the configuration from the `main` database into the active cluster module.

### Core Commands

| Action | Command |
| :--- | :--- |
| **Activate Nodes** | `LOAD PROXYSQL SERVERS TO RUNTIME` |
| **Persist Nodes** | `SAVE PROXYSQL SERVERS TO DISK` |
| **Revert from Disk** | `LOAD PROXYSQL SERVERS FROM DISK` |
| **Inspect Runtime** | `SAVE PROXYSQL SERVERS TO MEMORY` |
| **Reset from Config** | `LOAD PROXYSQL SERVERS FROM CONFIG` |

:::info
**Note**: To let other ProxySQL instances know that there is a new node, you must add the new node's details into the `proxysql_servers` table of at least one existing node and issue `LOAD PROXYSQL SERVERS TO RUNTIME`.
:::

---

## Workflow: Adding a Node to the Cluster

1.  **Start the new node**: Ensure it has the correct inter-node credentials.
2.  **Add to an existing node**: On any active **Core** node, insert the new node's details:
    ```sql
    INSERT INTO proxysql_servers (hostname, port) VALUES ('10.0.0.5', 6032);
    ```
3.  **Activate**:
    ```sql
    LOAD PROXYSQL SERVERS TO RUNTIME;
    ```
4.  **Propagate**: The cluster will automatically detect the change and propagate the new list of nodes to all other members (assuming `admin-cluster_proxysql_servers_diffs_before_sync` is met).
5.  **Verify**: Check the `stats_proxysql_servers_checksums` table to ensure the node is seen by its peers.

---
**See also**:
- [The Multi-Layer Configuration System](../main_runtime/multi_layer_configuration)
- [Admin Commands](../the_admin_schemas/admin_commands)
- [ProxySQL Cluster Overview](./proxysql-cluster)
