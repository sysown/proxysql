# ProxySQL Cluster

## Overview

ProxySQL is a decentralized proxy designed to scale horizontally. While you can manage ProxySQL nodes individually using configuration management tools (Ansible, Chef, etc.), the **ProxySQL Cluster** feature provides a native, peer-to-peer synchronization mechanism.

This feature ensures that configuration changes (users, servers, rules, etc.) are automatically propagated across all nodes in the cluster, providing consistent behavior and simplifying administration.

---

## Key Concepts

### Cluster Roles

A ProxySQL cluster consists of nodes acting in one of two roles:

1. **Core Nodes**: These are the primary nodes that hold and propagate the "Source of Truth." They are explicitly defined in each other's `proxysql_servers` table.
2. **Satellite Nodes**: These nodes fetch configuration from Core nodes but do not propagate changes themselves.

### Source of Truth
ProxySQL uses a versioning and epoch-based system to identify the most recent configuration. When you execute a `LOAD ... TO RUNTIME` command on a Core node, its version number increases, signaling to other nodes that a new "Source of Truth" is available for synchronization.

---

## What is Synchronized?

ProxySQL Cluster can synchronize the following configuration modules:

- **Global Variables**: Both Admin and MySQL variables.
- **MySQL Servers**: Including hostgroups and SSL parameters.
- **MySQL Users**: Credentials and attributes.
- **Query Rules**: Routing and rewriting policies.
- **ProxySQL Servers**: The list of Core nodes themselves.

---

## How Synchronization Works

The cluster uses a **pull-based** mechanism triggered by checksum mismatches.

### 1. Change Detection
Each node periodically checks the global configuration checksum of its peers. A mismatch indicates that a module has changed.

### 2. Grace Period
Before pulling data, a node waits for a consistent mismatch (defined by `diffs_before_sync` variables). This prevents unnecessary reconfigurations during transient network states.

### 3. Data Fetching
Once the threshold is reached, the local node performs a series of `SELECT` statements against the remote peer's `runtime_` tables to retrieve the new configuration.

### 4. Activation & Persistence
The fetched data is loaded into the local memory and activated via an internal `LOAD` command. If configured, it is also automatically saved to the local disk.

---

## Monitoring the Cluster

You can monitor the health and synchronization status of the cluster via the `stats` schema:

- **`stats_proxysql_servers_checksums`**: Shows the configuration versions and checksums of all known peers.
- **`stats_proxysql_servers_metrics`**: Displays real-time performance metrics (uptime, queries, latency) for other nodes.
- **`runtime_checksums_values`**: Shows the local node's current configuration versions.

---

## Next Steps

- **[Cluster Commands](./cluster_commands)**: Learn how to manage nodes and join the cluster.
- **[Admin Cluster Variables](./cluster_variables)**: Fine-tune synchronization intervals and thresholds.
- **[Admin Commands](../the_admin_schemas/admin_commands)**: Reference for the core `LOAD` and `SAVE` commands.