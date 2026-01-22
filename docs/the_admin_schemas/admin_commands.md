# Admin Commands

ProxySQL uses a multi-layer configuration system consisting of the **Configuration File**, **Disk Database**, **Main (Memory) Database**, and the **Runtime** data structures. Moving configuration between these layers is handled via `LOAD` and `SAVE` commands.

## Configuration Layers

1. **RUNTIME**: The internal data structures used by ProxySQL threads to process traffic. This is the only layer that actively affects proxy behavior.
2. **MEMORY (Main)**: The `main` SQLite database. This is where you make changes using standard SQL (`UPDATE`, `INSERT`, `DELETE`).
3. **DISK**: The `disk` SQLite database. This is used for persistence across ProxySQL restarts.
4. **CONFIG FILE**: The static `proxysql.cnf` file used for initial bootstrapping.

---

## Command Syntax Patterns

Commands generally follow these patterns for each module:

- `LOAD <MODULE> TO RUNTIME`: Copies configuration from **MEMORY** to **RUNTIME**.
- `SAVE <MODULE> TO DISK`: Copies configuration from **MEMORY** to **DISK**.
- `LOAD <MODULE> FROM DISK`: Copies configuration from **DISK** to **MEMORY**.
- `SAVE <MODULE> TO MEMORY`: Copies configuration from **RUNTIME** to **MEMORY** (useful for inspecting auto-discovered state).

---

## Supported Modules

### MySQL Configuration
Commands related to MySQL users, servers, and query rules.

| Module | Runtime | Disk | Memory |
| :--- | :--- | :--- | :--- |
| **MYSQL SERVERS** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |
| **MYSQL USERS** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |
| **MYSQL QUERY RULES** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |
| **MYSQL VARIABLES** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |

*Note: `LOAD MYSQL SERVERS` also loads replication hostgroups.*

### PostgreSQL Configuration (v3.0+)
Commands related to PostgreSQL users, servers, and query rules.

| Module | Runtime | Disk | Memory |
| :--- | :--- | :--- | :--- |
| **PGSQL SERVERS** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |
| **PGSQL USERS** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |
| **PGSQL QUERY RULES** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |
| **PGSQL VARIABLES** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |

### Generative AI / MCP (v4.0+)
Commands related to the Model Context Protocol server.

| Module | Runtime | Disk | Memory |
| :--- | :--- | :--- | :--- |
| **MCP QUERY RULES** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |
| **MCP VARIABLES** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |
| **GENAI VARIABLES** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |

### Core Admin & System
Commands related to the Admin interface itself and the scheduler.

| Module | Runtime | Disk | Memory |
| :--- | :--- | :--- | :--- |
| **ADMIN VARIABLES** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |
| **SCHEDULER** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |
| **PROXYSQL SERVERS** | `LOAD ... TO RUNTIME` | `SAVE ... TO DISK` | `SAVE ... TO MEMORY` |

---

## Specialized Commands

### Cluster Synchronization
If ProxySQL Cluster is enabled, many of these commands will automatically trigger synchronization across all nodes in the cluster.

### CONFIG File Loading
To reload configuration from the static config file into the **MEMORY** layer:
- `LOAD <MODULE> FROM CONFIG` (e.g., `LOAD MYSQL SERVERS FROM CONFIG`)

### Checksum Verification
To verify consistency between layers:
- `CHECKSUM <LAYER> <MODULE>` (e.g., `CHECKSUM DISK MYSQL QUERY RULES`)
