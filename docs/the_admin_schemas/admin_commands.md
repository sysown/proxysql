# Admin Commands

ProxySQL uses a multi-layer configuration system consisting of the **Configuration File**, **Disk Database**, **Main (Memory) Database**, and the **Runtime** data structures. Moving configuration between these layers is handled via `LOAD` and `SAVE` commands.

## Table of Contents
- [Configuration Layers](#configuration-layers)
- [MySQL Commands](#mysql-commands)
- [PostgreSQL Commands (v3.0+)](#postgresql-commands-v30)
- [Generative AI & MCP Commands (v4.0+)](#generative-ai--mcp-commands-v40)
- [Core Admin & System Commands](#core-admin--system-commands)
- [Specialized Commands](#specialized-commands)

## Configuration Layers

ProxySQL employs a unique architecture to manage its configuration. For a detailed explanation of why this system exists and how the layers interact, see **[The Multi-Layer Configuration System](../main_runtime/multi_layer_configuration)**.

---

## MySQL Commands

### MySQL Servers & Hostgroups
- `LOAD MYSQL SERVERS TO RUNTIME` (or `TO RUN`)
- `SAVE MYSQL SERVERS TO DISK`
- `LOAD MYSQL SERVERS FROM DISK`
- `SAVE MYSQL SERVERS TO MEMORY` (or `TO MEM`)
- `LOAD MYSQL SERVERS FROM MEMORY` (or `FROM MEM`)
- `LOAD MYSQL SERVERS FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

### MySQL Users
- `LOAD MYSQL USERS TO RUNTIME` (or `TO RUN`)
- `SAVE MYSQL USERS TO DISK`
- `LOAD MYSQL USERS FROM DISK`
- `SAVE MYSQL USERS TO MEMORY` (or `TO MEM`)
- `LOAD MYSQL USERS FROM MEMORY` (or `FROM MEM`)
- `LOAD MYSQL USERS FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

### MySQL Query Rules
- `LOAD MYSQL QUERY RULES TO RUNTIME` (or `TO RUN`)
- `SAVE MYSQL QUERY RULES TO DISK`
- `LOAD MYSQL QUERY RULES FROM DISK`
- `SAVE MYSQL QUERY RULES TO MEMORY` (or `TO MEM`)
- `LOAD MYSQL QUERY RULES FROM MEMORY` (or `FROM MEM`)
- `LOAD MYSQL QUERY RULES FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

### MySQL Variables
- `LOAD MYSQL VARIABLES TO RUNTIME` (or `TO RUN`)
- `SAVE MYSQL VARIABLES TO DISK`
- `LOAD MYSQL VARIABLES FROM DISK`
- `SAVE MYSQL VARIABLES TO MEMORY` (or `TO MEM`)
- `LOAD MYSQL VARIABLES FROM MEMORY` (or `FROM MEM`)
- `LOAD MYSQL VARIABLES FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

---

## PostgreSQL Commands (v3.0+)

### PostgreSQL Servers
- `LOAD PGSQL SERVERS TO RUNTIME` (or `TO RUN`)
- `SAVE PGSQL SERVERS TO DISK`
- `LOAD PGSQL SERVERS FROM DISK`
- `SAVE PGSQL SERVERS TO MEMORY` (or `TO MEM`)
- `LOAD PGSQL SERVERS FROM MEMORY` (or `FROM MEM`)
- `LOAD PGSQL SERVERS FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

### PostgreSQL Users
- `LOAD PGSQL USERS TO RUNTIME` (or `TO RUN`)
- `SAVE PGSQL USERS TO DISK`
- `LOAD PGSQL USERS FROM DISK`
- `SAVE PGSQL USERS TO MEMORY` (or `TO MEM`)
- `LOAD PGSQL USERS FROM MEMORY` (or `FROM MEM`)
- `LOAD PGSQL USERS FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

### PostgreSQL Query Rules
- `LOAD PGSQL QUERY RULES TO RUNTIME` (or `TO RUN`)
- `SAVE PGSQL QUERY RULES TO DISK`
- `LOAD PGSQL QUERY RULES FROM DISK`
- `SAVE PGSQL QUERY RULES TO MEMORY` (or `TO MEM`)
- `LOAD PGSQL QUERY RULES FROM MEMORY` (or `FROM MEM`)
- `LOAD PGSQL QUERY RULES FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

### PostgreSQL Variables
- `LOAD PGSQL VARIABLES TO RUNTIME` (or `TO RUN`)
- `SAVE PGSQL VARIABLES TO DISK`
- `LOAD PGSQL VARIABLES FROM DISK`
- `SAVE PGSQL VARIABLES TO MEMORY` (or `TO MEM`)
- `LOAD PGSQL VARIABLES FROM MEMORY` (or `FROM MEM`)
- `LOAD PGSQL VARIABLES FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

---

## Generative AI & MCP Commands (v4.0+)

### MCP Query Rules
- `LOAD MCP QUERY RULES TO RUNTIME` (or `TO RUN`)
- `SAVE MCP QUERY RULES TO DISK`
- `LOAD MCP QUERY RULES FROM DISK`
- `SAVE MCP QUERY RULES TO MEMORY` (or `TO MEM`)
- `LOAD MCP QUERY RULES FROM MEMORY` (or `FROM MEM`)

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

### MCP Variables
- `LOAD MCP VARIABLES TO RUNTIME` (or `TO RUN`)
- `SAVE MCP VARIABLES TO DISK`
- `LOAD MCP VARIABLES FROM DISK`
- `SAVE MCP VARIABLES TO MEMORY` (or `TO MEM`)
- `LOAD MCP VARIABLES FROM MEMORY` (or `FROM MEM`)
- `LOAD MCP VARIABLES FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

### GENAI Variables
- `LOAD GENAI VARIABLES TO RUNTIME` (or `TO RUN`)
- `SAVE GENAI VARIABLES TO DISK`
- `LOAD GENAI VARIABLES FROM DISK`
- `SAVE GENAI VARIABLES TO MEMORY` (or `TO MEM`)
- `LOAD GENAI VARIABLES FROM MEMORY` (or `FROM MEM`)
- `LOAD GENAI VARIABLES FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

---

## Core Admin & System Commands

### Admin Variables
- `LOAD ADMIN VARIABLES TO RUNTIME` (or `TO RUN`)
- `SAVE ADMIN VARIABLES TO DISK`
- `LOAD ADMIN VARIABLES FROM DISK`
- `SAVE ADMIN VARIABLES TO MEMORY` (or `TO MEM`)
- `LOAD ADMIN VARIABLES FROM MEMORY` (or `FROM MEM`)
- `LOAD ADMIN VARIABLES FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

### ProxySQL Servers (Cluster Nodes)
- `LOAD PROXYSQL SERVERS TO RUNTIME` (or `TO RUN`)
- `SAVE PROXYSQL SERVERS TO DISK`
- `LOAD PROXYSQL SERVERS FROM DISK`
- `SAVE PROXYSQL SERVERS TO MEMORY` (or `TO MEM`)
- `LOAD PROXYSQL SERVERS FROM MEMORY` (or `FROM MEM`)
- `LOAD PROXYSQL SERVERS FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

### Scheduler
- `LOAD SCHEDULER TO RUNTIME` (or `TO RUN`)
- `SAVE SCHEDULER TO DISK`
- `LOAD SCHEDULER FROM DISK`
- `SAVE SCHEDULER TO MEMORY` (or `TO MEM`)
- `LOAD SCHEDULER FROM MEMORY` (or `FROM MEM`)
- `LOAD SCHEDULER FROM CONFIG`

*See [Multi-Layer Configuration](../main_runtime/multi_layer_configuration) for details on how configuration flows between layers.*

---

## Specialized Commands

### Firewall Management
- `LOAD MYSQL FIREWALL TO RUNTIME` (or `TO RUN`)
- `SAVE MYSQL FIREWALL TO DISK`
- `LOAD PGSQL FIREWALL TO RUNTIME` (or `TO RUN`)
- `SAVE PGSQL FIREWALL TO DISK`

### Debugging & Coredump
- `LOAD DEBUG TO RUNTIME` (or `TO RUN`)
- `SAVE DEBUG TO DISK`
- `LOAD COREDUMP TO RUNTIME`
- `SAVE COREDUMP TO DISK`

### System Commands
- `PROXYSQL RELOAD TLS`: Reloads SSL/TLS certificates for the Admin and Proxy interfaces.
- `SAVE CONFIG TO FILE`: (v4.0+) Attempts to export the current configuration back to a `.cnf` file format.

### Checksum Verification
Verify consistency between layers using the `CHECKSUM` command:
- `CHECKSUM DISK <MODULE>` (e.g., `CHECKSUM DISK MYSQL SERVERS`)
- `CHECKSUM MEMORY <MODULE>`
- `CHECKSUM <MODULE>` (defaults to current memory state)