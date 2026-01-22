# Admin Commands

ProxySQL uses a multi-layer configuration system consisting of the **Configuration File**, **Disk Database**, **Main (Memory) Database**, and the **Runtime** data structures. Moving configuration between these layers is handled via `LOAD` and `SAVE` commands.

## Table of Contents
- [Configuration Layers](#configuration-layers)
- [MySQL Commands](#mysql-commands)
  - [MySQL Servers & Hostgroups](#mysql-servers--hostgroups)
  - [MySQL Users](#mysql-users)
  - [MySQL Query Rules](#mysql-query-rules)
  - [MySQL Variables](#mysql-variables)
- [PostgreSQL Commands (v3.0+)](#postgresql-commands-v30)
  - [PostgreSQL Servers](#postgresql-servers)
  - [PostgreSQL Users](#postgresql-users)
  - [PostgreSQL Query Rules](#postgresql-query-rules)
  - [PostgreSQL Variables](#postgresql-variables)
- [Generative AI & MCP Commands (v4.0+)](#generative-ai--mcp-commands-v40)
  - [MCP Query Rules](#mcp-query-rules)
  - [MCP Variables](#mcp-variables)
  - [GENAI Variables](#genai-variables)
- [Core Admin & System Commands](#core-admin--system-commands)
  - [Admin Variables](#admin-variables)
  - [ProxySQL Servers (Cluster Nodes)](#proxysql-servers-cluster-nodes)
  - [Scheduler](#scheduler)
- [Specialized Commands](#specialized-commands)
  - [Firewall Management](#firewall-management)
  - [Debugging & Coredump](#debugging--coredump)
  - [System Commands](#system-commands)
  - [Checksum Verification](#checksum-verification)

## Configuration Layers

1. **RUNTIME**: The internal data structures used by ProxySQL threads to process traffic. This is the only layer that actively affects proxy behavior.
2. **MEMORY (Main)**: The `main` SQLite database. This is where you make changes using standard SQL (`UPDATE`, `INSERT`, `DELETE`).
3. **DISK**: The `disk` SQLite database. This is used for persistence across ProxySQL restarts.
4. **CONFIG FILE**: The static `proxysql.cnf` file used for initial bootstrapping.

---

## MySQL Commands

Commands for managing MySQL servers, users, and routing rules.

### MySQL Servers & Hostgroups
- `LOAD MYSQL SERVERS TO RUNTIME` (or `TO RUN`)
- `SAVE MYSQL SERVERS TO DISK`
- `LOAD MYSQL SERVERS FROM DISK`
- `SAVE MYSQL SERVERS TO MEMORY` (or `TO MEM`)
- `LOAD MYSQL SERVERS FROM MEMORY` (or `FROM MEM`)
- `LOAD MYSQL SERVERS FROM CONFIG`

### MySQL Users
- `LOAD MYSQL USERS TO RUNTIME` (or `TO RUN`)
- `SAVE MYSQL USERS TO DISK`
- `LOAD MYSQL USERS FROM DISK`
- `SAVE MYSQL USERS TO MEMORY` (or `TO MEM`)
- `LOAD MYSQL USERS FROM MEMORY` (or `FROM MEM`)
- `LOAD MYSQL USERS FROM CONFIG`

### MySQL Query Rules
- `LOAD MYSQL QUERY RULES TO RUNTIME` (or `TO RUN`)
- `SAVE MYSQL QUERY RULES TO DISK`
- `LOAD MYSQL QUERY RULES FROM DISK`
- `SAVE MYSQL QUERY RULES TO MEMORY` (or `TO MEM`)
- `LOAD MYSQL QUERY RULES FROM MEMORY` (or `FROM MEM`)
- `LOAD MYSQL QUERY RULES FROM CONFIG`

### MySQL Variables
- `LOAD MYSQL VARIABLES TO RUNTIME` (or `TO RUN`)
- `SAVE MYSQL VARIABLES TO DISK`
- `LOAD MYSQL VARIABLES FROM DISK`
- `SAVE MYSQL VARIABLES TO MEMORY` (or `TO MEM`)
- `LOAD MYSQL VARIABLES FROM MEMORY` (or `FROM MEM`)
- `LOAD MYSQL VARIABLES FROM CONFIG`

---

## PostgreSQL Commands (v3.0+)

Commands for managing PostgreSQL servers, users, and routing rules.

### PostgreSQL Servers
- `LOAD PGSQL SERVERS TO RUNTIME` (or `TO RUN`)
- `SAVE PGSQL SERVERS TO DISK`
- `LOAD PGSQL SERVERS FROM DISK`
- `SAVE PGSQL SERVERS TO MEMORY` (or `TO MEM`)
- `LOAD PGSQL SERVERS FROM MEMORY` (or `FROM MEM`)
- `LOAD PGSQL SERVERS FROM CONFIG`

### PostgreSQL Users
- `LOAD PGSQL USERS TO RUNTIME` (or `TO RUN`)
- `SAVE PGSQL USERS TO DISK`
- `LOAD PGSQL USERS FROM DISK`
- `SAVE PGSQL USERS TO MEMORY` (or `TO MEM`)
- `LOAD PGSQL USERS FROM MEMORY` (or `FROM MEM`)
- `LOAD PGSQL USERS FROM CONFIG`

### PostgreSQL Query Rules
- `LOAD PGSQL QUERY RULES TO RUNTIME` (or `TO RUN`)
- `SAVE PGSQL QUERY RULES TO DISK`
- `LOAD PGSQL QUERY RULES FROM DISK`
- `SAVE PGSQL QUERY RULES TO MEMORY` (or `TO MEM`)
- `LOAD PGSQL QUERY RULES FROM MEMORY` (or `FROM MEM`)
- `LOAD PGSQL QUERY RULES FROM CONFIG`

### PostgreSQL Variables
- `LOAD PGSQL VARIABLES TO RUNTIME` (or `TO RUN`)
- `SAVE PGSQL VARIABLES TO DISK`
- `LOAD PGSQL VARIABLES FROM DISK`
- `SAVE PGSQL VARIABLES TO MEMORY` (or `TO MEM`)
- `LOAD PGSQL VARIABLES FROM MEMORY` (or `FROM MEM`)
- `LOAD PGSQL VARIABLES FROM CONFIG`

---

## Generative AI & MCP Commands (v4.0+)

Commands for managing the Model Context Protocol (MCP) server and AI components.

### MCP Query Rules
- `LOAD MCP QUERY RULES TO RUNTIME` (or `TO RUN`)
- `SAVE MCP QUERY RULES TO DISK`
- `LOAD MCP QUERY RULES FROM DISK`
- `SAVE MCP QUERY RULES TO MEMORY` (or `TO MEM`)
- `LOAD MCP QUERY RULES FROM MEMORY` (or `FROM MEM`)

### MCP Variables
- `LOAD MCP VARIABLES TO RUNTIME` (or `TO RUN`)
- `SAVE MCP VARIABLES TO DISK`
- `LOAD MCP VARIABLES FROM DISK`
- `SAVE MCP VARIABLES TO MEMORY` (or `TO MEM`)
- `LOAD MCP VARIABLES FROM MEMORY` (or `FROM MEM`)
- `LOAD MCP VARIABLES FROM CONFIG`

### GENAI Variables
- `LOAD GENAI VARIABLES TO RUNTIME` (or `TO RUN`)
- `SAVE GENAI VARIABLES TO DISK`
- `LOAD GENAI VARIABLES FROM DISK`
- `SAVE GENAI VARIABLES TO MEMORY` (or `TO MEM`)
- `LOAD GENAI VARIABLES FROM MEMORY` (or `FROM MEM`)
- `LOAD GENAI VARIABLES FROM CONFIG`

---

## Core Admin & System Commands

Commands for ProxySQL's internal administration and scheduling system.

### Admin Variables
- `LOAD ADMIN VARIABLES TO RUNTIME` (or `TO RUN`)
- `SAVE ADMIN VARIABLES TO DISK`
- `LOAD ADMIN VARIABLES FROM DISK`
- `SAVE ADMIN VARIABLES TO MEMORY` (or `TO MEM`)
- `LOAD ADMIN VARIABLES FROM MEMORY` (or `FROM MEM`)
- `LOAD ADMIN VARIABLES FROM CONFIG`

### ProxySQL Servers (Cluster Nodes)
- `LOAD PROXYSQL SERVERS TO RUNTIME` (or `TO RUN`)
- `SAVE PROXYSQL SERVERS TO DISK`
- `LOAD PROXYSQL SERVERS FROM DISK`
- `SAVE PROXYSQL SERVERS TO MEMORY` (or `TO MEM`)
- `LOAD PROXYSQL SERVERS FROM MEMORY` (or `FROM MEM`)
- `LOAD PROXYSQL SERVERS FROM CONFIG`

### Scheduler
- `LOAD SCHEDULER TO RUNTIME` (or `TO RUN`)
- `SAVE SCHEDULER TO DISK`
- `LOAD SCHEDULER FROM DISK`
- `SAVE SCHEDULER TO MEMORY` (or `TO MEM`)
- `LOAD SCHEDULER FROM MEMORY` (or `FROM MEM`)
- `LOAD SCHEDULER FROM CONFIG`

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