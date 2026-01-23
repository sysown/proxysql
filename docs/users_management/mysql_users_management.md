# MySQL Users Management

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## Overview

ProxySQL uses the **[`mysql_users`](../main_runtime/mysql_tables#mysql_users)** table to manage authentication for both client-to-proxy (frontend) and proxy-to-backend (backend) connections. This centralized management allows ProxySQL to authenticate clients and then use appropriate credentials to connect to the backend database servers.

---

## The `mysql_users` Table

The `mysql_users` table is the core of user management in ProxySQL. It defines credentials, default routing, and session-level constraints.

### Table Schema

| Column | Type | Description |
| :--- | :--- | :--- |
| `username` | VARCHAR | The MySQL username. |
| `password` | VARCHAR | The user's password (clear-text or hashed). |
| `active` | BOOLEAN | `1` to enable the user, `0` to disable. |
| `use_ssl` | BOOLEAN | If `1`, ProxySQL will use SSL when connecting to the backend. |
| `default_hostgroup` | INTEGER | The default hostgroup for queries from this user. |
| `default_schema` | VARCHAR | The default database schema for the session. |
| `schema_locked` | BOOLEAN | If `1`, the client cannot change the schema via `USE`. |
| `transaction_persistent` | BOOLEAN | If `1`, once a transaction starts, the session is locked to the same backend. |
| `fast_forward` | BOOLEAN | If `1`, ProxySQL bypasses the query processor for this user. |
| `frontend` | BOOLEAN | If `1`, the user can connect to ProxySQL. |
| `backend` | BOOLEAN | If `1`, ProxySQL can use these credentials for backend connections. |
| `max_connections` | INTEGER | Maximum concurrent connections allowed for this user. |
| `attributes` | JSON | Additional user-specific metadata or configuration. |
| `comment` | VARCHAR | Documentation field. |

---

## Configuration Workflow

User management follows ProxySQL's multi-layer configuration system. Changes are made in the memory database and must be explicitly promoted.

### 1. Create a User
```sql
INSERT INTO mysql_users (username, password, default_hostgroup)
VALUES ('app_user', 'secure_pass', 10);
```

### 2. Activate the User
To make the new user active in ProxySQL's worker threads:
```sql
LOAD MYSQL USERS TO RUNTIME;
```

### 3. Persist the Change
To ensure the user exists after a ProxySQL restart:
```sql
SAVE MYSQL USERS TO DISK;
```

---

## Key Features

### Frontend vs. Backend Users
- **Frontend (`frontend=1`)**: These users are allowed to log into ProxySQL.
- **Backend (`backend=1`)**: These are the credentials ProxySQL uses to connect to the backend MySQL servers.
- A user can have both flags set to `1` (common for simplicity), or they can be decoupled for advanced security architectures.

### Connection Limits
The `max_connections` column allows you to restrict the number of concurrent sessions a specific user can have, protecting ProxySQL and the backend from connection exhaustion.

### Transaction Persistence
When `transaction_persistent=1`, ProxySQL ensures that all queries within a transaction are routed to the same backend server. This is critical for maintaining consistency during write operations.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your user configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
