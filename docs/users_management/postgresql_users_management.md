# PostgreSQL Users Management

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## Overview

ProxySQL v3.0+ supports the PostgreSQL protocol and uses the **[`pgsql_users`](../main_runtime/postgresql_tables#pgsql_users)** table to manage authentication. This table functions similarly to the MySQL users table but is tailored for the specific requirements of PostgreSQL clients and backends.

---

## The `pgsql_users` Table

The `pgsql_users` table manages credentials and session behavior for all PostgreSQL traffic.

### Table Schema

| Column | Type | Description |
| :--- | :--- | :--- |
| `username` | VARCHAR | The PostgreSQL username. |
| `password` | VARCHAR | The user's password. |
| `active` | BOOLEAN | `1` to enable, `0` to disable. |
| `use_ssl` | BOOLEAN | If `1`, use SSL for backend connections. |
| `default_hostgroup` | INTEGER | The default hostgroup for this user's queries. |
| `transaction_persistent` | BOOLEAN | If `1`, keeps the session on the same backend during a transaction. |
| `fast_forward` | BOOLEAN | If `1`, bypasses the query processor. |
| `frontend` | BOOLEAN | If `1`, allow this user to connect to ProxySQL. |
| `backend` | BOOLEAN | If `1`, use these credentials for backend connections. |
| `max_connections` | INTEGER | Max concurrent sessions for this user. |
| `attributes` | JSON | Additional metadata (e.g., `default-transaction_isolation`). |
| `comment` | VARCHAR | Free-form description. |

---

## Configuration Workflow

PostgreSQL user management follows the standard ProxySQL multi-layer system.

### 1. Create a User
```sql
INSERT INTO pgsql_users (username, password, default_hostgroup)
VALUES ('pg_app_user', 'pg_secure_pass', 20);
```

### 2. Activate the User
To promote changes to the runtime:
```sql
LOAD PGSQL USERS TO RUNTIME;
```

### 3. Persist the Change
To save to the local disk:
```sql
SAVE PGSQL USERS TO DISK;
```

---

## Key Features

### Session Attributes
The `attributes` column in `pgsql_users` allows you to define PostgreSQL-specific session defaults. For example, you can set the default transaction isolation level for a specific user:

```sql
UPDATE pgsql_users 
SET attributes = json_object('default-transaction_isolation', 'READ COMMITTED')
WHERE username = 'pg_app_user';
```

### Authentication Compatibility
ProxySQL supports various PostgreSQL authentication methods, including SCRAM-SHA-256. For detailed information on how ProxySQL handles the PostgreSQL handshake, see the **[PostgreSQL Authentication](./postgresql_authentication)** page.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your user configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
