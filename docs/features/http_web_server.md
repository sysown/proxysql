# HTTP Web Server

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## Overview

ProxySQL includes a built-in **HTTP Web Server** that provides a visual interface for monitoring the proxy's health and performance. It exposes real-time metrics, connection pool statistics, and historical data in an easy-to-read format.

The web server is optional and disabled by default.

---

## Configuration

The HTTP server is controlled by several global variables within the **Admin** module.

### Core Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `admin-web_enabled` | `false` | Set to `true` to enable the server. |
| `admin-web_port` | `6080` | The TCP port the server listens on. |
| `admin-web_verbosity` | `0` | Debugging verbosity level (0-10). |

### Authentication
The web server uses the credentials defined in the `admin-stats_credentials` variable. These are semi-colon separated `user:password` pairs.

```sql
SET admin-stats_credentials = 'stats:stats_pass;monitor:monitor_pass';
```

---

## Features

### Dashboard & Metrics
The web interface provides several pages for deep inspection:
- **Connection Pool**: Detailed breakdown of backend connections (Used, Free, OK, Errors) per hostgroup and server.
- **Query Digest**: Real-time view of the most frequent queries and their performance metrics.
- **System Stats**: CPU and memory usage of the ProxySQL process.
- **Processlist**: View active client connections and their current state.

### Prometheus Integration
The HTTP server also provides a dedicated endpoint for **Prometheus** metrics collection (typically at `/metrics` when enabled).

---

## Activation

To enable the web server at runtime:

1.  Set the enabled flag:
    ```sql
    SET admin-web_enabled = 'true';
    ```
2.  Activate the change:
    ```sql
    LOAD ADMIN VARIABLES TO RUNTIME;
    ```

*See the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details.*

---

## Security

- **Restricted Access**: It is highly recommended to bind the web interface to `127.0.0.1` or use a firewall to restrict access, as it contains sensitive performance data.
- **Dedicated Users**: Use `admin-stats_credentials` specifically for monitoring to avoid sharing administrative `admin-admin_credentials`.
- **Read-Only**: The default built-in web server is strictly **read-only**. It cannot be used to modify ProxySQL configuration unless a UI plugin is explicitly installed.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
