# REST API

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## Overview

ProxySQL includes a built-in **REST API** that allows users to create custom HTTP endpoints for interaction with the proxy. This feature is designed to bridge external monitoring or automation tools with ProxySQL's internal state via standard HTTP GET and POST requests.

Unlike the [HTTP Web Server](./http_web_server), which provides a fixed dashboard, the REST API is a **pluggable routing engine** where you define which URI triggers which script.

---

## Configuration

The REST API is controlled by variables in the **Admin** module and routing rules in the `restapi_routes` table.

### Core Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `admin-restapi_enabled` | `false` | Set to `true` to enable the REST API. |
| `admin-restapi_port` | `6070` | The TCP port the API listens on. |

### Routing Table: `restapi_routes`

Endpoints are defined by adding rows to this table.

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER | Unique identifier for the route. |
| `active` | BOOLEAN | Set to `1` to enable, `0` to disable. |
| `timeout_ms` | INTEGER | Maximum execution time for the script. |
| `method` | VARCHAR | HTTP method: `GET` or `POST`. |
| `uri` | VARCHAR | The URL path (e.g., `/health`). |
| `script` | VARCHAR | The full path to the script to execute. |
| `comment` | VARCHAR | Documentation field. |

---

## How It Works

When a request arrives at the REST API:
1.  **Lookup**: ProxySQL looks for a match in the `runtime_restapi_routes` table based on the `uri` and `method`.
2.  **Execution**: If a match is found, ProxySQL executes the associated `script`.
3.  **Data Exchange**:
    -   **For POST**: The content of the HTTP request body is passed to the script via standard input (`stdin`).
    -   **Response**: The standard output (`stdout`) of the script is captured and returned as the HTTP response body.
4.  **Format**: The response header is automatically set to `Content-Type: application/json`.

---

## Example: Creating a Health Check

1.  **Define the script** (`/usr/local/bin/check_hg.sh`):
    ```bash
    #!/bin/bash
    # Simple script to check hostgroup status
    mysql -u admin -padmin -h 127.0.0.1 -P 6032 -e "SELECT * FROM stats_mysql_connection_pool" -J
    ```
2.  **Add the route**:
    ```sql
    INSERT INTO restapi_routes (active, timeout_ms, method, uri, script)
    VALUES (1, 2000, 'GET', '/pool_status', '/usr/local/bin/check_hg.sh');
    ```
3.  **Activate**:
    ```sql
    LOAD RESTAPI TO RUNTIME;
    ```
4.  **Test**:
    ```bash
    curl http://localhost:6070/pool_status
    ```

---

## Activation & Persistence

- **To Activate**: `LOAD RESTAPI TO RUNTIME`
- **To Persist**: `SAVE RESTAPI TO DISK`

*See the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for more details.*

---

## Security

- **Environment**: Scripts run with an empty environment. Ensure all paths and credentials are set within the script.
- **Port Binding**: Ensure the `admin-restapi_port` is protected by a firewall or bound to internal interfaces only.
- **Async Execution**: The REST API handles requests asynchronously to avoid blocking the main proxy threads.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
