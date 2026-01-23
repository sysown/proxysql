# MCP Variables

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## List of MCP Variables

NOTE: You can click on the variable name to jump to its definition

<!-- remark-ignore-start -->

| Variable Name | Default Value |
| :--- | :--- |
| [mcp-enabled](#mcp-enabled) | false |
| [mcp-port](#mcp-port) | 6071 |
| [mcp-use_ssl](#mcp-use_ssl) | true |
| [mcp-timeout_ms](#mcp-timeout_ms) | 30000 |
| [mcp-config_endpoint_auth](#mcp-config_endpoint_auth) | "" |
| [mcp-observe_endpoint_auth](#mcp-observe_endpoint_auth) | "" |
| [mcp-query_endpoint_auth](#mcp-query_endpoint_auth) | "" |
| [mcp-admin_endpoint_auth](#mcp-admin_endpoint_auth) | "" |
| [mcp-cache_endpoint_auth](#mcp-cache_endpoint_auth) | "" |
| [mcp-mysql_hosts](#mcp-mysql_hosts) | 127.0.0.1 |
| [mcp-mysql_ports](#mcp-mysql_ports) | 3306 |
| [mcp-mysql_user](#mcp-mysql_user) | "" |
| [mcp-mysql_password](#mcp-mysql_password) | "" |
| [mcp-mysql_schema](#mcp-mysql_schema) | "" |

<!-- remark-ignore-end -->

### `mcp-enabled`

Enables or disables the Model Context Protocol (MCP) server.

| | | |
| :--- | :--- | :--- |
| **System Variable** | **Name** | mcp-enabled |
| | **Dynamic** | Yes |
| **Permitted Values** | **Type** | Boolean |
| | **Default** | false |

**Description**: Master switch for the ProxySQL MCP server. When set to `true`, ProxySQL starts listening for MCP requests on the configured port.

### `mcp-port`

The port on which the MCP server listens.

| | | |
| :--- | :--- | :--- |
| **System Variable** | **Name** | mcp-port |
| | **Dynamic** | Yes |
| **Permitted Values** | **Type** | Integer |
| | **Default** | 6071 |

**Description**: Sets the TCP port for the MCP server.

### `mcp-use_ssl`

Enables or disables SSL/TLS for the MCP server.

| | | |
| :--- | :--- | :--- |
| **System Variable** | **Name** | mcp-use_ssl |
| | **Dynamic** | Yes |
| **Permitted Values** | **Type** | Boolean |
| | **Default** | true |

**Description**: When enabled, the MCP server will only accept HTTPS connections.

### `mcp-timeout_ms`

Global timeout for MCP requests in milliseconds.

| | | |
| :--- | :--- | :--- |
| **System Variable** | **Name** | mcp-timeout_ms |
| | **Dynamic** | Yes |
| **Permitted Values** | **Type** | Integer (ms) |
| | **Default** | 30000 |

**Description**: The maximum time ProxySQL will wait for an internal tool or backend query to complete before returning a timeout error to the MCP client.

### `mcp-config_endpoint_auth`
### `mcp-observe_endpoint_auth`
### `mcp-query_endpoint_auth`
### `mcp-admin_endpoint_auth`
### `mcp-cache_endpoint_auth`

Authentication tokens for specific MCP endpoints.

| | | |
| :--- | :--- | :--- |
| **System Variable** | **Name** | mcp-*_endpoint_auth |
| | **Dynamic** | Yes |
| **Permitted Values** | **Type** | String |
| | **Default** | "" |

**Description**: These variables define the Bearer tokens required to access different MCP endpoints. If left empty, no authentication is performed for that specific endpoint (not recommended for production).

### `mcp-mysql_hosts`
### `mcp-mysql_ports`
### `mcp-mysql_user`
### `mcp-mysql_password`
### `mcp-mysql_schema`

Configuration for the MySQL Tool Handler used by MCP.

| | | |
| :--- | :--- | :--- |
| **System Variable** | **Name** | mcp-mysql_* |
| | **Dynamic** | Yes |
| **Permitted Values** | **Type** | String |

**Description**: These variables configure how the MCP server connects to backend MySQL instances to perform autodiscovery and query execution.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
