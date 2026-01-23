# SQLite3 Server Variables

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## List of SQLite3 Server Variables

NOTE: You can click on the variable name to jump to its definition

<!-- remark-ignore-start -->

| Variable Name | Default Value |
| :--- | :--- |
| [sqliteserver-mysql_ifaces](#sqliteserver-mysql_ifaces) | 0.0.0.0:6030 |
| [sqliteserver-read_only](#sqliteserver-read_only) | false |

<!-- remark-ignore-end -->

### `sqliteserver-mysql_ifaces`

Network interfaces to listen on for the SQLite3 Server.

| | | |
| :--- | :--- | :--- |
| **System Variable** | **Name** | sqliteserver-mysql_ifaces |
| | **Dynamic** | Yes |
| **Permitted Values** | **Type** | String |
| | **Default** | 0.0.0.0:6030 |

**Description**: Comma-separated list of IP addresses and ports that the ProxySQL built-in SQLite3 Server should listen on. See the **[SQLite3 Server](../features/sqlite3_server)** feature page for more details.

### `sqliteserver-read_only`

Controls if the SQLite3 Server is in read-only mode.

| | | |
| :--- | :--- | :--- |
| **System Variable** | **Name** | sqliteserver-read_only |
| | **Dynamic** | Yes |
| **Permitted Values** | **Type** | Boolean |
| | **Default** | false |

**Description**: When set to `true`, the SQLite3 Server will only permit read operations (SELECT). Write operations (INSERT, UPDATE, DELETE, CREATE, DROP) will be blocked.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
