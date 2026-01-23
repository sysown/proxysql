# MySQL Password Management

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## Overview

ProxySQL is a protocol-aware proxy that authenticates clients before performing routing. For this reason, ProxySQL needs access to user credentials (either in clear-text or hashed format) to validate frontend logins and establish backend connections.

---

## Password Formats

Passwords can be stored in the `mysql_users` table in two formats:

### 1. Plain Text
Easy to read and manage, but poses a security risk if the database file is compromised.

### 2. Hashed Passwords
ProxySQL supports standard MySQL password hashes.
- **`mysql_native_password`**: Uses the `SHA1(SHA1('password'))` format. ProxySQL identifies these by the `*` prefix.
- **`caching_sha2_password`**: Supported since v2.6.0. These hashes typically start with `$A$0`.

---

## Utility Functions

ProxySQL provides built-in SQLite functions to generate hashes directly from the Admin interface:

### `MYSQL_NATIVE_PASSWORD()`
Generates a SHA1-based hash compatible with older MySQL versions.
```sql
SELECT MYSQL_NATIVE_PASSWORD('my_password');
-- Result: *520BA5BE3924F1A0DB9941C4EA0911B19CBDE1A3
```

### `CACHING_SHA2_PASSWORD()`
Generates a SHA2-based hash. It can optionally take a salt.
```sql
SELECT CACHING_SHA2_PASSWORD('my_password');
```

---

## Dual Passwords (v3.0+)

ProxySQL support **Dual Passwords**, allowing zero-downtime password rotations. You can define an additional password in the `attributes` column.

### Example: Adding an Additional Password
```sql
UPDATE mysql_users 
SET attributes = json_set(attributes, '$.additional_password', HEX(CACHING_SHA2_PASSWORD('old_pass')))
WHERE username = 'app_user';
```

When dual passwords are used, ProxySQL will accept either the primary or the additional password during the handshake.

---

## Migration and Importing

When importing users from a MySQL server, it is recommended to use the `HEX()` representation to avoid character escaping issues with binary hashes.

1. **Extract from MySQL**:
   ```sql
   SELECT HEX(authentication_string) FROM mysql.user WHERE user='app_user';
   ```
2. **Import to ProxySQL**:
   ```sql
   UPDATE mysql_users SET password = UNHEX('...') WHERE username = 'app_user';
   ```

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your password configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
