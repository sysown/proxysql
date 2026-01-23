# MySQL Authentication

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## Overview

ProxySQL deeply understands the MySQL authentication handshake and acts as both a server (for frontend clients) and a client (for backend servers). This allows ProxySQL to support various authentication plugins and security standards.

---

## Supported Methods

ProxySQL supports the following standard MySQL authentication plugins for both frontend and backend connections:

- **`mysql_native_password`**: The traditional SHA1-based authentication (default for MySQL < 8.0).
- **`caching_sha2_password`**: The modern SHA2-based authentication (default for MySQL >= 8.0).
- **`mysql_clear_password`**: Used primarily for integrating with external systems like LDAP or ProxySQL's built-in [LDAP support](https://proxysql.com/documentation/ldap-support/).

### Extra Frontend Methods
- **[SPIFFE](https://proxysql.com/documentation/spiffe-support/)**: Certificate-based, password-less authentication.
- **[LDAP](https://proxysql.com/documentation/ldap-support/)**: Authentication against OpenLDAP or Active Directory.

---

## Version Support Matrix

| ProxySQL Version | `mysql_native_password` | `caching_sha2_password` |
| :--- | :--- | :--- |
| **Pre-2.0.2** | Frontend & Backend | Not Supported |
| **Pre-2.6.0** | Frontend & Backend | Backend Only (Frontend requires clear-text pass) |
| **Post-2.6.0** | Frontend & Backend | Frontend & Backend |

---

## Handshake Control

The variable `mysql-default_authentication_plugin` controls which plugin ProxySQL announces to the client in the `Initial Handshake Packet`. Setting this correctly can reduce round-trips and avoid "Auth Switch" overhead.

**Example: Defaulting to modern SHA2**
```sql
SET mysql-default_authentication_plugin = 'caching_sha2_password';
LOAD MYSQL VARIABLES TO RUNTIME;
```

---

## Security Considerations

### SSL Requirement
When using `caching_sha2_password` with hashed passwords, an SSL connection is strictly required between the client and ProxySQL to protect the challenge-response exchange.

### Password Hashing
While ProxySQL can store clear-text passwords, it is highly recommended to use hashed passwords in production. See **[MySQL Password Management](./mysql_password_management)** for details on generating hashes.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your authentication configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
