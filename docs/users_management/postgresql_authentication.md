# PostgreSQL Authentication

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## Overview

ProxySQL v3.0+ implements the PostgreSQL wire protocol and handles the authentication handshake for both frontend clients and backend servers. This allows ProxySQL to enforce security policies and manage connections efficiently.

---

## Supported Methods

The authentication behavior is primarily controlled by the `pgsql-authentication_method` global variable.

| Value | Method | Description |
| :--- | :--- | :--- |
| **1** | `NO_PASSWORD` | Trust authentication. ProxySQL informs the client that no password is required. |
| **2** | `CLEAR_TEXT_PASSWORD` | The client sends the password in clear-text to ProxySQL. |
| **3** | `SASL_SCRAM_SHA_256` | Modern, secure authentication using the SCRAM-SHA-256 challenge-response mechanism. |

---

## The Handshake Process

ProxySQL acts as a protocol-aware gateway during the connection phase.

### 1. Frontend Challenge
When a client connects, ProxySQL sends an `AuthenticationRequest` message (Type 'R'). The specific challenge sent is determined **strictly** by the value of `pgsql-authentication_method`.

- If set to **1**, ProxySQL sends `AuthenticationOk`.
- If set to **2**, ProxySQL sends `AuthenticationCleartextPassword`.
- If set to **3**, ProxySQL sends `AuthenticationSASL` with the `SCRAM-SHA-256` mechanism.

**Implementation Note**: ProxySQL *forces* this method on the client. If you set the method to `NO_PASSWORD`, the client will be allowed to connect without a password even if one is defined in the `pgsql_users` table.

### 2. Backend Authentication
Once the client is authenticated, ProxySQL retrieves the backend credentials from the `pgsql_users` table to establish a connection to the PostgreSQL database servers. ProxySQL supports authenticating to backends using the same set of methods (Trust, Clear Text, or SCRAM).

---

## Configuration

To change the default authentication method used by the PostgreSQL module:

```sql
-- Set the method to SASL/SCRAM (Recommended)
SET pgsql-authentication_method = 3;

-- Activate the change
LOAD PGSQL VARIABLES TO RUNTIME;

-- Persist the change
SAVE PGSQL VARIABLES TO DISK;
```

---

## Security Considerations

- **Protocol Matching**: Ensure that `pgsql-authentication_method` matches the authentication requirements of your backend PostgreSQL servers. If the backend requires SCRAM but ProxySQL is configured for Clear Text, the connection will fail.
- **SCRAM-SHA-256**: This is the most secure method supported and should be the default for modern environments.
- **User Limits**: Individual user connection limits are enforced after the handshake is completed.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your authentication configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
