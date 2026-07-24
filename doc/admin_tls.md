# Dedicated TLS for the Admin interfaces

ProxySQL can use a dedicated TLS context for its MySQL and PostgreSQL Admin
interfaces. The feature is disabled by default, so existing deployments retain
their previous behavior.

When `admin-ssl_enabled` is enabled, all new connections to either Admin
interface must negotiate TLS. Existing connections are not disconnected.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `admin-ssl_enabled` | `false` | Require TLS and activate the dedicated Admin TLS context. |
| `admin-ssl_key` | empty | PEM private key. Required when enabled. |
| `admin-ssl_cert` | empty | PEM certificate chain. Required when enabled. |
| `admin-ssl_ca` | empty | PEM CA bundle used to verify client certificates. |
| `admin-ssl_capath` | empty | OpenSSL hashed CA directory used to verify client certificates. |
| `admin-ssl_cipher` | empty | OpenSSL TLS 1.2 cipher list. The OpenSSL default is used when empty. |
| `admin-tls_version` | `TLSv1.2` | Minimum accepted version: `TLSv1.2` or `TLSv1.3`. |
| `admin-ssl_curves` | empty | OpenSSL groups/curves list. |
| `admin-ssl_verify_client` | `DISABLED` | Client certificate mode: `DISABLED`, `OPTIONAL`, or `REQUIRED`. Numeric values `0`, `1`, and `2` are also accepted. |
| `admin-ssl_crl` | empty | PEM certificate revocation list. |
| `admin-ssl_crlpath` | empty | OpenSSL hashed CRL directory. |

Relative paths are resolved against ProxySQL's data directory. Client
verification requires `admin-ssl_ca` or `admin-ssl_capath`.

Example using ProxySQL's existing default certificate:

```sql
SELECT Variable_Name, Variable_Value
FROM stats.stats_proxysql_global
WHERE Variable_Name IN
  ('TLS_Key_File', 'TLS_Server_Cert_File', 'TLS_CA_Cert_File');

SET admin-ssl_key='/var/lib/proxysql/proxysql-key.pem';
SET admin-ssl_cert='/var/lib/proxysql/proxysql-cert.pem';
SET admin-ssl_ca='/var/lib/proxysql/proxysql-ca.pem';
SET admin-ssl_enabled='true';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
```

To require a trusted client certificate:

```sql
SET admin-ssl_verify_client='REQUIRED';
LOAD ADMIN VARIABLES TO RUNTIME;
```

## Reload behavior

`LOAD ADMIN VARIABLES TO RUNTIME` builds and validates a complete replacement
context before activating it. If validation fails, the previous runtime
configuration and context remain active and the command returns an error.

Certificate files can be re-read without changing variables:

```sql
PROXYSQL RELOAD ADMIN TLS;
```

The reload is atomic for new connections. Connections that are already using
TLS continue with the context under which they were established.
