# pgsql_servers_ssl_params

## Overview

The `pgsql_servers_ssl_params` table allows per-server SSL configuration for PostgreSQL backend connections. This enables different SSL certificates, keys, and TLS version restrictions for each backend server, overriding the global `pgsql-ssl_p2s_*` variables.

This is the PostgreSQL equivalent of MySQL's `mysql_servers_ssl_params` table.

## Table Schema

```sql
CREATE TABLE pgsql_servers_ssl_params (
  hostname VARCHAR NOT NULL,
  port INT CHECK (port >= 0 AND port <= 65535) NOT NULL DEFAULT 5432,
  username VARCHAR NOT NULL DEFAULT '',
  ssl_ca VARCHAR NOT NULL DEFAULT '',
  ssl_cert VARCHAR NOT NULL DEFAULT '',
  ssl_key VARCHAR NOT NULL DEFAULT '',
  ssl_crl VARCHAR NOT NULL DEFAULT '',
  ssl_crlpath VARCHAR NOT NULL DEFAULT '',
  ssl_protocol_version_range VARCHAR NOT NULL DEFAULT '',
  comment VARCHAR NOT NULL DEFAULT '',
  PRIMARY KEY (hostname, port, username)
)
```

## Column Reference

| Column | Description |
|--------|-------------|
| `hostname` | Backend server hostname. Must match the `hostname` in `pgsql_servers`. |
| `port` | Backend server port. Default: `5432`. Must match the `port` in `pgsql_servers`. |
| `username` | ProxySQL username. Empty string `''` acts as a wildcard fallback (see Lookup Hierarchy). |
| `ssl_ca` | Path to the CA certificate file (PEM). May contain multiple concatenated CA certs. Maps to libpq `sslrootcert`. |
| `ssl_cert` | Path to the client certificate file. Maps to libpq `sslcert`. |
| `ssl_key` | Path to the client private key file. Maps to libpq `sslkey`. |
| `ssl_crl` | Path to the certificate revocation list file. Maps to libpq `sslcrl`. |
| `ssl_crlpath` | Path to directory containing CRL files. Maps to libpq `sslcrldir` (PostgreSQL 14+). |
| `ssl_protocol_version_range` | TLS protocol version constraint. See format below. |
| `comment` | Free-form comment. |

## ssl_protocol_version_range

Controls which TLS protocol versions are allowed for backend connections. This maps to libpq's `ssl_min_protocol_version` and `ssl_max_protocol_version` parameters.

### Format

**Range:** `<min_version>-<max_version>`

Allows connections using any TLS version from `min_version` to `max_version` inclusive.

**Min-only:** `<min_version>-`

Sets a minimum TLS version with no upper bound (libpq default max applies).

**Max-only:** `-<max_version>`

Sets a maximum TLS version. The minimum defaults to libpq's built-in default (`TLSv1.2`).

**Single version (pin):** `<version>`

Pins to exactly that TLS version. Both min and max are set to the same value.

**Empty string:** `''`

Uses libpq defaults (no restriction).

A bare `-` is treated as malformed and ignored (a warning is logged).

### Valid Version Tokens

`TLSv1`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`

> **Note:** `TLSv1` and `TLSv1.1` are disabled in most modern PostgreSQL deployments. Attempting to use them will result in connection failures.

### Examples

| Value | Meaning |
|-------|---------|
| `TLSv1.2-TLSv1.3` | Allow TLS 1.2 and TLS 1.3 |
| `TLSv1.3` | Pin to TLS 1.3 only |
| `TLSv1.2-TLSv1.2` | Pin to TLS 1.2 only (equivalent to `TLSv1.2`) |
| `TLSv1.2-` | Require at least TLS 1.2 (max defaults to highest OpenSSL supports) |
| `-TLSv1.3` | Allow up to TLS 1.3 (min defaults to libpq's built-in `TLSv1.2`) |
| `''` (empty) | Use libpq defaults |

## Lookup Hierarchy

When ProxySQL opens a new connection to a PostgreSQL backend, it looks up SSL parameters in this order:

1. **Exact match:** `(hostname, port, username)` — if an entry exists for the specific server and the ProxySQL user making the connection, use it.
2. **Wildcard fallback:** `(hostname, port, '')` — if no exact match, check for an entry with empty username.
3. **Global fallback:** If no match found, use the global `pgsql-ssl_p2s_*` variables.

This allows you to set a default SSL configuration for a server (empty username) while overriding it for specific users.

> **Important — matching is all-or-nothing.** Once a row in `pgsql_servers_ssl_params` matches (either at step 1 or step 2), ProxySQL uses **only** the SSL fields from that row. Empty columns in the matched row are passed through as empty (libpq defaults), they are **not** silently filled in from `pgsql-ssl_p2s_*`. The global variables are consulted **only** when no row matches at all (step 3). If you want a per-server row to inherit some defaults from the globals, you must copy those values into the row explicitly.

## Usage

### Basic: Same SSL cert for all users connecting to a server

```sql
INSERT INTO pgsql_servers_ssl_params
  (hostname, port, ssl_ca, ssl_cert, ssl_key)
VALUES
  ('db1.example.com', 5432, '/certs/ca.crt', '/certs/client.crt', '/certs/client.key');

LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;
```

### Per-user: Different certs for different applications

```sql
-- Default for all users connecting to db1
INSERT INTO pgsql_servers_ssl_params
  (hostname, port, username, ssl_ca, ssl_cert, ssl_key)
VALUES
  ('db1.example.com', 5432, '', '/certs/ca.crt', '/certs/default.crt', '/certs/default.key');

-- Override for 'billing_app' user
INSERT INTO pgsql_servers_ssl_params
  (hostname, port, username, ssl_ca, ssl_cert, ssl_key)
VALUES
  ('db1.example.com', 5432, 'billing_app', '/certs/ca.crt', '/certs/billing.crt', '/certs/billing.key');

LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;
```

### TLS version restriction

```sql
-- Require TLS 1.3 for a specific server
INSERT INTO pgsql_servers_ssl_params
  (hostname, port, ssl_ca, ssl_cert, ssl_key, ssl_protocol_version_range)
VALUES
  ('secure-db.example.com', 5432, '/certs/ca.crt', '/certs/client.crt', '/certs/client.key', 'TLSv1.3');

-- Allow TLS 1.2 or 1.3 for another server
INSERT INTO pgsql_servers_ssl_params
  (hostname, port, ssl_ca, ssl_cert, ssl_key, ssl_protocol_version_range)
VALUES
  ('db2.example.com', 5432, '/certs/ca.crt', '/certs/client.crt', '/certs/client.key', 'TLSv1.2-TLSv1.3');

LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;
```

### Multiple servers with different SSL configs

```sql
-- Server A: uses company CA and TLS 1.3
INSERT INTO pgsql_servers_ssl_params
  (hostname, port, ssl_ca, ssl_cert, ssl_key, ssl_protocol_version_range, comment)
VALUES
  ('db-a.internal', 5432, '/certs/company-ca.crt', '/certs/a-client.crt', '/certs/a-client.key', 'TLSv1.3', 'Internal DB');

-- Server B: uses AWS RDS CA bundle
INSERT INTO pgsql_servers_ssl_params
  (hostname, port, ssl_ca, comment)
VALUES
  ('mydb.us-east-1.rds.amazonaws.com', 5432, '/certs/rds-combined-ca-bundle.pem', 'AWS RDS');

LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;
```

## Viewing Configuration

```sql
-- View configured SSL params
SELECT * FROM pgsql_servers_ssl_params;

-- View active runtime SSL params
SELECT * FROM runtime_pgsql_servers_ssl_params;
```

## Admin Commands

| Command | Effect |
|---------|--------|
| `LOAD PGSQL SERVERS TO RUNTIME` | Promotes `pgsql_servers_ssl_params` to runtime (activates the config) |
| `SAVE PGSQL SERVERS TO DISK` | Persists `pgsql_servers_ssl_params` to the on-disk database |
| `LOAD PGSQL SERVERS FROM DISK` | Restores `pgsql_servers_ssl_params` from the on-disk database |

## Prerequisites

Per-server SSL parameters only take effect when `use_ssl=1` is set for the corresponding server in `pgsql_servers`:

```sql
UPDATE pgsql_servers SET use_ssl=1 WHERE hostname='db1.example.com';
LOAD PGSQL SERVERS TO RUNTIME;
```

If `use_ssl=0`, the backend connection does not use SSL regardless of `pgsql_servers_ssl_params` entries.

## Notes

- Empty fields in `pgsql_servers_ssl_params` are omitted from the libpq connection string (libpq defaults apply for those fields).
- Per-server SSL params only affect **new** backend connections. Existing pooled connections continue using their original SSL settings. Use the `/* create_new_connection=1 */` query annotation to force ProxySQL to create a new backend connection.
- Per-server SSL params apply on the data path (`PgSQL_Connection`), the monitor path (`PgSQL_Monitor`), and the cancel/terminate path (`PgSQL_Backend_Kill_Args`).
