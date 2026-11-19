# Azure Entra ID backend authentication (v4.0)

ProxySQL v4.0 can connect to Azure Database for MySQL Flexible Server with a
Microsoft Entra ID access token instead of a stored password. The token comes
from the pod's AKS workload identity. This removes the MySQL password for the
backend users and, optionally, for the monitor user (issue #6649).

## Requirements

- A ProxySQL build with `PROXYSQL40=1`, and the plugin `proxysql_azure_entra.so`.
- Azure Database for MySQL Flexible Server with Microsoft Entra authentication on.
- AKS workload identity: a user-assigned managed identity with a federated
  credential for the ProxySQL service account, and the pod label
  `azure.workload.identity/use: "true"`. The webhook sets `AZURE_CLIENT_ID`,
  `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE` and `AZURE_AUTHORITY_HOST`.
- The servers in `mysql_servers` use the Azure host name
  (`<server>.mysql.database.azure.com`; China and US Government clouds are
  also accepted), `use_ssl=1`, and a CA bundle in `mysql-ssl_p2s_ca` (or per
  server in `mysql_servers_ssl_params`) that trusts the Azure server certificate.
  ProxySQL refuses to send a token to any other host name.

## 1. Create the database users

Connect to the server as the Entra administrator and create one user for each
managed identity. The MySQL user name is the name you give here:

```sql
CREATE AADUSER 'proxysql_app' IDENTIFIED BY '<client id of the managed identity>';
GRANT SELECT, INSERT, UPDATE, DELETE ON app.* TO 'proxysql_app'@'%';

-- Optional: a monitor user. It uses the same managed identity: ProxySQL
-- has one token for all users.
CREATE AADUSER 'proxysql_monitor' IDENTIFIED BY '<client id of the managed identity>';
GRANT REPLICATION CLIENT, PROCESS ON *.* TO 'proxysql_monitor'@'%';
```

## 2. Load the plugin

In `proxysql.cnf`:

```
plugins = ( "/usr/lib/proxysql/plugins/proxysql_azure_entra.so" )
```

`make install` puts the plugin at this path. The release packages do not include
the plugin yet: build it with `PROXYSQL40=1` and copy
`plugins/azure_entra/proxysql_azure_entra.so` to this path on the host.

At start, the plugin logs `azure_entra: token source installed for client ...`.
If an environment variable is missing or invalid, the plugin fails to start and
logs the variable name.

Optional environment variable: `PROXYSQL_AZURE_ENTRA_SCOPE` (default
`https://ossrdbms-aad.database.windows.net/.default`).

## 3. Configure the users

The backend row has an empty password and the policy attribute. The frontend
row keeps the password that the application sends to ProxySQL:

```sql
INSERT INTO mysql_users (username, password, frontend, backend, attributes)
VALUES ('proxysql_app', '', 0, 1, '{"backend_auth":{"type":"azure_entra"}}');
LOAD MYSQL USERS TO RUNTIME;
```

A row with an unknown or malformed `backend_auth` fails closed: queries get
ERR 9002 and no password is sent.

## 4. Monitor (optional)

```sql
SET mysql-monitor_username = 'proxysql_monitor';
SET mysql-monitor_backend_auth = 'azure_entra';
LOAD MYSQL VARIABLES TO RUNTIME;
```

The default is `password`. The monitor then does not send
`mysql-monitor_password` to the backends. Keep `mysql-monitor_password` set to
a strong value: ProxySQL still accepts the monitor user with this password on
the Admin and stats interfaces.

## Behaviour

- One token serves all users and servers. It is cached, refreshed 10 minutes
  before it expires, and used until 30 seconds before it expires.
- A session waits at most 5 seconds for a token. The HTTP call to Entra times
  out after 4 seconds.
- After a failed token request, requests fail for 2 seconds before the next try.
  While the cached token is still usable, the wait after each failed refresh
  doubles, up to 60 seconds.
- An "Access denied" (1045) fails the session with `backend_auth_rejected` and
  starts a token refresh, at most once per minute. Other sessions keep the
  cached token until the refresh succeeds, so one user without
  `CREATE AADUSER` does not affect the other users.
- The monitor waits at least 5 seconds for a token, also when
  `mysql-monitor_connect_timeout` is shorter.
- `stats_mysql_global` shows the token source counters as `AzureEntra_*` rows.
  Prometheus shows the same values as `proxysql_mysql_azure_entra_*` series,
  for example `proxysql_mysql_azure_entra_token_refresh_failures_total` and
  `proxysql_mysql_azure_entra_waiting_sessions`.
- Token connections are never reused for another user and never reset with
  `COM_CHANGE_USER`.
- When a user changes to `azure_entra`, ProxySQL stops using that user's
  pooled password connections. It closes each one when a session would reuse it.

## Failure codes

Log lines start with `Azure Entra backend ...`. Clients get ERR 9002
`Unable to connect to backend`.

| Code | Meaning |
|---|---|
| `token_source_unavailable` | The plugin is not loaded or failed to start. |
| `invalid_endpoint` | The host name is not an Azure Database for MySQL host. |
| `tls_required` | `use_ssl` is 0 for the server. |
| `ca_trust_required` | No CA is configured for the server. |
| `unix_socket_not_allowed` | The server is a Unix socket. |
| `provider_error` | Entra refused the token request; `code` and `request_id` show the Entra error and correlation id. |
| `credential_provider_error` | The federated token file cannot be read. |
| `backend_auth_rejected` | The server refused the token (check `CREATE AADUSER` and the user name). |
| `token_timeout` | The monitor got no token in time. |
