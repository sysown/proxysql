# DuckDB Plugin Security

The DuckDB plugin runs an analytical database inside the ProxySQL process.
Security decisions therefore affect both database contents and the filesystem,
memory, CPU, and privileges of that process.

## Trust model

The plugin authenticates MySQL connections against `mysql_users` and
PostgreSQL connections against `pgsql_users`. It does not add a separate
DuckDB user, role, schema, or table authorization layer.

After authentication, endpoint users share the embedded database and can issue
DuckDB SQL. A credential suitable for routed application traffic is not
automatically suitable for unrestricted access to the embedded analytical
database.

Use dedicated credentials where possible, restrict endpoint reachability, and
assume mutually untrusted users must not share this initial plugin instance.

## Listener exposure

Both listeners default to `0.0.0.0`, which exposes them on every available
interface unless host firewalling or network policy intervenes. For local-only
use, set:

```text
mysql_ifaces=127.0.0.1:6031
pgsql_ifaces=127.0.0.1:6034
```

Listener changes require restart. Do not confuse the plugin endpoints with
ProxySQL Admin on 6032 or the normal MySQL proxy endpoint on 6033.

This initial documentation does not make a transport-encryption guarantee for
the plugin-specific listeners. Before exposing them across an untrusted
network, verify the deployed build's TLS behavior or place the connection
inside an independently authenticated encrypted channel.

## External access is denied by default

ProxySQL sets DuckDB `enable_external_access=false`, overriding DuckDB's own
default. Keep it false unless all endpoint users are trusted with filesystem
capabilities of the ProxySQL operating-system account.

Enabling external access can permit operations such as:

- reading local files with functions such as `read_csv`;
- writing files with `COPY ... TO`;
- attaching other database files;
- interacting with other external state supported by the DuckDB build.

This setting is independent of `read_only`. A read-only main database does not
make arbitrary filesystem reads safe and does not replace the external-access
gate.

Changing `enable_external_access` in `duckdb_variables` and running LOAD does
not reconfigure the already-open engine. Restart is required. Do not interpret
the runtime table alone as proof that the live engine adopted the change.

## Extension behavior

The vendored build disables extension autoload and autoinstall, and unsigned
extensions are not enabled by default. The plugin does not fetch extensions
from the internet. These build properties are separate from filesystem access;
external access still controls a broader local/external-state surface.

## Database files

For a file-backed database:

- place it in a directory dedicated to ProxySQL;
- make the ProxySQL service account the owner;
- avoid world-readable or world-writable permissions;
- protect backups with the same controls as the live file;
- do not point `database_path` at a sensitive existing file.

The plugin passes the configured path to DuckDB. Operating-system permissions
are the final boundary for that path.

## Resource isolation

DuckDB shares the ProxySQL process. A memory- or CPU-intensive query can affect
normal proxy duties. Set a conservative `memory_limit`, choose `threads`
deliberately, cap connections, and limit which users can reach the plugin.

There is currently no per-query timeout. Network isolation and credential
control are therefore part of resource protection, not only data protection.

## SQL input

The plugin rejects multiple statements in one request, closing a statement
smuggling path where earlier side effects could be hidden by the final result.
That is not a substitute for normal SQL-injection defenses.

Use parameterization only with APIs the plugin supports. Because prepared
statement protocols are not currently supported, do not fall back to unsafe
string concatenation for untrusted values. Validate and quote data in a trusted
application layer, or avoid exposing such query construction until an
appropriate supported interface exists.

## Operational checklist

- Bind only required interfaces.
- Use dedicated active users and strong passwords.
- Keep `enable_external_access=false` by default.
- Use a dedicated database directory with restrictive permissions.
- Set memory and connection limits before admitting traffic.
- Verify backup confidentiality and restore procedures.
- Review logs after every configuration restart.
