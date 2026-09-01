# Installing the DuckDB Plugin

## Requirements

The DuckDB plugin requires the ProxySQL v4.0 Plugin Chassis build tier:

```text
PROXYSQL40=1
```

The current vendored engine is DuckDB 1.4.5. Its source archive is stored with
Git LFS, so a source build also requires Git LFS and the usual ProxySQL C/C++
build toolchain.

The plugin must be compiled with the same build mode as the ProxySQL core. In
particular, a DEBUG plugin cannot load into a release core, and a release
plugin cannot load into a DEBUG core. The loader rejects this mismatch before
plugin initialization.

## Source installation

Fetch and verify the vendored source:

```bash
git lfs install
git lfs pull --include="deps/duckdb/duckdb-1.4.5.tar.gz"
deps/duckdb/verify-source.bash
```

Build the complete matching tier:

```bash
PROXYSQL40=1 make
```

When switching from another tier or from DEBUG to release, clean the old
objects first and pass the same tier flag to every build command. See the
repository `CLAUDE.md` for the current tier-cleaning rules.

The build-tree artifact is:

```text
plugins/duckdb/ProxySQL_DuckDB_Plugin.so
```

The standard installed location is:

```text
/usr/lib/proxysql/plugins/ProxySQL_DuckDB_Plugin.so
```

If a package or local installation uses another path, use that exact absolute
path in `proxysql.cnf`.

## Configure plugin loading

Add the plugin to the startup configuration:

```ini
plugins = (
    "/usr/lib/proxysql/plugins/ProxySQL_DuckDB_Plugin.so"
)
```

If other plugins are present, list each element according to the existing
libconfig syntax. ProxySQL loads plugins in the listed order and does not
resolve dependencies between them.

There is no runtime `LOAD PLUGIN` command. Restart ProxySQL to add, remove, or
replace the shared object.

## Prepare a persistent database directory

The default database is in memory and needs no directory. For a persistent
database, create a directory writable by the operating-system account running
ProxySQL:

```bash
install -d -o proxysql -g proxysql -m 0750 /var/lib/proxysql/duckdb
```

Configure a file inside that directory through the Admin interface, save the
configuration to disk, and restart. See the
[five-minute tutorial](quickstart.md#6-make-the-database-persistent).

Do not grant broader filesystem permissions merely to make DuckDB open a path.
Use a dedicated directory and keep `enable_external_access=false` unless its
security consequences are explicitly accepted.

## Endpoint users

The plugin does not define a separate user table:

- MySQL-protocol connections use active entries from `mysql_users`.
- PostgreSQL-protocol connections use active entries from `pgsql_users`.

The endpoint user gains access to the shared embedded DuckDB database. Backend
hostgroups and routing rules do not provide a second authorization boundary
inside that database. Review the [Security guide](security.md) before reusing
application credentials.

## Verify startup

After restarting ProxySQL:

1. Check the ProxySQL log for plugin load, engine-open, or listener-bind errors.
2. Confirm the configured ports are listening.
3. Connect using `mysql` on 6031 or `psql` on 6034.
4. Query `runtime_duckdb_variables` through ProxySQL Admin.
5. Run `SELECT 42` through each protocol you intend to support.

If startup fails, see [Troubleshooting](troubleshooting.md).

## Upgrade and replacement

Treat the plugin and core as one ABI-coupled installation unit:

1. Stop ProxySQL cleanly.
2. Back up a file-backed DuckDB database and the ProxySQL configuration
   database.
3. Install the new core and matching plugin from the same build.
4. Start ProxySQL and inspect logs before admitting traffic.
5. Run a read and write smoke test through each enabled protocol.

Do not overwrite a loaded `.so` and assume the process has adopted it. The
running process continues using the loaded image until restart.
