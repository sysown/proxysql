# DuckDB Plugin: Five-Minute Tutorial

This tutorial builds the v4.0 tier from source, loads the DuckDB plugin, and
runs the same data through both supported client protocols.

## 1. Build the v4.0 tier

DuckDB's source archive is stored with Git LFS. Fetch it before the first
build:

```bash
git lfs install
git lfs pull --include="deps/duckdb/duckdb-1.4.5.tar.gz"
deps/duckdb/verify-source.bash
PROXYSQL40=1 make
```

The plugin is produced at:

```text
plugins/duckdb/ProxySQL_DuckDB_Plugin.so
```

For a system installation the expected path is:

```text
/usr/lib/proxysql/plugins/ProxySQL_DuckDB_Plugin.so
```

## 2. Load the plugin at startup

Add the shared object to the `plugins` array in `proxysql.cnf`:

```ini
plugins = (
    "/usr/lib/proxysql/plugins/ProxySQL_DuckDB_Plugin.so"
)
```

Plugins cannot be hot-loaded. Start or restart ProxySQL after changing this
array.

## 3. Ensure endpoint users exist

The MySQL endpoint authenticates against `mysql_users`; the PostgreSQL
endpoint authenticates against `pgsql_users`. Existing active users can be
used. If you add users through ProxySQL Admin, load and save them with the
normal user commands for the corresponding protocol.

This tutorial uses `duckuser` as a placeholder. Do not put a real password on
the command line in production.

## 4. Connect through MySQL protocol

The default MySQL-protocol port is 6031:

```bash
mysql -h 127.0.0.1 -P 6031 -u duckuser -p
```

Create a small data set and run an analytical query:

```sql
CREATE OR REPLACE TABLE sales (
    region VARCHAR,
    amount DECIMAL(12,2)
);

INSERT INTO sales VALUES
    ('north', 125.50),
    ('south', 200.00),
    ('north', 74.50);

SELECT region, SUM(amount) AS total
FROM sales
GROUP BY region
ORDER BY region;
```

Expected values:

```text
north  200.00
south  200.00
```

## 5. Read the same database through PostgreSQL protocol

The default PostgreSQL-protocol port is 6034. The database name used by the
examples is `main`:

```bash
psql -h 127.0.0.1 -p 6034 -U duckuser main
```

Then run:

```sql
SELECT * FROM sales ORDER BY region, amount;
```

Both connections address the same embedded DuckDB database. With the default
`:memory:` configuration, that database lives until ProxySQL stops. To retain
the table across restarts, configure a file-backed `database_path` as shown in
the next section.

## 6. Make the database persistent

Connect to ProxySQL Admin on port 6032 and populate the editable DuckDB
configuration table:

```sql
SAVE DUCKDB VARIABLES TO MEMORY;

UPDATE duckdb_variables
SET variable_value='/var/lib/proxysql/duckdb/analytics.db'
WHERE variable_name='database_path';

LOAD DUCKDB VARIABLES TO RUNTIME;
SAVE DUCKDB VARIABLES TO DISK;
```

`database_path` is an engine-open setting. `LOAD` records the new runtime
configuration, but the already-open engine continues using the old database.
Create the parent directory with permissions for the ProxySQL service account,
then restart ProxySQL. After restart, the plugin opens the configured file.

## 7. Verify configuration

Through ProxySQL Admin:

```sql
SELECT * FROM runtime_duckdb_variables ORDER BY variable_name;
```

The runtime table is generated from the plugin's current configuration store.
It is not the same as the state of every already-open engine or listener
resource; the [configuration reference](configuration-reference.md) identifies
which variables apply immediately and which require a restart.

## Next steps

- Learn normal workflows in the [User guide](user-guide.md).
- Review every setting in the [Configuration reference](configuration-reference.md).
- Read the [Security guide](security.md) before enabling external access or
  exposing either listener broadly.
- Check [Protocol compatibility](protocol-compatibility.md) before choosing a
  driver API.
