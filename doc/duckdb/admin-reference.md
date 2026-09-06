# DuckDB Admin Reference

Run all commands in this page through the ProxySQL Admin interface, normally
MySQL protocol on port 6032. Do not send them to the DuckDB plugin listeners.

## `duckdb_variables`

Editable configuration table in the Admin database:

```sql
CREATE TABLE duckdb_variables (
    variable_name VARCHAR NOT NULL PRIMARY KEY,
    variable_value VARCHAR NOT NULL DEFAULT ''
);
```

On a first-ever start, this table can be empty even though the plugin is
running with compiled defaults. Populate it from the runtime configuration:

```sql
SAVE DUCKDB VARIABLES TO MEMORY;
```

Edit rows with ordinary SQL and then LOAD them:

```sql
UPDATE duckdb_variables
SET variable_value='4'
WHERE variable_name='threads';

LOAD DUCKDB VARIABLES TO RUNTIME;
```

Editing the table alone does not affect the module.

## `runtime_duckdb_variables`

Read-only projection of the plugin's in-memory configuration store:

```sql
SELECT *
FROM runtime_duckdb_variables
ORDER BY variable_name;
```

The chassis refreshes this projection on demand. It shows what the module has
accepted, not necessarily what an already-open engine or bound listener has
adopted. Consult the apply behavior in the
[Configuration reference](configuration-reference.md).

Do not update this table directly.

## `disk.duckdb_variables`

Persistent copy stored in ProxySQL's on-disk configuration database. It is
populated by `SAVE DUCKDB VARIABLES TO DISK`.

At plugin startup, the plugin copies `disk.duckdb_variables` into the editable
Admin table and then installs those rows into the module. Thus a previously
saved configuration reappears after restart, while a fresh installation with
no disk rows starts with compiled defaults and an empty editable table.

## Commands

### `LOAD DUCKDB VARIABLES TO RUNTIME`

Alias:

```sql
LOAD DUCKDB VARIABLES FROM MEMORY;
```

Reads all rows from `duckdb_variables` and attempts to install them into the
module. Unknown or invalid rows are skipped and reported without rolling back
valid rows. The command updates the live `max_connections` cap; other settings
may require restart.

### `SAVE DUCKDB VARIABLES TO MEMORY`

Alias:

```sql
SAVE DUCKDB VARIABLES FROM RUNTIME TO MEMORY;
```

Replaces the editable `duckdb_variables` table with the module's complete
current configuration. It is a full replacement, not a merge.

This is the easiest way to materialize compiled defaults on a fresh install.

### `SAVE DUCKDB VARIABLES TO DISK`

Copies `main.duckdb_variables` to `disk.duckdb_variables`. It does not LOAD the
editable values into the module first.

A safe edit sequence is therefore:

```sql
UPDATE duckdb_variables
SET variable_value='200'
WHERE variable_name='max_connections';

LOAD DUCKDB VARIABLES TO RUNTIME;
SAVE DUCKDB VARIABLES TO DISK;
```

## Inspecting differences

Before LOAD, compare the editable and runtime values:

```sql
SELECT m.variable_name,
       m.variable_value AS editable_value,
       r.variable_value AS runtime_value
FROM duckdb_variables AS m
LEFT JOIN runtime_duckdb_variables AS r
  ON r.variable_name = m.variable_name
ORDER BY m.variable_name;
```

After SAVE to disk, inspect persistence:

```sql
SELECT * FROM disk.duckdb_variables ORDER BY variable_name;
```

## Failure semantics

Table-replacement operations are transactional. A failed replacement rolls
back instead of leaving a table deleted and partially refilled. Runtime-view
refresh failures are written through the plugin logger.

LOAD can report success with a warning-style message when some rows were
skipped. Read the command result and confirm `runtime_duckdb_variables` rather
than assuming every edited row was accepted.
