# ProxySQL: On‑Demand Core Dump Generation (coredump_filters)

## Introduction

ProxySQL includes a debugging feature that allows on‑demand generation of core dump files when specific code locations are reached. This is useful for diagnosing rare or hard‑to‑reproduce bugs without requiring a full debug build or restarting the proxy.

The feature works by:

1. **Defining filters**: Inserting file‑name and line‑number pairs into the `coredump_filters` table.
2. **Enabling filters**: Loading the filters to runtime with `LOAD COREDUMP TO RUNTIME`.
3. **Triggering core dumps**: When the macro `generate_coredump()` is executed at a filtered location, a core file is written to disk (subject to rate‑limiting and platform constraints).

Core dump generation is **rate‑limited** and **platform‑specific** (currently Linux on x86‑32, x86‑64, ARM, and MIPS architectures).

---

## Table Definitions

### `coredump_filters` (persistent configuration)

| Column   | Type         | Nullable | Primary Key | Description |
|----------|--------------|----------|-------------|-------------|
| filename | VARCHAR      | NOT NULL | Yes         | Source file name (as seen by the compiler) |
| line     | INT          | NOT NULL | Yes         | Line number within that file |

**Primary key**: (`filename`, `line`)

**SQL definition**:
```sql
CREATE TABLE coredump_filters (
    filename VARCHAR NOT NULL,
    line INT NOT NULL,
    PRIMARY KEY (filename, line)
);
```

### `runtime_coredump_filters` (runtime state)

This table mirrors the active filters currently loaded into memory. It is updated automatically when `LOAD COREDUMP TO RUNTIME` is executed.

**SQL definition**:
```sql
CREATE TABLE runtime_coredump_filters (
    filename VARCHAR NOT NULL,
    line INT NOT NULL,
    PRIMARY KEY (filename, line)
);
```

---

## Configuration Variables

Two global variables control the rate‑limiting behavior:

| Variable | Default | Range | Description |
|----------|---------|-------|-------------|
| `admin‑coredump_generation_threshold` | 10 | 1–500 | Maximum number of core files that can be generated during the lifetime of the ProxySQL process. |
| `admin‑coredump_generation_interval_ms` | 30000 (30 seconds) | 0–INT_MAX | Minimum time between two consecutive core dump generations. A value of `0` disables the interval check. |

**Notes**:
- Both variables are stored in the `global_variables` table (admin database).
- Changes take effect immediately when the variable is set (no need to `LOAD … TO RUNTIME`).
- The threshold is a **global counter**; once reached, no further core dumps will be generated until the process restarts.
- The interval is measured in **milliseconds**.

---

## Admin Commands

### `LOAD COREDUMP TO RUNTIME`

Reads the `coredump_filters` table and loads the filters into memory. After this command, any location matching a filter becomes active for core dump generation.

**Aliases**:
- `LOAD COREDUMP FROM MEMORY`
- `LOAD COREDUMP FROM MEM`
- `LOAD COREDUMP TO RUN`

**Example**:
```sql
LOAD COREDUMP TO RUNTIME;
```

**Effect**:
1. Clears the previous runtime filter set.
2. Reads all rows from `coredump_filters`.
3. Converts each row into a string `"filename:line"` and stores it in an internal hash set.
4. If at least one filter exists, the global flag `coredump_enabled` is set to `true`.

### `SAVE COREDUMP` (not implemented)

As of this writing, there is **no `SAVE COREDUMP` command**. The runtime state (`runtime_coredump_filters`) is automatically updated when filters are loaded, but there is no built‑in command to persist runtime filters back to the `coredump_filters` table.

If you need to copy the active filters back to the configuration table, you can do so manually:

```sql
INSERT INTO coredump_filters SELECT * FROM runtime_coredump_filters;
```

---

## Important Notes

- **Case‑sensitive filenames**: The `filename` column must match exactly the string returned by `__FILE__` (including relative path from the source root). The comparison is case‑sensitive.
- **Runtime‑only behavior**: Filters loaded via `LOAD COREDUMP TO RUNTIME` are stored in memory only. They are lost when ProxySQL restarts. To make filters persistent, keep them in the `coredump_filters` table and reload after each restart.
- **Instance‑specific**: Filters are local to the ProxySQL instance; there is no automatic synchronization across a cluster.
- **Rate limiting**: The feature includes two safety limits (`admin‑coredump_generation_threshold` and `admin‑coredump_generation_interval_ms`) to prevent disk filling and performance degradation.
- **Platform‑specific**: Core dump generation works only on Linux x86‑32, x86‑64, ARM, and MIPS architectures. On other platforms the macro logs a warning and does nothing.

---

## Usage Example

### 1. Insert a filter

Suppose you want to generate a core dump when the function `MySQL_Data_Stream::check_data_flow()` reaches line 485 (where `generate_coredump()` is called).

First, find the exact file name as used in the source code. The macro `LOCATION()` expands to `__FILE__ ":" __LINE__`. For the file `lib/mysql_data_stream.cpp` line 485:

```sql
INSERT INTO coredump_filters (filename, line) VALUES ('lib/mysql_data_stream.cpp', 485);
```

### 2. (Optional) Adjust rate‑limiting variables

Increase the threshold and shorten the interval if you expect to trigger the dump multiple times quickly:

```sql
SET admin-coredump_generation_threshold = 50;
SET admin-coredump_generation_interval_ms = 1000;  -- 1 second
```

These changes take effect immediately.

### 3. Load filters to runtime

```sql
LOAD COREDUMP TO RUNTIME;
```

### 4. Trigger the condition

Cause the code path to reach the filtered location. In this example, you would need to create a MySQL data‑stream condition where data exists at both ends of the stream (a fatal error). When that happens, ProxySQL will log:

```
[INFO] Coredump filter location 'lib/mysql_data_stream.cpp:485' was hit.
[INFO] Generating coredump file 'core.<pid>.<counter>'...
[INFO] Coredump file 'core.<pid>.<counter>' was generated ...
```

### 5. Inspect the core file

The core file is written in the current working directory of the ProxySQL process, with the name pattern `core.<pid>.<counter>` (e.g., `core.12345.0`). It is compressed using the **coredumper** library.

Analyze it with `gdb`:

```bash
gdb /usr/bin/proxysql core.12345.0
```

---

## Rate Limiting and Safety Features

To prevent disk filling and performance impact, core dump generation is protected by two mechanisms:

1. **Threshold limit**: The total number of core dumps generated during the process lifetime cannot exceed `admin‑coredump_generation_threshold` (default 10). Once the threshold is reached, `generate_coredump()` will still log the hit but will not write a new core file.

2. **Interval limit**: After a core dump is written, at least `admin‑coredump_generation_interval_ms` milliseconds must pass before another core dump can be generated (unless the interval is set to 0). This prevents burst generation when a hot code path is repeatedly executed.

Both counters are reset when `LOAD COREDUMP TO RUNTIME` is executed (or when `proxy_coredump_reset_stats()` is called internally).

---

## Platform Support

Core dump generation is **only available** on the following platforms:

- **Operating system**: Linux
- **Architectures**: x86‑32 (`__i386__`), x86‑64 (`__x86_64__`), ARM (`__ARM_ARCH_3__`), MIPS (`__mips__`)

On other platforms (e.g., FreeBSD, macOS, Windows) the `generate_coredump()` macro will log a warning and do nothing.

The feature relies on the **coredumper** library (https://github.com/elastic/coredumper), which is bundled as a dependency.

---

## Internal Implementation Details

### Macros and Functions

- `generate_coredump()`: The macro used in the source code to conditionally generate a core dump. It checks `coredump_enabled` and looks up the current `__FILE__:__LINE__` in the filter set.
- `proxy_coredump_load_filters()`: Loads a set of `"filename:line"` strings into the internal hash table.
- `proxy_coredump_generate()`: Performs the actual core dump writing, subject to rate‑limiting checks.
- `proxy_coredump_reset_stats()`: Resets the generation counter and last‑creation timestamp.

### Database‑to‑Runtime Flow

1. `LOAD COREDUMP TO RUNTIME` calls `ProxySQL_Admin::load_coredump_to_runtime()`.
2. Which calls `flush_coredump_filters_database_to_runtime()`.
3. Reads `coredump_filters` table, builds the string set, and passes it to `proxy_coredump_load_filters()`.
4. The runtime state is mirrored to `runtime_coredump_filters` via `dump_coredump_filter_values_table()`.

### Where `generate_coredump()` is Used

Currently, the macro is placed in a few strategic “fatal error” locations:

- `MySQL_Data_Stream::check_data_flow()` – when data exists at both ends of a MySQL data stream.
- `PgSQL_Data_Stream::check_data_flow()` – analogous condition for PostgreSQL.

Developers can add more `generate_coredump()` calls in other debug‑sensitive code sections.

---

## Troubleshooting

### No core file is generated even though the filter was hit

1. **Check platform support**: Verify ProxySQL is running on a supported Linux architecture.
2. **Check rate‑limiting counters**: The global threshold may have been reached. Execute `LOAD COREDUMP TO RUNTIME` to reset the counters (or restart ProxySQL).
3. **Check directory permissions**: The process must have write permission in the current working directory.
4. **Check disk space**: Ensure there is sufficient free disk space.

### Error “Coredump generation is not supported on this platform.”

The platform is not among the supported architectures. Use a different machine or consider using a debugger instead.

### Filters are not being activated after `LOAD COREDUMP TO RUNTIME`

- Verify that the `filename` matches exactly the string that `__FILE__` expands to (relative path from the source root).
- Ensure the line number is correct (check the source code for the exact line where `generate_coredump()` appears).
- Inspect the `runtime_coredump_filters` table to confirm the filters were loaded.

### High frequency of core dumps is affecting performance

Increase `admin‑coredump_generation_interval_ms` to space out the generation, or reduce `admin‑coredump_generation_threshold` to limit the total number.

---

## Best Practices

1. **Use for debugging only**: Enable coredump filters only during debugging sessions. Remove filters afterward to avoid unnecessary overhead.
2. **Limit the threshold**: Keep `admin‑coredump_generation_threshold` low (e.g., 1‑5) unless you are investigating a recurring issue.
3. **Set a reasonable interval**: A minimum interval of several seconds (e.g., 30000 ms) prevents storm generation.
4. **Document filter locations**: Keep a record of why each filter was inserted and under what condition it triggers.
5. **Monitor disk usage**: Core files can be large; ensure the working directory has enough space and consider a dedicated partition.

---

## Related Features

- **Debug filters**: ProxySQL also supports `debug_filters` for enabling debug logs at specific file‑line locations.
- **Core dump on crash**: For crash‑induced core dumps, use system‑level configuration (e.g., `ulimit -c unlimited`, `sysctl kernel.core_pattern`).

---

## Summary

The `coredump_filters` feature provides a targeted, rate‑limited way to obtain core dumps from specific code locations without restarting ProxySQL or building a debug binary. It is a valuable tool for diagnosing elusive bugs in production‑like environments.

Remember that core dump generation is **platform‑dependent** and **rate‑limited**; always verify support and adjust the configuration variables according to your debugging needs.