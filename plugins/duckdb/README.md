# ProxySQL DuckDB Server Plugin

This directory builds the ProxySQL v4.0 DuckDB server plugin. The plugin embeds
DuckDB and exposes it through independent MySQL- and PostgreSQL-protocol
listeners.

Operator and user documentation is canonical under [`doc/duckdb/`](../../doc/duckdb/index.md):

- [Five-minute tutorial](../../doc/duckdb/quickstart.md)
- [Installation](../../doc/duckdb/installation.md)
- [User guide](../../doc/duckdb/user-guide.md)
- [Configuration reference](../../doc/duckdb/configuration-reference.md)
- [Admin reference](../../doc/duckdb/admin-reference.md)
- [Protocol compatibility](../../doc/duckdb/protocol-compatibility.md)
- [Security](../../doc/duckdb/security.md)
- [Operations](../../doc/duckdb/operations.md)
- [Troubleshooting](../../doc/duckdb/troubleshooting.md)

## Developer build

The plugin and vendored DuckDB dependency are enabled only in the Plugin
Chassis tier:

```bash
git lfs pull --include="deps/duckdb/duckdb-1.4.5.tar.gz"
deps/duckdb/verify-source.bash
PROXYSQL40=1 make
```

The build-tree artifact is:

```text
plugins/duckdb/ProxySQL_DuckDB_Plugin.so
```

The standard installed path is:

```text
/usr/lib/proxysql/plugins/ProxySQL_DuckDB_Plugin.so
```

Build the plugin and ProxySQL core with the same tier and DEBUG mode. The ABI
encodes the DEBUG build tag and rejects a mismatched plugin/core pair.

## Source layout

| Path | Responsibility |
|---|---|
| `include/duckdb_plugin.h` | Plugin process context |
| `include/duckdb_config.h` | Configuration store and listener-address parsing |
| `include/duckdb_engine.h` | Shared database and connection accounting |
| `include/duckdb_listener.h` | MySQL/PostgreSQL listener lifecycle |
| `include/duckdb_session.h` | Query classification, execution, and protocol responses |
| `include/duckdb_result.h` | DuckDB-to-ProxySQL result conversion contract |
| `src/duckdb_plugin.cpp` | Chassis descriptor and lifecycle callbacks |
| `src/duckdb_admin_schema.cpp` | Admin tables, runtime view, and LOAD/SAVE commands |
| `src/duckdb_engine.cpp` | DuckDB open/close and connection cap |
| `src/duckdb_listener.cpp` | Socket accept and per-connection thread loop |
| `src/duckdb_session.cpp` | SQL execution and wire-protocol adaptation |
| `src/duckdb_result.cpp` | Length-aware text result conversion |

## Maintainer references

- [Vendored DuckDB](../../deps/duckdb/README.md)
- [Plugin API](../../doc/PLUGIN_API.md)
- [DuckDB plugin design](../../docs/superpowers/specs/2026-08-26-duckdb-server-plugin-design.md)
- [Review-fix/documentation plan](../../docs/superpowers/plans/2026-09-01-duckdb-review-and-documentation.md)

Focused unit targets are defined in `test/tap/tests/unit/Makefile`; end-to-end
tests live under `test/tap/tests/test_duckdb_*-t.cpp` and must be run through
the repository's isolated TAP infrastructure.
