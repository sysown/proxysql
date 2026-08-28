# SQLite-vec Integration in ProxySQL

This directory contains the integration of [sqlite-vec](https://github.com/asg017/sqlite-vec) - a SQLite extension that provides vector search capabilities directly within SQLite databases.

## What is sqlite-vec?

sqlite-vec is an extension that enables SQLite to perform vector similarity searches. It provides:
- Vector storage and indexing
- Distance calculations (cosine, Euclidean, etc.)
- Approximate nearest neighbor (ANN) search
- Support for multiple vector formats (JSON, binary, etc.)

## Integration Details

### Directory Structure
- `sqlite-vec-source/` - Source files for sqlite-vec (committed to repository)
- `sqlite3/` - Build directory where sqlite-vec gets compiled during the build process

### Integration Method

The integration uses **static linking** to embed sqlite-vec directly into ProxySQL:

1. **Source Storage**: sqlite-vec source files are stored in `sqlite-vec-source/` to persist across builds
2. **Compilation**: During build, sources are copied to the build directory and compiled with static linking flags:
   - `-DSQLITE_CORE` - Compiles as part of SQLite core
   - `-DSQLITE_VEC_STATIC` - Enables static linking mode
3. **Embedding**: The compiled `vec.o` object file is included in `libproxysql.a`
4. **Auto-loading**: The extension is automatically registered when any SQLite database is opened

### Modified Files

#### Build Files
- `../Makefile` - Updated to ensure git version is available during build
- `../deps/Makefile` - Added compilation target for sqlite-vec
- `../lib/Makefile` - Modified to include vec.o in libproxysql.a

#### Source Files
- `../lib/Admin_Bootstrap.cpp` - Added extension loading and auto-registration code

### Database Instances

The extension is enabled in all ProxySQL SQLite databases:
- **Admin database** - Management interface
- **Stats database** - Runtime statistics
- **Config database** - Configuration storage
- **Monitor database** - Monitoring data
- **Stats disk database** - Persistent statistics

## Usage

Once ProxySQL is built and restarted, you can use vector search functions in any SQLite database:

```sql
-- Create a vector table
CREATE VIRTUAL TABLE my_vectors USING vec0(
    vector float[128]
);

-- Insert vectors with JSON format
INSERT INTO my_vectors(rowid, vector)
VALUES (1, json('[0.1, 0.2, 0.3, ..., 0.128]'));

-- Perform similarity search
SELECT rowid, distance
FROM my_vectors
WHERE vector MATCH json('[0.1, 0.2, 0.3, ..., 0.128]')
LIMIT 10;
```

## Compilation Flags

The sqlite-vec source is compiled with these flags:
- `SQLITE_CORE` - Integrate with SQLite core
- `SQLITE_VEC_STATIC` - Static linking mode
- `SQLITE_ENABLE_MEMORY_MANAGEMENT` - Memory management features
- `SQLITE_ENABLE_JSON1` - JSON support
- `SQLITE_DLL=1` - DLL compatibility

## Benefits

- **No runtime dependencies** - Vector search is embedded in the binary
- **Automatic loading** - No need to manually load extensions
- **Full compatibility** - Works with all ProxySQL SQLite databases
- **Performance** - Native SQLite virtual table implementation

## Building

The integration is automatic when building ProxySQL. The sqlite-vec sources are compiled and linked as part of the normal build process.

## Verification

To verify that sqlite-vec is properly integrated:
1. Build ProxySQL: `make`
2. Check symbols: `nm src/proxysql | grep vec`
3. Should see symbols like `sqlite3_vec_init`, `vec0_*`, `vector_*`, etc.