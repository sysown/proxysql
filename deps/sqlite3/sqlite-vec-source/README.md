# sqlite-vec - Vector Search for SQLite

This directory contains the source files for [sqlite-vec](https://github.com/asg017/sqlite-vec), an SQLite extension that provides vector search capabilities directly within SQLite databases.

## What is sqlite-vec?

sqlite-vec is an open-source SQLite extension that enables SQLite to perform vector similarity searches. It implements vector search as a SQLite virtual table, providing:

### Features
- **Vector Storage**: Store vectors directly in SQLite tables
- **Vector Indexing**: Efficient indexing for fast similarity searches
- **Distance Functions**:
  - Cosine distance
  - Euclidean distance
  - Inner product
  - And more...
- **Approximate Nearest Neighbor (ANN)**: High-performance approximate search
- **Multiple Formats**: Support for JSON, binary, and other vector formats
- **Batch Operations**: Efficient bulk vector operations

### Vector Search Functions
```sql
-- Create a vector table
CREATE VIRTUAL TABLE my_vectors USING vec0(
    vector float[128]
);

-- Insert vectors
INSERT INTO my_vectors(rowid, vector)
VALUES (1, json('[0.1, 0.2, 0.3, ..., 0.128]'));

-- Search for similar vectors
SELECT rowid, distance
FROM my_vectors
WHERE vector MATCH json('[0.1, 0.2, 0.3, ..., 0.128]')
LIMIT 10;
```

## Source Files

### sqlite-vec.c
The main implementation file containing:
- Virtual table interface (vec0)
- Vector distance calculations
- Search algorithms
- Extension initialization

### sqlite-vec.h
Header file with:
- Function declarations
- Type definitions
- API documentation

### sqlite-vec.h.tmpl
Template for generating the header file.

## Integration in ProxySQL

These source files are integrated into ProxySQL through static linking:

### Compilation Flags
In ProxySQL's build system, sqlite-vec is compiled with these flags:
- `-DSQLITE_CORE` - Compile as part of SQLite core
- `-DSQLITE_VEC_STATIC` - Enable static linking mode
- `-DSQLITE_ENABLE_MEMORY_MANAGEMENT` - Memory management features
- `-DSQLITE_ENABLE_JSON1` - JSON support
- `-DSQLITE_DLL=1` - DLL compatibility

### Integration Process
1. Sources are stored in this directory (committed to repository)
2. During build, copied to the build directory
3. Compiled with static linking flags
4. Linked into `libproxysql.a`
5. Auto-loaded when SQLite databases are opened

## Licensing

sqlite-vec is licensed under the [MIT License](LICENSE). Please refer to the original project for complete license information.

## Documentation

For complete documentation, examples, and API reference, see:
- [sqlite-vec GitHub Repository](https://github.com/asg017/sqlite-vec)
- [sqlite-vec Documentation](https://sqlite-vec.github.io/)

## Building Standalone

To build sqlite-vec standalone (outside of ProxySQL):
```bash
# Download source
git clone https://github.com/asg017/sqlite-vec.git
cd sqlite-vec

# Build the extension
gcc -shared -fPIC -o libsqlite_vec.so sqlite_vec.c -I/path/to/sqlite/include \
  -DSQLITE_VEC_STATIC -DSQLITE_ENABLE_JSON1
```

## Performance Considerations

- Use appropriate vector dimensions for your use case
- Consider the trade-offs between exact and approximate search
- Batch operations are more efficient than single-row operations
- Indexing improves search performance for large datasets

## Contributing

This is a third-party library integrated into ProxySQL. For bugs, features, or contributions:
1. Check the [sqlite-vec repository](https://github.com/asg017/sqlite-vec)
2. Report issues or contribute to the sqlite-vec project
3. ProxySQL-specific integration issues should be reported to the ProxySQL project