# sqlite-rembed Integration into ProxySQL

## Overview

This document describes the integration of the `sqlite-rembed` Rust SQLite extension into ProxySQL, enabling text embedding generation from remote AI APIs (OpenAI, Nomic, Ollama, Cohere, etc.) directly within ProxySQL's SQLite3 Server.

## What is sqlite-rembed?

`sqlite-rembed` is a Rust-based SQLite extension that provides:
- `rembed()` function for generating text embeddings via HTTP requests
- `temp.rembed_clients` virtual table for managing embedding API clients
- Support for multiple embedding providers: OpenAI, Nomic, Cohere, Ollama, Llamafile
- Automatic handling of API authentication, request formatting, and response parsing

## Integration Architecture

The integration follows the same pattern as `sqlite-vec` (vector search extension):

### Static Linking Approach
1. **Rust static library**: `libsqlite_rembed.a` built from Rust source
2. **Build system integration**: Makefile targets for Rust compilation
3. **Auto-registration**: `sqlite3_auto_extension()` in ProxySQL initialization
4. **Single binary deployment**: No external dependencies at runtime

### Technical Implementation

```
ProxySQL Binary
├── C++ Core (libproxysql.a)
├── SQLite3 (sqlite3.o)
├── sqlite-vec (vec.o)
└── sqlite-rembed (libsqlite_rembed.a) ← Rust static library
```

## Build Requirements

### Rust Toolchain
```bash
# Required for building sqlite-rembed
rustc --version
cargo --version

# Development dependencies
clang
libclang-dev
```

### Build Process
1. Rust toolchain detection in `deps/Makefile`
2. Static library build with `cargo build --release --features=sqlite-loadable/static --lib`
3. Linking into `libproxysql.a` via `lib/Makefile`
4. Final binary linking via `src/Makefile`

## Code Changes Summary

### 1. `deps/Makefile`
- Added Rust toolchain detection (`rustc`, `cargo`)
- SQLite environment variables for sqlite-rembed build
- New target: `sqlite3/libsqlite_rembed.a`
- Added dependency to `sqlite3` target

### 2. `lib/Makefile`
- Added `SQLITE_REMBED_LIB` variable pointing to static library
- Library included in `libproxysql.a` dependencies (via src/Makefile)

### 3. `src/Makefile`
- Added `SQLITE_REMBED_LIB` variable
- Added `$(SQLITE_REMBED_LIB)` to `LIBPROXYSQLAR` dependencies

### 4. `lib/Admin_Bootstrap.cpp`
- Added `extern "C" int sqlite3_rembed_init(...)` declaration
- Added `sqlite3_auto_extension((void(*)(void))sqlite3_rembed_init)` registration
- Registered after `sqlite-vec` initialization

## Usage Examples

### Basic Embedding Generation
```sql
-- Register an OpenAI client
INSERT INTO temp.rembed_clients(name, format, model, key)
VALUES ('openai_client', 'openai', 'text-embedding-3-small', 'your-api-key');

-- Generate embedding
SELECT rembed('openai_client', 'Hello world') as embedding;

-- Use with vector search
CREATE VECTOR TABLE docs (embedding float[1536]);
INSERT INTO docs(rowid, embedding)
VALUES (1, rembed('openai_client', 'Document text here'));

-- Search similar documents
SELECT rowid, distance FROM docs
WHERE embedding MATCH rembed('openai_client', 'Query text');
```

### Multiple API Providers
```sql
-- OpenAI
INSERT INTO temp.rembed_clients(name, format, model, key, url)
VALUES ('gpt', 'openai', 'text-embedding-3-small', 'sk-...');

-- Ollama (local)
INSERT INTO temp.rembed_clients(name, format, model, url)
VALUES ('ollama', 'ollama', 'nomic-embed-text', 'http://localhost:11434');

-- Cohere
INSERT INTO temp.rembed_clients(name, format, model, key)
VALUES ('cohere', 'cohere', 'embed-english-v3.0', 'co-...');

-- Nomic
INSERT INTO temp.rembed_clients(name, format, model, key)
VALUES ('nomic', 'nomic', 'nomic-embed-text-v1.5', 'nm-...');
```

## Configuration

### Environment Variables (for building)
```bash
export SQLITE3_INCLUDE_DIR=/path/to/sqlite-amalgamation
export SQLITE3_LIB_DIR=/path/to/sqlite-amalgamation
export SQLITE3_STATIC=1
```

### Runtime Configuration
- API keys: Set via `temp.rembed_clients` table
- Timeouts: Handled by underlying HTTP client (ureq)
- Model selection: Per-client configuration

## Error Handling

The extension provides SQLite error messages for:
- Missing client registration
- API authentication failures
- Network connectivity issues
- Invalid input parameters
- Provider-specific errors

## Performance Considerations

### HTTP Latency
- Embedding generation involves HTTP requests to remote APIs
- Consider local embedding models (Ollama, Llamafile) for lower latency
- Batch processing not currently supported (single text inputs only)

### Caching
- No built-in caching layer
- Applications should cache embeddings when appropriate
- Consider database-level caching with materialized views

## Limitations

### Current Implementation
1. **Blocking HTTP requests**: Synchronous HTTP calls may block SQLite threads
2. **Single text input**: `rembed()` accepts single text string, not batches
3. **No async support**: HTTP requests are synchronous
4. **Rust dependency**: Requires Rust toolchain for building ProxySQL

### Security Considerations
- API keys stored in `temp.rembed_clients` table (in-memory, per-connection)
- Network access required for remote APIs
- No encryption of API keys in transit (use HTTPS endpoints)

## Testing

### Build Verification
```bash
# Verify Rust library builds
cd deps && make sqlite3

# Verify symbol exists
nm deps/sqlite3/libsqlite_rembed.a | grep sqlite3_rembed_init
```

### Functional Testing
```sql
-- Test extension registration
SELECT rembed_version();
SELECT rembed_debug();

-- Test client registration
INSERT INTO temp.rembed_clients(name, format, model)
VALUES ('test', 'ollama', 'nomic-embed-text');

-- Test embedding generation (requires running Ollama)
-- SELECT rembed('test', 'test text');
```

## Future Enhancements

### Planned Improvements
1. **Async HTTP**: Non-blocking requests using async Rust
2. **Batch processing**: Support for multiple texts in single call
3. **Embedding caching**: LRU cache for frequently generated embeddings
4. **More providers**: Additional embedding API support
5. **Configuration persistence**: Save clients across connections

### Integration with sqlite-vec
- Complete AI pipeline: `rembed()` → vector storage → `vec_search()`
- Example: Document embedding and similarity search
- Potential for RAG (Retrieval-Augmented Generation) applications

## Troubleshooting

### Build Issues
1. **Missing clang**: Install `clang` and `libclang-dev`
2. **Rust not found**: Install Rust toolchain via `rustup`
3. **SQLite headers**: Ensure `sqlite-amalgamation` is extracted

### Runtime Issues
1. **Client not found**: Verify `temp.rembed_clients` entry exists
2. **API errors**: Check API keys, network connectivity, model availability
3. **Memory issues**: Large embeddings may exceed SQLite blob limits

## References

- [sqlite-rembed GitHub](https://github.com/asg017/sqlite-rembed)
- [sqlite-vec Documentation](../doc/SQLite3-Server.md)
- [SQLite Loadable Extensions](https://www.sqlite.org/loadext.html)
- [Rust C FFI](https://doc.rust-lang.org/nomicon/ffi.html)

## Maintainers

- Integration: [Your Name/Team]
- Original sqlite-rembed: [Alex Garcia (@asg017)](https://github.com/asg017)
- ProxySQL Team: [ProxySQL Maintainers](https://github.com/sysown/proxysql)

## License

- sqlite-rembed: Apache 2.0 / MIT (see `deps/sqlite3/sqlite-rembed-source/LICENSE-*`)
- ProxySQL: GPL v3
- Integration code: Same as ProxySQL
