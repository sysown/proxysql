# Vendored DuckDB

DuckDB is built as a static library for the `PROXYSQL40` plugin tier. The
complete source archive and SHA-256 sidecar are committed directly to git.
`verify-source.bash` checks the checksum and archive root before extraction.

## Pinned source

- **Version:** DuckDB **v2.0.0** (LTS)
- **Release:** https://github.com/duckdb/duckdb/releases/tag/v2.0.0
- **Upstream archive:** https://github.com/duckdb/duckdb/archive/refs/tags/v2.0.0.tar.gz
- **Upstream gzip SHA-256:** `7e89053255046bfb26afbd7f524a2fb84df7dbef496aa911ea35e4a1182fdc00`
- **Vendored archive:** `duckdb-2.0.0.tar.xz` (86,703,408 bytes)
- **Vendored SHA-256:** `853148808ccfbb916465066d5701ce89fc60db8d2d6f2defacba2ae75be13e59`
- **Uncompressed tar SHA-256:** `271f44bb49145f16aabdb189ee5532e252721f53069e9ad61a072e113f7a565c`
- **Archive root:** `duckdb-2.0.0/`

The upstream gzip archive is 106,477,075 bytes, exceeding GitHub's 100 MiB
file limit. It is recompressed using XZ Utils without changing the tar stream
or excluding source files. No Git LFS or build-time download is required.
The pinned archive was produced with XZ Utils 5.4.5:

```bash
curl --fail -L -o duckdb-2.0.0.tar.gz \
  https://github.com/duckdb/duckdb/archive/refs/tags/v2.0.0.tar.gz
gzip -dc duckdb-2.0.0.tar.gz | xz -T2 -9e > duckdb-2.0.0.tar.xz
sha256sum duckdb-2.0.0.tar.gz duckdb-2.0.0.tar.xz
gzip -dc duckdb-2.0.0.tar.gz | sha256sum
xz -dc duckdb-2.0.0.tar.xz | sha256sum
```

Check both decompressed hashes match. Other compressor versions or thread
settings may produce a different compressed checksum; the tar hash must match.

## Compatibility

DuckDB 2.0 requires C++17, already required by ProxySQL. Source builds also
need CMake 3.14 or newer and XZ-capable tar (GNU tar needs `xz` / `xz-utils`). The verifier
reports a missing decompressor before extraction. The v1 C API remains in
`duckdb.h`; the separate v2 C API is not used by the plugin.

New 2.0 database files use a storage format unreadable by DuckDB 1.x. Opening
an existing 1.x file preserves its storage format. Before upgrading, back up
persistent files and test application SQL: 2.0 uses the PEG parser by default
and disables single-arrow lambdas. Use `lambda x: ...` for lambdas. Restore a
backup or export/import into a file explicitly created with an older
`STORAGE_VERSION` when rolling back a new 2.0 database. External DuckDB
extensions must match the engine release and platform.

See the [release announcement](https://duckdb.org/2026/10/21/announcing-duckdb-200)
and [storage compatibility](https://duckdb.org/docs/2.0/internals/storage).

## Building

```bash
make -C deps PROXYSQL40=1 duckdb
```

This produces `duckdb/build/release/src/libduckdb_static.a` and headers under
`duckdb/src/include/`. `include/makefiles_paths.mk` exposes these as
`DUCKDB_PATH`, `DUCKDB_IDIR` and `DUCKDB_LDIR`.

`DEPS_MODE=auto` restores an exact verified compiled artifact when registered,
otherwise builds the vendored source. Use `DEPS_MODE=source` for source-only
preparation or `DEPS_MODE=prebuilt` to require an artifact. See
[compiled dependency reuse](../../doc/dependency-artifacts.md).

The plugin needs every static archive listed in the generated
`build/release/DuckDBExports.cmake`. `list-static-archives.sh` rejects missing
or empty archives before linking and uses relative paths for relocated caches.
The set depends on platform and configuration. DuckDB exports capability
archives (HTTP and loadable extensions), a C++ API archive under `tools/cpp/`,
and jemalloc under `third_party/` on Linux. Static consumers compile the
generated extension loader and upstream autoregistration source directly into
their final binary or plugin; the archives alone do not register core SQL
functions. Both loader sources are included in compiled dependency bundles.
The build enables HTTP and loadable-extension capabilities explicitly, excluding
the build-local extension repository so relocated binaries do not retain its path.
TSAN builds force
`ENABLE_THREAD_SANITIZER=ON` and `ENABLE_JEMALLOC=OFF`; excluding a jemalloc
extension alone does not disable the allocator in this release.

The root Makefile exports `PROXYSQL40` to dependency sub-makes. Direct plugin
builds also reevaluate dependency preparation. The focused source recipe and
version settings are in `build.mk`. `DUCKDB_OPTIMIZATION_PROFILE=NONE` preserves
the compiler target baseline; upstream's CLI profile otherwise selects
`-march=x86-64-v3` for Linux release builds.

## Updating the source

1. Download the upstream release and record its checksum. If recompression is
   needed, preserve the complete tar stream and record both compressed hashes
   and the matching tar hash. Keep the committed file below 100 MiB.
2. Update the archive, SHA-256 sidecar, verifier defaults/root and `build.mk`
   version. Keep archive suffixes consistent with `deps/artifacts/identity.py`
   and the no-Python fallback in `deps/artifacts/prepare.bash`.
3. Remove the previous archive and sidecar. Update fixture version expectations
   and installation documentation. Old compiled artifacts cannot match the
   changed source/recipe identity; publish new artifacts separately.
4. Run the source-verifier and dependency-artifact tests, rebuild DuckDB and
   the plugin, and run DuckDB integration/unit tests. Check existing and newly
   created persistent files when storage compatibility changes.

## Result API

The pinned `duckdb.h` still declares `duckdb_value_varchar`, `duckdb_row_count`
and `duckdb_value_is_null`. They are deprecated and included by default
(`DUCKDB_API_ALLOW_DEPRECATED=1`); `DUCKDB_API_NO_DEPRECATED` hides them.
Recheck declarations and call sites on each future upgrade.

The plugin converts results using materialized chunks, vector data and
validity masks to preserve embedded NUL bytes and distinguish SQL NULLs.
Some result/session paths and tests still use deprecated accessors.
`GEOMETRY` and `VARIANT`, introduced after 1.4, remain outside the plugin's
explicit supported-type list and are rejected before conversion.
