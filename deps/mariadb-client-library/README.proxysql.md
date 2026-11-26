# ProxySQL's vendored MariaDB Connector/C

The connector is selected at build time. Stable and standalone v3.1 use the
existing 3.3.8 archive and the `mariadb_client` symlink. Builds with
`PROXYSQL40=1` use 3.4.11 and its own extracted tree. The separate 3.1.9
compatibility client under `test/deps` retains its independent pin.

The selection is shared by the dependency, core, daemon, plugin, and test
Makefiles. The v4.0 build tracks archive, checksum, patch files, OpenSSL and
build settings as prerequisites. The dependency artifact store does not
publish a standalone Connector/C bundle. CI's built products are bound to
the source revision and product tier.

The [upstream 3.4.11 tag](https://github.com/mariadb-corporation/mariadb-connector-c/releases/tag/v3.4.11)
points to `be67a4fc1e0493913732df90e562f122bff9dfe3`. The
[official source archive](https://archive.mariadb.org/connector-c-3.4.11/mariadb-connector-c-3.4.11-src.tar.gz)
is verified before extraction using the adjacent SHA-256 file, which matches
the [published checksum](https://downloads.mariadb.org/rest-api/connector-c/3.4.11/mariadb-connector-c-3.4.11-src.tar.gz/checksum/).
The source archives carry the upstream license notices.

## Patch disposition

`build-3.4.mk` is the ordered manifest. It applies every selected patch with
zero fuzz. All 3.3.8 patches stay in place for lower tiers.

| Area | 3.4.11 disposition |
| --- | --- |
| Build and plugins | Replace `plugin_auth_CMakeLists.txt.patch` with upstream static options for Ed25519, caching SHA-2, SHA-256 and cleartext. Add `ed25519_visibility.patch` to preserve the core's access to the keypair and verification symbols when it is linked as a shared TAP library. Replace `cmakelists.txt.patch` with explicit charset and warnings settings. Replace `mariadb_asan.patch` with upstream `WITH_ASAN`, which instruments the actual RelWithDebInfo target. |
| Compiler portability | Upstream guards its C23 `bool` typedef and fixes the bundled zlib prototypes and old `fdopen` stubs. The candidate omits `bool_keyword.patch`, `zutil.c.patch` and `zutil.h.patch`. The separate allocator and zlib overflow guards are retained. |
| Async and connection lifecycle | Retain `mariadb_lib.c.patch`, `mariadb_lib.c.ipv6_fix.patch`, `mariadb_async.c.patch`, `mysql.h.patch`, `ma_priv.h.patch`, and conditional `ma_context.h.patch`. Use upstream nonblocking socket and TLS I/O instead of the removed blocking-mode calls. Preserve the pre-greeting PROXY header and close-without-command API. |
| Charsets, allocation and password handling | Retain `mariadb_lib.c.collation.patch`, `ma_charset.c.patch`, `ma_password.c.patch`, `ma_alloc.c.patch`, `ma_array.c-multiplication-overflow.patch`, `mariadb_dyncol.c-multiplication-overflow.patch`, and `zutil.c-multiplication-overflow.patch`. Adapt the `unittest_basic-t.c.patch` and `unittest_charset.c.patch` test callers to the patched charset interface. |
| Prepared statements and wire protocol | Retain `mariadb_stmt.c.patch`, `cr_new_stmt_metadata_removal.patch`, `ps_buffer_stmt_read_all_rows.patch`, `mariadb_stmt_store_result_err.patch`, `mariadb_lib.c.metadata_column_check.patch`, `empty_split_compress_packet.patch`, `client_deprecate_eof.patch` and `mariadb_com.h.patch`. The rebase preserves upstream metadata bounds checks and makes the patched capability bits eligible for negotiation. |
| TLS | Retain `tls_server_name.patch`, `sslkeylogfile.patch`, and `x509cache.patch`. Place ProxySQL's TLS options after upstream's latest option range. Use vendored OpenSSL and explicitly retain the 3.3.8 certificate verification default. Preserve chain verification when a CA is configured and peer name verification when requested. |
| Replication | Retain `mariadb_rpl.patch` and `mariadb_rpl_rows.patch` for heartbeat and rows-query events, row decoding and binlog rotation. DuckDB uses 3.4.11's typed timestamp values without changing the resulting SQL representation. |

## Verification and rollback

Run `bash test/infra/control/test-mariadb-connector-selection.bash --linked`
to build and link probes across Stable, v4.0 and v3.1 in one checkout. The
probe checks both the compile-time and linked version. It also checks that
switching tiers preserves both archives.

Run `PROXYSQL40=1 test/infra/control/test-mariadb-default-trust-store.bash`
after building the production connector to exercise its CA trust and cache
lifetime behavior. The legacy invocation still tests 3.3.8. For release
validation, use the ProxySQL CI tier matrix and applicable package builds.
Cover TLS/auth, async connect and pool behavior, prepared statements,
compression and EOF negotiation, binlog, and DuckDB replication.

For an operational rollback, redeploy the previous v4.0 binary and its
matching plugins together. To revert from source, revert the upgrade as a
unit, including DuckDB's typed timestamp changes and the build selection.
Rebuild the previous v4.0 artifacts and rerun the linked-version and
applicable smoke tests.
