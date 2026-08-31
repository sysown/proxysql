# Mandatory Vendored OpenSSL Design

## Purpose

Restore OpenSSL as a mandatory source-vendored dependency and statically link
one vendored OpenSSL 3.5 LTS core into ProxySQL on Linux, macOS, and FreeBSD.
This is a build, dependency, and release-packaging project. It does not build,
load, configure, or claim a FIPS provider.

Project issue: <https://github.com/sysown/proxysql/issues/6115>

Parent roadmap: <https://github.com/sysown/proxysql/issues/6114>

## Approved decisions

- Pin the latest OpenSSL 3.5 LTS patch, initially OpenSSL 3.5.7.
- Do not provide a system-OpenSSL build mode.
- Track the exact upstream source archive with Git LFS and verify its published
  SHA-256 before extraction.
- Keep DSO and provider support enabled by avoiding `no-module` and `no-dso`.
- Use the vendored headers and libraries for every ProxySQL-owned OpenSSL
  consumer on every supported platform.
- Make the ProxySQL executable the sole owner of the OpenSSL runtime. Shared
  plugins compile against the vendored headers but do not embed another
  OpenSSL implementation.
- Remove dynamic OpenSSL runtime dependencies and tarball bundling after static
  linkage is proven.
- Remain on the OpenSSL 3.5 LTS series until a separately reviewed design
  selects a successor.

OpenSSL 3.5 is supported until 8 April 2030. The initial 3.5.7 source release
and lifecycle are published at:

- <https://www.openssl-library.org/source/>
- <https://www.openssl-library.org/policies/releasestrat/>

## Current State

ProxySQL changed from vendored, statically linked OpenSSL to system, dynamic
OpenSSL in 3.0.1. The current build discovers headers and libraries through
`common_mk/openssl_flags.mk`, checks for a minimum system version through
`common_mk/openssl_version_check.mk`, and links `-lssl -lcrypto` dynamically in
`src/Makefile`.

The release tarball work added after that transition copies the build host's
`libssl.so.3` and `libcrypto.so.3` into Linux tarballs. That makes the tarball
self-contained at runtime, but it is not source vendoring and does not make
the build reproducible across build distributions.

The earlier vendoring implementation is useful history, but it must not be
restored wholesale. In particular, the newer code no longer depends on
OpenSSL's internal BIO structures. The implementation will restore dependency
ownership and static linkage without reverting those public-API cleanups.

## Implementation design

### Source ownership and integrity

`deps/libssl/openssl-3.5.7.tar.gz` will be tracked by an exact-path rule in
`.gitattributes`:

```text
deps/libssl/openssl-3.5.7.tar.gz filter=lfs diff=lfs merge=lfs -text
```

The rule will not match the repository's other vendored tarballs. A companion
SHA-256 file will contain the digest published by OpenSSL. The build will check
the archive before extraction and fail with a direct explanation if the file
is an unhydrated Git LFS pointer, missing, or has the wrong digest.

Every GitHub Actions job that builds ProxySQL or its OpenSSL-dependent tests
will hydrate the LFS object. The repository build documentation will state
that source checkouts require Git LFS and show the recovery command for a
pointer-only checkout.

GitHub-generated source archives omit LFS contents by default. The repository
setting **Include Git LFS objects in archives** must therefore be enabled so
release source archives remain buildable. LFS storage and bandwidth usage are
an accepted operational cost of this decision.

GitHub's archive behavior is documented at:
<https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/managing-git-lfs-objects-in-archives-of-your-repository>

### Build

`deps/Makefile` will restore `libssl` as an early dependency. OpenSSL will be
configured to produce static libraries and position-independent code while
retaining DSO/provider support. The configuration must not use `no-module` or
`no-dso`. Tests may be omitted from normal dependency builds, but the OpenSSL
version-update procedure will run the upstream test suite before the new
archive is accepted.

One canonical set of paths will replace system discovery:

- `SSL_PATH`: extracted vendored OpenSSL tree;
- `SSL_IDIR`: vendored public headers;
- `SSL_LDIR`: directory containing the vendored static archives;
- `LIB_SSL_PATH`: exact `libssl.a` path;
- `LIB_CRYPTO_PATH`: exact `libcrypto.a` path.

These paths will be defined centrally and used by ProxySQL and every bundled
dependency that consumes OpenSSL, including MariaDB Connector/C, libcurl,
PostgreSQL/libpq, libusual, and libscram. Their build targets will depend on
the OpenSSL archive target so parallel builds cannot observe system headers or
partially built vendored archives.

Linux and FreeBSD may continue using linker mode switches for other libraries,
but OpenSSL will be referenced by exact archive paths. macOS will also use the
exact archive paths because it has no GNU `-Bstatic`/`-Bdynamic` equivalent.
Link ordering will retain the dynamic platform libraries needed by the static
OpenSSL archives, including thread and dynamic-loader support.

All ProxySQL tiers use the same OpenSSL build. Debug, sanitizer, coverage,
plugin, cluster-simulator, TAP, and unit-test targets must not silently return
to system OpenSSL.

### Single runtime OpenSSL instance

The ProxySQL executable will be the sole owner of the statically linked
OpenSSL core in a running process. A shared plugin must not contain its own
copy of `libssl.a` or `libcrypto.a`: separate static copies have separate
global state and library contexts, and passing objects such as `SSL_CTX *`
between them is unsafe. It would also prevent one process-wide `fips=yes`
policy from covering plugin operations.

Plugins such as MySQLX will compile against the vendored headers but resolve
their OpenSSL API references from the main executable. The executable already
uses `--export-dynamic` on ELF. Its final link will additionally retain and
export every OpenSSL symbol required by supported plugins, using a reviewed
symbol-retention mechanism or whole-archive link as appropriate for the
platform. macOS will use the corresponding force-load/export behavior while
plugins retain their existing dynamic-lookup model.

CI will inspect each plugin and reject either a dynamic `libssl`/`libcrypto`
dependency or plugin-defined OpenSSL implementation symbols. Plugin load and
TLS tests will prove that the executable-owned OpenSSL functions operate on
the shared contexts successfully.

### Packaging

Linux RPM and Debian metadata will stop declaring OpenSSL as a ProxySQL
runtime dependency when no independently dynamic bundled component requires
it. Build images may retain command-line OpenSSL temporarily if packaging or
test scripts use the executable, but they will not provide headers or libraries
to the ProxySQL link.

The Linux tarball packager will stop copying `libssl.so.3` and
`libcrypto.so.3`. Its runtime smoke test will change from verifying that those
libraries resolve inside the tarball to verifying that neither appears in the
binary's dynamic dependency list.

The initial packages contain no FIPS provider, `fipsmodule.cnf`, FIPS service
configuration, or FIPS claim.

### Update policy

ProxySQL will remain on the OpenSSL 3.5 LTS series until a separately reviewed
design selects a successor. Patch updates will replace the LFS archive,
expected digest, and documented version in one change. Each update must verify
the upstream signature or official digest, run OpenSSL's tests, build all
ProxySQL platforms and tiers, run TLS regressions, and repeat static-linkage
checks.

The build must expose the embedded OpenSSL version through the existing
ProxySQL version/statistics surfaces so operators can inventory security patch
levels without examining the binary manually.

## Verification

The milestone is complete only when all of the following hold:

- the LFS archive is hydrated and matches the expected SHA-256;
- OpenSSL reports the pinned 3.5.x version from the vendored build;
- release and debug dependency builds succeed;
- Linux amd64 and arm64 builds succeed;
- macOS Intel and Apple Silicon builds succeed;
- FreeBSD builds succeed;
- GCC and Clang configurations used by ProxySQL CI succeed;
- the stable, innovative, and plugin-chassis tiers use the same vendored
  headers and archives;
- `readelf`/`ldd` on ELF and `otool -L` on Mach-O show no dynamic dependency on
  `libssl` or `libcrypto`;
- shared plugins neither embed a second OpenSSL implementation nor declare a
  dynamic OpenSSL dependency, and their OpenSSL references resolve from the
  ProxySQL executable;
- no package declares or bundles shared OpenSSL solely for ProxySQL;
- existing MySQL and PostgreSQL TLS tests pass;
- certificate generation, RSA authentication, SCRAM authentication, and
  OpenSSL error-queue tests pass;
- a build with a deliberately unhydrated LFS pointer fails before extraction
  with recovery instructions;
- a build with a corrupted archive fails before extraction;
- documentation states that static vendoring is not a FIPS claim.

## Delivery sequence

1. Add the pinned LFS archive, digest, and preflight tests.
2. Restore the OpenSSL dependency target and canonical vendored paths.
3. Move every bundled dependency to the vendored headers and archives.
4. Link the executable statically and enforce a single OpenSSL runtime for
   plugins.
5. Move ProxySQL tools and tests away from system OpenSSL.
6. Remove obsolete package dependencies and shared-library tarball bundling.
7. Hydrate LFS in every affected CI build.
8. Run the complete cross-platform, cross-tier verification matrix.
9. Document and exercise the OpenSSL patch-update procedure.

## Non-goals

- Building, packaging, or loading `fips.so`.
- Adding a FIPS runtime switch or setting `fips=yes`.
- Migrating cryptographic algorithms solely for FIPS approved mode.
- Defining FIPS protocol restrictions or operational environments.
- Claiming that static vendoring provides FIPS compliance.
- Supporting arbitrary system OpenSSL libraries.

The later FIPS provider project is specified separately in
[2026-08-19-openssl-fips-provider-design.md](2026-08-19-openssl-fips-provider-design.md).

## Acceptance boundary

This project is accepted when ProxySQL builds exclusively against the pinned
vendored OpenSSL and release artifacts prove one statically linked OpenSSL core
on every supported platform. FIPS work is not part of this definition of done.
