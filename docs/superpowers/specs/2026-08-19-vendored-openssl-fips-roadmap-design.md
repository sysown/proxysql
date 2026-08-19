# Vendored OpenSSL and Future FIPS Roadmap Design

## Purpose

Restore a reproducible, mandatory vendored OpenSSL build for ProxySQL while
preserving a technically and procedurally sound path to a future FIPS mode.
Vendoring and static linking are the first project. FIPS support is a later,
explicitly enabled product capability with separate runtime, packaging,
testing, and compliance gates.

The design applies to every supported build platform: Linux, macOS, and
FreeBSD. ProxySQL will not provide a system-OpenSSL build mode.

Tracking issue: <https://github.com/sysown/proxysql/issues/6114>

## Decisions

- Vendor the latest patch of OpenSSL 3.5 LTS, initially OpenSSL 3.5.7.
- Statically link the vendored `libssl` and `libcrypto` into ProxySQL.
- Keep OpenSSL's DSO and provider machinery enabled so a future dynamically
  loaded FIPS provider remains possible.
- Store the upstream OpenSSL source archive in Git LFS and store its expected
  SHA-256 digest as ordinary Git text.
- Make vendored OpenSSL mandatory on Linux, macOS, and FreeBSD, including all
  ProxySQL-owned tools and test binaries that use OpenSSL. Runtime plugins use
  the executable's single OpenSSL instance rather than embedding another copy.
- Do not build, package, load, or advertise a FIPS provider in the initial
  vendoring milestone.
- Do not load a system-installed `fips.so` in the future FIPS mode. ProxySQL
  will ship and support an exact provider artifact and qualify it with the
  chosen vendored OpenSSL core.
- Treat FIPS as a fail-closed, explicit operating mode. Normal ProxySQL builds
  and installations must never imply FIPS approval.

OpenSSL 3.5 is an LTS series supported until 8 April 2030. The current pinned
release is 3.5.7:

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

## Milestone 1: Mandatory Vendored OpenSSL

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

## Milestone 1 Verification

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

## Future FIPS Architecture

### Validation boundary and version pairing

The FIPS cryptographic boundary is the dynamically loaded FIPS provider, not
the statically linked OpenSSL core. OpenSSL documents that a provider built
from a validated OpenSSL release can normally be used with `libcrypto` and
`libssl` from another release in the same major series. This permits the core
to receive security fixes outside the validated boundary:

<https://docs.openssl.org/master/man7/fips_module/>

The current OpenSSL FIPS 140-3 validation is the OpenSSL FIPS Provider 3.1.2,
NIST certificate 4985, active with a sunset date of 10 March 2030:

<https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985>

Technical compatibility is not by itself a compliance conclusion. ProxySQL
will select one exact provider source release, build recipe, module digest,
and vendored-core combination. The supported FIPS package will load only that
provider. Loading whatever `fips.so` happens to be installed on a host is
explicitly unsupported because it makes the tested combination, module
identity, and security-policy obligations unknowable.

Before release, the chosen combination and each supported operating
environment must be reviewed against the provider's current NIST certificate
and security policy. Product language must distinguish a package that is
technically FIPS-capable from a deployment that is correctly installed and
operating in approved mode.

### Packaging model

FIPS support will be delivered as an explicit FIPS package/profile layered on
the same statically linked ProxySQL core. It will contain:

- the exact supported `fips.so` for the package platform and architecture;
- licensing, NIST certificate, and unmodified security-policy references;
- the matching OpenSSL command-line utility or a controlled installer using
  the same core implementation;
- a ProxySQL-owned parent OpenSSL configuration template;
- an installation helper that generates and verifies `fipsmodule.cnf`;
- service configuration that gives ProxySQL explicit configuration and module
  paths rather than relying on ambient system defaults;
- diagnostics for provider identity and approved-mode activation.

The provider will be built dynamically even though the ProxySQL OpenSSL core
is static. It will not be folded into the executable or `libcrypto.a`.

### Installation configuration

The package will not ship a pre-generated installation-status configuration
and pretend that installation self-tests ran on the target. During package
installation or an explicit administrator command, the helper will run the
equivalent of:

```text
openssl fipsinstall -pedantic \
  -module <ProxySQL-owned absolute path>/fips.so \
  -out <ProxySQL-owned configuration path>/fipsmodule.cnf
```

The command loads the exact module, runs the required self-tests, verifies its
integrity, and writes module/install MAC state. The output will be written
atomically with restrictive ownership and permissions, then verified with
`openssl fipsinstall -verify` before the service may enter FIPS mode. This is
per-installation procedure, not a binding to a motherboard or host identity.

The strict installation behavior is documented at:
<https://docs.openssl.org/master/man1/openssl-fipsinstall/>

### Runtime activation and failure behavior

FIPS mode will be process-wide and startup-only. It must be selected explicitly
through the FIPS package's service configuration. ProxySQL will initialize the
default OpenSSL library context before any TLS, authentication, certificate,
random-number, or plugin operation can use OpenSSL.

Startup in FIPS mode will:

1. load only the ProxySQL-owned parent configuration and module paths;
2. load and activate the supported FIPS provider and required base provider;
3. set the default property query to `fips=yes`;
4. verify that FIPS default properties are enabled;
5. fetch representative required algorithms with `fips=yes`;
6. report the core version, provider version, module path, and configuration
   path;
7. continue only when every check succeeds.

The FIPS provider may contain non-approved algorithms, so merely loading it is
insufficient. OpenSSL requires `fips=yes` for applications operating in an
approved manner. ProxySQL will set that property globally and use explicit
property queries for security-critical fetches:

<https://docs.openssl.org/master/man7/fips_module/>

Missing files, bad permissions, integrity failures, provider self-test
failures, unsupported algorithms, configuration parse failures, or version
mismatches will terminate startup. ProxySQL will never fall back to the
default provider while claiming FIPS mode.

Normal mode will continue using the statically linked vendored OpenSSL default
provider and will not search for or activate `fips.so`.

### Cryptographic API and protocol audit

All cryptographic operations must flow through provider-aware high-level APIs.
The current source contains work that must be completed before FIPS mode can be
enabled:

- direct low-level `SHA1` and `SHA256` calls and `SHA*_Init/Update/Final`
  sequences in MySQL authentication, admin credential handling, file hashing,
  and startup code;
- deprecated `HMAC_CTX` APIs in the optimized SCRAM implementation, which
  should move to `EVP_MAC` with a FIPS property query;
- PostgreSQL MD5 authentication through `EVP_md5()`, which is unavailable in
  approved mode and must be rejected in FIPS mode in favor of SCRAM;
- RSA key generation, RSA-OAEP, X.509 signing, certificate parsing, random
  generation, and digest helpers that require provider/property/error-path
  verification;
- MySQL native-password SHA-1 and caching-SHA2 RSA-OAEP/SHA-1 flows whose exact
  approved-use conditions must be mapped to the security policy;
- Ed25519 authentication, which is not an approved algorithm in the currently
  validated provider and must be disabled in FIPS mode;
- TLS policy currently permitting TLS 1.0, which must be replaced by an
  approved FIPS-profile minimum, ciphersuite, group, signature, key-size, and
  certificate policy;
- third-party static libraries that call OpenSSL and therefore share the
  process default library context.

The audit also covers shared plugins. They must continue using the sole
executable-owned OpenSSL core so provider activation and default properties
apply to their operations.

Each operation will have an explicit disposition: approved and tested,
reimplemented with provider-aware EVP APIs, or unavailable with a clear error
in FIPS mode. Protocol compatibility will not override the approved-mode
boundary.

### GnuTLS boundary

ProxySQL's admin web HTTPS path uses libmicrohttpd/GnuTLS, not OpenSSL. An
OpenSSL FIPS provider cannot make those cryptographic operations FIPS approved.
The first supported FIPS profile will therefore disable admin web HTTPS unless
that GnuTLS path is separately paired with a validated module and reviewed as
part of the product boundary. Plain admin SQL access can remain available over
the separately evaluated ProxySQL TLS paths.

This limitation must be visible in startup diagnostics and documentation. A
whole-product FIPS statement is prohibited while an enabled cryptographic
surface operates outside the reviewed boundary.

### Diagnostics and operations

FIPS mode will expose enough state for an operator and support engineer to
verify the running configuration without treating a boolean as proof of
compliance:

- whether FIPS mode was requested and whether startup admitted it;
- embedded OpenSSL core version;
- loaded provider name and version;
- canonical provider module and configuration paths;
- whether `fips=yes` is set on the default library context;
- last installation verification and startup self-test result;
- reasons an algorithm or protocol feature is disabled.

Secrets, keys, module MAC keys, and sensitive configuration contents will not
be logged.

### FIPS verification matrix

The future FIPS work will add positive and negative tests covering:

- provider installation and verification on each supported package platform;
- static OpenSSL core plus dynamic FIPS provider loading;
- exact provider/core version acceptance and mismatch rejection;
- missing, moved, truncated, and tampered provider files;
- missing, malformed, stale, and tampered `fipsmodule.cnf`;
- startup self-test failure with fail-closed behavior;
- `fips=yes` fetches for every required digest, MAC, KDF, cipher, signature,
  key-exchange, key-generation, and random-generation operation;
- rejection of MD5, Ed25519, disallowed key sizes, disallowed TLS versions,
  and every other unsupported protocol flow;
- MySQL and PostgreSQL frontend/backend TLS and authentication paths that are
  declared supported;
- certificate creation, loading, rotation, and verification;
- package install, upgrade, rollback, relocation, and read-only filesystem
  behavior;
- diagnostics that accurately distinguish normal, failed-FIPS, and admitted
  FIPS mode;
- confirmation that normal packages do not load the FIPS provider;
- checks against the supported operational environments in the applicable
  NIST security policy.

Release qualification will preserve the provider binary and build evidence,
archive hashes, compiler/configuration inputs, installation procedure, test
results, and the exact ProxySQL commit associated with the package.

## Delivery Sequence

1. Restore mandatory vendored OpenSSL 3.5 LTS and prove static linkage.
2. Remove system OpenSSL build and packaging assumptions from every platform.
3. Inventory and classify every ProxySQL and bundled-dependency cryptographic
   operation.
4. Migrate low-level/deprecated calls to provider-aware EVP APIs without
   enabling FIPS mode.
5. Add negative tests for protocol features that cannot operate in approved
   mode.
6. Produce and archive a reproducible build of the selected validated FIPS
   provider for each candidate operational environment.
7. Add the FIPS package/profile, installation helper, strict startup
   activation, and diagnostics.
8. Run the complete FIPS verification matrix and security-policy review.
9. Publish narrowly scoped compliance documentation only for combinations
   that passed qualification.

Each step may ship independently except that no FIPS package or claim may ship
before steps 1 through 8 are complete for its supported platform.

## Non-goals

- The vendoring milestone does not make ProxySQL FIPS compliant.
- ProxySQL will not support arbitrary system OpenSSL libraries or providers.
- ProxySQL will not promise that any OpenSSL 3 core and provider combination
  is supported merely because their public ABI is compatible.
- ProxySQL will not pre-generate installation self-test status for another
  machine or package image.
- ProxySQL will not silently downgrade cryptography or fall back from FIPS
  mode.
- The initial FIPS profile will not claim admin web HTTPS until its GnuTLS
  boundary is separately resolved.
- This design does not select or claim new validation for a future OpenSSL 4.x
  core.

## Acceptance Boundary

Milestone 1 is accepted when ProxySQL builds exclusively against the pinned
vendored OpenSSL and release artifacts prove static linkage on all supported
platforms.

Future FIPS support is accepted only for an explicitly enumerated package,
platform, architecture, provider/core pair, installation procedure, runtime
configuration, and protocol feature set. The technical tests and the current
NIST security policy must both support that claim.
