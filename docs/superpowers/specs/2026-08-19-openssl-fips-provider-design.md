# Future OpenSSL FIPS Provider Mode Design

## Purpose

Add a future, explicitly enabled and fail-closed ProxySQL operating mode using
a shipped, validated OpenSSL 3 FIPS provider. This is a cryptographic runtime,
protocol, packaging, qualification, and compliance project. It is not part of
the mandatory OpenSSL vendoring project's definition of done.

Project issue: <https://github.com/sysown/proxysql/issues/6116>

Dependency issue: <https://github.com/sysown/proxysql/issues/6115>

Parent roadmap: <https://github.com/sysown/proxysql/issues/6114>

## Preconditions

- ProxySQL has one statically linked, executable-owned OpenSSL 3 core.
- All ProxySQL, bundled-library, and shared-plugin cryptographic operations use
  that core and its default library context.
- Normal packages build and operate without loading a FIPS provider.
- Static vendoring has passed its independent platform and packaging
  acceptance criteria.

## Approved constraints

- The validated FIPS provider remains a dynamically loaded `fips.so`; it is
  not folded into the executable or `libcrypto.a`.
- ProxySQL ships and qualifies one exact provider/core/platform combination
  and never loads an arbitrary system provider.
- Installation self-tests run for the target installation through
  `fipsinstall`; pre-generated installation status is not copied between
  installations.
- FIPS mode is process-wide, startup-only, explicit, and fail-closed.
- Approved algorithm selection requires `fips=yes`; merely loading the FIPS
  provider is insufficient.
- Normal ProxySQL packages do not load or advertise the FIPS provider.
- Product claims remain narrower than technical capability and require review
  against the applicable NIST certificate and security policy.

## Architecture

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

## Delivery sequence

1. Inventory and classify every ProxySQL, bundled-library, and plugin
   cryptographic operation.
2. Migrate low-level and deprecated calls to provider-aware EVP APIs while
   preserving normal-mode behavior.
3. Add negative tests for protocol operations that cannot run in approved
   mode.
4. Select exact validated provider/core/platform combinations and archive the
   reproducible provider build evidence.
5. Add the FIPS package/profile and per-installation configuration helper.
6. Add early provider activation, `fips=yes` enforcement, strict startup
   verification, and diagnostics.
7. Resolve or disable the separate GnuTLS HTTPS boundary.
8. Run the full positive, negative, tamper, package-lifecycle, and operational
   environment qualification matrix.
9. Publish narrowly scoped compliance documentation only for combinations
   that passed qualification.

## Non-goals

- Reopening the decision to source-vendor OpenSSL.
- Loading a system-installed or otherwise unqualified FIPS provider.
- Treating API/ABI compatibility as proof of a supported or compliant
  provider/core pairing.
- Shipping pre-generated installation status for another machine or package
  image.
- Silently falling back to non-FIPS cryptography.
- Claiming admin web HTTPS until its GnuTLS boundary is separately resolved.
- Selecting or claiming a new validation for an OpenSSL 4.x core.

## Acceptance boundary

FIPS support is accepted only for an explicitly enumerated package, platform,
architecture, provider/core pair, installation procedure, runtime
configuration, and protocol feature set. Both the technical qualification
matrix and the current NIST security policy must support any published claim.
