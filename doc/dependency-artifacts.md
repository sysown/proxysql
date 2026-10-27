# Compiled dependency reuse

ProxySQL can reuse its own compiled DuckDB and OpenSSL dependencies. The pinned
vendored source archives remain the authority for versions and source builds.
ProxySQL and its plugins still compile against the current checkout.

## Build modes

```bash
PROXYSQL40=1 make -j4 DEPS_MODE=auto
PROXYSQL40=1 make -j4 DEPS_MODE=source
PROXYSQL40=1 make -j4 DEPS_MODE=prebuilt
```

| Mode | DuckDB/OpenSSL behavior |
|---|---|
| `auto` (default) | Reuse an accepted output or restore an exact verified artifact; otherwise build the vendored source and save a reusable bundle. |
| `source` | Use source-origin outputs only. Switching from a prebuilt output rebuilds it from source, without requesting artifacts. |
| `prebuilt` | Require an exact, compatible artifact. Missing entries/downloads fail instead of compiling. |

The mode is exported through recursive Make and Docker Compose package builds.
It also applies to direct dependency builds:

```bash
make -C deps DEPS_MODE=source libssl
make -C deps PROXYSQL40=1 DEPS_MODE=prebuilt duckdb
```

Only DuckDB and OpenSSL use this mechanism. A v3 build does not acquire DuckDB.
`make -n` prints the preparation bridge without downloading, restoring, or
compiling dependencies. Source-only OpenSSL can still build without Python;
the fallback uses Bash, Perl (already required by OpenSSL), and the source tools.

Every eligible source build saves a verified bundle automatically. CI restores
and saves each dependency independently using its full signature. Public bundles
are looked up by that same signature; no registry update is required.

## What makes an artifact compatible

Bundle metadata records the exact build identity, HTTPS release URL, size,
SHA-256 digest, and producer provenance. The identity covers the dependency version, verified
source archive, focused dependency recipe, helper implementation/format, effective
dependency flags, and actual compiler/runtime/target facts. Native macOS includes
the SDK/deployment target; Linux includes the distribution and libc version.

ProxySQL branch, commit, version, and plugin DEBUG mode do not invalidate a
dependency unless they change its actual compilation settings. DuckDB remains a
Release dependency in DEBUG ProxySQL builds, matching its existing source recipe.
Compiler/platform changes conservatively require another artifact. Custom
toolchain files, external include/library search paths, compiler/flag overrides
inside dependency configuration options, and host-native CPU tuning are
ineligible for prebuilt selection; use the source path for those configurations.
This includes DuckDB `NATIVE_ARCH` enabled with any CMake true value.
Clang publication profiles use `clang` and `clang++` by default. Consumers must
select those same commands explicitly, for example:

```bash
CC=clang CXX=clang++ make -j4 PROXYSQL40=1 DEPS_MODE=prebuilt
```

The compiler commands, versions and runtime facts must match the artifact.
Leaving consumer defaults as `cc`/`g++` selects that configuration instead;
`auto` compiles source if no exact artifact exists.

Linux libc is queried from the running system, including with Python 3.6.
Restored dependency directories have mode `0755`, so a host build user can traverse
a tree prepared by a root-run container in a shared checkout. Staging remains
private until payload verification succeeds.

Python-free source preparation uses the same dependency lock and records all
public outputs so a missing header, archive, provider, or license triggers a rebuild.
It verifies the current vendored checksum sidecar before reusing source outputs.
Existing trees without accepted provenance metadata are rebuilt once; presence
of an archive alone is not sufficient for reuse.

DuckDB artifacts contain the headers, complete configured static archive set,
generated archive manifest, and licenses. OpenSSL artifacts contain generated
and public headers, static libraries, produced provider modules, configuration,
and licenses. No ProxySQL binary, plugin binary, object tree, or CMake cache is
restored.

## Automatic publication

Normal CI builds prepare missing bundles on demand and reuse exact cache hits.
`CI-dependency-artifacts.yml` additionally warms the common build profiles when
dependency inputs change on `v3.0`. Pull requests exercise preparation in their
own cache scope. Only reviewed `v3.0` runs publish public release assets.

Each dependency signature has its own immutable prerelease:
`dependency-artifact-v1-<dependency>-<fingerprint>`, containing `entry.json` and
`bundle.tar.gz`. It does not become the latest ProxySQL release. Consumers need
no GitHub token. Existing valid releases are reused; interrupted drafts can be
completed on retry. Unrelated ProxySQL commits keep the same dependency keys.

To warm additional profiles after deploying the workflow to the default branch:

```bash
gh workflow run CI-dependency-artifacts.yml --ref v3.0 \
  -f group=all -f dependency=both
```

Supported groups are `ubuntu24`, `almalinux8`, `macos`, and `all`. An optional
`source_ref` selects another reviewed revision; default-branch dispatches reject
unreviewed source before preparation. Read-only build jobs compile and run real
DuckDB/OpenSSL probes. Separate publication jobs use reviewed publisher code,
validate candidates against the selected source, and serialize only identical
keys. Successfully built profiles can publish even if another profile fails.

The existing checked-in registry remains supported for older publications;
new signature-based releases do not require registry commits.

## Updating a dependency or toolchain

Follow the existing vendored-source maintenance procedure first. DuckDB's version
and configure flags now live in `deps/duckdb/build.mk`; OpenSSL's source recipe
and configure flags live in `deps/libssl/build.mk`, with its version still in
`common_mk/openssl_flags.mk`.

Run CI with the updated inputs; a missing signature builds and saves a new bundle.
An OpenSSL update does not require rebuilding DuckDB. Source-only validation in
`CI-dependency-artifacts-checks.yml` continues to exercise compilation from the
vendored archives, independently of reusable artifacts.

## Cache and diagnostics

Verified archives and preparation locks live under
`.cache/dependency-artifacts/` in the checkout, which is also visible inside the
package workspace mount. `cleanbuild` and `cleanall` remove prepared dependency
trees but preserve these downloads. Preparation happens after that cleanup,
inside the dependency targets, with the container's actual toolchain.

Each dependency logs its mode, fingerprint prefix, and origin. Examples:

```text
[deps/duckdb] auto: restored verified artifact ...
[deps/openssl] prebuilt: already prepared from prebuilt (...)
[deps/duckdb] auto: no compatible artifact; building vendored source ...
```

An unavailable download falls back only in `auto`. An unavailable optional
compatibility probe also permits the source escape hatch in `auto`/`source`. A checksum mismatch, unsafe
archive, invalid registry, or invalid payload is an error, including in `auto`.
Investigate integrity errors rather than registering the unexpected bytes.

The helper stages and verifies the entire payload before replacing a dependency
tree. Missing DuckDB secondary archives or generated OpenSSL headers invalidate
the output. Concurrent preparation is serialized; completion metadata prevents
restored timestamps from causing repeated rebuilds. The tracked OpenSSL symlink
continues to point at its versioned directory.

To remove downloaded archives, first stop builds using this checkout, then remove
the bundle directories and digest-named `.tar.gz` files under the cache. Keep lock
files while preparation processes may still be running.
