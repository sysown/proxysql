# Compiled dependency reuse

ProxySQL can reuse its own compiled DuckDB and OpenSSL dependencies. The pinned
vendored source archives remain the authority for versions and source builds.
ProxySQL and its plugins still compile against the current checkout.

Reuse is automatic. A matching dependency signature restores a verified bundle;
a miss builds from source, validates the result, and saves a bundle for that
signature. No publication dispatch or registry-edit commit is required. OpenSSL
and DuckDB have separate keys, and bundles for different versions and settings
coexist.

## Build modes

```bash
PROXYSQL40=1 make -j4 DEPS_MODE=auto
PROXYSQL40=1 make -j4 DEPS_MODE=source
PROXYSQL40=1 make -j4 DEPS_MODE=prebuilt
```

| Mode | DuckDB/OpenSSL behavior |
|---|---|
| `auto` (default) | Reuse an accepted output or restore an exact verified bundle; otherwise build the vendored source and save an eligible bundle. |
| `source` | Use source-origin outputs only. Switching from a prebuilt output rebuilds it from source, without requesting artifacts. Eligible source builds still save reusable bundles. |
| `prebuilt` | Require a compatible verified bundle from the local store or public releases. Missing bundles/downloads fail instead of compiling. |

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
Python is required for bundle creation and restoration. Configurations whose
compatibility cannot be identified continue to use the source escape hatch in
`auto` or `source`.

## What makes an artifact compatible

Each bundle has an exact build identity and a fingerprint computed from it. The
identity covers the dependency version, verified source archive checksum, focused
dependency recipe, verifier and helper implementation/format, effective settings
and flags, and actual compiler/runtime/target facts. Native macOS includes the
SDK/deployment target; Linux includes the distribution and libc version.
`entry.json` records that full identity, the bundle size and SHA-256 digest, its
canonical release URL, and producer provenance.

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
`auto` compiles source and saves an eligible bundle if no exact artifact exists.

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

## Automatic storage and publication

Every successful eligible source preparation creates a local pair:

```text
.cache/dependency-artifacts/bundles/<dependency>/<fingerprint>/entry.json
.cache/dependency-artifacts/bundles/<dependency>/<fingerprint>/bundle.tar.gz
```

Preparation validates the outputs and commits the pair together under a lock.
A later build can restore it after prepared dependency trees are removed. Set
`DEPS_ARTIFACT_CACHE_DIR` to share the bundle store between separate checkouts;
their working trees and preparation locks remain isolated. Different signatures
retain separate directories, so switching A to B and back to A can reuse the
first bundle without recompiling it.

Public bundles use deterministic release tags:

```text
dependency-artifact-v1-<dependency>-<fingerprint>
```

Each release in `sysown/proxysql` contains `entry.json` and `bundle.tar.gz`.
Consumers derive those URLs from the dependency and their computed fingerprint,
compare the complete identity, verify the declared size and SHA-256 digest, and
validate the extracted manifest and outputs before installation. Public reads
need no GitHub token. Source archives remain vendored in Git; a missing bundle
does not introduce another source download.

`deps/artifacts/lock.json` remains a migration fallback for previously registered
bundles. New signatures are found and persisted without adding registry entries.
The old batch publication and registration procedure is not part of normal
dependency maintenance.

CI computes independent OpenSSL and DuckDB keys through dependency Make in the
actual build environment. It restores only exact Actions cache matches, verifies
the stored pair, prepares the dependencies, and runs compile/link/runtime probes
before saving bundles immediately. Extracted dependency trees and general build
outputs are not part of this cache. Keys contain the full dependency fingerprint;
they do not include the core commit, branch, or workflow run.

PR upgrades therefore build and save their own missing signatures automatically.
Their Actions caches stay scoped to the PR merge ref and are not promoted into
the global public store. A fresh publisher job accepts candidates only from
reviewed protected `v3.0` history. It verifies the actual triggering repository,
event and source SHA, checks source, recipe, verifier and helper hashes against
Git objects, and validates each complete candidate. An older producer commit is
acceptable only when it is also reviewed history with matching dependency inputs.

Source-build jobs have read-only repository credentials. Only the fresh
publisher receives publication credentials; it treats candidate archives as data
and never executes their libraries or scripts. It selects candidates from the
current workflow attempt, deduplicates equal dependency signatures, and serializes
publication by the full dependency fingerprint. Different versions and
dependencies can publish independently.

A completed valid release wins even if another build of the same identity has
different archive bytes. Published assets are never replaced. An interrupted
draft can be repaired by retrying publication of a validated pair. These releases
are prereleases and do not become the latest ProxySQL release. Publication does
not edit the source branch.

Ordinary core CI produces missing bundles, while `CI-dependency-artifacts.yml`
automatically prewarms selected profiles when dependency or build inputs change.
Manual dispatch is optional backfill. Linux profiles cover the existing
GCC/Clang packaging environments on amd64 and arm64; native macOS uses its own
SDK/compiler identity. Unsupported configurations continue to build from source.

## Updating a dependency or toolchain

Follow the existing vendored-source maintenance procedure first. DuckDB's version
and configure flags now live in `deps/duckdb/build.mk`; OpenSSL's source recipe
and configure flags live in `deps/libssl/build.mk`, with its version still in
`common_mk/openssl_flags.mk`.

Build or run CI normally after changing the vendored version, checksum, recipe,
settings, or toolchain. A changed signature creates a new bundle automatically;
existing versions remain reusable under their own keys. An OpenSSL-only update
does not invalidate DuckDB's key. Unrelated core commits do not rebuild either
dependency. Source-only validation in `CI-dependency-artifacts-checks.yml`
continues to exercise compilation from the vendored archives independently of
bundle availability.

## Cache and diagnostics

Verified bundles, downloaded archives and preparation locks live under
`.cache/dependency-artifacts/` by default, visible inside the package workspace
mount. `cleanbuild` and `cleanall` remove prepared dependency trees but preserve
the bundle store. Preparation happens after that cleanup, inside dependency
targets, with the container's actual toolchain.

Each dependency logs its mode, fingerprint prefix, and origin. Examples:

```text
[deps/duckdb] auto: restored verified artifact ...
[deps/openssl] prebuilt: already prepared from prebuilt (...)
[deps/duckdb] auto: no compatible artifact; building vendored source ...
[deps/duckdb] saved reusable bundle ...
```

An absent or unavailable remote bundle permits a source build in `auto`;
`prebuilt` fails instead. An unavailable optional compatibility probe also
permits the source escape hatch in `auto`/`source`. Corrupt local bundles,
mismatched metadata or identities, checksum mismatches, unsafe archives, invalid
legacy registries, and invalid payloads are errors, including in `auto`. They
are not silently treated as ordinary cache misses. Investigate integrity errors
rather than accepting unexpected bytes. Explicit `source` mode can repair a corrupt
regular local bundle from validated source outputs; it never follows cached symlinks.

The helper stages and verifies the entire payload before replacing a dependency
tree. Missing DuckDB secondary archives or generated OpenSSL headers invalidate
the output. Concurrent preparation is serialized; completion metadata prevents
restored timestamps from causing repeated rebuilds. The tracked OpenSSL symlink
continues to point at its versioned directory.

To remove a cached signature, first stop builds using that store, then remove its
`bundles/<dependency>/<fingerprint>/` directory. Legacy digest-named `.tar.gz`
downloads can also be removed. Keep lock files while preparation processes may
still be running, including processes in other checkouts sharing the store.

## Validation recorded during implementation

Regression coverage includes cold-miss bundle creation, clean-tree restoration,
version A/B/A reuse, configuration isolation, unchanged keys across unrelated
commits, same-key publication races, draft recovery, and refusal to promote PR
candidates. Git fixtures bind candidate versions and focused source hashes to
reviewed history. Publisher tests use fake release and download boundaries and
perform no live publication.

Existing validation covers Python-free concurrent preparation and complete output
inventories, dependency-to-plugin flag preservation, compiler/CPU settings, the
running libc version, older-Python download timeouts, truncated responses,
checksum sidecars, relocation, aliased checkout paths, shared-checkout permissions,
C/C++ compiler family consistency, and trusted control/source separation. Runtime
and helper fixtures have also been exercised in the AlmaLinux 8 packaging image
with Python 3.6.8. The workflow test module skips when optional PyYAML is absent.

On the development Linux host, a fresh combined source build using
`make -j4 ... NPROCS=4 DEPS_MODE=source libssl duckdb` took 612.71 seconds.
Restoring both verified bundles from the local archive cache into a different
checkout took 1.42 seconds. Both restored trees passed real compile/link/runtime
probes, and the second dependency Make invocation reported unchanged outputs.

These are measurements from one host and exclude artifact creation and network
download time from the restore measurement. They do not predict timings for the
other CI runner classes.

The full `PROXYSQL40=1` release build passed against restored dependencies, and
the executable/plugins passed the static OpenSSL linkage check. In the isolated
TAP infrastructure, admin and MySQL tests passed. PostgreSQL extended-query
failures reproduced when a second plugin linked directly to source-built
libraries. The default Python wrapper requires DEBUG admin commands, so these
release tests used the repository direct TAP runner on the isolated network.

The broader system-OpenSSL selector audit also reports existing selectors in
unrelated test/plugin Makefiles, present before this change. Neither these
selectors nor PostgreSQL protocol behavior is changed by dependency reuse.
