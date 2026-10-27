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
| `auto` (default) | Reuse an accepted output or restore an exact verified artifact; otherwise build the vendored source. |
| `source` | Use source-origin outputs only. Switching from a prebuilt output rebuilds it from source, without requesting artifacts. |
| `prebuilt` | Require a registered, compatible artifact. Missing entries/downloads fail instead of compiling. |

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

The checked-in registry initially contains no published artifacts. Until the
first publication is registered, `auto` builds from source and `prebuilt` fails
with a missing-compatible-artifact diagnostic.

## What makes an artifact compatible

`deps/artifacts/lock.json` records exact build identities, HTTPS release URLs,
sizes, SHA-256 digests, and producer provenance. The identity covers the verified
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

## Publish the initial artifacts

Deploy `CI-dependency-artifacts.yml` to the repository's default branch before
using manual dispatch. A maintainer can then select it in Actions or run:

```bash
gh workflow run CI-dependency-artifacts.yml --ref v3.0 \
  -f group=ubuntu24 -f dependency=both
```

Omitting `source_ref` builds the immutable `v3.0` revision used for the dispatch.
An explicit `source_ref` must resolve to a commit reachable from the trusted
`v3.0` control revision. Merge dependency source changes through review before
publishing their artifacts; unmerged topic commits are rejected before the
matrix or build jobs are created. Dispatch this workflow from `v3.0`: profile selection and publication run control code from
that branch, pinned to one SHA for the workflow. The selected `source_ref` is
checked out separately and executes only in read-only build jobs. Publication
checks the trusted plan's exact matrix and source SHA, and build artifacts cannot
overwrite the trusted plan or control code. Only the final publication job has
`contents: write`; its publisher command receives `GH_TOKEN`.

The protected `v3.0` branch is the publication trust root. No environment with
required reviewers is currently configured for this publication; the workflow
does not silently create an unprotected environment or claim an approval gate.
Repository administrators can add a protected publication environment as an
additional approval policy.

Supported groups are `ubuntu24`, `almalinux8`, `macos`, and `all`. Linux groups cover amd64/arm64
and the existing GCC/Clang packaging images; macOS covers the native macos-14
arm64 runner. Unsupported build configurations continue to build from source.

Each selected configuration compiles fresh source in its actual build
environment, packages outputs, restores them to a different path, and runs a
real compile/link/runtime probe. The probes execute a DuckDB query and construct
an OpenSSL TLS context while checking header/runtime versions.

Only after the entire matrix succeeds does the final job publish a prerelease
named `dependency-artifacts-v1-RUN_ID-ATTEMPT`. It does not become the latest
ProxySQL release. Existing assets are never replaced. Failed publication may
leave a draft; use a new complete workflow attempt rather than overwriting it.
On retry, rerun **all jobs**, so every candidate belongs to the same attempt.

The workflow publishes the archives and `lock-entries.json`, and uploads the
metadata as the Actions artifact `dependency-lock-entries-ATTEMPT`. Publication
does not modify the source branch.

## Register a publication

Set `dependency_run_id` and `dependency_attempt` to the successful workflow run
and attempt shown in Actions, then download its generated metadata:

```bash
dependency_entries_dir=$(mktemp -d)
gh run download "$dependency_run_id" \
  -n "dependency-lock-entries-$dependency_attempt" -D "$dependency_entries_dir"
python3 deps/artifacts/publish.py register \
  --entries "$dependency_entries_dir/lock-entries.json" \
  --registry deps/artifacts/lock.json
git diff -- deps/artifacts/lock.json
```

Review and commit the registry update. The registration command validates both
registries and preserves previously registered configurations. Duplicate
identities fail instead of silently replacing their URL/digest; retain the
existing entry, or explicitly remove a retired entry during review.

Ordinary builds now download only an exact match and verify it against this
committed digest. No GitHub token is required to consume public release assets.
There is no new source download: the source archives remain vendored in Git.

## Updating a dependency or toolchain

Follow the existing vendored-source maintenance procedure first. DuckDB's version
and configure flags now live in `deps/duckdb/build.mk`; OpenSSL's source recipe
and configure flags live in `deps/libssl/build.mk`, with its version still in
`common_mk/openssl_flags.mk`.

Publish the changed dependency/configurations and register the generated entries.
An OpenSSL update does not require rebuilding DuckDB. Source-only validation in
`CI-dependency-artifacts-checks.yml` continues to exercise compilation from the
vendored archives, independently of registered artifacts.

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
the digest-named `.tar.gz` files under the cache. Keep the lock files while
preparation processes may still be running.

## Validation recorded during implementation

All 83 artifact and workflow fixtures pass on the development host. The
AlmaLinux 8 packaging image with Python 3.6.8 passes all 73 runtime/helper
fixtures; the workflow test module explicitly skips when optional PyYAML is
absent. Regression coverage includes Python-free
concurrent preparation and complete output inventories, dependency-to-plugin
flag preservation, unprobed compiler/CPU settings, the running libc version,
and download response-read timeouts on older Python versions. PR #6520 review
coverage additionally verifies native CMake CPU options, truncated response
fallback, Python-free checksum sidecars and relocation, aliased checkout paths,
and shared-checkout permissions,
C/C++ compiler family consistency, publication ordering/completeness/timeouts,
trusted control/source separation, and CI event gates.

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
TAP infrastructure, all 22 admin and 17 MySQL assertions passed; the PostgreSQL
test passed 18 assertions and failed six extended-query assertions. Linking a
second plugin directly to the source-built libraries reproduced the same six
failures. The default Python wrapper requires DEBUG admin commands, so these
release tests used the repository direct TAP runner on the isolated network.

The broader system-OpenSSL selector audit also reports six existing selectors
in unrelated test/plugin Makefiles, present before this change. Neither these
selectors nor PostgreSQL protocol behavior is changed by dependency reuse.
