# Reuse compiled DuckDB and OpenSSL dependencies

Date: 2026-10-22
Status: Approved by the user on 2026-10-22; implementation-plan review pending.

## Purpose and scope

`PROXYSQL40=1` adds an expensive DuckDB compilation to fresh ProxySQL builds.
The user reports that dependency build time increased by approximately four
times. Dependency changes are rare, so compile each supported dependency
configuration once and reuse its output across subsequent ProxySQL revisions.

Implement reuse for DuckDB and OpenSSL, retaining their pinned vendored sources.
Compile ProxySQL and its plugins against the current checkout on every normal
build. Store dependency artifacts in versioned GitHub releases in this repository.
No new repository, dependency service, or independently distributed plugin is
needed. Plugin selection and DuckDB functionality are outside this change.

The user approved this direction in conversation. This document makes the build
contract, publication process, and validation criteria concrete for review.

## Existing integration points

- `deps/Makefile` builds DuckDB 1.4.5 and OpenSSL 3.5.7. DuckDB already disables
  shell and unit-test builds. OpenSSL uses `no-shared no-tests -fPIC`.
- DuckDB's static library is not self-contained. The plugin links the archive
  set described by `DuckDBExports.cmake`, validated by
  `deps/duckdb/list-static-archives.sh`. Preserve that complete set.
- DuckDB's headers live under `deps/duckdb/duckdb/src/include`. OpenSSL's headers
  and static libraries live under `deps/libssl/openssl`, a tracked symlink to
  the versioned source directory. Preserve the symlink and those public paths.
- OpenSSL consumers depend on `.proxysql-build-complete`. Its current broad
  `deps/Makefile` prerequisite and restored timestamps need explicit handling.
- Package targets call `cleanbuild`, which removes extracted dependencies, then
  normalize checkout timestamps before entering Docker. Artifact restoration
  must happen inside the dependency targets, after cleanup and with the actual
  container toolchain available.
- `docker-compose.yml` explicitly forwards build settings. New settings must
  reach its build services and recursive Make invocations.
- Regular CI bodies are on `GH-Actions`; current source-branch wrappers call
  them. Integration in product Make targets allows these callers to benefit
  without requiring a separate change to those reusable workflows.

## Chosen approach

Use independently versioned dependency archives selected through a committed
JSON lock file. A small shared helper computes build identities, looks up exact
matches, restores archives, and creates publication metadata. Dependency-specific
build recipes continue to own source compilation.

This is preferable to caching an entire `deps/` tree, which couples unrelated
dependencies and contains unnecessary objects and generated build machinery.
It also preserves the current static-linking contract more directly than
adopting arbitrary upstream binaries.

### Build modes

Introduce `DEPS_MODE`, exported by the root Makefile and forwarded by Compose:

| Value | Behavior for DuckDB and OpenSSL |
|---|---|
| `auto` (default) | Restore an exact verified artifact when available; otherwise compile the vendored source. |
| `source` | Use source-built outputs only; do not access the artifact network or reuse a restored prebuilt output. |
| `prebuilt` | Require a matching verified artifact, either already restored, locally cached, or downloadable; never fall back to compilation. |

The setting applies only to these two dependencies. A v3 build does not acquire
a DuckDB dependency. Existing complete source builds can be reused in `auto`
or `source` mode after their build identity is validated; `prebuilt` requires
artifact provenance. Unknown mode values fail with a clear message.

An unregistered platform, missing artifact, unavailable network, or absent
optional restore tooling is a source fallback in `auto`. A registered artifact
with a checksum mismatch, malformed metadata, or unsafe archive contents is a
hard error in both artifact-consuming modes. Report the dependency, selected
mode, artifact identity or fallback reason, and final origin of the output.

### Identity and invalidation

Compute a separate fingerprint for each dependency using canonical JSON and
SHA-256. It covers:

- The verified vendored source digest and version.
- Relevant patch digests, dependency recipe, archive-format revision, and shared
  helper revision. Put dependency build settings in focused recipe files so an
  unrelated edit to the monolithic Makefile does not invalidate both artifacts.
- Target OS, architecture, Linux distribution/version and libc identity, or
  macOS SDK and deployment target as appropriate.
- Actual C/C++ compiler identity, version, target, and C++ runtime selection.
- Effective dependency compilation/link options, including optimization, PIC,
  CPU target flags, extension selection, and any instrumentation actually used
  to compile that dependency. Include environment compiler/link flags and
  relevant toolchain-file digests; unsupported custom settings cause a miss.

Use conservative exact matches initially. Do not infer that the same CPU
architecture or dependency version makes different build environments
compatible. Record the producer's container image digest and source revision
as provenance; the source revision is not part of dependency identity.

ProxySQL commit, branch, version string, and plugin DEBUG setting do not belong
in the key unless they actually change dependency compilation. The present
DuckDB dependency recipe is Release even for a DEBUG ProxySQL core. Do not
silently change that behavior while implementing reuse.

Ordinary ProxySQL edits and changes to another dependency therefore leave an
artifact reusable. A dependency or toolchain change produces a new identity.

### Lock file and storage

Add `deps/artifacts/lock.json`, with a format version and entries keyed by
dependency name and configuration fingerprint. Each entry records dependency
version, complete identity metadata, exact release download URL, archive
SHA-256 and size, format revision, and producer provenance. Reject duplicate
entries, ambiguous matches, unsupported schemas, and invalid digests.

Use a new release tag for each publication batch, such as
`dependency-artifacts-v1-<run-id>-<attempt>`. Publish it as a prerelease with
`latest` disabled. Never replace an existing published asset or use a moving
`latest` URL. The lock file supplies the expected digest independently of the
download. Ordinary builds need public read access only and never publish.

Store verified downloads in `.cache/dependency-artifacts/` under the checkout,
ignored by Git and preserved by existing `cleanbuild`/`cleanall`. This path is
already visible through the workspace bind mount. Download to a temporary file,
verify, then rename into the cache by digest. Do not cache incomplete downloads
or treat local filenames alone as proof of identity.

The initial lock file may have no published entries. In that state, default
builds retain source behavior. Real acceleration is activated by the first
publication and the subsequent commit of its generated lock entries; an empty
registry must not be reported as an operational speedup.

### Archive contents and restoration

Use `.tar.gz` archives to avoid introducing a zstd requirement into native
dependency builds. Include an internal manifest with identity, regular-file
digests, and required payload paths. Normalize archive ordering and timestamps
for predictable packaging; do not promise byte-for-byte compiler reproducibility.

DuckDB payload:

- `src/include/` headers.
- `build/release/DuckDBExports.cmake`.
- Every non-empty static archive enumerated by `list-static-archives.sh`, with
  its existing relative path.

OpenSSL payload:

- Generated and public `include/openssl/` headers, including configuration
  headers, and the expected `libssl.a` and `libcrypto.a` archives.
- Provider modules produced under `providers/` and the source build's
  `apps/openssl.cnf`, preserving their relative paths. Include produced regular
  `.so`/`.dylib` module files; do not change provider search paths or introduce a
  new OpenSSL configuration, substitute a system library, or make a FIPS claim.

Include dependency license/notice files in both payloads. Exclude object files,
compiler caches, absolute-path build caches, ProxySQL/plugin binaries, and
upstream unit-test/CLI executables.

Before modifying installed outputs, verify the outer digest, internal manifest,
identity, and complete required payload in a staging directory. Reject absolute
paths, traversal, duplicate members, links, device nodes, and files outside the
declared payload. The minimal payload uses regular files and directories only.
Use extraction behavior compatible with the supported Python versions rather
than assuming a recent `tarfile` extraction default.

Promote the validated dependency directory only after validation succeeds;
coordinate concurrent operations on the same dependency and clean temporary
state on failure. Preserve the tracked OpenSSL symlink. Refresh local completion
markers after installation so older artifact timestamps cannot trigger an
immediate recompilation or rebuild consumers on every invocation.

Run the existing DuckDB archive validator against the restored tree. For
OpenSSL, verify the expected headers/libraries and pinned header version. A
small compile/link/runtime version probe belongs in publication validation.
Record build origin and fingerprint in a separate local metadata file; do not
trust `.proxysql-build-complete` or archive presence alone as artifact identity.

### Make integration and source escape hatch

Extract the two focused dependency recipes/settings into included Make files,
retaining current public targets and paths. Share the settings used for
fingerprinting with those used for actual compilation; avoid a second copy of
flags inside the publisher.

Each dependency has one coordinated preparation path: validate the existing
identity, restore a match according to mode, or invoke its source recipe.
Represent all required outputs, not only the principal archive. Missing headers,
secondary archives, or markers must be detected before consumers compile/link.
Both top-level builds and direct plugin/dependency builds use this path.

Retain `OPENSSL_BUILD_STAMP` for existing consumers. Replace its broad
Makefile-only invalidation with the dependency identity mechanism, preserving
rebuilds when actual OpenSSL inputs change. Update build-contract tests for
the new source recipe location rather than weakening their checks.

Preserve existing source verification before extraction. The source path must
remain usable without network access or GitHub credentials. Optional artifact
restoration uses Python 3 standard-library functionality; when it is unavailable
`auto` falls back to the existing source recipe and `prebuilt` explains what is
missing. Do not add an unconditional Python requirement to source-only OpenSSL
builds. Mode changes from prebuilt to source invalidate the restored origin and
rebuild from the vendored archive.

### Publication workflow

Add a manually dispatched source-branch workflow for producing DuckDB, OpenSSL,
or both. Inputs select the source ref and a supported build-profile group.
Use checked-in profile definitions for container-backed Linux builds and native
macOS builds. Profiles reference the actual packaging images/services and
compiler choices, not a generic host compiler. Linux profiles run natively on
the matching amd64/arm64 runner, overriding the packaging entrypoint to build
and package dependencies only. Start with Ubuntu 24.04 amd64/arm64, AlmaLinux 8
amd64/arm64, and macOS 14 arm64; include both GCC and Clang Linux profiles where
the existing packaging services provide them. Other configurations continue to
fall back to source until their profiles and artifacts are added.

The workflow:

1. Checks out the selected source and validates the selected profile.
2. Builds fresh dependency outputs with `DEPS_MODE=source` in that environment.
3. Packages each dependency and generates candidate lock entries using the same
   helper/identity function as consumers.
4. Restores into a separate workspace and runs real dependency compile/link
   smoke tests. For DuckDB, link using the complete archive set and execute a
   query. For OpenSSL, check runtime/header versions and a TLS-related operation.
5. Collects all successful matrix results before publication. Failing a selected
   configuration prevents publishing a batch described as complete.
6. Publishes the versioned release and a merged lock-entry JSON artifact. Existing
   assets are never clobbered. A maintainer imports the lock entries and commits
   them after review. The workflow never pushes source-branch changes itself.

Only the publication job requires `contents: write`; build jobs use read-only
permissions. Publishing is triggered by an explicit maintainer dispatch, with no
PR-triggered release writes. Adding this workflow to the repository's default
branch is part of deployment because GitHub requires that for manual dispatch.

Keep an automated source-only validation job for the modified dependency paths
so artifact reuse cannot conceal a broken source build. Artifact-logic tests run
without compiling DuckDB on every change; full builds are reserved for focused
integration/publication validation.

## Validation and acceptance

Use Python/shell fixture tests for identity, packaging, extraction, and Make
behavior. They must cover real failure modes:

- A ProxySQL revision change preserves an identity; changes to source, recipe,
  compiler, target, relevant flags, or dependency format invalidate it.
- Exact lock selection, malformed/duplicate entries, unsupported configurations,
  and digest/metadata mismatch are handled according to the mode contract.
- Round-trip restore works in a different absolute workspace; missing DuckDB
  secondary archives or generated OpenSSL headers cannot pass validation.
- Interrupted downloads, malicious archive paths/links, concurrent preparation,
  and failed restore leave no accepted partial dependency tree.
- A matching artifact skips compilation, including after `cleanbuild`; a second
  make does not restore again or recompile. OpenSSL's completion stamp remains
  valid after restoration and unrelated Makefile edits.
- Source mode makes no artifact network requests and rejects prebuilt-origin
  outputs; strict prebuilt mode cannot silently compile. Unregistered auto mode
  continues to compile the pinned source.
- Compose and recursive make preserve the selected mode; v3 builds remain free
  of DuckDB restoration/build work.

Run the existing DuckDB manifest and vendored OpenSSL source/build/consumer/link
contract checks affected by the integration. Complete at least one real Linux
source-build, package, relocate, restore, and compile/link/query round trip for
each dependency before claiming local integration works. In a full v4 build,
verify that the current plugin links and loads with restored libraries and that
the executable still uses the intended vendored OpenSSL.

Measure source-build time and restore time separately on the same runner class.
Do not claim a numerical speedup from fixture tests or from workstation numbers
applied to different CI runners.

## Delivery and activation

Implementation delivers the helper, lock schema, dependency integration,
publication workflow/profiles, tests, and maintenance documentation. It can be
reviewed and tested locally before any release is published. Initial artifact
publication and committing its generated lock entries activate the speedup for
the selected environments. New platforms can be added independently; a change
to OpenSSL does not require rebuilding DuckDB.

Update `deps/duckdb/README.md`, `deps/libssl/README.md`, and
`doc/vendored_openssl.md` with the mode contract and publication/update procedure.
Correct the stale DuckDB README statement that the root build does not export
`PROXYSQL40`; the current root Makefile does export it.

## External references

- [GitHub manual workflow dispatch requirements](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
- [GitHub release asset API and digests](https://docs.github.com/en/rest/releases/assets)
- [GitHub CLI release publication](https://cli.github.com/manual/gh_release_create)
