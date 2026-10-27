# Automatic dependency artifacts

## Required behavior

The user requires automatic dependency reuse, including dependency upgrades in
PRs and concurrent builds of different versions. Each dependency is independent.
The signature includes its version, verified source checksum, focused recipe,
effective settings and actual platform/compiler/runtime facts. Unrelated core
commits and branch names do not change it. A matching bundle is restored; a miss
compiles, validates, packages, and persists a new bundle without a manual workflow
dispatch or registry-edit commit. Mismatched or corrupt artifacts never count as
hits. Preserve Python 3.6 support, source-only mode, staged extraction, checksums,
complete output validation and preparation locks.

## Design

Keep the existing exact identity algorithm and add an independent keyed local
store under `.cache/dependency-artifacts/bundles/<dependency>/<fingerprint>/`.
Each entry contains `entry.json` and `bundle.tar.gz`. Automatically package every
successful eligible source build. Read local entries and exact public release
URLs before compiling. Retain the old committed registry only as a migration
fallback; it is never required to create or find new entries.

Public releases use `dependency-artifact-v1-<dependency>-<fingerprint>` tags and
fixed `entry.json`/`bundle.tar.gz` assets. Validate metadata against the full
computed identity and verify payload digests before restoration. A shared CI
composite action computes keys through dependency Make inside the actual Docker
service, restores separate exact Actions cache keys, prepares and smoke-tests
dependencies, then saves the bundles immediately. No broad restore keys or
extracted build trees are cached.

Core CI automatically publishes candidates from reviewed protected history in
a fresh publisher job. Source-build jobs receive no publication credential.
PR misses populate their PR-scoped CI cache automatically. Publication jobs
serialize by full dependency fingerprint, recover incomplete drafts, and never
overwrite a published bundle. Simultaneous versions remain independent.

The existing dependency publication workflow becomes automatic prewarming for
dependency/build-input changes, while ordinary core builds also produce missing
bundles. The normal build path is the authority for miss detection; manual
publication remains an optional backfill only. No lock registration is needed.

AWS plugin CI resolves `v3.0` once per run, passes that SHA to every build job,
updates only the workspace manifest's commit, preserves the declared ABI check,
and records the exact tested SHA in package metadata. A source-ref override
allows real PR testing before the core helper is merged. Override builds have
read-only repository credentials. Shared publication accepts only source SHAs
reachable from protected `v3.0`; a protected-branch prewarm dispatch rejects an
unreviewed override before running its build code or writing default-branch
caches. PR merge refs retain their own exact caches.

Planning selects hosted build profiles from a reviewed `v3.0` checkout.
Publication separately resolves fresh reviewed helper code and binds candidate
inputs to the exact source SHA through Git objects; it does not trust or execute
candidate planning or build code. The two reviewed control snapshots need not
share a commit because the full dependency identity determines compatibility.

## Approaches

The prior manual registry fails the user's automatic-miss requirement. An
Actions-only cache loses cross-repository reuse. Use a deterministic public
release store plus exact per-repository CI caches so both reviewed shared
artifacts and work-in-progress PR versions are reusable automatically.

## Acceptance evidence

Tests must prove a cold miss creates a bundle, a fresh checkout restores without
compiling, two versions coexist, unrelated commits preserve keys, an OpenSSL-only
change preserves DuckDB's key, wrong versions/corrupt payloads are rejected,
concurrent requests cannot mix entries, and retries recover partial publication.
Exercise real source preparation and restored compile/link/runtime probes, plus
workflow fixtures/lint, strict ABI/package provenance, and actual PR cache reuse.
