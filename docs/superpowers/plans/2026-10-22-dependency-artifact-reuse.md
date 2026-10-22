# Dependency Artifact Reuse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reuse verified DuckDB and OpenSSL build outputs across ProxySQL revisions while retaining a working offline source-build path.

**Architecture:** A dependency-specific identity selects an immutable archive from a committed lock file. Shared preparation code verifies and installs the complete payload inside the existing dependency Make targets, after package cleanup. A manually dispatched workflow builds and validates publication candidates in the actual packaging environments.

**Tech Stack:** GNU Make, Bash, Python 3 standard library, tar/gzip, existing C/C++ toolchains and Docker Compose, GitHub Actions and Releases.

**Spec:** [Approved design](../specs/2026-10-22-dependency-artifact-reuse-design.md)

## Global Constraints

- Preserve DuckDB 1.4.5, OpenSSL 3.5.7, vendored-source verification, current static linkage, and existing public build paths.
- Default `DEPS_MODE=auto`; support `source` and strict `prebuilt`. Only DuckDB and OpenSSL participate.
- Unknown modes, corrupt registered artifacts, unsafe payloads, and malformed metadata fail clearly. Ordinary availability misses fall back only in `auto`.
- Artifact identity excludes ProxySQL revision and includes actual dependency inputs and toolchain/target settings. Use conservative exact matches.
- Use `.tar.gz`, regular files/directories only, committed expected SHA-256, and `.cache/dependency-artifacts/` for verified downloads.
- Preserve the tracked `deps/libssl/openssl` symlink and the `.proxysql-build-complete` consumer contract.
- Restore inside dependency preparation after `cleanbuild`. Never restore ProxySQL/plugin binaries.
- Source-only OpenSSL must remain usable without Python, network access, or GitHub credentials.
- Keep changes in the existing checkout only if the user selects that execution approach. Preserve unrelated untracked `deps/json/local/` and `deps/opentelemetry/`.
- Do not publish a release or claim a speedup merely because implementation and fixture tests pass. Publication and committing real lock entries activate reuse.

## Review Focus

- An artifact downloaded for the host must not be accepted inside a different package container; test identities computed from container-specific compiler/libc facts.
- A direct plugin build must revalidate an existing DuckDB tree before compiling objects, not only before final linking; exercise missing headers and secondary archives.
- A source/prebuilt mode change must not silently accept the previous origin; test both transitions with an existing output tree.
- Two preparations of the same dependency must neither deadlock recursive Make nor accept a partially promoted tree; test concurrent subprocesses with timeouts.
- Restored timestamps and package timestamp normalization must not cause repeated restores or consumer recompiles; test output and completion-marker mtimes across two invocations.

## File Structure

| File | Responsibility |
|---|---|
| `deps/duckdb/build.mk`, `deps/libssl/build.mk` | Focused source recipes and the effective dependency settings used for identity. |
| `deps/artifacts/identity.py` | Dependency configuration, canonical identities, compiler/target probes, strict lock-file parsing. |
| `deps/artifacts/bundles.py` | Payload collection, deterministic packaging, digest/manifest checks, staged extraction and promotion. |
| `deps/artifacts/manage.py` | CLI, mode selection, download cache, locking, source invocation, publication metadata. |
| `deps/artifacts/prepare.bash` | Make-facing entrypoint and a Python-free source fallback. |
| `deps/artifacts/lock.json` | Versioned registry, initially with an empty artifact list. |
| `deps/artifacts/profiles.json` | Explicit supported publisher environments and profile groups. |
| `deps/artifacts/publish.py` | Profile selection, batch-entry merge, immutable release publication. |
| `test/infra/control/test_dependency_artifact_{identity,bundles,make,publication}.py` | Focused behavior and integration tests using the standard-library test runner. |
| `test/infra/control/dependency-artifacts-smoke.bash` | Real relocated archive compile/link/runtime probes for publication and local acceptance. |
| `.github/workflows/CI-dependency-artifacts.yml` | Manual build/validation/publication matrix. |
| `.github/workflows/CI-dependency-artifacts-checks.yml` | Fast regression tests and dependency-source validation. |
| `doc/dependency-artifacts.md` | Operator/developer modes, registry updates, publication, troubleshooting. |

Modify `deps/Makefile`, root `Makefile`, `plugins/duckdb/Makefile`, `docker-compose.yml`, `.gitignore`, affected OpenSSL contract checks, and the three dependency maintenance documents named in the spec.

### Task 1: Define dependency identity and the registry contract

**Interfaces:** `identity.py` provides `build_identity(dependency, root, environ) -> dict`, `fingerprint(identity) -> str`, and `load_registry(path) -> dict`. Dependencies are exactly `duckdb` and `openssl`. A registry is `{"format_version": 1, "artifacts": [...]}`; each entry contains `dependency`, `fingerprint`, `identity`, `url`, `sha256`, `size`, and `provenance`.

- [ ] Write `test_dependency_artifact_identity.py`. Assert canonical ordering produces the same SHA-256; changing ProxySQL revision does not change identity; changing source, focused recipe, compiler, libc/SDK, target, relevant flags, or format does. Test missing configuration facts, duplicate JSON keys/entries, malformed digests, unsupported schemas, and conflicting entries.
- [ ] Run `python3 -m unittest discover -s test/infra/control -p 'test_dependency_artifact_identity.py' -v`; confirm the new tests fail because the identity implementation does not exist.
- [ ] Factor the existing source commands into `deps/duckdb/build.mk` and `deps/libssl/build.mk` without changing current compiler settings or behavior. Define shared exported settings `DUCKDB_CMAKE_FLAGS` and `OPENSSL_CONFIGURE_FLAGS`, and internal source targets `dependency-source-duckdb` and `dependency-source-openssl`. Make target settings used by the helper come from these same definitions.
- [ ] Implement `identity.py` and an empty `lock.json`. Hash actual verified source content, focused recipe inputs, and the helper format/implementation. Probe the real `CC`/`CXX`, target, runtime, SDK, and relevant environment flags. Make ambiguous or unsupported custom toolchain settings ineligible for artifact selection rather than guessing compatibility.
- [ ] Run the identity tests and existing `test-vendored-openssl-build-contract.bash`. A source-only dry run must still show verification before extraction and `no-shared no-tests -fPIC`; unchanged DuckDB settings must still pin `v1.4.5`.
- [ ] Commit the identity/registry and recipe factoring as `feat: define dependency artifact identities`.

### Task 2: Package and restore complete dependency payloads

**Interfaces:** `bundles.py` provides `collect_payload(dependency, tree) -> list[str]`, `create_bundle(dependency, tree, identity, output) -> dict`, `validate_tree(dependency, tree) -> None`, and `restore_bundle(archive, entry, destination) -> None`. Paths in payload manifests are relative to the dependency tree. `create_bundle` returns the archive digest, size, identity, fingerprint, and payload metadata needed by Task 3.

- [ ] Write `test_dependency_artifact_bundles.py` with synthetic DuckDB exports/archive sets and OpenSSL generated headers/libraries. Assert relocated round trips preserve every required file and the OpenSSL version contract. Assert missing secondary archives/configuration headers cannot pass either packaging or restoration.
- [ ] Add tests rejecting traversal, absolute paths, duplicate archive members, links, devices, undeclared members, bad internal digests, wrong identity, and incorrect outer size/SHA-256. Inject an extraction/promotion failure and assert the prior destination remains usable.
- [ ] Run the bundle tests and confirm they fail before implementation.
- [ ] Implement payload selection and normalized gzip/tar packaging. Call the existing DuckDB manifest validator rather than duplicating its archive-selection rules. Include headers, licenses, OpenSSL configuration/provider modules, and the spec's exact required files; exclude compiler/build outputs outside that list.
- [ ] Implement safe manual extraction into a sibling staging directory using supported Python standard-library APIs. Verify all metadata and required outputs before promotion; preserve/rollback the previous destination on failure and preserve the tracked OpenSSL symlink. Bound metadata reads and reject oversized/invalid manifests before allocation or extraction.
- [ ] Run the bundle tests plus `python3 test/infra/control/test_duckdb_archives.py` and `bash test/infra/control/test-duckdb-platform-archives.bash`; expect all to pass.
- [ ] Commit as `feat: package and verify dependency bundles`.

### Task 3: Integrate preparation, modes, and incremental Make behavior

**Interfaces:** `manage.py` exposes CLI subcommands `identity`, `prepare`, and `package`, each taking `--dependency {duckdb,openssl}` and `--root PATH`. `prepare` also accepts `--mode {auto,source,prebuilt}`, with production registry/cache paths under the root. `package` accepts `--output PATH` and emits a candidate registry entry. Internal `prepare_dependency(dependency, root, mode, environ) -> dict` returns `origin`, `fingerprint`, and `changed`. Record local accepted-output metadata in `.proxysql-dependency.json` and retain OpenSSL's completion stamp.

- [ ] Write `test_dependency_artifact_make.py` using isolated fixture repositories and compiler/source-builder stubs. Exercise auto hit/miss, strict prebuilt failure, corrupt registered bundles, local cache verification, unknown modes, Python-free source fallback, mode transitions, and an empty registry making no network request.
- [ ] Add actual Make fixture cases for restore after `cleanbuild`, two no-op invocations, normalized old timestamps, a relevant-input change, an unrelated Makefile edit, missing OpenSSL headers, missing DuckDB secondary archives, direct plugin-object prerequisites, and v3 builds avoiding DuckDB.
- [ ] Add concurrent preparation tests and a recursive Make test with a timeout. Assert the source builder runs once, other consumers wait for completion, no jobserver deadlock occurs, and failed downloads/restores do not leave accepted output or poisoned cache entries.
- [ ] Run the new Make tests; confirm the expected failures before integration.
- [ ] Implement preparation/cache/mode handling in `manage.py`, serializing each dependency with a POSIX lock. Verify source tarballs through their current verifiers. Resolve exact registry entries, download with bounded timeouts to temporary cache files, and verify before caching or restoring. Classify availability misses separately from integrity failures. Preserve Make jobserver semantics when invoking the internal source target.
- [ ] Implement `prepare.bash`. Without Python, `auto`/`source` use the original focused source recipe and reject prebuilt-origin outputs; `prebuilt` fails clearly. Keep a source-origin freshness marker based on the focused inputs so ordinary Python-free builds remain incremental.
- [ ] Wire preparation into `deps/Makefile` for all public dependency targets/output prerequisites and into direct DuckDB plugin builds before compilation. Export `DEPS_MODE` in root Make and forward it through Compose. Add the ignored download cache. Refresh completion markers only when accepted outputs change.
- [ ] Update `test-vendored-openssl-build-contract.bash` and `test-vendored-openssl-consumers.bash` to inspect the internal source target and the preparation bridge. Preserve their source verification, fixed-path, ordering, and no-system-OpenSSL assertions.
- [ ] Run `python3 -m unittest discover -s test/infra/control -p 'test_dependency_artifact_*.py' -v`, the existing DuckDB checks, and the affected vendored OpenSSL source/build/consumer/link checks. Expect all applicable fixture checks to pass without compiling DuckDB.
- [ ] Commit as `feat: restore compiled dependencies during builds`.

### Task 4: Build and publish immutable dependency batches

**Interfaces:** `publish.py` exposes `matrix --group GROUP --dependency NAME`, `merge --input DIRECTORY --output PATH`, and `publish --input DIRECTORY --repository OWNER/REPO --tag TAG`. Its merge result is a complete registry document accepted by `load_registry`. Profile fields include stable profile name, runner, architecture, Compose service or native setup, and compiler choice. A batch tag is `dependency-artifacts-v1-<run-id>-<attempt>`.

- [ ] Write `test_dependency_artifact_publication.py`. Assert profile selection covers Ubuntu 24.04 and AlmaLinux 8 on amd64/arm64 plus macOS 14 arm64, using existing GCC/Clang packaging services. Test invalid groups, mismatched architectures, duplicate/conflicting merged entries, failed/missing matrix results, and refusal to replace assets.
- [ ] Test workflow contracts: only manual dispatch can publish; only publication has `contents: write`; actions are pinned; publication requires every selected build; releases are prereleases with latest disabled; source builds precede package/restore smoke tests. Test mode forwarding through Compose and profile-derived container/compiler matching.
- [ ] Run the publication tests and confirm they fail before workflow/profile implementation.
- [ ] Implement profiles and publication CLI. Resolve/record actual image digests, build inside the selected environment with `DEPS_MODE=source`, and derive candidate entries from `manage.py package`. Merge without mutating the source branch or replacing existing published assets.
- [ ] Add `dependency-artifacts-smoke.bash DEPENDENCY TREE`. Compile a tiny C/C++ client against a relocated tree: execute a DuckDB query through its C API using the complete archive set; verify OpenSSL header/runtime version and construct a TLS context with the vendored static libraries. Support Linux and macOS link differences.
- [ ] Add `CI-dependency-artifacts.yml` with matrix generation, clean source builds, packaging, relocation/smoke verification, collection, and final publication. Override Linux packaging entrypoints so no full ProxySQL package build is required. Upload merged candidate lock entries for maintainer import. No agent-triggered live publication is part of local implementation verification.
- [ ] Add `CI-dependency-artifacts-checks.yml` with fast fixture tests and source-only dependency validation on relevant changes. Run both dependencies on the supported Ubuntu Linux baseline, and validate workflow/profile syntax using available repository tooling.
- [ ] Run all artifact fixture tests and shell syntax checks. Commit as `ci: publish verified dependency artifacts`.

### Task 5: Validate real reuse and document activation

**Interfaces:** Reuse the CLI, registry format, preparation targets, and smoke script from Tasks 1–4. Real tests use a separate temporary checkout/output tree so existing dependency builds and unrelated user files remain intact.

- [ ] Run source builds for both dependencies with the current local toolchain in the temporary acceptance workspace. Capture source-build elapsed time and build origins; do not substitute existing artifacts for these measurements.
- [ ] Package the real outputs, record candidate entries in a test registry, relocate to a different absolute path, restore from the verified local download cache with `DEPS_MODE=prebuilt`, and run both real compile/link/runtime smoke probes. Record restore elapsed time separately.
- [ ] Invoke the real Make targets twice with the restored dependencies. Confirm no source compilation or second restore, stable completion-marker mtimes, and valid DuckDB archive enumeration. Check `source` mode rebuilds a prebuilt-origin tree without requesting artifacts.
- [ ] In an isolated full v4 acceptance checkout, build the current ProxySQL core/plugin against the restored trees. Run the existing `check-openssl-linkage.bash` against the executable/plugins and exercise plugin load plus a DuckDB query through the repository's isolated TAP infrastructure. Record any environment prerequisite that prevents this check; do not claim full integration passes without it.
- [ ] Run the complete affected fixture/contract suite once after final changes. Broaden testing only if failures or remaining concerns justify it.
- [ ] Write `doc/dependency-artifacts.md` and update `deps/duckdb/README.md`, `deps/libssl/README.md`, and `doc/vendored_openssl.md`. Include exact commands for all modes, initial publication, importing/merging candidate lock entries, source updates, cache location, and fallback diagnostics. Correct the stale root `PROXYSQL40` export statement.
- [ ] Document activation precisely: local implementation can pass with an empty production lock; operational acceleration requires a maintainer-dispatched publication and committed real entries. Report measured timings only for the tested runner class.
- [ ] Commit as `docs: document dependency artifact reuse and validation` and obtain the chosen final independent review before presenting the implementation as complete.

## Execution Handoff

Recommended: **Native**, with implementation in this checkout and one fresh final
reviewer. The tasks share one artifact identity/schema and Make integration;
keeping one implementer avoids repeated context transfer. The existing untracked
directories must remain untouched. **Subagent-driven** execution is also
available if the user prefers separate implementation/review gates per task.

This plan is ready for user review. Implementation begins after the user approves
the plan and selects the execution method, as required by the writing-plans
workflow.
