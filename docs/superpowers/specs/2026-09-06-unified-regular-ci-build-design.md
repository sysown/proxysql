# Unified Regular CI Build Design

## Goal

Compile the regular ProxySQL daemon, every in-tree plugin, and every TAP/unit
binary once on Ubuntu 24, then make all regular CI consumers execute that one
complete handoff. The builder must not know which tests belong to GenAI,
MySQLX, DuckDB, Router, or a future plugin.

## Current State

`CI-builds` currently emits three overlapping regular TAP variants:

- `ubuntu22-tap` for the general TAP matrix;
- `ubuntu24-tap-genai-gcov` for the full chassis/GenAI path; and
- `ubuntu22-tap-mysqlx` for MySQLX and plugin unit binaries.

The MySQLX variant deliberately deletes most unit binaries, while the other
TAP variants delete all of them. `CI-mysqlx` consequently has a bespoke unit
loop and restores a MySQLX-specific handoff. This makes the build matrix aware
of individual plugins and duplicates compilation.

`debian12-dbg` only supplied the ten `CI-3p-*` consumers; those workflows are
currently disabled. `ubuntu22-tap` has no enabled consumer that cannot be
served by the Ubuntu 24 full build.

## Architecture

### One regular producer and one complete artifact

The `GH-Actions` reusable `ci-builds.yml` will retain one regular TAP producer,
named `ubuntu24-tap-genai-gcov`. It builds with the complete chassis tier enabled,
builds every supported plugin, and retains every executable TAP and unit test.
It publishes one versioned handoff artifact for a head SHA rather than
per-plugin or per-test-class payloads.

The artifact contains:

- `src/` and the daemon runtime required by isolated infrastructure;
- every test executable and its runtime support under `test/`;
- all built plugin shared libraries and runtime libraries required by those
  binaries; and
- coverage metadata only when that producer is explicitly a coverage profile.

Its manifest is generic: it validates a non-zero regular TAP count and a
non-zero unit-test count, but never names a plugin or a test-family glob.
Consumers restore the complete handoff and select work only through a TAP
group. Extra download cost for consumers that execute a small group is an
intentional trade-off for one simple contract and future cross-plugin tests.

### Consumers select groups, not plugins

Every regular consumer uses the same artifact resolver and generic group
runner. The only consumer-specific input is `tap_group` plus its infrastructure
profile. No workflow manually loops `mysqlx_*_unit-t`, `plugin_*_unit-t`, or
another plugin-specific filename pattern.

Add `mysqlx-g1` in `test/tap/groups/groups.json`. It contains the MySQLX and
plugin chassis unit tests currently executed by `CI-mysqlx`'s bespoke unit
loop, with existing version constraints preserved. Existing `unit-tests-g1`
membership remains unchanged. MySQLX integration remains explicitly split:

- `mysqlx-g1`: normal unit/chassis execution through a new `CI-mysqlx-g1`
  group consumer;
- `mysqlx-e2e-g1`: MySQL 8.4 X-protocol sandbox E2E; and
- `mysqlx-soak-g1`: long-running MySQLX infrastructure tests.

The latter two keep their distinct infrastructure setup but restore the same
complete handoff. GenAI continues to use `ai-g1` and `ai-g2`; DuckDB and future
plugins follow the same group-registration model.

### Profiles that remain separate

The unified artifact replaces the regular Linux TAP build and carries the
existing gcov instrumentation used by its consumers. ASAN, TSAN, clang,
package, third-party-language, and OS-specific compatibility
profiles remain separate because their compiler flags, toolchains, runtime
libraries, or test purpose are not interchangeable.

## Rollout and Compatibility

The reusable workflows live on `GH-Actions` and callers/groups live on
`v3.0`, so the migration uses three compatible phases:

1. **`GH-Actions` support.** Use the existing `ubuntu24-tap-genai-gcov` producer,
   complete-handoff
   packing, and the generic group consumer while retaining all legacy producer
   and consumer paths.
2. **Switch `v3.0`.** Register `mysqlx-g1`, add its thin caller, and redirect
   existing regular callers—including MySQLX E2E and soak—to the unified
   handoff. Validate all affected groups from a real `CI-builds` run.
3. **Retire old paths.** Remove `ubuntu22-tap`, `ubuntu22-tap-mysqlx`, and
   `debian12-dbg` only after the enabled consumers have run successfully from
   the full handoff. Third-party workflows move downstream of the full handoff
   before Debian removal if any are re-enabled.

At each phase, artifact names include the SHA and variant. The generic resolver
must fail clearly on a missing handoff; it must not fall back to compiling on a
consumer runner or silently use a prior SHA.

## Failure Handling and Safety

- The producer fails before upload if any expected artifact tree is absent, or
  if no TAP or unit executable exists.
- Consumers verify the artifact SHA/manifest before test setup.
- Handoff unpacking is transactional enough for CI: unpack into the checkout
  only after the artifact is fully downloaded; failed resolution surfaces the
  exact artifact name and producing run ID.
- Artifact retention continues to be short-lived; caches are not relied on for
  correctness.
- No test binary is pruned based on a plugin-specific glob.

## Verification

Each implementation phase must provide:

1. static checks that the build matrix has exactly one regular full producer
   and its handoff contains executable TAP and unit binaries;
2. `groups.json` format/source/coverage lint proving `mysqlx-g1` is registered
   and selected by `CI-mysqlx-g1`;
3. a producer run plus one generic group consumer, MySQLX unit group, MySQLX
   E2E group, MySQLX soak group, GenAI group, and a non-plugin regular group;
4. proof that no listed consumer invokes a compiler or manually enumerates a
   plugin filename family; and
5. before/after timing and compressed handoff-size measurements, reported as
   observations rather than claimed savings until the paired runs complete.

## Non-Goals

- Do not reduce, skip, or reclassify plugin tests to make the artifact smaller.
- Do not split test binaries by plugin or teach the builder plugin-specific
  retention rules.
- Do not merge sanitizer or platform-specific profiles into the regular
  artifact.
- Do not change test semantics or infrastructure ownership merely to migrate
  the handoff.
