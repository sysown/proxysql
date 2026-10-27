# Automatic dependency cache implementation plan

> **For agentic workers:** Use superpowers:executing-plans for core helpers;
> independent CI integration tasks may use the parallel-agent skill.

**Goal:** Automatically find, build and persist correct dependency bundles for
every version/configuration, including PR upgrades, without registry maintenance.
**Architecture:** Exact local bundles + deterministic public releases + scoped
Actions caches; isolated automatic publisher; branch-following plugin CI.
**Tech Stack:** Existing Python 3.6-compatible helpers, Make, Docker, GitHub Actions.
**Spec:** `docs/superpowers/specs/2026-10-27-automatic-dependency-cache-design.md`

## Constraints / review focus

Preserve integrity errors and source/prebuilt semantics. Never key by core SHA.
Keep different dependency versions and simultaneous publisher keys independent.
Read actual Make/container settings. Never promote arbitrary PR cache payloads
into the shared store. Preserve ABI 16 checks and exact package provenance.

## Tasks

- [ ] Core helpers: add failing cold-miss/hit/version/isolation/remote-publication
  tests; implement keyed local store and exact remote discovery, automatic
  source packaging, Make key/prepare entry points, and idempotent publishing.
  Validate all old fixtures plus new cases and real restored native probes.
- [ ] Core CI control: shared per-dependency cache action, read-only build
  credentials, automatic candidate upload and reviewed-history publication
  keyed by full fingerprint. Include fork/caller integration where required.
  Validate workflow fixtures, expression lint, and publication concurrency.
- [ ] Product workflow: automate dependency prewarming for input changes,
  replace mandatory registration with deterministic lookup, update docs.
- [ ] AWS plugin CI: resolve current core once, preserve ABI/metadata checks,
  use shared cache action for normal/ASan/TSan and nightly builds. Add resolver,
  cache-policy and package provenance tests; exercise an unmerged core ref.
- [ ] Independently review all changes, open linked PRs, run real CI cold/hit
  validation and inspect logs proving version-specific automatic creation/reuse.
