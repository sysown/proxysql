# `GH-Actions` branch

**You probably didn't mean to land here.** This branch is not a development
branch for ProxySQL source code — it exists purely to host the
**reusable GitHub Actions workflows** that ProxySQL's CI uses.

If you're looking for ProxySQL itself, switch to the default branch:
**[`v3.0`](https://github.com/sysown/proxysql/tree/v3.0)**.

---

## What lives here

Only one directory matters on this branch:

```text
.github/workflows/
├── ci-trigger.yml              ← Entry point; babysits CI-builds
├── ci-builds.yml               ← Builds ProxySQL in Docker, caches artefacts
├── ci-basictests.yml
├── ci-selftests.yml
├── ci-maketest.yml
├── ci-legacy-g1.yml .. ci-legacy-g5.yml
├── ci-legacy-g2-genai.yml
├── ci-legacy-clickhouse-g1.yml
├── ci-mysql84-g1.yml .. ci-mysql84-g5.yml
├── ci-unittests.yml
├── ci-codeql.yml
├── ci-package-build.yml
├── ci-3p-*.yml                 ← Third-party integration workflows
└── ci-taptests-groups.yml      ← DEPRECATED; do not add new callers pointing here
```

These are **reusable workflows** — they declare `on: workflow_call` and are
invoked from matching "caller" files on the `v3.0` branch under the same
path (e.g. `v3.0:.github/workflows/CI-legacy-g1.yml`). The caller files
are what trigger on push/PR; the files here are the actual job bodies.

All other files on this branch (source code, docs, test directories, etc.)
are **vestigial**. They're snapshots from an old point in history that
remain on this branch because they're still tracked here and nobody
has removed them. **Do not edit them here.** Any changes to source code, TAP tests,
infra scripts, or documentation belong on `v3.0`.

---

## Where the real documentation is

The complete CI architecture is documented on the `v3.0` branch:

### [`doc/GH-Actions/README.md` on `v3.0`](https://github.com/sysown/proxysql/blob/v3.0/doc/GH-Actions/README.md)

That doc covers:

- The two-branch caller/reusable split and *why* it exists
- The `CI-trigger` → `CI-builds` → test-workflow cascade (with diagrams)
- The dedicated-reusable pattern with a step-by-step walkthrough of
  `ci-legacy-g4.yml` as the canonical template
- The build cache layout (`_src`, `_test`, `_bin`, `_matrix`)
- The TAP groups system (`test/tap/groups/`, `BASE_GROUP` stripping,
  `SKIP_PROXYSQL` mode)
- An end-to-end walkthrough for adding a new test group
- Common pitfalls (merge ordering, `workflow_run` head_sha propagation,
  the empty-matrix wedge, false-positive permissions hotspots)
- A debugging guide for failing runs

Read it before touching anything here.

---

## Quick reference for common tasks

### Adding a new test group

Four things, in this order:

1. On **`v3.0`**: add the group to `test/tap/groups/groups.json` and
   create `test/tap/groups/<base-group>/{env.sh,infras.lst}` if the base
   group doesn't exist yet.
2. On **`GH-Actions`** (here): create `.github/workflows/ci-<group>.yml`.
   Cut it from `ci-legacy-g4.yml` and change only `name:`, `INFRA_ID`,
   `TAP_GROUP`, and the `docker logs proxysql.<id>` target.
3. On **`v3.0`**: create `.github/workflows/CI-<group>.yml` (the thin
   caller). Cut it from `CI-legacy-g4.yml` on `v3.0` and change the
   `name:` and `uses:` target.
4. **Merge order:** the `GH-Actions` PR (step 2) must merge **before**
   the `v3.0` PR that introduces the new caller (steps 1 and 3).
   Otherwise the caller will try to resolve a reusable that doesn't yet
   exist on `GH-Actions` and every run will error out with
   `Unable to resolve action`.

### Modifying an existing reusable

Make the edit on `GH-Actions` directly in a feature branch, open a PR
targeting `GH-Actions`, and merge. The change takes effect on the next
run of any caller that points at that file — **no `v3.0` change is
needed** as long as you don't change the `inputs:` interface.

If you *do* change the `inputs:` (add a new required input, rename one,
etc.), you must update every caller on `v3.0` in a coordinated pair of
PRs — same merge-order rule as adding a new group.

### Deleting a reusable

1. First, make sure no caller on `v3.0` points at it. Grep for the
   filename in `v3.0:.github/workflows/CI-*.yml`. If any match, rewire
   them to a different reusable first (separate `v3.0` PR), merge that,
   then proceed.
2. Then open a `GH-Actions` PR deleting the file.

---

## Branch protection

As of 2026-04-11, `GH-Actions` has **no branch protection**. You can
push directly to it if you're a maintainer. PRs are the recommended
workflow so that review bots (CodeRabbit, Sonar) can comment on the
change and so the history is easy to audit, but they are not mechanically
required. The same applies to merge-button status checks: failing
Sonar/CodeRabbit runs don't block merges here.

`v3.0` protection rules are separate and stricter — see the repository
settings for the current state.
