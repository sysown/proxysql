# Self-hosted CI Compose Workspace Cleanup Design

## Problem

The `ubuntu24,-tap-genai-gcov` build on PR #6038 failed before checkout.
Its self-hosted runner, `ci-vm-1`, contained root-owned files under the
previous Docker build's bind mount. The workflow ran `chown -R`, but the
subsequent ownership check immediately found different root-owned files. This
demonstrates that a stale Docker Compose build container was still writing to
the persistent workspace. The failure-path artifact upload then attempted to
zip the whole changing checkout and failed with `ENOENT`.

## Scope

Modify only `.github/workflows/ci-builds.yml` on a branch based on
`GH-Actions`. The change must not alter ProxySQL source code, test selection,
Docker images, permissions, or unrelated runner workloads.

## Design

The Makefile invokes `docker-compose -p $(IMG_NAME)`, where `IMG_NAME` is the
distribution name. The active CI-builds matrix therefore owns the explicit
project set `debian12`, `ubuntu22`, and `ubuntu24`. A VM schedules those legs
serially, so a cancelled `ubuntu22` build can contaminate the persistent
workspace immediately before an `ubuntu24` build starts.

Before the existing ownership guard, a self-hosted entry must tear down only
that explicit CI-build project set, including volumes and orphan containers.
If a partial cleanup has already removed `docker-compose.yml`, it must also
remove containers carrying the corresponding Compose project labels; otherwise
the stale writer survives exactly when the configuration is absent. The
workflow must then reclaim and verify workspace ownership before checkout.
After every outcome, it must tear down the same set again before the final
ownership repair. Both cleanup steps must attempt every project before they
return a nonzero status; they must not use broad Docker pruning or suppress an
error.

Failure artifacts are diagnostic data, not a snapshot of a live bind mount.
Archive only `proxysql/ci_build_log/`, and only when the Build step or its
separate log-validation step failed. This avoids scanning and zipping hundreds
of thousands of files after a preflight failure while preserving the build logs
that explain genuine build errors.

## Acceptance Criteria

- A self-hosted matrix entry removes only the known CI-build Compose projects
  (`debian12`, `ubuntu22`, and `ubuntu24`) before the first ownership check and
  after the job outcome.
- Missing `docker-compose.yml` does not leave a labelled project container
  running, and a teardown reports failure only after attempting every project.
- The preflight cleanup runs before checkout; the postflight cleanup runs on
  successful and failed builds.
- Root ownership is still reclaimed and verified after each cleanup.
- The failure artifact is collected when Build or Check build failed, but not
  for an ownership-only preflight failure.
- The failure artifact does not run for a preflight ownership failure and does
  not include the full checkout.
- `.github/workflows/ci-builds.yml` remains valid YAML and does not broaden
  CI permissions.
