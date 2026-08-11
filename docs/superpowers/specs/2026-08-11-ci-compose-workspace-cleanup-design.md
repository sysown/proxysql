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

Each CI-builds matrix entry maps its Docker Compose project to `matrix.dist`:
the Makefile invokes `docker-compose -p $(IMG_NAME)`, and `IMG_NAME` is the
distribution name such as `ubuntu24`, `ubuntu22`, or `debian12`.

Before the existing ownership guard, a self-hosted entry must tear down only
that matrix-specific Compose project, including volumes and orphan containers.
The workflow must then reclaim and verify workspace ownership before checkout.
After every outcome, it must tear down the same project again before the final
ownership repair. Both cleanup steps must fail loudly if Docker cannot perform
the requested cleanup; they must not use broad Docker pruning or suppress an
error.

Failure artifacts are diagnostic data, not a snapshot of a live bind mount.
Archive only `proxysql/ci_build_log/`, and only when the Build step itself ran
and failed. This avoids scanning and zipping hundreds of thousands of files
after a preflight failure while preserving the build logs that explain genuine
build errors.

## Acceptance Criteria

- A self-hosted matrix entry removes only its `${{ matrix.dist }}` Compose
  project before the first ownership check and after the job outcome.
- The preflight cleanup runs before checkout; the postflight cleanup runs on
  successful and failed builds.
- Root ownership is still reclaimed and verified after each cleanup.
- The failure artifact does not run for a preflight ownership failure and does
  not include the full checkout.
- `.github/workflows/ci-builds.yml` remains valid YAML and does not broaden
  CI permissions.
