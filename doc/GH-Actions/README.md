# GitHub Actions CI/CD Documentation

## Architecture

ProxySQL CI uses a **two-tier workflow architecture**:

1. **Caller workflows** live on the main branches (e.g. `v3.0`). They are thin wrappers that trigger on events (push, PR, manual dispatch) and delegate to reusable workflows.
2. **Reusable workflows** live on the `GH-Actions` branch. They contain the actual build/test logic, matrix definitions, caching strategy, and infrastructure orchestration.

This separation allows updating CI logic on the `GH-Actions` branch without touching the main codebase.

### Execution Flow

```
Push/PR
  └─► CI-trigger (on: push/pull_request)
        │
        ├─[in_progress]─► CI-builds (3 matrix builds, caches artifacts)
        │                    ├── debian12-dbg
        │                    ├── ubuntu22-tap
        │                    └── ubuntu24-tap-genai-gcov
        │
        ├─[in_progress]─► CI-legacy-g2        (ubuntu22-tap cache)
        ├─[in_progress]─► CI-legacy-g2-genai  (ubuntu24-tap-genai-gcov cache)
        │
        ├─[completed]──► CI-selftests         (ubuntu22-tap cache)
        ├─[completed]──► CI-basictests        (ubuntu22-tap cache)
        ├─[completed]──► CI-maketest          (ubuntu22-tap cache)
        ├─[completed]──► CI-taptests-groups   (ubuntu22-tap cache) [BROKEN: #5521]
        ├─[completed]──► CI-taptests          (ubuntu22-tap cache) [BROKEN: #5521]
        ├─[completed]──► CI-taptests-ssl      (ubuntu22-tap cache) [BROKEN: #5521]
        ├─[completed]──► CI-taptests-asan     (ubuntu22-tap cache) [BROKEN: #5521]
        ├─[completed]──► CI-repltests         (ubuntu22-tap cache) [BROKEN: #5521]
        ├─[completed]──► CI-shuntest          (ubuntu22-tap cache) [BROKEN: #5521]
        ├─[completed]──► CI-codeql
        ├─[completed]──► CI-package-build
        │
        └─[completed]──► CI-3p-* (10 third-party integration workflows)
```

**Trigger types:**
- `in_progress` — fires as soon as CI-trigger starts. Used by CI-builds (which must run first) and workflows that wait on build caches.
- `completed` — fires after CI-trigger finishes. Used by test workflows that depend on CI-builds having already populated the cache.

### Concurrency

Every workflow uses concurrency groups to prevent resource waste:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref_name }}
  cancel-in-progress: true
```

Only one run per workflow per branch is active at any time. A new push cancels the previous run.

---

## CI-trigger

| | |
|---|---|
| **File** | `CI-trigger.yml` → `ci-trigger.yml@GH-Actions` |
| **Triggers** | Push to version branches (`v[0-9].[0-9x]+...`), pull requests, manual dispatch |
| **Paths ignored** | `.github/**`, `**.md` |
| **Purpose** | Entry point for the entire CI pipeline. Does not do any work itself — its `in_progress` and `completed` events trigger all downstream workflows. |

---

## CI-builds

| | |
|---|---|
| **File** | `CI-builds.yml` → `ci-builds.yml@GH-Actions` |
| **Triggers** | `CI-trigger` `in_progress`, manual dispatch |
| **Runs on** | `ubuntu-24.04` |
| **Purpose** | Compiles ProxySQL in Docker containers and caches the artifacts for downstream test workflows. |

### Build Matrix

| Matrix Entry | Make Target | Build Flags | Use Case |
|---|---|---|---|
| `debian12-dbg` | `make debian12-dbg` | Debug (`-O0 -ggdb`) | 3rd-party integration testing |
| `ubuntu22-tap` | `make ubuntu22-dbg` | Debug + TAP test binaries | Standard TAP testing |
| `ubuntu24-tap-genai-gcov` | `make ubuntu24-dbg` | Debug + `PROXYSQLGENAI=1` + `WITHGCOV=1` | GenAI feature testing with code coverage |

### Build Flag Injection

Build flags are injected into `docker-compose.yml` environment before the build runs, using the same pattern for each:

```yaml
# In the Build step:
if [[ "${{ matrix.type }}" =~ "-asan" ]]; then
  sed -i "/command/i \      - WITHASAN=1" docker-compose.yml
fi
if [[ "${{ matrix.type }}" =~ "-genai" ]]; then
  sed -i "/command/i \      - PROXYSQLGENAI=1" docker-compose.yml
fi
if [[ "${{ matrix.type }}" =~ "-gcov" ]]; then
  sed -i "/command/i \      - WITHGCOV=1" docker-compose.yml
fi
```

### Cache Strategy

Each build produces four cache entries keyed by `{SHA}_{dist}{type}`:

| Cache Suffix | Contents | Used By |
|---|---|---|
| `_bin` | `.git/` + `binaries/` | Package builds |
| `_src` | `src/` (includes proxysql binary) | All test workflows |
| `_test` | `test/` (includes TAP test binaries) | TAP test workflows |
| `_matrix` | `tap-matrix*.json` files | TAP matrix workflows |

Caches expire after 7 days of inactivity.

---

## Test Workflows — In-Repo Infrastructure

These workflows use the `test/infra/` orchestration system (no external dependencies).

### CI-selftests

| | |
|---|---|
| **File** | `CI-selftests.yml` → `ci-selftests.yml@GH-Actions` |
| **Cache** | `ubuntu22-tap_src` |
| **Status** | Working |
| **Infrastructure** | None (runs ProxySQL directly on the runner) |
| **What it tests** | ProxySQL self-test commands (`PROXYSQLTEST 1-6`), core dumps, query digest stats |

### CI-basictests

| | |
|---|---|
| **File** | `CI-basictests.yml` → `ci-basictests.yml@GH-Actions` |
| **Cache** | `ubuntu22-tap_src` |
| **Status** | Working (migrated from jenkins-build-scripts, PR #5525) |
| **Infrastructure** | MySQL 5.7 (via `test/infra/infra-mysql57/`) |
| **TAP Group** | `basictests` |
| **What it tests** | Sysbench benchmark, COM_CHANGE_USER, orchestrator failover |
| **Env flags** | `SKIP_CLUSTER_START=1` |

Uses `ensure-infras.bash` → `start-proxysql-isolated.bash` → `run-tests-isolated.bash` pipeline with the `basictests` TAP group. The `setup-infras.bash` hook aliases hostgroup pairs (e.g. 1300/1301 → 0/1) for backwards compatibility with `proxysql-tester.py`.

### CI-legacy-g2

| | |
|---|---|
| **File** | `CI-legacy-g2.yml` → `ci-legacy-g2.yml@GH-Actions` |
| **Cache** | `ubuntu22-tap_src` + `ubuntu22-tap_test` |
| **Status** | New |
| **Infrastructure** | MySQL 5.7, MariaDB 10, PostgreSQL 16, ClickHouse 23 |
| **TAP Group** | `legacy-g2` (44 TAP tests) |
| **Env flags** | `SKIP_CLUSTER_START=1`, `TAP_USE_NOISE=1` |

Runs the second batch of legacy TAP tests using the standard ubuntu22 build. Noise injection is enabled to help detect race conditions.

### CI-legacy-g2-genai

| | |
|---|---|
| **File** | `CI-legacy-g2-genai.yml` → `ci-legacy-g2-genai.yml@GH-Actions` |
| **Cache** | `ubuntu24-tap-genai-gcov_src` + `ubuntu24-tap-genai-gcov_test` |
| **Status** | New |
| **Infrastructure** | MySQL 5.7, MariaDB 10, PostgreSQL 16, ClickHouse 23 |
| **TAP Group** | `legacy-g2` (44 TAP tests) |
| **Env flags** | `SKIP_CLUSTER_START=1`, `TAP_USE_NOISE=1`, `COVERAGE=1` |
| **Artifacts** | Coverage report uploaded as workflow artifact |

Same tests as CI-legacy-g2 but runs against the GenAI build (`PROXYSQLGENAI=1`) with code coverage enabled (`WITHGCOV=1`). This validates that GenAI features don't break existing functionality.

### CI-maketest

| | |
|---|---|
| **File** | `CI-maketest.yml` → `ci-maketest.yml@GH-Actions` |
| **Cache** | `ubuntu22-tap_src` |
| **Status** | Working |
| **Infrastructure** | MySQL 5.7 (Docker) |
| **What it tests** | Runs `make test` inside a Docker build container |

---

## Test Workflows — Broken (Depend on jenkins-build-scripts)

These workflows still reference the private `proxysql/jenkins-build-scripts` repository and fail with `fatal: repository not found`. See issue #5521 for migration tracking.

### CI-taptests-groups

| | |
|---|---|
| **Status** | Broken (#5521) |
| **Purpose** | Runs TAP tests in parallel groups. Dynamically builds a test matrix from `tap-matrix.json`. |
| **Migration** | Medium effort. Most infrastructure exists in-repo (`test/tap/groups/`). |

### CI-repltests

| | |
|---|---|
| **Status** | Broken (#5521, #5523) |
| **Purpose** | Replication chain tests with sysbench load and data consistency verification. Tests MySQL 5.6/5.7/8.0 with/without SSL and debezium. |
| **Migration** | Requires porting `proxysql_repl_tests/` from jenkins-build-scripts. |

### CI-shuntest

| | |
|---|---|
| **Status** | Broken (#5521) |
| **Purpose** | Backend shunning/failover algorithm tests. Uses the same `proxysql_repl_tests` infrastructure as CI-repltests. |
| **Migration** | Unblocked by CI-repltests migration. |

### CI-taptests, CI-taptests-ssl, CI-taptests-asan

| | |
|---|---|
| **Status** | Broken (#5521) |
| **Purpose** | Various TAP test execution modes: standard, SSL-focused, and AddressSanitizer. |
| **Migration** | Similar to CI-taptests-groups. |

---

## CI-package-build

| | |
|---|---|
| **File** | `CI-package-build.yml` → `ci-package-build.yml@GH-Actions` |
| **Triggers** | Push (not workflow_run) |
| **Status** | Working |
| **Purpose** | Builds `.deb` and `.rpm` packages for distribution. Independent of the CI-trigger cascade. |

---

## CI-codeql

| | |
|---|---|
| **File** | `CI-codeql.yml` → `ci-codeql.yml@GH-Actions` |
| **Triggers** | `CI-trigger` `completed` |
| **Status** | Working |
| **Purpose** | GitHub CodeQL security analysis. |

---

## Third-Party Integration Workflows (CI-3p-*)

Ten workflows test ProxySQL against external client libraries and frameworks. They all:
- Trigger on `CI-trigger` `completed`
- Use repository variables for matrix configuration (database versions, connector versions)
- Run separate MySQL and MariaDB/PostgreSQL jobs
- Are independent of the build cache (they build ProxySQL inline)

| Workflow | Client Library | Protocols |
|---|---|---|
| `CI-3p-aiomysql` | Python aiomysql (async) | MySQL |
| `CI-3p-django-framework` | Django ORM | MySQL, PostgreSQL |
| `CI-3p-laravel-framework` | Laravel Eloquent | MySQL, PostgreSQL |
| `CI-3p-mariadb-connector-c` | MariaDB C connector | MySQL |
| `CI-3p-mysql-connector-j` | MySQL Connector/J (Java) | MySQL |
| `CI-3p-pgjdbc` | PostgreSQL JDBC | PostgreSQL |
| `CI-3p-php-pdo-mysql` | PHP PDO MySQL | MySQL |
| `CI-3p-php-pdo-pgsql` | PHP PDO PostgreSQL | PostgreSQL |
| `CI-3p-postgresql` | libpq (native) | PostgreSQL |
| `CI-3p-sqlalchemy` | SQLAlchemy ORM | MySQL, PostgreSQL |

### Matrix Variables

Each 3p workflow reads its test matrix from GitHub repository variables:

```
MATRIX_3P_AIOMYSQL_infradb_mysql      # e.g. ["mysql57", "mysql84", "mysql91"]
MATRIX_3P_AIOMYSQL_connector_mysql    # e.g. ["0.1.1", "0.2.0"]
MATRIX_3P_AIOMYSQL_infradb_mariadb    # e.g. ["mariadb105", "mariadb115"]
MATRIX_3P_AIOMYSQL_connector_mariadb  # e.g. ["0.1.1", "0.2.0"]
```

---

## Other Workflows

### claude.yml

Claude Code automation for AI-assisted development. Triggers on issue comments, PR comments, and issue assignments.

### claude-code-review.yml

Automated code review using Claude. Triggers on pull request events.

---

## Test Infrastructure (test/infra/)

Test workflows that use the in-repo infrastructure follow this pipeline:

```
ensure-infras.bash          # Start ProxySQL + backends based on TAP group's infras.lst
  ├── start-proxysql-isolated.bash   # ProxySQL in Docker container
  ├── infra-mysql57/docker-compose-init.bash  # MySQL 5.7 (3 nodes + 3 orchestrators)
  ├── docker-pgsql16-single/...              # PostgreSQL 16
  └── ...other backends from infras.lst

run-tests-isolated.bash     # Launch test runner container
  ├── Source group env.sh (TEST_PY_* flags)
  ├── Source env-isolated.bash (TAP_* connection vars)
  └── Run proxysql-tester.py

stop-proxysql-isolated.bash # Cleanup ProxySQL
destroy-infras.bash         # Cleanup backends
```

### TAP Groups

Tests are organized into groups under `test/tap/groups/`. Each group has:

| File | Purpose |
|---|---|
| `infras.lst` | Required backend infrastructure (one per line) |
| `env.sh` | Environment overrides (test flags, hostgroup defaults) |
| `pre-proxysql.bash` | Hook: runs before tests (cluster setup) |
| `setup-infras.bash` | Hook: runs after infra is up (hostgroup aliasing, etc.) |
| `pre-cleanup.bash` | Hook: runs before teardown |

Group assignment is defined in `test/tap/groups/groups.json` which maps test binary names to group names (e.g. `legacy-g1`, `legacy-g2`, `mysql84-g1`, etc.).

### Key Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `INFRA_ID` | `dev-$USER` | Namespace for Docker containers (enables parallel runs) |
| `TAP_GROUP` | — | Which test group to run |
| `SKIP_CLUSTER_START` | `0` | Skip ProxySQL cluster setup |
| `TAP_USE_NOISE` | `0` | Enable random delay injection for race condition testing |
| `COVERAGE` | `0` | Enable code coverage collection |
| `WITHGCOV` | `0` | Tell `proxysql-tester.py` binary was built with gcov |

---

## Adding a New Test Workflow

To add a new workflow for TAP group `<group>` with build variant `<build>`:

1. **Reusable workflow** — Create `.github/workflows/ci-<name>.yml` on the `GH-Actions` branch. Use `ci-legacy-g2.yml` as a template. Set the `BLDCACHE` env to match the build variant cache key (e.g. `ubuntu22-tap_src`).

2. **Caller workflow** — Create `.github/workflows/CI-<name>.yml` on the main branch:
   ```yaml
   name: CI-<name>
   on:
     workflow_dispatch:
     workflow_run:
       workflows: [ CI-trigger ]
       types: [ in_progress ]  # or completed
   jobs:
     run:
       uses: sysown/proxysql/.github/workflows/ci-<name>.yml@GH-Actions
       secrets: inherit
       with:
         trigger: ${{ toJson(github) }}
   ```

3. **TAP group** (if new) — Create `test/tap/groups/<group>/` with `infras.lst` and `env.sh`. Add test assignments to `groups.json`.

Use `in_progress` trigger type if the workflow should start building immediately (parallel with CI-builds). Use `completed` if it must wait for CI-builds to finish populating the cache.

---

## File Locations

| What | Where |
|---|---|
| Caller workflows | `.github/workflows/CI-*.yml` (main branch) |
| Reusable workflows | `.github/workflows/ci-*.yml` (`GH-Actions` branch) |
| Test infrastructure | `test/infra/` |
| Control scripts | `test/infra/control/` |
| TAP groups | `test/tap/groups/` |
| Group-to-test mapping | `test/tap/groups/groups.json` |
| Python test runner | `test/scripts/bin/proxysql-tester.py` |
| Tester config | `test/scripts/etc/proxysql-tester.yml` |
| Docker base image | `test/infra/docker-base/Dockerfile` |
| Migration tracking | Issue #5521 |
