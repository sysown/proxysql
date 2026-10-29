# PostgreSQL User Credential Synchronizer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and test a sample scheduler utility that provisions ProxySQL `pgsql_users` from an allow-listed PostgreSQL role-verifier snapshot.

**Architecture:** A self-contained Python module separates immutable configuration/row/action records, pure validation and reconciliation functions, and narrow PostgreSQL/ProxySQL adapters. The CLI acquires a file lock, validates the complete source snapshot, computes a deterministic plan, applies parameterized Admin writes, and loads runtime only after all writes succeed. Documentation and SQL assets make the sample deployable without adding a lookup to ProxySQL's authentication path.

**Tech Stack:** Python 3.10+, standard-library `argparse`, `configparser`, `dataclasses`, `fcntl`, `json`, `logging`, and `unittest`; `psycopg` 3.x; PyMySQL 1.1+; ProxySQL TAP/infrastructure harness.

## Global Constraints

- This utility remains outside ProxySQL core and performs no login-time lookup.
- `default_hostgroup` defaults to `0`; non-secret CLI options may override `[sync]` configuration.
- Connection passwords are config-only and must never appear in arguments, logs, exceptions, or complete configuration representations.
- Configuration files must be regular/readable, not group-writable/executable, and inaccessible to other users; `0600` and root-owned `0640` are supported examples.
- Managed ownership is stored at `attributes.proxysql_pgsql_user_sync.profile`; unrelated JSON attributes and all ProxySQL policy columns are preserved semantically.
- `missing_role_action` supports exactly `disable` (default) and `keep`; the utility never deletes users.
- Source snapshots are complete and validated before any Admin write; empty snapshots require `allow_empty_snapshot = true`.
- Runtime is the safety boundary because ProxySQL Admin does not expose multi-statement SQLite transactions to clients; never issue `LOAD PGSQL USERS TO RUNTIME` after a failed write.
- `SAVE PGSQL USERS TO DISK` occurs only after a successful runtime load and only when configured.
- Scheduler jobs run with an empty environment and can overlap, so examples use absolute paths and the script uses a nonblocking file lock.
- End-to-end authentication assertions require PR #5865 or equivalent verifier support; control-plane synchronization remains testable without it.

---

## File map

- Create `tools/pgsql_user_sync/proxysql_pgsql_user_sync.py`: records, validation, reconciliation, database adapters, orchestration, and CLI.
- Create `tools/pgsql_user_sync/tests/test_pgsql_user_sync.py`: dependency-free unit tests using fake adapters.
- Create `tools/pgsql_user_sync/proxysql_pgsql_user_sync.ini.example`: deployable configuration template.
- Create `tools/pgsql_user_sync/create_source_function.sql`: allow-list, safe `SECURITY DEFINER` function, and reader grants.
- Create `tools/pgsql_user_sync/requirements.txt`: supported driver versions.
- Create `tools/pgsql_user_sync/README.md`: installation, security, Scheduler SQL, clustering, and failure semantics.
- Create `test/tap/tests/pgsql-user-sync-unit-t.py`: no-infrastructure CI wrapper for the canonical unit suite.
- Create `test/tap/tests/pgsql-user-sync-t.py`: PostgreSQL infrastructure lifecycle/authentication test.
- Modify `test/tap/groups/groups.json`: register both test executables.
- Modify `test/infra/docker-base/Dockerfile`: install psycopg for integration tests.

---

### Task 1: Configuration and snapshot validation

**Files:**
- Create: `tools/pgsql_user_sync/proxysql_pgsql_user_sync.py`
- Create: `tools/pgsql_user_sync/tests/test_pgsql_user_sync.py`

**Interfaces:**
- Produces: frozen `SourceConfig`, `ProxySQLConfig`, `SyncSettings`, `AppConfig`, `CLIOverrides`, and `SourceRole` dataclasses.
- Produces: `parse_args(argv: Sequence[str]) -> argparse.Namespace`.
- Produces: `load_config(path: Path, overrides: CLIOverrides) -> AppConfig`.
- Produces: `validate_snapshot(rows: Iterable[Sequence[object]], allow_empty: bool) -> dict[str, SourceRole]`.
- Produces: `validate_verifier(value: str) -> None`, raising `SyncError` without embedding `value`.

- [ ] **Step 1: Write failing configuration tests**

Create an import helper so the test does not require a package, then cover defaults, CLI precedence, permissions, profile/function syntax, non-negative hostgroups, booleans, timeouts, and required fields:

```python
SCRIPT = Path(__file__).parents[1] / "proxysql_pgsql_user_sync.py"

def load_module():
    spec = importlib.util.spec_from_file_location("proxysql_pgsql_user_sync", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

class ConfigTests(unittest.TestCase):
    def test_defaults_and_cli_hostgroup_override(self):
        path = self.write_config(mode=0o600)
        cfg = self.mod.load_config(path, self.mod.CLIOverrides(default_hostgroup=12))
        self.assertEqual(12, cfg.sync.default_hostgroup)
        self.assertEqual("disable", cfg.sync.missing_role_action)
        self.assertFalse(cfg.sync.allow_empty_snapshot)

    def test_rejects_world_readable_config(self):
        path = self.write_config(mode=0o604)
        with self.assertRaisesRegex(self.mod.SyncError, "permissions"):
            self.mod.load_config(path, self.mod.CLIOverrides())
```

- [ ] **Step 2: Run configuration tests and verify they fail**

```bash
python3 -m unittest -v tools/pgsql_user_sync/tests/test_pgsql_user_sync.py
```

Expected: import failure because the implementation file does not exist.

- [ ] **Step 3: Implement immutable configuration records and parsing**

Keep module import standard-library-only. Import drivers inside adapter methods. Define:

```python
class SyncError(RuntimeError):
    pass

@dataclass(frozen=True)
class CLIOverrides:
    default_hostgroup: int | None = None
    missing_role_action: str | None = None
    save_to_disk: bool | None = None

@dataclass(frozen=True)
class SourceConfig:
    host: str
    port: int
    database: str
    username: str
    password: str = field(repr=False)
    connect_timeout: int = 10
    function_schema: str = "proxysql_auth"
    function_name: str = "export_login_roles"

@dataclass(frozen=True)
class ProxySQLConfig:
    host: str
    port: int
    username: str
    password: str = field(repr=False)
    connect_timeout: int = 10

@dataclass(frozen=True)
class SyncSettings:
    profile: str
    default_hostgroup: int = 0
    missing_role_action: str = "disable"
    adopt_existing_users: bool = False
    allow_empty_snapshot: bool = False
    save_to_disk: bool = True
    lock_file: Path = Path("/run/lock/proxysql-pgsql-user-sync.lock")

@dataclass(frozen=True)
class AppConfig:
    source: SourceConfig
    proxysql: ProxySQLConfig
    sync: SyncSettings

@dataclass(frozen=True)
class SourceRole:
    username: str
    password: str = field(repr=False)

PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
```

Split `[source].function` once on `.`. Validate the resolved file with `Path.stat()`, `stat.S_ISREG`, `os.access(path, os.R_OK)`, and `(mode & 0o037) == 0`, permitting group-read only.

- [ ] **Step 4: Write failing verifier and snapshot tests**

Cover lowercase MD5, valid SCRAM, invalid base64/key lengths, duplicates, empty opt-in, NULs, non-string/wrong-shaped rows, and UTF-8 names over 63 bytes:

```python
def test_snapshot_rejects_duplicate_without_leaking_verifier(self):
    verifier = "md5" + "b" * 32
    with self.assertRaisesRegex(self.mod.SyncError, "duplicate") as ctx:
        self.mod.validate_snapshot([("alice", verifier), ("alice", verifier)], False)
    self.assertNotIn(verifier, str(ctx.exception))
```

Build valid SCRAM values with `base64.b64encode(b"x" * 32).decode()` for both keys.

- [ ] **Step 5: Implement verifier and complete-snapshot validation**

Accept `md5[0-9a-f]{32}` or `SCRAM-SHA-256$iterations:salt$stored:server`. For SCRAM, require iterations `1..2_147_483_647`, strict base64, non-empty salt, and two decoded 32-byte keys. Materialize the full snapshot; require two string columns, unique names, no NUL, and at most 63 UTF-8 bytes; return a username-sorted dictionary.

- [ ] **Step 6: Run tests and commit**

```bash
python3 -m unittest -v tools/pgsql_user_sync/tests/test_pgsql_user_sync.py
python3 -m py_compile tools/pgsql_user_sync/proxysql_pgsql_user_sync.py
git add tools/pgsql_user_sync/proxysql_pgsql_user_sync.py tools/pgsql_user_sync/tests/test_pgsql_user_sync.py
git commit -m "feat: validate PostgreSQL user sync input"
```

Expected: all configuration/snapshot tests pass and byte compilation succeeds.

---

### Task 2: Pure ownership and reconciliation planner

**Files:**
- Modify: `tools/pgsql_user_sync/proxysql_pgsql_user_sync.py`
- Modify: `tools/pgsql_user_sync/tests/test_pgsql_user_sync.py`

**Interfaces:**
- Consumes: `SourceRole`, `SyncSettings`, and `SyncError`.
- Produces: frozen `ProxySQLUser`, `SyncAction`, and `SyncPlan` records plus `ActionKind`.
- Produces: `decode_ownership(attributes: str) -> str | None` and `with_ownership(attributes: str, profile: str) -> str`.
- Produces: `build_plan(source, main, runtime, settings) -> SyncPlan`.

- [ ] **Step 1: Write failing creation/update tests**

Use a helper populating every policy field. Verify new users use the configured hostgroup/defaults and existing managed users change only password, active, and ownership:

```python
def test_create_uses_configured_hostgroup(self):
    plan = self.mod.build_plan(
        {"alice": self.role("alice")}, [], [], self.settings(default_hostgroup=17)
    )
    action = plan.actions[0]
    self.assertEqual(self.mod.ActionKind.CREATE, action.kind)
    self.assertEqual(17, action.after.default_hostgroup)
    self.assertEqual((1, 1), (action.after.backend, action.after.frontend))
```

- [ ] **Step 2: Run focused tests and verify they fail**

```bash
python3 -m unittest -v tools.pgsql_user_sync.tests.test_pgsql_user_sync.PlannerTests
```

Expected: `ProxySQLUser`/`build_plan` are undefined.

- [ ] **Step 3: Implement row/action records and ownership helpers**

```python
@dataclass(frozen=True)
class ProxySQLUser:
    username: str
    password: str | None
    active: int
    use_ssl: int
    default_hostgroup: int
    transaction_persistent: int
    fast_forward: int
    backend: int
    frontend: int
    max_connections: int
    attributes: str
    comment: str

class ActionKind(Enum):
    CREATE = "create"
    UPDATE = "update"
    DISABLE = "disable"

@dataclass(frozen=True)
class SyncAction:
    kind: ActionKind
    before: ProxySQLUser | None
    after: ProxySQLUser

@dataclass(frozen=True)
class SyncPlan:
    actions: tuple[SyncAction, ...]
    requires_load: bool
    counts: Mapping[str, int]
```

Treat empty attributes as `{}`. Reject non-object JSON, malformed ownership, and another profile. Serialize changed JSON with sorted keys and compact separators.

- [ ] **Step 4: Write failing conflict/missing/divergence tests**

Cover unmanaged conflict/adoption, cross-profile conflict, duplicate Admin rows, `disable`, `keep`, reactivation, unchanged rows, managed runtime drift, and unrelated pending Admin changes:

```python
def test_missing_action_is_configurable(self):
    owned = self.user("alice", profile="p", active=1)
    disabled = self.mod.build_plan({}, [owned], [owned], self.settings(profile="p"))
    kept = self.mod.build_plan(
        {}, [owned], [owned], self.settings(profile="p", missing_role_action="keep")
    )
    self.assertEqual(self.mod.ActionKind.DISABLE, disabled.actions[0].kind)
    self.assertEqual((), kept.actions)

def test_aborts_for_unmanaged_main_runtime_drift(self):
    main = self.user("local", password=self.verifier_b)
    runtime = replace(main, password=self.verifier_a)
    with self.assertRaisesRegex(self.mod.SyncError, "unmanaged.*runtime"):
        self.mod.build_plan({}, [main], [runtime], self.settings())
```

- [ ] **Step 5: Implement deterministic planning**

Index by username and reject multiple rows per name. Compare active main rows to runtime; inactive main rows are expected to be absent. Reject unmanaged active main/runtime drift before planning because `LOAD PGSQL USERS TO RUNTIME` is global. Iterate source and missing managed usernames in sorted order. Create combined frontend/backend rows, preserve policy with `dataclasses.replace`, and require load when actions exist or managed active projections differ.

- [ ] **Step 6: Run planner tests and commit**

```bash
python3 -m unittest -v tools/pgsql_user_sync/tests/test_pgsql_user_sync.py
git add tools/pgsql_user_sync/proxysql_pgsql_user_sync.py tools/pgsql_user_sync/tests/test_pgsql_user_sync.py
git commit -m "feat: plan managed PostgreSQL user reconciliation"
```

Expected: validation and planner tests pass.

---

### Task 3: Database adapters and safe execution

**Files:**
- Modify: `tools/pgsql_user_sync/proxysql_pgsql_user_sync.py`
- Modify: `tools/pgsql_user_sync/tests/test_pgsql_user_sync.py`

**Interfaces:**
- Consumes: all records/functions from Tasks 1–2.
- Produces: `PostgreSQLSource.fetch_snapshot() -> list[tuple[str, str]]`.
- Produces: `ProxySQLAdmin.fetch_main_users()`, `fetch_runtime_users()`, `apply_actions()`, `load_runtime()`, and `save_to_disk()`.
- Produces: `RunSummary`, `run_sync(config: AppConfig, source: SourceAdapter, admin: AdminAdapter, *, dry_run: bool, verbose: bool) -> RunSummary`, `exclusive_lock(path: Path)`, and `main(argv: Sequence[str] | None = None) -> int`.

- [ ] **Step 1: Write failing adapter SQL tests**

Use fake DB-API connections/cursors to assert identifier composition, exact row projection, parameterized Admin writes, and lazy imports:

```python
def test_admin_update_uses_bound_parameters(self):
    adapter = self.mod.ProxySQLAdmin(self.config, connect=self.fake_connect)
    adapter.apply_actions((self.update_action(),))
    sql, params = self.cursor.executions[-1]
    self.assertIn("password=%s", sql)
    self.assertNotIn(self.verifier_b, sql)
    self.assertEqual(self.verifier_b, params[0])
```

- [ ] **Step 2: Run adapter tests and verify they fail**

```bash
python3 -m unittest -v tools.pgsql_user_sync.tests.test_pgsql_user_sync.AdapterTests
```

Expected: adapters are undefined.

- [ ] **Step 3: Implement narrow database adapters**

Compose the source call as identifiers:

```python
query = sql.SQL("SELECT username::text, password FROM {}.{}()").format(
    sql.Identifier(config.function_schema), sql.Identifier(config.function_name)
)
```

Select `username,password,active,use_ssl,default_hostgroup,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment` from both Admin tables. Create with explicit columns, update/disable by `(username, backend)`, and use bound parameters. Open Admin with autocommit. Wrap driver failures in fixed, credential-free `SyncError` messages.

Define the orchestration boundaries explicitly:

```python
class SourceAdapter(Protocol):
    def fetch_snapshot(self) -> list[tuple[str, str]]: ...

class AdminAdapter(Protocol):
    def fetch_main_users(self) -> list[ProxySQLUser]: ...
    def fetch_runtime_users(self) -> list[ProxySQLUser]: ...
    def apply_actions(self, actions: Sequence[SyncAction]) -> None: ...
    def load_runtime(self) -> None: ...
    def save_to_disk(self) -> None: ...

@dataclass(frozen=True)
class RunSummary:
    outcome: str
    counts: Mapping[str, int]
    loaded: bool
    saved: bool
    duration_seconds: float
```

The ellipses above are Python `Protocol` method bodies, not deferred behavior;
the concrete `PostgreSQLSource` and `ProxySQLAdmin` classes implement every
method in this task.

- [ ] **Step 4: Write failing orchestration/lock/redaction tests**

Cover source failure, dry-run, action failure with no load, load on actions/drift, save only after load, save failure after successful load, lock contention, summary counts, and secret redaction:

```python
def test_write_failure_never_loads_runtime(self):
    admin = FakeAdmin(fail_apply=True)
    with self.assertRaises(self.mod.SyncError):
        self.mod.run_sync(self.config, FakeSource(self.rows), admin,
                          dry_run=False, verbose=False)
    self.assertNotIn("load", admin.calls)
    self.assertNotIn("save", admin.calls)
```

- [ ] **Step 5: Implement orchestration, lock, summaries, and exits**

Use `os.open(path, os.O_CREAT | os.O_RDWR, 0o600)` and `fcntl.flock(fd, LOCK_EX | LOCK_NB)`. Execute fetch → validate → fetch Admin → plan → optional apply → optional load → optional save. Return a frozen summary containing outcome, counts, loaded, saved, and duration. Print one summary line; return `0` for success/dry-run/lock contention and `1` for failures.

- [ ] **Step 6: Run tests/smokes and commit**

```bash
python3 -m unittest -v tools/pgsql_user_sync/tests/test_pgsql_user_sync.py
python3 tools/pgsql_user_sync/proxysql_pgsql_user_sync.py --help
python3 -m py_compile tools/pgsql_user_sync/proxysql_pgsql_user_sync.py
git add tools/pgsql_user_sync/proxysql_pgsql_user_sync.py tools/pgsql_user_sync/tests/test_pgsql_user_sync.py
git commit -m "feat: synchronize PostgreSQL credentials into ProxySQL"
```

Expected: tests pass, help exits zero without installed drivers, and byte compilation succeeds.

---

### Task 4: Deployable SQL, configuration, dependencies, and guide

**Files:**
- Create: `tools/pgsql_user_sync/create_source_function.sql`
- Create: `tools/pgsql_user_sync/proxysql_pgsql_user_sync.ini.example`
- Create: `tools/pgsql_user_sync/requirements.txt`
- Create: `tools/pgsql_user_sync/README.md`
- Modify: `tools/pgsql_user_sync/tests/test_pgsql_user_sync.py`

**Interfaces:**
- Consumes: config/CLI behavior from Tasks 1–3.
- Produces: role `proxysql_auth_managed`, schema `proxysql_auth`, function `proxysql_auth.export_login_roles()`, and reader `proxysql_auth_reader`.

- [ ] **Step 1: Write failing asset-contract tests**

Read assets as text. Assert the SQL fixes `search_path`, revokes PUBLIC, filters login/expiration/null verifiers, and uses allow-list membership. Copy/substitute the example INI to a mode-`0600` temporary file and load it. Assert README Scheduler paths are absolute and both cluster modes are present:

```python
def test_source_function_has_security_boundaries(self):
    sql = (ASSET_DIR / "create_source_function.sql").read_text()
    for required in ("SECURITY DEFINER", "SET search_path = pg_catalog",
                     "rolcanlogin", "rolvaliduntil", "REVOKE ALL"):
        self.assertIn(required, sql)
```

- [ ] **Step 2: Run asset tests and verify they fail**

```bash
python3 -m unittest -v tools.pgsql_user_sync.tests.test_pgsql_user_sync.AssetTests
```

Expected: four asset files are absent.

- [ ] **Step 3: Create source SQL and example configuration**

Use guarded PL/pgSQL blocks for rerunnable role creation. Revoke default schema/function access before exact reader grants. The function selection is:

```sql
SELECT r.rolname::text AS username, r.rolpassword AS password
FROM pg_catalog.pg_authid AS r
WHERE r.rolcanlogin
  AND r.rolpassword IS NOT NULL
  AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil > pg_catalog.now())
  AND pg_catalog.pg_has_role(r.oid, 'proxysql_auth_managed', 'member')
ORDER BY r.rolname;
```

Use obvious placeholder secrets and instruct operators to replace them.

- [ ] **Step 4: Write requirements and operations README**

`requirements.txt` contains:

```text
psycopg[binary]>=3.2.13,<4
PyMySQL>=1.1.1,<2
```

Document installation, file permissions, allow-list grant/revoke, dry-run, manual execution, absolute Scheduler SQL, non-transactional main/runtime recovery, `disable|keep`, adoption, global-load/unmanaged-divergence guard, log guarantees, disk persistence, and the two mutually exclusive cluster models.

- [ ] **Step 5: Run tests and commit**

```bash
python3 -m unittest -v tools/pgsql_user_sync/tests/test_pgsql_user_sync.py
git add tools/pgsql_user_sync
git commit -m "docs: add PostgreSQL user sync deployment sample"
```

Expected: all tests pass.

---

### Task 5: Register dependency-free unit coverage

**Files:**
- Create: `test/tap/tests/pgsql-user-sync-unit-t.py`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: `tools/pgsql_user_sync/tests/test_pgsql_user_sync.py`.
- Produces: executable `pgsql-user-sync-unit-t` in `no-infra-g1`.

- [ ] **Step 1: Create the harness wrapper and registration**

```python
#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

root = Path(os.environ.get("WORKSPACE", Path(__file__).resolve().parents[3]))
suite = root / "tools/pgsql_user_sync/tests/test_pgsql_user_sync.py"
raise SystemExit(subprocess.call(
    [sys.executable, "-m", "unittest", "-v", str(suite)], cwd=root
))
```

Add this alphabetically to `groups.json`:

```json
"pgsql-user-sync-unit-t" : [ "no-infra-g1" ]
```

- [ ] **Step 2: Build/run wrapper and lint registration**

```bash
make -C test/tap/tests pgsql-user-sync-unit-t
test/tap/tests/pgsql-user-sync-unit-t
python3 test/tap/groups/lint_groups_json.py
```

Expected: canonical unit tests and group lint pass.

- [ ] **Step 3: Commit harness registration**

```bash
git add test/tap/tests/pgsql-user-sync-unit-t.py test/tap/groups/groups.json
git commit -m "test: register PostgreSQL user sync unit suite"
```

---

### Task 6: PostgreSQL/ProxySQL lifecycle integration test

**Files:**
- Create: `test/tap/tests/pgsql-user-sync-t.py`
- Modify: `test/tap/groups/groups.json`
- Modify: `test/infra/docker-base/Dockerfile`

**Interfaces:**
- Consumes: the CLI plus `TAP_ADMIN*`, `TAP_PGSQLSERVER_*`, and `TAP_PGSQL_*` environment variables.
- Produces: executable `pgsql-user-sync-t` in `legacy-g4`.
- Consumes optional `TAP_EXPECT_PGSQL_VERIFIER_AUTH=1`; when set, verifier-auth failures are failures rather than dependency skips.

- [ ] **Step 1: Add test-runner psycopg dependency**

Add this build argument beside `MYSQL_CONNECTOR_PYTHON_VERSION`:

```dockerfile
ARG PSYCOPG_VERSION=3.2.13
```

Add the exact argument `"psycopg[binary]==${PSYCOPG_VERSION}"` immediately
after `fastcov` in the existing `pip3 install --break-system-packages` command,
before the two MySQL connector arguments.

- [ ] **Step 2: Write cleanup-safe lifecycle test**

The executable must:

1. connect directly to PostgreSQL as `TAP_PGSQLSERVER_USERNAME`;
2. create uniquely prefixed allow-list, reader, test role, schema, and source function;
3. create a mode-`0600` temporary INI using `TAP_ADMIN*` for MySQL Admin;
4. create an unmanaged ProxySQL control row with non-default policy;
5. build `command = [sys.executable, str(SCRIPT), "--config", str(config_path)]`
   and invoke it with `subprocess.run(command, text=True, capture_output=True)`,
   never `shell=True`;
6. verify main/runtime creation, hostgroup, verifier equality, and ownership;
7. rotate the source password, rerun, and verify the verifier changes;
8. revoke `LOGIN`, run `disable`, and verify main inactive/runtime absent;
9. restore `LOGIN`, sync, remove eligibility, run `keep`, and verify active;
10. break source function execution and verify runtime rows remain identical;
11. verify the unmanaged control row remains identical; and
12. restore/delete ProxySQL rows and drop all PostgreSQL objects in `finally`.

Never put credentials in assertion messages or captured command displays.

- [ ] **Step 3: Add conditional frontend-auth assertions**

After creation/rotation, connect via `TAP_PGSQL_HOST:TAP_PGSQL_PORT`. When `TAP_EXPECT_PGSQL_VERIFIER_AUTH=1`, require new-password success and old-password failure. Otherwise, report a clear TAP-style verifier dependency skip if the initial capability probe fails, but continue every control-plane assertion.

- [ ] **Step 4: Register/build/lint integration test**

Add alphabetically:

```json
"pgsql-user-sync-t" : [ "legacy-g4" ]
```

Run:

```bash
make -C test/tap/tests pgsql-user-sync-t
python3 test/tap/groups/lint_groups_json.py
```

Expected: executable copied without `.py`, executable bit set, group lint passes.

- [ ] **Step 5: Run isolated test**

```bash
PROXYSQL31=1 make debug
PROXYSQL31=1 make build_tap_test_debug
docker build --network host -t proxysql-ci-base:latest test/infra/docker-base
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-user-sync-t" \
  test/infra/control/run-tests-isolated.bash
```

Expected: lifecycle passes; verifier frontend assertions pass on a capable build or report only the explicit dependency skip.

- [ ] **Step 6: Commit integration coverage**

```bash
git add test/infra/docker-base/Dockerfile test/tap/groups/groups.json test/tap/tests/pgsql-user-sync-t.py
git commit -m "test: cover PostgreSQL user synchronization lifecycle"
```

---

### Task 7: Final security and regression verification

**Files:**
- Modify only files from Tasks 1–6 if verification exposes a defect.

**Interfaces:**
- Consumes: all prior artifacts.
- Produces: a verified branch with no credential leakage or unrelated staged files.

- [ ] **Step 1: Run complete fast suite/static checks**

```bash
python3 -m unittest -v tools/pgsql_user_sync/tests/test_pgsql_user_sync.py
python3 -m py_compile \
  tools/pgsql_user_sync/proxysql_pgsql_user_sync.py \
  test/tap/tests/pgsql-user-sync-unit-t.py \
  test/tap/tests/pgsql-user-sync-t.py
python3 test/tap/groups/lint_groups_json.py
git diff --check HEAD~6..HEAD
```

Expected: all checks pass.

- [ ] **Step 2: Audit secrets and SQL construction**

```bash
rg -n 'password|verifier|execute\(|connect\(' \
  tools/pgsql_user_sync test/tap/tests/pgsql-user-sync-t.py
```

Confirm passwords are only config/parameter values, SQL data is bound, function names use identifier composition, password fields use `repr=False`, and logs contain no credential material.

- [ ] **Step 3: Re-run isolated integration test after any fixes**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g4 \
  TEST_PY_TAP_INCL="pgsql-user-sync-t" \
  test/infra/control/run-tests-isolated.bash
```

Expected: pass or explicit verifier-capability skip only.

- [ ] **Step 4: Confirm scope and commit verification fixes if any**

```bash
git status --short
git diff --stat HEAD~6..HEAD
```

Only plan files plus `tools/pgsql_user_sync`, the two TAP Python sources, groups registration, and docker-base dependency may change. If fixes were required:

```bash
git add tools/pgsql_user_sync test/tap/tests/pgsql-user-sync-unit-t.py \
  test/tap/tests/pgsql-user-sync-t.py test/tap/groups/groups.json \
  test/infra/docker-base/Dockerfile
git commit -m "fix: harden PostgreSQL user synchronizer"
```
