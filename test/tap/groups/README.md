# TAP Test Groups

This directory organizes TAP tests into **groups** that share the same infrastructure and configuration.

## groups.json

`groups.json` maps each test binary to one or more groups. Every entry is a test name (without path) and an array of group names it belongs to.

### Format

One entry per line, compact arrays with spaces around `:` and inside `[ ]`:

```json
{
  "admin-listen_on_unix-t" : [ "legacy-g1","mysql84-g1","mysql90-g1" ],
  "auth_unit-t" : [ "unit-tests-g1" ],
  "basic-t" : [ "legacy-g1","mysql84-g1" ]
}
```

This format keeps `grep` effective for quick lookups:

```bash
# Which groups does a test belong to?
grep "my_test-t" groups.json

# Which tests are in a group?
grep "unit-tests-g1" groups.json
```

Do **not** reformat the file with multi-line arrays or change the indentation style.

### Group naming convention

Groups follow the pattern `<base>-g<N>` where:

- `<base>` is the group name (e.g., `legacy`, `mysql84`, `unit-tests`)
- `<N>` is a subgroup number for splitting tests into parallel batches

The system strips the `-gN` suffix to find the base group directory for `infras.lst`, `env.sh`, and hooks.

## Group directory structure

Each group has a directory under `test/tap/groups/<base>/` with some or all of:

| File | Purpose |
|------|---------|
| `env.sh` | Environment variables for the group (sourced early by the runner) |
| `infras.lst` | Required backend infrastructures (one per line) |
| `setup-infras.bash` | Hook: runs after all backends are up |
| `pre-proxysql.bash` | Hook: runs before test execution (e.g., cluster setup) |
| `pre-cleanup.bash` | Hook: runs after tests, before container teardown |

## Infrastructure-free groups

Groups that set `SKIP_PROXYSQL=1` in their `env.sh` run without ProxySQL or any backend containers. The `unit-tests` group is the primary example. See `test/infra/README.md` section 6.1 for details.
