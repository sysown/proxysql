# AI TAP Group Local Infra

This group supports running AI/MCP TAP tests with an isolated local backend infra, without relying on Jenkins helper repos.

## What it starts

- MySQL 9.0 on `127.0.0.1:13306`
- PostgreSQL 16 on `127.0.0.1:15432`

Both are started from `test/tap/groups/ai/docker-compose.yml`.

## Group hooks

- `pre-proxysql.bash`
  - starts local containers (`docker-compose-init.bash`)
  - enables MCP
  - configures backend hostgroups and MCP profiles/targets:
    - MySQL target: `tap_mysql_default`
    - PostgreSQL target: `tap_pgsql_default`
- `post-proxysql.bash`
  - removes group-specific MCP profiles/targets/hostgroups
  - destroys local containers (`docker-compose-destroy.bash`)

## Manual run (without Jenkins)

From repository root:

```bash
source test/tap/groups/ai/env.sh
bash test/tap/groups/ai/pre-proxysql.bash
# run your TAP tests here
bash test/tap/groups/ai/post-proxysql.bash
```

For MCP query-rules suite:

```bash
source test/tap/groups/ai/env.sh
bash test/tap/groups/ai/pre-proxysql.bash
bash test/tap/tests/test_mcp_query_rules-t.sh
bash test/tap/groups/ai/post-proxysql.bash
```

## Notes

- All variables can be overridden from the environment before running hooks.
- The scripts still work in Jenkins-driven TAP flows because they do not require Jenkins-only paths.

