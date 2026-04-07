# MySQLX Plugin Branch Wrap-Up

Date: 2026-04-07
Branch: `mysqlx-plugin-impl`
Worktree: `/data/rene/proxysql/.worktrees/mysqlx-plugin-impl`

## Completed on this branch

- Task 1: generic plugin ABI and loader
- Task 2: plugin configuration and core lifecycle wiring
- Task 3: plugin-owned admin table and command registration
- Task 4: mysqlx plugin scaffold, build integration, and plugin-load smoke test

## Task 4 verification

The latest verified end-to-end smoke command was:

```bash
cd /data/rene/proxysql/.worktrees/mysqlx-plugin-impl/plugins/mysqlx && make clean && \
cd /data/rene/proxysql/.worktrees/mysqlx-plugin-impl/test/tap/tests && \
make test_mysqlx_plugin_load-t && \
./test_mysqlx_plugin_load-t
```

Result:

- `ok 1` load mysqlx plugin succeeds
- `ok 2` init_all registers mysqlx schema
- `ok 3` mysqlx_users registered in admin_db
- `ok 4` mysqlx_users registered in config_db
- `ok 5` mysqlx_users admin schema includes allowed_auth_methods
- `ok 6` mysqlx_users config schema includes backend_auth_mode

## Partial WIP

Task 5 was started but not completed.

Current branch state includes only failing-test scaffolding for:

- `test/tap/tests/unit/mysqlx_config_store_unit-t.cpp`
- `test/tap/tests/test_mysqlx_admin_tables-t.cpp`
- matching unit/top-level test Makefile wiring

What is still missing from Task 5:

- `plugins/mysqlx/include/mysqlx_config_store.h`
- `plugins/mysqlx/src/mysqlx_config_store.cpp`
- runtime table registration beyond `mysqlx_users`
- `PLUGIN MYSQLX LOAD ... TO RUNTIME` command implementations
- dual-mode identity merge logic
- Task 5 verification

## Remaining work tracked in GitHub

- Task 5: [#5585](https://github.com/sysown/proxysql/issues/5585) mysqlx runtime schema, load commands, and dual-mode identity resolution
- Task 6: [#5588](https://github.com/sysown/proxysql/issues/5588) plugin-owned listeners and worker threads
- Task 7: [#5584](https://github.com/sysown/proxysql/issues/5584) frontend X handshake, auth, and account enforcement
- Task 8: [#5586](https://github.com/sysown/proxysql/issues/5586) backend X sessions and hostgroup-based route selection
- Task 9: [#5587](https://github.com/sysown/proxysql/issues/5587) stats, end-to-end coverage, and topology invalidation hooks

## Notes

- The Task 5 implementer run was interrupted by a usage-limit error before it could finish the implementation.
- Plugin admin commands must remain namespaced with the `PLUGIN ` prefix.
- Runtime mysqlx tables should live in the admin DB; there is no separate plugin runtime DB kind.
