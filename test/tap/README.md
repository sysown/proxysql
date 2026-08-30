## Folder structure

## Persistent configuration policy

The TAP tester restores ProxySQL configuration from disk between tests. Therefore,
TAP tests and test-group setup/teardown scripts **must not execute** `SAVE ... TO
DISK` commands: they write test state into the persistent configuration and corrupt
the baseline for later tests.

For normal setup and cleanup, change only the relevant in-memory admin tables and
use `LOAD ... TO RUNTIME` to apply or remove those changes. A test may use `SAVE
... TO DISK` only when persistence is itself the behavior under test; such a test
must restore the original on-disk configuration before it exits.

- `tap`: Contains TAP helper library for testing, and general utilities used across all tests.
- `tests`: General test folder for either unitary or functional tests.
- `tests_with_deps`: Test folder that holds all the tests that require special dependencies for being build.

- `tests_grp_*`: tap test groups of specific tests with special configs applied via
  - `pre-tests_grp_*.bash` script run before tests
  - `pre-tests_grp_*.sql` script run before tests
  - `post-tests_grp_*.bash` script run after tests
  - `post-tests_grp_*.sql` script run after tests

example test group `tests_grp_mytests` can be created by
```
TG='mytests'
mkdir -p test/tap/tests_grp_$TG
cd test/tap/tests_grp_$TG
for T in $(ls -1 ../tests/); do ln -fsT ../tests/$T $T; done
cat > pre-test_grp_$TG-proxysql.sql << EOF
# run this test group with:
SET mysql-multiplexing='false';
LOAD MYSQL VARIABLES TO RUNTIME;
EOF
```
