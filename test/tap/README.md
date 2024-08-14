## Folder structure

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
SAVE MYSQL VARIABLES TO DISK;
EOF
```
