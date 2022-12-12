## Compilation

Compilation requires an env variable `MARIADB_TEST_DEP` to point to the location of a `mariadb-connector-c`
version `3.1.9`. Full expected path for the dependency is:

```
$(TEST_DEPS)/mariadb-client-library/mariadb-connector-c
```

The dependency is expected to be compiled in the target mode simply forwarding the `make`
supplied options:

```
	cd $(MARIADB_TEST_DEP) && CC=${CC} CXX=${CXX} ${MAKE} mariadbclient
```
