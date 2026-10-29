### Replication through ProxySQL tests

Special requirements:
- `sysbench` installed
- Docker Compose version 1.28.0 or later (in order to use `profiles` feature)
- `gettext` package (in order to use `envsubst` command)
- running `docker-hoster` container (see `infra_docker_hoster` directory)


### Launching all ProxySQL replication tests

For launching all proxysql replication tests:

```
./exec_all_repl_tests.sh
```

This executes all proxysql replication test options with mysql 5.6/5.7/8.0, ssl/no-ssl and debezium. After finishing check the last few rows in the output after "TOTAL SUMMARY" and check exit code:

```
echo $?
```

for either failure or success.

#### Options

Test can be executed with the following options:

`no_shutdown`:

executes all proxysql replication tests and finishes without shutting down infra.

Currently all tests run includes the following:
- mysql 5.6 no-ssl
- mysql 5.7 no-ssl with debezium
- mysql 5.7 ssl with debezium
- mysql 8.0 no-ssl
- mysql 8.0 ssl

### Launching single ProxySQL Replication test

For launching single proxysql replication test:

```
./exec_repl_test.sh
```
This executes proxysql replication test by default with mysql 5.7, no-ssl, no debezium without shutting down infra. After finishing check the last few rows in the output after "TEST SUMMARY" and check exit code:

```
echo $?
```

for either failure or success.

#### Options

Single test can be executed with the following options:

- mysql version option, $1: `5.6` or `5.7` or `8.0`
- SSL option, $2: `ssl` or `no-ssl`
- Debezium option, $3: `debezium`

Example:

```
./exec_repl_test.sh 8.0 no-ssl debezium
```
