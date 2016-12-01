# How to run test

Tests are written in python 2.7, using nosetests. 
Tests are running against a scenario.
Scenario is a architecture deployed with docker-composite.

To run a test, before we must run an scenario

```bash
$ python scenarios.py start
Creating tmp0y5ir1proxysqltests_backend1hostgroup0_1...
Creating tmp0y5ir1proxysqltests_proxysql_1...
Trying again to connect to 127.0.0.1:13306 (retries=1)
Trying again to connect to 127.0.0.1:13306 (retries=2)
[ stuff removed ]
Scenario started successfully at path /tmp/tmp0y5iR1-proxysql-tests
$
```

After the scenario started, we can for example admin_table_test.

```bash
$ nosetests --nocapture admin_tables_test.py
...
----------------------------------------------------------------------
Ran 3 tests in 5.785s

OK
$ 
```

After the tests, we can stop scenaro i.e. all docker containers that make a scenario.

```bash
$ python scenarios.py stop
Stopping tmp0y5ir1proxysqltests_proxysql_1... done
Stopping tmp0y5ir1proxysqltests_backend1hostgroup0_1... done
Scenario stopped successfully
$
```
## Ho to run all test together

TODO
