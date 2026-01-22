# ProxySQL's Configuration CLI

ProxySQL admin interface is an interface that uses the MySQL protocol, making it very easy to be configured by
any client able to send commands through such an interface. ProxySQL parses the queries sent through this
interface for any command specific to ProxySQL, and if appropriate it sends them to the embedded SQLite3
engine to run the queries. Please note that SQL syntax used by SQLite3 and MySQL differs, therefore not all
commands that work on MySQL will work on SQLite3. For example, although the USE command is accepted by the
admin interface, it doesn't change the default schema as this feature is not available in SQLite3. When
connecting to the ProxySQL admin interface, we can see that there are a few databases available. ProxySQL
converts `SHOW DATABASES` command into the equivalent command for SQLite3.

```bash
mysql> SHOW DATABASES;
+-----+------------------+-------------------------------------+
| seq | name             | file                                |
+-----+------------------+-------------------------------------+
| 0   | main             |                                     |
| 2   | disk             | /var/lib/proxysql/proxysql.db       |
| 3   | stats            |                                     |
| 4   | monitor          |                                     |
| 5   | stats_history    | /var/lib/proxysql/proxysql_stats.db |
+-----+------------------+-------------------------------------+
5 rows in set (0.00 sec)
```

The purposes of these schemas are:

- main: The in-memory configuration database. Using this database, it's easy to query and update ProxySQL's
  configuration in an automated manner. With `LOAD MYSQL USERS FROM MEMORY` and similar commands the
  configuration can be propagated into the [different layers][1]. In this example command, the contents
  from the `main.mysql_users` table will be propagated to the in-memory data structures used by ProxySQL at
  runtime for storing using information. The schema also holds several 'runtime_*' tables, these tables
  are populated with the current runtime configuration ProxySQL is using.
- disk: The disk-based mirror of "main", without the "runtime_*" information tables. Across restarts, "main"
  is not persisted and is loaded either from the "disk" database or from the config file, based on startup
  flags and the existence or not of an on-disk database.
- stats: Contains runtime metrics collected from the internal functioning of the proxy. Example metrics
  include the number of times each query rule was matched, the currently running queries, etc.
- monitor: Contains monitoring metrics related to the backend servers to which ProxySQL connects. Example
  metrics include the minimal and maximal time for connecting to a backend server or for pinging it.

Debug only schemas, for development and testing purposes:

- myhgm: Only enabled in debug builds.
- monitor_internal: Only enabled in debug builds.

<!-- -->

Also, the access to the admin database is done using two types of users, with these default credentials:

- User: admin, Password: admin -- With read-write access to all the tables.
- User: stats, Password: stats -- With read-only access to statistics tables. Used for metrics pulling
  without exposing too much of the database.

Remember that for security reasons, the default admin user can only connect locally, regardless of its password.

<!-- -->

The above credentials are configurable through the variables `admin-admin_credentials` and
`admin-stats_credentials`.

## Admin CLI Commands

The `Admin` interface offers access to the internal configuration schemas, stats, and it also offers multiple
administration commands to interact with different features:

- `PROXYSQL COREDUMP`: See [Coredumper Support][2].
- `PROXYSQL COMPRESSEDCOREDUMP`: See [Coredumper Support][2].
- `PROXYSQL FLUSH CONFIGDB`: Reopen the `configdb` file. Useful when deploying new config to ProxySQL via new
  `configdb` files. When doing this, it's very important that the new `configdb` file is a valid one.
  Supplying an invalid `configdb` file will cause **undefined behavior**.
- `PROXYSQL FLUSH QUERY CACHE`: Clears the current `QUERY CACHE`. See [Query Cache][3].
- `PROXYSQL FLUSH LOGS`: Perform a log rotation. See [Error Log][4].
- `PROXYSQL FLUSH MYSQL CLIENT HOSTS`: Clears the [Client Error Limit][5] host cache.

Commands dedicated to change ProxySQL [operating mode][6]:

- `PROXYSQL STOP`
- `PROXYSQL START`
- `PROXYSQL RESTART`

Commands for shutdown:

- `PROXYSQL SHUTDOWN`
- `PROXYSQL KILL`

When compiled with `Jemalloc` support:

- `PROXYSQL MEMPROFILE START`: Activate `Jemalloc` memory profiler.
- `PROXYSQL MEMPROFILE STOP`: Disable `Jemalloc` memory profiler.

In DEBUG builds:

- `PROXYSQL GCOV DUMP`: Dump current content of `gcda` and `gcno` profile files.
- `PROXYSQL GCOV RESET`: Reset the code coverage profiles.

### Operation Modes

Via the following commands, we can select between two operation modes regarding ProxySQL modules:

A) All modules running.
B) Only admin module running.

This selection is performed via commands:

- `PROXYSQL START`: Change operating mode to A.
- `PROXYSQL STOP`: Re-launch the main process, changing status to B.
- `PROXYSQL RESTART`: Re-launch the main process, returning at the same status. This is useful in case of
   major configuration changes that otherwise would require a process restart.

The transition performed from these two modes is not `smooth` from a client perspective. More details on
[graceful-shutdowns][7].

### Shutdown/Restart Operations

- `PROXYSQL SHUTDOWN`: Exit the process, gracefully. Since version `2.1`, this command behaves like `PROXYSQL
   KILL`. The motivation for this change was to simplify the exit process, thus avoiding potential errors that
   could lead to a non-clean exit. It's important to remember that non-zero exit codes could lead to undesired
   process restarts when started as a service.
- `PROXYSQL KILL`: Exit the process immediately with exit code `0`.

Extra commands:

- `PROXYSQL SHUTDOWN SLOW`: Only for testing purposes. Perform a graceful shutdown. All modules are shutdown
   and then the process exited.  This command was introduced in `v2.1`, as a rename for `PROXYSQL SHUTDOWN`.

#### Graceful shutdowns

ProxySQL has already 3 commands useful to stop and start without restarting the process:

- `PROXYSQL STOP`
- `PROXYSQL START`
- `PROXYSQL RESTART`

These commands are less disruptive than a `KILL` or `SHUTDOWN`, as `PROXYSQL STOP` brings down all ProxySQL
with the exception of the Admin module. Although, they are not graceful from a client perspective, since when
`PROXYSQL STOP` is received, client connections are terminated immediately. This presents a problem for the
scenarios in which you wish to stop ProxySQL, but you do not wish to disturb traffic in any way. For example:

- _Version upgrade_: When performing a live version upgrade.
- _Multi-layer ProxySQL_: In a multilayer scenario in which several ProxySQL instances are chained together, you
  may want to shutdown gracefully one of the instances.

These cases can be handled by the following commands:

- `PROXYSQL PAUSE`
- `PROXYSQL RESUME`

`PROXYSQL PAUSE` performs the following actions:

- The listeners are immediately shut down; no new connections are allowed.
- `mysql-wait_timeout` is set to 0; any **idle connection**, not in a transaction, is immediately closed.
- Connections with active transactions are still processed until they commit/rollback or
  `mysql-max_transaction_time` is reached.

`PROXYSQL RESUME` performs reverse `PROXYSQL PAUSE` actions:

- Resume the previous value of mysql-wait_timeout.
- Start the listeners.

For a more detailed explanation on how to use the previously described ProxySQL features, for gracefully
shutting down one running instance, please refer to [this blog entry][8].

[1]: https://proxysql.com/documentation/configuring-proxysql
[2]: https://proxysql.com/documentation/coredumper-support
[3]: https://proxysql.com/documentation/query-cache
[4]: https://proxysql.com/documentation/error-log
[5]: https://proxysql.com/documentation/client-error-limit
[6]: #operation-modes
[7]: #graceful-shutdowns
[8]: https://proxysql.com/blog/how-to-run-multiple-proxysql-instances/
