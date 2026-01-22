# ProxySQL startup options

ProxySQL can be started with additional options, and it is possible to use specific flags to retrieve useful
information. The options are the following:

- `-c, --config ARG`: Start ProxySQL with passing the location of the [configuration file][1]
- `-D, --datadir ARG`: Start ProxySQL with passing the location of the data directory
- `-e, --exit-on-error`: ProxySQL restarts in the event of a crash by default. Since `v2.6.2` this restart
    procedure has an exponential backoff. Supplying this option disables this mechanism.
- `-f, --foreground`: ProxySQL will be running in the foreground, without starting the daemon (without
    forking), writing error messages to `stderr`.
- `-h, -help, --help, --usage`: Invoking any of these will display usage options
- `-M, --no-monitor`: ProxySQL will not start the Monitor Module
- `-n, --no-start`: ProxySQL will only start the Admin service
- `-r, --reuseport`: ProxySQL will use `SO_REUSEPORT`
- `-S, --admin-socket ARG`: Start ProxySQL with passing the location of the Administration Unix Socket
- `-U, --uuid ARG`: Start ProxySQL with the passing of the specific UUID
- `-V, --version`: Displays the version of ProxySQL
- `--clickhouse-server`: Enable [Clickhouse Server][2]
- `--idle-threads`: Create [auxiliary threads][3] to handle idle connections
- `--initial`: Rename/empty the database file
- `--no-version-check`: Do not check for the latest version of ProxySQL
- `--reload`: Merge the [configuration file][1] into the database file
- `--sqlite3-server`: Enable [SQLite3 Server][3]

[1]: /documentation/configuration-file/
[2]: /documentation/clickhouse-configuration/
[3]: /documentation/proxysql-threads/
