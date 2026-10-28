# MySQL and PostgreSQL startup controls

ProxySQL starts both protocol stacks by default. Six startup permissions let an
operator omit worker threads, Admin listeners, or monitor threads independently:

| Command-line option | Top-level configuration entry | Controls |
| --- | --- | --- |
| `--mysql-workers` | `mysql-workers` | MySQL worker and idle threads and their listeners |
| `--pgsql-workers` | `pgsql-workers` | PostgreSQL worker and idle threads and their listeners |
| `--mysql-admin` | `mysql-admin` | Admin listeners speaking the MySQL protocol |
| `--pgsql-admin` | `pgsql-admin` | Admin listeners speaking the PostgreSQL protocol |
| `--mysql-monitor` | `mysql-monitor` | MySQL monitor scheduler, workers, and DNS-cache thread |
| `--pgsql-monitor` | `pgsql-monitor` | PostgreSQL monitor scheduler and DNS-cache thread |

All permissions default to `true`. CLI values accept `true`, `false`, `1`, or `0`,
using either `--mysql-workers false` or `--mysql-workers=false`. Configuration
entries are libconfig booleans at the top level, outside `mysql_variables`,
`pgsql_variables`, and `admin_variables`:

```ini
mysql-workers=true
mysql-admin=true
mysql-monitor=true
pgsql-workers=false
pgsql-admin=false
pgsql-monitor=false
```

Explicit CLI component values override the configuration file and the broader
`--no-monitor` (`-M`) switch. Repeated component options use the last value, and every occurrence
must supply a valid value. For example, `-M --pgsql-monitor true` permits only
the PostgreSQL monitor. Invalid values are startup errors.

These permissions are fixed for the process lifetime. `PROXYSQL START`,
`PROXYSQL RESTART`, and STOP/START cycles retain them. Set a different startup
permission by launching the process again with the desired arguments/config.

Authentication, hostgroup managers, monitor data objects, and query-processor
configuration remain shared infrastructure; disabling worker/monitor threads
is not unloading every object related to that protocol. Workers disabled at
startup create no worker or idle threads. Their `MySQL_Thread_Workers` or
`PgSQL_Thread_Workers` status count is zero. The `mysql-threads` and `pgsql-threads`
configuration values remain positive in `runtime_global_variables`, so SAVE to
memory/disk and later relaunch with workers enabled preserve the chosen counts.
Setting a thread variable cannot enable a component prohibited at startup;
positive thread-count validation applies regardless of startup permission.

Disabling an Admin protocol omits its listeners; the other Admin protocol can
still configure both backend protocols. Disabling both Admin protocols removes
SQL Admin access. With `--no-start`, leave at least one Admin protocol enabled
if you need to issue `PROXYSQL START`.

Monitor startup permission is separate from the persisted runtime variables
`mysql-monitor_enabled` and `pgsql-monitor_enabled`. A permission of `true`
allows the monitor module to start, but does not replace a configured runtime
`false`; a permission of `false` prevents the monitor threads from starting even
if the runtime variable is `true`. Runtime `monitor_enabled` continues to control
checks only within a monitor permitted at startup.

`PROXYSQL STOP` acknowledges the stop request and disconnects existing Admin
clients while rebuilding Admin in `--no-start` mode. Reconnect after the reload
before issuing further configuration commands or `PROXYSQL START`. Runtime
query-rule tables are empty when their processors are absent; configuration
can still be edited, and LOAD SERVERS remains available. Normal runtime
statistics refresh resumes after START. Explicit SAVE QUERY RULES/FIREWALL from
unavailable runtime state returns an error and preserves configuration. STOP
drains its reply before initiating shutdown, allowing up to one second for a
slow reader.

## Regression probes

The following launch private daemons with temporary datadirs and loopback ports;
they require Linux, a DEBUG daemon, Python 3, and the `mysql` and `psql` command-line
clients, but no backend servers:

```bash
PROXYSQL31=1 make debug -j4
python3 test/infra/control/test_module_lifecycle.py src/proxysql
python3 test/infra/control/test_module_startup.py src/proxysql
```

The probes are also registered as `module_lifecycle_unit-t` and
`module_startup_unit-t` in the CI unit/coverage suite. Standalone wrappers emit
TAP skips on non-Linux systems or when Python/SQL clients are unavailable. The
coverage runner installs these prerequisites and executes both probes; genuine
probe failures still fail the test.

Prior work: PRs #4960, #5217, #5222; issues #4951, #5186, #5218.
