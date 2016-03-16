How to operate ProxySQL
=======================

First of all, ProxySQL is a daemon ran by an angel process. The angel process monitors the daemon and restarts it when it has crashed, in order to minimize downtime. The daemon accepts incoming traffic from MySQL clients and forwards it to backend MySQL servers.

The proxy is designed to run for as long as possible without needing to be restarted. Most configurations can be done at runtime, through a configuration system that responds to SQL-like queries (["admin interface"](https://github.com/sysown/proxysql/blob/master/doc/admin_tables.md)). Runtime parameters, server grouping and traffic-related settings can all be changed at runtime.

Parameters
----------

```bash
$ ./proxysql --help
High Performance Advanced Proxy for MySQL

USAGE: proxysql [OPTIONS]

OPTIONS:

-c, --config ARG             Configuraton file
-D, --datadir ARG            Datadir
-e, --exit-on-error          Do not restart ProxySQL if crashes
-f, --foreground             Run in foreground
-h, -help, --help, --usage   Display usage instructions.
-m, --custom-memory          Enable custom memory allocator
-n, --no-start               Starts only the admin service
-S, --admin-socket ARG       Administration Unix Socket
-V, --version                Print version
--initial                    Rename/empty database file
--reload                     Merge config file into database file


ProxySQL rev. 20150902 -- Tue Sep 22 12:46:37 2015
Copyright (C) 2013-2015 René Cannaò
This program is free and without warranty
```

Let us explain in more depth each individual option.

* `-c, --config ARG`. By default, the proxy looks for the config file in the following locations (in this exact order):
 * `proxysql.cnf`, in the directory of the proxysql binary
 * `proxysql.cfg`, in the directory of the proxysql binary
 * `/etc/proxysql.cnf`
 * `/etc/proxysql.cfg`
 This setting allows you to override the configuration file, and specify a custom location. For the format of the configuration file and the options available within it, please refer to the relevant documentation (TODO: link)
* `-D, --datadir ARG`. The data directory is where the proxy keeps its running files:
 * the SQLite database which stores the runtime configuration for the proxy
 * the pidfile
 * the log files
* `-e, --exit-on-error`. Instruct the angel process to not restart the proxy when it crashes
* `-f, --foreground`. Run the daemon process in the foreground. Especially useful for debugging or for running the proxy under a different fault tolerance setup (such as `upstart` and `monit`).
* `-h, -help, --help, --usage`. Display the help message
* `-m, --custom-memory`. Use the stack-based custom memory allocator for ProxySQL.
* `-n, --no-start`. Only start the admin interface, which helps us configure the daemon. This will not accept any traffic until we start the daemon from the admin interface.
* `-S, --admin-socket ARG`. Currently unused.
* `-V, --version`. Print the current version of ProxySQL
* `--initial`. Reset the admin database with the content from the configuration file. Refer to the [configuration system documentation](https://github.com/sysown/proxysql/blob/master/doc/configuration_system.md) for more information.
* `--reload`. Merge the configuration from the config file with the current runtime database. Refer to the [configuration system documentation](https://github.com/sysown/proxysql/blob/master/doc/configuration_system.md) for more information.

Sending alerts for critical events
----------------------------------
ProxySQL supports integration with [OpsGenie](www.opsgenie.com) and [pagerduty](www.pagerduty.com) so it can send alerts when critical events happen.

So far ProxySQL sends alerts for the following events:
* when a backend server gets shunned

###Configure integration with OpsGenie
1. Create an OpsGenie account.
2. Create an OpsGenie [API integration](https://app.opsgenie.com/integration).
3. Add a recipient or team to the newly created integration to have someone notified when ProxySQL will create an alert. If you don't configure a recipient or team then the alert will be created but nobody will get notified.
4. Copy the API key and set the `admin-ops_genie_api_key` variable to it using ProxySQL's admin interface. See [Configuring ProxySQL](doc/configuration.md) on how to do that.
5. Set the `admin-enable_ops_genie_integration` variable to `true`.
6. Aditionally you can configure a global rate limit for the alerts by setting the value of `admin-min_time_between_alerts_sec` variable.

###Configure integration with pagerduty
1. Create an pagerduty account.
2. Follow the signup wizard to create an API Service or create a new one at <https://vitaminsoftware.pagerduty.com/services>.
3. Go to `Configuration`->`Services` and select your service. From the `Settings` tab copy the `Integration key` and set the `admin-pager_duty_service_key` variable to it using ProxySQL's admin interface.
5. Set the `admin-enable_pager_duty_integration` variable to `true`.
6. Aditionally you can configure a global rate limit for the alerts by setting the value of `admin-min_time_between_alerts_sec` variable.
