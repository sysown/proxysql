# The ProxySQL configuration file

ProxySQL uses a multi-layers configuration system, specifically a [3 layers of configuration][1]. In this
specific architecture, the majority of the configuration present in the configuration file is read and parsed
only during the [initial bootstrap][2], an [initial startup][3] or [reload startup][4]. Although, a very small
set of variables are always read from the config file, if present. Details below.

**IMPORTANT**: The configuration file isn't recommended for complex configurations; the database file should
be used for that purpose. Please refer to the [following section][9] for more details.

#### Grammar

ProxySQL config file is parsed using [libconfig][5], and its grammar is described on [libconfig manual][6].
The grammar is also copied at the end of the `proxysql.cfg` distributed in `proxysql` packaged. Finally,
grammar is also copied here for reference.

```
configuration = setting-list | empty

setting-list = setting | setting-list setting

setting = name (":" | "=") value (";" | "," | empty)

value = scalar-value | array | list | group

value-list = value | value-list "," value

scalar-value = boolean | integer | integer64 | hex | hex64 | float
               | string

scalar-value-list = scalar-value | scalar-value-list "," scalar-value

array = "[" (scalar-value-list | empty) "]"

list = "(" (value-list | empty) ")"

group = "{" (setting-list | empty) "}"

empty =
```

Terminals are defined below as regular expressions:

```
boolean     ([Tt][Rr][Uu][Ee])|([Ff][Aa][Ll][Ss][Ee])
string      "([^"\]|\.)*"
name        [A-Za-z*][-A-Za-z0-9_*]*
integer     [-+]?[0-9]+
integer64   [-+]?[0-9]+L(L)?
hex     0[Xx][0-9A-Fa-f]+
hex64       0[Xx][0-9A-Fa-f]+L(L)?
float       ([-+]?([0-9]*)?.[0-9]*([eE][-+]?[0-9]+)?)|([-+]([0-9]+)(.[0-9]*)?[eE][-+]?[0-9]+)
```

## General variables

The ProxySQL configuration file has few variables that are always parsed even if a database file is present:

- **datadir** (string): It defines the path of the ProxySQL datadir, where the database file, the logs and
  other files are stored
- **restart_on_missing_heartbeats** (integer): If MySQL threads miss `restart_on_missing_heartbeats`
  heartbeats, ProxySQL will raise a `SIGABRT` signal and restart. Its default value is 10. See [watchdog][7].
- **execute_on_exit_failure** (string): If set, the ProxySQL parent process will execute the defined script
  every time ProxySQL crashes. It is recommended to use this setting to generate an alert or log the event.
  Note that ProxySQL is able to restart in a few milliseconds in case of a crash, therefore it is possible
  that a normal failure is not detected by other monitoring tools.
- **errorlog** (string): If set, ProxySQL will use the defined file as its error-log. In case such a variable
  is not passed, the error log will be located in _`datadir`/proxysql.log_
- **uuid**: Allows to specify a default UUID for the ProxySQL instance regarding [Cluster][10].
- **pidfile** (string): If _not_ set, ProxySQL will use the file defined in the `systemd` service file
  (`proxysql.service`): _`datadir`/proxysql.pid_. If set to something different, make sure to change the
  `PIDFile` variable in the service file as well.
- **web_interface_plugin** (string): This defines the full path of the Web Interface (UI) Plugin that proxysql
  will try to load to replace its built-in web interface with a more advanced one
- **sqlite3_plugin** (string): This defines the full path of the SQLite3 Plugin that proxysql will try to load
  to replace its built-in SQLite3 engine in order to add extra functionality, specifically encryption at rest
- **cluster_sync_interfaces** (boolean): False by default, it defines if ProxySQL cluster should sync the
  config variables for Admin and MySQL interfaces:
  - [admin-mysql_ifaces][12]
  - [admin-restapi_port][13]
  - [admin-telnet_admin_ifaces][14]
  - [admin-telnet_stats_ifaces][15]
  - [admin-web_port][16]
  - [admin-pgsql_ifaces][17]
  - [mysql-interfaces][18]
- **set_thread_name** (boolean): Controls if names should be set for all threads for debugging purposes.

<!-- -->

## Modules variables

Specific modules require their variables to be configured in a section called _module_\_variables. For example
`admin_variables` for variables related to the admin module, `mysql_variables` for variables related to the
MySQL module, and `pgsql_variables` for variables related to the PostgreSQL module. Within each section where
the variables are configured, the variable prefix (`mysql-` , `psql-` , `admin-`, or others) _must not_ be
specified. Admin module automatically adds the prefix relative to the section when loading the variables into
the `global_variables` table. For example:

- `admin-` prefix will be added to all variables defined in `admin_variables`
- `mysql-` prefix will be added to all variables defined in `mysql_variables`
- `pgsql-` prefix will be added to all variables defined in `pgsql_variables`

<!-- -->

Here is an example of how variables are defined in the config file (prefix **must not** be specified):

```
admin_variables=
{
    admin_credentials="admin:admin;radmin:radmin"
    mysql_ifaces="0.0.0.0:6032"
    web_enabled="true"
}

mysql_variables=
{
    threads=4
    max_connections=2048
    default_query_delay=0
    default_query_timeout=36000000
    have_compress=true
}

pgsql_variables=
{
    threads=4
    max_connections=2048
    default_query_delay=0
    default_query_timeout=36000000
    have_compress=true
}
```

When loaded into the `global_variables` table, they will have the correct `admin-` , `mysql-` , and `pgsql-`
prefix. Example:

```
Admin> SELECT * FROM global_variables WHERE
variable_name IN ('admin_admin_credentials',
  'admin-mysql_ifaces', 'admin-web_enabled')
OR
variable_name IN ('mysql-threads','mysql-max_connections',
   'mysql-default_query_delay','mysql-default_query_timeout',
   'mysql-have_compress', 'pgsql-threads');
+-----------------------------+---------------------------+
| variable_name               | variable_value            |
+-----------------------------+---------------------------+
| admin_admin_credentials     | admin:admin;radmin:radmin |
| admin-mysql_ifaces          | 0.0.0.0:6032              |
| admin-web_enabled           | true                      |
| mysql-default_query_delay   | 0                         |
| mysql-default_query_timeout | 36000000                  |
| mysql-have_compress         | true                      |
| mysql-max_connections       | 2048                      |
| mysql-threads               | 4                         |
| pgsql-threads               | 4                         |
+-----------------------------+---------------------------+
6 rows in set (0,00 sec)
```

## Configuration file vs Database file

The database file is the recommended way to supply/deploy your configuration. The configuration file is only
recommended for providing an initial/basic configuration. Once the database file has been generated by
ProxySQL, the configuration can later be completed via [Admin interface][8] or directly in the generated
`SQLite3` database file using an `SQLite3` command line client.

A configuration text file is really rudimentary an error prone, especially in case of nested configuration.
For example, several fields in `Admin` tables, like `servers_defaults` from `mysql_hostgroup_attributes`
table, are `JSON`. There is no input validation on a text file, while in the database file there is input
validation and extra constraints that can be imposed at database level.

Storing ProxySQL configuration in a variety of tables in a relational database instead of a text file offers
several significant advantages:

- Relational databases enforce a schema, ensuring that data is stored in a structured manner. This reduces the
  risk of errors and inconsistencies compared to a text file where structure is harder to enforce.
- Relational databases allow the definition of constraints (e.g., primary keys, foreign keys, unique
  constraints) that maintain data integrity and prevent invalid data from being entered.
- Each column in a relational database table has a specific data type, ensuring that only valid data is stored
  (integer, strings, JSON, etc).

In contrast, while text files are simpler and easier to set up initially, they can become difficult to manage
as complexity grows, leading to potential issues with data integrity, consistency, and parsing errors.

For all these previous reasons, the preferred way to configure and deploy ProxySQL configuration is through
the _database file_.

[1]: /documentation/configuring-proxysql/
[2]: /documentation/configuring-proxysql/#lifecycle
[3]: /documentation/configuring-proxysql/#initialstartup
[4]: /documentation/configuring-proxysql/#reloadstartup
[5]: https://hyperrealm.github.io/libconfig/
[6]: http://www.hyperrealm.com/libconfig/libconfig_manual.html#Configuration-File-Grammar
[7]: /documentation/Watchdog
[8]: https://proxysql.com/documentation/the-admin-schemas/
[9]: #configuration-file-vs-database-file
[10]: https://proxysql.com/documentation/proxysql-cluster/
[11]: https://proxysql.com/documentation/admin_variables
[12]: https://proxysql.com/documentation/global-variables/admin-variables/#admin-mysql_ifaces
[13]: https://proxysql.com/documentation/global-variables/admin-variables/#admin-restapi_port
[14]: https://proxysql.com/documentation/global-variables/admin-variables/#admin-telnet_admin_ifaces
[15]: https://proxysql.com/documentation/global-variables/admin-variables/#admin-telnet_stats_ifaces
[16]: https://proxysql.com/documentation/global-variables/admin-variables/#admin-web_port
[17]: https://proxysql.com/documentation/global-variables/admin-variables/#admin-pgsql_ifaces
[18]: https://proxysql.com/documentation/global-variables/mysql-variables/#mysql-interfaces
