# Configuration Tables

## Introduction

ProxySQL's Admin stores configuration in tables. If you connect to Admin using [admin-admin_credentials][1]
credentials, you should be able to see a list of configuration and runtime tables like the following. The
exact list of tables may vary depending from the version in use, and if certain modules of ProxySQL are
operating.

```mysql
Admin> SHOW TABLES FROM main;
+----------------------------------------------------+
| tables                                             |
+----------------------------------------------------+
| clickhouse_users                                   |
| coredump_filters                                   |
| debug_filters                                      |
| debug_levels                                       |
| global_variables                                   |
...
| mysql_servers                                      |
| mysql_users                                        |
| pgsql_servers                                      |
| pgsql_users                                        |
| scheduler                                          |
...
+----------------------------------------------------+
```

## Key Configuration Tables

Below is a list of the core configuration tables. Protocol-specific tables are grouped in their respective sections.

| Tablename | Configures |
| :--- | :--- |
| [global_variables](#global_variables) | All ProxySQL global variables |
| [scheduler](#scheduler) | Tasks that the Scheduler can execute |
| [restapi_routes](#restapi_routes) | RESTAPI endpoints |
| [proxysql_servers](/proxysql_cluster/proxysql-cluster) | List of core nodes in ProxySQL Cluster |
| [MySQL Tables](./mysql_tables) | All MySQL-specific configuration and runtime tables |
| [PostgreSQL Tables](./postgresql_tables) | All PostgreSQL-specific configuration and runtime tables |

### global_variables

The table `global_variables` defines [Global variables][19]. This is a much simpler table, essentially a
key-value store. These are global variables used by ProxySQL and are useful in order to tweak its behaviour.
Global variables are grouped in classes based on their prefix. Currently there are 2 classes of global
variables, although more classes are in the roadmap:

- variables prefixed with `admin-` are relevant for Admin module and allow tweaking of the admin interface
  E.G. changing the admin interface (`admin-mysql_ifaces`) or admin credentials (`admin-admin_credentials`)
- variables prefixed with `mysql-` are relevant for MySQL modules.
- variables prefixed with `pgsql-` are relevant for PostgreSQL modules.

For more information about particular variables, please see the dedicated section on [global variables][19]

```mysql
Admin> SHOW CREATE TABLE global_variables\G
*************************** 1. row ***************************
       table: global_variables
Create Table: CREATE TABLE global_variables (
    variable_name VARCHAR NOT NULL PRIMARY KEY,
    variable_value VARCHAR NOT NULL)
1 row in set (0.00 sec)
```

### scheduler

Table `scheduler` defines jobs to be executed at regular intervals.

```mysql
Admin> SHOW CREATE TABLE scheduler\G
*************************** 1. row ***************************
       table: scheduler
Create Table: CREATE TABLE scheduler (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
    interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL,
    filename VARCHAR NOT NULL,
    arg1 VARCHAR,
    arg2 VARCHAR,
    arg3 VARCHAR,
    arg4 VARCHAR,
    arg5 VARCHAR,
    comment VARCHAR NOT NULL DEFAULT '')
1 row in set (0.00 sec)
```

Further details about the scheduler can be found [here][20]

### restapi_routes

Table `restapi_routes` defines endpoints that a remote client can call using a REST API endpoint using HTTP in
order to trigger the execution of a task by ProxySQL. The following is the table definition:

```sql
mysql> SHOW CREATE TABLE restapi_routes\G
*************************** 1. row ***************************
table: restapi_routes
Create Table: CREATE TABLE restapi_routes (
id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
timeout_ms INTEGER CHECK (timeout_ms>=100 AND timeout_ms<=100000000) NOT NULL,
method VARCHAR NOT NULL CHECK (UPPER(method) IN ('GET','POST')),
uri VARCHAR NOT NULL,
script VARCHAR NOT NULL,
comment VARCHAR NOT NULL DEFAULT '')
1 row in set (0,03 sec)
```

## Runtime tables

All the configuration tables have a matching `runtime_` table (e.g., `runtime_global_variables`, `runtime_mysql_servers`, etc.). These tables represent the configuration currently in use by the ProxySQL threads.

#### A note on `main` schema

Note that all the content of the in-memory tables (main database) are _lost_ when ProxySQL is restarted if
their content wasn't saved on disk database.

## Debug config

### debug_filters

The table `debug_filters` defines filters that can be used to suppress specific information from the error log
when 'debug_levels' is enabled in a ProxySQL 'DEBUG' build.

```mysql
Admin> SHOW CREATE TABLE debug_filters\G
*************************** 1. row ***************************
       table: debug_filters
Create Table: CREATE TABLE debug_filters (
    filename VARCHAR NOT NULL,
    line INT NOT NULL,
    funct VARCHAR NOT NULL,
    PRIMARY KEY (filename, line, funct) )
1 row in set (0.00 sec)
```

### debug_levels

The table `debug_levels` defines a series of verbosity levels that can be enabled for ProxySQL when compiled
in 'DEBUG' mode.

```mysql
Admin> SHOW CREATE TABLE debug_levels\G
*************************** 1. row ***************************
       table: debug_levels
Create Table: CREATE TABLE debug_levels (
    module VARCHAR NOT NULL PRIMARY KEY,
    verbosity INT NOT NULL DEFAULT 0)
1 row in set (0.00 sec)
```

## Disk database

The "disk" database has exactly the same tables as the "main" database (minus the `runtime_` tables), with the
same semantics. The only major difference is that these tables are stored on disk, instead of being stored
in-memory. Whenever ProxySQL is restarted, the in-memory "main" database will be populated starting from this
database. Note that all the content of the in-memory tables (main database) are _lost_ when ProxySQL is
restarted if their content wasn't saved on disk database.

[1]: /references/admin_variables/#admin-admin_credentials
[19]: /references/global_variables
[20]: /Features/scheduler
