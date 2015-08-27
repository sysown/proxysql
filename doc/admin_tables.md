Admin tables
============

Connecting to the ProxySQL admin interface, we see that there are a few databases available:

```bash
mysql> show databases;
+-----+---------+------------------+
| seq | name    | file             |
+-----+---------+------------------+
| 0   | main    |                  |
| 2   | disk    | /tmp/proxysql.db |
| 3   | stats   |                  |
| 4   | monitor |                  |
| 5   | myhgm   |                  |
+-----+---------+------------------+
5 rows in set (0.00 sec)

```

The purposes of these databases are as follows:
* main: the in-memory configuration database. Using this database, it's easy to query and update the configuration of ProxySQL in an automated manner. Using the LOAD MYSQL USERS FROM MEMORY and similar commands, the configuration stored in here can be propagated to the in-memory data structures used by ProxySQL at runtime.
* disk: the disk-based mirror of "main". Across restarts, "main" is not persisted and is loaded either from the "disk" database or from the config file, based on startup flags and the existence of not of an on-disk database.
* stats: contains runtime metrics collected from the internal functioning of the proxy. Example metrics include the number of times each query rule was matched, the currently running queries, etc.
* monitor: contains monitoring metrics related to the backend servers to which ProxySQL connects. Example metrics include the minimal and maximal time for connecting to a backend server or for pinging it.
* myhgm: only enabled in debug builds

# main database

Here are the tables from the "main" database:

```bash
mysql> show tables from main;
+-------------------+
| tables            |
+-------------------+
| mysql_servers     |
| mysql_users       |
| mysql_query_rules |
| global_variables  |
| mysql_collations  |
| debug_levels      |
+-------------------+
6 rows in set (0.01 sec)
```

## `mysql_servers`

Here is the statement used to create the `mysql_servers` table:

```sql
CREATE TABLE mysql_servers (
    hostgroup_id INT NOT NULL DEFAULT 0,
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    status VARCHAR CHECK (status IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE',
    weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1,
    compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0,
    max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000,
    PRIMARY KEY (hostgroup_id, hostname, port) )
```

The fields have the following semantics:
* hostgroup_id: the hostgroup in which this mysqld instance is included. Notice that the same instance can be part as more than one hostgroup
* hostname, port: the TCP endpoint at which the mysqld instance can be contacted
* status: 
  * ONLINE - backend server is fully operational
  * SHUNNED - backend sever is temporarily taken out of use because of too many connection errors in a time that was too short
  * OFFLINE_SOFT - when a server is put into OFFLINE_SOFT mode, the existing connections are kept, while new incoming connections aren't accepted anymore
  * OFFLINE_HARD - when a server is put into OFFLINE_HARD mode, the existing connections are dropped, while new incoming connections aren't accepted either. This is equivalent to deleting the server from a hostgroup, or temporarily taking it out of the hostgroup for maintenance work
* weight - the bigger the weight of a server relative to other weights, the higher the probability of the server to be chosen from a hostgroup
* compression - not supported yet
* max_connections - the maximal number of connections ProxySQL will open to this backend server. Even though this server will have the highest weight, no new connections will be opened to it once this limit is hit.

## `mysql_users`

Here is the statement used to create the `mysql_users` table:

```sql
CREATE TABLE mysql_users (
    username VARCHAR NOT NULL,
    password VARCHAR,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
    use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0,
    default_hostgroup INT NOT NULL DEFAULT 0,
    default_schema VARCHAR,
    schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0,
    transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0,
    fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0,
    backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1,
    frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1,
    max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000,
    PRIMARY KEY (username, backend),
    UNIQUE (username, frontend)
)
```

The fields have the following semantics:
* username, password - credentials for connecting to the mysqld or ProxySQL instance
* active - the users with active = 0 will be tracked in the database, but will be never loaded in the in-memory data structures
* default_hostgroup - the hostgroup for which this credential will be used (for backend credentials)
* default_schema - the schema to which the connection should change by default
* schema_locked - not supported yet (TODO: check)
* transaction_persistent - if this is set for the user with which the MySQL client is connecting to ProxySQL (thus a "frontend" user - see below), transactions started within a hostgroup will remain within that hostgroup,regardless of any other rules
* fast_forward - bypass the query processing layer (rewriting, caching) and pass through the query directly as is to the backend server. Users flagged as such 
* frontend - if set to 1, this (username, password) pair is used for authenticating to the ProxySQL instance
* backend - if set to 1, this (username, password) pair is used for authenticating to the mysqld servers in the default_hostgroup hostgroup

## `mysql_query_rules`

Here is the statement used to create the `mysql_users` table:

```sql
CREATE TABLE mysql_query_rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0,
    username VARCHAR,
    schemaname VARCHAR,
    flagIN INT NOT NULL DEFAULT 0,
    match_pattern VARCHAR,
    negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0,
    flagOUT INT,
    replace_pattern VARCHAR,
    destination_hostgroup INT DEFAULT NULL,
    cache_ttl INT CHECK(cache_ttl > 0),
    reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL,
    timeout INT UNSIGNED,
    delay INT UNSIGNED,
    apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0
)
```

The fields have the following semantics:
* rule_id - the unique id of the rule
* active - only rules with active=1 will be considered by the query processing module
* username, schemaname - filtering criteria for the rules. If these are non-NULL, a query will match only if the connection is made with the correct username and/or schemaname.
* flagIN, flagOUT, apply - these allow us to create "chains of rules" that get applied one after the other. An internal flag value is set to 0, and only rules with flagIN=0 are considered at the beginning. After the first rule is matched, the internal value of the flag is set to the flagOUT of the rule, and rules having flagIN equal to the internal value of the flag are searched again. This happens until there are no more matching rules, or apply is set to 1 (which means this is the last rule to be applied)
* match_pattern - regular expression that matches the query text. The dialect of regular expressions used is that of re2 - https://github.com/google/re2
* negate_match_pattern - if this is set to 1, only queries not matching the query text will be considered as a match. This acts as a NOT operator in front of the regular expression matching against match_pattern.
* replace_pattern - this is the pattern with which to replace the matched pattern. It's done using RE2::Replace, so it's worth taking a look at the online documentation for that: https://github.com/google/re2/blob/master/re2/re2.h#L378. Note that this is optional, and when this is missing, the query processor will only cache/route this query without rewriting.
* destination_hostgroup - route matched queries to this hostgroup. This happens unless there is a started transaction, and the logged in user has the transaction_persistent flag set to 1 (see `mysql_users` table).
* cache_ttl - the number of seconds for which to cache the result of the query 
* reconnect - feature not used
* timeout - the maximal timeout with which the matched or rewritten query should be executed.
* delay - delay the execution of the query. This is essentially a throttling mechanism, together with the `mysql-default_query_delay` global variable (see below).

More details can be found in the dedicated ![query rules](http://todo) section.

## `global_variables`

Here is the statement used to create the `global_variables` table:

```sql
CREATE TABLE global_variables (
    variable_name VARCHAR NOT NULL PRIMARY KEY,
    variable_value VARCHAR NOT NULL
)
```

This is a much simpler table, essentially a key-value store. These are global variables used by ProxySQL and are useful in order to tweak its behaviour.

There are 2 classes of global variables:
* those whose name begins with `mysql-`. They will tweak the behaviour of MySQL-related features. Examples:
    * `mysql-shun_on_failures` - number of connect failures allowed per second before the backend server is taken out of use temporarily
    * `mysql-max_connections` - maximal number of connections that the proxy
* those whose name begins with `admin-`. They will tweak the behaviour of the admin interface. Examples:
    * `admin-admin_credentials` - double-colon separated username and password for accessing the admin interface with read-write rights
    * `admin-mysql_ifaces` - TCP hostname and port on which to listen for incoming connections for the admin interface

For more information about particular variables, please see the dedicated section on ![global variables][http://todo]

# `mysql_collations`

```CREATE TABLE mysql_collations (
    Id INTEGER NOT NULL PRIMARY KEY,
    Collation VARCHAR NOT NULL,
    Charset VARCHAR NOT NULL,
    `Default` VARCHAR NOT NULL
)```

The available (charset, collation) pairs supported by ProxySQL. In principle, ProxySQL will validate that incoming connections have a supported charset, and will make sure that the pooled backend connections are switched to the correct charset before using them.