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
