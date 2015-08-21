Configuration system
====================

ProxySQL has a simple to use configuration system suited to serve the following needs:
* allow easy automated updates to the configuration (this is because some ProxySQL users use it in larger setups with automated provisioning). There is a MySQL-compatible admin interface for this purpose
* allow as many configuration items as possible to be modified
at runtime, without restarting the daemon
* allow easy rollbacks of wrong configurations

The 3 layers of the configuration system are described in the
picture below:

```
+-------------------------+
|         RUNTIME         |
+-------------------------+
       /|\          |
        |           |
        |           |
        |          \|/
+-------------------------+
|         MEMORY          |
+-------------------------+ _
       /|\   |             |\
        |    |               \
        |    |                \
        |   \|/                \
+-------------------------+  +-------------------------+
|          DISK           |  |       CONFIG FILE       |
+-------------------------+  +-------------------------+

```

__RUNTIME__ represents the in-memory data structures of ProxySQL used by the threads that are handling the requests. These contains the values of the global variables used, the list of backend servers grouped into hostgroups or the list of MySQL users that can connect to the proxy. Note that operators can never modify the contents of the __RUNTIME__ configuration section directly. They always have to go through the bottom layers.

__MEMORY__ represents an in-memory SQLite3 database which is exposed to the outside via a MySQL-compatible interface. Users can connect with a MySQL client to this interface and query different tables and databases. The configuration tables
available through this interface are:
* mysql_servers -- the list of backend servers
* mysql_users -- the list of users and their credentials which can connect to ProxySQL. Note that ProxySQL will use these credentials to connect to the backend servers as well (TODO: check)
* mysql_query_rules -- the list of rules for routing traffic to the different backend servers. These rules can also cause a rewrite of the query, or caching of the result
* global_variables -- the list of global variables used throughout the proxy that can be tweaked at runtime. Examples of global variables:
```
mysql> select * from global_variables limit 3;
+----------------------------------+----------------+
| variable_name                    | variable_value |
+----------------------------------+----------------+
| mysql-connect_retries_on_failure | 5              |
| mysql-connect_retries_delay      | 1              |
| mysql-connect_timeout_server_max | 10000          |
+----------------------------------+----------------+
```
* mysql_collations -- the list of MySQL collations available for the proxy to work with. See [this](http://stackoverflow.com/questions/341273/what-does-character-set-and-collation-mean-exactly) StackOverflow answer for the difference between a collation and a charset.
* [only available in debug builds] debug_levels -- the list of types of debug statements that ProxySQL emits together with their verbosity levels. This allows us to easily configure at runtime what kind of statements we have in the log in order to debug different problems

__DISK__ and __CONFIG FILE__

# Initial startup (--initial flag) for ProxySQL

# Locations of config files