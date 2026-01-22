## The `disk` database

The `disk` schema persists the configuration to disk.

The persistent configuration will be available on next restarts.

## List all tables

```mysql
Admin> SHOW TABLES FROM disk;
+------------------------------------+
| tables                             |
+------------------------------------+
| global_variables                   |
| mysql_collations                   |
| mysql_galera_hostgroups            |
| mysql_group_replication_hostgroups |
| mysql_query_rules                  |
| mysql_query_rules_fast_routing     |
| mysql_replication_hostgroups       |
| mysql_servers                      |
| mysql_servers_v144                 |
| mysql_users                        |
| mysql_users_v140                   |
| proxysql_servers                   |
| scheduler                          |
+------------------------------------+
13 rows in set (0.00 sec)
```

These tables are the persistent equivalent of configuration of [in-memory tables][1].<br />

Configuration on in-memory tables is lost across restarts, while the content of configuration on disk tables
is persistent.

[1]: https://proxysql.com/documentation/main-runtime/
