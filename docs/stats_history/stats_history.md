## The `stats_history` database

This database contains _historical_ metrics gathered by ProxySQL with respect to its internal functioning.<br />

These metrics are used by the [Web UI][1], and by the [Firewall][2] functionality.

```sql
mysql> SHOW TABLES FROM stats_history;
+----------------------------+
| tables                     |
+----------------------------+
| history_mysql_query_digest |
| myhgm_connections          |
| myhgm_connections_day      |
| myhgm_connections_hour     |
| mysql_connections          |
| mysql_connections_day      |
| mysql_connections_hour     |
| mysql_query_cache          |
| mysql_query_cache_day      |
| mysql_query_cache_hour     |
| system_cpu                 |
| system_cpu_day             |
| system_cpu_hour            |
| system_memory              |
| system_memory_day          |
| system_memory_hour         |
+----------------------------+
16 rows in set (0.00 sec)
```

This page doesn't describe the tables related to statistics displayed by Web UI, as they are mostly for
internal use only.

### Table `history_mysql_query_digest`

The definition for table `history_mysql_query_digest` is listed below:

```sql
mysql> SHOW CREATE TABLE stats_history.history_mysql_query_digest\G
*************************** 1. row ***************************
       table: history_mysql_query_digest
Create Table: CREATE TABLE history_mysql_query_digest (
    dump_time INT,
    hostgroup INT,
    schemaname VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    client_address VARCHAR NOT NULL,
    digest VARCHAR NOT NULL,
    digest_text VARCHAR NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    sum_time INTEGER NOT NULL,
    min_time INTEGER NOT NULL,
    max_time INTEGER NOT NULL,
    sum_rows_affected INTEGER NOT NULL,
    sum_rows_sent INTEGER NOT NULL)
1 row in set (0.00 sec)
```

Table `stats_history.history_mysql_query_digest` is used to persist to disk metrics from table
`stats.stats_mysql_query_digest`.<br />

Because `stats.stats_mysql_query_digest` is an in-memory only table, a restart of `ProxySQL` will wipe all its
content.<br />

Table `stats_history.history_mysql_query_digest` solves this problem by persisting metrics to disk on-demand
or at regular intervals.<br />

Either way, the content of table `stats.mysql_query_digest` is atomically dumped into
`stats_history.history_mysql_query_digest`, and table `stats.mysql_query_digest` is reset.<br />

The two options are:

- on-demand: executing `SAVE MYSQL DIGEST TO DISK` in Admin interface
- automatically: if the admin variable `admin-stats_mysql_query_digest_to_disk` is configured to a value other
  than 0, it represents at what regular intervals (in seconds) Admin will automatically perform the action

<!-- -->

[1]: https://proxysql.com/http-web-server/
[2]: https://proxysql.com/firewall-whitelist/
