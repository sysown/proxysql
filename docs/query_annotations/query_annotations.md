ProxySQL supports query annotations to modify the normal behavior of queries. Through this, queries can be
tuned individually. Query annotations are supplied inside a comment leading to the query which behavior wants
to be modified, e.g:

```
SELECT /*+ ;cache_ttl=0;query_timeout=100 */ c FROM sbtest3 WHERE id=2
```

**Please note that:**

-   query annotations overwrite global variable settings for the specific query (`mysql-default_query_timeout`
    value, for example)
-   ProxySQL applies query annotations before query rules are evaluated, therefore special settings in the
    `mysql_query_rules` table can potentially overwrite the annotations.

## Currently supported query annotations

-   **cache_ttl**: Specifies how long the query will be cached, in milliseconds.
-   **query_delay**: Specifies a time that the query will be delayed before being processed, in milliseconds.
-   **query_retries**: Number of times the query will be retried before returning a failure to the client.
-   **query_timeout**: Specifies the maximum execution time of the query, in milliseconds.
-   **hostgroup**: Specifies the destination hostgroup of query.
-   **mirror**: Activates mirroring for the query, and sets the `mirror_hostgroup` for it.
-   **max_lag_ms**: Sets the maximum replication lag of the aurora replica when choosing a connection.
-   **min_epoch_ms**: Specifies the `max_lag_ms` but in terms of an absolute min epoch time, instead of
    relative value.
-   **min_gtid**: Specifies the minimun GTID that the target server needs to have to be selected for this
    query.
-   **create_new_connection**: Creates a new backend connection instead of reusing a current one from the
    connection pool.
