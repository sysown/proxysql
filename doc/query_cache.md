# Query Cache

## Preface

Historically, there are 2 ways of using caching in a MySQL environment:

 - enable MySQL Query Cache : embedded in MySQL server itself, no external dependencies. Although it is a bottleneck for any write intensive workload because cache entries are invalidated when the relevant table receives a write.
 - use external caching : allows a lot of flexibility, but also requires a lot of application changes and logic, because the application must connect to both the database and the caching system, and be responsible for keeping it updated

Although external caching is very efficient, it requires development efforts and DBAs have no control over data flow.

## Caching on the wire

ProxySQL introduced a new paradigma to query caching. According to configuration (details below) resultsets are cached on the wire, while queries are executed and the resultset is returned to the application.
If the application will re-executed the same query, the resultset will be returned by the embedded Query Cache.

It is a quite common scenarios to identify database load caused by not-optimal SELECT statements that generate a resultset that should be cached for few seconds.
To implement a code change can be a long process (developers should write new code, build it, testing in staging, then deploy on production), and this is often not a suitable option during an emergency.
As the configuration of the database proxy layer (ProxySQL in this case) falls under the responsibility of DBAs, to enable caching DBAs won't require developers to make changes to the application.  
Therefore this is a feature that empowers the DBAs.


# Define traffic that needs to be cached

To define what traffic need to be cached we need to define [query rules](./admin_tables.md#mysql_query_rules) that 
match incoming traffic, and define a cache_ttl for it.

As pointed in the [documentation](./admin_tables.md#mysql_query_rules), there are many ways to define matches for incoming traffic.
All we need to do to cache resultset is to define matching criteria and timeout.

### Caching example

The best way to illustrate how to configure caching is with an example.  
Assume we run sysbench against proxysql, with a very small table:
```sh
$ sysbench --num-threads=16 --max-requests=0 --max-time=60 --test=oltp \
--mysql-user=msandbox --mysql-password=msandbox --mysql-db=sbtest --mysql-host=127.0.0.1 --mysql-port=6033 \
--oltp-table-size=10000 --oltp-read-only=on --db-ps-mode=disable --oltp-skip-trx=on \
--oltp-point-selects=100 --oltp-simple-ranges=1 --oltp-sum-ranges=1 --oltp-order-ranges=1 \
--oltp-distinct-ranges=1 run
```
And result is:
```sh
    read/write requests:                 380952 (6341.71 per sec.)
```

In ProxySQL we can see the follow results:
```sql
Admin> SELECT count_star,sum_time,hostgroup,digest,digest_text FROM stats_mysql_query_digest_reset ORDER BY sum_time DESC;
+------------+-----------+-----------+--------------------+-------------------------------------------------------------------+
| count_star | sum_time  | hostgroup | digest             | digest_text                                                       |
+------------+-----------+-----------+--------------------+-------------------------------------------------------------------+
| 366300     | 508306254 | 1         | 0xE8930CB2CC9E68D7 | SELECT c from sbtest where id=?                                   |
| 3663       | 6932505   | 1         | 0xB749413737FAF581 | SELECT DISTINCT c from sbtest where id between ? and ? order by c |
| 3663       | 6607248   | 1         | 0x78881FD58E5437B2 | SELECT c from sbtest where id between ? and ? order by c          |
| 3663       | 5534740   | 1         | 0x547C0EAF9BC36E91 | SELECT SUM(K) from sbtest where id between ? and ?                |
| 3663       | 5506153   | 1         | 0xDC1EE02F8CD8B09B | SELECT c from sbtest where id between ? and ?                     |
| 1          | 2372      | 1         | 0xD575B97BB01C8428 | SHOW TABLE STATUS LIKE ?                                          |
+------------+-----------+-----------+--------------------+-------------------------------------------------------------------+
6 rows in set (0.00 sec)
```

With no doubt, most of the execution time comes from a single type of `SELECT`, executed many time.
Let's cache it creating a matching rule. In this example we will use `digest` as a matching criteria, and a `cache_ttl` of 2000ms.

```sql
Admin> INSERT INTO mysql_query_rules (rule_id,active,digest,cache_ttl,apply)
VALUES (5,1,'0xE8930CB2CC9E68D7',2000,1);
Query OK, 1 row affected (0.00 sec)

Admin> LOAD MYSQL QUERY RULES TO RUNTIME;SAVE MYSQL QUERY RULES TO DISK;
Query OK, 0 rows affected (0.00 sec)

Query OK, 0 rows affected (0.01 sec)
```

Let's rerun the testing benchmark:
```sh
$ sysbench --num-threads=16 --max-requests=0 --max-time=60 --test=oltp \
--mysql-user=msandbox --mysql-password=msandbox --mysql-db=sbtest --mysql-host=127.0.0.1 --mysql-port=6033 \
--oltp-table-size=10000 --oltp-read-only=on --db-ps-mode=disable --oltp-skip-trx=on \
--oltp-point-selects=100 --oltp-simple-ranges=1 --oltp-sum-ranges=1 --oltp-order-ranges=1 \
--oltp-distinct-ranges=1 run
```
And result is:
```sh
    read/write requests:                 1613248 (26873.58 per sec.)
```

We can immediately see that the throughtput has increased drastically, as some queries were cached by ProxySQL.

In ProxySQL we can see the follow results `from stats_mysql_query_digest`:
```sql
Admin> SELECT count_star,sum_time,hostgroup,digest,digest_text FROM stats_mysql_query_digest ORDER BY sum_time DESC;
+------------+-----------+-----------+--------------------+-------------------------------------------------------------------+
| count_star | sum_time  | hostgroup | digest             | digest_text                                                       |
+------------+-----------+-----------+--------------------+-------------------------------------------------------------------+
| 114715     | 119933775 | 1         | 0xE8930CB2CC9E68D7 | SELECT c from sbtest where id=?                                   |
| 6783       | 8244945   | 1         | 0xB749413737FAF581 | SELECT DISTINCT c from sbtest where id between ? and ? order by c |
| 6800       | 8081234   | 1         | 0x78881FD58E5437B2 | SELECT c from sbtest where id between ? and ? order by c          |
| 6877       | 7923794   | 1         | 0xDC1EE02F8CD8B09B | SELECT c from sbtest where id between ? and ?                     |
| 6840       | 7535059   | 1         | 0x547C0EAF9BC36E91 | SELECT SUM(K) from sbtest where id between ? and ?                |
| 1          | 2199      | 1         | 0xD575B97BB01C8428 | SHOW TABLE STATUS LIKE ?                                          |
| 8729       | 0         | -1        | 0xB749413737FAF581 | SELECT DISTINCT c from sbtest where id between ? and ? order by c |
| 8672       | 0         | -1        | 0x547C0EAF9BC36E91 | SELECT SUM(K) from sbtest where id between ? and ?                |
| 8712       | 0         | -1        | 0x78881FD58E5437B2 | SELECT c from sbtest where id between ? and ? order by c          |
| 8635       | 0         | -1        | 0xDC1EE02F8CD8B09B | SELECT c from sbtest where id between ? and ?                     |
| 1436485    | 0         | -1        | 0xE8930CB2CC9E68D7 | SELECT c from sbtest where id=?                                   |
+------------+-----------+-----------+--------------------+-------------------------------------------------------------------+
11 rows in set (0.00 sec)
```

Note: queries with `hostgroup=-1` represent traffic served directly from the query cache, without hitting any backend.


## Metrics

Some of the metrics currently avaiable are the ones reported in `stats_mysql_query_digest` with `hostgroup=-1`, like in the example below.

Other metrics related to Query Cache are available through the stats table `stats_mysql_global` :
```sql
Admin> SELECT * FROM stats_mysql_global WHERE Variable_Name LIKE 'Query_Cache%';
+--------------------------+----------------+
| Variable_Name            | Variable_Value |
+--------------------------+----------------+
| Query_Cache_Memory_bytes | 54133472       |
| Query_Cache_count_GET    | 1892409        |
| Query_Cache_count_GET_OK | 1699405        |
| Query_Cache_count_SET    | 193004         |
| Query_Cache_bytes_IN     | 24323669       |
| Query_Cache_bytes_OUT    | 135396517      |
| Query_Cache_Purged       | 185323         |
| Query_Cache_Entries      | 7681           |
+--------------------------+----------------+
8 rows in set (0.00 sec)
```

They represent:
* `Query_Cache_Memory_bytes` : total size of the resultset stored in the Query Cache. This doesn't include metadata;
* `Query_Cache_count_GET` : total number of GET requests executed against the Query Cache;
* `Query_Cache_count_GET_OK` : total number of _successful_ GET requests executed against the Query Cache: resultset was present and not expired;
* `Query_Cache_count_SET` : total number of resultset inserted into Query Cache;
* `Query_Cache_bytes_IN` : amount of data written into the Query Cache;
* `Query_Cache_bytes_OUT` : amount of data read from the Query Cache;
* `Query_Cache_Purged` : number of entries purged;
* `Query_Cache_Entries` : number of entries currently in the Query Cache.

## Query Cache tuning

At the moment, it is only possible to tune the total amount of memory used by the Query Cache, using the variable `mysql-query_cache_size_MB` :
```sql
mysql> SHOW VARIABLES LIKE 'mysql-query_cache%';
+---------------------------+-------+
| Variable_name             | Value |
+---------------------------+-------+
| mysql-query_cache_size_MB | 256   |
+---------------------------+-------+
```

**Important note:** the current implementation of `mysql-query_cache_size_MB` *doesn't impose a hard limit* . Instead, it is used as an argument by the purging thread.

To change the total amount of memory used by the Query Cache, it is possible to use commands like the follows:
```sql
mysql> SET mysql-query_cache_size_MB=128; LOAD MYSQL VARIABLES TO RUNTIME;
Query OK, 1 row affected (0.00 sec)

Query OK, 0 rows affected (0.00 sec)
```

A variable not strictly related to Query Cache but that influence its behavior is `mysql-threshold_resultset_size`.  
`mysql-threshold_resultset_size` defines the maximum resultset size that ProxySQL will buffer before starting sending it to the client.  
Setting this variable too low will prevent the retry of queries failed while retrieving the resultset from the backend.  
Setting this variable too high will potentially increase memory footprint, as ProxySQL will try to buffer more data.  
Because `mysql-threshold_resultset_size` defines the maximum resultset size that can be buffered, it also defines the maximum resultset size that can be stored in Query Cache.

## Implementation details

Every element in the Query Cache has several metadata associated with it:
* `key` : uniquely identify a Query Cache entry: it is a hash derived from username, schemaname and query itself. Combining these, it ensures that users access only their resultsets and for the correct schema;
* `value` : the resultset;
* `length` : length of the resultset;
* `expire_ms` : defines when the entry will expire;
* `access_ms` : records the last time an entry was accessed;
* `ref_count` : a reference count to identify resultset currently in use.

##### GET calls
Every time a `GET` call succeeds, to improve performance, the copy of the data is performed after increasing a reference pointer and releasing any lock. Then the copy is completed, the ref_count is decreased. This ensures that entries are not deleted from the Query Cache while still in use.
When a `GET` call finds an entry that is expired, the entry will be moved to a purging queue.

##### SET calls
A `SET` call never fails. If `mysql-query_cache_size_MB` is reached, the `SET` call will not fails.  
If there is an entry with the same key, it is moved into the purging queue.

## Purging thread

The purging of entries in the Query Cache is performed by a Purging thread.  
This ensure that any maintenance of the Query Cache is not performed by the MySQL Thread accessing it, but by a background thread, thus improving performance.  
This is the reason why `SET` calls never fails even if `mysql-query_cache_size_MB` is reached: it is not responsibility of the MySQL Thread accessing the Query Cache to free some space; instead Purging thread will take care of it.  

Purging thread is not only responsible for purging entries from the purging queue. It is also responsible for peridiocally scanning the whole Query Cache looking for expired entries.  
As an optimization, Purging thread doesn't perform any purging if the current memory usage is less than 3% of `mysql-query_cache_size_MB` .



### Limitation

There are currently multiple knows limitations in Query Cache.  
Some are simple to implement, other less.  
There is not a defined priority list: and priorites will be defined based on user requests.

Current known limitations:
* it is not possible to define query cache invalidation other than by cache_ttl;
* it doesn't exist a command to immediately purge the whole content of the query cache
* `mysql-query_cache_size_MB` is not stricly enforced, but only used a metrics to trigger automatic purging of expired entries;
* although `access_ms` is recorded, it is not used as a metric to expire unused metric when `mysql-query_cache_size_MB` is achieved;
* Query Cache does not support Prepared Statements.


