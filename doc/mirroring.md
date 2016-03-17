# Mirroring

This is the first implementation of mirroring in ProxySQL, and should be considered experimental:
* specifications can change at any time.
* this hasn't been extensively tested
* upgrades from previous versions that do not support mirroring will lose any previously defined query rules

### Extensions to mysql_query_rules

Table `mysql_query_rules` was modified to add 2 more columns:
* `mirror_flagOUT`
* `mirror_hostgroup`

Therefore, the new table definition of `mysql_query_rules` becomes:

``` sql
mysql> show create table mysql_query_rules\G
*************************** 1. row ***************************
       table: mysql_query_rules
Create Table: CREATE TABLE mysql_query_rules (
rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0,
username VARCHAR,
schemaname VARCHAR,
flagIN INT NOT NULL DEFAULT 0,
match_digest VARCHAR,
match_pattern VARCHAR,
negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0,
flagOUT INT,
replace_pattern VARCHAR,
destination_hostgroup INT DEFAULT NULL,
cache_ttl INT CHECK(cache_ttl > 0),
reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL,
timeout INT UNSIGNED,
delay INT UNSIGNED,
mirror_flagOUT INT UNSIGNED,
mirror_hostgroup INT UNSIGNED,
error_msg VARCHAR,
apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0)
1 row in set (0.00 sec)

```

## Implementation overview

When either `mirror_flagOUT` or `mirror_hostgroup` are set for a matching query, real time query mirroring is automatically enabled.  
Note that mirroring is enabled for the the final query, if the original was rewritten: if the query was rewritten along the way, the mirroring logic applies to the rewritten query. Although, the mirrored query can be rewritten and modified again. Details below.  
If a source query is matched against multiple query rules, it is possible that `mirror_flagOUT` or `mirror_hostgroup` are changed multiple times.  
The mirroring logic is the following:
* if `mirror_flagOUT` or `mirror_hostgroup` are set while processing the source query, a new mysql session is created
* the new mysql session will get all the same properties of the original mysql session : same credentials, schemaname, default hostgroup, etc (note: charset is currently not copied)
* if `mirror_hostgroup` was set in the original session, the new session will change its default hostgroup to `mirror_hostgroup`
* if `mirror_flagOUT` is not set, the new session will execute the *original* query against the defined `mirror_hostgroup`
* if `mirror_flagOUT` was set in the original session, the new mysql session will try to match the query from the original session against `mysql_query_rules` starting from a value of `FlagIN=mirror_flagOUT` : in this way it is possible to modify the query, like rewriting it, or changing again the hostgroup

## Examples

### Mirror selects to same hostgroup

In this very simple example we will just send all `SELECT` statements to hostgroup2, both the original and the mirror ones.

``` sql
Admin> INSERT INTO mysql_query_rules (rule_id,active,match_pattern,destination_hostgroup,mirror_hostgroup,apply) VALUES (5,1,'^SELECT',2,2,1);
Query OK, 1 row affected (0.01 sec)

Admin> LOAD MYSQL QUERY RULES TO RUNTIME;                                                                                                                                 Query OK, 0 rows affected (0.01 sec)
```

From a mysql session we will run some queries:

``` sql
mysql> use sbtest;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> SHOW TABLES;
+------------------+
| Tables_in_sbtest |
+------------------+
| longtable        |
| sbtest1          |
| sbtest2          |
| sbtest3          |
| sbtest4          |
+------------------+
5 rows in set (0.00 sec)

mysql> SELECT id FROM sbtest1 LIMIT 3;
+------+
| id   |
+------+
| 6204 |
| 3999 |
| 6650 |
+------+
3 rows in set (0.02 sec)
```

Back to the admin interface, we can see that the SELECT statement was executed twice:
``` sql
Admin> select hostgroup,count_star,schemaname,digest_text from stats_mysql_query_digest ORDER BY digest;
+-----------+------------+--------------------+----------------------------------+
| hostgroup | count_star | schemaname         | digest_text                      |
+-----------+------------+--------------------+----------------------------------+
| 2         | 2          | sbtest             | SELECT id FROM sbtest1 LIMIT ?   |
| 1         | 1          | information_schema | select @@version_comment limit ? |
| 2         | 2          | information_schema | SELECT DATABASE()                |
+-----------+------------+--------------------+----------------------------------+
3 rows in set (0.00 sec)
```

As an additional test we re-run the same query:
``` sql
mysql> SELECT id FROM sbtest1 LIMIT 3;
+------+
| id   |
+------+
| 6204 |
| 3999 |
| 6650 |
+------+
3 rows in set (0.00 sec)
```

On admin interface:
``` sql
Admin> select hostgroup,count_star,schemaname,digest_text from stats_mysql_query_digest ORDER BY digest;
+-----------+------------+--------------------+----------------------------------+
| hostgroup | count_star | schemaname         | digest_text                      |
+-----------+------------+--------------------+----------------------------------+
| 2         | 4          | sbtest             | SELECT id FROM sbtest1 LIMIT ?   |
| 1         | 1          | information_schema | select @@version_comment limit ? |
| 2         | 2          | information_schema | SELECT DATABASE()                |
+-----------+------------+--------------------+----------------------------------+
3 rows in set (0.00 sec)
```

`count_star` is double the number of times we executed the queries, because it is mirrored.
It is important to note that ProxySQL collects metrics both for the original query and the mirrors.


### Mirror SELECT to different hostgroup

In this example, we will re-configure proxysql to send all the `SELECT` statements to hostgroup1, but to mirror them on hostgroup2 :
``` sql
Admin> DELETE FROM mysql_query_rules;
Query OK, 1 row affected (0.00 sec)

Admin> INSERT INTO mysql_query_rules (rule_id,active,match_pattern,destination_hostgroup,mirror_hostgroup,apply) VALUES (5,1,'^SELECT',1,2,1);
Query OK, 1 row affected (0.00 sec)

Admin> LOAD MYSQL QUERY RULES TO RUNTIME;                                                                                                                                 Query OK, 0 rows affected (0.00 sec)
```

We also empty `stats_mysql_query_digest` to have a fresh stats:
``` sql
Admin> SELECT COUNT(*) FROM stats_mysql_query_digest_reset;
+----------+
| COUNT(*) |
+----------+
| 3        |
+----------+
1 row in set (0.00 sec)

Admin> select hostgroup,count_star,schemaname,digest_text from stats_mysql_query_digest ORDER BY digest;
Empty set (0.00 sec)
```

From the mysql client we can now run some queries (for simplicity, we run the same):
``` sql
mysql> SELECT id FROM sbtest1 LIMIT 3;
+------+
| id   |
+------+
| 6204 |
| 3999 |
| 6650 |
+------+
3 rows in set (0.00 sec)
```

In Admin we can now verify what happened:
``` sql
Admin> select hostgroup,count_star,sum_time,digest_text from stats_mysql_query_digest ORDER BY digest;
+-----------+------------+----------+--------------------------------+
| hostgroup | count_star | sum_time | digest_text                    |
+-----------+------------+----------+--------------------------------+
| 1         | 1          | 2995     | SELECT id FROM sbtest1 LIMIT ? |
| 2         | 1          | 921      | SELECT id FROM sbtest1 LIMIT ? |
+-----------+------------+----------+--------------------------------+
2 rows in set (0.00 sec)
```
The same identical query was sent to both hostgroup1 and hostgroup2!

### rewrite both source query and mirror

In this example, we will rewrite the original query, and then mirror it:
For simplicity, we rewrite `sbtest[0-9]+` to `sbtest3` :
``` sql
Admin> DELETE FROM mysql_query_rules;
Query OK, 1 row affected (0.00 sec)

Admin> INSERT INTO mysql_query_rules (rule_id,active,match_pattern,destination_hostgroup,replace_pattern,mirror_hostgroup,apply) VALUES (5,1,'sbtest[0-9]+',1,'sbtest3',2,1);
Query OK, 1 row affected (0.00 sec)

Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

Again, we reset `stats_mysql_query_digest` :
``` sql
Admin> SELECT COUNT(*) FROM stats_mysql_query_digest_reset;
```

From the mysql client we can run the usual query:
``` sql
mysql> SELECT id FROM sbtest1 LIMIT 3;
+-------+
| id    |
+-------+
| 24878 |
|  8995 |
| 33622 |
+-------+
3 rows in set (0.03 sec)
```

As expected, the output is different from previous one because now the original query was rewritten.
Let's check `stats_mysql_query_digest` :
``` sql
Admin> select hostgroup,count_star,sum_time,digest_text from stats_mysql_query_digest ORDER BY digest;                                                                    +-----------+------------+----------+--------------------------------+
| hostgroup | count_star | sum_time | digest_text                    |
+-----------+------------+----------+--------------------------------+
| 2         | 1          | 30018    | SELECT id FROM sbtest3 LIMIT ? |
| 1         | 1          | 27227    | SELECT id FROM sbtest3 LIMIT ? |
+-----------+------------+----------+--------------------------------+
2 rows in set (0.00 sec)
```

As expected, the modified query was executed on both hostgroups

### rewrite mirror query only 

In this example we will rewrite only the mirrored query.  
This is very useful, if for example, we want to understand the performance of the rewritten query, or if a new index will improve performance.  

In this example we will compare the performance of the same queries with and without the use of indexes.
We will also send the queries to same hostgroups.

The following creates a rule (`rule_id=5`) that:
* matches `FROM sbtest1 `
* sets `destination hostgroup=2`
* sets `mirror_flagOUT=100`
* does NOT set a `mirror_hostgroup`

``` sql
Admin> DELETE FROM mysql_query_rules;
Query OK, 1 row affected (0.00 sec)

Admin> INSERT INTO mysql_query_rules (rule_id,active,match_pattern,destination_hostgroup,mirror_flagOUT,apply) VALUES (5,1,'FROM sbtest1 ',2,100,1);
Query OK, 1 row affected (0.00 sec)
```

Because `mirror_flagOUT` is set, a new session will be created to run the same query. However, `mirror_hostgroup` was not set, so the query will be sent to the default hostgroup for the specific user, according to `mysql_users`. Instead, we want to send the mirror query to the same hostgroup as the original. We could do this either setting `mirror_hostgroup` in rule with `rule_id=5` , or create a new rule. We will also create a new rule to rewrite the query:
``` sql
Admin> INSERT INTO mysql_query_rules (rule_id,active,flagIN,match_pattern,destination_hostgroup,replace_pattern,apply) VALUES (10,1,100,'FROM sbtest1 ',2,'FROM sbtest1 IGNORE INDEX(k_1) ',1);
Query OK, 1 row affected (0.00 sec)

Admin> SELECT * FROM mysql_query_rules\G
*************************** 1. row ***************************
              rule_id: 5
               active: 1
             username: NULL
           schemaname: NULL
               flagIN: 0
         match_digest: NULL
        match_pattern: FROM sbtest1
 negate_match_pattern: 0
              flagOUT: NULL
      replace_pattern: NULL
destination_hostgroup: 2
            cache_ttl: NULL
            reconnect: NULL
              timeout: NULL
                delay: NULL
       mirror_flagOUT: 100
     mirror_hostgroup: NULL
            error_msg: NULL
                apply: 1
*************************** 2. row ***************************
              rule_id: 10
               active: 1
             username: NULL
           schemaname: NULL
               flagIN: 100
         match_digest: NULL
        match_pattern: FROM sbtest1
 negate_match_pattern: 0
              flagOUT: NULL
      replace_pattern: FROM sbtest1 IGNORE INDEX(k_1)
destination_hostgroup: 2
            cache_ttl: NULL
            reconnect: NULL
              timeout: NULL
                delay: NULL
       mirror_flagOUT: NULL
     mirror_hostgroup: NULL
            error_msg: NULL
                apply: 1
2 rows in set (0.00 sec)

Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

It is important to note that in the rule with `rule_id=10` , the one the mirrored query will match against, we need to set `destination_hostgroup` and not `mirror_hostgroup` : `mirror_hostgroup` should be set only for the original query in order to immediately specify where the mirror query should be sent, without the need of extra rules in `mysql_query_rules` .

Let's reset `stats_mysql_query_digest`:
``` sql
Admin> SELECT COUNT(*) FROM stats_mysql_query_digest_reset;
```

And run some test from mysql client:
``` sql
mysql> SELECT id FROM sbtest1 ORDER BY k DESC LIMIT 3;
+-------+
| id    |
+-------+
| 26372 |
| 81250 |
| 60085 |
+-------+
3 rows in set (0.01 sec)

mysql> SELECT id,k FROM sbtest1 ORDER BY k DESC LIMIT 3;
+-------+-------+
| id    | k     |
+-------+-------+
| 26372 | 80626 |
| 81250 | 79947 |
| 60085 | 79142 |
+-------+-------+
3 rows in set (0.01 sec)

```

Let's check `stats_mysql_query_digest` :
``` sql
Admin> select hostgroup,count_star,sum_time,digest_text from stats_mysql_query_digest ORDER BY sum_time DESC;
+-----------+------------+----------+--------------------------------------------------------------------+
| hostgroup | count_star | sum_time | digest_text                                                        |
+-----------+------------+----------+--------------------------------------------------------------------+
| 2         | 1          | 1135673  | SELECT id,k FROM sbtest1 IGNORE INDEX(k_1) ORDER BY k DESC LIMIT ? |
| 2         | 1          | 683906   | SELECT id FROM sbtest1 IGNORE INDEX(k_1) ORDER BY k DESC LIMIT ?   |
| 2         | 1          | 7478     | SELECT id,k FROM sbtest1 ORDER BY k DESC LIMIT ?                   |
| 2         | 1          | 4422     | SELECT id FROM sbtest1 ORDER BY k DESC LIMIT ?                     |
+-----------+------------+----------+--------------------------------------------------------------------+
4 rows in set (0.00 sec)
```

Table `stats_mysql_query_digest` confirms that:
* queries were mirrored
* the original query was not rewritten
* the mirrored query was rewritten
* the mirrored query was much slower because ignored the index

### Advanced example: use mirroring to test query rewrite

While working on mirroring I was asked a completely different question, related to query rewrite: how one could know if the given regex matches a given query, and verify that the rewrite pattern is correct?  
To be more specific, the problem is to understand if the rewrite is correct without affecting live traffic.  
Although mirroring wasn't initially designed for that, it can answer this question.

In this example, we will write a rule to match all the `SELECT` , "mirror" them , and try to rewrite them .
``` sql
Admin> DELETE FROM mysql_query_rules;                                                                                                                                        Query OK, 2 rows affected (0.00 sec)

Admin> INSERT INTO mysql_query_rules (rule_id,active,match_pattern,destination_hostgroup,mirror_flagOUT,apply) VALUES (5,1,'^SELECT ',2,100,1);
Query OK, 1 row affected (0.00 sec)

Admin> INSERT INTO mysql_query_rules (rule_id,active,flagIN,match_pattern,destination_hostgroup,replace_pattern,apply) VALUES (10,1,100,'^SELECT DISTINCT c FROM sbtest([0-9]{1,2}) WHERE id BETWEEN ([0-9]+) AND ([0-9]+)\+([0-9]+) ORDER BY c$',2,'SELECT DISTINCT c FROM sbtest\1 WHERE id = \3 \+ \4 ORDER BY c',1);
Query OK, 1 row affected (0.00 sec)

Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

The regex above are quite complex, and this is why mirroring helps instead of rewriting live traffic.

Let's reset `stats_mysql_query_digest`:
``` sql
Admin> SELECT COUNT(*) FROM stats_mysql_query_digest_reset;
```

And run some tests from the mysql client:
``` sql
mysql> SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN 10 AND 10+2 ORDER BY c;
+-------------------------------------------------------------------------------------------------------------------------+
| c                                                                                                                       |
+-------------------------------------------------------------------------------------------------------------------------+
| 41189576069-45553989496-19463022727-28789271530-61175755423-36502565636-61804003878-85903592313-68207739135-17129930980 |
| 48090103407-09222928184-34050945574-85418069333-36966673537-23363106719-15284068881-04674238815-26203696337-24037044694 |
| 74234360637-48574588774-94392661281-55267159983-87261567077-93953988073-73238443191-61462412385-80374300764-69242108888 |
+-------------------------------------------------------------------------------------------------------------------------+
3 rows in set (0.01 sec)
```
The query ran successfully. As said, we didn't modify the original traffic.

What about in `stats_mysql_query_digest` ?
``` sql
Admin> select hostgroup,count_star,sum_time,digest_text from stats_mysql_query_digest ORDER BY digest_text;
+-----------+------------+----------+----------------------------------------------------------------------+
| hostgroup | count_star | sum_time | digest_text                                                          |
+-----------+------------+----------+----------------------------------------------------------------------+
| 2         | 2          | 25461    | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
+-----------+------------+----------+----------------------------------------------------------------------+
1 row in set (0.00 sec)
```

The original query was executed twice, so something didn't run correctly.
We can note that both queries were sent to hostgroup2 : we should assume that `rule_id=10` was a match, but didn't rewrite the query.
Let's verify it was a match:
``` sql
Admin> SELECT * from stats_mysql_query_rules;
+---------+------+
| rule_id | hits |
+---------+------+
| 5       | 1    |
| 10      | 1    |
+---------+------+
2 rows in set (0.00 sec)
```

Rule with `rule_id=10` was a match according to `hits` in `stats_mysql_query_rules`.  
Then why wasn't the query rewritten? The error log has this information:  
```
re2/re2.cc:881: invalid rewrite pattern: SELECT DISTINCT c FROM sbtest\1 WHERE id = \3 \+ \4 ORDER BY c
```
Indeed, it is invalid syntax , let's fix this:
``` sql
Admin> UPDATE mysql_query_rules SET replace_pattern='SELECT DISTINCT c FROM sbtest\1 WHERE id = \3 + \4 ORDER BY c' WHERE rule_id=10;
Query OK, 1 row affected (0.00 sec)

Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

Admin> SELECT COUNT(*) FROM stats_mysql_query_digest_reset;
```

Let's re-execute the query from mysql client:
``` sql
mysql> SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN 10 AND 10+2 ORDER BY c;
+-------------------------------------------------------------------------------------------------------------------------+
| c                                                                                                                       |
+-------------------------------------------------------------------------------------------------------------------------+
| 41189576069-45553989496-19463022727-28789271530-61175755423-36502565636-61804003878-85903592313-68207739135-17129930980 |
| 48090103407-09222928184-34050945574-85418069333-36966673537-23363106719-15284068881-04674238815-26203696337-24037044694 |
| 74234360637-48574588774-94392661281-55267159983-87261567077-93953988073-73238443191-61462412385-80374300764-69242108888 |
+-------------------------------------------------------------------------------------------------------------------------+
3 rows in set (0.00 sec)
```

And now let's verify if the query was rewritten correctly:
``` sql
Admin> select hostgroup,count_star,sum_time,digest_text from stats_mysql_query_digest ORDER BY digest_text;                                                                  +-----------+------------+----------+----------------------------------------------------------------------+
| hostgroup | count_star | sum_time | digest_text                                                          |
+-----------+------------+----------+----------------------------------------------------------------------+
| 2         | 1          | 2756     | SELECT DISTINCT c FROM sbtest1 WHERE id = ? + ? ORDER BY c           |
| 2         | 1          | 891      | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
+-----------+------------+----------+----------------------------------------------------------------------+
```

Well, yes, the query was rewritten correctly, and was also executed :-)  

### Advanced example: use mirroring and firewall to test query rewrite

Taking the previous example/exercise a bit forward: is it possible to know how a query will be rewritten without executing it? YES!  
To achieve this, we will set `error_msg` for the mirrored query: in this way ProxySQL will process the query, but it will filter it without sending it to any mysql servers. As stated in the very beginning, the mirrored query can be modified, and firewall it is an example of modifying the mirrored query.

Example:
``` sql
Admin> UPDATE mysql_query_rules SET error_msg="random error, blah blah" WHERE rule_id=10;
Query OK, 1 row affected (0.00 sec)

Admin> LOAD MYSQL QUERY RULES TO RUNTIME;
Query OK, 0 rows affected (0.01 sec)

Admin> SELECT COUNT(*) FROM stats_mysql_query_digest_reset;
```

Let's rerun the query in mysql client:
``` sql
mysql> SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN 10 AND 10+2 ORDER BY c;
+-------------------------------------------------------------------------------------------------------------------------+
| c                                                                                                                       |
+-------------------------------------------------------------------------------------------------------------------------+
| 41189576069-45553989496-19463022727-28789271530-61175755423-36502565636-61804003878-85903592313-68207739135-17129930980 |
| 48090103407-09222928184-34050945574-85418069333-36966673537-23363106719-15284068881-04674238815-26203696337-24037044694 |
| 74234360637-48574588774-94392661281-55267159983-87261567077-93953988073-73238443191-61462412385-80374300764-69242108888 |
+-------------------------------------------------------------------------------------------------------------------------+
3 rows in set (0.00 sec)
```

And now let's check statistics:
``` sql
dmin> select hostgroup,count_star,sum_time,digest_text from stats_mysql_query_digest ORDER BY digest_text;                                                                  +-----------+------------+----------+----------------------------------------------------------------------+
| hostgroup | count_star | sum_time | digest_text                                                          |
+-----------+------------+----------+----------------------------------------------------------------------+
| -1        | 1          | 0        | SELECT DISTINCT c FROM sbtest1 WHERE id = ? + ? ORDER BY c           |
| 2         | 1          | 3219     | SELECT DISTINCT c FROM sbtest1 WHERE id BETWEEN ? AND ?+? ORDER BY c |
+-----------+------------+----------+----------------------------------------------------------------------+
2 rows in set (0.00 sec)

Admin> SELECT * from stats_mysql_query_rules;                                                                                                                                +---------+------+
| rule_id | hits |
+---------+------+
| 5       | 1    |
| 10      | 1    |
+---------+------+
2 rows in set (0.00 sec)
```

Great! We know that the query was rewritten, but actually not sent anywhere:
* `sum_time=0` because the response was immediate
* `hostgroup=-1` has the special meaning of "not sent anywhere"
