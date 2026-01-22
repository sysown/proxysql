### Question 1 : Connection pooling in ProxySQL

`Answer` : Like any other database technology , ProxySQL also maintains a pool of connections.

A connection pool is a cache of database connections maintained so that the connections can be reused when
future requests to the database are required.

As we can see that each host has max_connection set to 1000.<br />

So ProxySQL can open total 1000 backend connection for that specific host.

```
mysql> select hostgroup_id,hostname,port,status,weight,max_connections from mysql_servers;
+--------------+------------+------+--------+--------+-----------------+
| hostgroup_id | hostname   | port | status | weight | max_connections |
+--------------+------------+------+--------+--------+-----------------+
| 0            | 172.17.0.1 | 3306 | ONLINE | 100    | 1000            |
+--------------+------------+------+--------+--------+-----------------+
3 rows in set (0.00 sec)
```

Below variable controls the percentage of open idle connections in pool from the total maximal number of
connections for a specific server in a hostgroup.

```
mysql> select * from global_variables where variable_name like 'mysql-free_connections_pct';
+----------------------------+----------------+
| variable_name              | variable_value |
+----------------------------+----------------+
| mysql-free_connections_pct | 20             |
+----------------------------+----------------+
1 row in set (0.01 sec)
```

This is the workflow for connection pool :

1. A session needs a connection to server , It check into the connection pool.
2. If there is a connection in the connection pool for that backend, that connection is used, otherwise a new
   connection is created.
3. When a session frees a connection this is sent back to the Hostgroup Manager. If the Hostgroup Manager
   determines that the connection is safe to share and the connection pool isn't full, it will place it in the
   connection pool.
4. If the connection is not safe to share (there are session variables, or temporary tables, etc) the
   Hostgroup Manager destroys that connection.
5. For each backend server, the hostgroup manager will keep in the connection pool up to
   `mysql-free_connections_pct * mysql_servers.max_connections / 100 connections`. Connections are kept open
   with periodic pings.

<!-- -->

So with above given example :<br />

Number of idle connection in pool = (20 \* 1000) / 100 = 200 Idle connection.

### Question 2 : USE DBNAME

`Answer` : Some users has raised question , why USE database will always succeed in ProxySQL even if database
doesn't exist.<br />

Issue reported on GitHub : [https://github.com/sysown/proxysql/issues/876][1]

First thing to note : ProxySQL will never give error while executing "Use" Command , Error will arise during
the execution of the query.(more details later on)

Let see what happens when MySQL CLI execute USE dbname:

- It sends a `COM_INIT_DB` command to change the database
- It sends a query `show tables`

<!-- -->

\[ The superfluous \`show tables\` is not executed by ProxySQL. That request coming from the client (mysql
cli) and ProxySQL is trying to forward. To suppress the \`show tables\` command, mysql cli should be executed
using \`-A\` to disable auto-refresh ]

When client execute `USE` command , ProxySQL does not forward the request to any backend, it only internally
track which one is the desired default schema for that specific client \[mysql_users.default_schema].

The reason why “USE DB” doesn't through any error at ProxySQL client , because there are chances that selected
DB is not present on default hostgroup for that user , but it is present on other hostgroup added behind same
ProxySQL.

Please see below example:

Assume we have two servers with one schema each and both host behind same ProxySQL:

```
employees DB on `172.17.0.1` [Hostgroup 0]
digital DB on `172.17.0.3` [Hostgroup 2]
```

1. User has `employees` database as default schema and ProxySQL forwarding all queries to `172.17.0.1`.
2. Now user wants to run queries on `digital` schema but request cannot be executed on `172.17.0.1` because
   `digital` Schema doesn't exist there.
3. In this case, ProxySQL will only reply OK to the client for `USE` command , and will wait for the client to
   sends a query. When the client sends a query, ProxySQL will decide what to do with it by checking the query
   rules, and if query rules match then it will send the request to `172.17.0.3`.

<!-- -->

Two hosts are present and belonging to different hostgroups:

```
mysql> select hostgroup_id,hostname,port,status,weight,max_connections from mysql_servers;
+--------------+------------+------+--------+--------+-----------------+
| hostgroup_id | hostname   | port | status | weight | max_connections |
+--------------+------------+------+--------+--------+-----------------+
| 0            | 172.17.0.1 | 3306 | ONLINE | 100    | 1000            |
| 2            | 172.17.0.3 | 3306 | ONLINE | 100    | 1000            |
+--------------+------------+------+--------+--------+-----------------+
```

User is used to connect to MySQL Servers through ProxySQL. So when every time the same user connects, it will
reach to `default_hostgroup=0` and `default_schema=employees`

```
mysql> select username,password,active,default_hostgroup,default_schema,max_connections from mysql_users;
+----------+----------+--------+-------------------+----------------+-----------------+
| username | password | active | default_hostgroup | default_schema | max_connections |
+----------+----------+--------+-------------------+----------------+-----------------+
| sysbench | sysbench | 1      | 0                 | employees      | 10000           |
+----------+----------+--------+-------------------+----------------+-----------------+
```

In below example , we are looking for table `dept` which is present in `digital` database and that database is
present only on hostname `172.17.0.3`.

Query Rule to forward all queries on hostgroup - 2 which belongs to digital schema.

```
mysql> select rule_id,active,destination_hostgroup, apply,schemaname from mysql_query_rules;
+---------+--------+-----------------------+-------+------------+
| rule_id | active | destination_hostgroup | apply | schemaname |
+---------+--------+-----------------------+-------+------------+
| 1       | 1      | 0                     | 1     | employees  |
| 2       | 1      | 2                     | 1     | digital    |
+---------+--------+-----------------------+-------+------------+
```

\- _Without any query rule:_

Query will hit on employees database on default host 172.17.0.1 2 and it fails due to DB not found.

```
root@8a9f96bb26f9:/# mysql -usysbench -psysbench -h127.0.0.1 -P6033 -A -e "select @@server_id;use digital;
select \* from dept; select @@server_id;" +-------------+ | @@server_id | +-------------+ | 1 |
+-------------+ ERROR 1049 (42000) at line 1: Unknown database 'digital'
```

\- _With query rule:_ It works successfully.

<!-- prettier-ignore-start -->

1\. Below query will hit the default host and default schema , which is employees DB on Host “172.17.0.1”.<br />
2\. Query rule get match because of `use digital` string found.<br />
3\. After matching rule , next consecutive query will get reroute to server “172.17.0.3” and execution
    finished.<br />

<!-- prettier-ignore-end -->

```
root@8a9f96bb26f9:/# mysql -usysbench -psysbench -h127.0.0.1 -P6033 -A -e "select @@server_id;use digital; select * from dept; select @@server_id;"
+-------------+
| @@server_id |
+-------------+
|           1 |
+-------------+
+------+------+
| id   | name |
+------+------+
|  101 | ashw |
+------+------+
+-------------+
| @@server_id |
+-------------+
|           3 |
+-------------+
root@8a9f96bb26f9:/#
```

So the behaviour we are seeing is expected. `USE database` will always succeed, but the queries will fail
until a valid schema is selected.

### Question 3 : Monitoring in ProxySQL

`Answer` : ProxySQL is quite unique when it performs failure detection , It can detect that a server is down
not because its Monitoring system fails to check the status of a backend, but because queries are failing.<br />

That means that even if Monitor is disabled, ProxySQL is able to detect if a node is down when it tries to
send queries to it.

The core of ProxySQL works this way : (that means without Monitor enabled)

1. Initially all nodes are online.
2. when sending traffic to a node errors are generated, if more than `mysql-shun_on_failures` errors are
   generated in 1 second, the node is shunned for `mysql-shun_recovery_time_sec` seconds.
3. After `mysql-shun_recovery_time_sec`, ProxySQL will bring the node back online and will try to send traffic
   to it
4. If the condition described in point 2 happens again, the node is shunned again.

<!-- -->

One important thing to note about point 3 is that ProxySQL doesn't have a timer to bring the node back online
after `mysql-shun_recovery_time_sec` seconds. The node is brought back online after
`mysql-shun_recovery_time_sec` seconds only if there is activity in the connections pool for that specific
hostgroup.

All the above works without Monitor enabled!

> Monitor module extends the functionality of the core of ProxySQL.

For example, if there is a network issue, ProxySQL's core won't be able to understand if a database server is
not replying because it is still running the query or because there is a network problem. Monitor will be able
to detect this and inform ProxySQL's core that the backend seems unreachable.

As said, this is not completely true.<br />

The core of ProxySQL can still detect that there is a problem if you send more traffic to ProxySQL and
ProxySQL tries to open new connection to that backend. `connect()` will fail, and ProxySQL will shun that
node. Although, the current connection won't be affected.

### Question 5 : ProxySQL HA

`Answer` : No matter how highly available ProxySQL is, a crash is always possible due to unknown bugs.<br />

For this reason, ProxySQL has the ability to auto-restart by angel process in less than a second in case of
failure .

Below are some examples for how to integrate ProxySQL in our architectures.

- One single ProxySQL instance
- Multiple ProxySQL hosts
- Multiple ProxySQL hosts + LB
- One ProxySQL instance per application server
- Silos approach
- Keepalived + VIP + ProxySQL
- Keepalived + VIP + LB
- Keepalived + VIP + LVS
- Multi-layer + Keepalived + VIP + LVS
- Multi-layers
- Silos + Multi-layers

<!-- -->

For reference : [slideshare][2]<br />

[webinar][3]

### Question 6 : Mirroring in ProxySQL

`Answer` :<br />

When we need a tool , To test our production queries on different or new platform we can make use of
mirroring.

This feature works similar to blackhole engine , It always execute query on server configured in
`mirror_hostgroup` and log into its own binlogs.

How to configure Mirroring : [In Detail][4]

Below are some use cases where you can actually take advantage of this feature without installing new plugin.

1. To test SQL queries performance on different MySQL forks (MySQL , Percona , MariaDB) :
2. Try production queries on newer MySQL version \[Validate SQL syntax]:
3. Test `mysql_query_rules` configured in ProxySQL before making it live.

<!-- -->

How to validate MySQL queries : [Example][5]

Important to note : ProxySQL mirroring should be only used for benchmarking ,testing, upgrade validation and
any other activity that doesn't require correctness.<br />

The whole process is not free for a server , it increased CPU utilization on box. so if we have more number of
ProxySQL configured, we can just configure mirroring on one-two proxy's to avoid extra cpu usage on every box.

Note : ProxySQL Mirroring doesn't support prepared statements. If you are running sysbench test don't forget
to add `--db-ps-mode=disable`

Benchmark test result : [https://www.percona.com/blog/2017/05/25/proxysql-and-mirroring-what-about-it/][6]

### Question 10 : Stop/Shutdown ProxySQL

`Answer` :

Once the process receives `SIGTERM` signal , a few different things can happen:

- the process may stop immediately
- the process may stop after a short delay after cleaning up resources
- the process may keep running indefinitely

<!-- -->

The application can determine what it wants to do once a SIGTERM is received. While most applications will
clean up their resources and stop, some may not.

See what ProxySQL does with [Kill][7]

`killall` - _kill processes by name_

killall sends a signal to all processes running any of the specified commands . If no signal name is
specified, SIGTERM is sent. To terminate all ProxySQL process (child and parent), enter: killall proxysql

### Question 11 : Configure Default Hostgroup

`Answer` : : In below example user doesn't have any host configured for `hostgroup 0`

```
mysql> select hostgroup_id,hostname,port,status,weight from mysql_servers;
+--------------+------------+------+--------+--------+
| hostgroup_id | hostname   | port | status | weight |
+--------------+------------+------+--------+--------+
| 2            | 172.17.0.2 | 3306 | ONLINE | 100    |
| 3            | 172.17.0.3 | 3306 | ONLINE | 100    |
| 1            | 172.17.0.1 | 3306 | ONLINE | 100    |
+--------------+------------+------+--------+--------+

 mysql> select * from mysql_replication_hostgroups;
+------------------+------------------+---------+
| writer_hostgroup | reader_hostgroup | comment |
+------------------+------------------+---------+
| 1                | 2                | stag1   |
+------------------+------------------+---------+

mysql> select rule_id, match_digest,destination_hostgroup,apply from mysql_query_rules;
+---------+---------------------+-----------------------+-------+
| rule_id | match_digest        | destination_hostgroup | apply |
+---------+---------------------+-----------------------+-------+
| 11      | ^SELECT.*           | 2                     | 0     |
| 12      | ^SELECT.*FOR UPDATE | 1                     | 1     |
+---------+---------------------+-----------------------+-------+
```

But still user facing error :

> Max connect timeout reached while reaching hostgroup 0 after 10000ms

This is because user forgot to change `default_hostgroup` in `mysql_users`.

```
mysql> select username,password,active,default_hostgroup,default_schema,max_connections, max_connections from mysql_users;
+----------+----------+--------+-------------------+----------------+-----------------+-----------------+
| username | password | active | default_hostgroup | default_schema | max_connections | max_connections |
+----------+----------+--------+-------------------+----------------+-----------------+-----------------+
| sysbench | sysbench | 1      | 0                 | NULL           | 10000           | 10000           |
+----------+----------+--------+-------------------+----------------+-----------------+-----------------+
1 row in set (0.00 sec)
```

[1]: https://github.com/sysown/proxysql/issues/876
[2]: https://www.slideshare.net/Severalnines/webinar-slides-high-availability-in-proxysql?from_action=save
[3]: https://www.youtube.com/watch?v=kzvazKEv4iY
[4]: https://github.com/sysown/proxysql/blob/v1.4.3/doc/mirroring.md
[5]: https://blog.pythian.com/using-proxysql-validate-mysql-updates/
[6]: https://www.percona.com/blog/2017/05/25/proxysql-and-mirroring-what-about-it/
[7]: https://github.com/sysown/proxysql/blob/v1.4.4/etc/init.d/proxysql#L109
