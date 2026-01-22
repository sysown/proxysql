### How do I configure connection pooling in ProxySQL?

The variable has been documented here [mysql-free_connections_pct][1]. More information at [Connection
pooling][2]

### How does ProxySQL handle the `USE dbname` Command?

Some users raised questions asking why will `USE database` always succeed in ProxySQL even when the database
doesn't exist. This document explains how ProxySQL deals with default schema and -D \[dbname] : [USE
databasename][3]

### Monitor module responsibilities in more details

The core of ProxySQL also observes the success/failure of backend servers, but it has some limitations (More
details later on) But the Monitor module extends the functionality of the core of ProxySQL. How to configure
monitoring in ProxySQL [Configure Monitoring][4]. The responsibilities have also been documented [here][4].
More in detail: [click here][5].

### How does ProxySQL handle database failovers?

An important point to note is that ProxySQL is an agent and it doesn't perform any kind of failover by its
own. But it is developed to handle DB failovers, either unplanned or initiated by external tools. The below
documents will explain how ProxySQL deals with failover to achieve high availability:

- ProxySQL + MHA [ProxySQL and MHA integration][6]
- ProxySQL + mysqlrpladmin [ProxySQL and mysqlrpladmin][7]
- How to configure MHA [Setup MHA][8]

Each failover is handled differently depending on the type of cluster being monitored and the configuration
selected. For details about each type of cluster configuration and monitoring behavior please refer to each of
the documentation pages:

- [AWS Aurora][35]
- [Galera Configuration][36]
- [MySQL Group Replication][35]

It's important to consider, that no matter the cluster type or configuration, the actions to perform on the
event of a failover are **never** dependent on witnessing the failover itself. This is result of two important
concepts related to ProxySQL cluster monitoring policy:

1. Actions taken over servers belonging to clusters, should take into account the complete cluster state. This
   means that only **the current servers state** is relevant for determining cluster level actions, not
   previous statuses or state transitions.
2. Actions taken over servers should be deterministic, when combined with the previous policy, this allows for
   distributed deterministic decision making, which is essential when considering ProxySQL clusters.

Due to these two previous motivations, ProxySQL wont consider any previous state transitions on the monitored
servers when performing cluster level monitoring actions (e.g. hostgroups servers placement). If a user, due
to workload or maintenance particularities requires control over servers placement that involves such
considerations, they should resort to [the scheduler][37], implementing their own monitoring solution.

### How do we avoid the problem of ProxySQL being a single point of failure?

ProxySQL itself doesn't have a built-in HA solution, but it is very easy to architecture its deployment in
order to avoid SPOF. A few months back Percona published some articles where it is highlighted how to avoid
single points of failure:

- [http://proxysql.com/blog/multiple-proxysql-on-same-ports][9]
- [http://proxysql.com/blog/how-to-run-multiple-proxysql-instances][10]
- [https://www.percona.com/blog/2017/01/19/setup-proxysql-for-high-availability-not-single-point-failure/][11]
- [https://www.percona.com/blog/2016/09/16/consul-proxysql-mysql-ha/][12]

Few more examples on how to implement MySQL HA (high-availability) solutions [here][13].

### What is Mirroring in ProxySQL and when to use it ?

ProxySQL’s mirror feature allows us to send real application traffic to a completely separate server without
touching the application. Mirroring functionality is not like replication topology in MySQL, but it has some
use cases. For more information: [In detail][14]

### How to use `flagIN`, `flagOUT`, `apply` to improve performance if you have multiple query rules?

If you have more query rules, then all your queries have to match against all of them and this has a serious
impact on performance. How can we avoid that? `flagIN`, `flagOUT`, `apply` - They work together and apply
logic into your rules so that even if you have more rules, you will get better performance. _flagIN, flagOUT,
apply - these allow us to create a "chain of rules" that get applied one after the other. An input flag value
is set to 0, and only rules with flagIN=0 are considered at the beginning. When a matching rule is found for a
specific query, flagOUT is evaluated and if NOT NULL the query will be flagged with the specified flag in
flagOUT. If flagOUT differs from flagIN, the query will exit the current chain and enter a new chain of rules
having flagIN as the new input flag. If flagOUT matches flagIN, the query will be re-evaluated again against
the first rule with said flagIN. This happens until there are no more matching rules, or apply is set to 1
(which means this is the last rule to be applied)._ Benchmark Result : [Too many query rules][15] How to
create a chain of rules : [example ][16]

### Is there any monitoring tool available to get statistic report for ProxySQL servers?

Yes, use Grafana and the built-in ProxySQL Prometheus Exporter, [read this blog to find out more][17] and make
sure to check the [sample dashboards as well as a Docker based deployment available here][18].

### How to manage ProxySQL configuration across multiple servers?

Actually it is easy to reconfigure ProxySQL at runtime , we can use a variety of approaches, like using a
configuration management tool (Puppet, Chef, Ansible, Salt etc..) or a service discovery toos (Consul, Etcd,
Zookeeper) to automatically reconfigure ProxySQL if needed. The most convenient method is to use the native
feature of [ProxySQL Cluster][19]

### How to gracefully shutdown the ProxySQL process?

To **kill** is the right way for graceful shutdown of ProxySQL, the rest is handled internally. When executing
the `kill` command, a SIGTERM signal is sent to the ProxySQL process. _SIGTERM 15 - Software termination
signal (sent by kill by default)_ More details : [click here][20]

### No Hostgroup 0 has been configured, then why do we get "Max connect timeout reached while reaching hostgroup 0 after 10000ms"?

This is how MySQL Query Rules work while selecting hostgroups.

1. When you set any query rules inside table `mysql_query_rules`, then your query gets analyzed by the Query
   Processor to decide which destination hostgroup it should be forwarded to. (according to
   mysql_query_rules.destination_hostgroup)
2. When your Query Processor doesn't find any query matching the query rule then the default hostgroup for the
   specific user is applied (according to mysql_users.default_hostgroup)

<!-- -->

Example : [Default Hostgroup for User][21]

### What is Multiplexing and How does it work (enable/disable)?

**Multiplexing** - Reduce the number of connections against mysqld, [see detailed info here][22]. Many clients
connections (tens of thousands) can use few backend connections (few hundreds). So it is possible for the
requests coming from a single client to be evenly distributed among all the backends of the same hostgroup.
ProxySQL understands the requirement of transactions execution. If a transaction is running, then multiplexing
is disabled until the transaction completes, either through a rollback or commit. So ProxySQL will ensure that
the statements within a transaction execute on same backend server by default. Default value for
`mysql-multiplexing` is true

```
mysql> select * from global_variables where variable_name like '%multiplexing%';
+--------------------+----------------+
| variable_name      | variable_value |
+--------------------+----------------+
| mysql-multiplexing | true           |
+--------------------+----------------+
1 row in set (0.01 sec)
```

More on multiplexing : [Here][23]

### How to configure ProxySQL using the config file?

Yes, the option is available to start ProxySQL from the config file using the `--initial` flag. Example :

```
proxysql --initial -f -c /etc/proxysql.cnf
```

There are a few things you should know before using this flag : [Initial flag][24]

### Why do entries in mysql_servers duplicated?

A few user have raised the question of why the writer host gets duplicated into the reader hostgroup. Okay, so
this behaviour is intensional! And it is controlled by `mysql-monitor_writer_is_also_reader` in [Monitor
Module][25] When we load `MYSQL SERVERS`, our writer host also gets configured in the reader hostgroup
automatically by ProxySQL to handle all those queries which are redirected to reader hostgroup in case no
slaves are online. This feature is dependent on reader/writer hostgroup which we configured in table
`mysql_replication_hostgroups`. Note: `LOAD MYSQL SERVERS TO RUNTIME` processes both `mysql_servers` and
`mysql_replication_hostgroups` tables.

### How can I kill a connection ?

You can find the processlist information in the ProxySQL Admin stats table by executing
`SELECT * FROM stats_mysql_processlist;`. This table contains the following fields:

```
ThreadID: Thread Identifier
 SessionID: Session Identifier
      user: Authentication User
        db: Connected Database
  cli_host: Client host / IP
  cli_port: Client port
 hostgroup: Hostgroup Identifier
l_srv_host: Listening host / IP (ProxySQL)
l_srv_port: Listening port (ProxySQL
  srv_host: MySQL host / IP (Backend MySQL instance)
  srv_port: MySQL port (Backend MySQL instance)
   command: Command State
   time_ms: Execution time
      info: SQL Statement executing
```

From here you can identify the `SessionID` and `KILL CONNECTION` e.g.:

```
ProxySQL Admin> KILL CONNECTION 1;
```

### When does query routing get disabled?

When we enable `transaction_persistent` for a specific user and application to execute `transactions`, it will
always use the same host to execute all queries to get more accurate results. Please note that it disables
query routing.

```
Admin> SELECT username, default_hostgroup, transaction_persistent, fast_forward FROM mysql_users;
+----------+-------------------+------------------------+--------------+
| username | default_hostgroup | transaction_persistent | fast_forward |
+----------+-------------------+------------------------+--------------+
| root     | 0                 | 1                      | 0            |
+----------+-------------------+------------------------+--------------+
```

More details in [Users Configuration][26].

**Note**: By default sysbench uses `transactions` and `prepared statements`. To disable transactions and
prepared statements make use of `--oltp-test-mode=nontrx` and `--db-ps-mode=disable` respectively.

### How can I drain connections from a ProxySQL instance?

Stop the listeners so no new connections are accepted using the "pause" feature. Existing connections are
maintained and running transactions are allowed to complete so that applications can disconnect gracefully:

```
ProxySQL Admin> PROXYSQL PAUSE;
```

To start listening for new connections again it is possible to resume with:

```
ProxySQL Admin> PROXYSQL RESUME;
```

Reference: [ISSUE-337][27]

### Feature X doesn't work. Please advise

Please read [How To ask Questions The Smart Way][28], then [ask on the forum][29] or [report a
bug][30]**Disclaimer**: Thyrsus Enterprises is _not a help desk_ .

### How do I configure ProxySQL to connect to MySQL?

`Port 6032` is the default port used by the "Admin interface". Through this interface you can configure
ProxySQL and get metrics from it by using a normal MySQL client. For configuration, also check out the
[documentation][31].

### How can I connect to a MySQL server through ProxySQL?

In order to connect to MySQL servers through ProxySQL you should connect to `Port 6033` (by default). For
configuration, also check out the [documentation][32].

### Does ProxySQL support ip address whitelist?

ProxySQL supports some sort of IP address whitelisting. Field mysql_query_rules.client_addr can be used to
filter traffic based on clients addresses, therefore it is possible to allow traffic from specific addresses
while blocking everything else. The catch here is that the filtering is done on the queries only: clients not
in the "whitelist" can still be able to connect to ProxySQL, although their queries will be blocked. Also
check out the [documentation][33].

### Are requests load balanced for a single connection?

Yes, by default, it is possible that the requests coming from a single connection are evenly distributed among
all the backends of the same hostgroup. Also check out the [documentation][34].

### Why do I get `Detected a broken connection during query on .... : 2006, MySQL server has gone away`

This message means that the **backend** server had closed the connection, but ProxySQL reports the generic
error message because it has no knowledge of the root reason. As for now we have seen that the most frequent
reasons for this error to appear are: \* wait_timeout \* large packet

### What happens if a user tries to use a database that does not exist?

When the `USE db_name` command is issued from the MySQL CLI, it sends a `COM_INIT_DB` command to change the
database, and also sends a `SHOW TABLES` query for the database specified. (In order to prevent the
`SHOW TABLES` query from being sent, it is necessary to execute the mysql command with the `-A` option)
ProxySQL itself does not execute the `SHOW TABLES` query, it only tries to forward it to the appropriate
backend. When a client issues a `USE` command or `COM_INIT_DB`, ProxySQL does not forward it to any backend,
it only tracks internally which one is the desired default schema for the specific client who issued it. The
reason for this behavior is that the default schema only becomes relevant when running a query and not before,
and routing depends on it. Assume you have two servers, with one schema each:

- schemaA on serverA
- schemaB on serverB

<!-- -->

You would configure ProxySQL to send all queries on schemaA to serverA, while all queries on schemaB to
serverB : this is a classic sharding. If a client has schemaA as default schema and is sending queries to
serverA, and now it issues `USE schemaB`, this request cannot be executed on serverA since schemaB doesn't
exist there. In this case, ProxySQL will only reply OK to the client, and will wait for the client to send a
query. When the client sends a query, ProxySQL will decide what to do with it: as the default schema is now
schemaB, it will send the request to serverB. Based on this, the `USE database` command will always succeed,
but the queries will fail until a valid schema is selected.

### In ProxySQL Cluster, why does the synchronization of mysql_users generate two records?

When you add a user in `mysql_users` with both `backend=1` and `frontend=1`, you are actually creating 2
users: one for frontend and one for backend. Although in `mysql_users` they can be represented (only
represented) as one row, they are actually 2 users. In fact, `runtime_mysql_users` shows 2 users and 2 rows.
ProxySQL uses `runtime_mysql_users` for syncing users, thus 2 users are synchronized, and in the receiving
nodes they are recorded as 2 rows in `mysql_users`

### How to guarantee at least one reader in cluster monitoring configurations?

A configuration to achieve this would be to pair `writer_is_also_reader=1`, to allow writers into the
reader_hostgroup and `max_writers=1` to allow just a single writer each time. Normally when a writer is
desired to be present as a reader, or a backup reader, there is no motivation for excluding it from the reader
hostgroup.

### Error when executing '\l' command on 'psql' cli

This isn't a `ProxySQL` issue, but likely the result of a mismatch between the target backend server and
`ProxySQL` announced version. `psql` client modifies the actual query to be performed for the `\l` command
based on the server advertised version, if `ProxySQL` advertised version doesn't match the real target one a
failure might takes place. This is because the tables/query themselves might not be valid between versions.

An example of such error for a mismatch between announced version (`16`) and real backend version (`17`) was:

```
PGPASSWORD=postgres psql -h127.0.0.1 -p6133 -Upostgres
psql (17.2, server 16.1)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off, ALPN: none)
Type "help" for help.

postgres=> \l
ERROR:  column d.daticulocale does not exist
LINE 8:   d.daticulocale as "Locale",
          ^
HINT:  Perhaps you meant to reference the column "d.datlocale".
```

[1]: /Global-variables#mysql-free_connections_pct
[2]: /detailed-answers-on-faq#question-1--connection-pooling-in-proxysql
[3]: /detailed-answers-on-faq#question-2--use-dbname
[4]: /ProxySQL-Configuration#configure-monitoring
[5]: /detailed-answers-on-faq#question-3--monitoring-in-proxysql
[6]: https://www.percona.com/blog/2016/09/13/proxysql-and-mha-integration/
[7]: https://planet.mysql.com/entry/?id=5992282
[8]: https://www.percona.com/blog/2016/09/02/mha-quickstart-guide/
[9]: http://proxysql.com/blog/multiple-proxysql-on-same-ports
[10]: http://proxysql.com/blog/how-to-run-multiple-proxysql-instances
[11]: https://www.percona.com/blog/2017/01/19/setup-proxysql-for-high-availability-not-single-point-failure/
[12]: https://www.percona.com/blog/2016/09/16/consul-proxysql-mysql-ha/
[13]: /detailed-answers-on-faq#question-5--proxysql-ha
[14]: /detailed-answers-on-faq#question-6--mirroring-in-proxysql
[15]: https://www.percona.com/blog/2017/04/10/proxysql-rules-do-i-have-too-many/
[16]: https://www.percona.com/blog/2017/04/12/proxysql-applying-and-chaining-the-rules/
[17]: https://proxysql.com/blog/observability-enhancements-in-proxysql-2-1-with-prometheus-grafana/
[18]: https://github.com/ProxySQL/proxysql-grafana-prometheus
[19]: http://proxysql.com/blog/proxysql-cluster
[20]: /detailed-answers-on-faq#question-10--stopshutdown-proxysql
[21]: /detailed-answers-on-faq#question-11--configure-default-hostgroup
[22]: https://proxysql.com/multiplexing/
[23]: /Multiplexing
[24]: /Configuring-ProxySQL#startup
[25]: https://proxysql.com/backend-monitoring/
[26]: /Users-configuration#disabling-routing-across-hostgroups-once-a-transaction-has-started-for-a-specific-user
[27]: https://github.com/sysown/proxysql/issues/337
[28]: http://catb.org/~esr/faqs/smart-questions.html
[29]: https://groups.google.com/forum/#!forum/proxysql
[30]: https://github.com/sysown/proxysql/issues/new
[31]: /ProxySQL-Configuration/#p6032
[32]: /ProxySQL-Configuration/#p6033
[33]: /ProxySQL-Configuration#mysql-query-rules
[34]: /ProxySQL-Configuration
[35]: https://proxysql.com/aws-aurora-configuration/
[36]: https://proxysql.com/galera-configuration/
[37]: https://proxysql.com/scheduler/
