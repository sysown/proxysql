# SSL configuration

ProxySQL supports SSL connections to the backends since version v1.2.0e . Attempts to configure an older version will fails.


To enabled SSL connections you need to:
* update `mysql_servers`.`use_ssl` for the server you want to use SSL;
* update associated global variables.


If you want to connect to the same server with both SSL and non-SSL you need to configure the same server in two different hostgroups, and define access rules.
For example, to configure SSL on one server:
```sql
mysql> SELECT * FROM mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| 1            | 127.0.0.1 | 21891 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
| 2            | 127.0.0.1 | 21892 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
| 2            | 127.0.0.1 | 21893 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
3 rows in set (0.00 sec)

mysql> UPDATE mysql_servers SET use_ssl=1 WHERE port=21891;
Query OK, 1 row affected (0.00 sec)

mysql> SELECT * FROM mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| 1            | 127.0.0.1 | 21891 | ONLINE | 1      | 0           | 1000            | 0                   | 1       | 0              |
| 2            | 127.0.0.1 | 21892 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
| 2            | 127.0.0.1 | 21893 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
3 rows in set (0.00 sec)

mysql> LOAD MYSQL SERVERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

mysql> SELECT * FROM runtime_mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| 1            | 127.0.0.1 | 21891 | ONLINE | 1      | 0           | 1000            | 0                   | 1       | 0              |
| 2            | 127.0.0.1 | 21892 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
| 2            | 127.0.0.1 | 21893 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
3 rows in set (0.00 sec)

```

At this stage, trying to connect to host 127.0.0.1 and port 21891 **will not** use SSL because no key and no certificate are configured. Instead, normal non-SSL connections will be established.


The next step to use SSL connections is to configure key and certificate.

```sql
mysql> SELECT * FROM global_variables WHERE variable_name LIKE 'mysql%ssl%';
+--------------------+----------------+
| variable_name      | variable_value |
+--------------------+----------------+
| mysql-ssl_p2s_ca   | (null)         |
| mysql-ssl_p2s_cert | (null)         |
| mysql-ssl_p2s_key  | (null)         |
+--------------------+----------------+
3 rows in set (0.00 sec)

mysql> SET mysql-ssl_p2s_cert="/home/vagrant/newcerts/client-cert.pem";
Query OK, 1 row affected (0.00 sec)

mysql> SET mysql-ssl_p2s_key="/home/vagrant/newcerts/client-key.pem";
Query OK, 1 row affected (0.00 sec)

mysql> SELECT * FROM global_variables WHERE variable_name LIKE 'mysql%ssl%';
+--------------------+----------------------------------------+
| variable_name      | variable_value                         |
+--------------------+----------------------------------------+
| mysql-ssl_p2s_ca   | (null)                                 |
| mysql-ssl_p2s_cert | /home/vagrant/newcerts/client-cert.pem |
| mysql-ssl_p2s_key  | /home/vagrant/newcerts/client-key.pem  |
+--------------------+----------------------------------------+
3 rows in set (0.01 sec)

mysql> LOAD MYSQL VARIABLES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```


At this point, all **new connections** to host 127.0.0.1 and port 21891 will use SSL.


If you are happy with the new changes, you can make them persistent saving the configuration on disk:
```sql
mysql> SAVE MYSQL SERVERS TO DISK;
Query OK, 0 rows affected (0.01 sec)

mysql> SAVE MYSQL VARIABLES TO DISK;
Query OK, 58 rows affected (0.00 sec)
```


Happy SSLing!
