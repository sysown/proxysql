

On Admin:

```sql
insert into mysql_servers (hostgroup_id, hostname, port) values (100,'127.0.0.1',6030);
insert into mysql_users (username,password,default_hostgroup) values ('sqlite','sqlite',100);

save mysql users to disk;
load mysql users to runtime;
save mysql servers to disk;
load mysql servers to runtime;



INSERT INTO mysql_query_rules (active,username,match_digest,match_pattern,replace_pattern,apply) values (1,'sqlite','^CREATE TABLE sbtest','id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT','id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT',0);
INSERT INTO mysql_query_rules (active,username,match_digest,match_pattern,replace_pattern,apply) values (1,'sqlite','^CREATE TABLE sbtest',"pad CHAR\(60\) DEFAULT '' NOT NULL,","pad CHAR(60) DEFAULT '' NOT NULL",0);
INSERT INTO mysql_query_rules (active,username,match_digest,match_pattern,replace_pattern,apply) values (1,'sqlite','^CREATE TABLE sbtest','PRIMARY KEY \(id\)','',0);

save mysql query rules to disk;
load mysql query rules to runtime;
```

Sysbbench:

```shell
sysbench --db-driver=mysql --test=/usr/share/sysbench/tests/include/oltp_legacy/oltp.lua --oltp-tables-count=10 --oltp-table-size=10000 --mysql-host=127.0.0.1 --mysql-db=test --mysql-engine-trx=yes --mysql-port=6033 --mysql-user=sqlite --mysql-password=sqlite --num-threads=10 prepare
```

```shell
sysbench --report-interval=3 --db-driver=mysql /usr/share/sysbench/tests/include/oltp_legacy/oltp.lua  --time=15  --oltp-tables-count=10 --oltp-table-size=10000 --mysql-host=127.0.0.1 --mysql-db=test --mysql-engine-trx=yes --oltp-skip-trx=off --mysql-port=6033 --mysql-user=sqlite --mysql-password=sqlite --threads=10 run
```
