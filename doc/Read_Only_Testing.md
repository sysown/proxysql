

### Compiling

To run `read_only` automated testing, ProxySQL needs to be compiled with `make testreadonly`.



### shutdown mysqld

When running automated testing, ProxySQL will listen on many IPs (30) an on port 3306.  
You need to make sure that MySQL server is not running, or not listening on port 3306.


### Running proxysql

`proxysql` needs to be executed with `--sqlite3-server` .  
For example, to run it under `gdb`: `run -f -D . --sqlite3-server`


### Similate failover

To simulate failover is enough to connect to sqlite3 server interface and update the `READONLY_STATUS` table.  
Note that to connect it is necessary to use a user configured in `mysql_users` table.  
To simulate a lot of failover at the same time, a query like the follow can be executed:  

```
 UPDATE READONLY_STATUS SET read_only=1; CREATE TABLE t1 AS SELECT hostname FROM READONLY_STATUS ORDER BY RANDOM() LIMIT 50; UPDATE READONLY_STATUS SET read_only=0 WHERE hostname IN (SELECT hostname FROM t1); DROP TABLE t1;
```
