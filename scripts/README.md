### Scripts description

This is a set of example scripts to show the capabilities of the RESTAPI interface and how to interface with it.

### Prepare ProxySQL

1. Launch ProxySQL:

```
./src/proxysql -M --sqlite3-server --idle-threads -f -c $PATH/restapi_examples/datadir/proxysql.cnf -D $PATH/restapi_examples/datadir
```

2. Configure ProxySQL:

```
cd $RESTAPI_EXAMPLES_DIR
./proxysql_config.sh
```

3. Install requirements

```
cd $RESTAPI_EXAMPLES_DIR/requirements
./install_requirements.sh
```

### Query the endpoints

1. Flush Query Cache: `curl -i -X GET http://localhost:6070/sync/flush_query_cache`
2. Change host status:
    - Assuming local ProxySQL:
      ```
      curl -i -X POST -d '{ "hostgroup_id": "", "hostname": "sbtest1", "port": 3306, "status": "OFFLINE_HARD" }' http://localhost:6070/sync/change_host_status
      ```
    - Specifying server:
      ```
      curl -i -X POST -d '{ "admin_host": "127.0.0.1", "admin_port": "6032", "admin_user": "radmin", "admin_pass": "radmin", "hostgroup_id": "0", "hostname": "sbtest1", "port": 3306, "status": "ONLINE_HARD" }' http://localhost:6070/sync/change_host_status
      ```
2. Add or replace MySQL user:
    - Assuming local ProxySQL:
      ```
      curl -i -X POST -d '{ "user": "sbtest1", "pass": "sbtest1" }' http://localhost:6070/sync/add_mysql_user
      ```
    - Add user and load to runtime (Assuming local instance):
      ```
      curl -i -X POST -d '{ "user": "sbtest1", "pass": "sbtest1", "to_runtime": 1 }' http://localhost:6070/sync/add_mysql_user
      ```
    - Specifying server:
      ```
      curl -i -X POST -d '{ "admin_host": "127.0.0.1", "admin_port": "6032", "admin_user": "radmin", "admin_pass": "radmin", "user": "sbtest1", "pass": "sbtest1" }' http://localhost:6070/sync/add_mysql_user
      ```
3. Kill idle backend connections:
    - Assuming local ProxySQL:
      ```
      curl -i -X POST -d '{ "timeout": 10 }' http://localhost:6070/sync/kill_idle_backend_conns
      ```
    - Specifying server:
      ```
      curl -i -X POST -d '{ "admin_host": "127.0.0.1", "admin_port": 6032, "admin_user": "radmin", "admin_pass": "radmin", "timeout": 10 }' http://localhost:6070/sync/kill_idle_backend_conns
      ```
4. Scrap tables from 'stats' schema:
    - Assuming local ProxySQL:
      ```
      curl -i -X POST -d '{ "table": "stats_mysql_users" }' http://localhost:6070/sync/scrap_stats
      ```
    - Specifying server:
      ```
      curl -i -X POST -d '{ "admin_host": "127.0.0.1", "admin_port": 6032, "admin_user": "radmin", "admin_pass": "radmin", "table": "stats_mysql_users" }' http://localhost:6070/sync/scrap_stats
      ```

### Scripts doc

- All scripts allows to perform the target operations on a local or remote ProxySQL instance.
- Notice how the unique 'GET' request is for 'QUERY CACHE' flushing, since it doesn't require any parameters.
