proxysql-consul writes table contents corresponding to a configuration read from ProxySQL's admin interface to Consul's key/value store. proxysql-consul uses one key for each configuration type and each key is prefixed with 'proxysql' so that all ProxySQL keys live in their own namespace.

Example:
```
key: proxysql/mysql_servers
```

The value written is a JSON with multiple fields:
- config_name - the name of the configuration.
- uuid - unique identifier of the proxysql-consul instance.
- tables - one key/value pair for each of the tables that comprise the configuration. The key is the table name and the value is an array of rows. Each row is an array of string values.

Example:
```
{  
   "tables":{  
      "mysql_replication_hostgroups":[  

      ],
      "mysql_servers":[  
         [  
            "0",
            "127.0.0.1",
            "3306",
            "ONLINE",
            "1",
            "0",
            "1000",
            "10"
         ],
         [  
            "0",
            "/var/lib/mysql/mysql.sock",
            "0",
            "ONLINE",
            "1",
            "0",
            "1000",
            "0"
         ]
   },
   "config_name":"mysql_servers",
   "uuid":"aae13abd-2a76-4882-afd3-0b2369e02b07"
}
```

The example corresponds to the following mysql_servers dump (mysql_replication_hostgroups is empty):
```
+--------------+---------------------------+------+--------+--------+-------------+-----------------+---------------------+
| hostgroup_id | hostname                  | port | status | weight | compression | max_connections | max_replication_lag |
+--------------+---------------------------+------+--------+--------+-------------+-----------------+---------------------+
| 0            | 127.0.0.1                 | 3306 | ONLINE | 1      | 0           | 1000            | 10                  |
| 0            | /var/lib/mysql/mysql.sock | 0    | ONLINE | 1      | 0           | 1000            | 0                   |
+--------------+---------------------------+------+--------+--------+-------------+-----------------+---------------------+
```
