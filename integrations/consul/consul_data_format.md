proxysql-consul writes table contents read from ProxySQL's admin interface to Consul's key/value store. proxysql-consul uses one key for each table and each key is prefixed with 'proxysql' so that all ProxySQL keys live in their own namespace.

Example:
```
key: proxysql/mysql_servers
```

The value written is a JSON with multiple fields:
- table - the name of the table.
- uuid - unique identifier of the proxysql-consul instance.
- rows - content of the table as an array of rows. Each row is an array of string values.

Example:
```
{  
   "table":"mysql_servers",
   "rows":[  
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
   ],
   "uuid":"aae13abd-2a76-4882-afd3-0b2369e02b07"
}
```

The value corresponds to the following mysql_servers dump:
```
+--------------+---------------------------+------+--------+--------+-------------+-----------------+---------------------+
| hostgroup_id | hostname                  | port | status | weight | compression | max_connections | max_replication_lag |
+--------------+---------------------------+------+--------+--------+-------------+-----------------+---------------------+
| 0            | 127.0.0.1                 | 3306 | ONLINE | 1      | 0           | 1000            | 10                  |
| 0            | /var/lib/mysql/mysql.sock | 0    | ONLINE | 1      | 0           | 1000            | 0                   |
+--------------+---------------------------+------+--------+--------+-------------+-----------------+---------------------+
```
