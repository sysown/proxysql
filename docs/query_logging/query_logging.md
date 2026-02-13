# Query Logging

ProxySQL is able to log queries that pass through: optionally, you can set it up to save to disk all the SQL
statements (or specific types of them) that are processed by the query processor and sent to backend
hostgroups.

Before version `v2.0.6`, logging is configured with Query Rules using `mysql_query_rules.log`: this allows
very broad or granular logging. From version 2.0.6 , a new global variable was added:
`mysql-eventslog_default_log` . If no matching rule specifies a value `mysql_query_rules.log` ,
`mysql-eventslog_default_log` applies. the default value for `mysql-eventslog_default_log` is `0`, and the
possible values are `0` and `1` .

## Setup

First, enable logging globally

```sql
SET mysql-eventslog_filename='queries.log';
```

The variable needs to be loaded at runtime, and eventually saved to disk:

```sql
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```

If you did not change the variable `mysql-eventslog_format` from its default setting of `1` (logging queries
in binary format) and you would like to log ALL queries, you do not need additional query rules for it to take
effect, but you need to enable the global variable `mysql-eventslog_default_log`. **Note:** not all queries
are processed by the query processor. Some special queries like `commit`, `rollback` and `set autocommit` are
handled before the query processor. If you want to log also such queries it is required to enable logging
globally.

```sql
SET mysql-eventslog_default_log=1;
```

The variable needs to be loaded at runtime, and eventually saved to disk:

```sql
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```

If you changed the variable `mysql-eventslog_format` to `2` (logging queries in JSON format, see below),
and/or you would only like to log queries matching certain criteria, you need additional query rules in the
following manner: If you don't trust Bob, you can log all of Bob's queries:

```sqlhttps://proxysql.com/documentation/global-variables/mysql-variables/#mysql-auditlog_filename
INSERT INTO mysql_query_rules (rule_id, active, username, log, apply) VALUES (1, 1, 'Bob', 1, 0);
```

If you want to log all `INSERT` statements against table `tableX`:

```sql
INSERT INTO mysql_query_rules (rule_id, active, match_digest, log, apply) VALUES (1, 1, 'INSERT.*tableX', 1, 0);
```

Now, make the rules active and persistent:

```SQL
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;
```

## Query Logging Format before 2.0.6

Before version 2.0.6 , the queries are logged in binary format. There is a sample app included in source that
can read the binary files and output plain text. The sample app is not included in the binary distribution.

```bash
$ ./tools/eventslog_reader_sample /var/lib/proxysql/file1.log.00001258
ProxySQL LOG QUERY: thread_id="2" username="root" schemaname=information_schema" client="127.0.0.1:58307" HID=0 server="127.0.0.1:3306" starttime="2016-10-23 12:34:37.132509" endtime="2016-10-23 12:34:38.347527" duration=1215018us digest="0xC5C3C490CA0825C1"
select sleep(1)
ProxySQL LOG QUERY: thread_id="2" username="root" schemaname=information_schema" client="127.0.0.1:58307" HID=0 server="127.0.0.1:3306" starttime="2016-10-23 12:41:38.604244" endtime="2016-10-23 12:41:38.813587" duration=209343us digest="0xE9D6D71A620B328F"
SELECT DATABASE()
ProxySQL LOG QUERY: thread_id="2" username="root" schemaname=test" client="127.0.0.1:58307" HID=0 server="127.0.0.1:3306" starttime="2016-10-23 12:42:38.511849" endtime="2016-10-23 12:42:38.712609" duration=200760us digest="0x524DB8D7A9B4C132"
select aaaaaaa
```

[https://github.com/sysown/proxysql/tree/v2.0.5/tools][1] To build the sample app:

- Clone the repo / Download the source
- Change to tools directory
- execute `make`

<!-- -->

## Query Logging Format from 2.0.6

In version 2.0.6 a new variable controls the query logging format: `mysql-eventslog_format`. Possible values:

- `1` : this is the default: queries are logged in binary format (like before 2.0.6) Note that in version
  2.0.6 were introduced better support for prepared statements and the logging of `rows_affected` and
  `rows_sent`. For this reason make sure to use an updated `eventslog_reader_sample` to read these files.
- `2` : the queries are logged in JSON format.

<!-- -->

### JSON format logging

To enable logging in JSON format it is required to set `mysql-eventslog_format=2`.

```sql
SET mysql-eventslog_format=2;
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```

Example of JSON logging:

```
~/proxysql/tools$ cat /var/lib/proxysql/events.00000001
{"client":"127.0.0.1:39840","digest":"0x226CD90D52A2BA0B","duration_us":0,"endtime":"2019-07-14 18:04:28.595961","endtime_timestamp_us":1563091468595961,"event":"COM_QUERY","hostgroup_id":-1,"query":"select @@version_comment limit 1","rows_affected":0,"rows_sent":0,"schemaname":"information_schema","starttime":"2019-07-14 18:04:28.595961","starttime_timestamp_us":1563091468595961,"thread_id":2,"username":"sbtest"}
{"client":"127.0.0.1:39840","digest":"0x1E092DAEFFBBF262","duration_us":8570,"endtime":"2019-07-14 18:04:34.400688","endtime_timestamp_us":1563091474400688,"event":"COM_QUERY","hostgroup_id":0,"query":"select 1","rows_affected":0,"rows_sent":1,"schemaname":"information_schema","server":"127.0.0.1:3306","starttime":"2019-07-14 18:04:34.392118","starttime_timestamp_us":1563091474392118,"thread_id":2,"username":"sbtest"}
{"client":"127.0.0.1:39840","digest":"0x620B328FE9D6D71A","duration_us":552,"endtime":"2019-07-14 18:04:46.129106","endtime_timestamp_us":1563091486129106,"event":"COM_QUERY","hostgroup_id":0,"query":"SELECT DATABASE()","rows_affected":0,"rows_sent":1,"schemaname":"information_schema","server":"127.0.0.1:3306","starttime":"2019-07-14 18:04:46.128554","starttime_timestamp_us":1563091486128554,"thread_id":2,"username":"sbtest"}
{"client":"127.0.0.1:39840","digest":"0x02033E45904D3DF0","duration_us":3412,"endtime":"2019-07-14 18:04:46.136484","endtime_timestamp_us":1563091486136484,"event":"COM_QUERY","hostgroup_id":0,"query":"show databases","rows_affected":0,"rows_sent":2,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:04:46.133072","starttime_timestamp_us":1563091486133072,"thread_id":2,"username":"sbtest"}
{"client":"127.0.0.1:39840","digest":"0x99531AEFF718C501","duration_us":580,"endtime":"2019-07-14 18:04:46.137842","endtime_timestamp_us":1563091486137842,"event":"COM_QUERY","hostgroup_id":0,"query":"show tables","rows_affected":0,"rows_sent":2,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:04:46.137262","starttime_timestamp_us":1563091486137262,"thread_id":2,"username":"sbtest"}
{"client":"127.0.0.1:39840","digest":"0xF434DBD7D158BC81","duration_us":10921,"endtime":"2019-07-14 18:05:05.769079","endtime_timestamp_us":1563091505769079,"event":"COM_QUERY","hostgroup_id":0,"query":"update test1 set id2=3 where id%2=0","rows_affected":2050,"rows_sent":0,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:05:05.758158","starttime_timestamp_us":1563091505758158,"thread_id":2,"username":"sbtest"}
{"client":"127.0.0.1:39840","digest":"0xB99A00381BD4F14D","duration_us":5560,"endtime":"2019-07-14 18:05:15.773149","endtime_timestamp_us":1563091515773149,"event":"COM_QUERY","hostgroup_id":0,"query":"select * from test1","rows_affected":0,"rows_sent":4099,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:05:15.767589","starttime_timestamp_us":1563091515767589,"thread_id":2,"username":"sbtest"}
{"client":"127.0.0.1:39840","digest":"0xF7E581BFC13DA7A4","duration_us":1783,"endtime":"2019-07-14 18:05:27.185155","endtime_timestamp_us":1563091527185155,"event":"COM_QUERY","hostgroup_id":0,"query":"SELECT * from test1 LIMIT 1000","rows_affected":0,"rows_sent":1000,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:05:27.183372","starttime_timestamp_us":1563091527183372,"thread_id":2,"username":"sbtest"}
{"client":"127.0.0.1:39958","digest":"0x1E180DC9CAA12D69","duration_us":252,"endtime":"2019-07-14 18:06:03.283974","endtime_timestamp_us":1563091563283974,"event":"COM_STMT_PREPARE","hostgroup_id":0,"query":"SELECT id,id2 FROM test1 WHERE id= ?","rows_affected":0,"rows_sent":0,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:06:03.283722","starttime_timestamp_us":1563091563283722,"thread_id":3,"username":"sbtest"}
{"client":"127.0.0.1:39958","digest":"0x1E180DC9CAA12D69","duration_us":186,"endtime":"2019-07-14 18:06:03.284413","endtime_timestamp_us":1563091563284413,"event":"COM_STMT_EXECUTE","hostgroup_id":0,"query":"SELECT id,id2 FROM test1 WHERE id= ?","rows_affected":0,"rows_sent":0,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:06:03.284227","starttime_timestamp_us":1563091563284227,"thread_id":3,"username":"sbtest"}
{"client":"127.0.0.1:39958","digest":"0x98A2503010E9E4C8","duration_us":366,"endtime":"2019-07-14 18:06:03.285029","endtime_timestamp_us":1563091563285029,"event":"COM_STMT_PREPARE","hostgroup_id":0,"query":"SELECT id,id2 FROM test1 WHERE id < ?","rows_affected":0,"rows_sent":0,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:06:03.284663","starttime_timestamp_us":1563091563284663,"thread_id":3,"username":"sbtest"}
{"client":"127.0.0.1:39958","digest":"0x98A2503010E9E4C8","duration_us":1491,"endtime":"2019-07-14 18:06:03.286928","endtime_timestamp_us":1563091563286928,"event":"COM_STMT_EXECUTE","hostgroup_id":0,"query":"SELECT id,id2 FROM test1 WHERE id < ?","rows_affected":0,"rows_sent":4099,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:06:03.285437","starttime_timestamp_us":1563091563285437,"thread_id":3,"username":"sbtest"}
{"client":"127.0.0.1:39960","digest":"0x1E180DC9CAA12D69","duration_us":0,"endtime":"2019-07-14 18:06:04.011205","endtime_timestamp_us":1563091564011205,"event":"COM_STMT_PREPARE","hostgroup_id":-1,"query":"SELECT id,id2 FROM test1 WHERE id= ?","rows_affected":0,"rows_sent":0,"schemaname":"test","starttime":"2019-07-14 18:06:04.011205","starttime_timestamp_us":1563091564011205,"thread_id":4,"username":"sbtest"}
{"client":"127.0.0.1:39960","digest":"0x1E180DC9CAA12D69","duration_us":240,"endtime":"2019-07-14 18:06:04.011697","endtime_timestamp_us":1563091564011697,"event":"COM_STMT_EXECUTE","hostgroup_id":0,"query":"SELECT id,id2 FROM test1 WHERE id= ?","rows_affected":0,"rows_sent":0,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:06:04.011457","starttime_timestamp_us":1563091564011457,"thread_id":4,"username":"sbtest"}
{"client":"127.0.0.1:39960","digest":"0x98A2503010E9E4C8","duration_us":0,"endtime":"2019-07-14 18:06:04.011912","endtime_timestamp_us":1563091564011912,"event":"COM_STMT_PREPARE","hostgroup_id":-1,"query":"SELECT id,id2 FROM test1 WHERE id < ?","rows_affected":0,"rows_sent":0,"schemaname":"test","starttime":"2019-07-14 18:06:04.011912","starttime_timestamp_us":1563091564011912,"thread_id":4,"username":"sbtest"}
{"client":"127.0.0.1:39960","digest":"0x98A2503010E9E4C8","duration_us":1492,"endtime":"2019-07-14 18:06:04.013779","endtime_timestamp_us":1563091564013779,"event":"COM_STMT_EXECUTE","hostgroup_id":0,"query":"SELECT id,id2 FROM test1 WHERE id < ?","rows_affected":0,"rows_sent":4099,"schemaname":"test","server":"127.0.0.1:3306","starttime":"2019-07-14 18:06:04.012287","starttime_timestamp_us":1563091564012287,"thread_id":4,"username":"sbtest"}
```

## Sampling

A new variable `mysql-eventslog_rate_limit` is introduced to control the sampling rate for event logs. When set to `1` (default),
all events are logged to the file. When set to a value greater than `1`, the number of events logged to the file will be
approximately equal to `1/N`, where `N` is the value set for the variable.

**To log all events (default)**

```sql
SET mysql-eventslog_rate_limit=1;
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```

**To log events at a certain sampling rate**

```sql
SET mysql-eventslog_rate_limit=100;
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```

## Logging at high RPS

Logging queries at high throughput often requires tuning `mysql-eventslog_flush_timeout` and `mysql-eventslog_flush_size`.
These variables determine when the log entries stored in temporary buffers are flushed to the file on disk.

**Time based flush**

`mysql-eventslog_flush_timeout` triggers a flush when the time elapsed since the last flush exceeds the specified timeout value.

**Size based flush**

`mysql-eventslog_flush_size` triggers a flush when the buffer size (in bytes) exceeds the specified limit. Note that each worker thread maintains its own temporary buffer for log entries. Therefore, this variable should be tuned based on the available hardware resources. Increasing this value will increase memory consumption, roughly calculated as the number of worker threads multiplied by the flush size.

```sql
SET mysql-eventslog_flush_timeout=5000;
SET mysql-eventslog_flush_size=16*1024;
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```

## Related Issues and Feature Requests

Here's some related discussion on this feature.

- [Issue #561][2]: Logging all queries.
- [Feature Request #871][3]: Logging in JSON format for Splunk/ElasticStack, etc.
- [Feature Request #1184][4]: Logging to Embedded Database.

[1]: https://github.com/sysown/proxysql/tree/v2.0.5/tools
[2]: https://github.com/sysown/proxysql/issues/561
[3]: https://github.com/sysown/proxysql/issues/871
[4]: https://github.com/sysown/proxysql/issues/1184
