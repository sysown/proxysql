## Overview

Since release 2.4.5 ProxySQL DNS caching is available. Historically, whenever client connection took
place, a Domain Name System (DNS) lookup for each client connection was performed. DNS lookup or DNS querying
is a blocking process and impacts performance if DNS server is slow or misconfigured. By caching the results,
the server avoids doing a DNS lookup for each client connection for a given host.

## Feature

ProxySQL DNS caching allows storing DNS records locally and re-using them in future, eliminating the need for
new DNS queries. Every DNS record has a time-to-live (TTL). TTL specifies the expiry time of the record and is
managed using **`mysql-monitor_local_dns_cache_ttl`** variable. DNS records are checked after every interval
and expired records are refreshed by issuing a DNS query. The interval value is specified in
**`mysql-monitor_local_dns_cache_refresh_interval`** variable. Other than that, cached records are checked
when **`mysql_servers`** and **`proxysql_servers`** tables are updated. If the domain contains multiple mapped
IPs, the load is balanced among them in a round-robin fashion on socket connection.

## Configuration

By default, DNS caching is enabled with these values:

```sqlmysql&gt; SELECT * FROM global_variables WHERE Variable_Name LIKE 'mysql-monitor_local_dns_%';
+------------------------------------------------+----------------+
| Variable_Name                                  | Variable_Value |
+------------------------------------------------+----------------+
| mysql-monitor_local_dns_cache_ttl              | 300000         |
| mysql-monitor_local_dns_cache_refresh_interval | 60000          |
| mysql-monitor_local_dns_resolver_queue_maxsize | 128            |
+------------------------------------------------+----------------+
3 rows in set (0.01 sec)
```

They represent:

- `mysql-monitor_local_dns_cache_ttl` : 300000 (ms) - TTL time-to-live per DNS record.
- `mysql-monitor_local_dns_cache_refresh_interval` : 60000 (ms) - Refresh interval at which monitor DNS cache
  entries, `mysql_servers` and `proxysql_servers` will be re-check for new records.
- `mysql-monitor_local_dns_resolver_queue_maxsize` : 128 - Determines how much the DNS resolver queue can grow
  before starting new monitoring helper threads, up to 32 threads.

<!-- -->

Setting value of **`mysql-monitor_local_dns_cache_ttl`** or
**`mysql-monitor_local_dns_cache_refresh_interval`** to **`'0'`** disables DNS caching feature.

## Metrics

Metrics related to DNS Caching are available through the stats table **`stats_mysql_global`**:

```sqlmysql&gt; SELECT * FROM stats_mysql_global WHERE Variable_Name LIKE 'MySQL_Monitor_dns_cache_%';
+----------------------------------------+----------------+
| Variable_Name                          | Variable_Value |
+----------------------------------------+----------------+
| MySQL_Monitor_dns_cache_queried        | 65             |
| MySQL_Monitor_dns_cache_lookup_success | 60             |
| MySQL_Monitor_dns_cache_record_updated | 30             |
+----------------------------------------+----------------+
3 rows in set (0.01 sec)
```

They represent:

- `proxysql_mysql_monitor_dns_cache_queried`: Times the DNS cache has been queried.
- `proxysql_mysql_monitor_dns_cache_lookup_success`: Times a DNS record was found in DNS cache on lookup
  (cache hit).
- `proxysql_mysql_monitor_dns_cache_record_updated`: Times a DNS records were updated (added, removed, or
  modified).

<!-- -->
