# ProxySQL Changelog

## Version 3.0.x Series - PostgreSQL Support Introduction

### v3.0.2 (2025-08-06)
#### PostgreSQL Enhancements
- Improved error processing and reporting format for backend connections using libpq (#4947)
- Fixed backend connection reset and parameter handling for `RESET/SET TO DEFAULT` (#5060)
- Fixed crash when mirroring is configured for PostgreSQL (#5051)
- Fixed memory leak during Admin startup in `flush_pgsql_variables___database_to_runtime` (#5037)
- Fixed `pgsql_replication_hostgroups` table definition - range for `check_type` now reflects only supported checks (#5043)

#### MySQL Fixes
- Added Group Replication support for MySQL 8.4 and 9.x (#4983)
- Fixed memory leak in `stats_mysql_global` (#5006)
- Fixed potential overflow in `SQLite3_memory_bytes` field from `stats_mysql_global` (#5006)
- Fixed MySQL binary log handling for prepared statements with 0 parameters (#5007)

#### Common Fixes
- Fixed memory leak in Query Processor during query rules deletion (#5037)

### v3.0.1 (2025-05-13)
#### Major PostgreSQL Features
- **Parameter/Variable Tracking**: Significantly improves multiplexing capabilities for better connection reuse (#4799)
- **Backend Monitoring Support**: Handles larger number of backend servers with small worker thread set (#4726)
  - Connect checks: Availability and connection latency assessment
  - Ping checks: Responsiveness with automatic SHUNNING and latency tracking
  - ReadOnly checks: Server placement via `pgsql_replication_hostgroups` with automatic failover
- **Transaction Support**: Variable state tracking through transactions and savepoints (SAVEPOINT/ROLLBACK) (#4929)
- **Connection Parameters**: Full support for all PostgreSQL connection parameters with server-side validation (#4899)
- **Notice and Warning Messages**: Support with Query Cache compatibility (#4770)
- **COPY Support**: Added support for `COPY ... FROM STDIN` via FAST FORWARD (#4762, #4874)

#### Major MySQL Features
- **Dual-Password Support**: Allows two passwords for password rotation like MySQL native feature
- **Enhanced Event and Query Logging** (ported from 2.7.2):
  - Real-time query logging in `stats_mysql_query_events` and `history_mysql_query_events`
  - MySQL Logger metrics exported through `stats_mysql_global` and Prometheus
  - Circular buffer with SQLite databases (in-memory and on-disk)
- **Prepared Statement Parameter Logging** (#4895, #4922):
  - Logs actual parameter values for prepared statements
  - Available in binary and JSON formats
  - Controlled by `mysql-eventslog_stmt_parameters` (disabled by default)
- **New PROXYSQL_METADATA Event**: Added metadata event in binary eventlog format (#4922)
- **DNS Cache Enhancement**: Better distribution of DNS resolution attempts (#4745)

#### Common Improvements
- **OpenSSL Changes**: Now uses system OpenSSL library (dynamically linked) instead of static (#4740)
- **Admin Performance**: Avoids unnecessary VACUUM operations on stats database (#4859)

### v3.0.0-alpha (2024-09-30)
- **Initial PostgreSQL Support**:
  - Default ports: 6132 (admin), 6133 (PostgreSQL traffic)
  - Authentication methods: Plain Text, MD5, SCRAM-SHA-256
  - PostgreSQL-specific configuration tables and options
  - SSL support for frontend and backend connections
  - Multiplexing and connection pooling
  - Multiple statements in single query support
- **Architecture Changes**:
  - Separate query processors for MySQL and PostgreSQL
  - Refactored Query Processor Architecture
  - New PostgreSQL statistics tables (pgsql_servers, pgsql_users, pgsql_query_rules, etc.)

## Version 2.7.x Series

### v2.7.3 (2025-03-11)
- Added PMM compatibility for `runtime_mysql_servers_*` metrics in Prometheus exporter (#4854)
- Ignore tracking for `session_track_system_variables` until properly supported (#4853, #4839)
- Added support for `@@session` and `@@global` syntax in SET statements parser (#4853)
- Fixed frontend/backend collation mismatch when collation ID larger than 255 (#4850)
- Fixed DELETE operations for `stats_mysql_query_events` on stats memory database (#4822)
- Fixed PMM compatibility for new MySQL_Logger metrics (#4822)

### v2.7.2 (2025-01-27)
#### Major Features
- **Enhanced Event and Query Logging** (#4713, #4802):
  - Real-time insights with circular buffer and SQLite databases
  - New tables: `stats_mysql_query_events` and `history_mysql_query_events`
  - MySQL Logger metrics in `stats_mysql_global` and Prometheus exporter
- MySQL protocol compression level control via `mysql-protocol_compression_level` (#4789)
- `mysql_hostgroup_attributes` configurable through config file (#4748)
- Randomized cache TTL queueing reducing helper thread needs (#4729)
- Integrity checks for malformed MySQL packets (#4742)

#### Bug Fixes
- Fixed crash on empty Admin interface queries (#4722)
- Fixed halt on `PROXYSQL RESUME` command (#4757)
- Fixed SSL cache leak for auxiliary threads (#4801)
- Fixed query cache storing behavior for `mysql-query_cache_stores_empty_result` (#4723)
- Fixed potential overflows for `mysql_thread___threshold_resultset_size` (#4733)

### v2.7.1 (2024-09-23)
- Added Fedora 41 builds (#4635)
- DNS Cache improvements - removes DNS records on connection failures (#4656)
- DNS cache auto-disabled with `-M` or `--no-monitor` option
- Faster packaging with optimized file operations (#4647)
- Fixed `--initial` option after crashes (#4659)
- Fixed TLS certificate reload after crashes (#4658)
- Fixed leading spaces in `stats_mysql_query_digest.digest` (#4646)
- Applied clang fix to all clang versions (#4635)

### v2.7.0 (2024-09-04)
#### Major Features
- **PROXY Protocol V1 Support**: Enables identifying original client IP behind load balancers
  - IP-based query rules for caching, routing, filtering
  - Improved processlist and audit logs showing original IPs
  - Enhanced security with IP-based access restrictions
- **Additional ProxySQL APT Repository Layout**: New common layout support
  - Example: `deb https://repo.proxysql.com/ProxySQL bookworm main`
- **Thread Naming**: Easier debugging with named threads

## Version 2.6.x Series

### v2.6.6 (2024-09-23)
- DNS Cache updates - removes outdated records on connection failures (#4656)
- DNS cache auto-disabled with `-M` or `--no-monitor` option
- Fixed leading spaces in `stats_mysql_query_digest.digest` (#4646)

### v2.6.5 (2024-08-29)
- Fixed USE command semicolon handling (#4629)
- Fixed `stats_mysql_query_digest.digest` case normalization (#4626)

### v2.6.4 (2024-08-27)
- Updated OpenSSL to v3.3.1 (#4561)
- Added Ubuntu 24 and Fedora 40 support (#4541)
- Improved USE query parsing for text protocol (#4605)
- Disabled AWS RDS topology auto-discovery by default (#4578)
- Fixed SSL error queue pollution causing invalid terminations (#4555, #4602)
- Fixed control chars in query digests (#4554) - **Note: Review mysql_query_rules if using extra spaces**
- Fixed `COM_CHANGE_USER` with hashed passwords for `native_mysql_password` (#4623)
- Fixed crashes for `COM_CHANGE_USER` with `caching_sha2_password` (#4619)

### v2.6.3 (2024-05-20)
#### Major Features
- **New Hostgroup Attributes**:
  - `monitor_slave_lag_when_null` for `hostgroup_settings` (#4528)
  - `max_num_online_servers` safety feature (#4517)
- Handle `SELECT LAST_INSERT_ID() FROM DUAL` without disabling multiplexing (#4520)
- Support SIGUSR1 for log rotation (#4502)

#### Bug Fixes
- Fixed client reconnect with SSL enabled (#4537)
- Fixed startup crashes from HTTP_Server/RESTAPI requests (#4518)
- Fixed memory leaks in Cluster and GTID Binlog Reader (#4546)

### v2.6.2 (2024-04-02)
- AWS RDS MySQL Multi-AZ Cluster auto-discovery (#4490, #4406)
- SQLite3 password management functions: `MYSQL_NATIVE_PASSWORD()`, `CACHING_SHA2_PASSWORD()` (#4479)
- Daemon restart with exponential backoff (#4480)
- Fixed invalid free for `caching_sha2_password` with `CLIENT_COMPRESS` (#4485)
- Fixed crash on invalid `stmt_id` for `COM_STMT_EXECUTE` (#4481)

### v2.6.1 (2024-03-21)
- Multiple fixes for `mysql_servers_ssl_params` (#4467)
- Fixed Prometheus `connection_pool` metrics reset (#4470)
- Added `session_id` to error log for lagging/offline server detection

### v2.6.0 (2024-03-04)
#### Major Features
- **`caching_sha2_password` Authentication Support**:
  - Deprecated `admin-hash_passwords`
  - New variable `mysql-default_authentication_plugin`
- **`mysql_servers_ssl_params` Table**: Per-host SSL configuration (#4458)
- **New Web Interface** via Web Interface Plugin
- **Enhanced LDAP Support** via LDAP Plugin
- **Warnings Handling**: `SHOW WARNINGS` support with control variables (#4365)
- **Group Replication Autodiscovery** for MySQL 8 (#4208)
- **Bootstrap Mode** for MySQL 8 Group Replication (#4232)
- **ProxySQL Cluster**: New synchronization algorithm for `mysql_servers` (#4169)

#### Dependency Updates
- libmariadbclient: 3.1.9 â†’ 3.3.8 (#4407)
- OpenSSL: 3.1.4 â†’ 3.2.1 (#4360, #4371, #4447, #4448)
- SQLite3: 3.42 â†’ 3.43.2 (#4363)
- curl: 7.87.0 â†’ 8.4.0 (#4359)
- libhttpserver: 0.9.75 â†’ 0.9.77 (#4362)

## Version 2.5.x Series

### v2.5.5 (2023-08-18)
- Fixed file descriptor leak with SSL CA certificates (regression from 2.5.1) (#4307)
- Fixed infinite loop when SSL frontend connection terminated during handshake (#4321)
- Fixed COMMIT/ROLLBACK filtering after backend errors (#4306)

### v2.5.4 (2023-07-19)
- Reworked SET parser implementation (disabled by default) (#4274)
- Added `SET TRANSACTION ISOLATION LEVEL` support (#4280, #4283)
- Added error code classification for Prometheus MySQL errors (#4290)
- Fixed utf8mb3 charset crashes (#4269)
- Fixed `read_only_actions` crash with OFFLINE_SERVERS (#4288)

### v2.5.3 (2023-06-21)
- Debian 12 support (#4265)
- SQLite3 3.42.0 (#4263)
- SSLKEYLOGFILE support via `admin-ssl_keylog_file` (#4236)
- New troubleshooting features: `mysql-data_packets_history_size`, `coredump_filters` (#4225)
- Fixed DNS cache configuration file loading (#4235)
- Fixed invalid reads in fast-forward sessions (#4229)

### v2.5.2 (2023-05-12)
- OpenSSL 3.1.0 (#4165)
- Weighted flagOUTs for `mysql_query_rules` (#4202)
- Monitor read-only actions rework - lighter operations (#4127)
- Query digest generation optimization (#4096)
- New `mysql-query_rules_fast_routing_algorithm` variable (#4182)
- Core dump generation on demand (x86-64 Linux only) (#4188)

### v2.5.1 (2023-03-09)
- `mysql_hostgroup_attributes.init_connect` support (#4110)
- Multiple binlog clients per username (#4105)
- x509 shared cache for faster SSL connections (#4120)
- OpenSSL 3.0.8 security update (#4122)
- Fixed fast_forward encryption for binlog commands (#4114)

### v2.5.0 (2023-02-05)
- Asynchronous parallel fetching for Monitor module (#4063)
- Group Replication one-thread-per-cluster monitoring (#4082)
- Native MySQL 8 Group Replication monitoring (#4082)
- `mysql_hostgroup_attributes` feature with multiplex/free_connections_pct/throttle (#4091)
- COM_BINLOG_DUMP/COM_BINLOG_DUMP_GTID/COM_REGISTER_SLAVE support (#3807)
- Query Cache soft TTL (#4086)
- Major dependency upgrades (cityhash, clickhouse-cpp, curl, json, etc.) (#4069)

## Version 2.4.x Series

### v2.4.8 (2023-02-14)
- **Security**: OpenSSL 3.0.8 with multiple CVE fixes (#4118)

### v2.4.7 (2023-01-18)
- Fixed SSL connection hangs under edge conditions (#4083)

### v2.4.6 (2023-01-12)
- fast_forward SSL support (#4062)
- Fedora 37 builds (#4058)
- Fixed autocommit reporting issues (#4052)
- Fixed replica shunning when `max_replication_lag = 0` (#4077)

### v2.4.5 (2022-12-12)
- OpenSSL 3.0.7 (#4007)
- RESTAPI improvements (#4046)
- ProxySQL local DNS Cache feature (#4024)
- Fixed malformed packet with MariaDB fast_forward (#3996)
- Fixed compressed packet handling (#3995)

### v2.4.4 (2022-09-15)
- AWS Aurora isolation level fixes (#3976)
- Fixed multiplexing with cached STMT (#3970)
- Fixed crashes with high server counts (#3973)

### v2.4.3 (2022-08-15)
- Cluster fetch query processing improvements (#3930, #3921)
- OpenSSL 3.0.5 performance fix (#3938)
- ClickHouse 2.1.0 with CLIENT_DEPRECATE_EOF (#3888)

### v2.4.2 (2022-06-27)
- AlmaLinux 9 builds (#3884)
- Fixed query digest parsing crashes (#3889, #3901)

### v2.4.1 (2022-05-13)
- GCC 12.1.0 compilation fixes (#3877, #3875)

### v2.4.0 (2022-05-11)
#### Major Features
- Session variable `transaction_isolation` no longer disables multiplexing (#3664)
- OpenSSL 3.0.2 (#3844, #3675)
- New `mysql-unshun_algorithm` variable (#3649)
- `COM_RESET_CONNECTION` support for frontend (#3645)
- Query digest improvements with grouping controls (#3680)
- Session variable parsing improvements (#3702, #3754)
- ProxySQL Cluster UUID support (#3305)
- AWS Aurora auto-discovery
- New builds: OpenSuse15, AlmaLinux, Fedora34, Ubuntu22

## Version 2.3.x Series

### v2.3.2 (2021-10-01)
- Fixed `get_multiple_idle_connections()` preventing backend pings (#3628)
- Fixed SET variable parsing with '@@' (#3647)
- Fixed crashes with client_error_limit and timeouts (#3646)

### v2.3.1 (2021-09-16)
- Fixed Client Error Limit initialization issues (#3627)

### v2.3.0 (2021-09-15)
#### Major Features
- TLS files runtime reload with `PROXYSQL TLS RELOAD` (#3552)
- Enhanced SPIFFE authentication (#3552)
- Private key support beyond RSA (e.g., EC keys) (#3552)
- Certificate revocation list (CRL) and multiple CA support (#3577)
- Client Error Limit auto-blocking feature (#3617)
- Group replication monitoring improvements (#3533)
- Per-user default transaction isolation level (#3466)
- Aurora improvements for replicas with zero lag (#3515)
- LDAP authentication rework (#3491)

## Version 2.2.x Series

### v2.2.2 (2021-09-08)
- Fixed USE statement parsing issues (#3610)
- Fixed prepared statement NULL value preservation (#3604)
- Fixed RESTAPI socket fd issues (#3611)

### v2.2.1 (2021-09-02)
- Grave accent support in SET statements (#3479)
- USE statement comment support (#3493)
- Fixed memory leaks and corruptions in prepared statements (#3544, #3546)
- Fixed fast_forward CLIENT_DEPRECATE_EOF mismatch (#3560)

### v2.2.0 (2021-06-08)
- Query annotations evaluation for prepared statements (#3453)
- LDAP global variables synchronization (#3419)
- re2 library with -fPIC (#3405)
- Fixed crashes with invalid metadata access (#3461)
- Fixed query rules processing for prepared statements (#3427)

## Version 2.1.x Series

### v2.1.1 (2021-04-21)
- Fixed collation issues (MySQL bugs #102265, #102266) (#3249, #3276)
- Fixed ARM CentOS startup abort (#3256)
- Fixed memory corruptions (#3263, #3350)
- Fixed PXC reader connections during maintenance (#3182)
- SPIFFE support (#3343)
- Prepared statements buffering (#3295)

### v2.1.0 (2021-01-13)
#### Major Features
- **Built-in Prometheus Exporter**: Native metrics endpoint
- Routing metadata caching prevention for COM_STMT_EXECUTE
- ProxySQL Cluster SSL support (#2748)
- Cluster version verification (#2750)
- Extended cluster synchronization (galera, group_replication, aurora) (#2687)
- SQLite3 plugin support (#2821)
- Oracle mysqlsh support (#2854)
- New `attributes` column for mysql_users (#3083) and mysql_query_rules (#3088)
- Initial CLIENT_DEPRECATE_EOF support (text protocol only)
- Honor `wsrep_sst_donor_rejects_queries` for Galera (#3227)

## Version 2.0.x Series (Selected Major Releases)

### v2.0.18 (2021-04-08)
- Improved prepared statement metadata handling (#1574)
- Fixed infinite loops and memory issues
- Fixed connection dropping from PXC readers (#3182)

### v2.0.15 (2020-10-29)
- ARM64 packages and Docker images
- `mysql-max_transaction_idle_time` and `mysql-max_transaction_time` variables
- Per-thread connection cache re-enabled

### v2.0.10 (2020-02-17)
- Fixed client stalls when no backends available (#2536)
- Fixed Galera issues with pxc_maint_mode (#2537, #2533)
- Firewall whitelist fixes (#2534)

### v2.0.1 (2019-01-25)
- MySQL replication hostgroups extended with `check_type` field
- GTID causal reads implementation
- Frontend SSL support
- Native Galera Cluster support
- LDAP authentication support
- DNS cache implementation
- Security: firewall whitelist and SQL injection engine

## Version 1.4.x Series (Selected)

### v1.4.16 (2020-01-20)
- COM_FIELD_LIST support
- mysql-keep_multiplexing_variables variable
- Integer overflow fixes

### v1.4.1 (2017-08-01)
- Native MySQL Group Replication support
- PCRE and RC2 regex engines
- Background thread for connection reset
- FreeBSD and ARM CPU support
