# PostgreSQL Tables

This section documents all tables related to the PostgreSQL protocol in ProxySQL, including configuration and runtime tables.

## List of PostgreSQL Tables

| Tablename | Description |
| :--- | :--- |
| [pgsql_users](#pgsql_users) | Frontend and Backend PostgreSQL Users |
| [pgsql_servers](#pgsql_servers) | Backend PostgreSQL Servers |
| [pgsql_replication_hostgroups](#pgsql_replication_hostgroups) | PostgreSQL replication clusters |
| [pgsql_hostgroup_attributes](#pgsql_hostgroup_attributes) | Hostgroup-specific overrides |
| [pgsql_query_rules](#pgsql_query_rules) | Query Rules for PostgreSQL traffic |
| [pgsql_query_rules_fast_routing](#pgsql_query_rules_fast_routing) | Specialized fast routing rules |

---

### pgsql_users

The `pgsql_users` table defines PostgreSQL users that clients can use to connect to ProxySQL.

```sql
CREATE TABLE pgsql_users (
    username VARCHAR NOT NULL,
    password VARCHAR,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
    use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0,
    default_hostgroup INT NOT NULL DEFAULT 0,
    transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 1,
    fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0,
    backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1,
    frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1,
    max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000,
    attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',
    comment VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (username, backend),
    UNIQUE (username, frontend)
);
```

### pgsql_servers

The `pgsql_servers` table defines all the backend PostgreSQL servers that ProxySQL manages.

```sql
CREATE TABLE pgsql_servers (
    hostgroup_id INT CHECK (hostgroup_id>=0) NOT NULL DEFAULT 0,
    hostname VARCHAR NOT NULL,
    port INT CHECK (port >= 0 AND port <= 65535) NOT NULL DEFAULT 5432,
    status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE',
    weight INT CHECK (weight >= 0 AND weight <=10000000) NOT NULL DEFAULT 1,
    compression INT CHECK (compression IN(0,1)) NOT NULL DEFAULT 0,
    max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000,
    max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0,
    use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0,
    max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0,
    comment VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (hostgroup_id, hostname, port)
);
```

### pgsql_hostgroup_attributes

The `pgsql_hostgroup_attributes` table defines hostgroup-specific settings that override global configurations.

```sql
CREATE TABLE pgsql_hostgroup_attributes (
    hostgroup_id INT NOT NULL PRIMARY KEY,
    max_num_online_servers INT CHECK (max_num_online_servers>=0 AND max_num_online_servers <= 1000000) NOT NULL DEFAULT 1000000,
    autocommit INT CHECK (autocommit IN (-1, 0, 1)) NOT NULL DEFAULT -1,
    free_connections_pct INT CHECK (free_connections_pct >= 0 AND free_connections_pct <= 100) NOT NULL DEFAULT 10,
    init_connect VARCHAR NOT NULL DEFAULT '',
    multiplex INT CHECK (multiplex IN (0, 1)) NOT NULL DEFAULT 1,
    connection_warming INT CHECK (connection_warming IN (0, 1)) NOT NULL DEFAULT 0,
    throttle_connections_per_sec INT CHECK (throttle_connections_per_sec >= 1 AND throttle_connections_per_sec <= 1000000) NOT NULL DEFAULT 1000000,
    ignore_session_variables VARCHAR CHECK (JSON_VALID(ignore_session_variables) OR ignore_session_variables = '') NOT NULL DEFAULT '',
    hostgroup_settings VARCHAR CHECK (JSON_VALID(hostgroup_settings) OR hostgroup_settings = '') NOT NULL DEFAULT '',
    servers_defaults VARCHAR CHECK (JSON_VALID(servers_defaults) OR servers_defaults = '') NOT NULL DEFAULT '',
    comment VARCHAR NOT NULL DEFAULT ''
);
```

### pgsql_replication_hostgroups

Table `pgsql_replication_hostgroups` defines replication hostgroups for PostgreSQL.

```sql
CREATE TABLE pgsql_replication_hostgroups (
    writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,
    reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>=0),
    check_type VARCHAR NOT NULL DEFAULT 'read_only',
    comment VARCHAR NOT NULL DEFAULT '',
    UNIQUE (reader_hostgroup)
);
```

### pgsql_query_rules

The `pgsql_query_rules` table defines routing policies and attributes for PostgreSQL queries.

```sql
CREATE TABLE pgsql_query_rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0,
    username VARCHAR,
    database VARCHAR,
    flagIN INT CHECK (flagIN >= 0) NOT NULL DEFAULT 0,
    client_addr VARCHAR,
    proxy_addr VARCHAR,
    proxy_port INT CHECK (proxy_port >= 0 AND proxy_port <= 65535),
    digest VARCHAR,
    match_digest VARCHAR,
    match_pattern VARCHAR,
    negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0,
    re_modifiers VARCHAR DEFAULT 'CASELESS',
    flagOUT INT CHECK (flagOUT >= 0),
    replace_pattern VARCHAR CHECK(CASE WHEN replace_pattern IS NULL THEN 1 WHEN replace_pattern IS NOT NULL AND match_pattern IS NOT NULL THEN 1 ELSE 0 END),
    destination_hostgroup INT DEFAULT NULL,
    cache_ttl INT CHECK(cache_ttl > 0),
    cache_empty_result INT CHECK (cache_empty_result IN (0,1)) DEFAULT NULL,
    cache_timeout INT CHECK(cache_timeout >= 0),
    reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL,
    timeout INT UNSIGNED CHECK (timeout >= 0),
    retries INT CHECK (retries>=0 AND retries <=1000),
    delay INT UNSIGNED CHECK (delay >=0),
    next_query_flagIN INT UNSIGNED,
    mirror_flagOUT INT UNSIGNED,
    mirror_hostgroup INT UNSIGNED,
    error_msg VARCHAR,
    OK_msg VARCHAR,
    sticky_conn INT CHECK (sticky_conn IN (0,1)),
    multiplex INT CHECK (multiplex IN (0,1,2)),
    log INT CHECK (log IN (0,1)),
    apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0,
    attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',
    comment VARCHAR
);
```

### pgsql_query_rules_fast_routing

The `pgsql_query_rules_fast_routing` table is an extension of `pgsql_query_rules` for fast routing policies.

```sql
CREATE TABLE pgsql_query_rules_fast_routing (
    username VARCHAR NOT NULL,
    database VARCHAR NOT NULL,
    flagIN INT NOT NULL DEFAULT 0,
    destination_hostgroup INT CHECK (destination_hostgroup >= 0) NOT NULL,
    comment VARCHAR NOT NULL,
    PRIMARY KEY (username, database, flagIN)
);
```

## Runtime Tables

All configuration tables have a corresponding `runtime_` version:

- `runtime_pgsql_users`
- `runtime_pgsql_servers`
- `runtime_pgsql_replication_hostgroups`
- `runtime_pgsql_hostgroup_attributes`
- `runtime_pgsql_query_rules`
- `runtime_pgsql_query_rules_fast_routing`
