-- ProxySQL PostgreSQL Server Configuration for pgsql17-repl
DELETE FROM pgsql_servers WHERE comment LIKE '%${INFRA}%%';

-- Primary in writer hostgroup
INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_replication_lag, max_connections, comment)
    VALUES (${WHG}, 'pgsql1.${INFRA}', 5432, 0, 500, 'pgsql1.${INFRA}');

-- Replicas in reader hostgroup
INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_replication_lag, max_connections, comment)
    VALUES (${RHG}, 'pgsql1.${INFRA}', 5432, 0, 500, 'pgsql1.${INFRA}');
INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_replication_lag, max_connections, comment)
    VALUES (${RHG}, 'pgsql2.${INFRA}', 5432, 0, 500, 'pgsql2.${INFRA}');

LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;

DELETE FROM pgsql_users WHERE comment LIKE '%${INFRA}%%';

-- Application users
REPLACE INTO pgsql_users (username, password, active, default_hostgroup, comment)
    VALUES ('postgres', '${ROOT_PASSWORD}', 1, ${WHG}, '${INFRA}');
REPLACE INTO pgsql_users (username, password, active, default_hostgroup, comment)
    VALUES ('testuser', 'testuser', 1, ${WHG}, '${INFRA}');

LOAD PGSQL USERS TO RUNTIME;
SAVE PGSQL USERS TO DISK;

-- Query rules for read/write splitting
DELETE FROM pgsql_query_rules WHERE destination_hostgroup IN (${WHG}, ${RHG});
INSERT INTO pgsql_query_rules (rule_id, active, match_digest, destination_hostgroup, apply)
    VALUES (${WHG}01, 1, '^SELECT.*FOR UPDATE', ${WHG}, 1),
           (${RHG}01, 1, '^SELECT', ${RHG}, 1);
LOAD PGSQL QUERY RULES TO RUNTIME;
SAVE PGSQL QUERY RULES TO DISK;
