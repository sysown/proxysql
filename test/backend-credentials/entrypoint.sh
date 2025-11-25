#!/bin/bash
# ProxySQL entrypoint with user initialization

# Start ProxySQL in the background
proxysql -f -c /etc/proxysql.cnf &
PROXYSQL_PID=$!

# Wait for ProxySQL admin interface to be ready
echo "⏳ Waiting for ProxySQL to start..."
for i in {1..30}; do
    if mysql -h 127.0.0.1 -P 6032 -uadmin -padmin -e "SELECT 1" >/dev/null 2>&1; then
        echo "✅ ProxySQL is ready"
        break
    fi
    sleep 1
done

# Configure servers
echo "⚙️  Configuring MySQL servers..."
mysql -h 127.0.0.1 -P 6032 -uadmin -padmin <<'SQL'
DELETE FROM mysql_servers;
INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (10, 'mysql-hg10-1', 3306);
INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (10, 'mysql-hg10-2', 3306);
INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (20, 'mysql-hg20-1', 3306);
INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (20, 'mysql-hg20-2', 3306);
INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (30, 'mysql-hg30-1', 3306);
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

-- Query rules (evaluated in rule_id order)
DELETE FROM mysql_query_rules;

-- Rule 0: Route standard_user to HG30 (classic ProxySQL mode)
INSERT INTO mysql_query_rules (rule_id, active, username, destination_hostgroup, apply, comment)
VALUES (0, 1, 'standard_user', 30, 1, 'Route standard_user queries to HG30 (classic ProxySQL mode)');

-- Rule 1: Route app_user write queries to HG20 (includes SELECT FOR UPDATE)
INSERT INTO mysql_query_rules (rule_id, active, username, match_pattern, destination_hostgroup, apply, comment)
VALUES (1, 1, 'app_user', '^(INSERT|UPDATE|DELETE)', 20, 1, 'Route app_user write queries to HG20 (writer backend)');

-- Rule 2: Route app_user SELECT FOR UPDATE to HG20 (must come before general SELECT rule)
INSERT INTO mysql_query_rules (rule_id, active, username, match_pattern, destination_hostgroup, apply, comment)
VALUES (2, 1, 'app_user', 'FOR UPDATE', 20, 1, 'Route app_user SELECT FOR UPDATE to HG20 (requires write lock)');

-- Rule 3: Route app_user read queries to HG10 (explicit, though HG10 is also the default)
INSERT INTO mysql_query_rules (rule_id, active, username, match_pattern, destination_hostgroup, apply, comment)
VALUES (3, 1, 'app_user', '^SELECT', 10, 1, 'Route app_user read queries to HG10 (reader backend)');

LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;
SQL

# Configure users with proper backend/frontend flags
echo "⚙️  Configuring users via SQL..."
mysql -h 127.0.0.1 -P 6032 -uadmin -padmin <<'SQL'
-- Frontend user (app connects with this)
DELETE FROM mysql_users WHERE username='app_user';
INSERT INTO mysql_users (username, password, default_hostgroup, default_schema, frontend, backend, max_connections, transaction_persistent, comment)
VALUES ('app_user', 'app_password_123', 10, 'testdb', 1, 0, 1000, 1, 'Frontend user');

-- Backend user for hostgroup 10 (read servers)
DELETE FROM mysql_users WHERE username='reader_user';
INSERT INTO mysql_users (username, password, default_hostgroup, frontend, backend, comment)
VALUES ('reader_user', 'reader_pass_456', 10, 0, 1, 'Backend credentials for hostgroup 10');

-- Backend user for hostgroup 20 (write servers)
DELETE FROM mysql_users WHERE username='writer_user';
INSERT INTO mysql_users (username, password, default_hostgroup, frontend, backend, comment)
VALUES ('writer_user', 'writer_pass_789', 20, 0, 1, 'Backend credentials for hostgroup 20');

-- Standard user for hostgroup 30 (classic ProxySQL mode: frontend=backend=1)
DELETE FROM mysql_users WHERE username='standard_user';
INSERT INTO mysql_users (username, password, default_hostgroup, default_schema, frontend, backend, comment)
VALUES ('standard_user', 'standard_pass_999', 30, 'testdb', 1, 1, 'Standard mode - same credentials for frontend and backend');

-- Load to runtime
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
SQL

echo "✅ MySQL user configuration complete"
echo ""
echo "Configured MySQL users:"
mysql -h 127.0.0.1 -P 6032 -uadmin -padmin -e "SELECT username, frontend, backend, default_hostgroup, comment FROM mysql_users ORDER BY backend, default_hostgroup;"

# Configure PostgreSQL servers
echo ""
echo "⚙️  Configuring PostgreSQL servers..."
mysql -h 127.0.0.1 -P 6032 -uadmin -padmin <<'SQL'
DELETE FROM pgsql_servers;
INSERT INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (10, 'pgsql-hg10-1', 5432);
INSERT INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (10, 'pgsql-hg10-2', 5432);
INSERT INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (20, 'pgsql-hg20-1', 5432);
INSERT INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (20, 'pgsql-hg20-2', 5432);
INSERT INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (30, 'pgsql-hg30-1', 5432);
LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;

-- Query rules (evaluated in rule_id order)
DELETE FROM pgsql_query_rules;

-- Rule 0: Route pgsql_standard to HG30 (classic ProxySQL mode)
INSERT INTO pgsql_query_rules (rule_id, active, username, destination_hostgroup, apply, comment)
VALUES (0, 1, 'pgsql_standard', 30, 1, 'Route pgsql_standard queries to HG30 (classic ProxySQL mode)');

-- Rule 1: Route pgsql_app write queries to HG20 (includes SELECT FOR UPDATE)
INSERT INTO pgsql_query_rules (rule_id, active, username, match_pattern, destination_hostgroup, apply, comment)
VALUES (1, 1, 'pgsql_app', '^(INSERT|UPDATE|DELETE)', 20, 1, 'Route pgsql_app write queries to HG20 (writer backend)');

-- Rule 2: Route pgsql_app SELECT FOR UPDATE to HG20 (must come before general SELECT rule)
INSERT INTO pgsql_query_rules (rule_id, active, username, match_pattern, destination_hostgroup, apply, comment)
VALUES (2, 1, 'pgsql_app', 'FOR UPDATE', 20, 1, 'Route pgsql_app SELECT FOR UPDATE to HG20 (requires write lock)');

-- Rule 3: Route pgsql_app read queries to HG10 (explicit, though HG10 is also the default)
INSERT INTO pgsql_query_rules (rule_id, active, username, match_pattern, destination_hostgroup, apply, comment)
VALUES (3, 1, 'pgsql_app', '^SELECT', 10, 1, 'Route pgsql_app read queries to HG10 (reader backend)');

LOAD PGSQL QUERY RULES TO RUNTIME;
SAVE PGSQL QUERY RULES TO DISK;
SQL

# Configure PostgreSQL users with proper backend/frontend flags
echo "⚙️  Configuring PostgreSQL users via SQL..."
mysql -h 127.0.0.1 -P 6032 -uadmin -padmin <<'SQL'
-- Frontend user (app connects with this)
DELETE FROM pgsql_users WHERE username='pgsql_app';
INSERT INTO pgsql_users (username, password, default_hostgroup, frontend, backend, max_connections, transaction_persistent, comment)
VALUES ('pgsql_app', 'pgsql_app_password', 10, 1, 0, 1000, 1, 'PG Frontend user');

-- Backend user for hostgroup 10 (read servers)
DELETE FROM pgsql_users WHERE username='pgsql_reader';
INSERT INTO pgsql_users (username, password, default_hostgroup, frontend, backend, comment)
VALUES ('pgsql_reader', 'pgsql_reader_pass', 10, 0, 1, 'PG Backend credentials for hostgroup 10');

-- Backend user for hostgroup 20 (write servers)
DELETE FROM pgsql_users WHERE username='pgsql_writer';
INSERT INTO pgsql_users (username, password, default_hostgroup, frontend, backend, comment)
VALUES ('pgsql_writer', 'pgsql_writer_pass', 20, 0, 1, 'PG Backend credentials for hostgroup 20');

-- Standard user for hostgroup 30 (classic ProxySQL mode: frontend=backend=1)
DELETE FROM pgsql_users WHERE username='pgsql_standard';
INSERT INTO pgsql_users (username, password, default_hostgroup, frontend, backend, comment)
VALUES ('pgsql_standard', 'pgsql_standard_pass', 30, 1, 1, 'PG Standard mode - same credentials for frontend and backend');

-- Load to runtime
LOAD PGSQL USERS TO RUNTIME;
SAVE PGSQL USERS TO DISK;
SQL

echo "✅ PostgreSQL user configuration complete"
echo ""
echo "Configured PostgreSQL users:"
mysql -h 127.0.0.1 -P 6032 -uadmin -padmin -e "SELECT username, frontend, backend, default_hostgroup, comment FROM pgsql_users ORDER BY backend, default_hostgroup;"

# Keep ProxySQL running in foreground
wait $PROXYSQL_PID


