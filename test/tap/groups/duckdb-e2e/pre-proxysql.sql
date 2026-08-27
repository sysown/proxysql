-- The duckdb plugin's sessions authenticate exactly like a normal MySQL
-- session: DuckDBListener::run_session() builds a real MySQL_Session with
-- session_type = PROXYSQL_SESSION_SQLITE, and its handshake response is
-- validated against GloMyAuth (mysql_users) the same way
-- src/SQLite3_Server.cpp's own PROXYSQL_SESSION_SQLITE sessions are (see
-- lib/MySQL_Session.cpp's `default_hostgroup>=0 && (session_type ==
-- PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE)`
-- branch). This group has no backend infra to provision this user for us
-- (unlike infra-mysql84's docker-proxy-post.bash, which seeds 'testuser'
-- into mysql_users for infra-backed groups), so seed it here -- mirrors
-- test/tap/groups/cluster_sim_rds_bgd/pre-proxysql.sql.
--
-- default_hostgroup only needs to be >= 0 to satisfy the auth branch
-- above; the duckdb session never routes to a backend (it answers every
-- query itself against its embedded DuckDB instance), so no
-- corresponding mysql_servers row is needed.
INSERT OR REPLACE INTO mysql_users (username, password, default_hostgroup, active)
    VALUES ('testuser', 'testuser', 0, 1);
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
