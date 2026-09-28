-- The duckdb plugin's sessions authenticate exactly like a normal MySQL
-- (or PgSQL) session: DuckDBListener::run_session() builds a real
-- MySQL_Session/PgSQL_Session with session_type = PROXYSQL_SESSION_SQLITE,
-- and its handshake response is validated against GloMyAuth (mysql_users)
-- or GloPgAuth (pgsql_users) respectively -- each protocol's Protocol
-- class always looks up its own credential table regardless of session
-- type (PgSQL_Protocol::process_handshake_response_packet() calls
-- GloPgAuth->lookup() unconditionally; lib/PgSQL_Session.cpp:3926 then
-- accepts the session via `default_hostgroup >= 0 && session_type ==
-- PROXYSQL_SESSION_SQLITE`, mirroring lib/MySQL_Session.cpp's
-- `default_hostgroup>=0 && (session_type == PROXYSQL_SESSION_MYSQL ||
-- session_type == PROXYSQL_SESSION_SQLITE)` branch). This group has no
-- backend infra to provision this user for us (unlike infra-mysql84's
-- docker-proxy-post.bash, which seeds 'testuser' into mysql_users for
-- infra-backed groups), so seed both tables here -- mirrors
-- test/tap/groups/cluster_sim_rds_bgd/pre-proxysql.sql.
--
-- default_hostgroup only needs to be >= 0 to satisfy the auth branches
-- above; the duckdb session never routes to a backend (it answers every
-- query itself against its embedded DuckDB instance), so no
-- corresponding mysql_servers/pgsql_servers row is needed.
INSERT OR REPLACE INTO mysql_users (username, password, default_hostgroup, active)
    VALUES ('testuser', 'testuser', 0, 1);
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;

INSERT OR REPLACE INTO pgsql_users (username, password, default_hostgroup, active)
    VALUES ('testuser', 'testuser', 0, 1);
LOAD PGSQL USERS TO RUNTIME;
SAVE PGSQL USERS TO DISK;
