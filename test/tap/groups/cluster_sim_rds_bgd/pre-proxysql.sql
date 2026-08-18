-- Create and persist the client account used by the BGD TAP tests.
INSERT OR REPLACE INTO mysql_users (username, password, default_hostgroup, active)
    VALUES ('testuser', 'testuser', 0, 1);
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;

-- When compiled with TEST_RDS_BGD, ProxySQL's monitor reaches its own SQLite3
-- server on :3306. The default proxysql-ci.cnf pins the server to :6030, so
-- rebind it to :3306 here.
SET sqliteserver-mysql_ifaces='0.0.0.0:3306';
LOAD SQLITESERVER VARIABLES TO RUNTIME;
SAVE SQLITESERVER VARIABLES TO DISK;
