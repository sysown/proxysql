-- The simulator connects to the SQLite server as root/root; enable_replicationlag_testing()
-- does not provision any mysql_user, so inject one and persist.
INSERT OR REPLACE INTO mysql_users (username, password, default_hostgroup, active)
    VALUES ('root', 'root', 0, 1);
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;

-- When compiled with TEST_* flags (for cluster simulation), ProxySQL's monitoring
-- reaches its own sqliteserver on :3306. The default proxysql-ci.cnf pins the server
-- to :6030, so rebind it to :3306 here.
SET sqliteserver-mysql_ifaces='0.0.0.0:3306';
LOAD SQLITESERVER VARIABLES TO RUNTIME;
SAVE SQLITESERVER VARIABLES TO DISK;
