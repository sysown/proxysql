-- enable_aurora_testing() populates runtime but not disk, so proxysql-tester.py's
-- LOAD ... FROM DISK wipes aurora1/2/3 + HG 1271-1276. Persist runtime -> mem -> disk.
SAVE MYSQL USERS FROM RUNTIME;
SAVE MYSQL USERS TO DISK;
SAVE MYSQL SERVERS FROM RUNTIME;
SAVE MYSQL SERVERS TO DISK;
SAVE MYSQL QUERY RULES FROM RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;

-- When compiled with TEST_* flags (for cluster simulation), ProxySQL's monitoring
-- reaches its own sqliteserver on :3306. The default proxysql-ci.cnf pins the server
-- to :6030, so rebind it to :3306 here.
SET sqliteserver-mysql_ifaces='0.0.0.0:3306';
LOAD SQLITESERVER VARIABLES TO RUNTIME;
SAVE SQLITESERVER VARIABLES TO DISK;
