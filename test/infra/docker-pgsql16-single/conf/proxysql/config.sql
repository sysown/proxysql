DELETE FROM pgsql_servers;
INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (0,'127.0.0.1',15432,0,50,'pgsql1');
INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (1,'127.0.0.1',15432,0,50,'pgsql1');

LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;

DELETE FROM pgsql_users;
INSERT INTO pgsql_users (username,password,active) values ('postgres','postgres',1);
INSERT INTO pgsql_users (username,password,active) values ('testuser','testuser',1);

LOAD PGSQL USERS TO RUNTIME;
SAVE PGSQL USERS TO DISK; 

SET pgsql-eventslog_default_log=1;
SET pgsql-eventslog_format=2;
SET pgsql-eventslog_filename="pgquery.log";
SET pgsql-auditlog_filesize=104857600;
SET pgsql-auditlog_filename="pgaudit.log";
LOAD PGSQL VARIABLES TO RUNTIME;
SAVE PGSQL VARIABLES TO DISK;

-- Debug provisioning (DEBUG builds only; no-ops/errors are harmless on release
-- builds since these statements are piped without ON_ERROR_STOP). Mirrors the
-- MySQL infras' conf/proxysql/infra-config.sql. Required because proxy_debug()
-- is gated on the admin-debug master switch (GloVars.global.gdbg): unless
-- admin-debug='true', every proxy_debug() is a runtime no-op and no MOD# line
-- is ever emitted. Tests that scrape debug-level markers from proxysql.log
-- (e.g. pgsql-native_prepared-t P25/P26 "Describe served from metadata cache")
-- raise admin-debug_output to 3 for their phase; they rely on admin-debug
-- already being enabled here. debug_output stays 2 (debug DB only) so ordinary
-- tests are not flooded on stderr/the scraped log.
SET admin-debug='true';
UPDATE global_variables SET variable_value='2' WHERE variable_name='admin-debug_output';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
UPDATE debug_levels SET verbosity=7;
UPDATE debug_levels SET verbosity=0 WHERE module IN ('debug_pkt_array','debug_net');
LOAD DEBUG TO RUNTIME;
SAVE DEBUG TO DISK;
