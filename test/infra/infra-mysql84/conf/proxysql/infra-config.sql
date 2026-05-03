UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-hash_passwords';
SET admin-mysql_ifaces='0.0.0.0:6032;0.0.0.0:6031;/tmp/proxysql_admin.sock';
SET mysql-have_ssl='true';
SET mysql-have_compress='true';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

DELETE FROM mysql_servers WHERE comment LIKE '%${INFRA}';
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (${WHG},'mysql1.${INFRA}',3306,1,'mysql1.${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (${RHG},'mysql1.${INFRA}',3306,1,'mysql1.${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (${RHG},'mysql2.${INFRA}',3306,1,'mysql2.${INFRA}');
#INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (${BHG},'mysql2.${INFRA}',3306,1,'mysql2.${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (${RHG},'mysql3.${INFRA}',3306,1,'mysql3.${INFRA}');
#INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (${BHG},'mysql3.${INFRA}',3306,1,'mysql3.${INFRA}');

DELETE FROM mysql_replication_hostgroups WHERE comment LIKE '%${INFRA}';
INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) VALUES (${WHG},${RHG},'${INFRA}');

DELETE FROM mysql_group_replication_hostgroups WHERE comment LIKE '%${INFRA}';

DELETE FROM mysql_galera_hostgroups  WHERE comment LIKE '%${INFRA}';

DELETE FROM mysql_aws_aurora_hostgroups  WHERE comment LIKE '%${INFRA}';
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

DELETE FROM mysql_users WHERE comment LIKE '%${INFRA}';
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('root','root',1,${WHG},'${INFRA}');
UPDATE mysql_users SET default_hostgroup=${WHG},comment='${INFRA}' WHERE username='root';
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('user','user',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('testuser','testuser',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest1','sbtest1',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest2','sbtest2',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest3','sbtest3',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest4','sbtest4',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest7','sbtest7',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest8','sbtest8',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('ssluser','ssluser',1,${WHG},'${INFRA}');
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('${INFRA}','${INFRA}',1,${WHG},'${INFRA}');
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK; 

DELETE FROM mysql_query_rules WHERE comment LIKE '%${INFRA}';
#INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply,comment) VALUES (${PREFIX}00,1,'^SELECT.*FOR UPDATE',${WHG},1,'${INFRA}');
#INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply,comment) VALUES (${PREFIX}01,1,'^SELECT',${RHG},1,'${INFRA}');
#INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply,comment) VALUES (${PREFIX}02,1,'.*',${WHG},1,'${INFRA}');
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;

DELETE FROM scheduler WHERE comment LIKE '%${INFRA}';
LOAD SCHEDULER TO RUNTIME;
SAVE SCHEDULER TO DISK;

SET mysql-eventslog_default_log=1;
SET mysql-eventslog_format=2;
SET mysql-eventslog_filename='query.log';
SET mysql-auditlog_filesize=104857600;
SET mysql-auditlog_filename='audit.log';
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;

# configure Prometheus
SET admin-restapi_enabled='true';
SET admin-restapi_port=6070;
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

# configure DEBUGDB_DISK
UPDATE global_variables SET variable_value='2' WHERE variable_name='admin-debug_output';
-- LOCAL PATCH: admin-debug not recognised in current builds
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
-- LOCAL PATCH (debug_levels/filters not in current build): UPDATE debug_levels SET verbosity=7;
-- LOCAL PATCH (debug_levels/filters not in current build): UPDATE debug_levels SET verbosity=0 WHERE module IN ('debug_pkt_array','debug_net');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'get_pkts_from_client');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('ProxySQL_Admin.cpp',0,'save_mysql_servers_runtime_to_database');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'ping_handler');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'generic_handler');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_backend_user_schema');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('mysql_data_stream.cpp',0,'assign_fd_from_mysql_conn');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('mysql_data_stream.cpp',0,'setDSS_STATE_QUERY_SENT_NET');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'set_no_backslash_escapes');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_backend_session_track_gtids');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_backend_autocommit');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Thread.cpp',0,'tune_timeout_for_myds_needs_pause');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'handler');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'real_query_cont');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_multiple_variables');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('PgSQL_Connection.cpp',0,'handler');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('Base_Thread.cpp',0,'tune_timeout_for_myds_needs_pause');
-- LOCAL PATCH (debug_levels/filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler_again___verify_backend_user_db');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'get_pkts_from_client');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_HostGroups_Manager.cpp',0,'push_MyConn_to_pool');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_HostGroups_Manager.cpp',0,'get_MyConn_from_pool');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('MySrvConnList.cpp',0,'get_random_MyConn');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('MyHGC.cpp',0,'get_random_MySrvC');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_S');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('PgSQL_HostGroups_Manager.cpp',0,'get_random_MySrvC');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'stmt_prepare_cont');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'stmt_execute_cont');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'event_loop');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'get_connection');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'put_connection');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('PgSQL_Monitor.cpp',0,'worker_thread');
-- LOCAL PATCH (debug_filters not in current build): REPLACE INTO debug_filters VALUES ('PgSQL_Data_Stream.cpp',0,'assign_fd_from_pgsql_conn');
-- LOCAL PATCH: LOAD DEBUG verb not in current build
-- LOCAL PATCH: SAVE DEBUG verb not in current build

# configure SSLKEYLOG
UPDATE global_variables SET variable_value='proxysql_ssl.keylog' WHERE variable_name='admin-ssl_keylog_file';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
