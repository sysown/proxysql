UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-hash_passwords';
SET admin-mysql_ifaces='0.0.0.0:6032;0.0.0.0:6031;/tmp/proxysql_admin.sock';
SET mysql-have_ssl='true';
SET mysql-have_compress='true';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

DELETE FROM mysql_servers WHERE comment LIKE 'test server';
DELETE FROM mysql_servers WHERE comment LIKE '%${INFRA}';
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (${WHG},'dbdeployer1.${INFRA}',3306,1,500,'dbdeployer1.${INFRA}');

DELETE FROM mysql_replication_hostgroups WHERE comment LIKE '%${INFRA}';
DELETE FROM mysql_group_replication_hostgroups WHERE comment LIKE '%${INFRA}';
DELETE FROM mysql_galera_hostgroups WHERE comment LIKE '%${INFRA}';
DELETE FROM mysql_aws_aurora_hostgroups WHERE comment LIKE '%${INFRA}';
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

DELETE FROM mysql_users WHERE username IN ('root','testuser') OR comment LIKE '%${INFRA}';
INSERT INTO mysql_users (username,password,active,default_hostgroup,fast_forward,backend,frontend,comment) VALUES ('root','${ROOT_PASSWORD}',1,${WHG},0,1,1,'dynamic-root-user');
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('user','user',1,${WHG},'${INFRA}');
INSERT INTO mysql_users (username,password,active,default_hostgroup,fast_forward,backend,frontend,comment) VALUES ('testuser','testuser',1,${WHG},0,1,1,'universal-testuser');
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('sbtest1','sbtest1',1,${WHG},'${INFRA}');
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('sbtest2','sbtest2',1,${WHG},'${INFRA}');
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('sbtest3','sbtest3',1,${WHG},'${INFRA}');
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('sbtest4','sbtest4',1,${WHG},'${INFRA}');
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('sbtest7','sbtest7',1,${WHG},'${INFRA}');
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('sbtest8','sbtest8',1,${WHG},'${INFRA}');
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('ssluser','ssluser',1,${WHG},'${INFRA}');
-- MySQL 5.6 limits usernames to 16 chars, so '${INFRA}' is documented here but intentionally disabled.
-- INSERT INTO mysql_users (username,password,active,default_hostgroup,fast_forward,backend,frontend,comment) VALUES ('${INFRA}','${INFRA}',1,${WHG},0,1,1,'${INFRA}');
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;

DELETE FROM mysql_query_rules WHERE comment LIKE '%${INFRA}';
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;

DELETE FROM scheduler WHERE comment LIKE '%${INFRA}';
LOAD SCHEDULER TO RUNTIME;
SAVE SCHEDULER TO DISK;

SET mysql-monitor_username='monitor';
SET mysql-monitor_password='monitor';
SET mysql-eventslog_default_log=1;
SET mysql-eventslog_format=2;
SET mysql-eventslog_filename='query.log';
SET mysql-auditlog_filesize=104857600;
SET mysql-auditlog_filename='audit.log';
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;

SET admin-restapi_enabled='true';
SET admin-restapi_port=6070;
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

UPDATE global_variables SET variable_value='2' WHERE variable_name='admin-debug_output';
SET admin-debug='true';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
UPDATE debug_levels SET verbosity=7;
UPDATE debug_levels SET verbosity=0 WHERE module IN ('debug_pkt_array','debug_net');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'get_pkts_from_client');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler');
REPLACE INTO debug_filters VALUES ('ProxySQL_Admin.cpp',0,'save_mysql_servers_runtime_to_database');
REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'ping_handler');
REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'generic_handler');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_backend_user_schema');
REPLACE INTO debug_filters VALUES ('mysql_data_stream.cpp',0,'assign_fd_from_mysql_conn');
REPLACE INTO debug_filters VALUES ('mysql_data_stream.cpp',0,'setDSS_STATE_QUERY_SENT_NET');
REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'set_no_backslash_escapes');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_backend_autocommit');
REPLACE INTO debug_filters VALUES ('MySQL_Thread.cpp',0,'tune_timeout_for_myds_needs_pause');
REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'handler');
REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'real_query_cont');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler_again___verify_multiple_variables');
REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler');
REPLACE INTO debug_filters VALUES ('PgSQL_Connection.cpp',0,'handler');
REPLACE INTO debug_filters VALUES ('Base_Thread.cpp',0,'tune_timeout_for_myds_needs_pause');
REPLACE INTO debug_filters VALUES ('MySQL_Session.cpp',0,'handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection');
REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection');
REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler_again___verify_backend_user_db');
REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'get_pkts_from_client');
REPLACE INTO debug_filters VALUES ('MySQL_HostGroups_Manager.cpp',0,'push_MyConn_to_pool');
REPLACE INTO debug_filters VALUES ('MySQL_HostGroups_Manager.cpp',0,'get_MyConn_from_pool');
REPLACE INTO debug_filters VALUES ('MySrvConnList.cpp',0,'get_random_MyConn');
REPLACE INTO debug_filters VALUES ('MyHGC.cpp',0,'get_random_MySrvC');
REPLACE INTO debug_filters VALUES ('PgSQL_Session.cpp',0,'handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_S');
REPLACE INTO debug_filters VALUES ('PgSQL_HostGroups_Manager.cpp',0,'get_random_MySrvC');
REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'stmt_prepare_cont');
REPLACE INTO debug_filters VALUES ('mysql_connection.cpp',0,'stmt_execute_cont');
REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'event_loop');
REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'get_connection');
REPLACE INTO debug_filters VALUES ('MySQL_Monitor.cpp',0,'put_connection');
REPLACE INTO debug_filters VALUES ('PgSQL_Monitor.cpp',0,'worker_thread');
REPLACE INTO debug_filters VALUES ('PgSQL_Data_Stream.cpp',0,'assign_fd_from_pgsql_conn');
LOAD DEBUG TO RUNTIME;
SAVE DEBUG TO DISK;

UPDATE global_variables SET variable_value='proxysql_ssl.keylog' WHERE variable_name='admin-ssl_keylog_file';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
