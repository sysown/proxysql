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
