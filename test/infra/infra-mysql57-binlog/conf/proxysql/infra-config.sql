UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-hash_passwords';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

DELETE FROM mysql_servers WHERE comment LIKE '%${INFRA}';
-- MySQL servers with gtid_port pointing to proxysql_mysqlbinlog readers
-- Note: reader1/2/3 hostnames resolve to the reader containers via Docker network aliases
INSERT INTO mysql_servers (hostgroup_id,hostname,gtid_port,port,max_replication_lag,comment) VALUES (${WHG},'mysql1.${INFRA}',6020,3306,10,'mysql1.${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,gtid_port,port,max_replication_lag,comment) VALUES (${RHG},'mysql2.${INFRA}',6020,3306,10,'mysql2.${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,gtid_port,port,max_replication_lag,comment) VALUES (${RHG},'mysql3.${INFRA}',6020,3306,10,'mysql3.${INFRA}');

DELETE FROM mysql_replication_hostgroups WHERE comment LIKE '%${INFRA}';
DELETE FROM mysql_replication_hostgroups WHERE writer_hostgroup=${WHG} AND reader_hostgroup=${RHG};
DELETE FROM mysql_replication_hostgroups WHERE comment='.' OR comment='' OR comment IS NULL;
REPLACE INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) VALUES (${WHG},${RHG},'${INFRA}');
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

DELETE FROM mysql_users WHERE comment LIKE '%${INFRA}';
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest7','sbtest7',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest8','sbtest8',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('${INFRA}','${INFRA}',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('root','${ROOT_PASSWORD}',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('testuser','testuser',1,${WHG},'${INFRA}');
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;

DELETE FROM mysql_query_rules WHERE comment LIKE '%${INFRA}';
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,gtid_from_hostgroup,comment) VALUES (${PREFIX}00,1,'sbtest7','^SELECT.*FOR UPDATE',${WHG},1,null,'${INFRA}');
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,gtid_from_hostgroup,comment) VALUES (${PREFIX}01,1,'sbtest7','^SELECT',${RHG},1,${WHG},'${INFRA}');
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,gtid_from_hostgroup,comment) VALUES (${PREFIX}02,1,'sbtest7','.*',${WHG},1,null,'${INFRA}');
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,gtid_from_hostgroup,comment) VALUES (${PREFIX}03,1,'sbtest8','^SELECT.*FOR UPDATE',${WHG},1,null,'${INFRA}');
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,gtid_from_hostgroup,comment) VALUES (${PREFIX}04,1,'sbtest8','^SELECT',${RHG},1,${WHG},'${INFRA}');
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,gtid_from_hostgroup,comment) VALUES (${PREFIX}05,1,'sbtest8','.*',${WHG},1,null,'${INFRA}');
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;
