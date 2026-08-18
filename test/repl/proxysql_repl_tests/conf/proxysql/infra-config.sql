LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

DELETE FROM mysql_servers WHERE comment LIKE '%${INFRA}';

INSERT INTO mysql_servers (hostgroup_id,hostname,port,use_ssl,max_replication_lag,max_connections,comment) VALUES (${WHG},'${MYSQL1_HOST}${INFRA}',${MYSQL1_PORT},${USE_SSL},180,500,'${MYSQL1_HOST}${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,use_ssl,max_replication_lag,max_connections,comment) VALUES (${RHG},'${MYSQL1_HOST}${INFRA}',${MYSQL1_PORT},${USE_SSL},180,500,'${MYSQL1_HOST}${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,use_ssl,max_replication_lag,max_connections,comment) VALUES (${RHG},'${MYSQL2_HOST}${INFRA}',${MYSQL2_PORT},${USE_SSL},180,500,'${MYSQL2_HOST}${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,use_ssl,max_replication_lag,max_connections,comment) VALUES (${RHG},'${MYSQL3_HOST}${INFRA}',${MYSQL3_PORT},${USE_SSL},180,500,'${MYSQL3_HOST}${INFRA}');

DELETE FROM mysql_replication_hostgroups WHERE comment LIKE '%${INFRA}';
INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) VALUES (${WHG},${RHG},'${INFRA}');
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

DELETE FROM mysql_users WHERE comment LIKE '%${INFRA}';
INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('root','root',1,${WHG},'${INFRA}');
UPDATE mysql_users SET default_hostgroup=${WHG}, comment='${INFRA}' WHERE username='root';
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) values ('user','user',1,${WHG},'${INFRA}');
INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest1','sbtest1',1,${WHG},'${INFRA}');
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;

DELETE FROM mysql_query_rules WHERE comment LIKE '%${INFRA}';
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,comment) VALUES (${PREFIX}0,1,'root','^SELECT.*FOR UPDATE',${WHG},1,'${INFRA}');
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,comment) VALUES (${PREFIX}1,1,'root','^SELECT',${RHG},1,'${INFRA}');
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;

SET mysql-eventslog_default_log=1;
SET mysql-eventslog_format=2;
SET mysql-eventslog_filename='query.log';
SET mysql-auditlog_filesize=104857600;
SET mysql-auditlog_filename='audit.log';
SET mysql-have_ssl='${HAVE_SSL}';
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;

# configure Prometheus
SET admin-restapi_enabled='true';
SET admin-restapi_port=6070;
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
