DELETE FROM mysql_servers WHERE comment LIKE '%${MYSQL3_HOST}${INFRA}%';
INSERT INTO mysql_servers (hostgroup_id,hostname,port,use_ssl,max_replication_lag,max_connections,comment) VALUES (${RHG2},'${MYSQL2_HOST}${INFRA}',${MYSQL2_PORT},${USE_SSL},180,500,'${MYSQL2_HOST}${INFRA}');
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) values ('repl_casc','repl_casc',1,${RHG2},'cascade replication through proxy, ${INFRA}');
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
