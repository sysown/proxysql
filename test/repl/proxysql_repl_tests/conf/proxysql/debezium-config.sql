REPLACE INTO mysql_servers (hostgroup_id,hostname,port,use_ssl,max_replication_lag,max_connections,comment) VALUES (${RHG1},'${MYSQL1_HOST}${INFRA}',${MYSQL1_PORT},${USE_SSL},180,500,'${MYSQL1_HOST}${INFRA}');
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

INSERT INTO mysql_users (username,password,active,default_hostgroup,comment) values ('debezium','debezium',1,${RHG1},'debezium through proxy, ${INFRA}');
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
