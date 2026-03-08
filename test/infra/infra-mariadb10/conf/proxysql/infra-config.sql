UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-hash_passwords';
SET admin-mysql_ifaces='0.0.0.0:6032;0.0.0.0:6031;/tmp/proxysql_admin.sock';
SET mysql-have_ssl='true';
SET mysql-have_compress='true';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

DELETE FROM mysql_servers WHERE comment LIKE '%${INFRA}';
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (${WHG},'mariadb1.${INFRA}',3306,180,500,'mariadb1.${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (${RHG},'mariadb1.${INFRA}',3306,180,500,'mariadb1.${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (${RHG},'mariadb2.${INFRA}',3306,180,500,'mariadb2.${INFRA}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (${RHG},'mariadb3.${INFRA}',3306,180,500,'mariadb3.${INFRA}');

DELETE FROM mysql_replication_hostgroups WHERE comment LIKE '%${INFRA}';
INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) VALUES (${WHG},${RHG},'${INFRA}');

LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

DELETE FROM mysql_users WHERE comment LIKE '%${INFRA}';
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('root','${ROOT_PASSWORD}',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('user','user',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('testuser','testuser',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest1','sbtest1',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest2','sbtest2',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest3','sbtest3',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('sbtest4','sbtest4',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('ssluser','ssluser',1,${WHG},'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('${INFRA}','${INFRA}',1,${WHG},'${INFRA}');

-- MariaDB specific users for the Fast Forward test
REPLACE INTO mysql_users (username,password,active,default_hostgroup,fast_forward,comment) values ('mariadbuser','mariadbuser',1,${WHG},0,'${INFRA}');
REPLACE INTO mysql_users (username,password,active,default_hostgroup,fast_forward,comment) values ('mariadbuserff','mariadbuserff',1,${WHG},1,'${INFRA}');

LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
