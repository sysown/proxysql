DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 1710 AND 1719;
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1710,'127.0.0.1',17306,0,'mariadb1');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1711,'127.0.0.1',17306,0,'mariadb1');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1711,'127.0.0.1',17307,0,'mariadb2');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1711,'127.0.0.1',17308,0,'mariadb3');

DELETE FROM mysql_replication_hostgroups WHERE writer_hostgroup BETWEEN 1710 AND 1719;
INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,check_type,comment) VALUES (1710,1711,'read_only','mariadb');
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

DELETE FROM mysql_users WHERE username='mariadbuser' OR username='mariadbuserff';
INSERT INTO mysql_users (username,password,active,default_hostgroup,fast_forward) values ('mariadbuser','mariadbuser',1,1710,0);
INSERT INTO mysql_users (username,password,active,default_hostgroup,fast_forward) values ('mariadbuserff','mariadbuserff',1,1710,1);
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;

DELETE FROM mysql_query_rules WHERE destination_hostgroup BETWEEN 1710 AND 1719;
#INSERT INTO mysql_query_rules (rule_id,username,active,match_digest,destination_hostgroup,apply) VALUES (1710,1,'mariadbuser','^SELECT.*FOR UPDATE',1710,1),(1711,1,'^SELECT',1711,1);
#INSERT INTO mysql_query_rules (rule_id,username,active,match_digest,destination_hostgroup,apply) VALUES (1710,1,'mariadbuserff','^SELECT.*FOR UPDATE',1710,1),(1711,1,'^SELECT',1711,1);
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;
