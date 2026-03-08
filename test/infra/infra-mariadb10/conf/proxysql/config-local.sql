DELETE FROM mysql_servers;
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (0,'127.0.0.1',17306,1,'mariadb1');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'127.0.0.1',17306,1,'mariadb1');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'127.0.0.1',17307,1,'mariadb2');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'127.0.0.1',17308,1,'mariadb3');

DELETE FROM mysql_group_replication_hostgroups;
INSERT INTO mysql_group_replication_hostgroups (writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind) VALUES (0,4,1,6,1,1,1,0);
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;

DELETE FROM mysql_users;
INSERT INTO mysql_users (username,password,active) values ('root','root',1);
INSERT INTO mysql_users (username,password,active) values ('user','user',1);
INSERT INTO mysql_users (username,password,active) values ('mariadbuser','mariadbuser',1);
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK; 

DELETE FROM mysql_query_rules;
INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply) VALUES (1,1,'^SELECT.*FOR UPDATE',0,1),(2,1,'^SELECT',1,1);
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;

