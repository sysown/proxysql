DELETE FROM pgsql_servers;
INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (0,'127.0.0.1',15432,0,50,'pgsql1');
INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_replication_lag,max_connections,comment) VALUES (1,'127.0.0.1',15432,0,50,'pgsql1');

LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;

DELETE FROM pgsql_users;
INSERT INTO pgsql_users (username,password,active) values ('postgres','postgres',1);
INSERT INTO pgsql_users (username,password,active) values ('testuser','testuser',1);

LOAD PGSQL USERS TO RUNTIME;
SAVE PGSQL USERS TO DISK; 

SET pgsql-eventslog_default_log=1;
SET pgsql-eventslog_format=2;
SET pgsql-eventslog_filename="pgquery.log";
SET pgsql-auditlog_filesize=104857600;
SET pgsql-auditlog_filename="pgaudit.log";
LOAD PGSQL VARIABLES TO RUNTIME;
SAVE PGSQL VARIABLES TO DISK;
