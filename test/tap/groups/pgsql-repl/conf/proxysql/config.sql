SET pgsql-monitor_password='proxymon';
SET pgsql-monitor_username='proxymon';

LOAD PGSQL VARIABLES TO RUNTIME;
SAVE PGSQL VARIABLES TO DISK;

DELETE FROM pgsql_users;
INSERT INTO pgsql_users (username,password,default_hostgroup) VALUES ('postgres','postgres',0);

LOAD PGSQL USERS TO RUNTIME;
SAVE PGSQL USERS TO DISK;

SET pgsql-monitor_replication_lag_interval=1000;

LOAD PGSQL VARIABLES TO RUNTIME;
SAVE PGSQL VARIABLES TO DISK;

DELETE FROM pgsql_replication_hostgroups;
INSERT INTO
    pgsql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type, comment)
VALUES
    (0, 1, 'read_only', 'pg-replication');

LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;

DELETE FROM pgsql_servers;

INSERT INTO
    pgsql_servers (hostgroup_id, hostname, port, max_replication_lag, comment)
VALUES
    (0, '127.0.0.1', 15432, 3, 'pg-primary'),
    (1, '127.0.0.1', 15433, 3, 'pg-replica');

LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;
