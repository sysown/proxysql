CREATE USER repluser WITH replication encrypted password 'replpass';
SELECT pg_create_physical_replication_slot('replication_slot');

CREATE USER proxymon WITH encrypted password 'proxymon';

GRANT pg_monitor TO proxymon;

-- For testing 'pgsql-monitor_dbname'
CREATE DATABASE proxymondb;
