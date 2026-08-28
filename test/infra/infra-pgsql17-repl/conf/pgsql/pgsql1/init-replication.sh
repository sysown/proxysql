#!/bin/bash
set -e

# Create replication user
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER replicator WITH REPLICATION ENCRYPTED PASSWORD 'replicator';
    SELECT pg_create_physical_replication_slot('replica_slot_2');
    SELECT pg_create_physical_replication_slot('replica_slot_3');
    SELECT pg_create_physical_replication_slot('replica_slot_4');
EOSQL
