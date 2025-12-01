-- Hostgroup 10 Server 1 - PostgreSQL Read server initialization
-- This server expects connections from ProxySQL using: pgsql_reader / pgsql_reader_pass

-- Create the backend user that ProxySQL will use
CREATE USER pgsql_reader WITH PASSWORD 'pgsql_reader_pass';
GRANT CONNECT ON DATABASE testdb TO pgsql_reader;
GRANT USAGE ON SCHEMA public TO pgsql_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pgsql_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO pgsql_reader;

-- Create test table and data
CREATE TABLE test_reads (
    id SERIAL PRIMARY KEY,
    server_name VARCHAR(50),
    data VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO test_reads (server_name, data) VALUES
    ('pgsql-hg10-1', 'PG Read server 1 - row 1'),
    ('pgsql-hg10-1', 'PG Read server 1 - row 2'),
    ('pgsql-hg10-1', 'PG Read server 1 - row 3');

-- Also create test_writes table (for reads from replicas)
CREATE TABLE test_writes (
    id SERIAL PRIMARY KEY,
    server_name VARCHAR(50),
    data VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

GRANT SELECT ON test_writes TO pgsql_reader;

