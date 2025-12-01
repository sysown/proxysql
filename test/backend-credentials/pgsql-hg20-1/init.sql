-- Hostgroup 20 Server 1 - PostgreSQL Write server initialization
-- This server expects connections from ProxySQL using: pgsql_writer / pgsql_writer_pass

-- Create the backend user that ProxySQL will use
CREATE USER pgsql_writer WITH PASSWORD 'pgsql_writer_pass';
GRANT CONNECT ON DATABASE testdb TO pgsql_writer;
GRANT USAGE ON SCHEMA public TO pgsql_writer;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO pgsql_writer;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO pgsql_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO pgsql_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO pgsql_writer;

-- Create test tables
CREATE TABLE test_writes (
    id SERIAL PRIMARY KEY,
    server_name VARCHAR(50),
    data VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO test_writes (server_name, data) VALUES
    ('pgsql-hg20-1', 'PG Write server 1 - initial data');

GRANT ALL PRIVILEGES ON test_writes TO pgsql_writer;
GRANT USAGE, SELECT ON SEQUENCE test_writes_id_seq TO pgsql_writer;

