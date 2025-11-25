-- PostgreSQL initialization for Hostgroup 30 (Standard ProxySQL Mode)
-- This server uses the SAME credentials for frontend and backend (frontend=1, backend=1)

-- Create user with same credentials used for both frontend and backend
CREATE USER pgsql_standard WITH PASSWORD 'pgsql_standard_pass';
GRANT CONNECT ON DATABASE testdb TO pgsql_standard;
GRANT USAGE ON SCHEMA public TO pgsql_standard;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO pgsql_standard;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO pgsql_standard;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO pgsql_standard;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO pgsql_standard;

-- Create a test table
CREATE TABLE hg30_data (
    id SERIAL PRIMARY KEY,
    server_name VARCHAR(50),
    message VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO hg30_data (server_name, message) VALUES
    ('pgsql-hg30-1', 'Standard ProxySQL mode - same credentials for frontend and backend');

GRANT ALL PRIVILEGES ON hg30_data TO pgsql_standard;
GRANT USAGE, SELECT ON SEQUENCE hg30_data_id_seq TO pgsql_standard;

