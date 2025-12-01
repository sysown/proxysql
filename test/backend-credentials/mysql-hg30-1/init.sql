-- MySQL initialization for Hostgroup 30 (Standard ProxySQL Mode)
-- This server uses the SAME credentials for frontend and backend (frontend=1, backend=1)

-- Create user with same credentials used for both frontend and backend
CREATE USER IF NOT EXISTS 'standard_user'@'%' IDENTIFIED BY 'standard_pass_999';
GRANT ALL PRIVILEGES ON testdb.* TO 'standard_user'@'%';
FLUSH PRIVILEGES;

-- Create a test table
USE testdb;
CREATE TABLE IF NOT EXISTS hg30_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_name VARCHAR(50),
    message VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO hg30_data (server_name, message) VALUES
    ('mysql-hg30-1', 'Standard ProxySQL mode - same credentials for frontend and backend');

SELECT 'HG30 server initialized with standard_user (frontend=backend=1)' AS status;

