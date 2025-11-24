-- Hostgroup 10 Server 1 - Read server initialization
-- This server expects connections from ProxySQL using: reader_user / reader_pass_456

-- Create the backend user that ProxySQL will use
CREATE USER 'reader_user'@'%' IDENTIFIED BY 'reader_pass_456';
GRANT SELECT ON testdb.* TO 'reader_user'@'%';
GRANT SELECT ON mysql.* TO 'reader_user'@'%';

-- Create monitor user for ProxySQL health checks
CREATE USER 'monitor'@'%' IDENTIFIED BY 'monitor';
GRANT REPLICATION CLIENT ON *.* TO 'monitor'@'%';

-- Create test data
USE testdb;
CREATE TABLE test_reads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_name VARCHAR(50),
    data VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO test_reads (server_name, data) VALUES
    ('mysql-hg10-1', 'Read server 1 - row 1'),
    ('mysql-hg10-1', 'Read server 1 - row 2'),
    ('mysql-hg10-1', 'Read server 1 - row 3');

-- Also create test_writes table for reading (read replicas should have write data replicated)
CREATE TABLE test_writes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_name VARCHAR(50),
    data VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

FLUSH PRIVILEGES;


