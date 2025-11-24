-- Hostgroup 20 Server 1 - Write server initialization
-- This server expects connections from ProxySQL using: writer_user / writer_pass_789

-- Create the backend user that ProxySQL will use
CREATE USER 'writer_user'@'%' IDENTIFIED BY 'writer_pass_789';
GRANT ALL PRIVILEGES ON testdb.* TO 'writer_user'@'%';
GRANT SELECT ON mysql.* TO 'writer_user'@'%';

-- Create monitor user for ProxySQL health checks
CREATE USER 'monitor'@'%' IDENTIFIED BY 'monitor';
GRANT REPLICATION CLIENT ON *.* TO 'monitor'@'%';

-- Create test tables
USE testdb;
CREATE TABLE test_writes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_name VARCHAR(50),
    data VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE connection_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    connection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    server_name VARCHAR(50)
);

INSERT INTO test_writes (server_name, data) VALUES
    ('mysql-hg20-1', 'Write server 1 - initial data');

FLUSH PRIVILEGES;


