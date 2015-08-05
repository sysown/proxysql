# Used by monitoring module for connection health
CREATE USER monitor@'%' IDENTIFIED BY 'monitor';
GRANT ALL PRIVILEGES ON test.* TO 'monitor'@'%';
FLUSH PRIVILEGES;