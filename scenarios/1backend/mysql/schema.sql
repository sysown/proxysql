DROP DATABASE IF EXISTS test;
CREATE DATABASE test;

CREATE USER john@'%' IDENTIFIED BY 'doe';
CREATE USER danny@'%' IDENTIFIED BY 'white'; 

GRANT ALL PRIVILEGES ON test.* TO 'john'@'%';
GRANT ALL PRIVILEGES ON test.* TO 'danny'@'%';
FLUSH PRIVILEGES;

USE test;

CREATE TABLE strings(value LONGTEXT);

INSERT INTO strings(value) VALUES('a');
INSERT INTO strings(value) VALUES('ab');
INSERT INTO strings(value) VALUES('abc');
INSERT INTO strings(value) VALUES('abcd');