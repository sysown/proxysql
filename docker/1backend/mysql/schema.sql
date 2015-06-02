DROP DATABASE IF EXISTS test;

CREATE DATABASE test;

USE test;

CREATE TABLE strings(value LONGTEXT);

INSERT INTO strings(value) VALUES('a');
INSERT INTO strings(value) VALUES('ab');
INSERT INTO strings(value) VALUES('abc');
INSERT INTO strings(value) VALUES('abcd');