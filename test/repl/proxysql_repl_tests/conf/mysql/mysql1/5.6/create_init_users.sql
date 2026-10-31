GRANT USAGE ON *.* TO 'monitor'@'%';
DROP USER 'monitor'@'%';
CREATE USER 'monitor'@'%' IDENTIFIED BY 'monitor';
GRANT USAGE, REPLICATION CLIENT ON *.* TO 'monitor'@'%';

GRANT USAGE ON *.* TO 'user'@'%';
DROP USER 'user'@'%';
CREATE USER 'user'@'%' IDENTIFIED BY 'user';
GRANT ALL ON *.* to 'user'@'%';

GRANT USAGE ON *.* TO 'sbtest1'@'%';
DROP USER 'sbtest1'@'%';
CREATE USER 'sbtest1'@'%' IDENTIFIED BY 'sbtest1';
GRANT ALL ON sysbench.* TO 'sbtest1'@'%';

GRANT USAGE ON *.* TO 'repl'@'%';
DROP USER 'repl'@'%';
CREATE USER 'repl'@'%' IDENTIFIED BY 'repl';
GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'repl'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'repl'@'%';

GRANT USAGE ON *.* TO 'repl_casc'@'%';
DROP USER 'repl_casc'@'%';
CREATE USER 'repl_casc'@'%' IDENTIFIED BY 'repl_casc';
GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'repl_casc'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'repl_casc'@'%';

GRANT USAGE ON *.* TO 'debezium'@'%';
DROP USER 'debezium'@'%';
CREATE USER 'debezium'@'%' IDENTIFIED BY 'debezium';
GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'debezium'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'debezium'@'%';
