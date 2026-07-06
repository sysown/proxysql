DROP USER IF EXISTS 'monitor'@'%';
CREATE USER 'monitor'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'monitor';
GRANT USAGE, REPLICATION CLIENT ON *.* TO 'monitor'@'%';

DROP USER IF EXISTS 'user'@'%';
CREATE USER 'user'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'user';
GRANT ALL ON *.* to 'user'@'%';

DROP USER IF EXISTS 'sbtest1'@'%';
CREATE USER 'sbtest1'@'%' IDENTIFIED BY 'sbtest1';
GRANT ALL ON sysbench.* TO 'sbtest1'@'%';

DROP USER IF EXISTS 'repl'@'%';
CREATE USER 'repl'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'repl'${REQUIRE_SSL};
GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'repl'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'repl'@'%';

DROP USER IF EXISTS 'repl_casc'@'%';
CREATE USER 'repl_casc'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'repl_casc'${REQUIRE_SSL};
GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'repl_casc'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'repl_casc'@'%';

DROP USER IF EXISTS 'debezium'@'%';
CREATE USER 'debezium'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'debezium'${REQUIRE_SSL};
GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'debezium'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'debezium'@'%';
