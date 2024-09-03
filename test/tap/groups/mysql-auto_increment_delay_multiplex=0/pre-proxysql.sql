# proxysql settings
SET mysql-auto_increment_delay_multiplex=0;
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
