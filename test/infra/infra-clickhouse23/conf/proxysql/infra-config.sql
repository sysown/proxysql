SET clickhouse-mysql_ifaces='0.0.0.0:6090';
SET clickhouse-hostname='clickhouse.${INFRA}';
SET clickhouse-port=9000;
LOAD CLICKHOUSE VARIABLES TO RUNTIME;
SAVE CLICKHOUSE VARIABLES TO DISK;
