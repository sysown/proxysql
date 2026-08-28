DELETE FROM clickhouse_servers WHERE comment LIKE '%${INFRA}';
INSERT INTO clickhouse_servers (hostgroup_id,hostname,port,comment) VALUES (8000,'clickhouse.${INFRA}',9000,'clickhouse.${INFRA}');
