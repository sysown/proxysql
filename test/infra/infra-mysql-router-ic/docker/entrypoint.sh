#!/usr/bin/env bash
set -euo pipefail

MYSQL_VERSION=$(find /root/opt/mysql -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | tail -1)
if [ -z "${MYSQL_VERSION}" ]; then
    echo "ERROR: no MySQL distribution is installed" >&2
    exit 1
fi

dbdeployer deploy multiple "${MYSQL_VERSION}" \
    --nodes=4 \
    --bind-address=0.0.0.0 \
    --base-port=3305 \
    --base-server-id=8400 \
    --remote-access='%' \
    --disable-mysqlx \
    -c report_host=dbdeployer1.infra-mysql-router-ic \
    -c max_connections=500 \
    -c local_infile=ON \
    -c innodb_buffer_pool_size=128M \
    -c innodb_redo_log_capacity=64M \
    -c innodb_flush_log_at_trx_commit=2 \
    -c sync_binlog=0 \
    -c binlog_checksum=NONE \
    -c innodb_use_native_aio=0

MYSQL_CMD=(mysql -h127.0.0.1 -uroot -pmsandbox)
for port in 3306 3307 3308 3309; do
    for attempt in $(seq 1 60); do
        if "${MYSQL_CMD[@]}" -P"${port}" -e 'SELECT 1' >/dev/null 2>&1; then
            break
        fi
        if [ "${attempt}" = 60 ]; then
            echo "ERROR: MySQL port ${port} did not become ready" >&2
            exit 1
        fi
        sleep 1
    done
    "${MYSQL_CMD[@]}" -P"${port}" <<SQL
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED BY '${ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED BY 'monitor';
GRANT SELECT, REPLICATION CLIENT ON *.* TO 'monitor'@'%';
FLUSH PRIVILEGES;
SQL
done

mysqlsh --version
touch /tmp/mysql_router_ic_ready
exec sleep infinity
