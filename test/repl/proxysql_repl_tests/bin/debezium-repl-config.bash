#!/bin/bash

. constants

# check if all required env vars are set
if [ -z "${INFRA}" ]; then
    echo "INFRA is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${HOST_IP}" ]; then
    echo "HOST_IP is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${USE_SSL}" ]; then
    echo "USE_SSL is empty, please check env vars passed to: " ${0}
    exit 1
fi

echo -n "Configuring connection: mysql1(source) => proxysql => debezium(replication stream) ..."

conn_mysql=`envsubst < conf/debezium/register-proxysql.json`
curl -S -s -o /dev/null -i -X POST -H "Accept:application/json" -H "Content-Type:application/json" kafka_connect.${INFRA}:8083/connectors/ -d "${conn_mysql}"
echo ' done.'

sleep 3

echo ' done.'
