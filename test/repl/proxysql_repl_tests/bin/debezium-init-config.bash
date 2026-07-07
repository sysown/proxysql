#!/bin/bash

. constants

# check if all required env vars are set
if [ -z "${INFRA}" ]; then
    echo "INFRA is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${USE_SSL}" ]; then
    echo "USE_SSL is empty, please check env vars passed to: " ${0}
    exit 1
fi

echo -n "Configuring connection: mysql1(source) => debezium(replication stream) ..."

echo -n "Waiting for kafka_connect to be ready ..."
kc_ready=0
for _i in $(seq 1 60); do
    if curl -s -f http://kafka_connect.${INFRA}:8083/connectors >/dev/null 2>&1; then kc_ready=1; break; fi
    echo -n "."; sleep 2
done
if [ "$kc_ready" -ne 1 ]; then echo " ERROR: kafka_connect not ready after 120s" >&2; exit 1; fi
echo " ready."

conn_mysql=`envsubst < conf/debezium/register-mysql1.json`
curl -S -s -f -o /dev/null -X POST -H "Accept:application/json" -H "Content-Type:application/json" http://kafka_connect.${INFRA}:8083/connectors/ -d "${conn_mysql}" || { echo "ERROR: connector registration failed" >&2; exit 1; }
echo ' done.'

sleep 3

echo ' done.'
