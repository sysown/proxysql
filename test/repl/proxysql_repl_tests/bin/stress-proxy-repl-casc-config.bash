#!/bin/bash

. constants

# check if all required env vars are set
if [ -z "${INFRA}" ]; then
    echo "INFRA is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${RHG2}" ]; then
    echo "RHG1 is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${MYSQL2_PORT}" ]; then
    echo "MYSQL1_PORT is empty, please check env vars passed to: " ${0}
    exit 1
fi

echo -n "Checking proxysql ..."
while [[ ! $(mysql ${SSLOPT} -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; done; echo -n " got "
mysql ${SSLOPT} -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} -e 'SELECT version()\G' 2>/dev/null | grep version

echo "Configuring proxysql ... "
mysql ${SSLOPT} -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} < <(eval "echo \"$(cat ./conf/proxysql/stress-repl-casc-config.sql)\"") 2>&1 | grep -v 'Using a password'

echo "done."
