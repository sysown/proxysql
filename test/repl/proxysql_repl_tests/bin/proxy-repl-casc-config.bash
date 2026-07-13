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
_w=0; while [[ ! $(mysql -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; _w=$((_w+1)); [ $_w -ge ${REPL_WAIT_TIMEOUT:-60} ] && { echo " [ERROR: timeout after ${REPL_WAIT_TIMEOUT:-60}s waiting for readiness in proxy-repl-casc-config.bash]" >&2; exit 1; }; done; echo -n " got "
mysql -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} -e 'SELECT version()\G' 2>/dev/null | grep version

echo "Configuring proxysql ... "
mysql -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} < <(eval "echo \"$(cat ./conf/proxysql/repl-casc-config.sql)\"") 2>&1 | grep -vP "mysql: .?Warning"

echo "done."
