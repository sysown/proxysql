#!/bin/bash

. constants

[[ $(mysql --skip-ssl-verify-server-cert -h 2>&1) =~ skip-ssl-verify-server-cert ]] || export SSLOPT=--skip-ssl-verify-server-cert

echo -n "Waiting for 'proxysql' ..."
while [[ ! $(mysql ${SSLOPT} -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; done; echo -n " got "
mysql ${SSLOPT} -h${PROXYSQL_HOST} -P${PROXYADM_PORT}  -u${PROXYADM_USER} -p${PROXYADM_PWD} -e 'SELECT version()\G' 2>/dev/null | grep version

echo -n "Configuring 'proxysql' ... "
#cat < <(eval "echo \"$(cat ./conf/proxysql/infra-config.sql)\"")
mysql ${SSLOPT} -h${PROXYSQL_HOST} -P${PROXYADM_PORT}  -u${PROXYADM_USER} -p${PROXYADM_PWD} < <(eval "echo \"$(cat ./conf/proxysql/infra-config.sql)\"") 2>&1 | grep -v 'Using a password'

echo "done."
