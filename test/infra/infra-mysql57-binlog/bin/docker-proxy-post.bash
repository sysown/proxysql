#!/bin/bash


echo -n "Waiting for 'proxysql' ..."
while [[ ! $(mysql -h127.0.0.1 -P6032 -uadmin -padmin -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; done; echo -n " got "
mysql -h127.0.0.1 -P6032 -uadmin -padmin -e 'SELECT version()\G' 2>/dev/null | grep version

echo -n "Configuring 'proxysql' ... "
mysql -uadmin -padmin -h127.0.0.1 -P6032 < <(eval "echo \"$(cat ./conf/proxysql/infra-config.sql)\"") 2>&1 | grep -vP 'mysql: .?Warning'

echo "done."
