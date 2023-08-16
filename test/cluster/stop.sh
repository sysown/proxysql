#!/usr/bin/env bash

echo "Stopping all nodes"
for i in `seq 1 9` ; do
	mysql -u admin -padmin -h 127.0.0.1 -P2600$i -e "PROXYSQL SHUTDOWN SLOW" 2>&1 | grep -v "Using a password"
done
