#/bin/bash
echo "Stopping all nodes"
for i in `seq 1 9` ; do
	mysql -u admin -padmin -h 127.0.0.1 -P2600$i -e "PROXYSQL SHUTDOWN SLOW"
done
