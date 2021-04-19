#/bin/bash
echo "IGNORE errors like 'Lost connection to MySQL server during query'"
echo "Rolling restarting the core nodes"
for i in `seq 1 3` ; do
	echo "  restarting node $i ... "
	mysql -u admin -padmin -h 127.0.0.1 -P2600$i -e "PROXYSQL SHUTDOWN SLOW"
	sleep 1
	../../src/proxysql -M -D $PWD/node0$i -c confs/proxysql0$i.cfg 2> /dev/null
	echo "Done!"
	echo -n "Pause"
	for j in `seq 1 3` ; do echo -n "." ; sleep 1 ; done ; echo
done

echo "Rolling restarting the satellite nodes"
for i in `seq 4 9` ; do
	echo "  restarting node $i ... "
	mysql -u admin -padmin -h 127.0.0.1 -P2600$i -e "PROXYSQL SHUTDOWN SLOW"
	sleep 1
	../../src/proxysql -M -D $PWD/node0$i -c confs/proxysql0$i.cfg 2> /dev/null
	echo "Done!"
done
