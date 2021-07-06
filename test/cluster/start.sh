#/bin/bash
echo "Starting the core nodes"
../../src/proxysql -M -D $PWD/node01 -c confs/proxysql01.cfg
../../src/proxysql -M -D $PWD/node02 -c confs/proxysql02.cfg
../../src/proxysql -M -D $PWD/node03 -c confs/proxysql03.cfg

echo "Starting the satellite nodes"
for i in `seq 4 9` ; do
	../../src/proxysql -M -D $PWD/node0$i -c confs/proxysql0$i.cfg
done
