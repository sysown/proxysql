#/bin/bash
../../src/proxysql -M -D $PWD/node01 -c confs/proxysql01.cfg
../../src/proxysql -M -D $PWD/node02 -c confs/proxysql02.cfg
../../src/proxysql -M -D $PWD/node03 -c confs/proxysql03.cfg
