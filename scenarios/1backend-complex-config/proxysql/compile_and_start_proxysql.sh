#!/bin/bash
cd /opt/proxysql
make clean && make
cd src
# TODO(andrei): re-enable the commented line when figuring out interactive mode
# gdbserver 0.0.0.0:2345 ./proxysql --initial -f -c /etc/proxysql.cnf
./proxysql --initial -f -c /etc/proxysql.cnf