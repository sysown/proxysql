#!/bin/bash
cd /opt/proxysql
make clean && make
cd src
gdbserver 0.0.0.0:2345 ./proxysql --initial