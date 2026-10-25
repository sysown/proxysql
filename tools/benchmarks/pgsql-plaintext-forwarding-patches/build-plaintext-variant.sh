#!/bin/bash
set -euo pipefail
cd /home/rene/pg-network-bench/src/proxysql-tls-handshake-cache
export OPTZ='-O2 -fno-omit-frame-pointer -ggdb'
export DEBUG=''
export GIT_VERSION='3.1.11-dev-ga0781dd'
export PROXYSQL31=1 PROXYSQLFFTO=1 PROXYSQLTSDB=1 PROXYSQLED25519=1 PROXYSQLCLICKHOUSE=1
make -C lib -j6
make -C src -j6
