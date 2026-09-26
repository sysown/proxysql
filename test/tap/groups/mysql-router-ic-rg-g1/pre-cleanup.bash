#!/usr/bin/env bash
set -u
export MYSQL_ROUTER_IC_INFRA="infra-mysql-router-ic-rg"
exec "${WORKSPACE}/test/tap/groups/mysql-router-ic-g1/pre-cleanup.bash"
