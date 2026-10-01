#!/usr/bin/env bash
# Same real-plugin InnoDB Cluster setup as mysql-router-ic-g1, on the
# MySQL Shell 9.x infra (metadata 2.3+), plus Shell-created Routing Guidelines.
set -euo pipefail
: "${WORKSPACE:?WORKSPACE must be set}"
export MYSQL_ROUTER_IC_INFRA="infra-mysql-router-ic-rg"
export MYSQL_ROUTER_IC_FIXTURE_HOOK="${WORKSPACE}/test/tap/groups/mysql-router-ic-rg-g1/create-routing-guidelines.bash"
export MYSQL_ROUTER_BOOTSTRAP_OPTIONAL="${MYSQL_ROUTER_BOOTSTRAP_OPTIONAL:-0}"
exec "${WORKSPACE}/test/tap/groups/mysql-router-ic-g1/setup-infras.bash"
