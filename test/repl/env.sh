#!/bin/bash

#export TERM=vt100
export TERM=xterm-256color

# Docker Swarm Mode needs maual init:
# `docker swarm init --advertise-addr 10.66.29.143`
# autodetect swarm mode
#export DOCKER_MODE=$([[ $(docker node ls -q 2>&1 | wc -l) -gt 1 ]] && echo 'swarm' || echo 'compose')
# force mode
export DOCKER_MODE=compose
#export DOCKER_MODE=swarm
#export DOCKER_MODE=k8s

# Paths to modify
export JENKINS_SCRIPTS_PATH=$(dirname $(readlink -f $BASH_SOURCE))
if [[ -z $WORKSPACE ]]; then
	export WORKSPACE=$JENKINS_SCRIPTS_PATH/../workspace/ProxySQL-Automated-Build-Testing
fi

# ProxySQL log path
export PROXYSQL_COMPILE_LOG=proxysql-compile.log
export INFRA_LOGS_PATH=$WORKSPACE/ci_infra_logs
export REGULAR_INFRA_DATADIR=$INFRA_LOGS_PATH/regular_infra/proxysql
export SB_INFRA_DATADIR=$INFRA_LOGS_PATH/single_backend_infra/proxysql
export TESTS_LOGS_PATH=$WORKSPACE/ci_tests_logs
export SPIFFE_INFRA_DATADIR=$INFRA_LOGS_PATH/spiffe_infra
export REPL_INFRA_DATADIR=$INFRA_LOGS_PATH/repl_infra

# Jenkins related paths
export DOCKER_SCRIPT_PATH=$JENKINS_SCRIPTS_PATH/docker-mysql-proxysql
export TEST_SCRIPT_PATH=$JENKINS_SCRIPTS_PATH/test-scripts
export SINGLE_BACKEND_WORKDIR=$JENKINS_SCRIPTS_PATH/proxysql_single_backend_tests
export PR_TESTING_COVERAGE=$JENKINS_SCRIPTS_PATH/pr_testing_coverage
export ASAN_CHECKER_PATH=$JENKINS_SCRIPTS_PATH/asan_checker
export ASAN_CONFIG_PATH=$JENKINS_SCRIPTS_PATH/asan_config
export SPIFFE_TESTS_PATH=$JENKINS_SCRIPTS_PATH/proxysql_spiffe_testing
export REPL_TESTS_PATH=$JENKINS_SCRIPTS_PATH/proxysql_repl_tests


# Tap tests related 'ENV' variables
export TAP_HOST=127.0.0.1
export TAP_PORT=6033
export TAP_USERNAME=root
export TAP_PASSWORD=root
# TAP_WORKDIR can be a space or nl separated list
# e.g.: "myfolder_tap/ otherfolder_tap/"
#export TAP_WORKDIR="$WORKSPACE/test/tap/tests/ $WORKSPACE/test/tap/group02_tap_tests"
export TAP_WORKDIR="$WORKSPACE/test/tap/tests/"
export INTERNAL_TAP_WORKDIR="$WORKSPACE/test/tap/tests_with_deps/"
export TEST_DEPS=$JENKINS_SCRIPTS_PATH/test-scripts/deps


# Test controls
PROXYSQL_LAYOUT=flat
#PROXYSQL_LAYOUT=2layer

# coverage reports (code coverage)
export WITHGCOV=1
# memory analyzer
export WITHASAN=0
# exit tester on fail
export TEST_EXIT_ON_FAIL=0

# run JDBC tests
export TEST_JDBC=1
export TEST_JDBC_EXIT_ON_FAIL=0

# run Python tests
export TEST_PY=1
export TEST_PY_EXIT_ON_FAIL_SECTION=0
export TEST_PY_EXIT_ON_FAIL_TEST=0

export TEST_PY_INTERNAL=1
export TEST_PY_BENCHMARK=1
export TEST_PY_CHUSER=1
export TEST_PY_STATS=1
export TEST_PY_TAP=1
export TEST_PY_TAPINT=1
export TEST_PY_FAILOVER=1
export TEST_PY_WARMING=0
export TEST_PY_READONLY=0

# TAP test filtering
# TAP_INCL/EXCL is a list of regular expressions matching againt filename
# e.g.: "basic-t admin_various_.* reg_test_3[5-7]\d\d-.*"
# logic: ( TAP_WORKDIR & TAP_INCL ) - TAP_EXCL
# ignored if empty
#export TEST_PY_TAP_INCL=".*clickhouse.*-t .*binlog.*-t"
#export TEST_PY_TAP_INCL="set_testing-multi-t reg_test_3847_admin_lock-t reg_test_3273_ssl_con-t test_default_value_transaction_isolation_attr-t"
export TEST_PY_TAP_INCL=""
export TEST_PY_TAP_EXCL="reg_test_3273_ssl_con-t"
export TEST_PY_TAPINT_INCL=""
export TEST_PY_TAPINT_EXCL=""

# run single tests
export TEST_SINGLE=1

# run SPIFFE tests
export TEST_SPIFFE=1


# overide these settings in PR
# $WORKSPACE/tests/env.sh
if [ -f $WORKSPACE/test/env.sh ]; then
	source $WORKSPACE/tests/env.sh
fi

# end
