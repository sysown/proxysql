#!/bin/bash

#export TERM=vt100
export TERM=xterm-256color

# Docker Swarm Mode needs maual init:
# `docker swarm init --advertise-addr 10.66.29.143`
# autodetect swarm mode
#export DOCKER_MODE=$([[ $(docker node ls -q 2>&1 | wc -l) -gt 1 ]] && echo 'swarm' || echo 'compose')
# force mode
export DOCKER_MODE=compose
#export DOCKER_MODE=compose-dns
#export DOCKER_MODE=swarm
#export DOCKER_MODE=k8s

# Paths to modify
export JENKINS_SCRIPTS_PATH=/var/lib/jenkins/scripts
if ! [[ -v WORKSPACE ]]; then
	export WORKSPACE=/var/lib/jenkins/workspace/ProxySQL-Automated-Build-Testing
fi

# test build essential
export VERS=$(git -C ${WORKSPACE} describe --tags --abbrev=7)
export DIST="ubuntu22-dbg"

# ProxySQL JEMALLOC settings
export MALLOC_CONF="retain:false"

# ProxySQL log path
export PROXYSQL_COMPILE_LOG=proxysql-compile.log
export INFRA_LOGS_PATH=$WORKSPACE/ci_infra_logs
export SYSTEM_LOGS_PATH=$WORKSPACE/ci_system_logs
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
# proxysql unpriviliged test connection
export TAP_HOST=127.0.0.1
export TAP_PORT=6033
export TAP_USERNAME=testuser
export TAP_PASSWORD=testuser
# proxysql privileged test connection
export TAP_ROOTHOST=127.0.0.1
export TAP_ROOTPORT=6033
export TAP_ROOTUSERNAME=root
export TAP_ROOTPASSWORD=root
# proxysql admin connection
export TAP_ADMINHOST=127.0.0.1
export TAP_ADMINPORT=6032
export TAP_ADMINUSERNAME=admin
export TAP_ADMINPASSWORD=admin
# mysql admin connection
export TAP_MYSQLHOST=$( [[ ${DOCKER_MODE} =~ dns ]] && echo -n "mysql1.infra-mysql57" || echo -n "127.0.0.1" )
export TAP_MYSQLPORT=$( [[ ${DOCKER_MODE} =~ dns ]] && echo -n "3306" || echo -n "13306" )
export TAP_MYSQLUSERNAME=root
export TAP_MYSQLPASSWORD=root

# PostgreSQL env variables
# proxysql unpriviliged test connection
export TAP_PGSQL_HOST=127.0.0.1
export TAP_PGSQL_PORT=6133
export TAP_PGSQL_USERNAME=testuser
export TAP_PGSQL_PASSWORD=testuser
# proxysql privileged test connection
export TAP_PGSQLROOT_HOST=127.0.0.1
export TAP_PGSQLROOT_PORT=6133
export TAP_PGSQLROOT_USERNAME=postgres
export TAP_PGSQLROOT_PASSWORD=postgres
# proxysql admin connection
export TAP_PGSQLADMIN_HOST=127.0.0.1
export TAP_PGSQLADMIN_PORT=6132
# admin username and password are identical for both MySQL and PostgreSQL.
# pgsql admin connection
export TAP_PGSQLSERVER_HOST=$( [[ ${DOCKER_MODE} =~ dns ]] && echo -n "pgsql1.infra-pgsql16-single" || echo -n "127.0.0.1" )
export TAP_PGSQLSERVER_PORT=$( [[ ${DOCKER_MODE} =~ dns ]] && echo -n "5432" || echo -n "15432" )
export TAP_PGSQLSERVER_USERNAME=postgres
export TAP_PGSQLSERVER_PASSWORD=postgres
# TAP_WORKDIRS - space or nl separated list of folders
# e.g.: "myfolder_tap/ otherfolder_tap/"
#export TAP_WORKDIRS="$WORKSPACE/test/tap/tests/ $WORKSPACE/test/tap/group02_tap_tests"
export TAP_WORKDIRS="$WORKSPACE/test/tap/tests/ $WORKSPACE/test/tap/tests_with_deps/deprecate_eof_support/"
# TAP_WORKDIR - sigle folder only for backwards compatibility
export TAP_WORKDIR="$WORKSPACE/test/tap/tests/"
export INTERNAL_TAP_WORKDIR="$WORKSPACE/test/tap/tests_with_deps/"

### FIXME! need cleanup - multiple names for the same thing
export TEST_DEPS_PATH="$JENKINS_SCRIPTS_PATH/test-scripts/deps"
export TEST_DEPS="${TEST_DEPS_PATH}"
export TAP_DEPS_PATH="${WORKSPACE}/test/tap/tap"
export TAP_DEPS="${TAP_DEPS_PATH}"
#export LD_LIBRARY_PATH="${TEST_DEPS}:${TAP_DEPS}:${LD_LIBRARY_PATH}"


# Test controls
export PROXYSQL_CLUSTER=0
export PROXYSQL_LAYOUT=flat
#export PROXYSQL_LAYOUT=2layer

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
export TEST_PY_TAPINT=0
export TEST_PY_FAILOVER=1
export TEST_PY_WARMING=0
export TEST_PY_READONLY=0

# TAP test filtering
# TAP_INCL/EXCL is a list of regular expressions matching againt filename
# e.g.: "basic-t admin_various_.* reg_test_3[5-7]\d\d-.*"
# logic: ( TAP_WORKDIR & TAP_INCL ) - TAP_EXCL
# ignored if empty
#export TEST_PY_TAP_INCL=".*clickhouse.*-t .*binlog.*-t"
export TEST_PY_TAP_INCL="${TEST_PY_TAP_INCL:-}"
export TEST_PY_TAP_EXCL="${TEST_PY_TAP_EXCL:-}"
export TEST_PY_TAP_EXCL="reg_test_3273_ssl_con-t"
# temporary exclude for postgres
#if [[ $(cd $WORKSPACE && git remote -v) =~ postgres ]]; then
#	export TEST_PY_TAP_EXCL="reg_test_3273_ssl_con-t set_testing-240-t libpq-t"
#fi
export TEST_PY_TAPINT_INCL=""
export TEST_PY_TAPINT_EXCL=""
# for stress testing, repeat the selected set of tests
export TEST_PY_TAP_REPEAT=1
# shuffle and limit TAP tests execution for randomized testing (CI optimization)
# Set to 0 to run all tests normally (alphabetical order)
# Set to N > 0 to shuffle all tests and run only the first N tests
# Useful for CI to run random subsets and catch order-dependent issues
export TEST_PY_TAP_SHUFFLE_LIMIT=0
# dump stats, disable to avoid log polution
export TEST_PY_TAP_DUMP_RUNTIME=1
export TEST_PY_TAP_DUMP_STATS=1
export TEST_PY_TAP_DISK_USAGE=""
# timeout for each individual TAP test in seconds (0 = no timeout)
export TEST_TAP_TIMEOUT=${TEST_TAP_TIMEOUT:-0}

# run single tests
export TEST_SINGLE=1

# run SPIFFE tests
export TEST_SPIFFE=1


# overide these settings in PR
# $WORKSPACE/test/env.sh
if [ -f $WORKSPACE/test/env.sh ]; then
	source $WORKSPACE/test/env.sh
fi

export GIT_CLONE_SRC=https://github.com/sysown/proxysql.git
# for convenient local testing, set up such local bare repo:
#export GIT_CLONE_SRC=/usr/src/proxysql.git

# end
