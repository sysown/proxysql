# Basictests Group Environment
# Runs Python-based functional tests: sysbench benchmark, change-user, failover.
# No ProxySQL cluster needed.

export DEFAULT_MYSQL_INFRA="infra-mysql57"

# No cluster
export SKIP_CLUSTER_START=1

# Test selection
export TEST_PY_BENCHMARK=1
export TEST_PY_CHUSER=1
export TEST_PY_FAILOVER=1

# Disable everything else
export TEST_PY_INTERNAL=0
export TEST_PY_STATS=0
export TEST_PY_TAP=0
export TEST_PY_TAPINT=0
export TEST_PY_WARMING=0
export TEST_PY_READONLY=0
