# pg-compat TAP group environment (SP-2 polyglot PG test foundation).
#
# The backend is the dbdeployer PG17 primary + 2-replica infra, which deploys
# all three nodes in ONE container (single hostname, three ports). Downstream
# SP-2 tasks (Toxiproxy, ProxySQL config, pytest harness) consume THESE vars.

export INFRA_TYPE="infra-dbdeployer-pgsql17-repl"

# Single container -> one host, three auto-derived ports (17.10 => 16710-16712).
export PGCOMPAT_PRIMARY_HOST="dbdeployer1.${INFRA_ID}"
export PGCOMPAT_PRIMARY_PORT="16710"
export PGCOMPAT_REPLICA1_HOST="dbdeployer1.${INFRA_ID}"
export PGCOMPAT_REPLICA1_PORT="16711"
export PGCOMPAT_REPLICA2_HOST="dbdeployer1.${INFRA_ID}"
export PGCOMPAT_REPLICA2_PORT="16712"

# Toxiproxy sidecar sits between ProxySQL and each PG backend node so later
# SP-2/SP-4 tasks can degrade backends individually (passthrough only today).
export PGCOMPAT_TOXI_ADMIN="toxiproxy.${INFRA_ID}:8474"
export PGCOMPAT_TOXI_PRIMARY_HOST="toxiproxy.${INFRA_ID}"
export PGCOMPAT_TOXI_PRIMARY_PORT="6001"
export PGCOMPAT_TOXI_REPLICA1_HOST="toxiproxy.${INFRA_ID}"
export PGCOMPAT_TOXI_REPLICA1_PORT="6002"
export PGCOMPAT_TOXI_REPLICA2_HOST="toxiproxy.${INFRA_ID}"
export PGCOMPAT_TOXI_REPLICA2_PORT="6003"
