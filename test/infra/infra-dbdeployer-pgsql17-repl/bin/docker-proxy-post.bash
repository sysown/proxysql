#!/bin/bash
# Placeholder: ProxySQL configuration for this PG replication backend is added
# in SP-2 Task 4 (pgsql_servers + pgsql_replication_hostgroups + monitor). Kept
# as a no-op so the control flow (docker-compose-init.bash / ensure-infras.bash)
# that unconditionally invokes ./bin/docker-proxy-post.bash succeeds today.
set -e
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/../.env" ] && . "${SCRIPT_DIR}/../.env"

echo ">>> docker-proxy-post.bash (infra-dbdeployer-pgsql17-repl): no-op placeholder (ProxySQL config lands in SP-2 Task 4)."
exit 0
