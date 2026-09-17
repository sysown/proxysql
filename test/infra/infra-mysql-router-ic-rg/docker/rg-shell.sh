#!/usr/bin/env bash
# Run a JavaScript snippet with the unmodified MySQL Shell against the
# fixture InnoDB Cluster. `session` and `cluster` are pre-bound.
#
#   rg-shell.sh -e "cluster.setRoutingOption('guideline', 'rg_custom')"
#   rg-shell.sh /path/to/script.js
#
# Connection: MYSQL_ROUTER_IC_HOST (default: $REPORT_HOST) and
# MYSQL_ROUTER_IC_PASSWORD (default: $ROOT_PASSWORD).
set -euo pipefail
export MYSQL_ROUTER_IC_HOST="${MYSQL_ROUTER_IC_HOST:-${REPORT_HOST:-}}"
export MYSQL_ROUTER_IC_PASSWORD="${MYSQL_ROUTER_IC_PASSWORD:-${ROOT_PASSWORD:-}}"
PRELUDE=/usr/local/share/mysql-router-ic/rg-shell-prelude.js

if [[ $# -eq 2 && "$1" == "-e" ]]; then
    BODY="$2"
elif [[ $# -eq 1 && -f "$1" ]]; then
    BODY=$(cat "$1")
else
    echo "usage: rg-shell.sh -e '<js>' | rg-shell.sh <file.js>" >&2
    exit 2
fi

SCRIPT=$(mktemp /tmp/rg-shell.XXXXXX.js)
trap 'rm -f "${SCRIPT}"' EXIT
{ cat "${PRELUDE}"; printf '\n%s\n' "${BODY}"; } > "${SCRIPT}"
mysqlsh --no-wizard --js --file "${SCRIPT}"
