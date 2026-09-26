#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "${SCRIPT_DIR}"
: "${INFRA_ID:?INFRA_ID must be set}"
export WORKSPACE=${WORKSPACE:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}
export INFRA=infra-mysql-router-ic-rg
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"
export MYSQL_SHELL_QUEUE_HOST_DIR="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/mysql-router/shell-queue"
docker compose -p "${COMPOSE_PROJECT}" down -v
