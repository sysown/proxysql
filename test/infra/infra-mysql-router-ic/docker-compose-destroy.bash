#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "${SCRIPT_DIR}"
: "${INFRA_ID:?INFRA_ID must be set}"
docker compose -p "infra-mysql-router-ic-${INFRA_ID}" down -v
