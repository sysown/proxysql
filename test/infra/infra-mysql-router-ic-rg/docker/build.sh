#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
docker build --network=host \
    --build-context router_ic="${SCRIPT_DIR}/../../infra-mysql-router-ic/docker" \
    -t proxysql/ci-infra:mysql-router-ic-rg \
    -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}"
