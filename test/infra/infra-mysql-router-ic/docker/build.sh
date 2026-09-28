#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
docker build --network=host -t proxysql/ci-infra:mysql-router-ic -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}"
