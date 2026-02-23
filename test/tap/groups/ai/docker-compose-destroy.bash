#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose -f "${COMPOSE_FILE}" "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose -f "${COMPOSE_FILE}" "$@"
    else
        echo "[ERROR] docker compose is not available" >&2
        exit 1
    fi
}

echo "[INFO] Stopping AI TAP group backend containers..."
compose down -v --remove-orphans
echo "[INFO] AI TAP group backend containers removed"

