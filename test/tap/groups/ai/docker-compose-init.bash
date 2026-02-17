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

wait_for_health() {
    local service="$1"
    local max_wait="${2:-180}"
    local waited=0
    local cid
    cid="$(compose ps -q "${service}")"
    if [ -z "${cid}" ]; then
        echo "[ERROR] Service '${service}' has no running container" >&2
        exit 1
    fi

    while [ "${waited}" -lt "${max_wait}" ]; do
        local status
        status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${cid}" 2>/dev/null || true)"
        if [ "${status}" = "healthy" ] || [ "${status}" = "running" ]; then
            echo "[INFO] ${service} status=${status}"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    echo "[ERROR] Timeout waiting for service '${service}' to become healthy" >&2
    compose ps
    compose logs --tail 100 "${service}" || true
    exit 1
}

echo "[INFO] Starting AI TAP group backend containers..."
compose up -d --remove-orphans

wait_for_health mysql90 240
wait_for_health pgsql 240

echo "[INFO] AI TAP group backend containers are ready"

