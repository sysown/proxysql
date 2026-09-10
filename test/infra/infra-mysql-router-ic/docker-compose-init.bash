#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "${SCRIPT_DIR}"

: "${INFRA_ID:?INFRA_ID must be set}"
export WORKSPACE=${WORKSPACE:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}
export INFRA=infra-mysql-router-ic
export INFRA_ID
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"
export ROOT_PASSWORD=${ROOT_PASSWORD:-$(printf '%s' "${INFRA_ID}" | sha256sum | head -c 10)}

if ! docker image inspect proxysql/ci-infra:mysql-router-ic >/dev/null 2>&1; then
    "${SCRIPT_DIR}/docker/build.sh"
fi

docker compose -p "${COMPOSE_PROJECT}" up -d
CONTAINER="${COMPOSE_PROJECT}-dbdeployer1-1"
if [ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER}" 2>/dev/null || true)" != "true" ]; then
    docker logs "${CONTAINER}" >&2 || true
    echo "ERROR: MySQL Router cluster container failed to start" >&2
    exit 1
fi
for attempt in $(seq 1 180); do
    if docker exec "${CONTAINER}" test -f /tmp/mysql_router_ic_ready 2>/dev/null; then
        "${SCRIPT_DIR}/bin/docker-mysql-post.bash"
        exit 0
    fi
    if [ "${attempt}" = 180 ]; then
        docker logs "${CONTAINER}" >&2 || true
        echo "ERROR: MySQL Router cluster instances did not become ready" >&2
        exit 1
    fi
    sleep 2
done
