#!/bin/bash

wait_for_proxysql_ports() {
    local container="$1"
    local timeout_seconds="$2"
    shift 2

    local port
    local attempt

    if [[ ! "${timeout_seconds}" =~ ^[1-9][0-9]*$ ]]; then
        echo "ERROR: Invalid ProxySQL readiness timeout: ${timeout_seconds}" >&2
        return 1
    fi

    echo ">>> Running readiness checks for ProxySQL ports: $*"

    for port in "$@"; do
        if [[ ! "${port}" =~ ^[0-9]+$ ]]; then
            echo "ERROR: Invalid ProxySQL readiness port: ${port}" >&2
            return 1
        fi

        echo -n ">>> Waiting for ${container}:${port} "
        for ((attempt = 0; attempt < timeout_seconds; attempt++)); do
            if docker exec "${container}" \
                bash -c "exec 3<>/dev/tcp/127.0.0.1/${port}" \
                >/dev/null 2>&1; then
                echo "Ready."
                break
            fi
            echo -n "."
            sleep 1
        done

        if [ "${attempt}" -ge "${timeout_seconds}" ]; then
            echo " TIMEOUT"
            docker logs --tail=60 "${container}" >&2 || true
            return 1
        fi
    done
}
