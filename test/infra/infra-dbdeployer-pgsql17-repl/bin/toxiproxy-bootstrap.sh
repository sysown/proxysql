#!/usr/bin/env bash
# Create one passthrough Toxiproxy proxy per PG backend (primary/replica1/
# replica2). No toxics are added here -- SP-4's chaos suite adds those later.
#
# Idempotent: safe to re-run against an already-bootstrapped toxiproxy (each
# proxy is deleted first, 404-on-delete is tolerated, and a 409 on create is
# treated as "already exists" -> success).
#
# The toxiproxy:2.9.0 image ships no shell/curl, so the admin HTTP API (port
# 8474) is driven from a throwaway curl container attached to the same
# Docker network as toxiproxy and the backend.
set -euo pipefail

: "${INFRA_ID:?INFRA_ID must be set}"

NETWORK="${INFRA_ID}_backend"
TOXI_HOST="toxiproxy.${INFRA_ID}"
TOXI_ADMIN="${TOXI_HOST}:8474"
UPSTREAM_HOST="dbdeployer1.${INFRA_ID}"
CURL_IMAGE="curlimages/curl:8.10.1"

curl_in_net() {
    docker run --rm --network "${NETWORK}" "${CURL_IMAGE}" "$@"
}

echo ">>> toxiproxy-bootstrap: waiting for Toxiproxy admin API at ${TOXI_ADMIN}..."
MAX_WAIT=60
COUNT=0
until curl_in_net -fsS -o /dev/null "http://${TOXI_ADMIN}/version"; do
    if [ "${COUNT}" -ge "${MAX_WAIT}" ]; then
        echo "ERROR: Toxiproxy admin API at ${TOXI_ADMIN} did not become reachable within ${MAX_WAIT}s."
        exit 1
    fi
    echo -n "."
    sleep 2
    COUNT=$((COUNT + 2))
done
echo " OK"

mk() {  # name  listen_port  upstream_port
    local name="$1" port="$2" upstream_port="$3"
    local body="{\"name\":\"${name}\",\"listen\":\"0.0.0.0:${port}\",\"upstream\":\"${UPSTREAM_HOST}:${upstream_port}\",\"enabled\":true}"

    echo -n "  - proxy ${name} (0.0.0.0:${port} -> ${UPSTREAM_HOST}:${upstream_port})..."

    # Delete any pre-existing proxy of the same name; tolerate 404 (doesn't exist yet).
    curl_in_net -sS -o /dev/null -XDELETE "http://${TOXI_ADMIN}/proxies/${name}" || true

    local http_code
    http_code=$(curl_in_net -sS -o /tmp/toxi_create_resp -w '%{http_code}' \
        -XPOST "http://${TOXI_ADMIN}/proxies" -d "${body}" 2>/dev/null || echo "000")

    if [ "${http_code}" = "200" ] || [ "${http_code}" = "201" ] || [ "${http_code}" = "409" ]; then
        echo " OK (${http_code})"
    else
        echo " FAIL (HTTP ${http_code})"
        exit 1
    fi
}

mk pg_primary  6001 16710
mk pg_replica1 6002 16711
mk pg_replica2 6003 16712

echo ">>> toxiproxy-bootstrap: verifying proxy list..."
curl_in_net -fsS "http://${TOXI_ADMIN}/proxies"
echo
echo ">>> toxiproxy-bootstrap: done."
