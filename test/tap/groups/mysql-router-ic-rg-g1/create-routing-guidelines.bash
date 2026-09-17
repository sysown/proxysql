#!/usr/bin/env bash
# Fixture hook (called by mysql-router-ic-g1/setup-infras.bash): create the
# Routing Guidelines with the unmodified MySQL Shell 9.x inside the backend
# container and record provenance in ${RESULT_DIR}/routing-guidelines.json.
set -euo pipefail
: "${INFRA_ID:?}" "${WORKSPACE:?}" "${BACKEND_CONTAINER:?}" "${BACKEND_HOST:?}" \
  "${RESULT_DIR:?}" "${ROOT_PASSWORD:?}"

# The TAP runner and ProxySQL live on this network; expose its IPv4 subnet so a
# route can match $.session.sourceIP with NETWORK().
SUBNET=$(docker network inspect "${INFRA_ID}_backend" \
    --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' | grep -m1 -E '^[0-9]+\.' || true)
if [[ -z "${SUBNET}" ]]; then
    # The NETWORK($.session.sourceIP, ...) route could not match any client: fail
    # the fixture instead of creating a guideline the test cannot exercise.
    echo "ERROR: cannot determine the IPv4 subnet of network ${INFRA_ID}_backend" >&2
    exit 1
fi
CLIENT_NETWORK=${SUBNET%/*}
CLIENT_MASK=${SUBNET#*/}

LOG="${RESULT_DIR}/routing_guidelines_setup.log"
docker exec \
    -e MYSQL_ROUTER_IC_HOST="${BACKEND_HOST}" \
    -e MYSQL_ROUTER_IC_PASSWORD="${ROOT_PASSWORD}" \
    -e MYSQL_ROUTER_RG_CLIENT_NETWORK="${CLIENT_NETWORK}" \
    -e MYSQL_ROUTER_RG_CLIENT_MASK="${CLIENT_MASK}" \
    "${BACKEND_CONTAINER}" /usr/local/bin/rg-shell.sh \
    "${WORKSPACE}/test/tap/tests/mysql_router/routing_guidelines_setup.js" \
    | tee "${LOG}"
grep '^MYSQL_ROUTER_RG_FIXTURE=' "${LOG}" | tail -1 \
    | sed 's/^MYSQL_ROUTER_RG_FIXTURE=//' > "${RESULT_DIR}/routing-guidelines.json"
[[ -s "${RESULT_DIR}/routing-guidelines.json" ]]
