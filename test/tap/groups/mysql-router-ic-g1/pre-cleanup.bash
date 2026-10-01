#!/usr/bin/env bash
set -u
MYSQL_ROUTER_IC_INFRA=${MYSQL_ROUTER_IC_INFRA:-infra-mysql-router-ic}
BACKEND_CONTAINER="${MYSQL_ROUTER_IC_INFRA}-${INFRA_ID}-dbdeployer1-1"
BACKEND_HOST="dbdeployer1.${MYSQL_ROUTER_IC_INFRA}"
RESULT_DIR="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/mysql-router"
ROUTER_KEY=$(cat "${RESULT_DIR}/router-key" 2>/dev/null || true)
if docker ps --format '{{.Names}}' | grep -qx "${BACKEND_CONTAINER}"; then
	TEARDOWN_PORT=""
	for port in 3306 3307 3308; do
		if docker exec -e MYSQL_PWD="${ROOT_PASSWORD}" "${BACKEND_CONTAINER}" mysql \
			-h"${BACKEND_HOST}" -P"${port}" \
			-uroot -NBe 'SELECT 1' >/dev/null 2>&1; then
			TEARDOWN_PORT="${port}"
			break
		fi
	done
	if [[ -z "${TEARDOWN_PORT}" ]]; then
		echo "WARNING: no reachable InnoDB Cluster member for metadata cleanup" >&2
		exit 0
	fi
	docker exec \
		-e MYSQL_ROUTER_IC_HOST="${BACKEND_HOST}" \
		-e MYSQL_ROUTER_IC_PORT="${TEARDOWN_PORT}" \
		-e MYSQL_ROUTER_IC_PASSWORD="${ROOT_PASSWORD}" \
		-e MYSQL_ROUTER_SHELL_ROUTER="${ROUTER_KEY}" \
		"${BACKEND_CONTAINER}" mysqlsh --no-wizard --js --file \
		"${WORKSPACE}/test/tap/tests/mysql_router/innodb_cluster_teardown.js" \
		>"${RESULT_DIR}/teardown.log" 2>&1 || true
fi
