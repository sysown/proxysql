#!/bin/bash
set -euo pipefail

mysql_client="${MYSQL_CLIENT_BIN:-mysql}"
admin_user="${TAP_ADMINUSERNAME:-radmin}"
admin_password="${TAP_ADMINPASSWORD:-radmin}"
admin_host="${TAP_ADMINHOST:-proxysql}"
admin_port="${TAP_ADMINPORT:-6032}"
dump_timeout="${GCOV_DUMP_TIMEOUT_SECONDS:-15}"

if [[ ! "${dump_timeout}" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]] \
    || [[ "${dump_timeout}" =~ ^0*([.]0*)?$ ]]; then
    echo "GCOV_DUMP_TIMEOUT_SECONDS must be a positive number of seconds" >&2
    exit 64
fi

exec timeout --signal=TERM --kill-after=5s "${dump_timeout}s" "${mysql_client}" \
    "-u${admin_user}" \
    "-p${admin_password}" \
    "-h${admin_host}" \
    "-P${admin_port}" \
    --batch \
    --skip-column-names \
    -e "PROXYSQL GCOV DUMP"
