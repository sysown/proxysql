#!/usr/bin/env bash
# File-based MySQL Shell request queue for TAP tests that cannot `docker exec`
# (the isolated test runner has no Docker socket). The queue directory is
# bind-mounted read-write into both this container and (via the workspace)
# the test runner.
#
# Protocol (all names relative to MYSQL_SHELL_QUEUE_DIR):
#   client: write <id>.js.tmp, then rename it to <id>.js   (atomic submit)
#   server: renames <id>.js -> <id>.running, runs rg-shell.sh on it,
#           writes combined stdout+stderr to <id>.out, then the exit code
#           to <id>.rc (written last, atomically: <id>.rc is the done marker)
# Requests are executed sequentially in lexical <id> order.
set -uo pipefail
QUEUE_DIR="${MYSQL_SHELL_QUEUE_DIR:?MYSQL_SHELL_QUEUE_DIR must be set}"
mkdir -p "${QUEUE_DIR}"
chmod 777 "${QUEUE_DIR}" 2>/dev/null || true
# One server per queue directory, so requests stay sequential.
exec 9>"${QUEUE_DIR}/.server.lock"
if ! flock -n 9; then
    echo "mysqlsh-queue: another server already serves ${QUEUE_DIR}" >&2
    exit 0
fi
# The directory is a host bind mount that survives destroy/re-init: drop
# requests and results left by a previous container.
rm -f "${QUEUE_DIR}"/*.js "${QUEUE_DIR}"/*.js.tmp "${QUEUE_DIR}"/*.running \
    "${QUEUE_DIR}"/*.out "${QUEUE_DIR}"/*.out.tmp "${QUEUE_DIR}"/*.rc "${QUEUE_DIR}"/*.rc.tmp
touch "${QUEUE_DIR}/.server-ready"

shopt -s nullglob
while true; do
    for request in "${QUEUE_DIR}"/*.js; do
        id=$(basename "${request}" .js)
        running="${QUEUE_DIR}/${id}.running"
        mv -f "${request}" "${running}" || continue
        /usr/local/bin/rg-shell.sh "${running}" > "${QUEUE_DIR}/${id}.out.tmp" 2>&1
        rc=$?
        chmod 666 "${QUEUE_DIR}/${id}.out.tmp" 2>/dev/null || true
        mv -f "${QUEUE_DIR}/${id}.out.tmp" "${QUEUE_DIR}/${id}.out"
        printf '%s\n' "${rc}" > "${QUEUE_DIR}/${id}.rc.tmp"
        chmod 666 "${QUEUE_DIR}/${id}.rc.tmp" 2>/dev/null || true
        mv -f "${QUEUE_DIR}/${id}.rc.tmp" "${QUEUE_DIR}/${id}.rc"
        rm -f "${running}"
    done
    sleep 0.2
done
