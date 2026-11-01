#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SCRIPT="${ROOT}/test/infra/infra-mysql57/bin/docker-mysql-post.bash"
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT
mkdir -p "${TMP}/bin" "${TMP}/state"

cat >"${TMP}/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
set -eu
if [ "$1" = inspect ]; then
    if [ "${FAIL_CONTAINER:-0}" = 1 ]; then echo false; else echo true; fi
    exit 0
fi
if [ "$1" = logs ]; then echo 'fixture container startup log'; exit 0; fi
if [ "$1" = exec ] && [ "$2" = -i ]; then cat >/dev/null; exit 0; fi
if [ "$1" = exec ] && [ "$3" = test ]; then exit 1; fi
if [ "$1" = exec ]; then
    case "$2" in
        *mysql1-1)
            count=0
            [ ! -f "${FIXTURE_STATE}/attempts" ] || count=$(cat "${FIXTURE_STATE}/attempts")
            count=$((count + 1))
            echo "$count" >"${FIXTURE_STATE}/attempts"
            # Two authentication probes per unsuccessful polling pass.
            # Readiness in the final polling interval must still be accepted.
            [ "$count" -ge "${READY_AFTER_PROBES:-599}" ]
            exit $?
            ;;
        *) exit 0 ;;
    esac
fi
echo "unexpected docker command: $*" >&2
exit 2
DOCKER
cat >"${TMP}/bin/sudo" <<'SUDO'
#!/usr/bin/env bash
exec "$@"
SUDO
cat >"${TMP}/bin/sleep" <<'SLEEP'
#!/usr/bin/env bash
count=0
[ ! -f "${FIXTURE_STATE}/seconds" ] || count=$(cat "${FIXTURE_STATE}/seconds")
echo "$((count + $1))" >"${FIXTURE_STATE}/seconds"
SLEEP
chmod +x "${TMP}/bin/"*
cat >"${TMP}/.env" <<ENV
INFRA_LOGS_PATH=${TMP}/logs
INFRA_ID=fixture
COMPOSE_PROJECT=fixture
ROOT_PASSWORD=fixture
INFRA=fixture
ENV
export PATH="${TMP}/bin:${PATH}" FIXTURE_STATE="${TMP}/state"

if ! (cd "${TMP}" && bash "${SCRIPT}") >"${TMP}/delayed.log" 2>&1; then
    cat "${TMP}/delayed.log" >&2
    echo 'FAIL: a running database ready in the final polling interval must reach provisioning' >&2
    exit 1
fi
grep -q 'Configuring users on fixture-mysql1-1' "${TMP}/delayed.log"
grep -q 'Configuring users on fixture-mysql3-1' "${TMP}/delayed.log"
[ "$(cat "${TMP}/state/seconds")" -eq 598 ]

rm -f "${TMP}/state/attempts" "${TMP}/state/seconds"
if (cd "${TMP}" && READY_AFTER_PROBES=601 bash "${SCRIPT}") >"${TMP}/timeout.log" 2>&1; then
    echo 'FAIL: a database missing the readiness deadline must fail' >&2
    exit 1
fi
grep -q 'TIMEOUT' "${TMP}/timeout.log"
grep -q 'fixture container startup log' "${TMP}/timeout.log"
[ "$(cat "${TMP}/state/seconds")" -eq 600 ]

rm -f "${TMP}/state/attempts" "${TMP}/state/seconds"
if (cd "${TMP}" && FAIL_CONTAINER=1 bash "${SCRIPT}") >"${TMP}/stopped.log" 2>&1; then
    echo 'FAIL: a stopped database container must fail immediately' >&2
    exit 1
fi
grep -q 'is NOT running' "${TMP}/stopped.log"
[ ! -f "${TMP}/state/seconds" ]
echo 'PASS: late readiness succeeds, missed deadlines report logs, and stopped containers fail immediately'
