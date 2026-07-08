#!/usr/bin/env bash
# Build the pg-compat pytest image and run it joined to the infra's backend
# network, so it can reach ProxySQL and the PG backends purely by DNS alias
# (no host ports are published — see the plan's Global Constraints).
set -euo pipefail
: "${INFRA_ID:?}"; : "${WORKSPACE:?}"
NETWORK="${INFRA_ID}_backend"

# Populates PGCOMPAT_{PRIMARY,REPLICA1,REPLICA2}_{HOST,PORT} and
# PGCOMPAT_TOXI_* (per-node vars; there is no single PGCOMPAT_BACKEND_PORT).
source "${WORKSPACE}/test/tap/groups/pg-compat/env.sh"

# ProxySQL frontend (PG protocol) and admin-over-PG-protocol ports/host.
# The proxysql container is started with --hostname proxysql and
# --network-alias proxysql on this network (see start-proxysql-isolated.bash).
export PGCOMPAT_PROXY_HOST="${PGCOMPAT_PROXY_HOST:-proxysql}"
export PGCOMPAT_PROXY_PORT="${PGCOMPAT_PROXY_PORT:-6133}"
export PGCOMPAT_ADMIN_HOST="${PGCOMPAT_ADMIN_HOST:-proxysql}"
export PGCOMPAT_ADMIN_PORT="${PGCOMPAT_ADMIN_PORT:-6132}"

# --network=host: this environment's default docker bridge network has no
# egress to the internet from build containers (buildkit's isolated build
# network cannot resolve/reach deb.debian.org or PyPI at all, verified by
# hand: DNS and raw-IP both fail on the default network, while the host
# itself has working internet access). --network=host runs apt-get/pip
# install steps using the host's network namespace so the image can build
# in environments like this one; the resulting image is unaffected by the
# network used at build time.
docker build --network=host -t proxysql-pg-compat:latest "${WORKSPACE}/test/pg-compat"

# Forward every PGCOMPAT_* env var currently set (from env.sh plus the
# PROXY_/ADMIN_ overrides above) as -e flags, so new vars added to env.sh
# in the future are picked up automatically without editing this script.
ENV_ARGS=()
while IFS='=' read -r name _; do
    [ -n "${name}" ] || continue
    ENV_ARGS+=("-e" "${name}")
done < <(env | grep '^PGCOMPAT_')

# Report output bind mount. The container runs with --rm, so anything pytest
# writes to its own filesystem (e.g. a --junitxml file) is destroyed the
# moment the container exits -- it never reaches the host regardless of "$@".
# Any caller (CI included) that wants a report file back on the host MUST
# write it under /pg-compat-reports inside the container, e.g.:
#   run-pg-compat.bash --junitxml=/pg-compat-reports/pg-compat.xml -rxX
# which lands at "${REPORT_DIR}/pg-compat.xml" on the host afterwards.
# Default REPORT_DIR is workspace-relative so CI's github.workspace-based
# artifact-upload path and a dev's ad-hoc invocation both work unmodified;
# override with PGCOMPAT_REPORT_DIR for a different host location. The
# container's default user is root, so files land root-owned on the host;
# CI chowns them back before uploading (see ci-pg-compat.yml).
REPORT_DIR="${PGCOMPAT_REPORT_DIR:-${WORKSPACE}/pg-compat-reports}"
mkdir -p "${REPORT_DIR}"

docker run --rm --network "${NETWORK}" \
    -e INFRA_ID \
    "${ENV_ARGS[@]}" \
    -v "${REPORT_DIR}:/pg-compat-reports" \
    proxysql-pg-compat:latest "$@"
