#!/bin/bash
# RELIABLY CAPTURE INFRA_ID FROM ENVIRONMENT OR DIRECTORY NAME
if [ -z "${INFRA_ID}" ]; then
    export INFRA_ID=$(basename $(dirname $(pwd)) | sed 's/infra-//; s/docker-//')
fi
# Final safety: if INFRA_ID is still empty or ".", use a default
if [ -z "${INFRA_ID}" ] || [ "${INFRA_ID}" = "." ]; then
    export INFRA_ID="dev-$USER"
fi

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

set -e
set -o pipefail

# make sure we have correct cwd
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

# Load .env but ensure INFRA_ID is preserved
if [ ! -f .env ]; then echo "Error: .env not found"; exit 1; fi
SAVED_INFRA_ID="${INFRA_ID}"
set -a; . .env; set +a
export INFRA_ID="${SAVED_INFRA_ID}"

# Docker Compose version helper - prefer plugin (v2)
COMPOSE_CMD="docker compose"
if ! $COMPOSE_CMD version &>/dev/null; then
    COMPOSE_CMD="docker-compose"
    if ! $COMPOSE_CMD version &>/dev/null; then
        echo "ERROR: Neither 'docker compose' nor 'docker-compose' found!"
        exit 1
    fi
fi

if [ -z "${INFRA_ID}" ]; then echo "Error: INFRA_ID must be set"; exit 1; fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
export INFRA=${PWD##*/}
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${WORKSPACE}/ci_infra_logs}

echo "================================================================================="
echo "Destroying CI Infra '${INFRA}' (Project: ${COMPOSE_PROJECT}) ..."
echo "================================================================================="

# Create temp env file
ENV_FILE=".env.isolated.${INFRA_ID}"
cat <<ENVEOF > "${ENV_FILE}"
INFRA_ID=${INFRA_ID}
ROOT_PASSWORD=${ROOT_PASSWORD}
INFRA=${INFRA}
COMPOSE_PROJECT=${COMPOSE_PROJECT}
INFRA_LOGS_PATH=${INFRA_LOGS_PATH}
ENVEOF

$COMPOSE_CMD --env-file .env --env-file "${ENV_FILE}" -p "${COMPOSE_PROJECT}" down -v
rm -f "${ENV_FILE}"

echo "================================================================================="
echo "Done."
echo "================================================================================="
