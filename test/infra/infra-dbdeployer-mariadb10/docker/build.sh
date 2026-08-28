#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="${1:-proxysql/ci-infra:dbdeployer-mariadb10}"

echo "Building Docker image: ${IMAGE_TAG}"
docker build --network=host -t "${IMAGE_TAG}" -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}"
echo "Done: ${IMAGE_TAG}"
