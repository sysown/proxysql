#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

IMAGE_TAG="${1:-proxysql/ci-infra:proxysql-mysqlbinlog-v2.3}"

# Check that the .deb is present in the build context
if ! ls proxysql-mysqlbinlog_*.deb >/dev/null 2>&1; then
    echo "ERROR: No proxysql-mysqlbinlog .deb found in ${SCRIPT_DIR}"
    echo ""
    echo "Build it from https://github.com/sysown/proxysql_mysqlbinlog (tag 2.3+):"
    echo "  cd /tmp/proxysql_mysqlbinlog && make build-debian12"
    echo "  cp binaries/proxysql-mysqlbinlog_*.deb ${SCRIPT_DIR}/"
    exit 1
fi

echo "Building ${IMAGE_TAG} ..."
docker build -f Dockerfile.reader -t "${IMAGE_TAG}" .

echo ""
echo "Done. To push:"
echo "  docker push ${IMAGE_TAG}"
