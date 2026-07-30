#!/bin/bash
set -eu

# CURVER, MAKE, MAKEOPT, PROXYSQL31/PROXYSQL40 are passed in from the outer
# `make` via the docker-compose `_build` environment passthrough. CURVER
# already reflects the tier (Stable 3.0.x, PROXYSQL31 -> 3.1.x, PROXYSQL40
# -> 4.0.x), so the three tier tarballs get distinct, self-describing names.
ARCH=$(uname -m)
REL_ARCH=$(echo "${ARCH}" | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
DIR_NAME="proxysql-${CURVER}-linux-${REL_ARCH}"
TARBALL_FILE="proxysql-${CURVER}-linux-${REL_ARCH}.tar.gz"

echo "==> Build environment (tier-relevant):"
env | grep -E '^(CURVER|PROXYSQL(31|40|FFTO|TSDB|_BUILD_TYPE)|MAKE|MAKEOPT)=' || true

echo "==> Cleaning staging directories"
rm -rf "/opt/proxysql/binaries/${TARBALL_FILE}" "/opt/proxysql/pkgroot" || true

echo "==> Building ProxySQL"
cd /opt/proxysql
git config --system --add safe.directory '/opt/proxysql'
echo "==> ProxySQL '$(git describe --long --abbrev=7 --tags)'  (tier CURVER=${CURVER})"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"

# Pass the chassis tier flag explicitly on the make command line (matches
# the deb/rpm entrypoints and is override-safe). CURVER above is computed
# by the outer make with the same flag, so the artifact name stays in sync.
EXTRA=""
[[ "${PROXYSQL40:-}" == "1" ]] && EXTRA="${EXTRA} PROXYSQL40=1"
[[ "${PROXYSQL31:-}" == "1" ]] && EXTRA="${EXTRA} PROXYSQL31=1"

deps_target="build_deps_clickhouse"
build_target="clickhouse"

${MAKE} ${MAKEOPT} ${EXTRA} ${deps_target}
${MAKE} ${MAKEOPT} ${EXTRA} ${build_target}

echo "==> Staging Tarball Files"
mkdir -p "pkgroot/${DIR_NAME}/bin"
mkdir -p "pkgroot/${DIR_NAME}/etc/logrotate.d"
mkdir -p "pkgroot/${DIR_NAME}/share/proxysql/tools"
mkdir -p "pkgroot/${DIR_NAME}/systemd/system"

cp src/proxysql "pkgroot/${DIR_NAME}/bin/"
cp etc/proxysql.cnf "pkgroot/${DIR_NAME}/etc/"
cp etc/logrotate.d/proxysql "pkgroot/${DIR_NAME}/etc/logrotate.d/"
cp tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl "pkgroot/${DIR_NAME}/share/proxysql/tools/"
cp systemd/system/proxysql.service systemd/system/proxysql-initial.service "pkgroot/${DIR_NAME}/systemd/system/"
cp LICENSE README.md "pkgroot/${DIR_NAME}/"

# v4.0 chassis: bundle the plugin .so artefacts. The proxysql binary is the
# loader; runtime features (mysqlx, genai/MCP) ship as separate .so files.
# Under PROXYSQL40=1 the Makefile builds them, so fail-fast if any is missing
# rather than ship an incomplete tarball.
if [[ "${PROXYSQL40:-}" == "1" ]]; then
    mkdir -p "pkgroot/${DIR_NAME}/lib/proxysql"
    for plugin in plugins/mysqlx/ProxySQL_MySQLX_Plugin.so plugins/genai/ProxySQL_GenAI_Plugin.so; do
        if [[ ! -f "${plugin}" ]]; then
            echo "ERROR: PROXYSQL40=1 build but '${plugin}' is missing" >&2
            exit 1
        fi
        cp "${plugin}" "pkgroot/${DIR_NAME}/lib/proxysql/"
    done
fi

echo "==> Compressing Tarball"
mkdir -p /opt/proxysql/binaries
cd pkgroot
tar -czf "../binaries/${TARBALL_FILE}" "${DIR_NAME}"

# Generate SHA256 sum file
cd ../binaries
sha256sum "${TARBALL_FILE}" > "${TARBALL_FILE}.sha256"

# Clean up staging (the repo root is bind-mounted, so leftover root-owned
# pkgroot/ would pollute the host git working tree).
rm -rf /opt/proxysql/pkgroot || true

echo "==> Tarball build successfully completed: ${TARBALL_FILE}"
