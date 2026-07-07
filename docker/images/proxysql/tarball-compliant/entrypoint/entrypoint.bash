#!/bin/bash
set -eu

ARCH=$(uname -m)
REL_ARCH=$(echo "${ARCH}" | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
DIR_NAME="proxysql-${CURVER}-linux-${REL_ARCH}"
TARBALL_FILE="proxysql-${CURVER}-linux-${REL_ARCH}.tar.gz"

echo "==> Cleaning staging directories"
rm -rf "/opt/proxysql/binaries/${TARBALL_FILE}" "/opt/proxysql/pkgroot" || true

echo "==> Building ProxySQL"
cd /opt/proxysql
git config --system --add safe.directory '/opt/proxysql'

# Determine targets
deps_target="build_deps_clickhouse"
build_target="clickhouse"

${MAKE} ${MAKEOPT} ${deps_target}
${MAKE} ${MAKEOPT} ${build_target}

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

# Add plugins for v4.0+
if [[ "${PROXYSQL40:-}" == "1" ]]; then
    mkdir -p "pkgroot/${DIR_NAME}/lib/proxysql"
    [[ -f plugins/mysqlx/ProxySQL_MySQLX_Plugin.so ]] && cp plugins/mysqlx/ProxySQL_MySQLX_Plugin.so "pkgroot/${DIR_NAME}/lib/proxysql/"
    [[ -f plugins/genai/ProxySQL_GenAI_Plugin.so ]] && cp plugins/genai/ProxySQL_GenAI_Plugin.so "pkgroot/${DIR_NAME}/lib/proxysql/"
fi

echo "==> Compressing Tarball"
cd pkgroot
tar -czf "../binaries/${TARBALL_FILE}" "${DIR_NAME}"

# Generate SHA256 sum file
cd ../binaries
sha256sum "${TARBALL_FILE}" > "${TARBALL_FILE}.sha256"

echo "==> Tarball build successfully completed!"
