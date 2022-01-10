#!/bin/bash
set -eu

echo "==> Build environment:"
env

ARCH=$PROXYSQL_BUILD_ARCH
echo "==> $ARCH architecture detected for package"

echo "==> Cleaning"
# Delete package if exists
rm -f /opt/proxysql/binaries/proxysql_${CURVER}-${PKG_RELEASE}_$ARCH.deb || true
# Cleanup relic directories from a previously failed build
rm -f /opt/proxysql/proxysql.ctl /opt/proxysql/proxysql || true

# Clean and build dependancies and source
echo "==> Building"
cd /opt/proxysql
if [[ -z ${PROXYSQL_BUILD_TYPE:-} ]] ; then
	deps_target="build_deps"
	build_target=""
else
	deps_target="build_deps_$PROXYSQL_BUILD_TYPE"
	build_target="$PROXYSQL_BUILD_TYPE"
fi
${MAKE} cleanbuild
${MAKE} ${MAKEOPT} "${deps_target}"

if [[ -z ${build_target} ]] ; then
	${MAKE} ${MAKEOPT}
else
	${MAKE} ${MAKEOPT} "${build_target}"
fi
touch /opt/proxysql/src/proxysql

# Prepare package files and build DEB
echo "==> Packaging"
cp /root/ctl/proxysql.ctl /opt/proxysql/proxysql.ctl
sed -i "s/PKG_VERSION_CURVER/${CURVER}/g" /opt/proxysql/proxysql.ctl
sed -i "s/PKG_ARCH/${ARCH}/g" /opt/proxysql/proxysql.ctl
cp /opt/proxysql/src/proxysql /opt/proxysql/
equivs-build proxysql.ctl
mv "/opt/proxysql/proxysql_${CURVER}_$ARCH.deb" "./binaries/proxysql_${CURVER}-${PKG_RELEASE}_$ARCH.deb"
# Cleanup current build
rm -f /opt/proxysql/proxysql.ctl /opt/proxysql/proxysql
