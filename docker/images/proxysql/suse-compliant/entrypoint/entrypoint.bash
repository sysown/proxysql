#!/bin/bash
set -eu

echo "==> Build environment:"
env

ARCH=$PROXYSQL_BUILD_ARCH
echo "==> $ARCH architecture detected for package"

echo -e "==> C compiler: ${CC} -> $(readlink -e $(which ${CC}))\n$(${CC} --version)"
echo -e "==> C++ compiler: ${CXX} -> $(readlink -e $(which ${CXX}))\n$(${CXX} --version)"
#echo -e "==> linker version:\n$ ${LD} -> $(readlink -e $(which ${LD}))\n$(${LD} --version)"

echo "==> Cleaning"
# Delete package if exists
rm -f /opt/proxysql/binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.$ARCH.rpm || true
# Cleanup relic directories from a previously failed build
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} /opt/proxysql/proxysql /opt/proxysql/proxysql-${CURVER} || true

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

# Prepare package files and build RPM
echo "==> Packaging"
# prepare build root
cd /opt/proxysql
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} ./proxysql-${CURVER}
mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}
mkdir -p proxysql-${CURVER}/usr/bin proxysql-${CURVER}/etc proxysql-${CURVER}/usr/share/proxysql/tools
# prepare files
cp src/proxysql proxysql-${CURVER}/usr/bin/
cp -a systemd proxysql-${CURVER}/etc/
cp -a etc/proxysql.cnf proxysql-${CURVER}/etc/
cp -a etc/logrotate.d proxysql-${CURVER}/etc/
cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql-${CURVER}/usr/share/proxysql/tools
tar czvf "proxysql-${CURVER}.tar.gz" proxysql-${CURVER}
mv "/opt/proxysql/proxysql-${CURVER}.tar.gz" /root/rpmbuild/SOURCES
# build package
#cd /root/rpmbuild && rpmbuild -bb SPECS/proxysql.spec --define "version ${CURVER}"
rpmbuild -bb --define "version ${CURVER}" /root/rpmbuild/SPECS/proxysql.spec
mv /root/rpmbuild/RPMS/${ARCH}/proxysql-${CURVER}-1.${ARCH}.rpm .//binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.${ARCH}.rpm
cp ./src/proxysql.sha1 ./binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.${ARCH}.id-hash
# cleanup
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} ./proxysql-${CURVER}
