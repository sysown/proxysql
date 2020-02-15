#!/bin/bash
set -eu

# For troubleshooting...
# while true; do echo hello; sleep 2; done

echo "==> Build environment:"
env

echo "==> Dirty patching to ensure OS deps are installed"

if [[ -f "/usr/bin/python" ]];
then 
    echo "==> Installing dependancies for RHEL compliant version 7"
    yum -y install gnutls-devel libtool || true
else
    echo "==> Installing dependancies for RHEL compliant version 8"
    yum -y install python2 gnutls-devel libtool || true
    ln -s /usr/bin/python2.7 /usr/bin/python || true
fi

echo "==> Cleaning"
# Delete package if exists
rm -f /opt/proxysql/binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.x86_64.rpm || true
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

# Prepare package files and build RPM
echo "==> Packaging"
mkdir -p proxysql/usr/bin proxysql/etc
cp src/proxysql proxysql/usr/bin/
cp -a systemd proxysql/etc/
cp -a etc/proxysql.cnf proxysql/etc/
cp -a etc/logrotate.d proxysql/etc/
mkdir -p proxysql/usr/share/proxysql/tools
cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools
mv proxysql "proxysql-${CURVER}"
tar czvf "proxysql-${CURVER}.tar.gz" proxysql-${CURVER}
mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}
mv "/opt/proxysql/proxysql-${CURVER}.tar.gz" /root/rpmbuild/SOURCES
cd /root/rpmbuild && rpmbuild -ba SPECS/proxysql.spec --define "version ${CURVER}"
mv "/root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm" "/opt/proxysql/binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.x86_64.rpm"
# Cleanup current build
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} /opt/proxysql/proxysql "/opt/proxysql/proxysql-${CURVER}"
