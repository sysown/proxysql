#!/bin/bash

set -eu


if [[ "$PROXYSQL_BUILD_ARCH" == *"arm64" ]]; then
    ARCH="arm64"
else    
    ARCH="amd64"
fi      
echo "==> $ARCH architecture detected for package"

# Dirty patch to ensure OS deps are installed:
apt-get update
apt-get -y install gnutls-dev || true
apt-get -y install libgnutls28-dev || true
apt-get -y install libtool || true

# Delete package if exists
rm -f "/opt/proxysql/binaries/proxysql_${CURVER}-${PKG_RELEASE}_$ARCH.deb" || true
# Cleanup relic directories from a previously failed build
rm -f /opt/proxysql/proxysql.ctl /opt/proxysql/proxysql || true
# Clean and build dependancies and source
cd /opt/proxysql
# Patch for Ubuntu 12
if [ "`grep Ubuntu /etc/issue | awk '{print $2}' | cut -d. -f1`" == "12" ]; then
	sed -i -e 's/c++11/c++0x/' lib/Makefile
	sed -i -e 's/c++11/c++0x/' src/Makefile
        cd /opt/proxysql/deps/re2/
	mv re2.tar.gz /tmp/
	wget -O re2.tar.gz https://github.com/sysown/proxysql/raw/v1.3.9/deps/re2/re2-20140304.tgz
        cd /opt/proxysql
fi
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
cp /root/ctl/proxysql.ctl /opt/proxysql/proxysql.ctl
sed -i "s/PKG_VERSION_CURVER/${CURVER}/g" /opt/proxysql/proxysql.ctl
sed -i "s/PKG_ARCH/${ARCH}/g" /opt/proxysql/proxysql.ctl
cp /opt/proxysql/src/proxysql /opt/proxysql/
equivs-build proxysql.ctl
mv "/opt/proxysql/proxysql_${CURVER}_$ARCH.deb" "./binaries/proxysql_${CURVER}-${PKG_RELEASE}_$ARCH.deb"
# Cleanup current build
# Unpatch Ubuntu 12
if [ "`grep Ubuntu /etc/issue | awk '{print $2}' | cut -d. -f1`" == "12" ]; then
        sed -i -e 's/c++0x/c++11/' lib/Makefile
        sed -i -e 's/c++0x/c++11/' src/Makefile
        mv /tmp/re2.tar.gz /opt/proxysql/deps/re2/
fi
rm -f /opt/proxysql/proxysql.ctl /opt/proxysql/proxysql
