#!/bin/bash
# Delete package if exists
rm -f /opt/proxysql/binaries/proxysql_${CURVER}-${PKG_RELEASE}_amd64.deb || true &&
# Cleanup relic directories from a previously failed build
rm -f /opt/proxysql/proxysql.ctl /opt/proxysql/proxysql || true &&
# Clean and build dependancies and source
cd /opt/proxysql && \
${MAKE} cleanbuild && \
${MAKE} ${MAKEOPT} build_deps_debug && \
${MAKE} ${MAKEOPT} debug && \
# Prepare package files and build RPM
cp /root/ctl/proxysql.ctl /opt/proxysql/proxysql.ctl && \
sed -i "s/PKG_VERSION_CURVER/${CURVER}/g" /opt/proxysql/proxysql.ctl && \
cp /opt/proxysql/src/proxysql /opt/proxysql/ && \
equivs-build proxysql.ctl && \
mv /opt/proxysql/proxysql_${CURVER}_amd64.deb ./binaries/proxysql_${CURVER}-${PKG_RELEASE}_amd64.deb && \
# Cleanup current build
rm -f /opt/proxysql/proxysql.ctl /opt/proxysql/proxysql
