#!/bin/bash
# Delete package if exists
rm -f /opt/proxysql/binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.x86_64.rpm || true && \
# Cleanup relic directories from a previously failed build
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} /opt/proxysql/proxysql /opt/proxysql/proxysql-${CURVER} || true && \
# Clean and build dependancies and source
cd /opt/proxysql && \
${MAKE} cleanbuild && \
${MAKE} ${MAKEOPT} build_deps && \
${MAKE} ${MAKEOPT} && \
# Prepare package files and build RPM
mkdir -p proxysql/usr/bin proxysql/etc && \
cp src/proxysql proxysql/usr/bin/ && \
cp -a etc proxysql && \
mkdir -p proxysql/usr/share/proxysql/tools && \
cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools && \
mv proxysql proxysql-${CURVER} && \
tar czvf proxysql-${CURVER}.tar.gz proxysql-${CURVER} && \
mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp} && \
mv /opt/proxysql/proxysql-${CURVER}.tar.gz /root/rpmbuild/SOURCES && \
cd /root/rpmbuild && rpmbuild -ba SPECS/proxysql.spec --define "version ${CURVER}" && \
mv /root/rpmbuild/RPMS/x86_64/proxysql-${CURVER}-1.x86_64.rpm /opt/proxysql/binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.x86_64.rpm && \
# Cleanup current build
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} /opt/proxysql/proxysql /opt/proxysql/proxysql-${CURVER}
