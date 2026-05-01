#!/bin/bash
set -eu

echo "==> Build environment:"
env

ARCH=$(rpm --eval '%{_arch}')
echo "==> '${ARCH}' architecture detected for package"

DIST=$(source /etc/os-release; echo ${ID%%[-._ ]*}${VERSION%%[-._ ]*})
echo "==> '${DIST}' distro detected for package"

echo -e "==> C compiler: ${CC} -> $(readlink -e $(type -p ${CC}))\n$(${CC} --version)"
echo -e "==> C++ compiler: ${CXX} -> $(readlink -e $(type -p ${CXX}))\n$(${CXX} --version)"
#echo -e "==> linker version:\n$ ${LD} -> $(readlink -e $(type -p ${LD}))\n$(${LD} --version)"

echo "==> Cleaning"
# Delete package if exists
rm -f /opt/proxysql/binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.${ARCH}.rpm || true
# Cleanup relic directories from a previously failed build
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} /opt/proxysql/proxysql /opt/proxysql/proxysql-${CURVER} || true

# Clean and build dependancies and source
echo "==> Building"
git config --system --add safe.directory '/opt/proxysql'
cd /opt/proxysql
echo "==> ProxySQL '$(git describe --long --abbrev=7)'"
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
echo "==> Setting SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
# touch is expensive, do it before, outside of container
#find . -not -path "./binaries/*" -not -path "./.git/*" | xargs touch -h --date=@${SOURCE_DATE_EPOCH}

if [[ -z ${PROXYSQL_BUILD_TYPE:-} ]] ; then
	deps_target="build_deps"
	build_target=""
elif [[ ${BLD_NAME} =~ \-test|\-tap ]]; then
	deps_target="build_deps"
	build_target="build_tap_test_debug"
else
	deps_target="build_deps_$PROXYSQL_BUILD_TYPE"
	build_target="$PROXYSQL_BUILD_TYPE"
fi

# See deb-compliant entrypoint for the rationale: PROXYSQLGENAI=1
# triggers a build of plugins/mysqlx/ which dynamically links against
# the system libprotobuf (3.x). Some of the v4.0.0 packaging images
# were built before plugins/mysqlx existed and do not yet ship
# protobuf-devel. Install it on demand for SUSE-family images.
if [[ "${PROXYSQLGENAI:-}" == "1" ]]; then
    if ! pkg-config --exists protobuf 2>/dev/null; then
        echo "==> Installing protobuf-devel (required for PROXYSQLGENAI=1 mysqlx plugin build)"
        if command -v zypper >/dev/null 2>&1; then
            zypper install -y libprotobuf-c-devel || zypper install -y protobuf-devel
        else
            echo "ERROR: cannot install protobuf-devel (zypper not present)" >&2
            exit 1
        fi
    fi
fi

# clean is expensive, do it before, outside of container
#${MAKE} cleanbuild
if [[ "${PROXYSQLGENAI:-}" == "1" ]]; then
    ${MAKE} ${MAKEOPT} PROXYSQLGENAI=1 ${deps_target}
    ${MAKE} ${MAKEOPT} PROXYSQLGENAI=1 ${build_target}
else
    ${MAKE} ${MAKEOPT} ${deps_target}
    ${MAKE} ${MAKEOPT} ${build_target}
fi

touch /opt/proxysql/src/proxysql

# Prepare package files and build RPM
echo "==> Packaging"
# prepare build root
cd /opt/proxysql
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} ./proxysql-${CURVER}
mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}
chown -R root:root /root/rpmbuild/SPECS
mkdir -p proxysql-${CURVER}/usr/bin proxysql-${CURVER}/etc proxysql-${CURVER}/usr/share/proxysql/tools
# prepare files
cp src/proxysql proxysql-${CURVER}/usr/bin/
cp -a systemd proxysql-${CURVER}/etc/
cp -a etc/proxysql.cnf proxysql-${CURVER}/etc/
cp -a etc/logrotate.d proxysql-${CURVER}/etc/
cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql-${CURVER}/usr/share/proxysql/tools

# Plugin .so artefacts (v4.0+ chassis); see rhel-compliant entrypoint
# for the full rationale.  Gated on the same build flags so v3.x
# packaging is unchanged.
if [[ "${PROXYSQL40:-}" == "1" || "${PROXYSQLGENAI:-}" == "1" ]]; then
    mkdir -p proxysql-${CURVER}/usr/lib/proxysql
    if [[ -f plugins/mysqlx/ProxySQL_Mysqlx_Plugin.so ]]; then
        cp plugins/mysqlx/ProxySQL_Mysqlx_Plugin.so proxysql-${CURVER}/usr/lib/proxysql/
    fi
fi
if [[ "${PROXYSQLGENAI:-}" == "1" ]]; then
    mkdir -p proxysql-${CURVER}/usr/lib/proxysql
    if [[ -f plugins/genai/ProxySQL_GenAI_Plugin.so ]]; then
        cp plugins/genai/ProxySQL_GenAI_Plugin.so proxysql-${CURVER}/usr/lib/proxysql/
    fi
fi

# Belt-and-braces: only set with_plugins=1 when at least one .so was
# actually staged.  rpmbuild aborts on "File not found by glob" if the
# %files block lists /usr/lib/proxysql/*.so and the directory is empty.
RPMBUILD_WITH_PLUGINS=0
if compgen -G "proxysql-${CURVER}/usr/lib/proxysql/*.so" >/dev/null 2>&1; then
    RPMBUILD_WITH_PLUGINS=1
fi

tar czvf "proxysql-${CURVER}.tar.gz" proxysql-${CURVER}
mv "/opt/proxysql/proxysql-${CURVER}.tar.gz" "/root/rpmbuild/SOURCES"
# build package
RPMBUILD_DEFINES=( --define "version ${CURVER}" )
if [[ "${RPMBUILD_WITH_PLUGINS}" == "1" ]]; then
    # gates the %if 0%{?with_plugins} block in proxysql.spec %files —
    # only enabled when at least one .so was actually staged above.
    RPMBUILD_DEFINES+=( --define "with_plugins 1" )
fi
rpmbuild -bb "${RPMBUILD_DEFINES[@]}" /root/rpmbuild/SPECS/proxysql.spec
cp /root/rpmbuild/RPMS/${ARCH}/proxysql-${CURVER}-1.${ARCH}.rpm ./binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.${ARCH}.rpm
# get SHA1 of the packaged executable
mkdir -p /opt/proxysql/pkgroot/tmp
pushd /opt/proxysql/pkgroot
rpm2cpio /root/rpmbuild/RPMS/${ARCH}/proxysql-${CURVER}-1.${ARCH}.rpm | cpio -iu --to-stdout ./usr/bin/proxysql > tmp/proxysql
sha1sum tmp/proxysql | sed 's|tmp/||' | tee tmp/proxysql.sha1
cp tmp/proxysql.sha1 ../binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.${ARCH}.id-hash
popd
# cleanup
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} ./proxysql-${CURVER} ./pkgroot
