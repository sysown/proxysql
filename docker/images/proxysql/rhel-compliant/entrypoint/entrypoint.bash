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
# protobuf-devel. Install it on demand for RHEL-family images.
if [[ "${PROXYSQLGENAI:-}" == "1" ]]; then
    if ! pkg-config --exists protobuf 2>/dev/null; then
        echo "==> Installing protobuf-devel (required for PROXYSQLGENAI=1 mysqlx plugin build)"
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y protobuf-devel
        elif command -v yum >/dev/null 2>&1; then
            yum install -y protobuf-devel
        else
            echo "ERROR: cannot install protobuf-devel (neither dnf nor yum present)" >&2
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
mkdir -p proxysql/usr/bin proxysql/etc
cp src/proxysql proxysql/usr/bin/
cp -a systemd proxysql/etc/
cp -a etc/proxysql.cnf proxysql/etc/
cp -a etc/logrotate.d proxysql/etc/
mkdir -p proxysql/usr/share/proxysql/tools
cp -a tools/proxysql_galera_checker.sh tools/proxysql_galera_writer.pl proxysql/usr/share/proxysql/tools

# Plugin .so artefacts (v4.0+ chassis): proxysql becomes the loader;
# runtime features (mysqlx, genai/MCP) ship as separate .so files
# installed to /usr/lib/proxysql/ and named in proxysql.cnf
# `plugins=("...")` to be loaded.  Conditional on the same flags that
# gated the build above so v3.x rpm packaging stays unchanged.  The
# proxysql.spec %files section already lists /usr/lib/proxysql/* so
# anything dropped in this directory ends up packaged automatically.
if [[ "${PROXYSQL40:-}" == "1" || "${PROXYSQLGENAI:-}" == "1" ]]; then
    mkdir -p proxysql/usr/lib/proxysql
    if [[ -f plugins/mysqlx/ProxySQL_MySQLX_Plugin.so ]]; then
        cp plugins/mysqlx/ProxySQL_MySQLX_Plugin.so proxysql/usr/lib/proxysql/
    fi
fi
if [[ "${PROXYSQLGENAI:-}" == "1" ]]; then
    mkdir -p proxysql/usr/lib/proxysql
    if [[ -f plugins/genai/ProxySQL_GenAI_Plugin.so ]]; then
        cp plugins/genai/ProxySQL_GenAI_Plugin.so proxysql/usr/lib/proxysql/
    fi
fi

# Belt-and-braces: the spec gates `/usr/lib/proxysql/*.so` under
# `%if 0%{?with_plugins}`, but rpmbuild aborts with "File not found
# by glob" if the directory exists with no .so files.  This can
# happen if a plugin build silently produced no artefact (link
# failure that returned 0, etc.).  Only set with_plugins=1 when at
# least one .so actually made it to the staging directory.
RPMBUILD_WITH_PLUGINS=0
if compgen -G "proxysql/usr/lib/proxysql/*.so" >/dev/null 2>&1; then
    RPMBUILD_WITH_PLUGINS=1
fi
mv proxysql "proxysql-${CURVER}"
tar czvf "proxysql-${CURVER}.tar.gz" proxysql-${CURVER}
mkdir -p /root/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}
chown -R root:root /root/rpmbuild/SPECS
mv "/opt/proxysql/proxysql-${CURVER}.tar.gz" /root/rpmbuild/SOURCES
# build package
RPMBUILD_DEFINES=( --define "version ${CURVER}" )
if [[ "${RPMBUILD_WITH_PLUGINS}" == "1" ]]; then
    # gates the %if 0%{?with_plugins} block in proxysql.spec %files —
    # only enabled when at least one .so was actually staged above.
    RPMBUILD_DEFINES+=( --define "with_plugins 1" )
fi
cd /root/rpmbuild && rpmbuild -ba SPECS/proxysql.spec "${RPMBUILD_DEFINES[@]}"
cp "/root/rpmbuild/RPMS/${ARCH}/proxysql-${CURVER}-1.${ARCH}.rpm" "/opt/proxysql/binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.${ARCH}.rpm"
# get SHA1 of the packaged executable
mkdir -p /opt/proxysql/pkgroot/tmp
pushd /opt/proxysql/pkgroot
rpm2cpio /root/rpmbuild/RPMS/${ARCH}/proxysql-${CURVER}-1.${ARCH}.rpm | cpio -iu --to-stdout ./usr/bin/proxysql > tmp/proxysql
sha1sum tmp/proxysql | sed 's|tmp/||' | tee tmp/proxysql.sha1
cp tmp/proxysql.sha1 ../binaries/proxysql-${CURVER}-1-${PKG_RELEASE}.${ARCH}.id-hash
popd
# cleanup
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} /opt/proxysql/proxysql /opt/proxysql/proxysql-${CURVER} ./pkgroot
