#!/bin/bash
set -eu

echo "==> Build environment:"
env

ARCH=$(dpkg --print-architecture)
echo "==> '${ARCH}' architecture detected for package"

DIST=$(source /etc/os-release; echo ${ID%%[-._ ]*}${VERSION%%[-._ ]*})
echo "==> '${DIST}' distro detected for package"

echo -e "==> C compiler: ${CC} -> $(readlink -e $(type -p ${CC}))\n$(${CC} --version)"
echo -e "==> C++ compiler: ${CXX} -> $(readlink -e $(type -p ${CXX}))\n$(${CXX} --version)"
#echo -e "==> linker version:\n$ ${LD} -> $(readlink -e $(type -p ${LD}))\n$(${LD} --version)"

echo "==> Cleaning"
# Delete package if exists
rm -f /opt/proxysql/binaries/proxysql_${CURVER}-${PKG_RELEASE}_${ARCH}.deb || true
# Cleanup relic directories from a previously failed build
rm -f /opt/proxysql/proxysql.ctl /opt/proxysql/proxysql || true

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

# When the chassis tier is enabled (PROXYSQL40=1, or PROXYSQLGENAI=1
# which implies PROXYSQL40 via the cascade in include/makefiles_vars.mk),
# the build recurses into plugins/mysqlx/ which dynamically links
# against the system libprotobuf (3.x). Some of the v4.0.0 packaging
# images were built before plugins/mysqlx existed and do not yet ship
# libprotobuf-dev. Install it on demand here so the plugin's pkg-config
# check at plugins/mysqlx/Makefile:47 succeeds. The install is
# idempotent — apt-get returns 0 if the package is already present.
# Skip silently for v3.x builds where neither flag is set and the plugin
# path is not exercised.
if [[ "${PROXYSQLGENAI:-}" == "1" || "${PROXYSQL40:-}" == "1" ]]; then
    if ! pkg-config --exists protobuf 2>/dev/null; then
        echo "==> Installing libprotobuf-dev (required for the mysqlx plugin build under PROXYSQL40 / PROXYSQLGENAI)"
        apt-get update -qq
        apt-get install -y --no-install-recommends libprotobuf-dev
    fi
fi

# clean is expensive, do it before, outside of container
#${MAKE} cleanbuild
#
# Pass through the chassis tier flag explicitly to make. WITHTSAN /
# WITHASAN / WITHGCOV come through via the docker-compose.yml env
# passthrough (the Makefile reads them via $(WITHTSAN) etc.), so they
# don't need to be replicated here. PROXYSQLGENAI=1 implies
# PROXYSQL40=1 via the Makefile cascade, so passing one is sufficient
# in either case — but we mirror whichever the operator set so the
# matrix stays explicit for downstream commands that match on env.
EXTRA=""
[[ "${PROXYSQL40:-}" == "1" ]] && EXTRA="$EXTRA PROXYSQL40=1"
[[ "${PROXYSQLGENAI:-}" == "1" ]] && EXTRA="$EXTRA PROXYSQLGENAI=1"
${MAKE} ${MAKEOPT} ${EXTRA} ${deps_target}
${MAKE} ${MAKEOPT} ${EXTRA} ${build_target}

touch /opt/proxysql/src/proxysql

# Prepare package files and build DEB
echo "==> Packaging"
mkdir -p /opt/proxysql/pkgroot/tmp || true
pushd /opt/proxysql/pkgroot
cp /root/ctl/proxysql.ctl ./proxysql.ctl
cp /root/ctl/copyright ./copyright
sed -i "s/PKG_VERSION_CURVER/${CURVER}/g" ./proxysql.ctl
sed -i "s/PKG_ARCH/${ARCH}/g" ./proxysql.ctl
sed -i "s/PKG_YEAR/$(date +%Y)/g" ./copyright
cp ../src/proxysql ./
cp -r ../etc ./etc
cp -r ../tools ./tools
cp -r ../systemd ./systemd

# Plugin .so artefacts (v4.0+ chassis): the proxysql binary is the
# loader; runtime features (mysqlx, genai/MCP) ship as separate .so
# files installed to /usr/lib/proxysql/ and named in proxysql.cnf
# `plugins=("...")` to be loaded.  Conditional on the same flags that
# gated the build above so v3.x deb packaging stays unchanged.
PLUGIN_FILES_LINES=""
mkdir -p ./plugins
if [[ "${PROXYSQL40:-}" == "1" || "${PROXYSQLGENAI:-}" == "1" ]]; then
    if [[ -f ../plugins/mysqlx/ProxySQL_Mysqlx_Plugin.so ]]; then
        cp ../plugins/mysqlx/ProxySQL_Mysqlx_Plugin.so ./plugins/
        PLUGIN_FILES_LINES+=" plugins/ProxySQL_Mysqlx_Plugin.so /usr/lib/proxysql/\n"
    fi
fi
if [[ "${PROXYSQLGENAI:-}" == "1" ]]; then
    if [[ -f ../plugins/genai/ProxySQL_GenAI_Plugin.so ]]; then
        cp ../plugins/genai/ProxySQL_GenAI_Plugin.so ./plugins/
        PLUGIN_FILES_LINES+=" plugins/ProxySQL_GenAI_Plugin.so /usr/lib/proxysql/\n"
    fi
fi
# Substitute the placeholder line in the ctl file.  If no plugins were
# built (v3.x release builds), strip the placeholder line entirely.
if [[ -n "${PLUGIN_FILES_LINES}" ]]; then
    # awk so we don't have to escape the newline-laden RHS for sed.
    awk -v repl="${PLUGIN_FILES_LINES%\\n}" '{
        if ($0 == "PKG_PLUGIN_FILES_PLACEHOLDER") { gsub("\\\\n", "\n", repl); printf "%s", repl; }
        else { print; }
    }' ./proxysql.ctl > ./proxysql.ctl.new && mv ./proxysql.ctl.new ./proxysql.ctl
else
    sed -i '/^PKG_PLUGIN_FILES_PLACEHOLDER$/d' ./proxysql.ctl
fi
DEB_BUILD_OPTIONS=nostrip equivs-build proxysql.ctl
cp ./proxysql_${CURVER}_${ARCH}.deb ../binaries/proxysql_${CURVER}-${PKG_RELEASE}_${ARCH}.deb
# get SHA1 of the packaged executable
if [[ -x $(command -v unzstd) ]]; then
	ar -p proxysql_${CURVER}_${ARCH}.deb $(ar t proxysql_${CURVER}_${ARCH}.deb | grep data.tar) | unzstd -c - | tar xvf - ./usr/bin/proxysql -O > tmp/proxysql
else
	ar -p proxysql_${CURVER}_${ARCH}.deb $(ar t proxysql_${CURVER}_${ARCH}.deb | grep data.tar) | unxz -c - | tar xvf - ./usr/bin/proxysql -O > tmp/proxysql
fi
sha1sum tmp/proxysql | sed 's|tmp/||' | tee tmp/proxysql.sha1
cp tmp/proxysql.sha1 ../binaries/proxysql_${CURVER}-${PKG_RELEASE}_${ARCH}.id-hash
popd
# Cleanup current build
rm -rf /opt/proxysql/pkgroot
exit 0

# Prepare package files and build DEB
echo "==> Packaging"
cp /root/ctl/proxysql.ctl /opt/proxysql/proxysql.ctl
sed -i "s/PKG_VERSION_CURVER/${CURVER}/g" /opt/proxysql/proxysql.ctl
sed -i "s/PKG_ARCH/${ARCH}/g" /opt/proxysql/proxysql.ctl
cp /opt/proxysql/src/proxysql /opt/proxysql/
equivs-build proxysql.ctl
mv "/opt/proxysql/proxysql_${CURVER}_${ARCH}.deb" "./binaries/proxysql_${CURVER}-${PKG_RELEASE}_${ARCH}.deb"
cp "/opt/proxysql/src/proxysql.sha1" "/opt/proxysql/binaries/proxysql_${CURVER}-${PKG_RELEASE}_${ARCH}.id-hash"
# Cleanup current build
rm -f /opt/proxysql/proxysql.ctl /opt/proxysql/proxysql
exit 0
