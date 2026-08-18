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

# clean is expensive, do it before, outside of container
#${MAKE} cleanbuild
#
# Pass through the chassis tier flag explicitly to make. WITHTSAN /
# WITHASAN / WITHGCOV come through via the docker-compose.yml env
# passthrough (the Makefile reads them via $(WITHTSAN) etc.), so they
# don't need to be replicated here.  PROXYSQL40=1 builds and packages
# all v4.0 plugins — PROXYSQLGENAI is no longer a separate flag.
EXTRA=""
[[ "${PROXYSQL40:-}" == "1" ]] && EXTRA="$EXTRA PROXYSQL40=1"
# SKIP_GENAI_UNIT_TESTS=1 lets ci-builds.yml's -tap-mysqlx matrix
# variant skip the ~14 genai_*_unit-t binaries (each links 30+
# plugins/genai/src/*.cpp at -O0 -ggdb, ~160 MB apiece) so the
# in-build working set fits the runner's ~14 GB free disk.
# CI-mysqlx, the only consumer of -tap-mysqlx, never runs them.
[[ "${SKIP_GENAI_UNIT_TESTS:-}" == "1" ]] && EXTRA="$EXTRA SKIP_GENAI_UNIT_TESTS=1"
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
# loader; runtime features (mysqlx, genai/MCP, etc.) ship as separate
# .so files installed to /usr/lib/proxysql/ and named in proxysql.cnf
# `plugins=("...")` to be loaded.  Conditional on PROXYSQL40=1 so
# v3.x deb packaging stays unchanged.
mkdir -p ./plugins
PLUGIN_FILES_BLOCK=""
add_plugin_to_pkg() {
    # $1 = source path under ../plugins/, $2 = file basename to ship
    local src="$1"
    local basename="$2"
    if [[ -f "${src}" ]]; then
        cp "${src}" "./plugins/${basename}"
        # Build the equivs `Files:` line for this plugin.  Each line
        # starts with a single literal space (equivs continuation
        # marker) and a real newline terminator.  Avoid string escapes
        # — interpolation happens in bash here, not awk/sed later.
        PLUGIN_FILES_BLOCK+=$' plugins/'"${basename}"$' /usr/lib/proxysql/\n'
    fi
}
if [[ "${PROXYSQL40:-}" == "1" ]]; then
    add_plugin_to_pkg "../plugins/mysqlx/ProxySQL_MySQLX_Plugin.so" "ProxySQL_MySQLX_Plugin.so"
    add_plugin_to_pkg "../plugins/genai/ProxySQL_GenAI_Plugin.so" "ProxySQL_GenAI_Plugin.so"
fi

# Replace the PKG_PLUGIN_FILES_PLACEHOLDER line with the assembled
# block.  We use `awk` reading the replacement block from a separate
# file rather than via -v; -v parses backslash escapes in the value
# string, which mangles paths.  Reading the file verbatim sidesteps
# that entirely — and also handles the empty-replacement (v3.x) case
# by simply not printing the placeholder line.
printf '%s' "${PLUGIN_FILES_BLOCK}" > ./proxysql.ctl.plugins
awk '
    BEGIN { while ((getline line < "./proxysql.ctl.plugins") > 0) repl = repl line "\n"; close("./proxysql.ctl.plugins") }
    $0 == "PKG_PLUGIN_FILES_PLACEHOLDER" { printf "%s", repl; next }
    { print }
' ./proxysql.ctl > ./proxysql.ctl.new && mv ./proxysql.ctl.new ./proxysql.ctl
rm -f ./proxysql.ctl.plugins

# Defensive fail-fast: if the placeholder somehow survived (ctl file
# reorganised, awk failed silently), abort rather than ship a broken
# package.
if grep -q '^PKG_PLUGIN_FILES_PLACEHOLDER$' ./proxysql.ctl; then
    echo "ERROR: PKG_PLUGIN_FILES_PLACEHOLDER not substituted in proxysql.ctl" >&2
    exit 1
fi
DEB_BUILD_OPTIONS=nostrip equivs-build proxysql.ctl

# Force xz compression for the data tarball.  Ubuntu 22/24's dpkg-deb
# defaults to zstd, while Debian 12/13 still defaults to xz.  The
# release server signs with dpkg-sig 0.13 on dpkg 1.21.1, which
# accepts the signature but then reports BADSIG on `dpkg-sig --verify`
# for the zstd-compressed Ubuntu DEBs.  Repacking to xz makes the
# format consistent across all distros and unblocks signing.  The
# check on data.tar.xz also covers any future dpkg-deb default change
# (e.g. lzma, gzip) by triggering the repack whenever the format
# isn't already xz.  See issue #5580.
PKG="proxysql_${CURVER}_${ARCH}.deb"
if ! ar t "${PKG}" | grep -q '^data\.tar\.xz$'; then
	echo "==> Repacking ${PKG} with xz compression (was: $(ar t "${PKG}" | grep '^data\.tar'))"
	REPACK_DIR=$(mktemp -d)
	dpkg-deb -R "${PKG}" "${REPACK_DIR}"
	dpkg-deb -Zxz -b "${REPACK_DIR}" "${PKG}"
	rm -rf "${REPACK_DIR}"
fi

cp "./${PKG}" "../binaries/proxysql_${CURVER}-${PKG_RELEASE}_${ARCH}.deb"
# get SHA1 of the packaged executable (always xz after the repack above)
ar -p "${PKG}" $(ar t "${PKG}" | grep '^data\.tar') | unxz -c - | tar xvf - ./usr/bin/proxysql -O > tmp/proxysql
sha1sum tmp/proxysql | sed 's|tmp/||' | tee tmp/proxysql.sha1
cp tmp/proxysql.sha1 ../binaries/proxysql_${CURVER}-${PKG_RELEASE}_${ARCH}.id-hash
# Verify plugin .so files are present in the package
if [[ "${PROXYSQL40:-}" == "1" ]]; then
    echo "==> Verifying plugin .so files in package"
    for plugin in ProxySQL_MySQLX_Plugin.so ProxySQL_GenAI_Plugin.so; do
        if dpkg -c "${PKG}" 2>/dev/null | grep -q "/usr/lib/proxysql/${plugin}"; then
            echo "  OK   ${plugin}"
        else
            echo "  FAIL ${plugin} not found in package" >&2
            exit 1
        fi
    done
    echo "==> Plugin packaging verification PASSED"
fi
# Plugin smoke test: verify .so files are valid and export the expected
# descriptor symbol.
if [[ "${PROXYSQL40:-}" == "1" ]]; then
    echo "==> Running plugin smoke test"
    SMOKE_DIR=$(mktemp -d)
    dpkg-deb -R "${PKG}" "${SMOKE_DIR}"
    ALL_OK=0
    for plugin in ProxySQL_MySQLX_Plugin.so ProxySQL_GenAI_Plugin.so; do
        plugin_path="${SMOKE_DIR}/usr/lib/proxysql/${plugin}"
        if [[ -f "${plugin_path}" ]]; then
            if file "${plugin_path}" | grep -q 'ELF 64-bit.*shared object'; then
                echo "  OK   ${plugin} (valid ELF shared library)"
                if nm -D --defined-only "${plugin_path}" 2>/dev/null | grep -q 'proxysql_plugin_descriptor_v1'; then
                    echo "  OK   ${plugin} (exports proxysql_plugin_descriptor_v1)"
                else
                    echo "  FAIL ${plugin} (no proxysql_plugin_descriptor_v1 symbol)" >&2
                    ALL_OK=1
                fi
            else
                echo "  FAIL ${plugin} (not a valid ELF shared object)" >&2
                ALL_OK=1
            fi
        else
            echo "  FAIL ${plugin} (not found in package)" >&2
            ALL_OK=1
        fi
    done
    rm -rf "${SMOKE_DIR}"
    if [[ "${ALL_OK}" != "0" ]]; then
        echo "==> Plugin smoke test FAILED" >&2
        exit 1
    fi
    echo "==> Plugin smoke test PASSED"
fi
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
