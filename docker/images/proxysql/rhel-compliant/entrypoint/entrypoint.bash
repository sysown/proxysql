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

# clean is expensive, do it before, outside of container
#${MAKE} cleanbuild
# PROXYSQL40=1 enables the plugin chassis tier; all v4.0 plugins
# (mysqlx, genai, etc.) are built and packaged automatically.
# PROXYSQLGENAI is no longer a separate flag.
EXTRA=""
[[ "${PROXYSQL40:-}" == "1" ]] && EXTRA="$EXTRA PROXYSQL40=1"
[[ "${PROXYSQLAWSIAM:-}" == "1" ]] && EXTRA="$EXTRA PROXYSQLAWSIAM=1"
${MAKE} ${MAKEOPT} ${EXTRA} ${deps_target}
${MAKE} ${MAKEOPT} ${EXTRA} ${build_target}

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
# runtime features (mysqlx, genai/MCP, etc.) ship as separate .so files
# installed to /usr/lib/proxysql/ and named in proxysql.cnf
# `plugins=("...")` to be loaded.  Conditional on PROXYSQL40=1 so
# v3.x rpm packaging stays unchanged.  The proxysql.spec %files section
# already lists /usr/lib/proxysql/* so anything dropped in this
# directory ends up packaged automatically.
if [[ "${PROXYSQL40:-}" == "1" ]]; then
    mkdir -p proxysql/usr/lib/proxysql
    # mysqlx protocol plugin
    if [[ -f plugins/mysqlx/ProxySQL_MySQLX_Plugin.so ]]; then
        cp plugins/mysqlx/ProxySQL_MySQLX_Plugin.so proxysql/usr/lib/proxysql/
    fi
    # genai/MCP plugin
    if [[ -f plugins/genai/ProxySQL_GenAI_Plugin.so ]]; then
        cp plugins/genai/ProxySQL_GenAI_Plugin.so proxysql/usr/lib/proxysql/
    fi
    if [[ "${PROXYSQLAWSIAM:-}" == "1" ]]; then
        if [[ ! -f plugins/aws_iam/ProxySQL_AwsIam_Plugin.so ]]; then
            echo "ERROR: AWS IAM plugin is missing from feature-enabled build" >&2
            exit 1
        fi
        cp plugins/aws_iam/ProxySQL_AwsIam_Plugin.so proxysql/usr/lib/proxysql/
        mkdir -p proxysql/usr/share/doc/proxysql/aws-sdk-cpp
        for attribution in LICENSE NOTICE THIRD_PARTY_NOTICES.md; do
            source="deps/aws-sdk-cpp/${attribution}"
            if [[ ! -s "${source}" ]]; then
                echo "ERROR: AWS IAM plugin attribution file is missing: ${source}" >&2
                exit 1
            fi
            cp "${source}" proxysql/usr/share/doc/proxysql/aws-sdk-cpp/
        done
    fi
fi

# Belt-and-braces: the spec gates `/usr/lib/proxysql/*.so` under
# `%if 0%{?with_plugins}`, but rpmbuild aborts with "File not found
# by glob" if the directory exists with no .so files.  This can
# happen if a plugin build silently produced no artefact (link
# failure that returned 0, etc.).  Only set with_plugins=1 when at
# least one .so actually made it to the staging directory.
RPMBUILD_WITH_PLUGINS=0
RPMBUILD_WITH_AWS_IAM=0
if compgen -G "proxysql/usr/lib/proxysql/*.so" >/dev/null 2>&1; then
    RPMBUILD_WITH_PLUGINS=1
fi
if [[ "${PROXYSQLAWSIAM:-}" == "1" ]]; then
    RPMBUILD_WITH_AWS_IAM=1
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
if [[ "${RPMBUILD_WITH_AWS_IAM}" == "1" ]]; then
    RPMBUILD_DEFINES+=( --define "with_aws_iam 1" )
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
# Verify plugin .so files are present in the package
if [[ "${PROXYSQL40:-}" == "1" ]]; then
    echo "==> Verifying plugin .so files in package"
    PKG_PATH="/root/rpmbuild/RPMS/${ARCH}/proxysql-${CURVER}-1.${ARCH}.rpm"
    plugins=(ProxySQL_MySQLX_Plugin.so ProxySQL_GenAI_Plugin.so)
    if [[ "${PROXYSQLAWSIAM:-}" == "1" ]]; then
        plugins+=(ProxySQL_AwsIam_Plugin.so)
    fi
    for plugin in "${plugins[@]}"; do
        if rpm -qpl "${PKG_PATH}" 2>/dev/null | grep -q "/usr/lib/proxysql/${plugin}"; then
            echo "  OK   ${plugin}"
        else
            echo "  FAIL ${plugin} not found in package" >&2
            exit 1
        fi
    done
    if [[ "${PROXYSQLAWSIAM:-}" == "1" ]]; then
        for attribution in LICENSE NOTICE THIRD_PARTY_NOTICES.md; do
            if ! rpm -qpl "${PKG_PATH}" 2>/dev/null | grep -q "/usr/share/doc/proxysql/aws-sdk-cpp/${attribution}"; then
                echo "  FAIL AWS IAM attribution ${attribution} not found in package" >&2
                exit 1
            fi
        done
    fi
    echo "==> Plugin packaging verification PASSED"
fi
# Plugin smoke test: verify .so files are valid and export the expected
# descriptor symbol, then attempt a quick start to confirm plugin loading.
if [[ "${PROXYSQL40:-}" == "1" ]]; then
    echo "==> Running plugin smoke test"
    SMOKE_DIR=$(mktemp -d)
    pushd "${SMOKE_DIR}" >/dev/null
    rpm2cpio /root/rpmbuild/RPMS/${ARCH}/proxysql-${CURVER}-1.${ARCH}.rpm | cpio -idm 2>/dev/null
    ALL_OK=0
    plugins=(usr/lib/proxysql/ProxySQL_MySQLX_Plugin.so usr/lib/proxysql/ProxySQL_GenAI_Plugin.so)
    if [[ "${PROXYSQLAWSIAM:-}" == "1" ]]; then
        plugins+=(usr/lib/proxysql/ProxySQL_AwsIam_Plugin.so)
    fi
    for plugin in "${plugins[@]}"; do
        if [[ -f "${plugin}" ]]; then
            if file "${plugin}" | grep -q 'ELF 64-bit.*shared object'; then
                echo "  OK   ${plugin} (valid ELF shared library)"
                if nm -D --defined-only "${plugin}" 2>/dev/null | grep -q 'proxysql_plugin_descriptor_v1'; then
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
    popd >/dev/null
    rm -rf "${SMOKE_DIR}"
    if [[ "${ALL_OK}" != "0" ]]; then
        echo "==> Plugin smoke test FAILED" >&2
        exit 1
    fi
    echo "==> Plugin smoke test PASSED"
fi
# cleanup
rm -fr /root/.pki /root/rpmbuild/{BUILDROOT,RPMS,SRPMS,BUILD,SOURCES,tmp} /opt/proxysql/proxysql /opt/proxysql/proxysql-${CURVER} ./pkgroot
