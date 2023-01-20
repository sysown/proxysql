#!/bin/bash
set -eu

echo "==> Build environment:"
env

ARCH=$(dpkg --print-architecture)
echo "==> '${ARCH}' architecture detected for package"

DIST=$(source /etc/os-release; echo ${ID%%[-._ ]*}${VERSION%%[-._ ]*})
echo "==> '${DIST}' distro detected for package"

echo -e "==> C compiler: ${CC} -> $(readlink -e $(which ${CC}))\n$(${CC} --version)"
echo -e "==> C++ compiler: ${CXX} -> $(readlink -e $(which ${CXX}))\n$(${CXX} --version)"
#echo -e "==> linker version:\n$ ${LD} -> $(readlink -e $(which ${LD}))\n$(${LD} --version)"

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
find /opt/proxysql -not -path "/opt/proxysql/binaries/*" -exec touch -h --date=@${SOURCE_DATE_EPOCH} {} \;

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

# Prepare package files and build DEB
echo "==> Packaging"
mkdir -p /opt/proxysql/pkgroot/tmp || true
pushd /opt/proxysql/pkgroot
cp /root/ctl/proxysql.ctl ./proxysql.ctl
sed -i "s/PKG_VERSION_CURVER/${CURVER}/g" ./proxysql.ctl
sed -i "s/PKG_ARCH/${ARCH}/g" ./proxysql.ctl
cp ../src/proxysql ./
cp -r ../etc ./etc
cp -r ../tools ./tools
cp -r ../systemd ./systemd
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
