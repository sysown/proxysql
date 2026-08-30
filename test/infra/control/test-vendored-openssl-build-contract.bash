#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=${OPENSSL_BUILD_CONTRACT_ROOT:-$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)}
source_dir="${repo_root}/deps/libssl/openssl-3.5.7"
tmp_dir=$(mktemp -d)
created_source_stub=0

cleanup() {
	rm -rf "${tmp_dir}"
	if [[ "${created_source_stub}" == 1 ]]; then
		rmdir "${source_dir}" 2>/dev/null || true
	fi
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

if [[ ! -d "${source_dir}" ]]; then
	mkdir "${source_dir}"
	created_source_stub=1
fi

contract_makefile="${tmp_dir}/contract.mk"
printf '%s\n' \
	'.PHONY: print-openssl-contract' \
	'print-openssl-contract:' \
	$'\t@echo "OPENSSL_VERSION=$(OPENSSL_VERSION)"' \
	$'\t@echo "SSL_PATH=$(SSL_PATH)"' \
	$'\t@echo "SSL_IDIR=$(SSL_IDIR)"' \
	$'\t@echo "SSL_LDIR=$(SSL_LDIR)"' \
	$'\t@echo "LIB_SSL_PATH=$(LIB_SSL_PATH)"' \
	$'\t@echo "LIB_CRYPTO_PATH=$(LIB_CRYPTO_PATH)"' \
	$'\t@echo "OPENSSL_STATIC_LIBS=$(OPENSSL_STATIC_LIBS)"' \
	> "${contract_makefile}"

if ! variables=$(make -s -C "${repo_root}/deps" \
	-f Makefile -f "${contract_makefile}" print-openssl-contract 2>&1); then
	printf '%s\n' "${variables}" >&2
	fail "unable to read the OpenSSL Make contract"
fi

expected_path="${repo_root}/deps/libssl/openssl"
for expected in \
	"OPENSSL_VERSION=3.5.7" \
	"SSL_PATH=${expected_path}" \
	"SSL_IDIR=${expected_path}/include" \
	"SSL_LDIR=${expected_path}" \
	"LIB_SSL_PATH=${expected_path}/libssl.a" \
	"LIB_CRYPTO_PATH=${expected_path}/libcrypto.a" \
	"OPENSSL_STATIC_LIBS=${expected_path}/libssl.a ${expected_path}/libcrypto.a"
do
	[[ "${variables}" == *"${expected}"* ]] || \
		fail "Make contract is missing '${expected}'; got: ${variables}"
done

if ! commands=$(make -C "${repo_root}/deps" --no-print-directory \
	-B -n libssl MAKE=/bin/true 2>&1); then
	printf '%s\n' "${commands}" >&2
	fail "make -C deps -n libssl did not produce the vendored build recipe"
fi

line_number() {
	local needle=$1
	local line
	line=$(printf '%s\n' "${commands}" | awk -v needle="${needle}" 'index($0, needle) { print NR; exit }')
	[[ -n "${line}" ]] || fail "dry-run recipe is missing '${needle}'"
	printf '%s\n' "${line}"
}

verify_line=$(line_number 'cd libssl && ./verify-source.bash')
extract_line=$(line_number 'tar --no-same-owner -zxf openssl-3.5.7.tar.gz')
config_line=$(line_number './config no-shared no-tests -fPIC')
ssl_check_line=$(line_number "test -f ${expected_path}/libssl.a")
crypto_check_line=$(line_number "test -f ${expected_path}/libcrypto.a")
stamp_line=$(line_number 'touch libssl/openssl/.proxysql-build-complete')

(( verify_line < extract_line )) || fail "source verification does not precede extraction"
(( extract_line < config_line )) || fail "extraction does not precede OpenSSL configuration"
(( config_line < ssl_check_line )) || fail "archive checks do not follow configuration/build"
(( ssl_check_line < stamp_line )) || fail "libssl.a is not checked before the build stamp"
(( crypto_check_line < stamp_line )) || fail "libcrypto.a is not checked before the build stamp"

for forbidden in \
	'pkg-config' \
	'CUSTOM_OPENSSL_PATH' \
	'OPENSSL_ROOT_DIR' \
	'no-module' \
	'no-dso'
do
	[[ "${variables}${commands}" != *"${forbidden}"* ]] || \
		fail "vendored build contract contains forbidden system/module option '${forbidden}'"
done

if ! clean_commands=$(make -C "${repo_root}/deps" --no-print-directory \
	-n cleanall MAKE=/bin/true 2>&1); then
	printf '%s\n' "${clean_commands}" >&2
	fail "make -C deps -n cleanall failed"
fi
[[ "${clean_commands}" == *'cd libssl && rm -rf openssl-3.5.7'* ]] || \
	fail "cleanall does not remove the extracted OpenSSL build tree"

fixture_root="${tmp_dir}/connector-stamp-fixture"
fixture_test_deps="${fixture_root}/test/deps"
fixture_openssl="${fixture_root}/deps/libssl/openssl"
fixture_stamp="${fixture_openssl}/.proxysql-build-complete"
fixture_connector="${fixture_test_deps}/mariadb-connector-c/mariadb-connector-c/libmariadb/libmariadbclient.a"
mkdir -p "${fixture_root}/src" "${fixture_root}/include" \
	"${fixture_openssl}" "$(dirname -- "${fixture_connector}")"
: > "${fixture_root}/src/proxysql_global.cpp"
: > "${fixture_root}/include/makefiles_vars.mk"
cat > "${fixture_root}/include/makefiles_paths.mk" <<EOF
SSL_PATH := ${fixture_openssl}
SSL_IDIR := ${fixture_openssl}/include
LIB_SSL_PATH := ${fixture_openssl}/libssl.a
LIB_CRYPTO_PATH := ${fixture_openssl}/libcrypto.a
EOF
noop_make="${fixture_root}/noop-make"
advanced_make="${fixture_root}/advanced-make"
cat > "${noop_make}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "${advanced_make}" <<EOF
#!/usr/bin/env bash
if [[ "\$*" == *'-C ${fixture_root}/deps libssl'* ]]; then
	touch ${fixture_stamp}
fi
exit 0
EOF
chmod +x "${noop_make}" "${advanced_make}"
: > "${fixture_stamp}"
: > "${fixture_connector}"
python3 - "${fixture_stamp}" "${fixture_connector}" <<'PY'
import os
import sys

os.utime(sys.argv[1], (1_700_000_000, 1_700_000_000))
os.utime(sys.argv[2], (1_700_000_100, 1_700_000_100))
PY

no_op_bridge_commands=$(make -C "${fixture_test_deps}" --no-print-directory \
	-f "${repo_root}/test/deps/Makefile" -n mariadb_client \
	MAKE="${noop_make}" 2>&1)
[[ "${no_op_bridge_commands}" == *"-C ${fixture_root}/deps libssl"* ]] || \
	fail "test/deps does not reevaluate the incremental OpenSSL target"
[[ "${no_op_bridge_commands}" != *'cd mariadb-connector-c && rm -rf mariadb-connector-c-'* ]] || \
	fail "a no-op OpenSSL delegation rebuilds an up-to-date connector"

advanced_bridge_commands=$(make -C "${fixture_test_deps}" --no-print-directory \
	-f "${repo_root}/test/deps/Makefile" -n mariadb_client \
	MAKE="${advanced_make}" 2>&1)
[[ "${advanced_bridge_commands}" == *'cd mariadb-connector-c && rm -rf mariadb-connector-c-'* ]] || \
	fail "an advanced OpenSSL stamp does not rebuild the stale connector"

echo "Vendored OpenSSL build contract tests passed"
