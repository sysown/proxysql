#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
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

echo "Vendored OpenSSL build contract tests passed"
