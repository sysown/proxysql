#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
openssl_root="${repo_root}/deps/libssl/openssl"
ssl_archive="${openssl_root}/libssl.a"
crypto_archive="${openssl_root}/libcrypto.a"
created_stubs=()

cleanup() {
	local path
	for path in "${created_stubs[@]}"; do
		rm -rf "${path}"
	done
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

ensure_stub() {
	local path=$1
	if [[ ! -d "${path}" ]]; then
		mkdir -p "${path}"
		created_stubs+=("${path}")
	fi
}

ensure_stub "${repo_root}/deps/curl/curl-8.16.0"
ensure_stub "${repo_root}/deps/mariadb-client-library/mariadb-connector-c-3.3.8-src"
ensure_stub "${repo_root}/deps/postgresql/postgres-REL_16_10/src/interfaces/libpq"
ensure_stub "${repo_root}/deps/libusual/libusual-f8d49e2"
ensure_stub "${repo_root}/test/deps/mariadb-connector-c/mariadb-connector-c-3.1.9"
ensure_stub "${repo_root}/test/deps/mysql-connector-c/mysql-5.7.44"
ensure_stub "${repo_root}/test/deps/mysql-connector-c-8.4.0/mysql-8.4.0"

dry_run() {
	local make_dir=$1
	local target=$2
	local platform=$3
	local output

	if ! output=$(make -C "${make_dir}" --no-print-directory \
		-B -n "${target}" MAKE=/bin/true UNAME_S="${platform}" 2>&1); then
		printf '%s\n' "${output}" >&2
		fail "dry run failed for ${make_dir##*/}:${target} on ${platform}"
	fi
	output=${output//\"/}
	printf '%s\n' "${output}"
}

assert_contains() {
	local output=$1
	local expected=$2
	local context=$3
	[[ "${output}" == *"${expected}"* ]] || \
		fail "${context} is missing '${expected}'"
}

assert_vendored_first() {
	local output=$1
	local consumer_marker=$2
	local context=$3
	local verify_line
	local consumer_line

	verify_line=$(printf '%s\n' "${output}" | awk 'index($0, "cd libssl && ./verify-source.bash") { print NR; exit }')
	consumer_line=$(printf '%s\n' "${output}" | awk -v marker="${consumer_marker}" 'index($0, marker) { print NR; exit }')
	[[ -n "${verify_line}" ]] || fail "${context} has no vendored OpenSSL prerequisite"
	[[ -n "${consumer_line}" ]] || fail "${context} has no expected configure command"
	(( verify_line < consumer_line )) || fail "${context} configures before vendored OpenSSL"
}

assert_no_system_openssl() {
	local output=$1
	local context=$2
	local forbidden
	for forbidden in \
		'brew --prefix openssl' \
		'CUSTOM_OPENSSL_PATH' \
		'pkg-config --cflags openssl' \
		'-DOPENSSL_ROOT_DIR=/usr' \
		'-DOPENSSL_ROOT_DIR=/opt'
	do
		[[ "${output}" != *"${forbidden}"* ]] || \
			fail "${context} contains system OpenSSL selector '${forbidden}'"
	done
	if printf '%s\n' "${output}" | grep -Eq -- "(^|[[:space:]\"'])(-lssl|-lcrypto)([[:space:]\"']|$)"; then
		fail "${context} contains a bare OpenSSL linker flag"
	fi
}

for platform in Linux Darwin; do
	curl_output=$(dry_run "${repo_root}/deps" curl "${platform}")
	assert_vendored_first "${curl_output}" './configure' "curl/${platform}"
	assert_contains "${curl_output}" "CPPFLAGS=-I${openssl_root}/include" "curl/${platform}"
	assert_contains "${curl_output}" "LDFLAGS=-L${openssl_root}" "curl/${platform}"
	assert_contains "${curl_output}" "LIBS=${ssl_archive} ${crypto_archive}" "curl/${platform}"
	assert_contains "${curl_output}" "--with-openssl=${openssl_root}" "curl/${platform}"
	assert_contains "${curl_output}" '--disable-shared' "curl/${platform}"
	assert_contains "${curl_output}" '--enable-static' "curl/${platform}"
	assert_no_system_openssl "${curl_output}" "curl/${platform}"

	mariadb_output=$(dry_run "${repo_root}/deps" mariadb_client "${platform}")
	assert_vendored_first "${mariadb_output}" 'cmake .' "MariaDB Connector/C/${platform}"
	assert_contains "${mariadb_output}" "-DOPENSSL_ROOT_DIR=${openssl_root}" "MariaDB Connector/C/${platform}"
	assert_contains "${mariadb_output}" "-DOPENSSL_INCLUDE_DIR=${openssl_root}/include" "MariaDB Connector/C/${platform}"
	assert_contains "${mariadb_output}" "-DOPENSSL_SSL_LIBRARY=${ssl_archive}" "MariaDB Connector/C/${platform}"
	assert_contains "${mariadb_output}" "-DOPENSSL_CRYPTO_LIBRARY=${crypto_archive}" "MariaDB Connector/C/${platform}"
	assert_no_system_openssl "${mariadb_output}" "MariaDB Connector/C/${platform}"

	postgres_output=$(dry_run "${repo_root}/deps" postgresql "${platform}")
	assert_vendored_first "${postgres_output}" './configure' "PostgreSQL/${platform}"
	assert_contains "${postgres_output}" "--with-includes=${openssl_root}/include" "PostgreSQL/${platform}"
	assert_contains "${postgres_output}" "--with-libraries=${openssl_root}" "PostgreSQL/${platform}"
	assert_contains "${postgres_output}" "LIBS=${ssl_archive} ${crypto_archive}" "PostgreSQL/${platform}"
	assert_no_system_openssl "${postgres_output}" "PostgreSQL/${platform}"

	libusual_output=$(dry_run "${repo_root}/deps" libusual "${platform}")
	assert_vendored_first "${libusual_output}" './configure' "libusual/${platform}"
	assert_contains "${libusual_output}" "--with-openssl=${openssl_root}" "libusual/${platform}"
	assert_contains "${libusual_output}" "LDFLAGS=${ssl_archive} ${crypto_archive}" "libusual/${platform}"
	assert_no_system_openssl "${libusual_output}" "libusual/${platform}"

	libscram_output=$(dry_run "${repo_root}/deps" libscram "${platform}")
	assert_vendored_first "${libscram_output}" 'LIBOPENSSL_DIR=' "libscram/${platform}"
	assert_contains "${libscram_output}" "LIBOPENSSL_DIR=${openssl_root}/include" "libscram/${platform}"
	assert_no_system_openssl "${libscram_output}" "libscram/${platform}"

	test_mariadb_output=$(dry_run "${repo_root}/test/deps" mariadb_client "${platform}")
	assert_contains "${test_mariadb_output}" "-C ${repo_root}/deps libssl" "test MariaDB Connector/C/${platform}"
	assert_contains "${test_mariadb_output}" "-DOPENSSL_ROOT_DIR=${openssl_root}" "test MariaDB Connector/C/${platform}"
	assert_contains "${test_mariadb_output}" "-DOPENSSL_SSL_LIBRARY=${ssl_archive}" "test MariaDB Connector/C/${platform}"
	assert_contains "${test_mariadb_output}" "-DOPENSSL_CRYPTO_LIBRARY=${crypto_archive}" "test MariaDB Connector/C/${platform}"
	assert_no_system_openssl "${test_mariadb_output}" "test MariaDB Connector/C/${platform}"

	for target in mysql_client mysql8_client; do
		test_mysql_output=$(dry_run "${repo_root}/test/deps" "${target}" "${platform}")
		assert_contains "${test_mysql_output}" "-C ${repo_root}/deps libssl" "test ${target}/${platform}"
		assert_contains "${test_mysql_output}" "-DWITH_SSL=${openssl_root}" "test ${target}/${platform}"
		assert_contains "${test_mysql_output}" "-DOPENSSL_ROOT_DIR=${openssl_root}" "test ${target}/${platform}"
		assert_contains "${test_mysql_output}" "-DOPENSSL_SSL_LIBRARY=${ssl_archive}" "test ${target}/${platform}"
		assert_contains "${test_mysql_output}" "-DOPENSSL_CRYPTO_LIBRARY=${crypto_archive}" "test ${target}/${platform}"
		assert_no_system_openssl "${test_mysql_output}" "test ${target}/${platform}"
	done
done

echo "Vendored OpenSSL consumer contract tests passed"
