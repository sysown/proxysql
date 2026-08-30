#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
connector_dir="${repo_root}/deps/mariadb-client-library"
openssl_root="${repo_root}/deps/libssl/openssl"
export OPENSSL_CONF="${openssl_root}/apps/openssl.cnf"
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

apply_connector_patch() {
	patch -s -d "${source_dir}" -p0 < "${connector_dir}/$1"
}

test -x "${openssl_root}/apps/openssl" || fail "vendored OpenSSL CLI is not built"
test -f "${openssl_root}/libssl.a" || fail "vendored libssl.a is not built"
test -f "${openssl_root}/libcrypto.a" || fail "vendored libcrypto.a is not built"

tar --no-same-owner -zxf \
	"${connector_dir}/mariadb-connector-c-3.3.8-src.tar.gz" \
	-C "${tmp_dir}"
source_dir="${tmp_dir}/mariadb-connector-c-3.3.8-src"
apply_connector_patch plugin_auth_CMakeLists.txt.patch

if ! cmake -S "${source_dir}" -B "${source_dir}" -Wno-dev \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DCMAKE_C_FLAGS=-Wno-error=declaration-after-statement \
		-DOPENSSL_ROOT_DIR="${openssl_root}" \
		-DOPENSSL_INCLUDE_DIR="${openssl_root}/include" \
		-DOPENSSL_SSL_LIBRARY="${openssl_root}/libssl.a" \
		-DOPENSSL_CRYPTO_LIBRARY="${openssl_root}/libcrypto.a" \
		-DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
		>"${tmp_dir}/connector-configure.log" 2>&1; then
	tail -100 "${tmp_dir}/connector-configure.log" >&2
	fail "Connector/C fixture configuration failed"
fi

for patch_name in \
	mariadb_stmt.c.patch \
	mariadb_lib.c.patch \
	mariadb_lib.c.collation.patch \
	mariadb_lib.c.ipv6_fix.patch \
	mariadb_async.c.patch \
	ma_password.c.patch \
	mysql.h.patch \
	ma_priv.h.patch \
	ma_alloc.c.patch \
	ma_charset.c.patch \
	unittest_basic-t.c.patch \
	unittest_charset.c.patch \
	mariadb_dyncol.c-multiplication-overflow.patch \
	ma_array.c-multiplication-overflow.patch \
	zutil.c-multiplication-overflow.patch \
	cr_new_stmt_metadata_removal.patch \
	ps_buffer_stmt_read_all_rows.patch \
	mariadb_stmt_store_result_err.patch \
	empty_split_compress_packet.patch \
	sslkeylogfile.patch \
	client_deprecate_eof.patch \
	mariadb_com.h.patch \
	x509cache.patch \
	mariadb_rpl.patch \
	cmakelists.txt.patch \
	mariadb_lib.c.metadata_column_check.patch \
	bool_keyword.patch
do
	apply_connector_patch "${patch_name}"
done

if ! cmake --build "${source_dir}" --target mariadbclient --parallel 2 \
		>"${tmp_dir}/connector-build.log" 2>&1; then
	tail -100 "${tmp_dir}/connector-build.log" >&2
	fail "patched Connector/C mariadbclient build failed"
fi
test -f "${source_dir}/libmariadb/libmariadbclient.a" || \
	fail "patched Connector/C archive was not produced"

fixture_dir="${tmp_dir}/trust-fixtures"
mkdir "${fixture_dir}" "${fixture_dir}/explicit-capath"
for name in one two unsafe; do
	"${openssl_root}/apps/openssl" req -x509 -newkey rsa:2048 -nodes \
		-subj "/CN=ProxySQL trust-store fixture ${name}" -days 1 \
		-keyout "${fixture_dir}/${name}.key" \
		-out "${fixture_dir}/${name}.pem" >/dev/null 2>&1
done
chmod 0644 "${fixture_dir}/one.pem" "${fixture_dir}/two.pem"
printf '%s\n' 'not a certificate bundle' > "${fixture_dir}/corrupt.pem"
chmod 0644 "${fixture_dir}/corrupt.pem"
chmod 0666 "${fixture_dir}/unsafe.pem"
ln -s "${fixture_dir}/one.pem" "${fixture_dir}/symlink.pem"
cp "${fixture_dir}/one.pem" "${fixture_dir}/explicit-capath/one.pem"
"${openssl_root}/apps/openssl" rehash "${fixture_dir}/explicit-capath" >/dev/null

${CC:-cc} -std=c99 -Wall -Wextra -Werror -pedantic \
	-I"${source_dir}/libmariadb/secure" \
	-I"${openssl_root}/include" \
	"${script_dir}/fixtures/mariadb-default-trust-store.c" \
	"${openssl_root}/libssl.a" "${openssl_root}/libcrypto.a" \
	-pthread -ldl -o "${tmp_dir}/mariadb-default-trust-store"

"${tmp_dir}/mariadb-default-trust-store" \
	"${fixture_dir}/one.pem" \
	"${fixture_dir}/two.pem" \
	"${fixture_dir}/corrupt.pem" \
	"${fixture_dir}/unsafe.pem" \
	"${fixture_dir}/symlink.pem" \
	"${fixture_dir}/missing.pem" \
	"${fixture_dir}/explicit-capath"

if [[ $(uname -s) == Linux ]]; then
	${CC:-cc} -std=gnu99 -Wall -Wextra -Werror \
		-DHAVE_OPENSSL -DHAVE_TLS -DLIBMARIADB -DTHREAD \
		-I"${source_dir}/include" \
		-I"${source_dir}/libmariadb" \
		-I"${openssl_root}/include" \
		"${script_dir}/fixtures/mariadb-thread-ctx-allocation.c" \
		"${source_dir}/libmariadb/libmariadbclient.a" \
		"${openssl_root}/libssl.a" "${openssl_root}/libcrypto.a" \
		-Wl,--wrap=SSL_CTX_new -pthread -ldl \
		-o "${tmp_dir}/mariadb-thread-ctx-allocation"
	"${tmp_dir}/mariadb-thread-ctx-allocation" "${fixture_dir}/one.pem"
fi
