#!/usr/bin/env bash

set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
archive_check="${script_dir}/test-vendored-curl-archive.bash"
cc_spec=${CC:-cc}
read -r -a cc_command <<<"${cc_spec}"
ar=${AR:-ar}
platform=$(uname -s)

if (( ${#cc_command[@]} == 0 )); then
	printf 'SKIP: vendored curl archive regressions require a non-empty CC command\n'
	exit 0
fi

case ${platform} in
	Linux|FreeBSD)
	required_tools=("${cc_command[0]}" "${ar}" nm readelf)
	;;
	Darwin)
	required_tools=("${cc_command[0]}" "${ar}" nm)
	;;
	*)
	printf 'SKIP: vendored curl archive regressions do not support %s\n' \
		"${platform}"
	exit 0
	;;
esac

for tool in "${required_tools[@]}"; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		printf 'SKIP: vendored curl archive regressions require %s on %s\n' \
			"${tool}" "${platform}"
		exit 0
	fi
done

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT
failures=0

fail() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

record_failure() {
	printf 'ERROR: %s\n' "$*" >&2
	failures=$((failures + 1))
}

expect_pass() {
	local context=$1
	shift
	local output
	if ! output=$("$@" 2>&1); then
		printf '%s\n' "${output}" >&2
		record_failure "${context}: expected success"
	fi
}

expect_fail() {
	local context=$1
	local expected=$2
	shift 2
	local output
	if output=$("$@" 2>&1); then
		printf '%s\n' "${output}" >&2
		record_failure "${context}: expected failure"
		return
	fi
	[[ "${output}" == *"${expected}"* ]] || {
		printf '%s\n' "${output}" >&2
		record_failure "${context}: expected diagnostic containing '${expected}'"
	}
}

cat > "${tmp_dir}/curl-required.c" <<'EOF'
void curl_easy_cleanup(void) {}
void curl_easy_getinfo(void) {}
void curl_easy_init(void) {}
void curl_easy_perform(void) {}
void curl_easy_setopt(void) {}
void curl_easy_strerror(void) {}
void curl_global_init(void) {}
void curl_slist_append(void) {}
void curl_slist_free_all(void) {}
EOF
"${cc_command[@]}" -c "${tmp_dir}/curl-required.c" -o "${tmp_dir}/curl-required.o"
"${ar}" rcs "${tmp_dir}/good.a" "${tmp_dir}/curl-required.o"

cat > "${tmp_dir}/fake-libssl.c" <<'EOF'
void controlled_libssl_baseline(void) {}
void SSL_CTX_new(void) {}
void DTLSv1_method(void) {}
EOF
cat > "${tmp_dir}/fake-libcrypto.c" <<'EOF'
void controlled_libcrypto_baseline(void) {}
void BN_new(void) {}
void RAND_bytes(void) {}
void d2i_X509(void) {}
void ossl_provider_init(void) {}
void AES_encrypt(void) {}
void PKCS7_new(void) {}
void aesni_encrypt(void) {}
EOF
"${cc_command[@]}" -c "${tmp_dir}/fake-libssl.c" -o "${tmp_dir}/fake-libssl.o"
"${cc_command[@]}" -c "${tmp_dir}/fake-libcrypto.c" -o "${tmp_dir}/fake-libcrypto.o"
"${ar}" rcs "${tmp_dir}/fake-libssl.a" "${tmp_dir}/fake-libssl.o"
"${ar}" rcs "${tmp_dir}/fake-libcrypto.a" "${tmp_dir}/fake-libcrypto.o"

check_archive() {
	local archive=$1
	local curl_la=${2:-}
	local curl_pc=${3:-}
	bash "${archive_check}" "${archive}" "${curl_la}" "${curl_pc}" \
		"${tmp_dir}/fake-libssl.a" "${tmp_dir}/fake-libcrypto.a"
}

expect_fail "missing OpenSSL deny archive" \
	"required vendored OpenSSL deny archive is missing" \
	bash "${archive_check}" "${tmp_dir}/good.a" '' '' \
		"${tmp_dir}/missing-libssl.a" "${tmp_dir}/fake-libcrypto.a"

expect_pass "complete public curl API" \
	check_archive "${tmp_dir}/good.a"

if [[ ${platform} == Linux || ${platform} == FreeBSD ]]; then
	cat > "${tmp_dir}/curl-hidden.c" <<'EOF'
void curl_easy_cleanup(void) {}
void curl_easy_getinfo(void) {}
__attribute__((visibility("hidden"))) void curl_easy_init(void) {}
void curl_easy_perform(void) {}
void curl_easy_setopt(void) {}
void curl_easy_strerror(void) {}
void curl_global_init(void) {}
void curl_slist_append(void) {}
void curl_slist_free_all(void) {}
EOF
	"${cc_command[@]}" -c "${tmp_dir}/curl-hidden.c" -o "${tmp_dir}/curl-hidden.o"
	"${ar}" rcs "${tmp_dir}/hidden.a" "${tmp_dir}/curl-hidden.o"
	expect_fail "hidden required curl API" \
		"missing required GLOBAL DEFAULT curl definition" \
		check_archive "${tmp_dir}/hidden.a"

	cat > "${tmp_dir}/curl-underscored.c" <<'EOF'
void curl_easy_cleanup(void) {}
void curl_easy_getinfo(void) {}
void _curl_easy_init(void) {}
void curl_easy_perform(void) {}
void curl_easy_setopt(void) {}
void curl_easy_strerror(void) {}
void curl_global_init(void) {}
void curl_slist_append(void) {}
void curl_slist_free_all(void) {}
EOF
	"${cc_command[@]}" -c "${tmp_dir}/curl-underscored.c" -o "${tmp_dir}/curl-underscored.o"
	"${ar}" rcs "${tmp_dir}/underscored.a" "${tmp_dir}/curl-underscored.o"
	expect_fail "ELF leading underscore false match" \
		"missing required GLOBAL DEFAULT curl definition" \
		check_archive "${tmp_dir}/underscored.a"
fi

cat > "${tmp_dir}/curl-missing.c" <<'EOF'
void curl_easy_cleanup(void) {}
EOF
"${cc_command[@]}" -c "${tmp_dir}/curl-missing.c" -o "${tmp_dir}/curl-missing.o"
"${ar}" rcs "${tmp_dir}/missing.a" "${tmp_dir}/curl-missing.o"
if [[ ${platform} == Darwin ]]; then
	missing_api_diagnostic="missing required external curl definition"
else
	missing_api_diagnostic="missing required GLOBAL DEFAULT curl definition"
fi
expect_fail "missing required curl APIs" "${missing_api_diagnostic}" \
	check_archive "${tmp_dir}/missing.a"

cat > "${tmp_dir}/curl-undefined.c" <<'EOF'
extern void curl_easy_getinfo(void);
extern void curl_easy_init(void);
extern void curl_easy_perform(void);
extern void curl_easy_setopt(void);
extern void curl_easy_strerror(void);
extern void curl_global_init(void);
extern void curl_slist_append(void);
extern void curl_slist_free_all(void);
void curl_easy_cleanup(void) {}
void require_curl_imports(void) {
	curl_easy_getinfo();
	curl_easy_init();
	curl_easy_perform();
	curl_easy_setopt();
	curl_easy_strerror();
	curl_global_init();
	curl_slist_append();
	curl_slist_free_all();
}
EOF
"${cc_command[@]}" -c "${tmp_dir}/curl-undefined.c" -o "${tmp_dir}/curl-undefined.o"
"${ar}" rcs "${tmp_dir}/undefined.a" "${tmp_dir}/curl-undefined.o"
expect_fail "undefined required curl APIs" "${missing_api_diagnostic}" \
	check_archive "${tmp_dir}/undefined.a"

cat > "${tmp_dir}/openssl-core.c" <<'EOF'
void SSL_CTX_new(void) {}
EOF
"${cc_command[@]}" -c "${tmp_dir}/openssl-core.c" -o "${tmp_dir}/openssl-core.o"
"${ar}" rcs "${tmp_dir}/flattened-openssl.a" \
	"${tmp_dir}/curl-required.o" "${tmp_dir}/openssl-core.o"
expect_fail "flattened OpenSSL ownership" "embedded OpenSSL definition" \
	check_archive "${tmp_dir}/flattened-openssl.a"

for openssl_symbol in BN_new RAND_bytes d2i_X509 ossl_provider_init; do
	printf 'void %s(void) {}\n' "${openssl_symbol}" > \
		"${tmp_dir}/${openssl_symbol}.c"
	"${cc_command[@]}" -c "${tmp_dir}/${openssl_symbol}.c" -o \
		"${tmp_dir}/${openssl_symbol}.o"
	"${ar}" rcs "${tmp_dir}/${openssl_symbol}.a" \
		"${tmp_dir}/curl-required.o" "${tmp_dir}/${openssl_symbol}.o"
	expect_fail "embedded OpenSSL family ${openssl_symbol}" \
		"embedded OpenSSL definition" \
		check_archive "${tmp_dir}/${openssl_symbol}.a"
done

for openssl_symbol in AES_encrypt PKCS7_new DTLSv1_method aesni_encrypt; do
	printf 'void %s(void) {}\n' "${openssl_symbol}" > \
		"${tmp_dir}/${openssl_symbol}.c"
	"${cc_command[@]}" -c "${tmp_dir}/${openssl_symbol}.c" -o \
		"${tmp_dir}/${openssl_symbol}.o"
	"${ar}" rcs "${tmp_dir}/${openssl_symbol}.a" \
		"${tmp_dir}/curl-required.o" "${tmp_dir}/${openssl_symbol}.o"
	expect_fail "exact OpenSSL deny symbol ${openssl_symbol}" \
		"embedded OpenSSL definition" \
		check_archive "${tmp_dir}/${openssl_symbol}.a"
done

if [[ ${platform} == Linux || ${platform} == FreeBSD ]]; then
	cat > "${tmp_dir}/hidden-openssl.c" <<'EOF'
__attribute__((visibility("hidden"))) void AES_encrypt(void) {}
EOF
	cat > "${tmp_dir}/localized-openssl.c" <<'EOF'
__attribute__((used)) static void AES_encrypt(void) {}
EOF
	for visibility in hidden localized; do
		"${cc_command[@]}" -c "${tmp_dir}/${visibility}-openssl.c" -o \
			"${tmp_dir}/${visibility}-openssl.o"
		"${ar}" rcs "${tmp_dir}/${visibility}-openssl.a" \
			"${tmp_dir}/curl-required.o" \
			"${tmp_dir}/${visibility}-openssl.o"
		expect_fail "${visibility} exact OpenSSL deny symbol" \
			"embedded OpenSSL definition" \
			check_archive "${tmp_dir}/${visibility}-openssl.a"
	done
fi

cat > "${tmp_dir}/curl-owned-tls.c" <<'EOF'
void TLS_curl_owned_helper(void) {}
EOF
"${cc_command[@]}" -c "${tmp_dir}/curl-owned-tls.c" -o "${tmp_dir}/curl-owned-tls.o"
"${ar}" rcs "${tmp_dir}/curl-owned-tls.a" \
	"${tmp_dir}/curl-required.o" "${tmp_dir}/curl-owned-tls.o"
expect_pass "curl-owned TLS helper" \
	check_archive "${tmp_dir}/curl-owned-tls.a"

"${ar}" rcs "${tmp_dir}/libcrypto.a" "${tmp_dir}/openssl-core.o"
"${ar}" rcs "${tmp_dir}/nested.a" \
	"${tmp_dir}/curl-required.o" "${tmp_dir}/libcrypto.a"
expect_fail "nested archive" "nested archive member" \
	check_archive "${tmp_dir}/nested.a"

cp "${tmp_dir}/libcrypto.a" "${tmp_dir}/payload.bin"
"${ar}" rcs "${tmp_dir}/renamed-nested.a" \
	"${tmp_dir}/curl-required.o" "${tmp_dir}/payload.bin"
expect_fail "renamed nested archive" "is not a recognized object file" \
	check_archive "${tmp_dir}/renamed-nested.a"

cat > "${tmp_dir}/incomplete.la" <<'EOF'
dependency_libs=' -L/vendored/openssl'
EOF
cat > "${tmp_dir}/complete.pc" <<'EOF'
Libs: -L${libdir} -lcurl -lssl -lcrypto -lz /vendored/openssl/libssl.a /vendored/openssl/libcrypto.a
EOF
expect_fail "partial curl dependency metadata arguments" \
	"Usage:" \
	bash "${archive_check}" "${tmp_dir}/good.a" "${tmp_dir}/incomplete.la"
expect_fail "incomplete curl dependency metadata" \
	"libcurl.la is missing required dependency" \
	check_archive "${tmp_dir}/good.a" \
		"${tmp_dir}/incomplete.la" "${tmp_dir}/complete.pc"

if [[ -z ${CURL_ARCHIVE_COMPOSITE_CC_CHECK:-} ]]; then
	expect_pass "composite CC command" env CURL_ARCHIVE_COMPOSITE_CC_CHECK=1 \
		CC="env ${cc_spec}" bash "${BASH_SOURCE[0]}"
fi

if (( failures != 0 )); then
	fail "vendored curl archive regressions failed: ${failures} case(s)"
fi

printf 'Vendored curl archive regression tests passed\n'
