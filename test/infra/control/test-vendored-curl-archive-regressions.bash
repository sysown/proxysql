#!/usr/bin/env bash

set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
archive_check="${script_dir}/test-vendored-curl-archive.bash"
cc=${CC:-cc}
ar=${AR:-ar}
platform=$(uname -s)

case ${platform} in
	Linux|FreeBSD)
	required_tools=("${cc%% *}" "${ar}" nm readelf)
	;;
	Darwin)
	required_tools=("${cc%% *}" "${ar}" nm)
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
"${cc}" -c "${tmp_dir}/curl-required.c" -o "${tmp_dir}/curl-required.o"
"${ar}" rcs "${tmp_dir}/good.a" "${tmp_dir}/curl-required.o"
expect_pass "complete public curl API" \
	bash "${archive_check}" "${tmp_dir}/good.a"

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
	"${cc}" -c "${tmp_dir}/curl-hidden.c" -o "${tmp_dir}/curl-hidden.o"
	"${ar}" rcs "${tmp_dir}/hidden.a" "${tmp_dir}/curl-hidden.o"
	expect_fail "hidden required curl API" \
		"missing required GLOBAL DEFAULT curl definition" \
		bash "${archive_check}" "${tmp_dir}/hidden.a"

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
	"${cc}" -c "${tmp_dir}/curl-underscored.c" -o "${tmp_dir}/curl-underscored.o"
	"${ar}" rcs "${tmp_dir}/underscored.a" "${tmp_dir}/curl-underscored.o"
	expect_fail "ELF leading underscore false match" \
		"missing required GLOBAL DEFAULT curl definition" \
		bash "${archive_check}" "${tmp_dir}/underscored.a"
fi

cat > "${tmp_dir}/curl-missing.c" <<'EOF'
void curl_easy_cleanup(void) {}
EOF
"${cc}" -c "${tmp_dir}/curl-missing.c" -o "${tmp_dir}/curl-missing.o"
"${ar}" rcs "${tmp_dir}/missing.a" "${tmp_dir}/curl-missing.o"
if [[ ${platform} == Darwin ]]; then
	missing_api_diagnostic="missing required external curl definition"
else
	missing_api_diagnostic="missing required GLOBAL DEFAULT curl definition"
fi
expect_fail "missing required curl APIs" "${missing_api_diagnostic}" \
	bash "${archive_check}" "${tmp_dir}/missing.a"

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
"${cc}" -c "${tmp_dir}/curl-undefined.c" -o "${tmp_dir}/curl-undefined.o"
"${ar}" rcs "${tmp_dir}/undefined.a" "${tmp_dir}/curl-undefined.o"
expect_fail "undefined required curl APIs" "${missing_api_diagnostic}" \
	bash "${archive_check}" "${tmp_dir}/undefined.a"

cat > "${tmp_dir}/openssl-core.c" <<'EOF'
void SSL_CTX_new(void) {}
EOF
"${cc}" -c "${tmp_dir}/openssl-core.c" -o "${tmp_dir}/openssl-core.o"
"${ar}" rcs "${tmp_dir}/flattened-openssl.a" \
	"${tmp_dir}/curl-required.o" "${tmp_dir}/openssl-core.o"
expect_fail "flattened OpenSSL ownership" "embedded OpenSSL definition" \
	bash "${archive_check}" "${tmp_dir}/flattened-openssl.a"

for openssl_symbol in BN_new RAND_bytes d2i_X509 ossl_provider_init; do
	printf 'void %s(void) {}\n' "${openssl_symbol}" > \
		"${tmp_dir}/${openssl_symbol}.c"
	"${cc}" -c "${tmp_dir}/${openssl_symbol}.c" -o \
		"${tmp_dir}/${openssl_symbol}.o"
	"${ar}" rcs "${tmp_dir}/${openssl_symbol}.a" \
		"${tmp_dir}/curl-required.o" "${tmp_dir}/${openssl_symbol}.o"
	expect_fail "embedded OpenSSL family ${openssl_symbol}" \
		"embedded OpenSSL definition" \
		bash "${archive_check}" "${tmp_dir}/${openssl_symbol}.a"
done

cat > "${tmp_dir}/curl-owned-tls.c" <<'EOF'
void TLS_curl_owned_helper(void) {}
EOF
"${cc}" -c "${tmp_dir}/curl-owned-tls.c" -o "${tmp_dir}/curl-owned-tls.o"
"${ar}" rcs "${tmp_dir}/curl-owned-tls.a" \
	"${tmp_dir}/curl-required.o" "${tmp_dir}/curl-owned-tls.o"
expect_pass "curl-owned TLS helper" \
	bash "${archive_check}" "${tmp_dir}/curl-owned-tls.a"

"${ar}" rcs "${tmp_dir}/libcrypto.a" "${tmp_dir}/openssl-core.o"
"${ar}" rcs "${tmp_dir}/nested.a" \
	"${tmp_dir}/curl-required.o" "${tmp_dir}/libcrypto.a"
expect_fail "nested archive" "nested archive member" \
	bash "${archive_check}" "${tmp_dir}/nested.a"

cp "${tmp_dir}/libcrypto.a" "${tmp_dir}/payload.bin"
"${ar}" rcs "${tmp_dir}/renamed-nested.a" \
	"${tmp_dir}/curl-required.o" "${tmp_dir}/payload.bin"
expect_fail "renamed nested archive" "is not a recognized object file" \
	bash "${archive_check}" "${tmp_dir}/renamed-nested.a"

cat > "${tmp_dir}/incomplete.la" <<'EOF'
dependency_libs=' -L/vendored/openssl'
EOF
cat > "${tmp_dir}/complete.pc" <<'EOF'
Libs: -L${libdir} -lcurl -lssl -lcrypto -lz /vendored/openssl/libssl.a /vendored/openssl/libcrypto.a
EOF
expect_fail "incomplete curl dependency metadata" \
	"libcurl.la is missing required dependency" \
	bash "${archive_check}" "${tmp_dir}/good.a" \
		"${tmp_dir}/incomplete.la" "${tmp_dir}/complete.pc"

if (( failures != 0 )); then
	fail "vendored curl archive regressions failed: ${failures} case(s)"
fi

printf 'Vendored curl archive regression tests passed\n'
