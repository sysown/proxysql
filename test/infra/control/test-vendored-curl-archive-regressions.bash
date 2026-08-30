#!/usr/bin/env bash

set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
archive_check="${script_dir}/test-vendored-curl-archive.bash"
cc=${CC:-cc}
ar=${AR:-ar}
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

expect_pass() {
	local context=$1
	shift
	local output
	if ! output=$("$@" 2>&1); then
		printf '%s\n' "${output}" >&2
		fail "${context}: expected success"
	fi
}

expect_fail() {
	local context=$1
	local expected=$2
	shift 2
	local output
	if output=$("$@" 2>&1); then
		printf '%s\n' "${output}" >&2
		fail "${context}: expected failure"
	fi
	[[ "${output}" == *"${expected}"* ]] || {
		printf '%s\n' "${output}" >&2
		fail "${context}: expected diagnostic containing '${expected}'"
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

mkdir "${tmp_dir}/fake-bin"
cat > "${tmp_dir}/fake-bin/readelf" <<'EOF'
#!/usr/bin/env sh
exit 127
EOF
chmod +x "${tmp_dir}/fake-bin/readelf"
expect_pass "portable nm inspection" \
	env PATH="${tmp_dir}/fake-bin:${PATH}" bash "${archive_check}" "${tmp_dir}/good.a"

cat > "${tmp_dir}/curl-missing.c" <<'EOF'
void curl_easy_cleanup(void) {}
EOF
"${cc}" -c "${tmp_dir}/curl-missing.c" -o "${tmp_dir}/curl-missing.o"
"${ar}" rcs "${tmp_dir}/missing.a" "${tmp_dir}/curl-missing.o"
expect_fail "missing required curl APIs" "missing required external curl definition" \
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
expect_fail "undefined required curl APIs" "missing required external curl definition" \
	bash "${archive_check}" "${tmp_dir}/undefined.a"

cat > "${tmp_dir}/openssl-core.c" <<'EOF'
void SSL_CTX_new(void) {}
EOF
"${cc}" -c "${tmp_dir}/openssl-core.c" -o "${tmp_dir}/openssl-core.o"
"${ar}" rcs "${tmp_dir}/flattened-openssl.a" \
	"${tmp_dir}/curl-required.o" "${tmp_dir}/openssl-core.o"
expect_fail "flattened OpenSSL ownership" "embedded OpenSSL definition" \
	bash "${archive_check}" "${tmp_dir}/flattened-openssl.a"

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

printf 'Vendored curl archive regression tests passed\n'
