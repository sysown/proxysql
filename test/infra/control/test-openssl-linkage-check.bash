#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
checker="${script_dir}/check-openssl-linkage.bash"
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

cat > "${tmp_dir}/fake_ssl.c" <<'EOF'
void *SSL_CTX_new(void) { return (void *)1; }
EOF

cat > "${tmp_dir}/dynamic_executable.c" <<'EOF'
extern void *SSL_CTX_new(void);
int main(void) { return SSL_CTX_new() == 0; }
EOF

cat > "${tmp_dir}/dynamic_plugin.c" <<'EOF'
extern void *SSL_CTX_new(void);
void *plugin_ssl_context(void) { return SSL_CTX_new(); }
EOF

cat > "${tmp_dir}/embedded_plugin.c" <<'EOF'
__attribute__((visibility("hidden")))
const char *OpenSSL_version(int type) {
	(void)type;
	return "fixture";
}
EOF

cat > "${tmp_dir}/curl_importing_plugin.c" <<'EOF'
extern void *curl_easy_init(void);
void *plugin_curl_handle(void) { return curl_easy_init(); }
EOF

cat > "${tmp_dir}/plain_executable.c" <<'EOF'
int main(void) { return 0; }
EOF

cat > "${tmp_dir}/exporting_executable.c" <<'EOF'
void *SSL_CTX_new(void) { return (void *)1; }
int main(void) { return SSL_CTX_new() == 0; }
EOF

cat > "${tmp_dir}/importing_plugin.c" <<'EOF'
extern void *SSL_CTX_new(void);
void *plugin_ssl_context(void) { return SSL_CTX_new(); }
EOF

case $(uname -s) in
	Darwin)
		cc -dynamiclib -Wl,-install_name,@rpath/libssl.3.dylib \
			-o "${tmp_dir}/libssl.3.dylib" "${tmp_dir}/fake_ssl.c"
		ln -s libssl.3.dylib "${tmp_dir}/libssl.dylib"
		cc -o "${tmp_dir}/dynamic-executable" "${tmp_dir}/dynamic_executable.c" \
			-L"${tmp_dir}" -Wl,-rpath,"${tmp_dir}" -lssl
		cc -dynamiclib -o "${tmp_dir}/dynamic-plugin.dylib" \
			"${tmp_dir}/dynamic_plugin.c" -L"${tmp_dir}" \
			-Wl,-rpath,"${tmp_dir}" -lssl
		cc -dynamiclib -o "${tmp_dir}/embedded-plugin.dylib" \
			"${tmp_dir}/embedded_plugin.c"
		cc -o "${tmp_dir}/plain-executable" "${tmp_dir}/plain_executable.c"
		cc -o "${tmp_dir}/exporting-executable" \
			"${tmp_dir}/exporting_executable.c" -Wl,-export_dynamic
		cc -dynamiclib -Wl,-undefined,dynamic_lookup \
			-o "${tmp_dir}/importing-plugin.dylib" \
			"${tmp_dir}/importing_plugin.c"
		cc -dynamiclib -Wl,-undefined,dynamic_lookup \
			-o "${tmp_dir}/curl-importing-plugin.dylib" \
			"${tmp_dir}/curl_importing_plugin.c"
		;;
	Linux|FreeBSD)
		cc -shared -fPIC -Wl,-soname,libssl.so.3 \
			-o "${tmp_dir}/libssl.so.3" "${tmp_dir}/fake_ssl.c"
		ln -s libssl.so.3 "${tmp_dir}/libssl.so"
		cc -o "${tmp_dir}/dynamic-executable" "${tmp_dir}/dynamic_executable.c" \
			-L"${tmp_dir}" -Wl,-rpath,"${tmp_dir}" -Wl,--no-as-needed -lssl
		cc -shared -fPIC -o "${tmp_dir}/dynamic-plugin.so" \
			"${tmp_dir}/dynamic_plugin.c" -L"${tmp_dir}" \
			-Wl,-rpath,"${tmp_dir}" -Wl,--no-as-needed -lssl
		cc -shared -fPIC -o "${tmp_dir}/embedded-plugin.so" \
			"${tmp_dir}/embedded_plugin.c"
		cc -o "${tmp_dir}/plain-executable" "${tmp_dir}/plain_executable.c"
		cc -o "${tmp_dir}/exporting-executable" \
			"${tmp_dir}/exporting_executable.c" -Wl,--export-dynamic
		cc -shared -fPIC -o "${tmp_dir}/importing-plugin.so" \
			"${tmp_dir}/importing_plugin.c"
		cc -shared -fPIC -o "${tmp_dir}/curl-importing-plugin.so" \
			"${tmp_dir}/curl_importing_plugin.c"
		;;
	*)
		fail "unsupported test platform: $(uname -s)"
		;;
esac

expect_rejected() {
	local expected=$1
	shift
	local output
	if output=$("${checker}" "$@" 2>&1); then
		fail "linkage checker unexpectedly accepted: $*"
	fi
	[[ "${output}" == *"${expected}"* ]] || \
		fail "rejection for '$*' did not contain '${expected}'; got: ${output}"
}

plugin_suffix=so
if [[ $(uname -s) == Darwin ]]; then
	plugin_suffix=dylib
fi

expect_rejected 'dynamically depends on forbidden OpenSSL library' \
	"${tmp_dir}/dynamic-executable"
expect_rejected 'dynamically depends on forbidden OpenSSL library' \
	"${tmp_dir}/plain-executable" "${tmp_dir}/dynamic-plugin.${plugin_suffix}"
expect_rejected 'defines OpenSSL core sentinel OpenSSL_version' \
	"${tmp_dir}/plain-executable" "${tmp_dir}/embedded-plugin.${plugin_suffix}"
expect_rejected 'imports SSL_CTX_new but the executable does not export it' \
	"${tmp_dir}/plain-executable" "${tmp_dir}/importing-plugin.${plugin_suffix}"
expect_rejected 'imports curl_easy_init but the executable does not export it' \
	"${tmp_dir}/plain-executable" "${tmp_dir}/curl-importing-plugin.${plugin_suffix}"

pass_output=$("${checker}" \
	"${tmp_dir}/exporting-executable" \
	"${tmp_dir}/importing-plugin.${plugin_suffix}") || \
	fail "linkage checker rejected the valid ownership fixture"
[[ "${pass_output}" == *'OpenSSL linkage check passed'* ]] || \
	fail "valid fixture did not report success; got: ${pass_output}"

if [[ $(uname -s) == Linux ]]; then
	cat > "${tmp_dir}/host_curl.c" <<'EOF'
#include <dlfcn.h>

typedef void *(*plugin_curl_handle_fn)(void);

int main(int argc, char **argv) {
	void *plugin;
	plugin_curl_handle_fn plugin_curl_handle;

	if (argc != 2) return 2;
	plugin = dlopen(argv[1], RTLD_NOW);
	if (plugin == 0) return 3;
	plugin_curl_handle = (plugin_curl_handle_fn)dlsym(plugin, "plugin_curl_handle");
	if (plugin_curl_handle == 0) return 4;
	return plugin_curl_handle() == (void *)0x6115 ? 0 : 5;
}
EOF
	cat > "${tmp_dir}/fake_curl.c" <<'EOF'
void *curl_easy_init(void) { return (void *)0x6115; }
EOF
	cc -c -fPIC -o "${tmp_dir}/fake_curl.o" "${tmp_dir}/fake_curl.c"
	ar rcs "${tmp_dir}/libcurl.a" "${tmp_dir}/fake_curl.o"
	cc -o "${tmp_dir}/curl-owning-executable" "${tmp_dir}/host_curl.c" \
		-Wl,--export-dynamic -Wl,--whole-archive "${tmp_dir}/libcurl.a" \
		-Wl,--no-whole-archive -ldl
	"${tmp_dir}/curl-owning-executable" \
		"${tmp_dir}/curl-importing-plugin.${plugin_suffix}" || \
		fail "plugin did not resolve curl from the force-loaded executable archive"
	"${checker}" "${tmp_dir}/curl-owning-executable" \
		"${tmp_dir}/curl-importing-plugin.${plugin_suffix}" >/dev/null || \
		fail "linkage checker rejected executable-owned curl fixture"
fi

cat > "${tmp_dir}/openssl-contract.mk" <<EOF
PROXYSQL_PATH := ${script_dir}/../../..
DEPS_PATH := \$(PROXYSQL_PATH)/deps
include \$(PROXYSQL_PATH)/common_mk/openssl_flags.mk
.PHONY: print-link-flags
print-link-flags:
	@echo "EXECUTABLE_EXPORT_FLAGS=\$(EXECUTABLE_EXPORT_FLAGS)"
	@echo "OPENSSL_FORCE_LOAD_LIBS=\$(OPENSSL_FORCE_LOAD_LIBS)"
EOF

linux_link_flags=$(make -s -f "${tmp_dir}/openssl-contract.mk" \
	UNAME_S=Linux print-link-flags)
[[ "${linux_link_flags}" == *'EXECUTABLE_EXPORT_FLAGS=-Wl,--export-dynamic'* ]] || \
	fail "Linux executable export flags are incorrect: ${linux_link_flags}"
[[ "${linux_link_flags}" == *"OPENSSL_FORCE_LOAD_LIBS=-Wl,--whole-archive ${script_dir}/../../../deps/libssl/openssl/libssl.a ${script_dir}/../../../deps/libssl/openssl/libcrypto.a -Wl,--no-whole-archive"* ]] || \
	fail "Linux OpenSSL force-load flags are incorrect: ${linux_link_flags}"

freebsd_link_flags=$(make -s -f "${tmp_dir}/openssl-contract.mk" \
	UNAME_S=FreeBSD print-link-flags)
[[ "${freebsd_link_flags}" == *'EXECUTABLE_EXPORT_FLAGS=-Wl,--export-dynamic'* ]] || \
	fail "FreeBSD executable export flags are incorrect: ${freebsd_link_flags}"
[[ "${freebsd_link_flags}" == *"OPENSSL_FORCE_LOAD_LIBS=-Wl,--whole-archive ${script_dir}/../../../deps/libssl/openssl/libssl.a ${script_dir}/../../../deps/libssl/openssl/libcrypto.a -Wl,--no-whole-archive"* ]] || \
	fail "FreeBSD OpenSSL force-load flags are incorrect: ${freebsd_link_flags}"

darwin_link_flags=$(make -s -f "${tmp_dir}/openssl-contract.mk" \
	UNAME_S=Darwin print-link-flags)
[[ "${darwin_link_flags}" == *'EXECUTABLE_EXPORT_FLAGS=-Wl,-export_dynamic'* ]] || \
	fail "macOS executable export flags are incorrect: ${darwin_link_flags}"
[[ "${darwin_link_flags}" == *"OPENSSL_FORCE_LOAD_LIBS=-Wl,-force_load,${script_dir}/../../../deps/libssl/openssl/libssl.a -Wl,-force_load,${script_dir}/../../../deps/libssl/openssl/libcrypto.a"* ]] || \
	fail "macOS OpenSSL force-load flags are incorrect: ${darwin_link_flags}"

cat > "${tmp_dir}/src-contract.mk" <<'EOF'
.PHONY: print-executable-link-contract
print-executable-link-contract:
	@echo "EXECUTABLE_EXPORT_FLAGS=$(EXECUTABLE_EXPORT_FLAGS)"
	@echo "CURL_FORCE_LOAD_LIBS=$(CURL_FORCE_LOAD_LIBS)"
	@echo "STATICMYLIBS=$(STATICMYLIBS)"
	@echo "LIBPROXYSQLAR=$(LIBPROXYSQLAR)"
	@echo "MYLIBS=$(MYLIBS)"
EOF

linux_executable_contract=$(make -s -C "${repo_root}/src" \
	-f Makefile -f "${tmp_dir}/src-contract.mk" UNAME_S=Linux \
	print-executable-link-contract)
linux_static_libs=$(printf '%s\n' "${linux_executable_contract}" | \
	awk -F= '$1 == "STATICMYLIBS" { sub(/^[^=]*=/, ""); print }')
[[ "${linux_executable_contract}" == *"CURL_FORCE_LOAD_LIBS=-Wl,--whole-archive ${repo_root}/deps/curl/curl/lib/.libs/libcurl.a -Wl,--no-whole-archive"* ]] || \
	fail "Linux executable does not force-load vendored curl: ${linux_executable_contract}"
[[ "${linux_static_libs}" != *'-lcurl'* ]] || \
	fail "Linux executable still links curl outside its ownership flags: ${linux_executable_contract}"
[[ "${linux_executable_contract}" == *'MYLIBS=-Wl,--export-dynamic '* ]] || \
	fail "Linux executable does not export its force-loaded symbols: ${linux_executable_contract}"

darwin_executable_contract=$(make -s -C "${repo_root}/src" \
	-f Makefile -f "${tmp_dir}/src-contract.mk" UNAME_S=Darwin \
	print-executable-link-contract)
darwin_archives=$(printf '%s\n' "${darwin_executable_contract}" | \
	awk -F= '$1 == "LIBPROXYSQLAR" { sub(/^[^=]*=/, ""); print }')
[[ "${darwin_executable_contract}" == *"CURL_FORCE_LOAD_LIBS=-Wl,-force_load,${repo_root}/deps/curl/curl/lib/.libs/libcurl.a"* ]] || \
	fail "macOS executable does not force-load vendored curl: ${darwin_executable_contract}"
[[ "${darwin_archives}" != *"${repo_root}/deps/curl/curl/lib/.libs/libcurl.a"* ]] || \
	fail "macOS executable still links curl outside its ownership flags: ${darwin_executable_contract}"
[[ "${darwin_executable_contract}" == *'MYLIBS=-Wl,-export_dynamic '* ]] || \
	fail "macOS executable does not export its force-loaded symbols: ${darwin_executable_contract}"

genai_link=$(make -Bn -C "${repo_root}/plugins/genai" \
	UNAME_S=Linux "${repo_root}/plugins/genai/ProxySQL_GenAI_Plugin.so" | \
	awk '/ -shared -o .*ProxySQL_GenAI_Plugin\.so / { print }')
[[ -n "${genai_link}" ]] || fail "unable to inspect the GenAI plugin link command"
[[ "${genai_link}" != *"${repo_root}/deps/curl/curl/lib/.libs/libcurl.a"* ]] || \
	fail "GenAI plugin must import curl instead of embedding its archive: ${genai_link}"

linux_mcp_link=$(make -Bn -C "${repo_root}/test/tap/tests/unit" \
	UNAME_S=Linux mcp_client_unit-t | tr '\n' ' ')
[[ "${linux_mcp_link}" == *"${repo_root}/deps/curl/curl/lib/.libs/libcurl.a -Wl,--whole-archive ${repo_root}/deps/libssl/openssl/libssl.a ${repo_root}/deps/libssl/openssl/libcrypto.a -Wl,--no-whole-archive -lz -lpthread -ldl -o mcp_client_unit-t"* ]] || \
	fail "Linux MCP unit link command must use vendored static curl/OpenSSL then zlib, pthread, and libdl: ${linux_mcp_link}"

darwin_mcp_link=$(make -Bn -C "${repo_root}/test/tap/tests/unit" \
	UNAME_S=Darwin mcp_client_unit-t | tr '\n' ' ')
[[ "${darwin_mcp_link}" == *"${repo_root}/deps/curl/curl/lib/.libs/libcurl.a -Wl,-force_load,${repo_root}/deps/libssl/openssl/libssl.a -Wl,-force_load,${repo_root}/deps/libssl/openssl/libcrypto.a -lz -lpthread -o mcp_client_unit-t"* ]] || \
	fail "macOS MCP unit link command must use vendored static curl/OpenSSL: ${darwin_mcp_link}"
[[ "${darwin_mcp_link}" != *"-ldl"* ]] || \
	fail "macOS MCP unit link command must not include Linux-only -ldl: ${darwin_mcp_link}"

echo "OpenSSL linkage checker tests passed"
