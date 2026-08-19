#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
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
const char *OpenSSL_version(int type) {
	(void)type;
	return "fixture";
}
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

pass_output=$("${checker}" \
	"${tmp_dir}/exporting-executable" \
	"${tmp_dir}/importing-plugin.${plugin_suffix}") || \
	fail "linkage checker rejected the valid ownership fixture"
[[ "${pass_output}" == *'OpenSSL linkage check passed'* ]] || \
	fail "valid fixture did not report success; got: ${pass_output}"

cat > "${tmp_dir}/openssl-contract.mk" <<EOF
PROXYSQL_PATH := ${script_dir}/../../..
DEPS_PATH := \$(PROXYSQL_PATH)/deps
include \$(PROXYSQL_PATH)/common_mk/openssl_flags.mk
.PHONY: print-openssl-export-libs
print-openssl-export-libs:
	@echo "\$(OPENSSL_EXPORT_LIBS)"
EOF

linux_export_libs=$(make -s -f "${tmp_dir}/openssl-contract.mk" \
	UNAME_S=Linux print-openssl-export-libs)
[[ "${linux_export_libs}" == \
	"-Wl,--whole-archive ${script_dir}/../../../deps/libssl/openssl/libssl.a ${script_dir}/../../../deps/libssl/openssl/libcrypto.a -Wl,--no-whole-archive" ]] || \
	fail "Linux executable ownership flags are incorrect: ${linux_export_libs}"

darwin_export_libs=$(make -s -f "${tmp_dir}/openssl-contract.mk" \
	UNAME_S=Darwin print-openssl-export-libs)
[[ "${darwin_export_libs}" == \
	"-Wl,-force_load,${script_dir}/../../../deps/libssl/openssl/libssl.a -Wl,-force_load,${script_dir}/../../../deps/libssl/openssl/libcrypto.a" ]] || \
	fail "macOS executable ownership flags are incorrect: ${darwin_export_libs}"

echo "OpenSSL linkage checker tests passed"
