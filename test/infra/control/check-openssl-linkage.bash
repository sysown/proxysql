#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
ssl_archive="${repo_root}/deps/libssl/openssl/libssl.a"
crypto_archive="${repo_root}/deps/libssl/openssl/libcrypto.a"

if (( $# < 1 )); then
	echo "Usage: $0 EXECUTABLE [PLUGIN ...]" >&2
	exit 2
fi

executable=$1
shift
plugins=("$@")
platform=$(uname -s)
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

for binary in "${executable}" "${plugins[@]}"; do
	[[ -f "${binary}" ]] || fail "binary does not exist: ${binary}"
done
for archive in "${ssl_archive}" "${crypto_archive}"; do
	[[ -f "${archive}" ]] || \
		fail "required vendored OpenSSL ownership archive is missing: ${archive}"
done

case ${platform} in
	Linux|FreeBSD)
		for tool in readelf nm; do
			command -v "${tool}" >/dev/null 2>&1 || \
				fail "required inspection tool is unavailable: ${tool}"
		done
		;;
	Darwin)
		for tool in otool nm; do
			command -v "${tool}" >/dev/null 2>&1 || \
				fail "required inspection tool is unavailable: ${tool}"
		done
		;;
	*)
		fail "unsupported platform: ${platform}"
		;;
esac

check_dynamic_dependencies() {
	local binary=$1
	local dependency

	case ${platform} in
		Linux|FreeBSD)
			dependency=$(readelf -d "${binary}" 2>/dev/null | \
				awk '/\(NEEDED\)/ && /lib(ssl|crypto)\.so/ { print; exit }')
			;;
		Darwin)
			dependency=$(otool -L "${binary}" 2>/dev/null | \
				awk '/lib(ssl|crypto)(\.[^[:space:]]*)?\.dylib/ { print; exit }')
			;;
	esac

	[[ -z "${dependency}" ]] || \
		fail "${binary} dynamically depends on forbidden OpenSSL library:${dependency}"
}

defined_symbols() {
	local binary=$1
	case ${platform} in
		Linux|FreeBSD)
			nm -D --defined-only --format=posix "${binary}" 2>/dev/null | \
				awk '{ symbol=$1; sub(/@.*/, "", symbol); print symbol }' | \
				sort -u
			;;
		Darwin)
			nm -gU "${binary}" 2>/dev/null | \
				awk '{ symbol=$NF; sub(/^_/, "", symbol); print symbol }' | \
				sort -u
			;;
	esac
}

all_defined_symbols() {
	local binary=$1
	case ${platform} in
		Linux|FreeBSD)
			nm --defined-only --format=posix "${binary}" 2>/dev/null | \
				awk '{ symbol=$1; sub(/@.*/, "", symbol); print symbol }' | \
				sort -u
			;;
		Darwin)
			nm -U "${binary}" 2>/dev/null | \
				awk '{ symbol=$NF; sub(/^_/, "", symbol); print symbol }' | \
				sort -u
			;;
	esac
}

archive_defined_symbols() {
	case ${platform} in
		Linux|FreeBSD)
			readelf -Ws "$@" 2>/dev/null | awk '
				NF >= 8 && $7 != "UND" && $4 != "FILE" && $4 != "SECTION" &&
					($5 == "GLOBAL" || $5 == "WEAK" || $5 == "UNIQUE") {
					name = $8
					sub(/@.*/, "", name)
					print name
				}
			' | sort -u
			;;
		Darwin)
			nm -gU "$@" 2>/dev/null | awk '
				NF >= 2 && $(NF - 1) ~ /^[A-Za-z]$/ {
					name = $NF
					sub(/^_/, "", name)
					print name
				}
			' | sort -u
			;;
	esac
}

undefined_symbols() {
	local binary=$1
	case ${platform} in
		Linux|FreeBSD)
			nm -D --undefined-only --format=posix "${binary}" 2>/dev/null | \
				awk '{ symbol=$1; sub(/@.*/, "", symbol); print symbol }' | \
				sort -u
			;;
		Darwin)
			nm -gu "${binary}" 2>/dev/null | \
				awk '{ symbol=$NF; sub(/^_/, "", symbol); print symbol }' | \
				sort -u
			;;
	esac
}

openssl_imports() {
	local binary=$1
	undefined_symbols "${binary}" | grep -E \
		'^(ASN1|BIO|BN|CMS|COMP|CONF|CRYPTO|DH|DSA|DTLS|EC|ENGINE|ERR|EVP|HMAC|KDF|MD5|NCONF|OBJ|OCSP|OPENSSL|OSSL|PEM|PKCS|RAND|RSA|SHA|SRP|SSL|TLS|TS|UI|X509)_[A-Za-z0-9_]+$|^(d2i|i2d)_[A-Za-z0-9_]+' || true
}

curl_imports() {
	local binary=$1
	undefined_symbols "${binary}" | grep -E '^curl_[A-Za-z0-9_]+$' || true
}

check_dynamic_dependencies "${executable}"
for plugin in "${plugins[@]}"; do
	check_dynamic_dependencies "${plugin}"
done

executable_exports="${tmp_dir}/executable.exports"
defined_symbols "${executable}" > "${executable_exports}"
openssl_definitions="${tmp_dir}/openssl.definitions"
archive_defined_symbols "${ssl_archive}" "${crypto_archive}" > \
	"${openssl_definitions}"

sentinels=(OpenSSL_version SSL_CTX_new EVP_MD_fetch OSSL_PROVIDER_load)
for plugin in "${plugins[@]}"; do
	plugin_definitions="${tmp_dir}/plugin-definitions"
	all_defined_symbols "${plugin}" > "${plugin_definitions}"

	for sentinel in "${sentinels[@]}"; do
		if grep -Fxq "${sentinel}" "${plugin_definitions}"; then
			fail "plugin ${plugin} defines OpenSSL core sentinel ${sentinel}"
		fi
	done

	embedded_openssl=$(awk '
		NR == FNR {
			if ($0 != "") denied[$0] = 1
			next
		}
		$0 in denied { print; exit }
	' "${openssl_definitions}" "${plugin_definitions}")
	if [[ -n "${embedded_openssl}" ]]; then
		fail "plugin ${plugin} defines vendored OpenSSL symbol ${embedded_openssl}"
	fi

	embedded_curl=$(grep -E '^curl_[A-Za-z0-9_]+$' \
		"${plugin_definitions}" | head -n 1 || true)
	if [[ -n "${embedded_curl}" ]]; then
		fail "plugin ${plugin} defines curl API ${embedded_curl}"
	fi

	while IFS= read -r symbol; do
		[[ -n "${symbol}" ]] || continue
		if ! grep -Fxq "${symbol}" "${executable_exports}"; then
			fail "plugin ${plugin} imports ${symbol} but the executable does not export it"
		fi
	done < <(openssl_imports "${plugin}")

	while IFS= read -r symbol; do
		[[ -n "${symbol}" ]] || continue
		if ! grep -Fxq "${symbol}" "${executable_exports}"; then
			fail "plugin ${plugin} imports ${symbol} but the executable does not export it"
		fi
	done < <(curl_imports "${plugin}")
done

echo "OpenSSL linkage check passed: 1 executable, ${#plugins[@]} plugin(s)"
