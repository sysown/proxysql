#!/usr/bin/env bash

set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
platform=$(uname -s)
if (( $# == 0 )); then
	curl_archive="${repo_root}/deps/curl/curl/lib/.libs/libcurl.a"
	curl_la="${repo_root}/deps/curl/curl/lib/libcurl.la"
	curl_pc="${repo_root}/deps/curl/curl/libcurl.pc"
else
	curl_archive=$1
	curl_la=${2:-}
	curl_pc=${3:-}
fi
required_curl_apis=(
	curl_easy_cleanup
	curl_easy_getinfo
	curl_easy_init
	curl_easy_perform
	curl_easy_setopt
	curl_easy_strerror
	curl_global_init
	curl_slist_append
	curl_slist_free_all
)

case ${platform} in
	Linux|FreeBSD)
	required_tools=(ar nm readelf)
	missing_api_diagnostic='missing required GLOBAL DEFAULT curl definition'
	;;
	Darwin)
	required_tools=(ar nm)
	missing_api_diagnostic='missing required external curl definition'
	;;
	*)
	printf 'ERROR: unsupported archive inspection platform: %s\n' \
		"${platform}" >&2
	exit 1
	;;
esac

for tool in "${required_tools[@]}"; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		printf 'ERROR: required archive inspection tool is unavailable on %s: %s\n' \
			"${platform}" "${tool}" >&2
		exit 1
	fi
done

if [[ ! -f "${curl_archive}" ]]; then
	printf 'ERROR: vendored curl archive is missing: %s\n' "${curl_archive}" >&2
	exit 1
fi

nested_archives=$(ar t "${curl_archive}" | awk '/\.a$/ { print }')
if [[ -n "${nested_archives}" ]]; then
	printf 'ERROR: vendored curl contains nested archive member(s):\n%s\n' \
		"${nested_archives}" >&2
	exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT
member_index=0
while IFS= read -r member; do
	member_index=$((member_index + 1))
	member_file="${tmp_dir}/member-${member_index}.o"
	if ! ar p "${curl_archive}" "${member}" > "${member_file}" || \
		ar t "${member_file}" >/dev/null 2>&1 || \
		! nm -g "${member_file}" >/dev/null 2>&1; then
		printf 'ERROR: vendored curl member is not a recognized object file: %s\n' \
			"${member}" >&2
		exit 1
	fi
done < <(ar t "${curl_archive}")

case ${platform} in
	Linux|FreeBSD)
	elf_symbols=$(readelf -Ws "${curl_archive}" 2>/dev/null)
	defined_global_symbols=$(awk '
		$5 == "GLOBAL" && $7 != "UND" {
			name = $8
			sub(/@.*/, "", name)
			print name
		}
	' <<<"${elf_symbols}" | sort -u)
	defined_public_symbols=$(awk '
		$5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" {
			name = $8
			sub(/@.*/, "", name)
			print name
		}
	' <<<"${elf_symbols}" | sort -u)
	;;
	Darwin)
	defined_global_symbols=$(nm -gU "${curl_archive}" 2>/dev/null | awk '
		NF >= 1 {
			name = $NF
			sub(/^_/, "", name)
			print name
		}
	' | sort -u)
	defined_public_symbols=${defined_global_symbols}
	;;
esac

for symbol in "${required_curl_apis[@]}"; do
	if ! grep -Fxq "${symbol}" <<<"${defined_public_symbols}"; then
		printf 'ERROR: vendored curl is %s: %s\n' \
			"${missing_api_diagnostic}" "${symbol}" >&2
		exit 1
	fi
done

embedded_openssl=$(grep -E \
	'^(ASN1|BIO|BN|CMS|COMP|CONF|CRYPTO|DH|DSA|DTLS|EC|ENGINE|ERR|EVP|HMAC|KDF|MD5|NCONF|OBJ|OCSP|OPENSSL|OpenSSL|OSSL|PEM|PKCS|RAND|RSA|SHA|SRP|SSL|TS|UI|X509)_[A-Za-z0-9_]+$|^(d2i|i2d)_[A-Za-z0-9_]+$|^ossl_[A-Za-z0-9_]+$|^TLS_(client_|server_)?method$|^TLSv1(_[0-9]+)?_(client_|server_)?method$' \
	<<<"${defined_global_symbols}" | sort -u || true)
if [[ -n "${embedded_openssl}" ]]; then
	printf 'ERROR: vendored curl contains embedded OpenSSL definition(s):\n%s\n' \
		"${embedded_openssl}" >&2
	exit 1
fi

if [[ -n "${curl_la}" || -n "${curl_pc}" ]]; then
	for metadata_file in "${curl_la}" "${curl_pc}"; do
		if [[ ! -f "${metadata_file}" ]]; then
			printf 'ERROR: vendored curl dependency metadata is missing: %s\n' \
				"${metadata_file}" >&2
			exit 1
		fi
	done

	for dependency in -lssl -lcrypto -lz; do
		if ! grep -Eq -- "(^|[[:space:]])${dependency}([[:space:]]|$)" \
			"${curl_la}"; then
			printf 'ERROR: libcurl.la is missing required dependency: %s\n' \
				"${dependency}" >&2
			exit 1
		fi
		if ! grep -Eq -- "(^|[[:space:]])${dependency}([[:space:]]|$)" \
			"${curl_pc}"; then
			printf 'ERROR: libcurl.pc is missing required dependency: %s\n' \
				"${dependency}" >&2
			exit 1
		fi
	done

	for metadata_path in \
		"-L${repo_root}/deps/libssl/openssl" \
		"${repo_root}/deps/libssl/openssl/libssl.a" \
		"${repo_root}/deps/libssl/openssl/libcrypto.a"
	do
		if ! grep -Fq -- "${metadata_path}" "${curl_pc}"; then
			printf 'ERROR: libcurl.pc is missing vendored dependency path: %s\n' \
				"${metadata_path}" >&2
			exit 1
		fi
	done
	if ! grep -Fq -- "-L${repo_root}/deps/libssl/openssl" "${curl_la}"; then
		printf 'ERROR: libcurl.la is missing vendored OpenSSL search path\n' >&2
		exit 1
	fi
fi

printf 'Vendored curl archive contract passed\n'
