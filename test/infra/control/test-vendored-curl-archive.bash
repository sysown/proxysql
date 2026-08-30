#!/usr/bin/env bash

set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
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

defined_external_symbols=$(nm -g "${curl_archive}" 2>/dev/null | awk '
	NF >= 2 {
		type = $(NF - 1)
		name = $NF
		sub(/^_/, "", name)
		if (type ~ /^[A-TV-Z]$/) {
			print name
		}
	}
')

for symbol in "${required_curl_apis[@]}"; do
	if ! grep -Fxq "${symbol}" <<<"${defined_external_symbols}"; then
		printf 'ERROR: vendored curl is missing required external curl definition: %s\n' \
			"${symbol}" >&2
		exit 1
	fi
done

embedded_openssl=$(grep -E \
	'^(OPENSSL_|OpenSSL_|SSL_|TLS_|EVP_|OSSL_|BIO_|X509_|CRYPTO_)' \
	<<<"${defined_external_symbols}" | sort -u || true)
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
