#!/usr/bin/env bash

set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
platform=$(uname -s)
default_ssl_archive="${repo_root}/deps/libssl/openssl/libssl.a"
default_crypto_archive="${repo_root}/deps/libssl/openssl/libcrypto.a"
case $# in
	0|1|3|5)
		;;
	*)
		printf 'Usage: %s [CURL_ARCHIVE [CURL_LA CURL_PC [LIBSSL_ARCHIVE LIBCRYPTO_ARCHIVE]]]\n' \
			"$0" >&2
		exit 2
		;;
esac
if (( $# == 0 )); then
	curl_archive="${repo_root}/deps/curl/curl/lib/.libs/libcurl.a"
	curl_la="${repo_root}/deps/curl/curl/lib/libcurl.la"
	curl_pc="${repo_root}/deps/curl/curl/libcurl.pc"
	ssl_archive=${default_ssl_archive}
	crypto_archive=${default_crypto_archive}
else
	curl_archive=$1
	curl_la=${2:-}
	curl_pc=${3:-}
	ssl_archive=${4:-${default_ssl_archive}}
	crypto_archive=${5:-${default_crypto_archive}}
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

for openssl_archive in "${ssl_archive}" "${crypto_archive}"; do
	if [[ ! -f "${openssl_archive}" ]]; then
		printf 'ERROR: required vendored OpenSSL deny archive is missing: %s\n' \
			"${openssl_archive}" >&2
		exit 1
	fi
done

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
	openssl_elf_symbols=$(
		readelf -Ws "${ssl_archive}" "${crypto_archive}" 2>/dev/null
	)
	defined_openssl_symbols=$(awk '
		NF >= 8 && $7 != "UND" && $4 != "FILE" && $4 != "SECTION" &&
			($5 == "GLOBAL" || $5 == "WEAK" || $5 == "UNIQUE") {
			name = $8
			sub(/@.*/, "", name)
			print name
		}
	' <<<"${openssl_elf_symbols}" | sort -u)
	defined_all_symbols=$(awk '
		NF >= 8 && $7 != "UND" && $4 != "FILE" && $4 != "SECTION" {
			name = $8
			sub(/@.*/, "", name)
			print name
		}
	' <<<"${elf_symbols}" | sort -u)
	defined_public_symbols=$(awk '
		NF >= 8 && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" {
			name = $8
			sub(/@.*/, "", name)
			print name
		}
	' <<<"${elf_symbols}" | sort -u)
	;;
	Darwin)
	defined_openssl_symbols=$(
		nm -gU "${ssl_archive}" "${crypto_archive}" 2>/dev/null | awk '
		NF >= 2 && $(NF - 1) ~ /^[A-Za-z]$/ {
			name = $NF
			sub(/^_/, "", name)
			print name
		}
	' | sort -u
	)
	defined_all_symbols=$(nm -U "${curl_archive}" 2>/dev/null | awk '
		NF >= 2 && $(NF - 1) ~ /^[A-Za-z]$/ {
			name = $NF
			sub(/^_/, "", name)
			print name
		}
	' | sort -u)
	defined_public_symbols=$(nm -gU "${curl_archive}" 2>/dev/null | awk '
		NF >= 2 && $(NF - 1) ~ /^[A-Za-z]$/ {
			name = $NF
			sub(/^_/, "", name)
			print name
		}
	' | sort -u)
	;;
esac

for symbol in "${required_curl_apis[@]}"; do
	if ! grep -Fxq "${symbol}" <<<"${defined_public_symbols}"; then
		printf 'ERROR: vendored curl is %s: %s\n' \
			"${missing_api_diagnostic}" "${symbol}" >&2
		exit 1
	fi
done

embedded_openssl=$(awk '
	NR == FNR {
		if ($0 != "") {
			denied[$0] = 1
		}
		next
	}
	$0 in denied { print }
' <(printf '%s\n' "${defined_openssl_symbols}") \
	<(printf '%s\n' "${defined_all_symbols}") | sort -u)
if [[ -n "${embedded_openssl}" ]]; then
	printf 'ERROR: vendored curl contains embedded OpenSSL definition(s) from exact vendored archives:\n%s\n' \
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
