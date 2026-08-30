#!/usr/bin/env bash

set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
curl_archive=${1:-"${repo_root}/deps/curl/curl/lib/.libs/libcurl.a"}

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

if ! readelf -Ws "${curl_archive}" 2>/dev/null | awk '
	$5 == "GLOBAL" && $6 == "DEFAULT" && $8 == "curl_easy_cleanup" {
		found = 1
	}
	END { exit found ? 0 : 1 }
'; then
	printf 'ERROR: vendored curl public API symbols are not externally visible\n' >&2
	exit 1
fi

printf 'Vendored curl archive contract passed\n'
