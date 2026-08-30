#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
connector_dir="${repo_root}/deps/mariadb-client-library"
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

tar --no-same-owner -zxf \
	"${connector_dir}/mariadb-connector-c-3.3.8-src.tar.gz" \
	-C "${tmp_dir}"
source_dir="${tmp_dir}/mariadb-connector-c-3.3.8-src"
patch -s -d "${source_dir}" -p0 < "${connector_dir}/x509cache.patch"

${CC:-cc} -std=c99 -Wall -Wextra -Werror -pedantic \
	-I"${source_dir}/libmariadb/secure" \
	"${script_dir}/fixtures/mariadb-default-trust-store.c" \
	-o "${tmp_dir}/mariadb-default-trust-store"

mkdir "${tmp_dir}/trust-fixtures"
"${tmp_dir}/mariadb-default-trust-store" "${tmp_dir}/trust-fixtures"
