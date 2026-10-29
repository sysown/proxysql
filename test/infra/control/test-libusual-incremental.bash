#!/usr/bin/env bash
set -euo pipefail
script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
# Evaluate the real dependency recipe against an up-to-date fixture archive.
# Never touch the developer's extracted dependencies.
target=libusual/libusual/.libs/libusual.a
mkdir -p "$temporary/libusual/libusual/.libs"
mkdir -p "$temporary/src"
touch "$temporary/src/proxysql_global.cpp"
touch -t 200001010000 "$temporary/libusual/tls_free_namespace.patch"
touch -t 200001020000 "$temporary/$target"
baseline=$(make -C "$temporary" -f "$repo_root/deps/Makefile" \
    PROXYSQL_PATH="$repo_root" --no-print-directory -n "$target" \
    MAKE=true -o libssl/openssl/.proxysql-build-complete)
changed=$(make -C "$temporary" -f "$repo_root/deps/Makefile" \
    PROXYSQL_PATH="$repo_root" --no-print-directory -n "$target" \
    MAKE=true -o libssl/openssl/.proxysql-build-complete \
    -W libusual/tls_free_namespace.patch)
[[ "$baseline" != *'./autogen.sh'* ]] || { echo 'Unexpected baseline rebuild' >&2; exit 1; }
[[ "$changed" == *'patch -p1 < ../tls_free_namespace.patch'* ]] || {
    echo 'Changed libusual namespace patch does not invalidate the archive' >&2; exit 1;
}
echo 'libusual incremental patch rebuild passed'

target=mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a
mkdir -p "$temporary/mariadb-client-library/mariadb_client/libmariadb"
touch -t 200001010000 "$temporary/mariadb-client-library/x509cache.patch"
touch -t 200001020000 "$temporary/$target"
changed=$(make -C "$temporary" -f "$repo_root/deps/Makefile" \
    PROXYSQL_PATH="$repo_root" --no-print-directory -n "$target" \
    MAKE=true -o libssl/openssl/.proxysql-build-complete \
    -W mariadb-client-library/x509cache.patch)
[[ "$changed" == *'x509cache.patch'* ]] || {
    echo 'Changed CA cache patch does not invalidate the connector archive' >&2; exit 1;
}
echo 'MariaDB incremental CA cache patch rebuild passed'
