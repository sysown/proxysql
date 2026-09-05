#!/usr/bin/env bash
set -euo pipefail
script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
usual="${repo_root}/deps/libusual/libusual"
openssl="${repo_root}/deps/libssl/openssl"
temporary=$(mktemp -d)
trap 'rm -rf "${temporary}"' EXIT
# Both APIs must link together without duplicate or interposed tls_free symbols.
${CC:-cc} -I"${usual}" -I"${openssl}/include" \
    "${script_dir}/fixtures/libusual-static-openssl.c" \
    "${usual}/.libs/libusual.a" "${openssl}/libssl.a" "${openssl}/libcrypto.a" \
    -lpthread -lm -o "${temporary}/libusual-static-openssl"
"${temporary}/libusual-static-openssl"
echo 'libusual and vendored OpenSSL coexistence test passed'
