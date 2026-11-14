#!/usr/bin/env bash
set -euo pipefail
dependency=${1:?dependency}
tree=$(CDPATH='' cd -- "${2:?restored tree}" && pwd)
repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
read -r -a compiler <<< "${CXX:-g++}"
system_libraries=(-lm -lpthread)
[[ $(uname -s) == Darwin ]] || system_libraries+=(-ldl)
case "$dependency" in
    duckdb)
        cat > "$temporary/probe.cpp" <<'CPP'
#include "duckdb.h"
int main() {
    duckdb_database db = nullptr;
    duckdb_connection connection = nullptr;
    duckdb_result result {};
    if (duckdb_open(nullptr, &db) != DuckDBSuccess) return 1;
    if (duckdb_connect(db, &connection) != DuckDBSuccess) return 2;
    if (duckdb_query(connection, "SELECT 42", &result) != DuckDBSuccess) return 3;
    const bool correct = duckdb_value_int64(&result, 0, 0) == 42;
    duckdb_destroy_result(&result);
    duckdb_disconnect(&connection);
    duckdb_close(&db);
    return correct ? 0 : 4;
}
CPP
        archives=()
        while IFS= read -r archive; do archives+=("$archive"); done < <(
            sh "$repo_root/deps/duckdb/list-static-archives.sh" "$tree/build/release")
        [[ ${#archives[@]} -gt 0 ]] || exit 1
        if [[ $(uname -s) == Darwin ]]; then
            "${compiler[@]}" -std=c++11 -I"$tree/src/include" "$temporary/probe.cpp" \
                "${archives[@]}" "${system_libraries[@]}" -o "$temporary/probe"
        else
            "${compiler[@]}" -std=c++11 -I"$tree/src/include" "$temporary/probe.cpp" \
                -Wl,--start-group "${archives[@]}" -Wl,--end-group "${system_libraries[@]}" -o "$temporary/probe"
        fi
        ;;
    openssl)
        cat > "$temporary/probe.cpp" <<'CPP'
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
int main() {
    if (OpenSSL_version_num() != OPENSSL_VERSION_NUMBER) return 1;
    SSL_CTX *context = SSL_CTX_new(TLS_method());
    if (!context) return 2;
    SSL_CTX_free(context);
    return 0;
}
CPP
        "${compiler[@]}" -I"$tree/include" "$temporary/probe.cpp" "$tree/libssl.a" "$tree/libcrypto.a" \
            "${system_libraries[@]}" -o "$temporary/probe"
        ;;
    *) echo 'Unknown smoke dependency' >&2; exit 1;;
esac
"$temporary/probe"
echo "$dependency relocated compile/link/runtime smoke passed"
