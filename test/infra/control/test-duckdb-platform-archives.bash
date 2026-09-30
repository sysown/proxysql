#!/usr/bin/env bash
set -euo pipefail
script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

# Exercise the real plugin link recipe without compiling DuckDB or the plugin.
cat > "$fixture/linker" <<'LINKER'
#!/usr/bin/env bash
printf 'plugin linker reached\n'
LINKER
chmod +x "$fixture/linker"

check_archives() {
    local platform=$1 count=$2 expected=$3 result=0
    rm -rf "$fixture/build"
    mkdir -p "$fixture/build/release/src"
    touch "$fixture/build/release/src/libduckdb_static.a"
    for ((i=1; i<count; i++)); do
        touch "$fixture/build/release/library${i}.a"
    done
    make --no-print-directory -s -C "$repo_root/plugins/duckdb" \
        UNAME_S="$platform" PROXYSQL_PATH="$repo_root" \
        DUCKDB_PATH="$fixture" DUCKDB_LDIR="$fixture/build/release/src" \
        PLUGIN_SO="$fixture/plugin.so" OBJS= CXX="$fixture/linker" \
        > "$fixture/output" 2>&1 || result=$?
    if [[ "$expected" == pass ]]; then
        if [[ "$result" != 0 ]] || ! grep -q 'plugin linker reached' "$fixture/output"; then
            cat "$fixture/output" >&2
            echo "$platform with $count archives should reach the linker" >&2
            exit 1
        fi
    else
        if [[ "$result" == 0 ]] || grep -q 'plugin linker reached' "$fixture/output"; then
            cat "$fixture/output" >&2
            echo "$platform with $count archives should fail before linking" >&2
            exit 1
        fi
        if ! grep -q 'ERROR: expected at least' "$fixture/output"; then
            cat "$fixture/output" >&2
            echo "$platform with $count archives failed for an unexpected reason" >&2
            exit 1
        fi
    fi
}
check_archives Darwin 15 pass
check_archives Darwin 14 fail
check_archives Linux 16 pass
check_archives Linux 15 fail
echo 'DuckDB platform archive checks passed'
