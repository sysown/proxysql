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
    local platform=$1 count=$2 expected=$3 loader=${4:-} state=${5:-}
    local result=0 required=20 expected_error
    [[ "$platform" == Darwin ]] && required=19
    rm -rf "$fixture/build"
    rm -f "$fixture/plugin.so"
    mkdir -p "$fixture/build/release/src" "$fixture/build/release/third_party"
    printf '!<arch>\n' > "$fixture/build/release/src/libduckdb_static.a"
    printf '  IMPORTED_LOCATION_RELEASE "%s/build/release/src/libduckdb_static.a"\n' "$fixture" \
        > "$fixture/build/release/DuckDBExports.cmake"
    mkdir -p "$fixture/extension/loader"
    printf '// static loader fixture\n' > "$fixture/build/release/src/duckdb_static_extension_loader.c"
    printf '// static loader fixture\n' > "$fixture/extension/loader/static_extension_autoregister.cpp"
    # Make the loader fixtures newer than their archive prerequisite, as in an
    # already built dependency tree. Validation must also catch empty files.
    touch -t 202001010000 "$fixture/build/release/src/libduckdb_static.a"
    if [[ -n "$loader" ]]; then
        if [[ "$state" == missing ]]; then
            rm "$fixture/$loader"
        else
            : > "$fixture/$loader"
        fi
    fi
    for ((i=1; i<required; i++)); do
        printf '  IMPORTED_LOCATION_RELEASE "%s/build/release/third_party/library%s.a"\n' "$fixture" "$i" \
            >> "$fixture/build/release/DuckDBExports.cmake"
    done
    for ((i=1; i<count; i++)); do
        printf '!<arch>\n' > "$fixture/build/release/third_party/library${i}.a"
    done
    # Invalid loaders must fail even when the plugin needs no relink.
    [[ "$expected" != loader ]] || touch "$fixture/plugin.so"
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
            echo "$platform with $count archives ($loader $state) should fail before linking" >&2
            exit 1
        fi
        expected_error='ERROR: missing or empty DuckDB static archive'
        [[ "$expected" == loader ]] && expected_error='ERROR: missing DuckDB static extension loader'
        if ! grep -q "$expected_error" "$fixture/output"; then
            cat "$fixture/output" >&2
            echo "$platform with $count archives failed for an unexpected reason" >&2
            exit 1
        fi
    fi
}
check_archives Darwin 19 pass
check_archives Darwin 18 fail
check_archives Linux 20 pass
check_archives Linux 19 fail
for platform in Darwin Linux; do
    count=20
    [[ "$platform" == Darwin ]] && count=19
    for loader in build/release/src/duckdb_static_extension_loader.c extension/loader/static_extension_autoregister.cpp; do
        for state in missing empty; do
            check_archives "$platform" "$count" loader "$loader" "$state"
        done
    done
done
echo 'DuckDB platform archive and static loader checks passed'
