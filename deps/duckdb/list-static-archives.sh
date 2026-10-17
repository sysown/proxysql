#!/bin/sh
# Enumerate exactly the static libraries exported by this DuckDB configuration.
# Use build-relative paths so a relocated dependency cache remains usable.
set -eu
build_dir=${1:?Usage: list-static-archives.sh DUCKDB_BUILD_DIRECTORY}
manifest=$build_dir/DuckDBExports.cmake
if [ ! -r "$manifest" ]; then
    echo "ERROR: missing DuckDB build manifest: $manifest; configure and rebuild deps/duckdb" >&2
    exit 1
fi
archives=$(awk -F '"' '
    /^[[:space:]]*IMPORTED_LOCATION_[A-Z0-9_]+[[:space:]]+".*[.]a"/ {
        path = $2
        sub(/^.*\/build\/release\//, "", path)
        print path
    }
' "$manifest" | LC_ALL=C sort -u)
if ! printf '%s\n' "$archives" | grep -qx 'src/libduckdb_static.a'; then
    echo "ERROR: invalid DuckDB static archive manifest: $manifest (no libduckdb_static.a)" >&2
    exit 1
fi
for archive in $archives; do
    case "$archive" in
        src/*.a|third_party/*.a|extension/*.a) ;;
        *) echo "ERROR: unexpected DuckDB archive path: $archive" >&2; exit 1 ;;
    esac
    case "/$archive/" in
        */../*) echo "ERROR: invalid DuckDB archive path: $archive" >&2; exit 1 ;;
    esac
    if [ ! -s "$build_dir/$archive" ]; then
        echo "ERROR: missing or empty DuckDB static archive: $build_dir/$archive; rebuild deps/duckdb" >&2
        exit 1
    fi
done
for archive in $archives; do
    printf '%s/%s\n' "$build_dir" "$archive"
done
