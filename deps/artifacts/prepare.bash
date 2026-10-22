#!/usr/bin/env bash
# Python is optional for source-only OpenSSL (which already requires Perl).
set -euo pipefail
dependency=${1:?dependency required}
repo_root=${2:?repository root required}
mode=${3:-auto}
case "$mode" in auto|source|prebuilt) ;; *) echo 'ERROR: DEPS_MODE must be auto, source, or prebuilt' >&2; exit 1;; esac
make_flags=${MAKEFLAGS:-}
make_short_flags=${make_flags%% *}
if [[ "$make_short_flags" != --* && "$make_short_flags" == *n* ]]; then
    echo "[deps/$dependency] dry run: prepare mode=$mode" >&2
    exit 0
fi
if [[ "${4:-}" != --locked ]] && command -v python3 >/dev/null 2>&1; then
    status=0
    python3 "$repo_root/deps/artifacts/manage.py" prepare --dependency "$dependency" --root "$repo_root" --mode "$mode" || status=$?
    if [[ "$status" != 75 ]]; then exit "$status"; fi
fi
if [[ "$mode" == prebuilt ]]; then
    echo 'ERROR: DEPS_MODE=prebuilt requires Python 3' >&2
    exit 1
fi
cache="$repo_root/.cache/dependency-artifacts"
mkdir -p "$cache"
if [[ "${4:-}" != --locked ]]; then
    # Flock is the same POSIX lock used by the Python path. Perl is already an
    # OpenSSL build prerequisite, including on macOS where flock(1) is absent.
    exec perl -MFcntl=:flock -e '$^F = 1024; open(my $lock, ">>", shift @ARGV) or die $!; flock($lock, LOCK_EX) or die $!; exec @ARGV or die $!;' \
        "$cache/$dependency.lock" bash "$0" "$dependency" "$repo_root" "$mode" --locked
fi
case "$dependency" in
    openssl)
        version=$(sed -n 's/^OPENSSL_VERSION *:= *//p' "$repo_root/common_mk/openssl_flags.mk")
        directory=libssl
        tree="$repo_root/deps/libssl/openssl-$version"
        ;;
    duckdb)
        version=$(sed -n 's/^DUCKDB_VERSION *:= *//p' "$repo_root/deps/duckdb/build.mk")
        directory=duckdb
        tree="$repo_root/deps/duckdb/duckdb"
        ;;
    *) echo 'ERROR: unknown dependency' >&2; exit 1;;
esac
archive="$repo_root/deps/$directory/$dependency-$version.tar.gz"
# Source integrity remains mandatory even when a completed tree is reusable.
bash "$repo_root/deps/$directory/verify-source.bash" "$archive"
signature=$({
    printf '%s\n' "${CC:-cc}" "${CXX:-g++}" "${CFLAGS:-}" "${CPPFLAGS:-}" "${CXXFLAGS:-}" "${LDFLAGS:-}" \
        "${OPENSSL_CONFIGURE_FLAGS:-}" "${DUCKDB_CMAKE_FLAGS:-}" "${SDKROOT:-}" "${MACOSX_DEPLOYMENT_TARGET:-}"
    cat "$repo_root/deps/artifacts/prepare.bash" "$repo_root/deps/$directory/build.mk" \
        "$repo_root/deps/$directory/verify-source.bash" "$archive.sha256"
    read -r -a compiler_command <<< "${CC:-cc}"
    "${compiler_command[@]}" --version || printf 'C compiler identity unavailable\n'
    read -r -a compiler_command <<< "${CXX:-g++}"
    "${compiler_command[@]}" --version || printf 'C++ compiler identity unavailable\n'
    cksum < "$archive"
} | cksum)
# Keep a complete inventory of public outputs even when Python is unavailable.
# Paths are relative to the tree so source reuse also survives checkout moves.
source_outputs() (
    cd "$tree"
    if [[ "$dependency" == openssl ]]; then
        printf '%s\n' libssl.a libcrypto.a apps/openssl.cnf
        find include/openssl -type f -print
        find providers -type f \( -name '*.so' -o -name '*.dylib' \) -print
    else
        printf '%s\n' build/release/DuckDBExports.cmake
        find src/include -type f -print
        sh "$repo_root/deps/duckdb/list-static-archives.sh" build/release
        for directory in third_party extension; do
            if [[ -d "$directory" ]]; then
                find "$directory" -type f \( -iname 'LICENSE*' -o -iname 'NOTICE*' -o -iname 'COPYING*' \) -print
            fi
        done
    fi
    for name in *; do
        case "$name" in
            [Ll][Ii][Cc][Ee][Nn][Ss][Ee]*|[Nn][Oo][Tt][Ii][Cc][Ee]*|[Cc][Oo][Pp][Yy][Ii][Nn][Gg]*)
                if [[ -f "$name" ]]; then printf '%s\n' "$name"; fi;;
        esac
    done
)
outputs_present() {
    [[ -s "$tree/.proxysql-source-outputs" ]] || return 1
    local name
    while IFS= read -r name; do
        [[ -n "$name" && "$name" != /* && "/$name/" != */../* &&
           -f "$tree/$name" && ! -L "$tree/$name" ]] || return 1
    done < "$tree/.proxysql-source-outputs"
}
valid=0
if [[ -f "$tree/.proxysql-source-signature" && -f "$tree/.proxysql-origin" &&
      "$(cat "$tree/.proxysql-origin")" == source &&
      "$(cat "$tree/.proxysql-source-signature")" == "$signature" ]] && outputs_present; then
    if [[ "$dependency" == openssl ]]; then
        if [[ -s "$tree/libssl.a" && -s "$tree/libcrypto.a" && -s "$tree/include/openssl/configuration.h" &&
              -s "$tree/include/openssl/ssl.h" && -s "$tree/include/openssl/opensslv.h" &&
              -f "$tree/.proxysql-build-complete" ]]; then valid=1; fi
    elif [[ -s "$tree/src/include/duckdb.h" ]] &&
        sh "$repo_root/deps/duckdb/list-static-archives.sh" "$tree/build/release" >/dev/null; then valid=1; fi
fi
if [[ "$valid" == 0 ]]; then
    rm -rf "$tree"
    "${MAKE:-make}" --no-print-directory -C "$repo_root/deps" "dependency-source-$dependency"
    source_outputs > "$tree/.proxysql-source-outputs"
    outputs_present || { echo 'ERROR: incomplete dependency source outputs' >&2; exit 1; }
    printf '%s\n' "$signature" > "$tree/.proxysql-source-signature"
    printf 'source\n' > "$tree/.proxysql-origin"
fi
echo "[deps/$dependency] $mode: source ready (Python artifact tooling unavailable)" >&2
