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
    exec perl -MFcntl=:flock -e 'open(my $lock, ">>", shift @ARGV) or die $!; flock($lock, LOCK_EX) or die $!; $^F = 1024; exec @ARGV or die $!;' \
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
signature=$({
    printf '%s\n' "${CC:-cc}" "${CXX:-g++}" "${CFLAGS:-}" "${CPPFLAGS:-}" "${CXXFLAGS:-}" "${LDFLAGS:-}" \
        "${OPENSSL_CONFIGURE_FLAGS:-}" "${DUCKDB_CMAKE_FLAGS:-}" "${SDKROOT:-}" "${MACOSX_DEPLOYMENT_TARGET:-}"
    cat "$repo_root/deps/$directory/build.mk" "$repo_root/deps/$directory/verify-source.bash"
    read -r -a compiler_command <<< "${CC:-cc}"
    "${compiler_command[@]}" --version || printf 'C compiler identity unavailable\n'
    read -r -a compiler_command <<< "${CXX:-g++}"
    "${compiler_command[@]}" --version || printf 'C++ compiler identity unavailable\n'
    cksum "$repo_root/deps/$directory/$dependency-$version.tar.gz"
} | cksum)
valid=0
if [[ -f "$tree/.proxysql-source-signature" && -f "$tree/.proxysql-origin" &&
      "$(cat "$tree/.proxysql-origin")" == source &&
      "$(cat "$tree/.proxysql-source-signature")" == "$signature" ]]; then
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
    printf '%s\n' "$signature" > "$tree/.proxysql-source-signature"
    printf 'source\n' > "$tree/.proxysql-origin"
fi
echo "[deps/$dependency] $mode: source ready (Python artifact tooling unavailable)" >&2
