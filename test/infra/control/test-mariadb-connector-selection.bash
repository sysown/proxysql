#!/usr/bin/env bash
set -euo pipefail

repo=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
connector="$repo/deps/mariadb-client-library"

probe() {
	local directory=$1 tier40=$2 tier31=$3
	make --no-print-directory -s -C "$repo/$directory" \
		PROXYSQL40="$tier40" PROXYSQL31="$tier31" \
		-f Makefile -f - connector-path <<'MAKEFILE'
.PHONY: connector-path
connector-path:
	@printf '%s\n' '$(MARIADB_PATH)'
MAKEFILE
}

probe_auto() {
	local directory=$1 archive=$2
	env -u PROXYSQL40 make --no-print-directory -s -C "$repo/$directory" \
		PROXYSQL31= LIBPROXYSQLAR="$archive" \
		-f Makefile -f - connector-path <<'MAKEFILE'
.PHONY: connector-path
connector-path:
	@printf '%s\n' '$(MARIADB_PATH)'
MAKEFILE
}

expect_path() {
	local directory=$1 tier40=$2 tier31=$3 expected=$4 actual
	actual=$(probe "$directory" "$tier40" "$tier31")
	if [[ "$actual" != "$connector/$expected" ]]; then
		printf '%s selected %s for PROXYSQL40=%s PROXYSQL31=%s, expected %s\n' \
			"$directory" "$actual" "$tier40" "$tier31" "$connector/$expected" >&2
		return 1
	fi
}

for directory in deps lib src test/tap/tap test/tap/tests test/tap/tests/unit \
	test/tap/tests_with_deps/deprecate_eof_support test/PrepStmt; do
	expect_path "$directory" '' '' mariadb_client
	expect_path "$directory" 0 1 mariadb_client
	expect_path "$directory" 1 1 mariadb-connector-c-3.4.11-src
	# Switching back, including an explicit v3.1 request, selects the old path.
	expect_path "$directory" 0 1 mariadb_client
done

expect_path plugins/duckdb 1 1 mariadb-connector-c-3.4.11-src

# Standalone TAP builds infer the v4.0 tier from an already-built core when
# callers do not provide PROXYSQL40 explicitly. Exercise both sides of that
# branch with tiny representative core objects.
probe_dir=$(mktemp -d)
trap 'rm -rf "$probe_dir"' EXIT
printf '%s\n' 'void legacy_core_symbol(void) {}' | \
	"${CC:-cc}" -x c -c -o "$probe_dir/legacy.o" -
printf '%s\n' 'void invoke_register_schemas_phase(void) {}' | \
	"${CC:-cc}" -x c -c -o "$probe_dir/v40.o" -
for directory in test/tap/tap test/tap/tests test/tap/tests/unit; do
	actual=$(probe_auto "$directory" "$probe_dir/legacy.o")
	[[ "$actual" == "$connector/mariadb_client" ]] || {
		printf '%s auto-selected %s for a legacy core\n' "$directory" "$actual" >&2
		exit 1
	}
	actual=$(probe_auto "$directory" "$probe_dir/v40.o")
	[[ "$actual" == "$connector/mariadb-connector-c-3.4.11-src" ]] || {
		printf '%s auto-selected %s for a v4.0 core\n' "$directory" "$actual" >&2
		exit 1
	}
done

# Every TAP object compiled with MARIADB_IDIR must be invalidated when the
# selected connector changes. Discover header consumers from their recipes so
# a new one cannot silently escape the authoritative invalidation list.
declared_tap_objects=$(make --no-print-directory -s -C "$repo/test/tap/tap" \
	-f Makefile -f - print-mariadb-header-objects <<'MAKEFILE'
.PHONY: print-mariadb-header-objects
print-mariadb-header-objects:
	@printf '%s\n' '$(MARIADB_HEADER_OBJECTS)'
MAKEFILE
)
declared_tap_objects=$(printf '%s\n' "$declared_tap_objects" | \
	tr ' ' '\n' | sed '/^$/d' | LC_ALL=C sort | paste -sd' ' -)
actual_tap_objects=$(awk '
	/^[^[:space:]#][^:]*:/ {
		targets=$0
		sub(/:.*/, "", targets)
	}
	/^\t/ && /MARIADB_IDIR/ { print targets }
' "$repo/test/tap/tap/Makefile" | tr ' ' '\n' | sed '/^$/d' | \
	LC_ALL=C sort -u | paste -sd' ' -)
[[ "$actual_tap_objects" == "$declared_tap_objects" ]] || {
	printf 'TAP Connector/C header consumers are [%s], invalidation list is [%s]\n' \
		"$actual_tap_objects" "$declared_tap_objects" >&2
	exit 1
}
printf '%s\n' 'Connector/C tier selection passed.'

if [[ ${1:-} != --linked ]]; then
	exit 0
fi

# Run the production connector build for each tier in one checkout, then
# compile against the selected headers and link the corresponding archive.
temporary=$(mktemp -d)
trap 'rm -rf "$probe_dir" "$temporary"' EXIT
cat > "$temporary/linked-version.c" <<'EOF'
#include <mysql.h>
#include <stdio.h>

int main(void) {
    unsigned long linked = mysql_get_client_version();
    printf("%lu\n", linked);
    return MARIADB_PACKAGE_VERSION_ID != EXPECTED_VERSION || linked != EXPECTED_VERSION;
}
EOF

iconv_libs=()
if [[ $(uname -s) == Darwin ]]; then
	iconv_libs+=(-liconv)
fi

check_linked_version() {
	local tier40=$1 tier31=$2 expected=$3 selected
	make -C "$repo/deps" mariadb_client PROXYSQL40="$tier40" PROXYSQL31="$tier31"
	selected=$(probe src "$tier40" "$tier31")
	"${CC:-cc}" -DEXPECTED_VERSION="$expected" -I"$selected/include" \
		"$temporary/linked-version.c" "$selected/libmariadb/libmariadbclient.a" \
		"$repo/deps/libssl/openssl/libssl.a" "$repo/deps/libssl/openssl/libcrypto.a" \
		-lz -ldl -lm -pthread "${iconv_libs[@]}" -o "$temporary/linked-version"
	"$temporary/linked-version"
}

check_linked_version 0 0 30308
cp "$connector/mariadb_client/libmariadb/libmariadbclient.a" "$temporary/legacy.a"
check_linked_version 1 1 30411
cp "$connector/mariadb-connector-c-3.4.11-src/libmariadb/libmariadbclient.a" "$temporary/v40.a"
check_linked_version 0 1 30308
check_linked_version 0 0 30308
cmp "$temporary/legacy.a" "$connector/mariadb_client/libmariadb/libmariadbclient.a"
cmp "$temporary/v40.a" "$connector/mariadb-connector-c-3.4.11-src/libmariadb/libmariadbclient.a"
