# MySQL / DuckDB analytical semantic baseline

This is a differential experiment, not a test of production translation or ProxySQL routing. Every source and candidate SQL statement is explicitly authored in `tools/probes/duckdb_mysql_semantics.cpp`. There is no parser, renderer, or production translator here. A match supports only the tested input, types, session and versions; it does not establish general compatibility. An expected difference is an example requiring refusal or a separately proven translation, not an approved rewrite.

The probe connects as root over the explicitly supplied local test socket, creates a PID-named database and drops it on normal exit or caught errors. It creates no global settings, connects to no other database, and runs DuckDB in memory. The MySQL session sets `STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,ONLY_FULL_GROUP_BY`, `utf8mb4`/`utf8mb4_bin`, and UTC. It prints the actual server version, SQL mode, connection charset and collation, time zone, `div_precision_increment`, and `lower_case_table_names`. A killed process or cleanup failure can leave the printed PID-derived database behind; do not run this against a shared or production server.

Build and run in a local test environment from the repository root. ROOT is the built repository checkout, SSL its built bundled OpenSSL version, PROBE_SOCKET the unix socket of a private MySQL server you own (never a shared or production one), and OUT a scratch directory:

```sh
ROOT="$(git rev-parse --show-toplevel)"
OUT="${TMPDIR:-/tmp}"
PROBE_SOCKET=/path/to/private-mysql.sock
MDB="$ROOT/deps/mariadb-client-library/mariadb-connector-c-3.3.8-src"
SSL="$ROOT/deps/libssl/openssl-3.5.9"
g++ -std=c++17 -Wall -Wextra -Werror -I"$MDB/include" \
  -I"$ROOT/deps/duckdb/duckdb/src/include" \
  tools/probes/duckdb_mysql_semantics.cpp \
  -L"$ROOT/deps/duckdb/duckdb/build/release/src" \
  -Wl,-rpath,"$ROOT/deps/duckdb/duckdb/build/release/src" \
  -lduckdb "$MDB/libmariadb/libmariadbclient.a" \
  "$SSL/libssl.a" "$SSL/libcrypto.a" -lz -ldl -lpthread \
  -o "$OUT/semantics-probe"
"$OUT/semantics-probe" "$PROBE_SOCKET"
```

The fixture includes signed BIGINT extremes, unsigned BIGINT maximum, DECIMAL(18,4), duplicates, negative values, NULLs, UTF-8, DATE and DATETIME, raw VARBINARY/BLOB bytes `00 ff`, plus an unmatched join group. Order-sensitive cases use explicit ordering and a unique tie-breaker. The comparison checks output labels including duplicate labels, column count, NULL positions, row order and multiplicity, exact string values, and coarse logical metadata categories (integer, decimal, date, datetime, text, binary). It does not compare widths, signedness, precision/scale, collation, flags, or the MySQL protocol metadata exposed by a proxy. It strips trailing fractional zeroes only for results that both APIs identify as exact decimal; integers, text, binary and approximate values are not normalized or rounded. Unsupported metadata types cause failure. All expected-difference examples require differing actual values with matching labels and categories; their casts to text are for displaying values, and do not test native result metadata.

On 2026-11-16, MySQL `8.0.46-0ubuntu0.24.04.5` and DuckDB `v2.0.0` produced exit status 0: **12 matches and 5 expected differences**. The source session returned `utf8mb4`, `utf8mb4_bin`, `+00:00`, `div_precision_increment=4` and `lower_case_table_names=0`; its SQL mode contained exactly the configured modes. Matches covered escaped identifiers and duplicate labels, numeric boundaries, nullable temporal and UTF-8 values, three LIMIT cases (including MySQL `LIMIT 1, 2` versus DuckDB `LIMIT 2 OFFSET 1`), both explicit NULL-order mappings, LEFT JOIN with grouped COUNT/SUM, empty aggregate, and DATE_FORMAT `%Y-%m` for DATE and DATETIME.

| Deliberate counterexample | MySQL | DuckDB candidate |
| --- | --- | --- |
| AVG of integers 0, 0, 1 | `0.3333` | `0.3333333333333333` |
| AVG of DECIMAL(18,4) boundary values | `99999999999999.99990000` | `100000000000000.0` |
| Case-insensitive source collation versus binary candidate | `1` | `0` |
| Source numeric coercion of `2x` versus TRY_CAST candidate | `1` | NULL |
| Source `3/2` versus candidate integer division | `1.5000` | `1` |

Do not admit native DuckDB AVG for exact-value MySQL inputs based on syntactic correspondence: it loses precision in these examples. Do not assume equivalent string collation, mixed string/numeric comparisons, or `/` to `//` mapping. Source ordering needs explicit NULL placement in the candidate; DATE_FORMAT coverage here is restricted to the literal `%Y-%m`. Results for other SQL modes, collations, date values, format specifiers, time zones, floating-point values, overflow and error behavior remain unproven. Unsafe functions are not executed.

The [MySQL aggregate documentation](https://dev.mysql.com/doc/refman/8.0/en/aggregate-functions.html) specifies DECIMAL results for AVG and SUM of exact-value arguments and NULL handling; the [MySQL arithmetic documentation](https://dev.mysql.com/doc/refman/8.0/en/arithmetic-functions.html) describes exact division scale and `div_precision_increment`. The [DuckDB aggregate documentation](https://duckdb.org/docs/2.0/sql/functions/aggregates) describes its AVG behavior. The actual counterexample values above are observations from this fixture, not assertions that those manuals specify their exact textual representation.
