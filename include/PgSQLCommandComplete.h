/**
 * @file PgSQLCommandComplete.h
 * @brief Pure parser for PostgreSQL CommandComplete message tags.
 *
 * Extracted from PgSQLFFTO for unit testability. Parses command tags
 * like "INSERT 0 10", "SELECT 5", "UPDATE 3" to extract row counts.
 *
 * @see FFTO unit testing (GitHub issue #5499)
 */

#ifndef PGSQL_COMMAND_COMPLETE_H
#define PGSQL_COMMAND_COMPLETE_H

#include <cstdint>
#include <cstddef>

/**
 * @brief Result of parsing a PostgreSQL CommandComplete tag.
 */
struct PgSQLCommandResult {
	uint64_t rows;    ///< Number of rows affected/returned.
	bool is_select;   ///< True if the command is a result-set operation (SELECT, FETCH, MOVE).
};

/**
 * @brief Parse a PostgreSQL CommandComplete message tag to extract row count.
 *
 * PostgreSQL encodes row counts in the tag string:
 *   - "INSERT 0 10" → rows=10, is_select=false
 *   - "SELECT 5"    → rows=5, is_select=true
 *   - "UPDATE 3"    → rows=3, is_select=false
 *   - "FETCH 10"    → rows=10, is_select=true
 *   - "MOVE 7"      → rows=7, is_select=true
 *   - "DELETE 0"    → rows=0, is_select=false
 *   - "COPY 100"    → rows=100, is_select=false
 *   - "MERGE 5"     → rows=5, is_select=false
 *   - "CREATE TABLE" → rows=0, is_select=false (no row count)
 *
 * @param payload  Pointer to the CommandComplete tag string.
 * @param len      Length of the payload.
 * @return PgSQLCommandResult with parsed rows and is_select flag.
 */
PgSQLCommandResult parse_pgsql_command_complete(
	const unsigned char *payload,
	size_t len
);

#endif // PGSQL_COMMAND_COMPLETE_H
