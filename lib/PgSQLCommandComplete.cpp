/**
 * @file PgSQLCommandComplete.cpp
 * @brief Implementation of PostgreSQL CommandComplete tag parser.
 *
 * Logic mirrors extract_pg_rows_affected() in PgSQLFFTO.cpp.
 *
 * @see PgSQLCommandComplete.h
 * @see FFTO unit testing (GitHub issue #5499)
 */

#include "PgSQLCommandComplete.h"
#include <string>
#include <cctype>
#include <cstdlib>

PgSQLCommandResult parse_pgsql_command_complete(
	const unsigned char *payload,
	size_t len)
{
	PgSQLCommandResult result = {0, false};

	if (payload == nullptr || len == 0) return result;

	// Trim whitespace and null terminators
	size_t begin = 0;
	while (begin < len && std::isspace(payload[begin])) begin++;
	while (len > begin && (payload[len - 1] == '\0' || std::isspace(payload[len - 1]))) len--;
	if (begin >= len) return result;

	std::string tag(reinterpret_cast<const char*>(payload + begin), len - begin);

	// Extract command type (first token)
	size_t first_space = tag.find(' ');
	if (first_space == std::string::npos) return result;

	std::string command = tag.substr(0, first_space);

	if (command == "SELECT" || command == "FETCH" || command == "MOVE") {
		result.is_select = true;
	} else if (command != "INSERT" && command != "UPDATE" &&
			   command != "DELETE" && command != "COPY" &&
			   command != "MERGE") {
		return result;  // Unknown command, no row count
	}

	// Extract row count (last token)
	size_t last_space = tag.rfind(' ');
	if (last_space == std::string::npos || last_space + 1 >= tag.size()) return result;

	const char *rows_str = tag.c_str() + last_space + 1;
	char *endptr = nullptr;
	unsigned long long rows = std::strtoull(rows_str, &endptr, 10);
	if (endptr == rows_str || *endptr != '\0') return result;

	result.rows = rows;
	return result;
}
