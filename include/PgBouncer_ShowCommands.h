#ifndef __CLASS_PGBOUNCER_SHOW_COMMANDS_H
#define __CLASS_PGBOUNCER_SHOW_COMMANDS_H

#include <string>

namespace PgBouncer {

// Checks if a query is a PgBouncer-compatible SHOW command.
// Returns true if the query matches "SHOW [EXTENDED] <command>"
// where <command> is a known PgBouncer command.
// If matched, sets out_query to the equivalent ProxySQL SQL query.
// If not matched, returns false and the caller should handle normally.
bool translate_show_command(const char* query, int query_len,
                           std::string& out_query, bool& is_extended);

// Returns an error message for unsupported PgBouncer SHOW commands,
// or empty string if the command is not a known unsupported command.
std::string get_unsupported_show_message(const char* query, int query_len);

} // namespace PgBouncer

#endif // __CLASS_PGBOUNCER_SHOW_COMMANDS_H
