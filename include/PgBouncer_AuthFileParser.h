#ifndef __CLASS_PGBOUNCER_AUTH_FILE_PARSER_H
#define __CLASS_PGBOUNCER_AUTH_FILE_PARSER_H

#include "PgBouncer_Config.h"
#include <string>
#include <vector>

namespace PgBouncer {

class AuthFileParser {
public:
    // Parse a PgBouncer userlist.txt file.
    // Format: "username" "password" per line
    // Password types detected:
    //   - Plain text: any string not matching MD5 or SCRAM patterns
    //   - MD5: starts with "md5" followed by 32 hex chars
    //   - SCRAM: starts with "SCRAM-SHA-256$"
    // Double-quote escaping: "" inside quoted strings represents a literal "
    bool parse(const std::string& filepath,
               std::vector<AuthFileEntry>& entries,
               std::vector<ParseMessage>& errors);

private:
    // Parse a double-quoted string starting at pos, advancing pos past the closing quote.
    // Returns the unescaped content. Returns false if malformed.
    static bool parse_quoted_string(const std::string& line, size_t& pos,
                                     std::string& result);

    // Detect password type from the raw password string
    static AuthType detect_password_type(const std::string& password);
};

} // namespace PgBouncer

#endif // __CLASS_PGBOUNCER_AUTH_FILE_PARSER_H
