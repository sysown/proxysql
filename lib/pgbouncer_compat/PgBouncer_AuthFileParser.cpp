#include "PgBouncer_AuthFileParser.h"

#include <fstream>
#include <cctype>
#include <algorithm>

namespace PgBouncer {

// ---------------------------------------------------------------------------
// AuthFileParser – private helpers
// ---------------------------------------------------------------------------

bool AuthFileParser::parse_quoted_string(const std::string& line, size_t& pos,
                                          std::string& result) {
    result.clear();

    // Must start with a double-quote
    if (pos >= line.size() || line[pos] != '"') {
        return false;
    }
    ++pos; // skip opening quote

    while (pos < line.size()) {
        char ch = line[pos];
        if (ch == '"') {
            // Check for escaped quote ("")
            if (pos + 1 < line.size() && line[pos + 1] == '"') {
                result += '"';
                pos += 2;
            } else {
                // Closing quote
                ++pos;
                return true;
            }
        } else {
            result += ch;
            ++pos;
        }
    }

    // Reached end of line without closing quote
    return false;
}

AuthType AuthFileParser::detect_password_type(const std::string& password) {
    // SCRAM detection: starts with "SCRAM-SHA-256$"
    if (password.size() >= 14 && password.compare(0, 14, "SCRAM-SHA-256$") == 0) {
        return AuthType::SCRAM;
    }

    // MD5 detection: exactly "md5" + 32 hex characters = 35 chars total
    if (password.size() == 35 &&
        password[0] == 'm' && password[1] == 'd' && password[2] == '5') {
        bool all_hex = true;
        for (size_t i = 3; i < 35; ++i) {
            char c = password[i];
            if (!((c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'))) {
                all_hex = false;
                break;
            }
        }
        if (all_hex) {
            return AuthType::MD5;
        }
    }

    return AuthType::PLAIN;
}

// ---------------------------------------------------------------------------
// AuthFileParser::parse
// ---------------------------------------------------------------------------

bool AuthFileParser::parse(const std::string& filepath,
                           std::vector<AuthFileEntry>& entries,
                           std::vector<ParseMessage>& errors) {
    // Full load, not an append -- see the note in HBAParser::parse.
    entries.clear();
    std::ifstream file(filepath);
    if (!file.is_open()) {
        errors.push_back({filepath, 0, "Cannot open auth file: " + filepath});
        return false;
    }

    std::string line;
    int line_num = 0;
    bool had_errors = false;

    while (std::getline(file, line)) {
        ++line_num;

        // Skip empty lines
        if (line.empty()) {
            continue;
        }

        // Find the first non-whitespace character
        size_t first_non_ws = line.find_first_not_of(" \t\r");
        if (first_non_ws == std::string::npos) {
            // Blank line (only whitespace)
            continue;
        }

        // Skip comment lines (starting with ; or #)
        char first_char = line[first_non_ws];
        if (first_char == ';' || first_char == '#') {
            continue;
        }

        // Parse username
        size_t pos = first_non_ws;
        std::string username;
        if (!parse_quoted_string(line, pos, username)) {
            errors.push_back({filepath, line_num,
                "Malformed username (expected double-quoted string)"});
            had_errors = true;
            continue;
        }

        // Skip whitespace between username and password
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) {
            ++pos;
        }

        // Parse password
        std::string password;
        if (!parse_quoted_string(line, pos, password)) {
            errors.push_back({filepath, line_num,
                "Malformed password (expected double-quoted string)"});
            had_errors = true;
            continue;
        }

        // Extra fields after the second quoted string are silently ignored,
        // matching PgBouncer behaviour.

        AuthFileEntry entry;
        entry.username = std::move(username);
        entry.password = std::move(password);
        entry.type = detect_password_type(entry.password);
        entries.push_back(std::move(entry));
    }

    return !had_errors;
}

// ---------------------------------------------------------------------------
// Free function declared in PgBouncer_Config.h
// ---------------------------------------------------------------------------

bool parse_auth_file(const std::string& filepath,
                     std::vector<AuthFileEntry>& entries,
                     std::vector<ParseMessage>& errors) {
    AuthFileParser parser;
    return parser.parse(filepath, entries, errors);
}

} // namespace PgBouncer
