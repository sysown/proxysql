#ifndef __CLASS_PGBOUNCER_CONFIG_PARSER_H
#define __CLASS_PGBOUNCER_CONFIG_PARSER_H

#include "PgBouncer_Config.h"
#include <string>
#include <functional>

namespace PgBouncer {

class ConfigParser {
public:
    // Parse a pgbouncer.ini file. Returns true on success.
    // On failure, errors are populated in config.errors.
    // If resolve_includes is true, %include directives are followed.
    // If resolve_referenced_files is true, auth_file and auth_hba_file are parsed.
    bool parse(const std::string& filepath, Config& config,
               bool resolve_includes = true,
               bool resolve_referenced_files = true);

private:
    int include_depth_ = 0;
    static const int MAX_INCLUDE_DEPTH = 10;

    bool parse_ini(const std::string& filepath, Config& config,
                   bool resolve_includes, bool resolve_referenced_files);

    // Section parsers
    bool parse_global_key(const std::string& key, const std::string& value,
                         GlobalSettings& settings, const std::string& file, int line,
                         std::vector<ParseMessage>& errors);
    bool parse_database_entry(const std::string& name, const std::string& connstr,
                             Database& db, const std::string& file, int line,
                             std::vector<ParseMessage>& errors);
    bool parse_user_entry(const std::string& name, const std::string& settings_str,
                         User& user, const std::string& file, int line,
                         std::vector<ParseMessage>& errors);
    bool parse_peer_entry(const std::string& name, const std::string& connstr,
                         Peer& peer, const std::string& file, int line,
                         std::vector<ParseMessage>& errors);

    // Connection string parser (key=value pairs used in [databases], [users], [peers])
    static bool parse_connstr_pairs(const std::string& connstr,
                                    std::vector<std::pair<std::string, std::string>>& pairs,
                                    const std::string& file, int line,
                                    std::vector<ParseMessage>& errors);

    // String utilities
    static std::string trim(const std::string& s);
    static std::string unquote(const std::string& s);
    static std::string strip_inline_comment(const std::string& s);
    static bool parse_bool(const std::string& value, bool& result);
    static bool parse_int(const std::string& value, int& result);
    static bool parse_uint(const std::string& value, unsigned int& result);
};

} // namespace PgBouncer

#endif // __CLASS_PGBOUNCER_CONFIG_PARSER_H
