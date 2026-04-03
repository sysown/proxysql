#ifndef PGBOUNCER_CONFIG_CONVERTER_H
#define PGBOUNCER_CONFIG_CONVERTER_H

#include "PgBouncer_Config.h"
#include <string>
#include <vector>

namespace PgBouncer {

struct ConversionEntry {
    std::string sql;        // SQL statement
    std::string comment;    // Explanatory comment
};

struct ConversionResult {
    std::vector<ConversionEntry> entries;
    std::vector<ParseMessage> warnings;   // Non-fatal mapping issues
    std::vector<ParseMessage> errors;     // Unmappable parameters (strict mode)
    bool success = true;

    // Summary counts
    int server_count = 0;
    int user_count = 0;
    int rule_count = 0;
    int variable_count = 0;
};

class ConfigConverter {
public:
    // Convert a parsed PgBouncer config into ProxySQL SQL statements.
    // If strict is true (default), unmappable parameters produce errors and success=false.
    // If strict is false, unmappable parameters produce warnings only.
    ConversionResult convert(const Config& config, bool strict = true);

    // Generate the full dry-run output as a string (SQL with comments)
    static std::string format_dry_run(const ConversionResult& result,
                                       const std::string& source_path,
                                       bool strict);

private:
    int next_hostgroup_ = 0;
    int next_rule_id_ = 1;
    int wildcard_hostgroup_ = -1;  // hostgroup for the * database, or -1

    void convert_databases(const Config& config, ConversionResult& result);
    void convert_users(const Config& config, ConversionResult& result);
    void convert_globals(const Config& config, ConversionResult& result, bool strict);
    void convert_hba_rules(const Config& config, ConversionResult& result, bool strict);
    void add_load_and_save(ConversionResult& result);

    // Check for unmappable parameters
    void check_unmappable(const Config& config, ConversionResult& result, bool strict);

    // Helper to add error or warning based on strict mode
    void add_issue(ConversionResult& result, bool strict,
                   const std::string& msg);

    // SQL escaping for string values
    static std::string sql_escape(const std::string& s);
};

} // namespace PgBouncer

#endif
