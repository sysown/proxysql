#include "ProxySQL_CLI.h"
#include "PgBouncer_Config.h"
#include "PgBouncer_ConfigConverter.h"

#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

// Single-quote a path for the copy-pasteable example command, so a path with
// spaces or shell metacharacters does not turn into something else when run.
static std::string shell_quote(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else out += c;
    }
    out += "'";
    return out;
}

static void print_usage() {
    std::cerr << "Usage: proxysql-cli <command> [options]\n"
              << "\n"
              << "Commands:\n"
              << "  import-pgbouncer <path> [--dry-run] [--ignore-warnings]\n"
              << "      Convert a PgBouncer config file to ProxySQL configuration.\n"
              << "      --dry-run          Show SQL output without applying changes.\n"
              << "      --ignore-warnings  Warn instead of error on unmappable parameters.\n"
              << "\n"
              << "  help\n"
              << "      Show this help message.\n";
}

static int cmd_import_pgbouncer(int argc, const char* argv[]) {
    // Parse arguments: import-pgbouncer <path> [--dry-run] [--ignore-warnings]
    if (argc < 3) {
        std::cerr << "Error: import-pgbouncer requires a config file path.\n\n";
        print_usage();
        return 1;
    }

    // argv[2] is the config path, not an option. Catching an option here turns
    // "import-pgbouncer --dry-run" into a usage error rather than a confusing
    // "cannot open file: --dry-run".
    if (argv[2][0] == '-') {
        std::cerr << "Error: import-pgbouncer requires a config file path "
                     "before any options (got '" << argv[2] << "').\n\n";
        print_usage();
        return 1;
    }

    std::string config_path = argv[2];
    bool dry_run = false;
    bool ignore_warnings = false;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = true;
        } else if (strcmp(argv[i], "--ignore-warnings") == 0) {
            ignore_warnings = true;
        } else {
            std::cerr << "Error: unknown option '" << argv[i] << "'\n\n";
            print_usage();
            return 1;
        }
    }

    // Stage 1: Parse PgBouncer config
    PgBouncer::Config config;
    bool parse_ok = PgBouncer::parse_config_file(config_path, config);

    if (!parse_ok) {
        std::cerr << "Error: Failed to parse PgBouncer config file: " << config_path << "\n";
        for (const auto& err : config.errors) {
            std::cerr << "  " << err.file << ":" << err.line << ": " << err.message << "\n";
        }
        return 1;
    }

    // Stage 2: Convert to ProxySQL SQL
    bool strict = !ignore_warnings;
    PgBouncer::ConfigConverter converter;
    PgBouncer::ConversionResult result = converter.convert(config, strict);

    if (!result.success) {
        // In strict mode, unmappable parameters cause failure
        std::cerr << "Error: Conversion failed due to unmappable parameters.\n";
        std::cerr << "Use --ignore-warnings to convert anyway.\n\n";
        for (const auto& err : result.errors) {
            std::cerr << "  ERROR: " << err.message << "\n";
        }
        // Show dry-run output on stderr only (never stdout — it could be piped to mysql)
        if (dry_run) {
            std::cerr << "\n" << PgBouncer::ConfigConverter::format_dry_run(result, config_path, strict);
        }
        return 1;
    }

    if (dry_run) {
        // Print SQL + comments to stdout
        std::cout << PgBouncer::ConfigConverter::format_dry_run(result, config_path, strict);

        if (!result.warnings.empty()) {
            std::cerr << "\nWarnings:\n";
            for (const auto& w : result.warnings) {
                std::cerr << "  WARNING: " << w.message << "\n";
            }
        }

        std::cerr << "\nDry run complete. "
                  << result.server_count << " servers, "
                  << result.user_count << " users, "
                  << result.rule_count << " query rules, "
                  << result.variable_count << " variables.\n";
        return 0;
    }

    // Non-dry-run: Write SQL to a file that can be loaded by ProxySQL
    // Output the SQL statements to stdout for piping or manual review
    for (const auto& entry : result.entries) {
        if (!entry.comment.empty()) {
            std::cout << "-- " << entry.comment << "\n";
        }
        std::cout << entry.sql << "\n";
    }

    if (!result.warnings.empty()) {
        std::cerr << "\nWarnings:\n";
        for (const auto& w : result.warnings) {
            std::cerr << "  WARNING: " << w.message << "\n";
        }
    }

    std::cerr << "\nConversion complete. "
              << result.server_count << " servers, "
              << result.user_count << " users, "
              << result.rule_count << " query rules, "
              << result.variable_count << " variables.\n"
              << "Pipe the output to ProxySQL admin interface to apply:\n"
              << "  proxysql-cli import-pgbouncer " << shell_quote(config_path)
              << " | mysql -h 127.0.0.1 -P 6032 -u admin -p\n";
    return 0;
}

int proxysql_cli_main(int argc, const char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "import-pgbouncer") == 0) {
        return cmd_import_pgbouncer(argc, argv);
    } else if (strcmp(command, "help") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        print_usage();
        return 0;
    } else {
        std::cerr << "Error: unknown command '" << command << "'\n\n";
        print_usage();
        return 1;
    }
}
