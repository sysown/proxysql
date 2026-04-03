#include "PgBouncer_ConfigParser.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <climits>

namespace PgBouncer {

// ---------------------------------------------------------------------------
// String utilities
// ---------------------------------------------------------------------------

std::string ConfigParser::trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string ConfigParser::unquote(const std::string& s) {
    if (s.size() >= 2 && s.front() == '\'' && s.back() == '\'') {
        // PgBouncer single-quote escaping: '' -> '
        std::string result;
        result.reserve(s.size());
        for (size_t i = 1; i + 1 < s.size(); ++i) {
            if (s[i] == '\'' && i + 2 < s.size() && s[i + 1] == '\'') {
                result += '\'';
                ++i;
            } else {
                result += s[i];
            }
        }
        return result;
    }
    return s;
}

bool ConfigParser::parse_bool(const std::string& value, bool& result) {
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (lower == "1" || lower == "yes" || lower == "true" || lower == "on") {
        result = true;
        return true;
    }
    if (lower == "0" || lower == "no" || lower == "false" || lower == "off") {
        result = false;
        return true;
    }
    return false;
}

bool ConfigParser::parse_int(const std::string& value, int& result) {
    if (value.empty()) return false;
    try {
        size_t pos = 0;
        long v = std::stol(value, &pos);
        if (pos != value.size()) return false;
        if (v < INT_MIN || v > INT_MAX) return false;
        result = static_cast<int>(v);
        return true;
    } catch (...) {
        return false;
    }
}

bool ConfigParser::parse_uint(const std::string& value, unsigned int& result) {
    if (value.empty()) return false;
    try {
        size_t pos = 0;
        unsigned long v = std::stoul(value, &pos);
        if (pos != value.size()) return false;
        if (v > UINT_MAX) return false;
        result = static_cast<unsigned int>(v);
        return true;
    } catch (...) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Connection-string pair parser
// ---------------------------------------------------------------------------

bool ConfigParser::parse_connstr_pairs(
    const std::string& connstr,
    std::vector<std::pair<std::string, std::string>>& pairs,
    const std::string& file, int line,
    std::vector<ParseMessage>& errors)
{
    // Parses "key=value key2=value2 key3='val with spaces'"
    pairs.clear();
    size_t i = 0;
    const size_t len = connstr.size();

    while (i < len) {
        // Skip whitespace
        while (i < len && std::isspace(static_cast<unsigned char>(connstr[i]))) ++i;
        if (i >= len) break;

        // Read key
        size_t key_start = i;
        while (i < len && connstr[i] != '=' && !std::isspace(static_cast<unsigned char>(connstr[i]))) ++i;
        std::string key = connstr.substr(key_start, i - key_start);

        // Skip whitespace around '='
        while (i < len && std::isspace(static_cast<unsigned char>(connstr[i]))) ++i;
        if (i >= len || connstr[i] != '=') {
            errors.push_back({file, line, "expected '=' after key '" + key + "' in connection string"});
            return false;
        }
        ++i; // skip '='
        while (i < len && std::isspace(static_cast<unsigned char>(connstr[i]))) ++i;

        // Read value
        std::string value;
        if (i < len && connstr[i] == '\'') {
            // Quoted value: collect until unescaped closing quote
            // PgBouncer escapes single quotes by doubling: ''
            ++i; // skip opening quote
            bool closed = false;
            while (i < len) {
                if (connstr[i] == '\'') {
                    if (i + 1 < len && connstr[i + 1] == '\'') {
                        value += '\'';
                        i += 2;
                    } else {
                        // closing quote
                        ++i;
                        closed = true;
                        break;
                    }
                } else {
                    value += connstr[i];
                    ++i;
                }
            }
            if (!closed) {
                errors.push_back({file, line, "unterminated single quote in connection string value for key '" + key + "'"});
                return false;
            }
        } else {
            // Unquoted value: read until whitespace
            size_t val_start = i;
            while (i < len && !std::isspace(static_cast<unsigned char>(connstr[i]))) ++i;
            value = connstr.substr(val_start, i - val_start);
        }

        pairs.emplace_back(std::move(key), std::move(value));
    }
    return true;
}

// ---------------------------------------------------------------------------
// Section parsers
// ---------------------------------------------------------------------------

bool ConfigParser::parse_global_key(
    const std::string& key, const std::string& value,
    GlobalSettings& settings, const std::string& file, int line,
    std::vector<ParseMessage>& errors)
{
    // Helper macros to reduce repetition.
    // Each maps a key name to the corresponding field.
#define SET_STR(name) do { if (key == #name) { settings.name = value; return true; } } while(0)
#define SET_INT(name) do { if (key == #name) { \
    int v; if (!parse_int(value, v)) { \
        errors.push_back({file, line, "invalid integer for '" + key + "': " + value}); return false; } \
    settings.name = v; return true; } } while(0)
#define SET_UINT(name) do { if (key == #name) { \
    unsigned int v; if (!parse_uint(value, v)) { \
        errors.push_back({file, line, "invalid unsigned integer for '" + key + "': " + value}); return false; } \
    settings.name = v; return true; } } while(0)
#define SET_BOOL(name) do { if (key == #name) { \
    bool v; if (!parse_bool(value, v)) { \
        errors.push_back({file, line, "invalid boolean for '" + key + "': " + value}); return false; } \
    settings.name = v; return true; } } while(0)

    // Listener
    SET_STR(listen_addr);
    SET_INT(listen_port);
    SET_STR(unix_socket_dir);
    SET_INT(listen_backlog);
    SET_STR(unix_socket_mode);
    SET_STR(unix_socket_group);

    // Pooling
    SET_STR(pool_mode);
    SET_INT(default_pool_size);
    SET_INT(min_pool_size);
    SET_INT(reserve_pool_size);
    SET_INT(reserve_pool_timeout);
    SET_BOOL(server_round_robin);

    // Limits
    SET_INT(max_client_conn);
    SET_INT(max_db_connections);
    SET_INT(max_db_client_connections);
    SET_INT(max_user_connections);
    SET_INT(max_user_client_connections);

    // Authentication
    SET_STR(auth_type);
    SET_STR(auth_file);
    SET_STR(auth_hba_file);
    SET_STR(auth_ident_file);
    SET_STR(auth_user);
    SET_STR(auth_query);
    SET_STR(auth_dbname);
    SET_STR(auth_ldap_options);

    // Timeouts
    SET_INT(server_lifetime);
    SET_INT(server_idle_timeout);
    SET_INT(server_connect_timeout);
    SET_INT(server_login_retry);
    SET_INT(client_login_timeout);
    SET_INT(client_idle_timeout);
    SET_INT(query_timeout);
    SET_INT(query_wait_timeout);
    SET_INT(cancel_wait_timeout);
    SET_INT(idle_transaction_timeout);
    SET_INT(transaction_timeout);
    SET_INT(suspend_timeout);
    SET_INT(autodb_idle_timeout);

    // Server maintenance
    SET_STR(server_reset_query);
    SET_BOOL(server_reset_query_always);
    SET_STR(server_check_query);
    SET_INT(server_check_delay);
    SET_BOOL(server_fast_close);

    // TLS client-facing
    SET_STR(client_tls_sslmode);
    SET_STR(client_tls_key_file);
    SET_STR(client_tls_cert_file);
    SET_STR(client_tls_ca_file);
    SET_STR(client_tls_protocols);
    SET_STR(client_tls_ciphers);
    SET_STR(client_tls13_ciphers);
    SET_STR(client_tls_dheparams);
    SET_STR(client_tls_ecdhcurve);

    // TLS server-facing
    SET_STR(server_tls_sslmode);
    SET_STR(server_tls_key_file);
    SET_STR(server_tls_cert_file);
    SET_STR(server_tls_ca_file);
    SET_STR(server_tls_protocols);
    SET_STR(server_tls_ciphers);
    SET_STR(server_tls13_ciphers);

    // Logging
    SET_STR(logfile);
    SET_BOOL(syslog);
    SET_STR(syslog_ident);
    SET_STR(syslog_facility);
    SET_BOOL(log_connections);
    SET_BOOL(log_disconnections);
    SET_BOOL(log_pooler_errors);
    SET_BOOL(log_stats);
    SET_INT(stats_period);
    SET_INT(verbose);

    // Admin
    SET_STR(admin_users);
    SET_STR(stats_users);

    // Networking
    SET_BOOL(so_reuseport);
    SET_BOOL(tcp_defer_accept);
    SET_BOOL(tcp_keepalive);
    SET_INT(tcp_keepcnt);
    SET_INT(tcp_keepidle);
    SET_INT(tcp_keepintvl);
    SET_INT(tcp_socket_buffer);
    SET_INT(tcp_user_timeout);

    // Protocol
    SET_INT(max_prepared_statements);
    SET_BOOL(disable_pqexec);
    SET_BOOL(application_name_add_host);
    SET_STR(track_extra_parameters);
    SET_STR(ignore_startup_parameters);
    SET_INT(scram_iterations);
    SET_INT(pkt_buf);
    SET_UINT(max_packet_size);
    SET_INT(sbuf_loopcnt);
    SET_INT(query_wait_notify);

    // DNS
    SET_INT(dns_max_ttl);
    SET_INT(dns_nxdomain_ttl);
    SET_INT(dns_zone_check_period);
    SET_STR(resolv_conf);

    // Process
    SET_STR(pidfile);
    SET_STR(user);
    SET_INT(peer_id);

#undef SET_STR
#undef SET_INT
#undef SET_UINT
#undef SET_BOOL

    errors.push_back({file, line, "unknown pgbouncer setting: " + key});
    return false;
}

bool ConfigParser::parse_database_entry(
    const std::string& name, const std::string& connstr,
    Database& db, const std::string& file, int line,
    std::vector<ParseMessage>& errors)
{
    db.name = name;

    std::vector<std::pair<std::string, std::string>> pairs;
    if (!parse_connstr_pairs(connstr, pairs, file, line, errors)) {
        return false;
    }

    bool ok = true;
    for (const auto& [k, v] : pairs) {
        if (k == "host") { db.host = v; }
        else if (k == "port") {
            if (!parse_int(v, db.port)) {
                errors.push_back({file, line, "invalid integer for 'port': " + v});
                ok = false;
            }
        }
        else if (k == "dbname") { db.dbname = v; }
        else if (k == "user") { db.user = v; }
        else if (k == "password") { db.password = v; }
        else if (k == "auth_user") { db.auth_user = v; }
        else if (k == "auth_query") { db.auth_query = v; }
        else if (k == "auth_dbname") { db.auth_dbname = v; }
        else if (k == "pool_mode") { db.pool_mode = v; }
        else if (k == "pool_size") {
            if (!parse_int(v, db.pool_size)) {
                errors.push_back({file, line, "invalid integer for 'pool_size': " + v});
                ok = false;
            }
        }
        else if (k == "min_pool_size") {
            if (!parse_int(v, db.min_pool_size)) {
                errors.push_back({file, line, "invalid integer for 'min_pool_size': " + v});
                ok = false;
            }
        }
        else if (k == "reserve_pool_size") {
            if (!parse_int(v, db.reserve_pool_size)) {
                errors.push_back({file, line, "invalid integer for 'reserve_pool_size': " + v});
                ok = false;
            }
        }
        else if (k == "max_db_connections") {
            if (!parse_int(v, db.max_db_connections)) {
                errors.push_back({file, line, "invalid integer for 'max_db_connections': " + v});
                ok = false;
            }
        }
        else if (k == "max_db_client_connections") {
            if (!parse_int(v, db.max_db_client_connections)) {
                errors.push_back({file, line, "invalid integer for 'max_db_client_connections': " + v});
                ok = false;
            }
        }
        else if (k == "server_lifetime") {
            if (!parse_int(v, db.server_lifetime)) {
                errors.push_back({file, line, "invalid integer for 'server_lifetime': " + v});
                ok = false;
            }
        }
        else if (k == "load_balance_hosts") { db.load_balance_hosts = v; }
        else if (k == "connect_query") { db.connect_query = v; }
        else if (k == "client_encoding") { db.client_encoding = v; }
        else if (k == "datestyle") { db.datestyle = v; }
        else if (k == "timezone") { db.timezone = v; }
        else if (k == "application_name") { db.application_name = v; }
        else {
            errors.push_back({file, line, "unknown database parameter: " + k});
            ok = false;
        }
    }
    return ok;
}

bool ConfigParser::parse_user_entry(
    const std::string& name, const std::string& settings_str,
    User& user, const std::string& file, int line,
    std::vector<ParseMessage>& errors)
{
    user.name = name;

    std::vector<std::pair<std::string, std::string>> pairs;
    if (!parse_connstr_pairs(settings_str, pairs, file, line, errors)) {
        return false;
    }

    bool ok = true;
    for (const auto& [k, v] : pairs) {
        if (k == "pool_mode") { user.pool_mode = v; }
        else if (k == "pool_size") {
            if (!parse_int(v, user.pool_size)) {
                errors.push_back({file, line, "invalid integer for 'pool_size': " + v});
                ok = false;
            }
        }
        else if (k == "reserve_pool_size") {
            if (!parse_int(v, user.reserve_pool_size)) {
                errors.push_back({file, line, "invalid integer for 'reserve_pool_size': " + v});
                ok = false;
            }
        }
        else if (k == "max_user_connections") {
            if (!parse_int(v, user.max_user_connections)) {
                errors.push_back({file, line, "invalid integer for 'max_user_connections': " + v});
                ok = false;
            }
        }
        else if (k == "max_user_client_connections") {
            if (!parse_int(v, user.max_user_client_connections)) {
                errors.push_back({file, line, "invalid integer for 'max_user_client_connections': " + v});
                ok = false;
            }
        }
        else if (k == "query_timeout") {
            if (!parse_int(v, user.query_timeout)) {
                errors.push_back({file, line, "invalid integer for 'query_timeout': " + v});
                ok = false;
            }
        }
        else if (k == "idle_transaction_timeout") {
            if (!parse_int(v, user.idle_transaction_timeout)) {
                errors.push_back({file, line, "invalid integer for 'idle_transaction_timeout': " + v});
                ok = false;
            }
        }
        else if (k == "transaction_timeout") {
            if (!parse_int(v, user.transaction_timeout)) {
                errors.push_back({file, line, "invalid integer for 'transaction_timeout': " + v});
                ok = false;
            }
        }
        else if (k == "client_idle_timeout") {
            if (!parse_int(v, user.client_idle_timeout)) {
                errors.push_back({file, line, "invalid integer for 'client_idle_timeout': " + v});
                ok = false;
            }
        }
        else {
            errors.push_back({file, line, "unknown user parameter: " + k});
            ok = false;
        }
    }
    return ok;
}

bool ConfigParser::parse_peer_entry(
    const std::string& name, const std::string& connstr,
    Peer& peer, const std::string& file, int line,
    std::vector<ParseMessage>& errors)
{
    // The name in [peers] is the peer_id (an integer)
    if (!parse_int(name, peer.peer_id)) {
        errors.push_back({file, line, "invalid peer_id (expected integer): " + name});
        return false;
    }

    std::vector<std::pair<std::string, std::string>> pairs;
    if (!parse_connstr_pairs(connstr, pairs, file, line, errors)) {
        return false;
    }

    bool ok = true;
    for (const auto& [k, v] : pairs) {
        if (k == "host") { peer.host = v; }
        else if (k == "port") {
            if (!parse_int(v, peer.port)) {
                errors.push_back({file, line, "invalid integer for 'port': " + v});
                ok = false;
            }
        }
        else if (k == "pool_size") {
            if (!parse_int(v, peer.pool_size)) {
                errors.push_back({file, line, "invalid integer for 'pool_size': " + v});
                ok = false;
            }
        }
        else {
            errors.push_back({file, line, "unknown peer parameter: " + k});
            ok = false;
        }
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Core INI parser
// ---------------------------------------------------------------------------

bool ConfigParser::parse_ini(
    const std::string& filepath, Config& config,
    bool resolve_includes, bool resolve_referenced_files)
{
    std::ifstream ifs(filepath);
    if (!ifs.is_open()) {
        config.errors.push_back({filepath, 0, "cannot open file: " + filepath});
        return false;
    }

    enum class Section { NONE, PGBOUNCER, DATABASES, USERS, PEERS };
    Section current_section = Section::NONE;

    std::string line_str;
    int line_num = 0;
    bool ok = true;

    // Resolve the directory of this file for relative %include paths
    std::string base_dir;
    {
        auto pos = filepath.find_last_of("/\\");
        if (pos != std::string::npos) {
            base_dir = filepath.substr(0, pos + 1);
        }
    }

    while (std::getline(ifs, line_str)) {
        ++line_num;
        std::string trimmed = trim(line_str);

        // Skip empty lines and comments
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        // %include directive
        if (trimmed.size() > 9 && trimmed.substr(0, 9) == "%include ") {
            if (!resolve_includes) continue;
            std::string inc_path = trim(trimmed.substr(9));
            // Resolve relative paths against the base directory
            if (!inc_path.empty() && inc_path[0] != '/') {
                inc_path = base_dir + inc_path;
            }
            if (include_depth_ >= MAX_INCLUDE_DEPTH) {
                config.errors.push_back({filepath, line_num,
                    "maximum include depth (" + std::to_string(MAX_INCLUDE_DEPTH) + ") exceeded"});
                ok = false;
                continue;
            }
            ++include_depth_;
            if (!parse_ini(inc_path, config, resolve_includes, resolve_referenced_files)) {
                ok = false;
            }
            --include_depth_;
            continue;
        }

        // Section header
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            std::string section_name = trim(trimmed.substr(1, trimmed.size() - 2));
            std::string section_lower = section_name;
            std::transform(section_lower.begin(), section_lower.end(), section_lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });

            if (section_lower == "pgbouncer") {
                current_section = Section::PGBOUNCER;
            } else if (section_lower == "databases") {
                current_section = Section::DATABASES;
            } else if (section_lower == "users") {
                current_section = Section::USERS;
            } else if (section_lower == "peers") {
                current_section = Section::PEERS;
            } else {
                config.errors.push_back({filepath, line_num, "unknown section: " + section_name});
                current_section = Section::NONE;
                ok = false;
            }
            continue;
        }

        // Key = value line
        auto eq_pos = trimmed.find('=');
        if (eq_pos == std::string::npos) {
            config.errors.push_back({filepath, line_num, "syntax error: expected key = value"});
            ok = false;
            continue;
        }

        std::string key = trim(trimmed.substr(0, eq_pos));
        std::string value = trim(trimmed.substr(eq_pos + 1));

        // Strip inline comments from values (only for [pgbouncer] section, not connection strings)
        if (current_section == Section::PGBOUNCER) {
            // Remove trailing comments, but be careful with quoted values
            if (!value.empty() && value[0] != '\'') {
                auto comment_pos = value.find(" #");
                if (comment_pos == std::string::npos) comment_pos = value.find(" ;");
                if (comment_pos == std::string::npos) comment_pos = value.find("\t#");
                if (comment_pos == std::string::npos) comment_pos = value.find("\t;");
                if (comment_pos != std::string::npos) {
                    value = trim(value.substr(0, comment_pos));
                }
            }
        }

        if (current_section == Section::NONE) {
            config.errors.push_back({filepath, line_num, "key-value pair outside of any section"});
            ok = false;
            continue;
        }

        switch (current_section) {
            case Section::PGBOUNCER: {
                if (!parse_global_key(key, value, config.global, filepath, line_num, config.errors)) {
                    ok = false;
                }
                break;
            }
            case Section::DATABASES: {
                Database db;
                if (!parse_database_entry(key, value, db, filepath, line_num, config.errors)) {
                    ok = false;
                } else {
                    config.databases.push_back(std::move(db));
                }
                break;
            }
            case Section::USERS: {
                User user;
                if (!parse_user_entry(key, value, user, filepath, line_num, config.errors)) {
                    ok = false;
                } else {
                    config.users.push_back(std::move(user));
                }
                break;
            }
            case Section::PEERS: {
                Peer peer;
                if (!parse_peer_entry(key, value, peer, filepath, line_num, config.errors)) {
                    ok = false;
                } else {
                    config.peers.push_back(std::move(peer));
                }
                break;
            }
            default:
                break;
        }
    }

    // After parsing, resolve referenced files if requested
    if (resolve_referenced_files && include_depth_ == 0) {
        if (!config.global.auth_file.empty()) {
            // Resolve relative path
            std::string auth_path = config.global.auth_file;
            if (!auth_path.empty() && auth_path[0] != '/') {
                auth_path = base_dir + auth_path;
            }
            if (!parse_auth_file(auth_path, config.auth_entries, config.errors)) {
                ok = false;
            }
        }
        if (!config.global.auth_hba_file.empty()) {
            std::string hba_path = config.global.auth_hba_file;
            if (!hba_path.empty() && hba_path[0] != '/') {
                hba_path = base_dir + hba_path;
            }
            if (!parse_hba_file(hba_path, config.hba_rules, config.errors)) {
                ok = false;
            }
        }
    }

    return ok;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool ConfigParser::parse(
    const std::string& filepath, Config& config,
    bool resolve_includes, bool resolve_referenced_files)
{
    include_depth_ = 0;
    return parse_ini(filepath, config, resolve_includes, resolve_referenced_files);
}

// ---------------------------------------------------------------------------
// Free function (declared in PgBouncer_Config.h)
// ---------------------------------------------------------------------------

bool parse_config_file(const std::string& filepath, Config& config) {
    ConfigParser parser;
    return parser.parse(filepath, config);
}

} // namespace PgBouncer
