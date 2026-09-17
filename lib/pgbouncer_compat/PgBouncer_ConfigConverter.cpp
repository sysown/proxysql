#include "PgBouncer_ConfigConverter.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <ctime>

namespace PgBouncer {

// ---------------------------------------------------------------------------
// sql_escape: double single-quotes for SQL string literals
// ---------------------------------------------------------------------------
std::string ConfigConverter::sql_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\'') out += "''";
        else out += c;
    }
    return out;
}

// ---------------------------------------------------------------------------
// add_issue: error (strict) or warning (relaxed)
// ---------------------------------------------------------------------------
void ConfigConverter::add_issue(ConversionResult& result, bool strict,
                                const std::string& msg) {
    ParseMessage pm;
    pm.message = msg;
    if (strict) {
        result.errors.push_back(pm);
        result.success = false;
    } else {
        result.warnings.push_back(pm);
    }
}

// ---------------------------------------------------------------------------
// add_note: informational, never fatal
// ---------------------------------------------------------------------------
void ConfigConverter::add_note(ConversionResult& result, const std::string& msg) {
    ParseMessage pm;
    pm.message = msg;
    result.notes.push_back(pm);
}

// ---------------------------------------------------------------------------
// convert  (top-level entry point)
// ---------------------------------------------------------------------------
ConversionResult ConfigConverter::convert(const Config& config, bool strict) {
    // Reset state
    next_hostgroup_ = 0;
    next_rule_id_ = 1;
    wildcard_hostgroup_ = -1;

    ConversionResult result;

    convert_databases(config, result, strict);
    convert_users(config, result, strict);
    convert_globals(config, result, strict);
    convert_hba_rules(config, result, strict);
    check_unmappable(config, result, strict);
    add_load_and_save(result);

    return result;
}

// ---------------------------------------------------------------------------
// Helper: split a string on a delimiter
// ---------------------------------------------------------------------------
static std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, delim)) {
        // trim whitespace
        size_t start = token.find_first_not_of(" \t");
        size_t end = token.find_last_not_of(" \t");
        if (start != std::string::npos)
            parts.push_back(token.substr(start, end - start + 1));
    }
    return parts;
}

// ---------------------------------------------------------------------------
// Map a PgBouncer auth_type to pgsql-authentication_method:
// 1 = cleartext, 2 = md5, 3 = scram-sha-256. Returns 0 when there is no
// equivalent, in which case no variable is emitted.
// ---------------------------------------------------------------------------
static int map_auth_type(const std::string& auth_type) {
    std::string at = auth_type;
    std::transform(at.begin(), at.end(), at.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (at == "plain" || at == "password") return 1;
    if (at == "md5") return 2;
    if (at == "scram-sha-256") return 3;
    return 0;
}

// ---------------------------------------------------------------------------
// Length of the data encoded by a padded base64 string, or -1 if invalid.
// ---------------------------------------------------------------------------
static int base64_decoded_len(const std::string& s) {
    if (s.empty() || s.size() % 4 != 0) return -1;
    size_t pad = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = s[i];
        if (c == '=') {
            // padding only in the last two positions
            if (i < s.size() - 2) return -1;
            pad++;
        } else if (pad > 0 || !(std::isalnum(c) || c == '+' || c == '/')) {
            return -1;
        }
    }
    return static_cast<int>(s.size() / 4 * 3 - pad);
}

// ---------------------------------------------------------------------------
// Structural check of a SCRAM-SHA-256 verifier, matching what ProxySQL accepts
// when loading pgsql_users (a malformed verifier is skipped there):
//   SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>
// ---------------------------------------------------------------------------
static bool is_valid_scram_verifier(const std::string& v) {
    static const std::string scheme = "SCRAM-SHA-256$";
    static const int SCRAM_KEY_LEN = 32;
    if (v.compare(0, scheme.size(), scheme) != 0) return false;

    const std::string rest = v.substr(scheme.size());
    const size_t dollar = rest.find('$');
    if (dollar == std::string::npos) return false;
    const std::string iter_salt = rest.substr(0, dollar);
    const std::string keys = rest.substr(dollar + 1);

    const size_t colon1 = iter_salt.find(':');
    const size_t colon2 = keys.find(':');
    if (colon1 == std::string::npos || colon2 == std::string::npos) return false;

    const std::string iterations = iter_salt.substr(0, colon1);
    if (iterations.empty() ||
        iterations.find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }
    if (base64_decoded_len(iter_salt.substr(colon1 + 1)) <= 0) return false;
    if (base64_decoded_len(keys.substr(0, colon2)) != SCRAM_KEY_LEN) return false;
    if (base64_decoded_len(keys.substr(colon2 + 1)) != SCRAM_KEY_LEN) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Join user names for a message: 'a', 'b', 'c'
// ---------------------------------------------------------------------------
static std::string quote_join(const std::vector<std::string>& names) {
    std::string out;
    for (size_t i = 0; i < names.size(); ++i) {
        if (i) out += ", ";
        out += "'" + names[i] + "'";
    }
    return out;
}

// ---------------------------------------------------------------------------
// convert_databases
// ---------------------------------------------------------------------------
void ConfigConverter::convert_databases(const Config& config,
                                         ConversionResult& result, bool strict) {
    if (config.databases.empty()) return;

    // Clean slate
    result.entries.push_back({
        "DELETE FROM pgsql_servers;",
        "Remove existing server entries before importing"
    });
    result.entries.push_back({
        "DELETE FROM pgsql_query_rules;",
        "Remove existing query rules before importing"
    });

    for (const auto& db : config.databases) {
        int hg = next_hostgroup_++;

        // Wildcard database: remember its hostgroup for user defaults
        if (db.name == "*") {
            wildcard_hostgroup_ = hg;
        }

        // Resolve host list
        std::string host_str = db.host.empty() ? "127.0.0.1" : db.host;
        std::vector<std::string> hosts = split(host_str, ',');
        int port = db.port;

        // max_connections per server from pool_size (or default 20)
        int max_conn = (db.pool_size > 0) ? db.pool_size : 20;

        // Weight: equal across all hosts
        int weight = 1000;

        bool use_ssl = false;
        // SSL will be set later in convert_globals if server_tls_sslmode requires it

        for (const auto& h : hosts) {
            std::ostringstream sql;
            sql << "INSERT INTO pgsql_servers "
                << "(hostgroup_id, hostname, port, max_connections, weight, use_ssl) "
                << "VALUES ("
                << hg << ", "
                << "'" << sql_escape(h) << "', "
                << port << ", "
                << max_conn << ", "
                << weight << ", "
                << (use_ssl ? 1 : 0)
                << ");";

            std::string comment = "Server for database '" + db.name + "'";
            if (hosts.size() > 1)
                comment += " (multi-host: " + host_str + ")";

            result.entries.push_back({sql.str(), comment});
            result.server_count++;
        }

        // Query rule to route by database name (skip for wildcard)
        if (db.name != "*") {
            int rule_id = next_rule_id_++;

            // The routing column in pgsql_query_rules is `database` (the
            // MySQL table calls it `schemaname`; the PgSQL one does not).
            std::ostringstream sql;
            sql << "INSERT INTO pgsql_query_rules "
                << "(rule_id, active, database, destination_hostgroup, apply) "
                << "VALUES ("
                << rule_id << ", 1, "
                << "'" << sql_escape(db.name) << "', "
                << hg << ", 1);";

            std::string comment = "Route database '" + db.name + "' to hostgroup " + std::to_string(hg);

            result.entries.push_back({sql.str(), comment});
            result.rule_count++;

            // `dbname=` makes PgBouncer connect to a backend database under a
            // different name than the one the client asked for. ProxySQL routes
            // to a hostgroup but does not rewrite the database in the startup
            // packet, so the alias cannot be honoured -- say so instead of
            // emitting a rule that quietly connects to the wrong database.
            if (!db.dbname.empty() && db.dbname != db.name) {
                add_issue(result, strict,
                    "database '" + db.name + "' maps to backend database '" +
                    db.dbname + "' (dbname=), which ProxySQL cannot rewrite; "
                    "rule_id " + std::to_string(rule_id) +
                    " routes to the hostgroup but the backend database name is "
                    "passed through unchanged");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// convert_users
// ---------------------------------------------------------------------------
void ConfigConverter::convert_users(const Config& config,
                                     ConversionResult& result, bool strict) {
    // Build a password lookup from auth_entries, keeping the detected type.
    // pgsql_users.password holds cleartext, an md5 hash or a SCRAM-SHA-256
    // verifier, auto-detected by prefix -- the same three forms userlist.txt
    // stores -- so every entry is imported as-is. The hashed forms constrain
    // the frontend and backend authentication methods; see the checks below.
    std::map<std::string, const AuthFileEntry*> passwords;
    for (const auto& ae : config.auth_entries) {
        passwords[ae.username] = &ae;
    }

    // Collect users from [users] section; also add any auth_entries users not
    // already listed.
    std::vector<User> user_list = config.users;
    std::map<std::string, bool> seen;
    for (const auto& u : user_list) seen[u.name] = true;
    for (const auto& ae : config.auth_entries) {
        if (!seen[ae.username]) {
            User u;
            u.name = ae.username;
            user_list.push_back(u);
            seen[ae.username] = true;
        }
    }

    if (user_list.empty()) return;

    // Clean slate
    result.entries.push_back({
        "DELETE FROM pgsql_users;",
        "Remove existing user entries before importing"
    });

    int default_hg = (wildcard_hostgroup_ >= 0) ? wildcard_hostgroup_ : 0;
    const int auth_method = map_auth_type(config.global.auth_type);
    std::vector<std::string> md5_users;
    std::vector<std::string> scram_users;

    for (const auto& u : user_list) {
        // Resolve password from auth_entries
        std::string password;
        auto it = passwords.find(u.name);
        if (it != passwords.end()) {
            password = it->second->password;
            if (it->second->type == AuthType::MD5) {
                // ProxySQL only recognises lowercase hex; anything else would
                // be taken for a cleartext password.
                std::transform(password.begin() + 3, password.end(), password.begin() + 3,
                               [](unsigned char c) { return std::tolower(c); });
                md5_users.push_back(u.name);
                if (auth_method == 3) {
                    add_issue(result, strict,
                        "user '" + u.name + "' has an md5 hash in the auth file, but "
                        "auth_type=scram-sha-256 maps to pgsql-authentication_method=3, "
                        "which rejects md5-stored credentials; this user will fail to "
                        "authenticate unless the method is lowered to 2 or the entry "
                        "is replaced with a SCRAM-SHA-256 verifier or the cleartext password");
                }
            } else if (it->second->type == AuthType::SCRAM) {
                if (!is_valid_scram_verifier(password)) {
                    add_issue(result, strict,
                        "user '" + u.name + "' has a malformed SCRAM-SHA-256 verifier in "
                        "the auth file; ProxySQL skips it when loading pgsql_users to "
                        "runtime, so this user will not be able to log in");
                } else {
                    scram_users.push_back(u.name);
                }
            }
        }

        // Pool mode mapping
        std::string pool = u.pool_mode.empty() ? config.global.pool_mode : u.pool_mode;
        int fast_forward = 0;
        int transaction_persistent = 0;
        if (pool == "session") {
            fast_forward = 1;
        } else if (pool == "transaction") {
            transaction_persistent = 1;
        }
        // statement mode and default: no special flags

        // max_connections from max_user_connections
        int max_conn = (u.max_user_connections > 0) ? u.max_user_connections : 0;

        std::ostringstream sql;
        sql << "INSERT INTO pgsql_users "
            << "(username, password, default_hostgroup, max_connections, "
            << "fast_forward, transaction_persistent, active, backend, frontend) "
            << "VALUES ("
            << "'" << sql_escape(u.name) << "', "
            << "'" << sql_escape(password) << "', "
            << default_hg << ", "
            << max_conn << ", "
            << fast_forward << ", "
            << transaction_persistent << ", "
            << "1, 1, 1);";

        std::string comment = "User '" + u.name + "'";
        if (fast_forward)
            comment += " (session mode -> fast_forward)";
        else if (transaction_persistent)
            comment += " (transaction mode -> transaction_persistent)";

        result.entries.push_back({sql.str(), comment});
        result.user_count++;
    }

    if (!md5_users.empty()) {
        if (auth_method == 0) {
            add_note(result,
                "md5-stored users (" + quote_join(md5_users) + ") need "
                "pgsql-authentication_method 1 or 2, but auth_type=" +
                config.global.auth_type + " sets no method; the ProxySQL "
                "default (3, scram-sha-256) rejects them");
        }
        add_note(result,
            "md5-stored users (" + quote_join(md5_users) + ") authenticate to the "
            "backend only with the md5 method: the backend pg_hba.conf must select "
            "md5 for them and their rolpassword must be the same md5 hash");
    }
    if (!scram_users.empty()) {
        add_note(result,
            "SCRAM-verifier-stored users (" + quote_join(scram_users) + ") authenticate "
            "to the backend only with scram-sha-256, and the verifier must be "
            "byte-identical to the backend rolpassword (same salt and iterations). "
            "This holds when userlist.txt was copied from the backend, but not across "
            "independently created or logically replicated servers in one hostgroup");
    }
}

// ---------------------------------------------------------------------------
// convert_globals
// ---------------------------------------------------------------------------
void ConfigConverter::convert_globals(const Config& config,
                                       ConversionResult& result, bool strict) {
    const auto& g = config.global;

    // Helper lambda to emit a SET + track variable count
    auto emit_set = [&](const std::string& var, const std::string& val,
                        const std::string& comment) {
        std::ostringstream sql;
        sql << "SET " << var << "='" << sql_escape(val) << "';";
        result.entries.push_back({sql.str(), comment});
        result.variable_count++;
    };

    auto emit_set_int = [&](const std::string& var, int val,
                            const std::string& comment) {
        std::ostringstream sql;
        sql << "SET " << var << "=" << val << ";";
        result.entries.push_back({sql.str(), comment});
        result.variable_count++;
    };

    // -- listen_addr:listen_port -> pgsql-interfaces
    if (!g.listen_addr.empty()) {
        std::string iface = g.listen_addr + ":" + std::to_string(g.listen_port);
        emit_set("pgsql-interfaces", iface,
                 "PgBouncer listen_addr:listen_port -> ProxySQL pgsql-interfaces");
    }

    // -- auth_type -> pgsql-authentication_method
    //
    // pgsql-authentication_method selects the method ProxySQL challenges
    // clients with: 1 = cleartext, 2 = md5, 3 = scram-sha-256.
    {
        std::string at = g.auth_type;
        std::transform(at.begin(), at.end(), at.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        switch (map_auth_type(g.auth_type)) {
        case 1:
            emit_set_int("pgsql-authentication_method", 1,
                         "PgBouncer auth_type=" + g.auth_type +
                         " -> ProxySQL cleartext authentication");
            break;
        case 2:
            emit_set_int("pgsql-authentication_method", 2,
                         "PgBouncer auth_type=md5 -> ProxySQL md5 authentication");
            break;
        case 3:
            emit_set_int("pgsql-authentication_method", 3,
                         "PgBouncer auth_type=scram-sha-256 -> ProxySQL SCRAM authentication");
            break;
        default:
            if (at == "trust") {
                add_issue(result, strict,
                          "auth_type=trust has no ProxySQL equivalent; ProxySQL always "
                          "authenticates clients against pgsql_users and cannot accept "
                          "unauthenticated connections");
            } else if (at == "hba") {
                add_issue(result, strict,
                          "auth_type=hba has no ProxySQL equivalent; the per-rule methods "
                          "in pg_hba.conf cannot select the frontend authentication method, "
                          "which is global (pgsql-authentication_method)");
            } else if (at == "any") {
                add_issue(result, strict,
                          "auth_type=any has no ProxySQL equivalent; ProxySQL always "
                          "verifies the username against pgsql_users");
            } else if (!at.empty()) {
                add_issue(result, strict,
                          "auth_type=" + g.auth_type + " has no ProxySQL equivalent");
            }
            break;
        }
    }

    // -- max_client_conn -> pgsql-max_connections (ProxySQL default: 2048)
    if (g.max_client_conn != 100) {
        // PgBouncer default is 100; only emit if changed
        emit_set_int("pgsql-max_connections", g.max_client_conn,
                     "PgBouncer max_client_conn -> ProxySQL pgsql-max_connections");
    }

    // -- server_connect_timeout (seconds -> milliseconds, ProxySQL default: 10000)
    if (g.server_connect_timeout != 15) {
        emit_set_int("pgsql-connect_timeout_server", g.server_connect_timeout * 1000,
                     "PgBouncer server_connect_timeout (s) -> ProxySQL (ms)");
    }

    // -- server_idle_timeout (seconds -> milliseconds, ProxySQL default: 0)
    if (g.server_idle_timeout != 600) {
        emit_set_int("pgsql-connection_max_age_ms", g.server_idle_timeout * 1000,
                     "PgBouncer server_idle_timeout (s) -> ProxySQL connection_max_age_ms (ms)");
    }

    // -- client_idle_timeout (seconds -> milliseconds)
    if (g.client_idle_timeout != 0) {
        emit_set_int("pgsql-wait_timeout", g.client_idle_timeout * 1000,
                     "PgBouncer client_idle_timeout (s) -> ProxySQL wait_timeout (ms)");
    }

    // -- query_timeout (seconds -> milliseconds)
    if (g.query_timeout != 0) {
        emit_set_int("pgsql-long_query_time", g.query_timeout * 1000,
                     "PgBouncer query_timeout (s) -> ProxySQL long_query_time (ms). "
                     "Note: ProxySQL logs long queries but does not kill them by default; "
                     "consider adding a query rule with timeout to replicate kill behavior");
    }

    // -- idle_transaction_timeout (seconds -> milliseconds)
    if (g.idle_transaction_timeout != 0) {
        emit_set_int("pgsql-max_transaction_idle_time", g.idle_transaction_timeout * 1000,
                     "PgBouncer idle_transaction_timeout (s) -> ProxySQL (ms)");
    }

    // -- transaction_timeout (seconds -> milliseconds)
    if (g.transaction_timeout != 0) {
        emit_set_int("pgsql-max_transaction_time", g.transaction_timeout * 1000,
                     "PgBouncer transaction_timeout (s) -> ProxySQL (ms)");
    }

    // -- max_prepared_statements -> pgsql-max_stmts_per_connection (ProxySQL default: 20)
    if (g.max_prepared_statements != 200) {
        emit_set_int("pgsql-max_stmts_per_connection", g.max_prepared_statements,
                     "PgBouncer max_prepared_statements -> ProxySQL max_stmts_per_connection");
    }

    // -- server_tls_sslmode: require/verify-ca/verify-full -> use_ssl=1 on servers
    {
        bool need_ssl = (g.server_tls_sslmode == "require" ||
                         g.server_tls_sslmode == "verify-ca" ||
                         g.server_tls_sslmode == "verify-full");
        if (need_ssl) {
            // Safe to apply unscoped: convert_databases() emits
            // "DELETE FROM pgsql_servers" before its INSERTs, so every row in
            // the table at this point came from this import.
            result.entries.push_back({
                "UPDATE pgsql_servers SET use_ssl=1;",
                "PgBouncer server_tls_sslmode=" + g.server_tls_sslmode +
                " -> enable SSL on all backend connections"
            });

            if (!g.server_tls_ca_file.empty()) {
                emit_set("pgsql-ssl_p2s_ca", g.server_tls_ca_file,
                         "PgBouncer server_tls_ca_file -> ProxySQL pgsql-ssl_p2s_ca");
            }
            if (!g.server_tls_cert_file.empty()) {
                emit_set("pgsql-ssl_p2s_cert", g.server_tls_cert_file,
                         "PgBouncer server_tls_cert_file -> ProxySQL pgsql-ssl_p2s_cert");
            }
            if (!g.server_tls_key_file.empty()) {
                emit_set("pgsql-ssl_p2s_key", g.server_tls_key_file,
                         "PgBouncer server_tls_key_file -> ProxySQL pgsql-ssl_p2s_key");
            }
        }
    }

    // -- server_check_query -> enable monitoring
    if (!g.server_check_query.empty()) {
        emit_set_int("pgsql-monitor_enabled", 1,
                     "PgBouncer server_check_query present -> enable ProxySQL monitor");
        emit_set_int("pgsql-monitor_ping_interval", g.server_check_delay * 1000,
                     "PgBouncer server_check_delay (s) -> ProxySQL monitor_ping_interval (ms)");
    }

    // -- tcp_keepalive
    if (!g.tcp_keepalive) {
        // ProxySQL default is usually enabled; only emit if PgBouncer disables it
        emit_set_int("pgsql-use_tcp_keepalive", 0,
                     "PgBouncer tcp_keepalive=false -> disable TCP keepalive");
    }

    // -- tcp_keepidle
    if (g.tcp_keepidle != 0) {
        emit_set_int("pgsql-tcp_keepalive_time", g.tcp_keepidle,
                     "PgBouncer tcp_keepidle -> ProxySQL tcp_keepalive_time");
    }
}

// ---------------------------------------------------------------------------
// convert_hba_rules
// ---------------------------------------------------------------------------
void ConfigConverter::convert_hba_rules(const Config& config,
                                          ConversionResult& result, bool strict) {
    if (config.hba_rules.empty()) return;

    bool any_converted = false;

    if (!config.hba_rules.empty()) {
        result.entries.push_back({
            "DELETE FROM pgsql_firewall_whitelist_rules;",
            "Remove existing firewall whitelist rules before importing HBA rules"
        });
    }

    for (const auto& rule : config.hba_rules) {
        // Unsupported connection types
        if (rule.conn_type == "local") {
            add_issue(result, strict,
                      "HBA rule with conn_type 'local' (Unix socket) has no ProxySQL equivalent");
            continue;
        }
        if (rule.conn_type == "hostnossl") {
            add_issue(result, strict,
                      "HBA rule with conn_type 'hostnossl' has no ProxySQL equivalent");
            continue;
        }

        // Unsupported auth methods
        if (rule.method == "cert" || rule.method == "peer" || rule.method == "pam" ||
            rule.method == "ident" || rule.method == "gss" || rule.method == "sspi") {
            add_issue(result, strict,
                      "HBA rule with method '" + rule.method +
                      "' has no ProxySQL equivalent");
            continue;
        }

        // hostssl -> mark users for SSL
        if (rule.conn_type == "hostssl") {
            std::string user_clause;
            if (rule.user != "all") {
                user_clause = " WHERE username='" + sql_escape(rule.user) + "'";
            }
            result.entries.push_back({
                "UPDATE pgsql_users SET use_ssl=1" + user_clause + ";",
                "HBA hostssl rule -> require SSL for " +
                (rule.user == "all" ? "all users" : "user '" + rule.user + "'")
            });
        }

        // Resolve address for firewall rule
        std::string addr = rule.address;
        if (addr.empty() || addr == "all") addr = "0.0.0.0/0";

        // reject -> whitelist deny (we still add to the whitelist table but the
        // absence from the whitelist effectively blocks access when whitelist mode
        // is enabled; we emit a comment explaining this)
        if (rule.method == "reject") {
            // The ProxySQL whitelist is allow-only and has no deny entry. An
            // HBA `reject` that precedes a broader allow rule therefore cannot
            // be reproduced: the allow would win. Surface it rather than
            // emitting a comment and implying the deny was handled.
            add_issue(result, strict,
                      "HBA 'reject' rule (" + rule.conn_type + " " + rule.database +
                      " " + rule.user + " " + addr + ") cannot be represented: "
                      "the ProxySQL firewall whitelist is allow-only, so this "
                      "denial must be reproduced manually or enforced upstream");
            continue;
        }

        // host / hostssl with md5, scram-sha-256, trust -> whitelist allow
        if (rule.method == "md5" || rule.method == "scram-sha-256" ||
            rule.method == "trust" || rule.method == "password") {

            std::string user_val = (rule.user == "all") ? "" : rule.user;
            std::string db_val = (rule.database == "all") ? "" : rule.database;

            std::string comment = "HBA allow: " + rule.conn_type + " " +
                                  rule.database + " " + rule.user + " " +
                                  addr + " " + rule.method;

            // The column is `database` (not `schemaname`), and both `digest`
            // and `comment` are NOT NULL without a default, so they must be
            // supplied explicitly. An empty digest whitelists every query for
            // the (user, address, database) triple, which is the closest
            // equivalent to an HBA allow rule.
            std::ostringstream sql;
            sql << "INSERT INTO pgsql_firewall_whitelist_rules "
                << "(active, client_address, username, database, flagIN, digest, comment) "
                << "VALUES (1, "
                << "'" << sql_escape(addr) << "', "
                << "'" << sql_escape(user_val) << "', "
                << "'" << sql_escape(db_val) << "', "
                << "0, '', "
                << "'" << sql_escape(comment) << "');";

            result.entries.push_back({sql.str(), comment});
            any_converted = true;
        }
    }

    if (any_converted) {
        result.entries.push_back({
            "SET pgsql-firewall_whitelist_enabled=1;",
            "Enable ProxySQL firewall whitelist (converted from PgBouncer HBA rules)"
        });
        result.variable_count++;
    }
}

// ---------------------------------------------------------------------------
// check_unmappable
// ---------------------------------------------------------------------------
void ConfigConverter::check_unmappable(const Config& config,
                                        ConversionResult& result, bool strict) {
    const auto& g = config.global;

    if (!g.auth_query.empty()) {
        add_issue(result, strict,
                  "auth_query has no ProxySQL equivalent; "
                  "ProxySQL authenticates from pgsql_users table or LDAP");
    }
    if (!g.auth_user.empty()) {
        add_issue(result, strict,
                  "auth_user has no ProxySQL equivalent; "
                  "configure authentication directly in pgsql_users");
    }
    if (!g.auth_dbname.empty()) {
        add_issue(result, strict,
                  "auth_dbname has no ProxySQL equivalent");
    }
    if (g.peer_id != 0) {
        add_issue(result, strict,
                  "peer_id has no ProxySQL equivalent; "
                  "ProxySQL uses its own clustering mechanism");
    }
    if (!config.peers.empty()) {
        add_issue(result, strict,
                  "[peers] section has no ProxySQL equivalent; "
                  "use ProxySQL Cluster instead");
    }
    if (g.so_reuseport) {
        add_issue(result, strict,
                  "so_reuseport has no ProxySQL equivalent");
    }
    if (g.disable_pqexec) {
        add_issue(result, strict,
                  "disable_pqexec has no ProxySQL equivalent");
    }
    if (g.application_name_add_host) {
        add_issue(result, strict,
                  "application_name_add_host has no ProxySQL equivalent");
    }
    if (g.dns_zone_check_period != 0) {
        add_issue(result, strict,
                  "dns_zone_check_period has no ProxySQL equivalent");
    }
    if (!g.resolv_conf.empty()) {
        add_issue(result, strict,
                  "resolv_conf has no ProxySQL equivalent; "
                  "ProxySQL uses system resolver");
    }
    if (g.server_reset_query != "DISCARD ALL" || g.server_reset_query_always) {
        add_issue(result, strict,
                  "server_reset_query has no ProxySQL equivalent; "
                  "ProxySQL handles connection reset internally");
    }
    if (g.sbuf_loopcnt != 5) {
        add_issue(result, strict,
                  "sbuf_loopcnt has no ProxySQL equivalent");
    }
    if (g.pkt_buf != 4096) {
        add_issue(result, strict,
                  "pkt_buf has no ProxySQL equivalent; "
                  "ProxySQL manages buffer sizes internally");
    }
    if (g.max_packet_size != 2147483647u) {
        add_issue(result, strict,
                  "max_packet_size has no ProxySQL equivalent");
    }
    if (g.query_wait_notify != 5) {
        add_issue(result, strict,
                  "query_wait_notify has no ProxySQL equivalent");
    }
    if (g.suspend_timeout != 10) {
        add_issue(result, strict,
                  "suspend_timeout has no ProxySQL equivalent; "
                  "ProxySQL does not support suspend/resume");
    }
}

// ---------------------------------------------------------------------------
// add_load_and_save
// ---------------------------------------------------------------------------
void ConfigConverter::add_load_and_save(ConversionResult& result) {
    // Load to runtime
    result.entries.push_back({
        "LOAD PGSQL SERVERS TO RUNTIME;",
        "Activate server configuration"
    });
    result.entries.push_back({
        "LOAD PGSQL USERS TO RUNTIME;",
        "Activate user configuration"
    });
    result.entries.push_back({
        "LOAD PGSQL QUERY RULES TO RUNTIME;",
        "Activate query rules"
    });
    result.entries.push_back({
        "LOAD PGSQL VARIABLES TO RUNTIME;",
        "Activate variable changes"
    });

    // Save to disk
    result.entries.push_back({
        "SAVE PGSQL SERVERS TO DISK;",
        "Persist server configuration"
    });
    result.entries.push_back({
        "SAVE PGSQL USERS TO DISK;",
        "Persist user configuration"
    });
    result.entries.push_back({
        "SAVE PGSQL QUERY RULES TO DISK;",
        "Persist query rules"
    });
    result.entries.push_back({
        "SAVE PGSQL VARIABLES TO DISK;",
        "Persist variable changes"
    });
}

// ---------------------------------------------------------------------------
// format_dry_run
// ---------------------------------------------------------------------------
std::string ConfigConverter::format_dry_run(const ConversionResult& result,
                                             const std::string& source_path,
                                             bool strict) {
    std::ostringstream out;

    // Header
    out << "-- ==========================================================================\n";
    out << "-- ProxySQL configuration converted from PgBouncer\n";
    out << "-- Source: " << source_path << "\n";
    out << "-- Mode:   " << (strict ? "strict" : "relaxed") << "\n";
    out << "-- ==========================================================================\n";
    out << "\n";

    // SQL entries with comments
    for (const auto& entry : result.entries) {
        if (!entry.comment.empty()) {
            out << "-- " << entry.comment << "\n";
        }
        out << entry.sql << "\n";
        out << "\n";
    }

    // Warnings
    if (!result.warnings.empty()) {
        out << "-- ==========================================================================\n";
        out << "-- WARNINGS (" << result.warnings.size() << ")\n";
        out << "-- ==========================================================================\n";
        for (const auto& w : result.warnings) {
            out << "-- WARNING: " << w.message << "\n";
        }
        out << "\n";
    }

    // Notes
    if (!result.notes.empty()) {
        out << "-- ==========================================================================\n";
        out << "-- NOTES (" << result.notes.size() << ")\n";
        out << "-- ==========================================================================\n";
        for (const auto& n : result.notes) {
            out << "-- NOTE: " << n.message << "\n";
        }
        out << "\n";
    }

    // Errors
    if (!result.errors.empty()) {
        out << "-- ==========================================================================\n";
        out << "-- ERRORS (" << result.errors.size() << ")\n";
        out << "-- ==========================================================================\n";
        for (const auto& e : result.errors) {
            out << "-- ERROR: " << e.message << "\n";
        }
        out << "\n";
    }

    // Summary footer
    out << "-- ==========================================================================\n";
    out << "-- Summary\n";
    out << "-- ==========================================================================\n";
    out << "-- Servers:   " << result.server_count << "\n";
    out << "-- Users:     " << result.user_count << "\n";
    out << "-- Rules:     " << result.rule_count << "\n";
    out << "-- Variables: " << result.variable_count << "\n";
    out << "-- Warnings:  " << result.warnings.size() << "\n";
    out << "-- Notes:     " << result.notes.size() << "\n";
    out << "-- Errors:    " << result.errors.size() << "\n";
    out << "-- Result:    " << (result.success ? "SUCCESS" : "FAILED") << "\n";
    out << "-- ==========================================================================\n";

    return out.str();
}

} // namespace PgBouncer
