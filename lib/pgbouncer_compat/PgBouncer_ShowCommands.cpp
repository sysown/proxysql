#include "PgBouncer_ShowCommands.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <vector>

namespace PgBouncer {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string to_upper(const std::string& s) {
    std::string r = s;
    for (size_t i = 0; i < r.size(); i++) {
        r[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(r[i])));
    }
    return r;
}

// Trim leading/trailing whitespace and trailing semicolons, collapse internal
// whitespace runs to a single space.
static std::string normalize(const char* query, int query_len) {
    std::string raw(query, static_cast<size_t>(query_len));

    // strip trailing whitespace and semicolons
    while (!raw.empty() && (std::isspace(static_cast<unsigned char>(raw.back())) || raw.back() == ';')) {
        raw.pop_back();
    }

    // collapse whitespace
    std::string out;
    out.reserve(raw.size());
    bool prev_space = true; // treat start as space to trim leading ws
    for (size_t i = 0; i < raw.size(); i++) {
        unsigned char c = static_cast<unsigned char>(raw[i]);
        if (std::isspace(c)) {
            if (!prev_space) {
                out.push_back(' ');
            }
            prev_space = true;
        } else {
            out.push_back(static_cast<char>(c));
            prev_space = false;
        }
    }
    // trim trailing space left by collapse
    if (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return out;
}

// Split a normalized string on spaces and return tokens in upper case.
static std::vector<std::string> tokenize_upper(const std::string& s) {
    std::vector<std::string> tokens;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) {
        tokens.push_back(to_upper(tok));
    }
    return tokens;
}

// ---------------------------------------------------------------------------
// Query generators
// ---------------------------------------------------------------------------

static std::string query_pools(bool extended) {
    std::string q =
        "SELECT "
        "'default' AS database, "
        "su.username AS user, "
        "0 AS cl_active, "
        "0 AS cl_waiting, "
        "0 AS cl_cancel_req, "
        "cp.ConnUsed AS sv_active, "
        "cp.ConnFree AS sv_idle, "
        "0 AS sv_used, "
        "0 AS sv_tested, "
        "0 AS sv_login, "
        "0 AS maxwait, "
        "0 AS maxwait_us, "
        "CASE WHEN su.fast_forward=1 THEN 'session' "
             "WHEN su.transaction_persistent=1 THEN 'transaction' "
             "ELSE 'statement' END AS pool_mode";
    if (extended) {
        q += ", cp.hostgroup AS hostgroup_id"
             ", cp.ConnUsed AS multiplex"
             ", cp.Latency_us AS latency_us"
             ", cp.Queries AS Queries"
             ", cp.Bytes_data_sent AS Bytes_data_sent"
             ", cp.Bytes_data_recv AS Bytes_data_recv";
    }
    q += " FROM stats_pgsql_connection_pool cp"
         " JOIN runtime_pgsql_users su ON 1=1"
         " GROUP BY su.username";
    return q;
}

static std::string query_stats(bool /*extended*/) {
    return
        "SELECT "
        "'default' AS database, "
        "SUM(count_star) AS total_xact_count, "
        "SUM(count_star) AS total_query_count, "
        "0 AS total_received, "
        "0 AS total_sent, "
        "SUM(sum_time) AS total_xact_time, "
        "SUM(sum_time) AS total_query_time, "
        "0 AS total_wait_time, "
        "0 AS avg_xact_count, "
        "0 AS avg_query_count, "
        "0 AS avg_recv, "
        "0 AS avg_sent, "
        "CASE WHEN SUM(count_star) > 0 THEN SUM(sum_time)/SUM(count_star) ELSE 0 END AS avg_xact_time, "
        "CASE WHEN SUM(count_star) > 0 THEN SUM(sum_time)/SUM(count_star) ELSE 0 END AS avg_query_time, "
        "0 AS avg_wait_time "
        "FROM stats_pgsql_query_digest";
}

static std::string query_servers(bool extended) {
    std::string q =
        "SELECT "
        "'S' AS type, "
        "'' AS user, "
        "'' AS database, "
        "CASE WHEN ConnUsed > 0 THEN 'active' ELSE 'idle' END AS state, "
        "srv_host AS addr, "
        "srv_port AS port, "
        "'' AS local_addr, "
        "0 AS local_port, "
        "'' AS connect_time, "
        "'' AS request_time, "
        "0 AS wait, "
        "0 AS wait_us, "
        "0 AS close_needed, "
        "'' AS ptr, "
        "'' AS link, "
        "0 AS remote_pid, "
        "'' AS tls, "
        "'' AS application_name, "
        "0 AS prepared_statements";
    if (extended) {
        q += ", hostgroup AS hostgroup"
             ", weight AS weight"
             ", status AS status"
             ", max_replication_lag AS max_replication_lag"
             ", Latency_us AS Latency_us"
             ", ConnUsed AS ConnUsed"
             ", ConnFree AS ConnFree"
             ", ConnOK AS ConnOK"
             ", ConnERR AS ConnERR";
    }
    q += " FROM stats_pgsql_connection_pool";
    return q;
}

static std::string query_clients(bool /*extended*/) {
    return
        "SELECT "
        "'C' AS type, "
        "user AS user, "
        "db AS database, "
        "CASE WHEN command = 'Sleep' THEN 'idle' ELSE 'active' END AS state, "
        "cli_host AS addr, "
        "cli_port AS port, "
        "'' AS local_addr, "
        "0 AS local_port, "
        "time_ms AS connect_time, "
        "time_ms AS request_time, "
        "0 AS wait, "
        "0 AS wait_us, "
        "0 AS close_needed, "
        "'' AS ptr, "
        "'' AS link, "
        "0 AS remote_pid, "
        "'' AS tls, "
        "extended_info AS application_name, "
        "0 AS prepared_statements "
        "FROM stats_pgsql_processlist";
}

static std::string query_databases(bool /*extended*/) {
    return
        "SELECT "
        "srv_host AS name, "
        "srv_host AS host, "
        "srv_port AS port, "
        "'' AS database, "
        "'' AS force_user, "
        "max_connections AS pool_size, "
        "0 AS min_pool_size, "
        "0 AS reserve_pool, "
        "'statement' AS pool_mode, "
        "max_connections AS max_connections, "
        "ConnUsed + ConnFree AS current_connections, "
        "0 AS paused, "
        "CASE WHEN status = 'ONLINE' THEN 0 ELSE 1 END AS disabled "
        "FROM stats_pgsql_connection_pool";
}

static std::string query_users(bool /*extended*/) {
    return
        "SELECT "
        "username AS name, "
        "CASE WHEN fast_forward=1 THEN 'session' "
             "WHEN transaction_persistent=1 THEN 'transaction' "
             "ELSE 'statement' END AS pool_mode "
        "FROM runtime_pgsql_users "
        "WHERE active=1 "
        "ORDER BY username";
}

static std::string query_config(bool /*extended*/) {
    return
        "SELECT "
        "REPLACE(variable_name, 'pgsql-', '') AS key, "
        "variable_value AS value, "
        "'' AS `default`, "
        "'yes' AS changeable "
        "FROM global_variables "
        "WHERE variable_name LIKE 'pgsql-%' "
        "ORDER BY variable_name";
}

static std::string query_version(bool /*extended*/) {
    return
        "SELECT 'ProxySQL ' || "
        "(SELECT variable_value FROM global_variables WHERE variable_name='admin-version') "
        "|| ' (PgBouncer compatibility mode)' AS version";
}

static std::string query_state(bool /*extended*/) {
    return "SELECT 'active' AS state";
}

static std::string query_lists(bool /*extended*/) {
    return
        "SELECT 'databases' AS list, COUNT(DISTINCT srv_host) AS items FROM stats_pgsql_connection_pool "
        "UNION ALL SELECT 'users', COUNT(*) FROM runtime_pgsql_users WHERE active=1 "
        "UNION ALL SELECT 'pools', COUNT(*) FROM stats_pgsql_connection_pool "
        "UNION ALL SELECT 'free_servers', SUM(ConnFree) FROM stats_pgsql_connection_pool "
        "UNION ALL SELECT 'used_servers', SUM(ConnUsed) FROM stats_pgsql_connection_pool";
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool translate_show_command(const char* query, int query_len,
                           std::string& out_query, bool& is_extended) {
    if (query == nullptr || query_len <= 0) {
        return false;
    }

    std::string norm = normalize(query, query_len);
    std::vector<std::string> tokens = tokenize_upper(norm);

    if (tokens.empty() || tokens[0] != "SHOW") {
        return false;
    }

    is_extended = false;
    size_t cmd_idx = 1;

    if (tokens.size() > 1 && tokens[1] == "EXTENDED") {
        is_extended = true;
        cmd_idx = 2;
    }

    if (cmd_idx >= tokens.size()) {
        return false;
    }

    const std::string& cmd = tokens[cmd_idx];

    if (cmd == "POOLS") {
        out_query = query_pools(is_extended);
    } else if (cmd == "STATS") {
        out_query = query_stats(is_extended);
    } else if (cmd == "SERVERS") {
        out_query = query_servers(is_extended);
    } else if (cmd == "CLIENTS") {
        out_query = query_clients(is_extended);
    } else if (cmd == "DATABASES") {
        out_query = query_databases(is_extended);
    } else if (cmd == "USERS") {
        out_query = query_users(is_extended);
    } else if (cmd == "CONFIG") {
        out_query = query_config(is_extended);
    } else if (cmd == "VERSION") {
        out_query = query_version(is_extended);
    } else if (cmd == "STATE") {
        out_query = query_state(is_extended);
    } else if (cmd == "LISTS") {
        out_query = query_lists(is_extended);
    } else {
        return false;
    }

    return true;
}

std::string get_unsupported_show_message(const char* query, int query_len) {
    if (query == nullptr || query_len <= 0) {
        return "";
    }

    std::string norm = normalize(query, query_len);
    std::vector<std::string> tokens = tokenize_upper(norm);

    if (tokens.empty() || tokens[0] != "SHOW") {
        return "";
    }

    size_t cmd_idx = 1;
    if (tokens.size() > 1 && tokens[1] == "EXTENDED") {
        cmd_idx = 2;
    }
    if (cmd_idx >= tokens.size()) {
        return "";
    }

    // Build the command name; handle two-word commands like DNS_HOSTS,
    // ACTIVE_SOCKETS, PEER_POOLS by joining remaining tokens with underscore.
    std::string cmd = tokens[cmd_idx];
    for (size_t i = cmd_idx + 1; i < tokens.size(); i++) {
        cmd += "_" + tokens[i];
    }

    if (cmd == "DNS_HOSTS") {
        return "SHOW DNS_HOSTS is not supported in ProxySQL PgBouncer compatibility mode";
    } else if (cmd == "DNS_ZONES") {
        return "SHOW DNS_ZONES is not supported in ProxySQL PgBouncer compatibility mode";
    } else if (cmd == "FDS") {
        return "SHOW FDS is not supported in ProxySQL PgBouncer compatibility mode";
    } else if (cmd == "PEERS") {
        return "SHOW PEERS is not supported in ProxySQL PgBouncer compatibility mode";
    } else if (cmd == "PEER_POOLS") {
        return "SHOW PEER_POOLS is not supported in ProxySQL PgBouncer compatibility mode";
    } else if (cmd == "MEM") {
        return "SHOW MEM is not supported in ProxySQL PgBouncer compatibility mode";
    } else if (cmd == "ACTIVE_SOCKETS") {
        return "SHOW ACTIVE_SOCKETS is not supported in ProxySQL PgBouncer compatibility mode";
    } else if (cmd == "SOCKETS") {
        return "SHOW SOCKETS is not supported in ProxySQL PgBouncer compatibility mode";
    }

    return "";
}

} // namespace PgBouncer
