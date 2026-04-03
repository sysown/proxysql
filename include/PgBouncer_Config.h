#ifndef PGBOUNCER_CONFIG_H
#define PGBOUNCER_CONFIG_H

#include <string>
#include <vector>
#include <map>

namespace PgBouncer {

struct ParseMessage {
    std::string file;
    int line = 0;
    std::string message;
};

struct GlobalSettings {
    // Listener
    std::string listen_addr;
    int listen_port = 6432;
    std::string unix_socket_dir;
    int listen_backlog = 128;
    std::string unix_socket_mode;
    std::string unix_socket_group;

    // Pooling
    std::string pool_mode = "session";
    int default_pool_size = 20;
    int min_pool_size = 0;
    int reserve_pool_size = 0;
    int reserve_pool_timeout = 5;
    bool server_round_robin = false;

    // Limits
    int max_client_conn = 100;
    int max_db_connections = 0;
    int max_db_client_connections = 0;
    int max_user_connections = 0;
    int max_user_client_connections = 0;

    // Authentication
    std::string auth_type = "md5";
    std::string auth_file;
    std::string auth_hba_file;
    std::string auth_ident_file;
    std::string auth_user;
    std::string auth_query;
    std::string auth_dbname;
    std::string auth_ldap_options;

    // Timeouts (in seconds)
    int server_lifetime = 3600;
    int server_idle_timeout = 600;
    int server_connect_timeout = 15;
    int server_login_retry = 15;
    int client_login_timeout = 60;
    int client_idle_timeout = 0;
    int query_timeout = 0;
    int query_wait_timeout = 120;
    int cancel_wait_timeout = 10;
    int idle_transaction_timeout = 0;
    int transaction_timeout = 0;
    int suspend_timeout = 10;
    int autodb_idle_timeout = 3600;

    // Server maintenance
    std::string server_reset_query = "DISCARD ALL";
    bool server_reset_query_always = false;
    std::string server_check_query;
    int server_check_delay = 30;
    bool server_fast_close = false;

    // TLS client-facing
    std::string client_tls_sslmode = "disable";
    std::string client_tls_key_file;
    std::string client_tls_cert_file;
    std::string client_tls_ca_file;
    std::string client_tls_protocols = "secure";
    std::string client_tls_ciphers;
    std::string client_tls13_ciphers;
    std::string client_tls_dheparams = "auto";
    std::string client_tls_ecdhcurve = "auto";

    // TLS server-facing
    std::string server_tls_sslmode = "prefer";
    std::string server_tls_key_file;
    std::string server_tls_cert_file;
    std::string server_tls_ca_file;
    std::string server_tls_protocols = "secure";
    std::string server_tls_ciphers;
    std::string server_tls13_ciphers;

    // Logging
    std::string logfile;
    bool syslog = false;
    std::string syslog_ident = "pgbouncer";
    std::string syslog_facility = "daemon";
    bool log_connections = true;
    bool log_disconnections = true;
    bool log_pooler_errors = true;
    bool log_stats = true;
    int stats_period = 60;
    int verbose = 0;

    // Admin
    std::string admin_users;
    std::string stats_users;

    // Networking
    bool so_reuseport = false;
    bool tcp_defer_accept = false;
    bool tcp_keepalive = true;
    int tcp_keepcnt = 0;
    int tcp_keepidle = 0;
    int tcp_keepintvl = 0;
    int tcp_socket_buffer = 0;
    int tcp_user_timeout = 0;

    // Protocol
    int max_prepared_statements = 200;
    bool disable_pqexec = false;
    bool application_name_add_host = false;
    std::string track_extra_parameters = "IntervalStyle";
    std::string ignore_startup_parameters;
    int scram_iterations = 4096;
    int pkt_buf = 4096;
    unsigned int max_packet_size = 2147483647;
    int sbuf_loopcnt = 5;
    int query_wait_notify = 5;

    // DNS
    int dns_max_ttl = 15;
    int dns_nxdomain_ttl = 15;
    int dns_zone_check_period = 0;
    std::string resolv_conf;

    // Process
    std::string pidfile;
    std::string user;
    int peer_id = 0;
};

struct Database {
    std::string name;              // entry name, or "*" for wildcard
    std::string host;              // comma-separated for multi-host
    int port = 5432;
    std::string dbname;            // destination database (empty = same as name)
    std::string user;              // forced user (empty = client user)
    std::string password;
    std::string auth_user;
    std::string auth_query;
    std::string auth_dbname;
    std::string pool_mode;         // per-db override, empty = use global
    int pool_size = -1;            // -1 = use default
    int min_pool_size = -1;
    int reserve_pool_size = -1;
    int max_db_connections = -1;
    int max_db_client_connections = -1;
    int server_lifetime = -1;
    std::string load_balance_hosts;
    std::string connect_query;
    std::string client_encoding;
    std::string datestyle;
    std::string timezone;
    std::string application_name;
};

struct User {
    std::string name;
    std::string pool_mode;
    int pool_size = -1;
    int reserve_pool_size = -1;
    int max_user_connections = -1;
    int max_user_client_connections = -1;
    int query_timeout = -1;
    int idle_transaction_timeout = -1;
    int transaction_timeout = -1;
    int client_idle_timeout = -1;
};

struct Peer {
    int peer_id = 0;
    std::string host;
    int port = 6432;
    int pool_size = -1;
};

enum class AuthType { PLAIN, MD5, SCRAM };

struct AuthFileEntry {
    std::string username;
    std::string password;
    AuthType type = AuthType::PLAIN;
};

struct HBARule {
    std::string conn_type;         // local, host, hostssl, hostnossl
    std::string database;          // all, sameuser, dbname, @file
    std::string user;              // all, username, @file
    std::string address;           // IP/CIDR or "all" (empty for local)
    std::string mask;              // optional separate mask
    std::string method;            // trust, reject, md5, scram-sha-256, etc.
    std::map<std::string, std::string> options;
};

struct Config {
    GlobalSettings global;
    std::vector<Database> databases;
    std::vector<User> users;
    std::vector<Peer> peers;
    std::vector<AuthFileEntry> auth_entries;
    std::vector<HBARule> hba_rules;
    std::vector<ParseMessage> errors;
    std::vector<ParseMessage> warnings;
};

// Parser functions
// Returns true on success, false on error (errors populated in config.errors)
bool parse_config_file(const std::string& filepath, Config& config);
bool parse_auth_file(const std::string& filepath, std::vector<AuthFileEntry>& entries, std::vector<ParseMessage>& errors);
bool parse_hba_file(const std::string& filepath, std::vector<HBARule>& rules, std::vector<ParseMessage>& errors);

} // namespace PgBouncer

#endif // PGBOUNCER_CONFIG_H
