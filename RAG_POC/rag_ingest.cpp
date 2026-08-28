/**
 * @file rag_ingest.cpp
 * @brief ProxySQL RAG (Retrieval-Augmented Generation) Ingestion Tool - MySQL Protocol Version
 *
 * @verbatim
 * ProxySQL RAG Ingestion PoC (General-Purpose) - MySQL Protocol Version
 * @endverbatim
 *
 * @section overview Overview
 *
 * This program is a general-purpose ingestion tool for ProxySQL's RAG index.
 * It reads data from external sources (currently MySQL), transforms it according
 * to configurable JSON specifications, chunks the content, builds full-text
 * search indexes, and optionally generates vector embeddings for semantic search.
 *
 * @section architecture Architecture
 *
 * Two-Port Design:
 *
 * <pre>
 *                     rag_ingest
 *                         |
 *         MySQL Protocol (mariadb client)
 *                         |
 *                         v
 *              +------------------------+
 *              | ProxySQL SQLite3 Server|  Port 6030 (default)
 *              |   (MySQL Protocol      |
 *              |    Gateway to SQLite)  |
 *              +------------------------+
 *                         |
 *                         | SQLite engine
 *                         v
 *              +------------------------+
 *              |   RAG Database         |
 *              |   - rag_* tables       |
 *              |   - FTS5 index         |
 *              |   - vec0 index         |
 *              +------------------------+
 *
 *              rag_sources table points to backend MySQL:
 *              - backend_host: 127.0.0.1 (default)
 *              - backend_port: 3306 (default)
 * </pre>
 *
 * @section v0_features v0 Features
 *
 * - Reads enabled sources from rag_sources table (via MySQL protocol to SQLite gateway)
 * - Connects to MySQL backend and fetches data using configurable SELECT queries
 * - Transforms rows using doc_map_json specification
 * - Chunks document bodies using configurable chunking parameters
 * - Inserts into rag_documents, rag_chunks, rag_fts_chunks (FTS5)
 * - Optionally generates embeddings and inserts into rag_vec_chunks (sqlite3-vec)
 * - Skips documents that already exist (no upsert in v0)
 * - Supports incremental sync using watermark-based cursor tracking
 *
 * @section dependencies Dependencies
 *
 * - mysqlclient / mariadb-client: For MySQL protocol connections
 * - libcurl: For HTTP-based embedding providers (OpenAI-compatible)
 * - nlohmann/json: Single-header JSON library (json.hpp)
 * - libcrypt: For sha256_crypt_r weak alias (platform compatibility)
 *
 * @section building Building
 *
 * @verbatim
 * g++ -std=c++17 -O2 rag_ingest.cpp -o rag_ingest \
 *     -lmysqlclient -lcurl -lcrypt
 * @endverbatim
 *
 * @section usage Usage
 *
 * @verbatim
 * # Initialize schema (SQLite Server via MySQL protocol gateway)
 * ./rag_ingest init --host=127.0.0.1 --port=6030 --user=root --password=root --database=rag_db
 *
 * # Run ingestion
 * ./rag_ingest ingest --host=127.0.0.1 --port=6030 --user=root --password=root --database=rag_db
 *
 * # Short options
 * ./rag_ingest init -h 127.0.0.1 -P 6030 -u root -p root -D rag_db
 * ./rag_ingest ingest -h 127.0.0.1 -P 6030 -u root -p root -D rag_db
 * @endverbatim
 *
 * @section ingestion_flow Ingestion Flow
 *
 * <pre>
 * 1. Connect to SQLite Server (via MySQL protocol on port 6030)
 * 2. Load enabled sources from rag_sources table
 * 3. For each source:
 *    a. Parse chunking_json and embedding_json configurations
 *    b. Load sync cursor (watermark) from rag_sync_state
 *    c. Connect to MySQL backend (configured in rag_sources)
 *    d. Build minimal SELECT query (only fetch needed columns)
 *    e. Add incremental filter based on watermark
 *    f. For each row:
 *       i. Build document using doc_map_json specification
 *       ii. Check if doc_id already exists (skip if yes)
 *       iii. Insert document into rag_documents
 *       iv. Chunk the document body
 *       v. For each chunk:
 *          - Insert into rag_chunks
 *          - Insert into rag_fts_chunks (FTS5)
 *          - If embedding enabled: generate and insert embedding
 *    g. Update sync cursor with max watermark value
 * 4. Commit transaction or rollback on error
 * </pre>
 *
 * @author ProxySQL Development Team
 * @version 0.2.0 (MySQL Protocol)
 * @date 2026
 */

#include "mysql.h"
#include "crypt.h"
#include "curl/curl.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <chrono>
#include <ctime>
#include <cctype>

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <set>
#include <getopt.h>

#include "json.hpp"
using json = nlohmann::json;

// ===========================================================================
// Logging Infrastructure
// ===========================================================================

/**
 * @brief Detailed logging system for rag_ingest with timestamp and log levels
 *
 * Log Levels:
 * - ERROR: Critical errors that prevent operation
 * - WARN:  Warning messages for non-critical issues
 * - INFO:  Informational messages about operation progress
 * - DEBUG: Detailed debugging information
 * - TRACE: Very fine-grained tracing (function entry/exit, etc.)
 */
enum class LogLevel {
    ERROR,
    WARN,
    INFO,
    DEBUG,
    TRACE
};

struct Logger {
    LogLevel min_level = LogLevel::INFO;
    bool use_colors = true;
    bool show_timestamp = true;
    bool show_level = true;

    // ANSI color codes
    static const char* color_reset()   { return "\033[0m"; }
    static const char* color_red()     { return "\033[31m"; }
    static const char* color_yellow()  { return "\033[33m"; }
    static const char* color_green()   { return "\033[32m"; }
    static const char* color_cyan()    { return "\033[36m"; }
    static const char* color_gray()    { return "\033[90m"; }

    static const char* level_string(LogLevel level) {
        switch (level) {
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::WARN:  return "WARN";
            case LogLevel::INFO:  return "INFO";
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::TRACE: return "TRACE";
        }
        return "UNKNOWN";
    }

    static const char* level_color(LogLevel level) {
        switch (level) {
            case LogLevel::ERROR: return color_red();
            case LogLevel::WARN:  return color_yellow();
            case LogLevel::INFO:  return color_green();
            case LogLevel::DEBUG: return color_cyan();
            case LogLevel::TRACE: return color_gray();
        }
        return color_reset();
    }

    bool should_log(LogLevel level) const {
        return level <= min_level;
    }

    void log(LogLevel level, const std::string& msg) {
        if (!should_log(level)) return;

        std::ostream& out = (level == LogLevel::ERROR || level == LogLevel::WARN) ? std::cerr : std::cout;

        if (use_colors) out << level_color(level);

        if (show_timestamp) {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            char time_buf[64];
            struct tm timeinfo;
            localtime_r(&time, &timeinfo);
            std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &timeinfo);
            out << "[" << time_buf << "] ";
        }

        if (show_level) {
            out << "[" << level_string(level) << "] ";
        }

        out << msg;

        if (use_colors) out << color_reset();

        out << "\n";
        out.flush();
    }

    void trace(const std::string& msg) { log(LogLevel::TRACE, msg); }
    void debug(const std::string& msg) { log(LogLevel::DEBUG, msg); }
    void info(const std::string& msg) { log(LogLevel::INFO, msg); }
    void warn(const std::string& msg) { log(LogLevel::WARN, msg); }
    void error(const std::string& msg) { log(LogLevel::ERROR, msg); }
};

// Global logger instance
static Logger g_logger;

// ===========================================================================
// Utility Functions
// ===========================================================================

static void fatal(const std::string& msg) {
    std::cerr << "FATAL: " << msg << "\n";
    std::exit(1);
}

// Helper: Convert float to hex string for SQLite BLOB (X'...')
// Handles endianness correctly for IEEE 754 float32
static std::string float_to_hex_blob(float f) {
    // Use memcpy for safe type-punning (avoids strict aliasing violation)
    uint32_t bits = 0;
    std::memcpy(&bits, &f, sizeof(float));

    // Format as little-endian hex (matches typical x86_64 architecture)
    char buf[16];
    snprintf(buf, sizeof(buf), "%02x%02x%02x%02x",
             static_cast<unsigned char>(bits & 0xFF),
             static_cast<unsigned char>((bits >> 8) & 0xFF),
             static_cast<unsigned char>((bits >> 16) & 0xFF),
             static_cast<unsigned char>((bits >> 24) & 0xFF));
    return std::string(buf);
}

// ===========================================================================
// MySQL Connection Wrapper
// ===========================================================================

/**
 * @brief MySQL connection wrapper for RAG database
 *
 * Wraps MYSQL* connection with RAII and helper methods.
 * The backend is SQLite, but accessed via MySQL protocol gateway.
 */
struct MySQLDB {
    MYSQL* conn = nullptr;

    // Default constructor
    MySQLDB() = default;

    // RAII: prevent copying
    MySQLDB(const MySQLDB&) = delete;
    MySQLDB& operator=(const MySQLDB&) = delete;

    // Allow moving
    MySQLDB(MySQLDB&& other) noexcept : conn(other.conn) {
        other.conn = nullptr;
    }

    MySQLDB& operator=(MySQLDB&& other) noexcept {
        if (this != &other) {
            if (conn) mysql_close(conn);
            conn = other.conn;
            other.conn = nullptr;
        }
        return *this;
    }

    ~MySQLDB() {
        if (conn) mysql_close(conn);
    }

    /**
     * @brief Verify connected server is ProxySQL SQLite3 Server
     *
     * Checks if the connected server is a SQLite Server by querying
     * sqlite_master table. If not, logs an error and exits.
     */
    void verify_sqlite_server() {
        g_logger.info("Verifying SQLite Server connection...");

        // Try to query sqlite_master - this will only work on SQLite Server
        const char* verify_sql = "SELECT name FROM sqlite_master LIMIT 1";
        g_logger.debug(std::string("Executing verification query: ") + verify_sql);

        if (mysql_query(conn, verify_sql) != 0) {
            g_logger.error("SQLite Server verification failed");

            std::cerr << "\n"
                      << "========================================\n"
                      << "ERROR: Not connected to SQLite Server!\n"
                      << "========================================\n"
                      << "\n"
                      << "rag_ingest writes RAG index data to ProxySQL SQLite3 Server.\n"
                      << "The server you connected to does not appear to be a SQLite Server.\n"
                      << "\n"
                      << "SQLite Server identification failed: sqlite_master table not found.\n"
                      << "\n"
                      << "Please ensure you are connecting to:\n"
                      << "  - ProxySQL SQLite3 Server (default port: 6030)\n"
                      << "  - NOT a regular MySQL/MariaDB server (port: 3306)\n"
                      << "\n"
                      << "Connection details:\n"
                      << "  - Host: " << mysql_get_host_info(conn) << "\n"
                      << "  - Server info: " << mysql_get_server_info(conn) << "\n"
                      << "========================================\n";
            std::exit(1);
        }

        // Free the result from the verification query
        MYSQL_RES* res = mysql_store_result(conn);
        if (res) {
            my_ulonglong rows = mysql_num_rows(res);
            g_logger.debug("SQLite Server verification: sqlite_master query returned " +
                          std::to_string(rows) + " row(s)");
            mysql_free_result(res);
        }

        g_logger.info("SQLite Server verification successful");
    }

    /**
     * @brief Connect to MySQL server
     * @param host Server hostname or IP
     * @param port Server port
     * @param user Username
     * @param pass Password
     * @param db Database name
     */
    void connect(const char* host, int port, const char* user,
                 const char* pass, const char* db) {
        g_logger.info("Connecting to SQLite Server (MySQL protocol gateway)...");
        g_logger.debug(std::string("Connection params: host=") + host +
                      ", port=" + std::to_string(port) +
                      ", user=" + user +
                      ", database=" + db);

        conn = mysql_init(nullptr);
        if (!conn) {
            g_logger.error("mysql_init failed: out of memory");
            fatal("mysql_init failed");
        }
        g_logger.trace("mysql_init successful");

        mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8mb4");
        g_logger.trace("Set charset to utf8mb4");

        if (!mysql_real_connect(conn, host, user, pass, db, port, nullptr, 0)) {
            g_logger.error(std::string("MySQL connect failed: ") + mysql_error(conn));
            fatal(std::string("MySQL connect failed: ") + mysql_error(conn));
        }

        g_logger.info("Connected to SQLite Server successfully");
        g_logger.debug(std::string("Server info: ") + mysql_get_server_info(conn));
        g_logger.debug(std::string("Host info: ") + mysql_get_host_info(conn));

        // Verify we're connected to SQLite Server
        verify_sqlite_server();
    }

    /**
     * @brief Execute a simple SQL statement
     * @param sql SQL statement to execute
     */
    void execute(const char* sql) {
        g_logger.trace(std::string("Executing SQL: ") + sql);
        if (mysql_query(conn, sql) != 0) {
            g_logger.error(std::string("MySQL error: ") + mysql_error(conn));
            g_logger.error(std::string("Failed SQL: ") + sql);
            std::cerr << "MySQL error: " << mysql_error(conn) << "\nSQL: " << sql << "\n";
            fatal("Query failed");
        }
        g_logger.trace("SQL executed successfully");
    }

    /**
     * @brief Execute SQL statement and return true on success, false on error
     * @param sql SQL statement to execute
     * @return true if successful, false otherwise
     */
    bool try_execute(const char* sql) {
        g_logger.trace(std::string("Trying SQL: ") + sql);
        if (mysql_query(conn, sql) != 0) {
            g_logger.debug(std::string("SQL failed (expected): ") + mysql_error(conn));
            return false;
        }
        g_logger.trace("SQL executed successfully");
        return true;
    }

    /**
     * @brief Execute query and return result
     * @param sql SQL query to execute
     * @return MYSQL_RES* Result set (caller must free with mysql_free_result)
     */
    MYSQL_RES* query(const char* sql) {
        g_logger.debug(std::string("Executing query: ") + sql);
        if (mysql_query(conn, sql) != 0) {
            g_logger.error(std::string("MySQL query failed: ") + mysql_error(conn));
            fatal(std::string("MySQL query failed: ") + mysql_error(conn) + "\nSQL: " + sql);
        }
        MYSQL_RES* res = mysql_store_result(conn);
        if (!res) {
            g_logger.error(std::string("mysql_store_result failed: ") + mysql_error(conn));
            fatal(std::string("mysql_store_result failed: ") + mysql_error(conn));
        }
        my_ulonglong rows = mysql_num_rows(res);
        g_logger.debug(std::string("Query returned ") + std::to_string(rows) + " row(s)");
        return res;
    }
};

// ===========================================================================
// Utility Functions
// ===========================================================================

static std::string str_or_empty(const char* p) {
    return p ? std::string(p) : std::string();
}

static bool is_integer_string(const std::string& s) {
    if (s.empty()) return false;
    size_t i = 0;
    if (s[0] == '-') {
        if (s.size() == 1) return false;
        i = 1;
    }
    for (; i < s.size(); i++) {
        if (s[i] < '0' || s[i] > '9') return false;
    }
    return true;
}

static std::string sql_escape_single_quotes(const std::string& s) {
    std::string out;
    out.reserve(s.size() * 2);  // Reserve more space for escapes
    for (char c : s) {
        if (c == '\'') {
            out.push_back('\'');  // Escape single quote as ''
            out.push_back('\'');
        } else if (c == '\\') {
            out.push_back('\\');  // Escape backslash as \\
            out.push_back('\\');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

#include <openssl/sha.h>

static std::string compute_content_hash(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    }
    return std::string(hex);
}

static std::string json_dump_compact(const json& j) {
    return j.dump();
}

// ===========================================================================
// Data Structures
// ===========================================================================

struct RagSource {
    int source_id = 0;
    std::string name;
    int enabled = 0;

    std::string backend_type;
    std::string host;
    int port = 3306;
    std::string user;
    std::string pass;
    std::string db;

    std::string table_name;
    std::string pk_column;
    std::string where_sql;

    json doc_map_json;
    json chunking_json;
    json embedding_json;
};

struct ChunkingConfig {
    bool enabled = true;
    std::string unit = "chars";
    int chunk_size = 4000;
    int overlap = 400;
    int min_chunk_size = 800;
};

struct EmbeddingConfig {
    bool enabled = false;
    int dim = 1536;
    std::string model = "unknown";
    json input_spec;
    std::string provider = "stub";
    std::string api_base;
    std::string api_key;
    int batch_size = 16;
    int timeout_ms = 20000;
};

struct SyncCursor {
    std::string column;
    bool has_value = false;
    bool numeric = false;
    std::int64_t num_value = 0;
    std::string str_value;
};

typedef std::unordered_map<std::string, std::string> RowMap;

struct PendingEmbedding {
    std::string chunk_id;
    std::string doc_id;
    int source_id;
    std::string input_text;
};

// ===========================================================================
// JSON Parsing Functions
// ===========================================================================

static ChunkingConfig parse_chunking_json(const json& j) {
    g_logger.trace("Parsing chunking_json configuration");
    ChunkingConfig cfg;
    if (!j.is_object()) {
        g_logger.debug("chunking_json is not an object, using defaults");
        return cfg;
    }

    if (j.contains("enabled")) cfg.enabled = j["enabled"].get<bool>();
    if (j.contains("unit")) cfg.unit = j["unit"].get<std::string>();
    if (j.contains("chunk_size")) cfg.chunk_size = j["chunk_size"].get<int>();
    if (j.contains("overlap")) cfg.overlap = j["overlap"].get<int>();
    if (j.contains("min_chunk_size")) cfg.min_chunk_size = j["min_chunk_size"].get<int>();

    // Validate and sanitize
    if (cfg.chunk_size <= 0) {
        g_logger.debug("chunk_size <= 0, using default 4000");
        cfg.chunk_size = 4000;
    }
    if (cfg.overlap < 0) {
        g_logger.debug("overlap < 0, setting to 0");
        cfg.overlap = 0;
    }
    if (cfg.overlap >= cfg.chunk_size) {
        g_logger.warn("overlap >= chunk_size, reducing to chunk_size/4");
        cfg.overlap = cfg.chunk_size / 4;
    }
    if (cfg.min_chunk_size < 0) {
        g_logger.debug("min_chunk_size < 0, setting to 0");
        cfg.min_chunk_size = 0;
    }

    if (cfg.unit != "chars") {
        g_logger.warn(std::string("chunking_json.unit=") + cfg.unit +
                     " not supported, falling back to 'chars'");
        cfg.unit = "chars";
    }

    g_logger.debug(std::string("Chunking config: enabled=") + (cfg.enabled ? "yes" : "no") +
                  ", unit=" + cfg.unit +
                  ", chunk_size=" + std::to_string(cfg.chunk_size) +
                  ", overlap=" + std::to_string(cfg.overlap) +
                  ", min_chunk_size=" + std::to_string(cfg.min_chunk_size));

    return cfg;
}

static EmbeddingConfig parse_embedding_json(const json& j) {
    g_logger.trace("Parsing embedding_json configuration");
    EmbeddingConfig cfg;
    if (!j.is_object()) {
        g_logger.debug("embedding_json is not an object, using defaults");
        return cfg;
    }

    if (j.contains("enabled")) cfg.enabled = j["enabled"].get<bool>();
    if (j.contains("dim")) cfg.dim = j["dim"].get<int>();
    if (j.contains("model")) cfg.model = j["model"].get<std::string>();
    if (j.contains("input")) cfg.input_spec = j["input"];
    if (j.contains("provider")) cfg.provider = j["provider"].get<std::string>();
    if (j.contains("api_base")) cfg.api_base = j["api_base"].get<std::string>();
    if (j.contains("api_key")) cfg.api_key = j["api_key"].get<std::string>();
    if (j.contains("batch_size")) cfg.batch_size = j["batch_size"].get<int>();
    if (j.contains("timeout_ms")) cfg.timeout_ms = j["timeout_ms"].get<int>();

    // Validate and sanitize
    if (cfg.dim <= 0) {
        g_logger.debug("dim <= 0, using default 1536");
        cfg.dim = 1536;
    }
    if (cfg.batch_size <= 0) {
        g_logger.debug("batch_size <= 0, using default 16");
        cfg.batch_size = 16;
    }
    if (cfg.timeout_ms <= 0) {
        g_logger.debug("timeout_ms <= 0, using default 20000");
        cfg.timeout_ms = 20000;
    }

    g_logger.debug(std::string("Embedding config: enabled=") + (cfg.enabled ? "yes" : "no") +
                  ", provider=" + cfg.provider +
                  ", model=" + cfg.model +
                  ", dim=" + std::to_string(cfg.dim) +
                  ", batch_size=" + std::to_string(cfg.batch_size) +
                  ", timeout_ms=" + std::to_string(cfg.timeout_ms));

    return cfg;
}

// ===========================================================================
// Row Access Helpers
// ===========================================================================

static std::optional<std::string> row_get(const RowMap& row, const std::string& key) {
    auto it = row.find(key);
    if (it == row.end()) return std::nullopt;
    return it->second;
}

// ===========================================================================
// Format String Template Engine
// ===========================================================================

static std::string apply_format(const std::string& fmt, const RowMap& row) {
    std::string out;
    out.reserve(fmt.size() + 32);

    for (size_t i = 0; i < fmt.size(); i++) {
        char c = fmt[i];
        if (c == '{') {
            size_t j = fmt.find('}', i + 1);
            if (j == std::string::npos) {
                out.push_back(c);
                continue;
            }
            std::string col = fmt.substr(i + 1, j - (i + 1));
            auto v = row_get(row, col);
            if (v.has_value()) out += v.value();
            i = j;
        } else {
            out.push_back(c);
        }
    }
    return out;
}

// ===========================================================================
// Concat Specification Evaluator
// ===========================================================================

static std::string eval_concat(const json& concat_spec,
                               const RowMap& row,
                               const std::string& chunk_body,
                               bool allow_chunk_body) {
    if (!concat_spec.is_array()) return "";

    std::string out;
    for (const auto& part : concat_spec) {
        if (!part.is_object()) continue;

        if (part.contains("col")) {
            std::string col = part["col"].get<std::string>();
            auto v = row_get(row, col);
            if (v.has_value()) out += v.value();
        } else if (part.contains("lit")) {
            out += part["lit"].get<std::string>();
        } else if (allow_chunk_body && part.contains("chunk_body")) {
            bool yes = part["chunk_body"].get<bool>();
            if (yes) out += chunk_body;
        }
    }
    return out;
}

// ===========================================================================
// Metadata Builder
// ===========================================================================

static json build_metadata(const json& meta_spec, const RowMap& row) {
    json meta = json::object();

    if (meta_spec.is_object()) {
        if (meta_spec.contains("pick") && meta_spec["pick"].is_array()) {
            for (const auto& colv : meta_spec["pick"]) {
                if (!colv.is_string()) continue;
                std::string col = colv.get<std::string>();
                auto v = row_get(row, col);
                if (v.has_value()) meta[col] = v.value();
            }
        }

        if (meta_spec.contains("rename") && meta_spec["rename"].is_object()) {
            std::vector<std::pair<std::string,std::string>> renames;
            for (auto it = meta_spec["rename"].begin(); it != meta_spec["rename"].end(); ++it) {
                if (!it.value().is_string()) continue;
                renames.push_back({it.key(), it.value().get<std::string>()});
            }
            for (size_t i = 0; i < renames.size(); i++) {
                const std::string& oldk = renames[i].first;
                const std::string& newk = renames[i].second;
                if (meta.contains(oldk)) {
                    meta[newk] = meta[oldk];
                    meta.erase(oldk);
                }
            }
        }
    }

    return meta;
}

// ===========================================================================
// Text Chunking
// ===========================================================================

static std::vector<std::string> chunk_text_chars(const std::string& text, const ChunkingConfig& cfg) {
    g_logger.trace(std::string("chunk_text_chars: text_size=") + std::to_string(text.size()) +
                  ", enabled=" + (cfg.enabled ? "yes" : "no") +
                  ", chunk_size=" + std::to_string(cfg.chunk_size));

    std::vector<std::string> chunks;

    if (!cfg.enabled) {
        g_logger.trace("Chunking disabled, using single chunk");
        chunks.push_back(text);
        return chunks;
    }

    if ((int)text.size() <= cfg.chunk_size) {
        g_logger.trace("Text size <= chunk_size, using single chunk");
        chunks.push_back(text);
        return chunks;
    }

    int step = cfg.chunk_size - cfg.overlap;
    if (step <= 0) {
        g_logger.debug("step <= 0, setting to chunk_size");
        step = cfg.chunk_size;
    }

    g_logger.debug(std::string("Chunking with step=") + std::to_string(step) +
                  ", expected_chunks=" + std::to_string((text.size() + step - 1) / step));

    for (int start = 0; start < (int)text.size(); start += step) {
        int end = start + cfg.chunk_size;
        if (end > (int)text.size()) end = (int)text.size();
        int len = end - start;
        if (len <= 0) break;

        if (len < cfg.min_chunk_size && !chunks.empty()) {
            g_logger.trace(std::string("Final chunk too small (") + std::to_string(len) +
                          " < " + std::to_string(cfg.min_chunk_size) + "), appending to previous");
            chunks.back() += text.substr(start, len);
            break;
        }

        chunks.push_back(text.substr(start, len));
        g_logger.trace(std::string("Created chunk ") + std::to_string(chunks.size()) +
                      ": start=" + std::to_string(start) +
                      ", len=" + std::to_string(len));

        if (end == (int)text.size()) break;
    }

    g_logger.debug(std::string("Created ") + std::to_string(chunks.size()) + " chunks");
    return chunks;
}

// ===========================================================================
// MySQL Backend Functions
// ===========================================================================

static MYSQL* mysql_connect_or_die(const RagSource& s) {
    g_logger.info(std::string("Connecting to backend MySQL: ") + s.host + ":" + std::to_string(s.port) +
                  ", db=" + s.db + ", user=" + s.user);
    g_logger.debug(std::string("Backend connection params: host=") + s.host +
                  ", port=" + std::to_string(s.port) +
                  ", user=" + s.user +
                  ", db=" + s.db);

    MYSQL* conn = mysql_init(nullptr);
    if (!conn) {
        g_logger.error("Backend mysql_init failed: out of memory");
        fatal("mysql_init failed");
    }

    mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8mb4");

    if (!mysql_real_connect(conn,
                            s.host.c_str(),
                            s.user.c_str(),
                            s.pass.c_str(),
                            s.db.c_str(),
                            s.port,
                            nullptr,
                            0)) {
        std::string err = mysql_error(conn);
        g_logger.error(std::string("Backend MySQL connect failed: ") + err);
        mysql_close(conn);
        fatal("MySQL connect failed: " + err);
    }

    g_logger.info("Connected to backend MySQL successfully");
    g_logger.debug(std::string("Backend server info: ") + mysql_get_server_info(conn));
    return conn;
}

static RowMap mysql_row_to_map(MYSQL_RES* res, MYSQL_ROW row) {
    RowMap m;
    unsigned int n = mysql_num_fields(res);
    MYSQL_FIELD* fields = mysql_fetch_fields(res);

    for (unsigned int i = 0; i < n; i++) {
        const char* name = fields[i].name;
        const char* val  = row[i];
        if (name) {
            m[name] = str_or_empty(val);
        }
    }
    return m;
}

// ===========================================================================
// Column Collection
// ===========================================================================

static void add_unique(std::vector<std::string>& cols, const std::string& c) {
    for (size_t i = 0; i < cols.size(); i++) {
        if (cols[i] == c) return;
    }
    cols.push_back(c);
}

static void collect_cols_from_concat(std::vector<std::string>& cols, const json& concat_spec) {
    if (!concat_spec.is_array()) return;
    for (const auto& part : concat_spec) {
        if (part.is_object() && part.contains("col") && part["col"].is_string()) {
            add_unique(cols, part["col"].get<std::string>());
        }
    }
}

static std::vector<std::string> collect_needed_columns(const RagSource& s, const EmbeddingConfig& ecfg) {
    std::vector<std::string> cols;
    add_unique(cols, s.pk_column);

    if (s.doc_map_json.contains("title") && s.doc_map_json["title"].contains("concat"))
        collect_cols_from_concat(cols, s.doc_map_json["title"]["concat"]);
    if (s.doc_map_json.contains("body") && s.doc_map_json["body"].contains("concat"))
        collect_cols_from_concat(cols, s.doc_map_json["body"]["concat"]);

    if (s.doc_map_json.contains("metadata") && s.doc_map_json["metadata"].contains("pick")) {
        const auto& pick = s.doc_map_json["metadata"]["pick"];
        if (pick.is_array()) {
            for (const auto& c : pick) if (c.is_string()) add_unique(cols, c.get<std::string>());
        }
    }

    if (ecfg.enabled && ecfg.input_spec.is_object() && ecfg.input_spec.contains("concat")) {
        collect_cols_from_concat(cols, ecfg.input_spec["concat"]);
    }

    return cols;
}

static std::string build_select_sql(const RagSource& s,
                                    const std::vector<std::string>& cols,
                                    const std::string& extra_filter) {
    std::string sql = "SELECT ";
    for (size_t i = 0; i < cols.size(); i++) {
        if (i) sql += ", ";
        sql += "`" + cols[i] + "`";
    }
    sql += " FROM `" + s.table_name + "`";
    if (!s.where_sql.empty() || !extra_filter.empty()) {
        sql += " WHERE ";
        if (!s.where_sql.empty()) {
            sql += "(" + s.where_sql + ")";
            if (!extra_filter.empty()) sql += " AND ";
        }
        if (!extra_filter.empty()) sql += "(" + extra_filter + ")";
    }
    return sql;
}

// ===========================================================================
// Sync Cursor (Watermark) Management
// ===========================================================================

static json load_sync_cursor_json(MySQLDB& db, int source_id) {
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT cursor_json FROM rag_sync_state WHERE source_id=%d", source_id);

    MYSQL_RES* res = db.query(sql);
    json out = json::object();

    MYSQL_ROW row = mysql_fetch_row(res);
    if (row && row[0]) {
        try {
            out = json::parse(row[0]);
        } catch (...) {
            out = json::object();
        }
    }

    mysql_free_result(res);
    if (!out.is_object()) out = json::object();
    return out;
}

static SyncCursor parse_sync_cursor(const json& cursor_json, const std::string& default_col) {
    SyncCursor c;
    c.column = default_col;
    if (cursor_json.is_object()) {
        if (cursor_json.contains("column") && cursor_json["column"].is_string()) {
            c.column = cursor_json["column"].get<std::string>();
        }
        if (cursor_json.contains("value")) {
            const auto& v = cursor_json["value"];
            if (v.is_number_integer()) {
                c.has_value = true;
                c.numeric = true;
                c.num_value = v.get<std::int64_t>();
            } else if (v.is_number_float()) {
                c.has_value = true;
                c.numeric = true;
                c.num_value = static_cast<std::int64_t>(v.get<double>());
            } else if (v.is_string()) {
                c.has_value = true;
                c.str_value = v.get<std::string>();
                if (is_integer_string(c.str_value)) {
                    c.numeric = true;
                    c.num_value = std::stoll(c.str_value);
                }
            }
        }
    }
    return c;
}

static std::string build_incremental_filter(const SyncCursor& c) {
    if (!c.has_value || c.column.empty()) return "";
    std::string col = "`" + c.column + "`";
    if (c.numeric) {
        return col + " > " + std::to_string(c.num_value);
    }
    return col + " > '" + sql_escape_single_quotes(c.str_value) + "'";
}

static void update_sync_state(MySQLDB& db, int source_id, const json& cursor_json) {
    std::string cursor_str = json_dump_compact(cursor_json);
    std::string escaped_cursor = sql_escape_single_quotes(cursor_str);

    // Use std::ostringstream to avoid fixed buffer size issues
    std::ostringstream sql;
    sql << "INSERT INTO rag_sync_state(source_id, mode, cursor_json, last_ok_at, last_error) "
        << "VALUES(" << source_id << ", 'poll', '" << escaped_cursor << "', unixepoch(), NULL) "
        << "ON CONFLICT(source_id) DO UPDATE SET "
        << "cursor_json='" << escaped_cursor << "', last_ok_at=unixepoch(), last_error=NULL";

    db.execute(sql.str().c_str());
}

// ===========================================================================
// Document Operations (via MySQL)
// ===========================================================================

static bool doc_exists(MySQLDB& db, const std::string& doc_id) {
    g_logger.trace(std::string("Checking if doc exists: ") + doc_id);
    std::string escaped_id = sql_escape_single_quotes(doc_id);
    std::ostringstream sql;
    sql << "SELECT 1 FROM rag_documents WHERE doc_id = '" << escaped_id << "' LIMIT 1";

    MYSQL_RES* res = db.query(sql.str().c_str());
    my_ulonglong rows = mysql_num_rows(res);
    mysql_free_result(res);

    g_logger.trace(std::string("doc_exists: ") + doc_id + " -> " + (rows > 0 ? "true" : "false"));
    return rows > 0;
}

static void insert_doc(MySQLDB& db,
                      int source_id,
                      const std::string& source_name,
                      const std::string& doc_id,
                      const std::string& pk_json,
                      const std::string& title,
                      const std::string& body,
                      const std::string& meta_json,
                      const std::string& content_hash) {
    g_logger.debug(std::string("Inserting document: ") + doc_id +
                  ", title_length=" + std::to_string(title.size()) +
                  ", body_length=" + std::to_string(body.size()));

    std::string e_doc_id = sql_escape_single_quotes(doc_id);
    std::string e_source_name = sql_escape_single_quotes(source_name);
    std::string e_pk_json = sql_escape_single_quotes(pk_json);
    std::string e_title = sql_escape_single_quotes(title);
    std::string e_body = sql_escape_single_quotes(body);
    std::string e_meta = sql_escape_single_quotes(meta_json);
    std::string e_hash = sql_escape_single_quotes(content_hash);

    std::ostringstream sql;
    sql << "INSERT INTO rag_documents(doc_id, source_id, source_name, pk_json, title, body, metadata_json, content_hash) "
        << "VALUES('" << e_doc_id << "', " << source_id << ", '" << e_source_name << "', '"
        << e_pk_json << "', '" << e_title << "', '" << e_body << "', '" << e_meta << "', '" << e_hash << "')";

    db.execute(sql.str().c_str());
    g_logger.trace("Document inserted successfully");
}

static void insert_chunk(MySQLDB& db,
                        const std::string& chunk_id,
                        const std::string& doc_id,
                        int source_id,
                        int chunk_index,
                        const std::string& title,
                        const std::string& body,
                        const std::string& meta_json) {
    g_logger.trace(std::string("Inserting chunk: ") + chunk_id +
                  ", chunk_index=" + std::to_string(chunk_index) +
                  ", body_length=" + std::to_string(body.size()));

    std::string e_chunk_id = sql_escape_single_quotes(chunk_id);
    std::string e_doc_id = sql_escape_single_quotes(doc_id);
    std::string e_title = sql_escape_single_quotes(title);
    std::string e_body = sql_escape_single_quotes(body);
    std::string e_meta = sql_escape_single_quotes(meta_json);

    // Use std::ostringstream to avoid fixed buffer size issues
    std::ostringstream sql;
    sql << "INSERT INTO rag_chunks(chunk_id, doc_id, source_id, chunk_index, title, body, metadata_json) "
        << "VALUES('" << e_chunk_id << "', '" << e_doc_id << "', " << source_id << ", " << chunk_index
        << ", '" << e_title << "', '" << e_body << "', '" << e_meta << "')";

    db.execute(sql.str().c_str());
}

static void insert_fts(MySQLDB& db,
                      const std::string& chunk_id,
                      const std::string& title,
                      const std::string& body) {
    g_logger.trace(std::string("Inserting FTS entry: ") + chunk_id);
    std::string e_chunk_id = sql_escape_single_quotes(chunk_id);
    std::string e_title = sql_escape_single_quotes(title);
    std::string e_body = sql_escape_single_quotes(body);

    // Use std::ostringstream to avoid fixed buffer size issues
    std::ostringstream sql;
    sql << "INSERT INTO rag_fts_chunks(chunk_id, title, body) "
        << "VALUES('" << e_chunk_id << "', '" << e_title << "', '" << e_body << "')";

    db.execute(sql.str().c_str());
}

// ===========================================================================
// Embedding Generation
// ===========================================================================

static std::vector<float> pseudo_embedding(const std::string& text, int dim) {
    std::vector<float> v;
    v.resize((size_t)dim, 0.0f);

    std::uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < text.size(); i++) {
        h ^= (unsigned char)text[i];
        h *= 1099511628211ULL;

        size_t idx = (size_t)(h % (std::uint64_t)dim);
        float val = (float)((h >> 32) & 0xFFFF) / 65535.0f;
        v[idx] += (val - 0.5f);
    }

    double norm = 0.0;
    for (int i = 0; i < dim; i++) norm += (double)v[(size_t)i] * (double)v[(size_t)i];
    norm = std::sqrt(norm);
    if (norm > 1e-12) {
        for (int i = 0; i < dim; i++) v[(size_t)i] = (float)(v[(size_t)i] / norm);
    }
    return v;
}

/**
 * @brief Abstract base class for embedding generation providers
 *
 * Embedding providers generate vector embeddings from text input.
 * This interface supports both stub (pseudo-embeddings for testing)
 * and real OpenAI-compatible API providers.
 *
 * @note The embed() method accepts multiple inputs for batch processing,
 *       which significantly reduces API calls for real providers.
 */
struct EmbeddingProvider {
    virtual ~EmbeddingProvider() = default;

    /**
     * @brief Generate embeddings for multiple text inputs
     * @param inputs Vector of text strings to embed
     * @param dim Expected output vector dimension
     * @return Vector of embedding vectors (one per input)
     *
     * @note This method should handle all inputs in a single batch for
     *       optimal performance with API-based providers.
     */
    virtual std::vector<std::vector<float>> embed(const std::vector<std::string>& inputs, int dim) = 0;
};

/**
 * @brief Stub embedding provider for testing without external API calls
 *
 * Generates deterministic pseudo-embeddings by hashing the input text.
 * Useful for testing embedding workflows without:
 * - Network dependencies
 * - API rate limits
 * - API costs
 *
 * The pseudo-embeddings are normalized and maintain consistent values
 * for the same input text.
 */
struct StubEmbeddingProvider : public EmbeddingProvider {
    std::vector<std::vector<float>> embed(const std::vector<std::string>& inputs, int dim) override {
        std::vector<std::vector<float>> out;
        out.reserve(inputs.size());
        for (const auto& s : inputs) out.push_back(pseudo_embedding(s, dim));
        return out;
    }
};

struct CurlBuffer {
    std::string data;
};

/**
 * @brief libcurl write callback for capturing HTTP response body
 */
static size_t curl_write_cb(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    CurlBuffer* buf = static_cast<CurlBuffer*>(userp);
    buf->data.append(static_cast<const char*>(contents), total);
    return total;
}

/**
 * @brief OpenAI-compatible API embedding provider
 *
 * Connects to OpenAI or OpenAI-compatible embedding services via HTTP.
 * Supports batch processing by sending multiple inputs in a single API request.
 *
 * Features:
 * - Configurable API endpoint (api_base)
 * - Bearer token authentication
 * - Request timeout configuration
 * - Batch processing (sends multiple texts in one request)
 * - Model and dimension parameters
 *
 * Compatible with:
 * - OpenAI API (api.openai.com/v1)
 * - Azure OpenAI
 * - Any OpenAI-compatible service (e.g., synthetic.new, local models)
 *
 * @note Batching significantly reduces API overhead. For example, with batch_size=16,
 *       100 chunks require only 7 API calls (16+16+16+16+16+16+4) instead of 100.
 */
struct OpenAIEmbeddingProvider : public EmbeddingProvider {
    std::string api_base;
    std::string api_key;
    std::string model;
    int timeout_ms = 20000;

    OpenAIEmbeddingProvider(std::string base, std::string key, std::string mdl, int timeout)
        : api_base(std::move(base)), api_key(std::move(key)), model(std::move(mdl)), timeout_ms(timeout) {}

    std::vector<std::vector<float>> embed(const std::vector<std::string>& inputs, int dim) override {
        g_logger.info(std::string("OpenAI embed: processing ") + std::to_string(inputs.size()) + " inputs");

        if (api_base.empty()) {
            g_logger.error("embedding api_base is empty");
            throw std::runtime_error("embedding api_base is empty");
        }
        if (api_key.empty()) {
            g_logger.error("embedding api_key is empty");
            throw std::runtime_error("embedding api_key is empty");
        }
        if (model.empty()) {
            g_logger.error("embedding model is empty");
            throw std::runtime_error("embedding model is empty");
        }

        json req;
        req["model"] = model;
        req["input"] = inputs;
        if (dim > 0) req["dimensions"] = dim;
        std::string body = req.dump();

        std::string url = api_base;
        if (!url.empty() && url.back() == '/') url.pop_back();
        url += "/embeddings";

        g_logger.debug(std::string("Calling OpenAI API: ") + url +
                      ", model=" + model +
                      ", inputs=" + std::to_string(inputs.size()) +
                      ", dim=" + std::to_string(dim));

        CURL* curl = curl_easy_init();
        if (!curl) throw std::runtime_error("curl_easy_init failed");

        CurlBuffer buf;
        struct curl_slist* headers = nullptr;
        std::string auth = "Authorization: Bearer " + api_key;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, auth.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);

        CURLcode res = curl_easy_perform(curl);
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            g_logger.error(std::string("curl error: ") + curl_easy_strerror(res));
            throw std::runtime_error(std::string("curl error: ") + curl_easy_strerror(res));
        }
        if (status < 200 || status >= 300) {
            g_logger.error(std::string("embedding request failed with status ") + std::to_string(status));
            throw std::runtime_error("embedding request failed with status " + std::to_string(status));
        }

        g_logger.debug(std::string("HTTP response status: ") + std::to_string(status) +
                      ", body_size=" + std::to_string(buf.data.size()));

        json resp = json::parse(buf.data);
        if (!resp.contains("data") || !resp["data"].is_array()) {
            g_logger.error("embedding response missing data array");
            throw std::runtime_error("embedding response missing data array");
        }

        std::vector<std::vector<float>> out;
        out.reserve(resp["data"].size());
        for (const auto& item : resp["data"]) {
            if (!item.contains("embedding") || !item["embedding"].is_array()) {
                g_logger.error("embedding item missing embedding array");
                throw std::runtime_error("embedding item missing embedding array");
            }
            std::vector<float> vec;
            vec.reserve(item["embedding"].size());
            for (const auto& v : item["embedding"]) vec.push_back(v.get<float>());
            if ((int)vec.size() != dim) {
                g_logger.error(std::string("embedding dimension mismatch: got ") +
                              std::to_string(vec.size()) + ", expected " + std::to_string(dim));
                throw std::runtime_error("embedding dimension mismatch");
            }
            out.push_back(std::move(vec));
        }

        if (out.size() != inputs.size()) {
            g_logger.error(std::string("embedding response size mismatch: got ") +
                          std::to_string(out.size()) + ", expected " + std::to_string(inputs.size()));
            throw std::runtime_error("embedding response size mismatch");
        }

        g_logger.info(std::string("OpenAI embed completed: ") + std::to_string(out.size()) + " embeddings generated");
        return out;
    }
};

static std::unique_ptr<EmbeddingProvider> build_embedding_provider(const EmbeddingConfig& cfg) {
    g_logger.debug(std::string("Building embedding provider: ") + cfg.provider);
    if (cfg.provider == "openai") {
        g_logger.debug(std::string("Using OpenAI provider: api_base=") + cfg.api_base +
                      ", model=" + cfg.model +
                      ", timeout_ms=" + std::to_string(cfg.timeout_ms));
        return std::make_unique<OpenAIEmbeddingProvider>(cfg.api_base, cfg.api_key, cfg.model, cfg.timeout_ms);
    }
    g_logger.debug("Using stub embedding provider");
    return std::make_unique<StubEmbeddingProvider>();
}

// ===========================================================================
// Source Loading
// ===========================================================================

static std::vector<RagSource> load_sources(MySQLDB& db) {
    g_logger.info("Loading enabled sources from rag_sources...");

    std::vector<RagSource> out;

    const char* sql =
        "SELECT source_id, name, enabled, "
        "backend_type, backend_host, backend_port, backend_user, backend_pass, backend_db, "
        "table_name, pk_column, COALESCE(where_sql,''), "
        "doc_map_json, chunking_json, COALESCE(embedding_json,'') "
        "FROM rag_sources WHERE enabled = 1";

    MYSQL_RES* res = db.query(sql);
    MYSQL_FIELD* fields = mysql_fetch_fields(res);

    MYSQL_ROW row;
    int source_count = 0;
    while ((row = mysql_fetch_row(res)) != nullptr) {
        RagSource s;
        s.source_id = atoi(row[0]);
        s.name      = str_or_empty(row[1]);
        s.enabled   = atoi(row[2]);

        s.backend_type = str_or_empty(row[3]);
        s.host         = str_or_empty(row[4]);
        s.port         = atoi(row[5]);
        s.user         = str_or_empty(row[6]);
        s.pass         = str_or_empty(row[7]);
        s.db           = str_or_empty(row[8]);

        s.table_name   = str_or_empty(row[9]);
        s.pk_column    = str_or_empty(row[10]);
        s.where_sql    = str_or_empty(row[11]);

        const char* doc_map = row[12];
        const char* chunk_j = row[13];
        const char* emb_j   = row[14];

        g_logger.debug(std::string("Loading source_id=") + std::to_string(s.source_id) +
                      ", name=" + s.name +
                      ", backend_type=" + s.backend_type +
                      ", table=" + s.db + "." + s.table_name);

        try {
            s.doc_map_json = json::parse(doc_map ? doc_map : "{}");
            s.chunking_json = json::parse(chunk_j ? chunk_j : "{}");
            if (emb_j && std::strlen(emb_j) > 0) s.embedding_json = json::parse(emb_j);
            else s.embedding_json = json();
        } catch (const std::exception& e) {
            g_logger.error(std::string("Invalid JSON in rag_sources.source_id=") +
                          std::to_string(s.source_id) + ": " + e.what());
            mysql_free_result(res);
            fatal("Invalid JSON in rag_sources.source_id=" + std::to_string(s.source_id) + ": " + e.what());
        }

        if (!s.doc_map_json.is_object()) {
            g_logger.error(std::string("doc_map_json must be a JSON object for source_id=") +
                          std::to_string(s.source_id));
            mysql_free_result(res);
            fatal("doc_map_json must be a JSON object for source_id=" + std::to_string(s.source_id));
        }
        if (!s.chunking_json.is_object()) {
            g_logger.error(std::string("chunking_json must be a JSON object for source_id=") +
                          std::to_string(s.source_id));
            mysql_free_result(res);
            fatal("chunking_json must be a JSON object for source_id=" + std::to_string(s.source_id));
        }

        out.push_back(std::move(s));
        source_count++;
    }

    mysql_free_result(res);
    g_logger.info(std::string("Loaded ") + std::to_string(source_count) + " enabled source(s)");
    return out;
}

// ===========================================================================
// Document Building
// ===========================================================================

struct BuiltDoc {
    std::string doc_id;
    std::string pk_json;
    std::string title;
    std::string body;
    std::string metadata_json;
};

static BuiltDoc build_document_from_row(const RagSource& src, const RowMap& row) {
    BuiltDoc d;

    if (src.doc_map_json.contains("doc_id") && src.doc_map_json["doc_id"].is_object()
        && src.doc_map_json["doc_id"].contains("format") && src.doc_map_json["doc_id"]["format"].is_string()) {
        d.doc_id = apply_format(src.doc_map_json["doc_id"]["format"].get<std::string>(), row);
    } else {
        auto pk = row_get(row, src.pk_column).value_or("");
        d.doc_id = src.table_name + ":" + pk;
    }

    json pk = json::object();
    pk[src.pk_column] = row_get(row, src.pk_column).value_or("");
    d.pk_json = json_dump_compact(pk);

    if (src.doc_map_json.contains("title") && src.doc_map_json["title"].is_object()
        && src.doc_map_json["title"].contains("concat")) {
        d.title = eval_concat(src.doc_map_json["title"]["concat"], row, "", false);
    } else {
        d.title = "";
    }

    if (src.doc_map_json.contains("body") && src.doc_map_json["body"].is_object()
        && src.doc_map_json["body"].contains("concat")) {
        d.body = eval_concat(src.doc_map_json["body"]["concat"], row, "", false);
    } else {
        d.body = "";
    }

    json meta = json::object();
    if (src.doc_map_json.contains("metadata")) {
        meta = build_metadata(src.doc_map_json["metadata"], row);
    }
    d.metadata_json = json_dump_compact(meta);

    return d;
}

// ===========================================================================
// Embedding Input Builder
// ===========================================================================

static std::string build_embedding_input(const EmbeddingConfig& ecfg,
                                         const RowMap& row,
                                         const std::string& chunk_body) {
    if (!ecfg.enabled) return "";
    if (!ecfg.input_spec.is_object()) return chunk_body;

    if (ecfg.input_spec.contains("concat") && ecfg.input_spec["concat"].is_array()) {
        return eval_concat(ecfg.input_spec["concat"], row, chunk_body, true);
    }

    return chunk_body;
}

// ===========================================================================
// Vector Insert (BLOB storage for SQLite backend)
// ===========================================================================

static void insert_vec(MySQLDB& db,
                      const std::vector<float>& emb,
                      const std::string& chunk_id,
                      const std::string& doc_id,
                      int source_id) {
    // Convert float vector to hex string for SQLite BLOB literal syntax X'...'
    std::string hex_blob;
    hex_blob.reserve(emb.size() * 8);
    for (float f : emb) {
        hex_blob += float_to_hex_blob(f);
    }

    std::string e_chunk_id = sql_escape_single_quotes(chunk_id);
    std::string e_doc_id = sql_escape_single_quotes(doc_id);

    // Use SQLite's X'' hex literal syntax - works through MySQL protocol gateway
    // Use stringstream to avoid fixed buffer size issues
    std::ostringstream sql;
    sql << "INSERT INTO rag_vec_chunks(embedding, chunk_id, doc_id, source_id, updated_at) "
        << "VALUES(X'" << hex_blob << "', '" << e_chunk_id << "', '" << e_doc_id
        << "', " << source_id << ", unixepoch())";

    db.execute(sql.str().c_str());
}

/**
 * @brief Process a batch of pending chunks for embedding generation
 *
 * This function implements bulk embedding generation by:
 * 1. Collecting input text from all pending chunks
 * 2. Calling the embedding provider once with all inputs
 * 3. Storing the resulting embeddings in rag_vec_chunks
 *
 * Batching significantly reduces API calls:
 * - Without batching: N chunks = N API calls
 * - With batching (batch_size=B): N chunks = ceil(N/B) API calls
 *
 * Example: 100 chunks with batch_size=16:
 * - Without batching: 100 API calls
 * - With batching: 7 API calls (16+16+16+16+16+16+4)
 *
 * @param pending Vector of pending chunks to embed
 * @param embedder Embedding provider (stub or OpenAI)
 * @param ecfg Embedding configuration (dimension, timeout, etc.)
 * @param db Database connection for storing results
 * @return Number of embeddings generated and stored
 *
 * @note Logs progress to stderr:
 *       - "Generating embeddings for batch of N chunks..."
 *       - "Calling OpenAI API: ... (model=X, chunks=N)" (OpenAI only)
 *       - "Successfully stored N embeddings"
 */
static size_t flush_embedding_batch(std::vector<PendingEmbedding>& pending,
                                    EmbeddingProvider* embedder,
                                    const EmbeddingConfig& ecfg,
                                    MySQLDB& db) {
    if (pending.empty()) return 0;

    g_logger.info(std::string("Generating embeddings for batch of ") + std::to_string(pending.size()) + " chunks...");

    g_logger.trace("Building input texts for embedding batch...");
    std::vector<std::string> inputs;
    inputs.reserve(pending.size());
    for (const auto& p : pending) {
        inputs.push_back(p.input_text);
    }

    g_logger.debug("Calling embedder for batch...");
    std::vector<std::vector<float>> embeddings = embedder->embed(inputs, ecfg.dim);

    g_logger.debug("Storing embeddings to rag_vec_chunks...");
    for (size_t i = 0; i < pending.size() && i < embeddings.size(); i++) {
        const auto& p = pending[i];
        g_logger.trace(std::string("Storing embedding for chunk_id=") + p.chunk_id);
        insert_vec(db, embeddings[i], p.chunk_id, p.doc_id, p.source_id);
    }

    size_t count = pending.size();
    pending.clear();
    g_logger.info(std::string("Successfully stored ") + std::to_string(count) + " embeddings");
    return count;
}

// ===========================================================================
// Source Ingestion
// ===========================================================================

static void ingest_source(MySQLDB& db, const RagSource& src) {
    g_logger.info(std::string("=== Starting ingestion for source_id=") + std::to_string(src.source_id) +
                  ", name=" + src.name +
                  ", backend=" + src.backend_type +
                  ", table=" + src.table_name + " ===");

    if (src.backend_type != "mysql") {
        g_logger.warn(std::string("Skipping source ") + src.name + ": backend_type '" + src.backend_type + "' not supported");
        return;
    }

    g_logger.debug("Parsing chunking and embedding configurations...");
    ChunkingConfig ccfg = parse_chunking_json(src.chunking_json);
    EmbeddingConfig ecfg = parse_embedding_json(src.embedding_json);

    std::unique_ptr<EmbeddingProvider> embedder;
    if (ecfg.enabled) {
        g_logger.info("Embeddings enabled, building embedding provider...");
        embedder = build_embedding_provider(ecfg);
    } else {
        g_logger.info("Embeddings disabled for this source");
    }

    g_logger.debug("Loading sync cursor (watermark)...");
    json cursor_json = load_sync_cursor_json(db, src.source_id);
    SyncCursor cursor = parse_sync_cursor(cursor_json, src.pk_column);

    if (cursor.has_value) {
        g_logger.info(std::string("Resuming from watermark: column=") + cursor.column +
                      (cursor.numeric ? ", value=" + std::to_string(cursor.num_value)
                                      : ", value=" + cursor.str_value));
    } else {
        g_logger.info("No previous watermark found, starting from beginning");
    }

    MYSQL* mdb = mysql_connect_or_die(src);

    g_logger.debug("Building SELECT query with incremental filter...");
    std::vector<std::string> cols = collect_needed_columns(src, ecfg);
    if (!cursor.column.empty()) add_unique(cols, cursor.column);
    std::string extra_filter = build_incremental_filter(cursor);
    std::string sel = build_select_sql(src, cols, extra_filter);

    g_logger.debug(std::string("Executing backend query:\n") + sel);

    if (mysql_query(mdb, sel.c_str()) != 0) {
        std::string err = mysql_error(mdb);
        g_logger.error(std::string("Backend MySQL query failed: ") + err);
        mysql_close(mdb);
        fatal("MySQL query failed: " + err + "\nSQL: " + sel);
    }

    MYSQL_RES* res = mysql_store_result(mdb);
    if (!res) {
        std::string err = mysql_error(mdb);
        g_logger.error(std::string("Backend mysql_store_result failed: ") + err);
        mysql_close(mdb);
        fatal("mysql_store_result failed: " + err);
    }

    my_ulonglong total_rows = mysql_num_rows(res);
    g_logger.info(std::string("Backend query returned ") + std::to_string(total_rows) + " row(s) to process");

    std::uint64_t ingested_docs = 0;
    std::uint64_t skipped_docs = 0;
    std::uint64_t updated_docs = 0;
    std::uint64_t total_chunks = 0;
    std::uint64_t embedding_batches = 0;
    std::vector<PendingEmbedding> pending_embeddings;
    std::set<std::string> seen_doc_ids;

    MYSQL_ROW r;
    bool max_set = false;
    bool max_numeric = false;
    std::int64_t max_num = 0;
    std::string max_str;

    while ((r = mysql_fetch_row(res)) != nullptr) {
        RowMap row = mysql_row_to_map(res, r);

        if (!cursor.column.empty()) {
            auto it = row.find(cursor.column);
            if (it != row.end()) {
                const std::string& v = it->second;
                if (!v.empty()) {
                    if (!max_set) {
                        if (cursor.numeric || is_integer_string(v)) {
                            try {
                                max_numeric = true;
                                max_num = std::stoll(v);
                            } catch (...) {
                                max_numeric = false;
                                max_str = v;
                            }
                        } else {
                            max_numeric = false;
                            max_str = v;
                        }
                        max_set = true;
                    } else if (max_numeric) {
                        if (is_integer_string(v)) {
                            try {
                                std::int64_t nv = std::stoll(v);
                                if (nv > max_num) max_num = nv;
                            } catch (...) {
                                max_numeric = false;
                                max_str = v;
                            }
                        }
                    } else {
                        if (v > max_str) max_str = v;
                    }
                }
            }
        }

        BuiltDoc doc = build_document_from_row(src, row);

        g_logger.trace(std::string("Processing doc_id=") + doc.doc_id);

        std::string content_input = doc.title + "|" + doc.body + "|" + doc.metadata_json;
        std::string content_hash = compute_content_hash(content_input);

        seen_doc_ids.insert(doc.doc_id);

        std::string existing_hash;
        bool doc_changed = false;
        {
            std::string escaped_id = sql_escape_single_quotes(doc.doc_id);
            std::ostringstream qsql;
            qsql << "SELECT content_hash FROM rag_documents WHERE doc_id = '" << escaped_id << "' AND deleted = 0 LIMIT 1";
            MYSQL_RES* qres = db.query(qsql.str().c_str());
            if (qres) {
                MYSQL_ROW qrow = mysql_fetch_row(qres);
                if (qrow && qrow[0]) {
                    existing_hash = qrow[0];
                }
                mysql_free_result(qres);
            }
        }

        if (!existing_hash.empty()) {
            if (existing_hash == content_hash) {
                g_logger.trace(std::string("Document unchanged: ") + doc.doc_id);
                skipped_docs++;
                continue;
            }
            doc_changed = true;
            g_logger.debug(std::string("Document changed: ") + doc.doc_id + " (hash mismatch)");

            std::string escaped_id = sql_escape_single_quotes(doc.doc_id);
            db.execute(("UPDATE rag_documents SET deleted = 1, updated_at = unixepoch() WHERE doc_id = '" + escaped_id + "'").c_str());
            db.execute(("DELETE FROM rag_chunks WHERE doc_id = '" + escaped_id + "'").c_str());
            db.execute(("DELETE FROM rag_fts_chunks WHERE chunk_id LIKE '" + escaped_id + "#%'").c_str());
            db.execute(("DELETE FROM rag_vec_chunks WHERE doc_id = '" + escaped_id + "'").c_str());
        } else {
            g_logger.debug(std::string("New document: ") + doc.doc_id);
        }

        insert_doc(db, src.source_id, src.name,
                   doc.doc_id, doc.pk_json, doc.title, doc.body, doc.metadata_json, content_hash);

        std::vector<std::string> chunks = chunk_text_chars(doc.body, ccfg);
        g_logger.debug(std::string("Created ") + std::to_string(chunks.size()) + " chunks for doc_id=" + doc.doc_id);
        total_chunks += chunks.size();

        for (size_t i = 0; i < chunks.size(); i++) {
            std::string chunk_id = doc.doc_id + "#" + std::to_string(i);

            json cmeta = json::object();
            cmeta["chunk_index"] = (int)i;

            std::string chunk_title = doc.title;

            insert_chunk(db, chunk_id, doc.doc_id, src.source_id, (int)i,
                        chunk_title, chunks[i], json_dump_compact(cmeta));

            insert_fts(db, chunk_id, chunk_title, chunks[i]);

            if (ecfg.enabled) {
                std::string emb_input = build_embedding_input(ecfg, row, chunks[i]);
                pending_embeddings.push_back({chunk_id, doc.doc_id, src.source_id, emb_input});

                if ((int)pending_embeddings.size() >= ecfg.batch_size) {
                    embedding_batches++;
                    flush_embedding_batch(pending_embeddings, embedder.get(), ecfg, db);
                }
            }
        }

        if (doc_changed) {
            updated_docs++;
        } else {
            ingested_docs++;
        }
        if ((ingested_docs + updated_docs) % 1000 == 0) {
            g_logger.info(std::string("Progress: ingested_docs=") + std::to_string(ingested_docs) +
                         ", updated_docs=" + std::to_string(updated_docs) +
                         ", skipped_docs=" + std::to_string(skipped_docs) +
                         ", chunks=" + std::to_string(total_chunks));
        }
    }

    if (ecfg.enabled && !pending_embeddings.empty()) {
        embedding_batches++;
        g_logger.debug("Flushing final pending embeddings batch...");
        flush_embedding_batch(pending_embeddings, embedder.get(), ecfg, db);
    }

    mysql_free_result(res);
    mysql_close(mdb);

    g_logger.info("Detecting removed documents...");
    {
        std::ostringstream qsql;
        qsql << "SELECT doc_id FROM rag_documents WHERE source_id = " << src.source_id << " AND deleted = 0";
        MYSQL_RES* dres = db.query(qsql.str().c_str());
        int soft_deleted = 0;
        if (dres) {
            MYSQL_ROW drow;
            while ((drow = mysql_fetch_row(dres)) != nullptr) {
                std::string existing_doc_id = drow[0] ? drow[0] : "";
                if (!existing_doc_id.empty() && seen_doc_ids.find(existing_doc_id) == seen_doc_ids.end()) {
                    g_logger.debug(std::string("Document removed from source: ") + existing_doc_id + " (soft deleting)");
                    std::string escaped_id = sql_escape_single_quotes(existing_doc_id);
                    db.execute(("UPDATE rag_documents SET deleted = 1, updated_at = unixepoch() WHERE doc_id = '" + escaped_id + "'").c_str());
                    db.execute(("DELETE FROM rag_chunks WHERE doc_id = '" + escaped_id + "'").c_str());
                    db.execute(("DELETE FROM rag_fts_chunks WHERE chunk_id LIKE '" + escaped_id + "#%'").c_str());
                    db.execute(("DELETE FROM rag_vec_chunks WHERE doc_id = '" + escaped_id + "'").c_str());
                    soft_deleted++;
                }
            }
            mysql_free_result(dres);
        }
        if (soft_deleted > 0) {
            g_logger.info(std::string("Soft-deleted ") + std::to_string(soft_deleted) +
                         " documents no longer in source '" + src.name + "'");
        }
    }

    g_logger.info("Updating sync state with new watermark...");
    if (!cursor_json.is_object()) cursor_json = json::object();
    if (!cursor.column.empty()) cursor_json["column"] = cursor.column;
    if (max_set) {
        if (max_numeric) {
            g_logger.debug(std::string("New watermark value (numeric): ") + std::to_string(max_num));
            cursor_json["value"] = max_num;
        } else {
            g_logger.debug(std::string("New watermark value (string): ") + max_str);
            cursor_json["value"] = max_str;
        }
    }
    update_sync_state(db, src.source_id, cursor_json);

    g_logger.info(std::string("=== Source ingestion complete: ") + src.name + " ===");
    g_logger.info(std::string("  ingested_docs=") + std::to_string(ingested_docs) +
                  ", updated_docs=" + std::to_string(updated_docs) +
                  ", skipped_docs=" + std::to_string(skipped_docs) +
                  ", total_chunks=" + std::to_string(total_chunks));
    if (ecfg.enabled) {
        g_logger.info(std::string("  embedding_batches=") + std::to_string(embedding_batches));
    }
}

// ===========================================================================
// Schema Initialization
// ===========================================================================

/**
 * @brief Check if a table exists in the database
 * @param db Database connection
 * @param table_name Name of the table to check
 * @return true if table exists, false otherwise
 */
static bool table_exists(MySQLDB& db, const std::string& table_name) {
    // Check connection validity
    if (!db.conn) {
        return false;
    }

    // Try to query the table - if it fails, table doesn't exist
    std::string escaped = sql_escape_single_quotes(table_name);
    std::ostringstream sql;
    sql << "SELECT COUNT(*) FROM `" << escaped << "` LIMIT 1";

    // Suppress error output for this check
    if (mysql_query(db.conn, sql.str().c_str()) != 0) {
        return false;  // Table doesn't exist
    }

    // Check for actual errors (like "table doesn't exist")
    unsigned int err = mysql_errno(db.conn);
    if (err != 0) {
        return false;  // Table doesn't exist
    }

    MYSQL_RES* res = mysql_store_result(db.conn);
    if (res) {
        mysql_free_result(res);
        return true;  // Table exists
    }
    return false;  // Table doesn't exist
}

/**
 * @brief Initialize RAG schema in the database
 * @param db Database connection
 * @param vec_dim Vector dimension for rag_vec_chunks table
 * @return true if schema was created, false if already exists
 */
static bool init_schema(MySQLDB& db, int vec_dim = 1536) {
    g_logger.info(std::string("Initializing RAG schema (vec_dim=") + std::to_string(vec_dim) + ")...");

    // Check if schema is complete by checking for rag_sync_state table
    // (rag_sync_state is created last, so if it exists, schema is complete)
    bool schema_complete = table_exists(db, "rag_sync_state");
    if (schema_complete) {
        g_logger.info("Schema already exists (rag_sync_state table found)");
        return false;
    }

    g_logger.debug("Creating rag_sources table...");
    // Note: PRAGMA commands are SQLite-specific and not supported through MySQL protocol
    // The SQLite backend should have these configured already

    // Create rag_sources table
    db.execute(
        "CREATE TABLE IF NOT EXISTS rag_sources ("
        "  source_id        INTEGER PRIMARY KEY,"
        "  name             TEXT NOT NULL UNIQUE,"
        "  enabled          INTEGER NOT NULL DEFAULT 1,"
        "  backend_type     TEXT NOT NULL,"
        "  backend_host     TEXT NOT NULL,"
        "  backend_port     INTEGER NOT NULL,"
        "  backend_user     TEXT NOT NULL,"
        "  backend_pass     TEXT NOT NULL,"
        "  backend_db       TEXT NOT NULL,"
        "  table_name       TEXT NOT NULL,"
        "  pk_column        TEXT NOT NULL,"
        "  where_sql        TEXT,"
        "  doc_map_json     TEXT NOT NULL,"
        "  chunking_json    TEXT NOT NULL,"
        "  embedding_json   TEXT,"
        "  created_at       INTEGER NOT NULL DEFAULT (unixepoch()),"
        "  updated_at       INTEGER NOT NULL DEFAULT (unixepoch())"
        ")"
    );

    db.execute("CREATE INDEX IF NOT EXISTS idx_rag_sources_enabled ON rag_sources(enabled)");
    db.execute("CREATE INDEX IF NOT EXISTS idx_rag_sources_backend ON rag_sources(backend_type, backend_host, backend_port, backend_db, table_name)");
    g_logger.trace("rag_sources table created");

    g_logger.debug("Creating rag_documents table...");
    // Create rag_documents table
    db.execute(
        "CREATE TABLE IF NOT EXISTS rag_documents ("
        "  doc_id         TEXT PRIMARY KEY,"
        "  source_id      INTEGER NOT NULL REFERENCES rag_sources(source_id),"
        "  source_name    TEXT NOT NULL,"
        "  pk_json        TEXT NOT NULL,"
        "  title          TEXT,"
        "  body           TEXT,"
        "  metadata_json  TEXT NOT NULL DEFAULT '{}',"
        "  content_hash   VARCHAR(64),"
        "  updated_at     INTEGER NOT NULL DEFAULT (unixepoch()),"
        "  deleted        INTEGER NOT NULL DEFAULT 0"
        ")"
    );

    db.execute("ALTER TABLE rag_documents ADD COLUMN content_hash VARCHAR(64)");

    db.execute("CREATE INDEX IF NOT EXISTS idx_rag_documents_source_updated ON rag_documents(source_id, updated_at)");
    db.execute("CREATE INDEX IF NOT EXISTS idx_rag_documents_source_deleted ON rag_documents(source_id, deleted)");
    g_logger.trace("rag_documents table created");

    g_logger.debug("Creating rag_chunks table...");
    // Create rag_chunks table
    db.execute(
        "CREATE TABLE IF NOT EXISTS rag_chunks ("
        "  chunk_id       TEXT PRIMARY KEY,"
        "  doc_id         TEXT NOT NULL REFERENCES rag_documents(doc_id),"
        "  source_id      INTEGER NOT NULL REFERENCES rag_sources(source_id),"
        "  chunk_index    INTEGER NOT NULL,"
        "  title          TEXT,"
        "  body           TEXT NOT NULL,"
        "  metadata_json  TEXT NOT NULL DEFAULT '{}',"
        "  updated_at     INTEGER NOT NULL DEFAULT (unixepoch()),"
        "  deleted        INTEGER NOT NULL DEFAULT 0"
        ")"
    );

    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_rag_chunks_doc_idx ON rag_chunks(doc_id, chunk_index)");
    db.execute("CREATE INDEX IF NOT EXISTS idx_rag_chunks_source_doc ON rag_chunks(source_id, doc_id)");
    db.execute("CREATE INDEX IF NOT EXISTS idx_rag_chunks_deleted ON rag_chunks(deleted)");
    g_logger.trace("rag_chunks table created");

    g_logger.debug("Creating rag_fts_chunks FTS5 virtual table...");
    // Create FTS5 virtual table
    db.execute(
        "CREATE VIRTUAL TABLE IF NOT EXISTS rag_fts_chunks "
        "USING fts5("
        "  chunk_id UNINDEXED,"
        "  title,"
        "  body,"
        "  tokenize = 'unicode61'"
        ")"
    );
    g_logger.trace("rag_fts_chunks FTS5 table created");

    // Create vec0 virtual table for embeddings
    // Note: This may fail if sqlite-vec extension is not loaded
    g_logger.debug(std::string("Creating rag_vec_chunks vec0 virtual table (dim=") + std::to_string(vec_dim) + ")...");
    std::ostringstream vec_sql;
    vec_sql << "CREATE VIRTUAL TABLE IF NOT EXISTS rag_vec_chunks "
            << "USING vec0("
            << "  embedding  float[" << vec_dim << "],"
            << "  chunk_id   TEXT,"
            << "  doc_id     TEXT,"
            << "  source_id  INTEGER,"
            << "  updated_at INTEGER"
            << ")";
    if (!db.try_execute(vec_sql.str().c_str())) {
        g_logger.warn("vec0 table creation failed (sqlite-vec extension not available). Vector embeddings will be disabled.");
    } else {
        g_logger.trace("rag_vec_chunks vec0 table created");
    }

    // Create convenience view
    g_logger.debug("Creating rag_chunk_view convenience view...");
    db.execute(
        "CREATE VIEW IF NOT EXISTS rag_chunk_view AS "
        "SELECT "
        "  c.chunk_id, "
        "  c.doc_id, "
        "  c.source_id, "
        "  d.source_name, "
        "  d.pk_json, "
        "  COALESCE(c.title, d.title) AS title, "
        "  c.body, "
        "  d.metadata_json AS doc_metadata_json, "
        "  c.metadata_json AS chunk_metadata_json, "
        "  c.updated_at "
        "FROM rag_chunks c "
        "JOIN rag_documents d ON d.doc_id = c.doc_id "
        "WHERE c.deleted = 0 AND d.deleted = 0"
    );
    g_logger.trace("rag_chunk_view created");

    // Create sync state table
    g_logger.debug("Creating rag_sync_state table...");
    db.execute(
        "CREATE TABLE IF NOT EXISTS rag_sync_state ("
        "  source_id     INTEGER PRIMARY KEY REFERENCES rag_sources(source_id),"
        "  mode          TEXT NOT NULL DEFAULT 'poll',"
        "  cursor_json   TEXT NOT NULL DEFAULT '{}',"
        "  last_ok_at    INTEGER,"
        "  last_error    TEXT"
        ")"
    );
    g_logger.trace("rag_sync_state table created");

    g_logger.info("RAG schema initialization complete");
    return !schema_complete;  // Return true if we created it, false if it was already complete
}

// ===========================================================================
// Main Entry Point
// ===========================================================================

/**
 * @brief Connection parameters
 */
struct ConnParams {
    std::string host = "127.0.0.1";
    int port = 6030;
    std::string user;
    std::string pass;
    std::string database;

    // Query-specific parameters
    std::string query_text;
    int source_id = -1;
    int limit = 5;

    // Init-specific parameters
    int vec_dim = 1536;  // Vector dimension for vec0 table

    // Logging parameters
    std::string log_level = "info";  // Log level: error, warn, info, debug, trace
};

/**
 * @brief Parse log level string to LogLevel enum
 * @param level_str Log level string (case-insensitive: error, warn, info, debug, trace)
 * @return Corresponding LogLevel enum value
 */
static LogLevel parse_log_level(const std::string& level_str) {
    std::string lower = level_str;
    for (char& c : lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    if (lower == "error") return LogLevel::ERROR;
    if (lower == "warn" || lower == "warning") return LogLevel::WARN;
    if (lower == "info") return LogLevel::INFO;
    if (lower == "debug") return LogLevel::DEBUG;
    if (lower == "trace") return LogLevel::TRACE;

    // Default to INFO if unknown
    return LogLevel::INFO;
}

static void print_usage(const char* prog_name) {
    std::cerr << "Usage:\n";
    std::cerr << "  Initialize schema:\n";
    std::cerr << "    " << prog_name << " init [OPTIONS]\n";
    std::cerr << "\n";
    std::cerr << "  Run ingestion:\n";
    std::cerr << "    " << prog_name << " ingest [OPTIONS]\n";
    std::cerr << "\n";
    std::cerr << "  Vector similarity search:\n";
    std::cerr << "    " << prog_name << " query --text=\"your query\" [OPTIONS]\n";
    std::cerr << "\n";
    std::cerr << "Common Options (SQLite Server via MySQL protocol gateway):\n";
    std::cerr << "  -h, --host=name     SQLite Server host (default: 127.0.0.1)\n";
    std::cerr << "  -P, --port=#        SQLite Server port - MySQL protocol gateway (default: 6030)\n";
    std::cerr << "  -u, --user=name     User for login\n";
    std::cerr << "  -p, --password=name  Password to use\n";
    std::cerr << "  -D, --database=name Database to use (required)\n";
    std::cerr << "  -?, --help          Show this help message\n";
    std::cerr << "\n";
    std::cerr << "Logging Options:\n";
    std::cerr << "  --log-level=LEVEL  Log level: error, warn, info, debug, trace (default: info)\n";
    std::cerr << "\n";
    std::cerr << "Init Options:\n";
    std::cerr << "  --vec-dim=#        Vector dimension for rag_vec_chunks table (default: 1536)\n";
    std::cerr << "\n";
    std::cerr << "Query Options:\n";
    std::cerr << "  -t, --text=text     Query text to search for (required for query)\n";
    std::cerr << "  -s, --source-id=#   Source ID to search (default: all enabled sources)\n";
    std::cerr << "  -l, --limit=#       Maximum results to return (default: 5)\n";
}

/**
 * @brief Parse connection parameters from command-line arguments
 * @param argc Argument count
 * @param argv Argument values
 * @param params Output connection parameters
 * @return Command name ("init", "ingest", or "query") or empty string on error
 */
static std::string parse_args(int argc, char** argv, ConnParams& params) {
    static struct option long_options[] = {
        {"host",      required_argument, 0, 'h'},
        {"port",      required_argument, 0, 'P'},
        {"user",      required_argument, 0, 'u'},
        {"password",  required_argument, 0, 'p'},
        {"database",  required_argument, 0, 'D'},
        {"text",      required_argument, 0, 't'},
        {"source-id", required_argument, 0, 's'},
        {"limit",     required_argument, 0, 'l'},
        {"vec-dim",   required_argument, 0, 1000},  // Using 1000 as short code
        {"log-level", required_argument, 0, 1001},  // Using 1001 as short code
        {"help",      no_argument,       0, '?'},
        {0, 0, 0, 0}
    };

    std::string command;
    int opt;
    int option_index = 0;

    // Parse command as first argument
    if (argc < 2) {
        return "";
    }

    command = argv[1];

    // Validate command
    if (command != "init" && command != "ingest" && command != "query") {
        return "";
    }

    // Shift argv for getopt so command is processed separately
    argc--;
    argv++;

    // Parse options using getopt_long
    while ((opt = getopt_long(argc, argv, "h:P:u:p:D:t:s:l:?", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                params.host = optarg;
                break;
            case 'P':
                params.port = std::atoi(optarg);
                break;
            case 'u':
                params.user = optarg;
                break;
            case 'p':
                params.pass = optarg;
                break;
            case 'D':
                params.database = optarg;
                break;
            case 't':
                params.query_text = optarg;
                break;
            case 's':
                params.source_id = std::atoi(optarg);
                break;
            case 'l':
                params.limit = std::atoi(optarg);
                break;
            case 1000:  // --vec-dim
                params.vec_dim = std::atoi(optarg);
                if (params.vec_dim <= 0) {
                    std::cerr << "Error: --vec-dim must be positive\n";
                    return "";
                }
                break;
            case 1001:  // --log-level
                params.log_level = optarg;
                break;
            case '?':
            default:
                return "";
        }
    }

    // Validate required parameters
    if (params.database.empty()) {
        std::cerr << "Error: Required parameter missing: --database is required\n";
        return "";
    }

    // For query command, query_text is required
    if (command == "query" && params.query_text.empty()) {
        std::cerr << "Error: --text is required for query command\n";
        return "";
    }

    return command;
}

int main(int argc, char** argv) {
    ConnParams params;
    std::string command = parse_args(argc, argv, params);

    if (command.empty()) {
        print_usage(argv[0]);
        return 2;
    }

    // Set log level from command line parameter
    g_logger.min_level = parse_log_level(params.log_level);

    g_logger.info("=== RAG Ingestion Tool Starting ===");

    g_logger.info(std::string("Command: ") + command);
    g_logger.info(std::string("Log level: ") + params.log_level);
    g_logger.debug(std::string("Connection params: host=") + params.host +
                  ", port=" + std::to_string(params.port) +
                  ", database=" + params.database);

    // Initialize command
    if (command == "init") {
        g_logger.info("Executing 'init' command...");
        MySQLDB db;
        db.connect(params.host.c_str(), params.port, params.user.c_str(),
                   params.pass.c_str(), params.database.c_str());

        bool created = init_schema(db, params.vec_dim);
        if (created) {
            g_logger.info("Schema created successfully");
            std::cout << "Schema created successfully (vec_dim=" << params.vec_dim << ").\n";
        } else {
            g_logger.info("Schema already exists");
            std::cout << "Schema already exists.\n";
        }

        g_logger.info("=== 'init' command complete ===");
        return 0;
    }

    // Ingest command
    if (command == "ingest") {
        g_logger.info("Executing 'ingest' command...");
        MySQLDB db;
        db.connect(params.host.c_str(), params.port, params.user.c_str(),
                   params.pass.c_str(), params.database.c_str());

        // Check if schema exists before proceeding
        if (!table_exists(db, "rag_sources")) {
            g_logger.error("RAG schema not found. Please run 'init' command first.");
            std::cerr << "Error: RAG schema not found. Please run 'init' command first:\n";
            std::cerr << "  " << argv[0] << " init -h " << params.host
                      << " -P " << params.port << " -u " << params.user
                      << " -p " << params.pass << " -D " << params.database << "\n";
            return 1;
        }

        g_logger.debug("Initializing libcurl...");
        curl_global_init(CURL_GLOBAL_DEFAULT);

        std::vector<RagSource> sources = load_sources(db);
        if (sources.empty()) {
            g_logger.warn("No enabled sources found in rag_sources");
            std::cerr << "No enabled sources found in rag_sources.\n";
        }

        // Per-source transaction handling
        int succeeded = 0;
        int failed = 0;

        for (size_t i = 0; i < sources.size(); i++) {
            g_logger.info(std::string("Processing source ") + std::to_string(i + 1) +
                          " of " + std::to_string(sources.size()));

            // Start transaction for this source
            g_logger.debug("Starting transaction for source " + std::to_string(sources[i].source_id) + "...");
            db.execute("BEGIN IMMEDIATE;");

            bool source_ok = true;
            try {
                ingest_source(db, sources[i]);
            } catch (const std::exception& e) {
                g_logger.error(std::string("Exception during source ingestion: ") + e.what());
                std::cerr << "Exception: " << e.what() << "\n";
                source_ok = false;
            } catch (...) {
                g_logger.error("Unknown exception during source ingestion");
                std::cerr << "Unknown exception\n";
                source_ok = false;
            }

            // Commit or rollback this source's transaction
            if (source_ok) {
                g_logger.info("Committing source " + std::to_string(sources[i].source_id) + "...");
                db.execute("COMMIT;");
                succeeded++;
            } else {
                g_logger.warn("Rolling back source " + std::to_string(sources[i].source_id) + " due to errors");
                db.execute("ROLLBACK;");
                failed++;
            }
        }

        g_logger.debug("Cleaning up libcurl...");
        curl_global_cleanup();

        g_logger.info(std::string("=== 'ingest' command complete ===") +
                     "\n  Succeeded: " + std::to_string(succeeded) +
                     "\n  Failed: " + std::to_string(failed));

        return (failed > 0) ? 1 : 0;
    }

    // Query command
    if (command == "query") {
        g_logger.info(std::string("Executing 'query' command: ") + params.query_text);
        MySQLDB db;
        db.connect(params.host.c_str(), params.port, params.user.c_str(),
                   params.pass.c_str(), params.database.c_str());

        // Check if schema exists
        if (!table_exists(db, "rag_sources")) {
            g_logger.error("RAG schema not found. Please run 'init' command first.");
            std::cerr << "Error: RAG schema not found. Please run 'init' command first:\n";
            std::cerr << "  " << argv[0] << " init -h " << params.host
                      << " -P " << params.port << " -u " << params.user
                      << " -p " << params.pass << " -D " << params.database << "\n";
            return 1;
        }

        g_logger.debug("Initializing libcurl...");
        curl_global_init(CURL_GLOBAL_DEFAULT);

        try {
            // Load sources
            std::vector<RagSource> sources = load_sources(db);

            // Filter by source_id if specified
            if (params.source_id >= 0) {
                g_logger.debug(std::string("Filtering by source_id=") + std::to_string(params.source_id));
                auto it = std::remove_if(sources.begin(), sources.end(),
                    [params](const RagSource& s) { return s.source_id != params.source_id; });
                sources.erase(it, sources.end());
            }

            if (sources.empty()) {
                g_logger.warn("No enabled sources found for query");
                std::cerr << "No enabled sources found";
                if (params.source_id >= 0) {
                    std::cerr << " for source_id=" << params.source_id;
                }
                std::cerr << ".\n";
                curl_global_cleanup();
                return 1;
            }

            // Use the first source's embedding config
            RagSource& source = sources[0];
            g_logger.debug(std::string("Using source_id=") + std::to_string(source.source_id) +
                          " for embedding config");

            if (source.embedding_json.empty()) {
                g_logger.error("Embeddings not configured for source");
                std::cerr << "Error: Embeddings not configured for source " << source.source_id << "\n";
                curl_global_cleanup();
                return 1;
            }

            EmbeddingConfig emb_cfg = parse_embedding_json(source.embedding_json);
            if (!emb_cfg.enabled) {
                g_logger.error("Embeddings not enabled for source");
                std::cerr << "Error: Embeddings not enabled for source " << source.source_id << "\n";
                curl_global_cleanup();
                return 1;
            }

            g_logger.info(std::string("Generating embedding for query using: ") + emb_cfg.provider);
            std::cout << "Generating embedding for query using: " << emb_cfg.provider << "\n";

            // Build embedding provider
            auto embedder = build_embedding_provider(emb_cfg);

            // Generate embedding for query
            g_logger.debug("Generating query embedding...");
            std::vector<std::string> query_inputs = {params.query_text};
            std::vector<std::vector<float>> query_embeddings = embedder->embed(query_inputs, emb_cfg.dim);

            if (query_embeddings.empty() || query_embeddings[0].empty()) {
                g_logger.error("Failed to generate embedding for query");
                std::cerr << "Error: Failed to generate embedding for query\n";
                curl_global_cleanup();
                return 1;
            }

            g_logger.info("Query embedding generated successfully");

            // Convert embedding to hex string for vec0 MATCH
            std::string query_hex;
            query_hex.reserve(query_embeddings[0].size() * 8);
            for (float f : query_embeddings[0]) {
                query_hex += float_to_hex_blob(f);
            }

            // Build search query
            // vec0 knn requires subquery approach: MATCH (SELECT ... LIMIT 1) AND k = ?
            std::string source_filter;
            if (params.source_id >= 0) {
                source_filter = "AND c.source_id = " + std::to_string(params.source_id);
            }

            g_logger.debug(std::string("Building vector search query, limit=") + std::to_string(params.limit));

            // Use subquery with VALUES to provide the query embedding
            // This creates a temporary single-row result with the query embedding
            std::string search_sql =
                "SELECT c.chunk_id, c.source_id, SUBSTR(c.body, 1, 200) as content, "
                "v.distance, d.title "
                "FROM rag_vec_chunks v "
                "JOIN rag_chunks c ON c.chunk_id = v.chunk_id "
                "JOIN rag_documents d ON d.doc_id = c.doc_id "
                "WHERE v.embedding MATCH ("
                "  SELECT X'" + query_hex + "' AS embedding"
                ") AND k = " + std::to_string(params.limit) + " "
                + source_filter + " "
                "ORDER BY v.distance";

            // Execute search
            g_logger.info("Executing vector search query...");
            MYSQL_RES* result = db.query(search_sql.c_str());
            if (result) {
                MYSQL_ROW row;
                int row_count = 0;
                while ((row = mysql_fetch_row(result))) {
                    std::cout << "\n--- Result " << (++row_count) << " ---\n";
                    unsigned long* lengths = mysql_fetch_lengths(result);
                    int field_count = mysql_num_fields(result);
                    for (int i = 0; i < field_count; i++) {
                        MYSQL_FIELD* field = mysql_fetch_field_direct(result, i);
                        if (row[i]) {
                            std::cout << field->name << ": " << row[i] << "\n";
                        }
                    }
                }
                mysql_free_result(result);

                g_logger.info(std::string("Vector search complete: ") + std::to_string(row_count) + " result(s)");
                if (row_count == 0) {
                    std::cout << "No results found.\n";
                } else {
                    std::cout << "\nFound " << row_count << " result(s).\n";
                }
            }

        } catch (const std::exception& e) {
            g_logger.error(std::string("Exception during query: ") + e.what());
            std::cerr << "Exception: " << e.what() << "\n";
            curl_global_cleanup();
            return 1;
        } catch (...) {
            g_logger.error("Unknown exception during query");
            std::cerr << "Unknown exception\n";
            curl_global_cleanup();
            return 1;
        }

        g_logger.debug("Cleaning up libcurl...");
        curl_global_cleanup();

        g_logger.info("=== 'query' command complete ===");
        return 0;
    }

    // Unknown command
    g_logger.error(std::string("Unknown command: ") + command);
    print_usage(argv[0]);
    return 2;
}
