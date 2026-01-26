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

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <getopt.h>

#include "json.hpp"
using json = nlohmann::json;

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
     * @brief Connect to MySQL server
     * @param host Server hostname or IP
     * @param port Server port
     * @param user Username
     * @param pass Password
     * @param db Database name
     */
    void connect(const char* host, int port, const char* user,
                 const char* pass, const char* db) {
        conn = mysql_init(nullptr);
        if (!conn) fatal("mysql_init failed");

        mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8mb4");

        if (!mysql_real_connect(conn, host, user, pass, db, port, nullptr, 0)) {
            fatal(std::string("MySQL connect failed: ") + mysql_error(conn));
        }
    }

    /**
     * @brief Execute a simple SQL statement
     * @param sql SQL statement to execute
     */
    void execute(const char* sql) {
        if (mysql_query(conn, sql) != 0) {
            std::cerr << "MySQL error: " << mysql_error(conn) << "\nSQL: " << sql << "\n";
            fatal("Query failed");
        }
    }

    /**
     * @brief Execute SQL statement and return true on success, false on error
     * @param sql SQL statement to execute
     * @return true if successful, false otherwise
     */
    bool try_execute(const char* sql) {
        if (mysql_query(conn, sql) != 0) {
            return false;
        }
        return true;
    }

    /**
     * @brief Execute query and return result
     * @param sql SQL query to execute
     * @return MYSQL_RES* Result set (caller must free with mysql_free_result)
     */
    MYSQL_RES* query(const char* sql) {
        if (mysql_query(conn, sql) != 0) {
            fatal(std::string("MySQL query failed: ") + mysql_error(conn) + "\nSQL: " + sql);
        }
        MYSQL_RES* res = mysql_store_result(conn);
        if (!res) {
            fatal(std::string("mysql_store_result failed: ") + mysql_error(conn));
        }
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
    ChunkingConfig cfg;
    if (!j.is_object()) return cfg;

    if (j.contains("enabled")) cfg.enabled = j["enabled"].get<bool>();
    if (j.contains("unit")) cfg.unit = j["unit"].get<std::string>();
    if (j.contains("chunk_size")) cfg.chunk_size = j["chunk_size"].get<int>();
    if (j.contains("overlap")) cfg.overlap = j["overlap"].get<int>();
    if (j.contains("min_chunk_size")) cfg.min_chunk_size = j["min_chunk_size"].get<int>();

    if (cfg.chunk_size <= 0) cfg.chunk_size = 4000;
    if (cfg.overlap < 0) cfg.overlap = 0;
    if (cfg.overlap >= cfg.chunk_size) cfg.overlap = cfg.chunk_size / 4;
    if (cfg.min_chunk_size < 0) cfg.min_chunk_size = 0;

    if (cfg.unit != "chars") {
        std::cerr << "WARN: chunking_json.unit=" << cfg.unit
                  << " not supported in v0. Falling back to chars.\n";
        cfg.unit = "chars";
    }

    return cfg;
}

static EmbeddingConfig parse_embedding_json(const json& j) {
    EmbeddingConfig cfg;
    if (!j.is_object()) return cfg;

    if (j.contains("enabled")) cfg.enabled = j["enabled"].get<bool>();
    if (j.contains("dim")) cfg.dim = j["dim"].get<int>();
    if (j.contains("model")) cfg.model = j["model"].get<std::string>();
    if (j.contains("input")) cfg.input_spec = j["input"];
    if (j.contains("provider")) cfg.provider = j["provider"].get<std::string>();
    if (j.contains("api_base")) cfg.api_base = j["api_base"].get<std::string>();
    if (j.contains("api_key")) cfg.api_key = j["api_key"].get<std::string>();
    if (j.contains("batch_size")) cfg.batch_size = j["batch_size"].get<int>();
    if (j.contains("timeout_ms")) cfg.timeout_ms = j["timeout_ms"].get<int>();

    if (cfg.dim <= 0) cfg.dim = 1536;
    if (cfg.batch_size <= 0) cfg.batch_size = 16;
    if (cfg.timeout_ms <= 0) cfg.timeout_ms = 20000;
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
    std::vector<std::string> chunks;

    if (!cfg.enabled) {
        chunks.push_back(text);
        return chunks;
    }

    if ((int)text.size() <= cfg.chunk_size) {
        chunks.push_back(text);
        return chunks;
    }

    int step = cfg.chunk_size - cfg.overlap;
    if (step <= 0) step = cfg.chunk_size;

    for (int start = 0; start < (int)text.size(); start += step) {
        int end = start + cfg.chunk_size;
        if (end > (int)text.size()) end = (int)text.size();
        int len = end - start;
        if (len <= 0) break;

        if (len < cfg.min_chunk_size && !chunks.empty()) {
            chunks.back() += text.substr(start, len);
            break;
        }

        chunks.push_back(text.substr(start, len));

        if (end == (int)text.size()) break;
    }

    return chunks;
}

// ===========================================================================
// MySQL Backend Functions
// ===========================================================================

static MYSQL* mysql_connect_or_die(const RagSource& s) {
    MYSQL* conn = mysql_init(nullptr);
    if (!conn) fatal("mysql_init failed");

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
        mysql_close(conn);
        fatal("MySQL connect failed: " + err);
    }
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
    std::string escaped_id = sql_escape_single_quotes(doc_id);
    std::ostringstream sql;
    sql << "SELECT 1 FROM rag_documents WHERE doc_id = '" << escaped_id << "' LIMIT 1";

    MYSQL_RES* res = db.query(sql.str().c_str());
    my_ulonglong rows = mysql_num_rows(res);
    mysql_free_result(res);

    return rows > 0;
}

static void insert_doc(MySQLDB& db,
                      int source_id,
                      const std::string& source_name,
                      const std::string& doc_id,
                      const std::string& pk_json,
                      const std::string& title,
                      const std::string& body,
                      const std::string& meta_json) {
    std::string e_doc_id = sql_escape_single_quotes(doc_id);
    std::string e_source_name = sql_escape_single_quotes(source_name);
    std::string e_pk_json = sql_escape_single_quotes(pk_json);
    std::string e_title = sql_escape_single_quotes(title);
    std::string e_body = sql_escape_single_quotes(body);
    std::string e_meta = sql_escape_single_quotes(meta_json);

    // Use std::ostringstream to avoid fixed buffer size issues
    std::ostringstream sql;
    sql << "INSERT INTO rag_documents(doc_id, source_id, source_name, pk_json, title, body, metadata_json) "
        << "VALUES('" << e_doc_id << "', " << source_id << ", '" << e_source_name << "', '"
        << e_pk_json << "', '" << e_title << "', '" << e_body << "', '" << e_meta << "')";

    db.execute(sql.str().c_str());
}

static void insert_chunk(MySQLDB& db,
                        const std::string& chunk_id,
                        const std::string& doc_id,
                        int source_id,
                        int chunk_index,
                        const std::string& title,
                        const std::string& body,
                        const std::string& meta_json) {
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

struct EmbeddingProvider {
    virtual ~EmbeddingProvider() = default;
    virtual std::vector<std::vector<float>> embed(const std::vector<std::string>& inputs, int dim) = 0;
};

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

static size_t curl_write_cb(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    CurlBuffer* buf = static_cast<CurlBuffer*>(userp);
    buf->data.append(static_cast<const char*>(contents), total);
    return total;
}

struct OpenAIEmbeddingProvider : public EmbeddingProvider {
    std::string api_base;
    std::string api_key;
    std::string model;
    int timeout_ms = 20000;

    OpenAIEmbeddingProvider(std::string base, std::string key, std::string mdl, int timeout)
        : api_base(std::move(base)), api_key(std::move(key)), model(std::move(mdl)), timeout_ms(timeout) {}

    std::vector<std::vector<float>> embed(const std::vector<std::string>& inputs, int dim) override {
        if (api_base.empty()) throw std::runtime_error("embedding api_base is empty");
        if (api_key.empty()) throw std::runtime_error("embedding api_key is empty");
        if (model.empty()) throw std::runtime_error("embedding model is empty");

        json req;
        req["model"] = model;
        req["input"] = inputs;
        if (dim > 0) req["dimensions"] = dim;
        std::string body = req.dump();

        std::string url = api_base;
        if (!url.empty() && url.back() == '/') url.pop_back();
        url += "/embeddings";

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

        if (res != CURLE_OK) throw std::runtime_error(std::string("curl error: ") + curl_easy_strerror(res));
        if (status < 200 || status >= 300) throw std::runtime_error("embedding request failed with status " + std::to_string(status));

        json resp = json::parse(buf.data);
        if (!resp.contains("data") || !resp["data"].is_array()) throw std::runtime_error("embedding response missing data array");

        std::vector<std::vector<float>> out;
        out.reserve(resp["data"].size());
        for (const auto& item : resp["data"]) {
            if (!item.contains("embedding") || !item["embedding"].is_array()) throw std::runtime_error("embedding item missing embedding array");
            std::vector<float> vec;
            vec.reserve(item["embedding"].size());
            for (const auto& v : item["embedding"]) vec.push_back(v.get<float>());
            if ((int)vec.size() != dim) throw std::runtime_error("embedding dimension mismatch");
            out.push_back(std::move(vec));
        }

        if (out.size() != inputs.size()) throw std::runtime_error("embedding response size mismatch");
        return out;
    }
};

static std::unique_ptr<EmbeddingProvider> build_embedding_provider(const EmbeddingConfig& cfg) {
    if (cfg.provider == "openai") {
        return std::make_unique<OpenAIEmbeddingProvider>(cfg.api_base, cfg.api_key, cfg.model, cfg.timeout_ms);
    }
    return std::make_unique<StubEmbeddingProvider>();
}

// ===========================================================================
// Source Loading
// ===========================================================================

static std::vector<RagSource> load_sources(MySQLDB& db) {
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

        try {
            s.doc_map_json = json::parse(doc_map ? doc_map : "{}");
            s.chunking_json = json::parse(chunk_j ? chunk_j : "{}");
            if (emb_j && std::strlen(emb_j) > 0) s.embedding_json = json::parse(emb_j);
            else s.embedding_json = json();
        } catch (const std::exception& e) {
            mysql_free_result(res);
            fatal("Invalid JSON in rag_sources.source_id=" + std::to_string(s.source_id) + ": " + e.what());
        }

        if (!s.doc_map_json.is_object()) {
            mysql_free_result(res);
            fatal("doc_map_json must be a JSON object for source_id=" + std::to_string(s.source_id));
        }
        if (!s.chunking_json.is_object()) {
            mysql_free_result(res);
            fatal("chunking_json must be a JSON object for source_id=" + std::to_string(s.source_id));
        }

        out.push_back(std::move(s));
    }

    mysql_free_result(res);
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

static size_t flush_embedding_batch(std::vector<PendingEmbedding>& pending,
                                    EmbeddingProvider* embedder,
                                    const EmbeddingConfig& ecfg,
                                    MySQLDB& db) {
    if (pending.empty()) return 0;

    std::vector<std::string> inputs;
    inputs.reserve(pending.size());
    for (const auto& p : pending) {
        inputs.push_back(p.input_text);
    }

    std::vector<std::vector<float>> embeddings = embedder->embed(inputs, ecfg.dim);

    for (size_t i = 0; i < pending.size() && i < embeddings.size(); i++) {
        const auto& p = pending[i];
        insert_vec(db, embeddings[i], p.chunk_id, p.doc_id, p.source_id);
    }

    size_t count = pending.size();
    pending.clear();
    return count;
}

// ===========================================================================
// Source Ingestion
// ===========================================================================

static void ingest_source(MySQLDB& db, const RagSource& src) {
    std::cerr << "Ingesting source_id=" << src.source_id
              << " name=" << src.name
              << " backend=" << src.backend_type
              << " table=" << src.table_name << "\n";

    if (src.backend_type != "mysql") {
        std::cerr << "  Skipping: backend_type not supported in v0.\n";
        return;
    }

    ChunkingConfig ccfg = parse_chunking_json(src.chunking_json);
    EmbeddingConfig ecfg = parse_embedding_json(src.embedding_json);
    std::unique_ptr<EmbeddingProvider> embedder;
    if (ecfg.enabled) {
        embedder = build_embedding_provider(ecfg);
    }

    json cursor_json = load_sync_cursor_json(db, src.source_id);
    SyncCursor cursor = parse_sync_cursor(cursor_json, src.pk_column);

    MYSQL* mdb = mysql_connect_or_die(src);

    std::vector<std::string> cols = collect_needed_columns(src, ecfg);
    if (!cursor.column.empty()) add_unique(cols, cursor.column);
    std::string extra_filter = build_incremental_filter(cursor);
    std::string sel = build_select_sql(src, cols, extra_filter);

    if (mysql_query(mdb, sel.c_str()) != 0) {
        std::string err = mysql_error(mdb);
        mysql_close(mdb);
        fatal("MySQL query failed: " + err + "\nSQL: " + sel);
    }

    MYSQL_RES* res = mysql_store_result(mdb);
    if (!res) {
        std::string err = mysql_error(mdb);
        mysql_close(mdb);
        fatal("mysql_store_result failed: " + err);
    }

    std::uint64_t ingested_docs = 0;
    std::uint64_t skipped_docs = 0;
    std::vector<PendingEmbedding> pending_embeddings;

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

        if (doc_exists(db, doc.doc_id)) {
            skipped_docs++;
            continue;
        }

        insert_doc(db, src.source_id, src.name,
                   doc.doc_id, doc.pk_json, doc.title, doc.body, doc.metadata_json);

        std::vector<std::string> chunks = chunk_text_chars(doc.body, ccfg);

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
                    flush_embedding_batch(pending_embeddings, embedder.get(), ecfg, db);
                }
            }
        }

        ingested_docs++;
        if (ingested_docs % 1000 == 0) {
            std::cerr << "  progress: ingested_docs=" << ingested_docs
                      << " skipped_docs=" << skipped_docs << "\n";
        }
    }

    if (ecfg.enabled && !pending_embeddings.empty()) {
        flush_embedding_batch(pending_embeddings, embedder.get(), ecfg, db);
    }

    mysql_free_result(res);
    mysql_close(mdb);

    if (!cursor_json.is_object()) cursor_json = json::object();
    if (!cursor.column.empty()) cursor_json["column"] = cursor.column;
    if (max_set) {
        if (max_numeric) {
            cursor_json["value"] = max_num;
        } else {
            cursor_json["value"] = max_str;
        }
    }
    update_sync_state(db, src.source_id, cursor_json);

    std::cerr << "Done source " << src.name
              << " ingested_docs=" << ingested_docs
              << " skipped_docs=" << skipped_docs << "\n";
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
    // Check if schema is complete by checking for rag_sync_state table
    // (rag_sync_state is created last, so if it exists, schema is complete)
    bool schema_complete = table_exists(db, "rag_sync_state");

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
        "  updated_at     INTEGER NOT NULL DEFAULT (unixepoch()),"
        "  deleted        INTEGER NOT NULL DEFAULT 0"
        ")"
    );

    db.execute("CREATE INDEX IF NOT EXISTS idx_rag_documents_source_updated ON rag_documents(source_id, updated_at)");
    db.execute("CREATE INDEX IF NOT EXISTS idx_rag_documents_source_deleted ON rag_documents(source_id, deleted)");

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

    // Create vec0 virtual table for embeddings
    // Note: This may fail if sqlite-vec extension is not loaded
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
        std::cerr << "Warning: vec0 table creation failed (sqlite-vec extension not available). Vector embeddings will be disabled.\n";
    }

    // Create convenience view
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

    // Create sync state table
    db.execute(
        "CREATE TABLE IF NOT EXISTS rag_sync_state ("
        "  source_id     INTEGER PRIMARY KEY REFERENCES rag_sources(source_id),"
        "  mode          TEXT NOT NULL DEFAULT 'poll',"
        "  cursor_json   TEXT NOT NULL DEFAULT '{}',"
        "  last_ok_at    INTEGER,"
        "  last_error    TEXT"
        ")"
    );

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
};

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
        {"host",     required_argument, 0, 'h'},
        {"port",     required_argument, 0, 'P'},
        {"user",     required_argument, 0, 'u'},
        {"password", required_argument, 0, 'p'},
        {"database", required_argument, 0, 'D'},
        {"text",     required_argument, 0, 't'},
        {"source-id",required_argument, 0, 's'},
        {"limit",    required_argument, 0, 'l'},
        {"vec-dim",  required_argument, 0, 1000},  // Using 1000 as short code
        {"help",     no_argument,       0, '?'},
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

    // Initialize command
    if (command == "init") {
        MySQLDB db;
        db.connect(params.host.c_str(), params.port, params.user.c_str(),
                   params.pass.c_str(), params.database.c_str());

        bool created = init_schema(db, params.vec_dim);
        if (created) {
            std::cout << "Schema created successfully (vec_dim=" << params.vec_dim << ").\n";
        } else {
            std::cout << "Schema already exists.\n";
        }

        return 0;
    }

    // Ingest command
    if (command == "ingest") {
        MySQLDB db;
        db.connect(params.host.c_str(), params.port, params.user.c_str(),
                   params.pass.c_str(), params.database.c_str());

        // Check if schema exists before proceeding
        if (!table_exists(db, "rag_sources")) {
            std::cerr << "Error: RAG schema not found. Please run 'init' command first:\n";
            std::cerr << "  " << argv[0] << " init -h " << params.host
                      << " -P " << params.port << " -u " << params.user
                      << " -p " << params.pass << " -D " << params.database << "\n";
            return 1;
        }

        curl_global_init(CURL_GLOBAL_DEFAULT);

        // Note: PRAGMA commands are SQLite-specific and not supported through MySQL protocol
        // The SQLite backend should have these configured already
        db.execute("BEGIN IMMEDIATE;");

        bool ok = true;
        try {
            std::vector<RagSource> sources = load_sources(db);
            if (sources.empty()) {
                std::cerr << "No enabled sources found in rag_sources.\n";
            }
            for (size_t i = 0; i < sources.size(); i++) {
                ingest_source(db, sources[i]);
            }
        } catch (const std::exception& e) {
            std::cerr << "Exception: " << e.what() << "\n";
            ok = false;
        } catch (...) {
            std::cerr << "Unknown exception\n";
            ok = false;
        }

        db.execute(ok ? "COMMIT;" : "ROLLBACK;");
        curl_global_cleanup();
        return ok ? 0 : 1;
    }

    // Query command
    if (command == "query") {
        MySQLDB db;
        db.connect(params.host.c_str(), params.port, params.user.c_str(),
                   params.pass.c_str(), params.database.c_str());

        // Check if schema exists
        if (!table_exists(db, "rag_sources")) {
            std::cerr << "Error: RAG schema not found. Please run 'init' command first:\n";
            std::cerr << "  " << argv[0] << " init -h " << params.host
                      << " -P " << params.port << " -u " << params.user
                      << " -p " << params.pass << " -D " << params.database << "\n";
            return 1;
        }

        curl_global_init(CURL_GLOBAL_DEFAULT);

        try {
            // Load sources
            std::vector<RagSource> sources = load_sources(db);

            // Filter by source_id if specified
            if (params.source_id >= 0) {
                auto it = std::remove_if(sources.begin(), sources.end(),
                    [params](const RagSource& s) { return s.source_id != params.source_id; });
                sources.erase(it, sources.end());
            }

            if (sources.empty()) {
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

            if (source.embedding_json.empty()) {
                std::cerr << "Error: Embeddings not configured for source " << source.source_id << "\n";
                curl_global_cleanup();
                return 1;
            }

            EmbeddingConfig emb_cfg = parse_embedding_json(source.embedding_json);
            if (!emb_cfg.enabled) {
                std::cerr << "Error: Embeddings not enabled for source " << source.source_id << "\n";
                curl_global_cleanup();
                return 1;
            }

            std::cout << "Generating embedding for query using: " << emb_cfg.provider << "\n";

            // Build embedding provider
            auto embedder = build_embedding_provider(emb_cfg);

            // Generate embedding for query
            std::vector<std::string> query_inputs = {params.query_text};
            std::vector<std::vector<float>> query_embeddings = embedder->embed(query_inputs, emb_cfg.dim);

            if (query_embeddings.empty() || query_embeddings[0].empty()) {
                std::cerr << "Error: Failed to generate embedding for query\n";
                curl_global_cleanup();
                return 1;
            }

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

                if (row_count == 0) {
                    std::cout << "No results found.\n";
                } else {
                    std::cout << "\nFound " << row_count << " result(s).\n";
                }
            }

        } catch (const std::exception& e) {
            std::cerr << "Exception: " << e.what() << "\n";
            curl_global_cleanup();
            return 1;
        } catch (...) {
            std::cerr << "Unknown exception\n";
            curl_global_cleanup();
            return 1;
        }

        curl_global_cleanup();
        return 0;
    }

    // Unknown command
    print_usage(argv[0]);
    return 2;
}
