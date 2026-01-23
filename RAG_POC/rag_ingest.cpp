/**
 * @file rag_ingest.cpp
 * @brief ProxySQL RAG (Retrieval-Augmented Generation) Ingestion Tool
 *
 * @verbatim
 * ProxySQL RAG Ingestion PoC (General-Purpose)
 * @endverbatim
 *
 * @section overview Overview
 *
 * This program is a general-purpose ingestion tool for ProxySQL's RAG index.
 * It reads data from external sources (currently MySQL), transforms it according
 * to configurable JSON specifications, chunks the content, builds full-text
 * search indexes, and optionally generates vector embeddings for semantic search.
 *
 * @section v0_features v0 Features
 *
 * - Reads enabled sources from rag_sources table
 * - Connects to MySQL backend and fetches data using configurable SELECT queries
 * - Transforms rows using doc_map_json specification
 * - Chunks document bodies using configurable chunking parameters
 * - Inserts into rag_documents, rag_chunks, rag_fts_chunks (FTS5)
 * - Optionally generates embeddings and inserts into rag_vec_chunks (sqlite3-vec)
 * - Skips documents that already exist (no upsert in v0)
 * - Supports incremental sync using watermark-based cursor tracking
 *
 * @section future_plans Future Plans (v1+)
 *
 * - Add hash-based change detection for efficient updates
 * - Support document updates (not just skip-if-exists)
 * - Add PostgreSQL backend support
 * - Add async embedding workers
 * - Add operational metrics and monitoring
 *
 * @section dependencies Dependencies
 *
 * - sqlite3: For RAG index storage
 * - mysqlclient / libmysqlclient: For MySQL backend connections
 * - libcurl: For HTTP-based embedding providers (OpenAI-compatible)
 * - nlohmann/json: Single-header JSON library (json.hpp)
 * - libcrypt: For sha256_crypt_r weak alias (platform compatibility)
 *
 * @section building Building
 *
 * @verbatim
 * g++ -std=c++17 -O2 rag_ingest.cpp -o rag_ingest \
 *     -lsqlite3 -lmysqlclient -lcurl -lcrypt
 * @endverbatim
 *
 * @section usage Usage
 *
 * @verbatim
 * ./rag_ingest /path/to/rag_index.sqlite
 * @endverbatim
 *
 * The RAG_VEC0_EXT environment variable can be set to specify the path
 * to the sqlite3-vec extension:
 *
 * @verbatim
 * export RAG_VEC0_EXT=/usr/local/lib/sqlite3-vec.so
 * ./rag_ingest /path/to/rag_index.sqlite
 * @endverbatim
 *
 * @section architecture Architecture
 *
 * @subsection ingestion_flow Ingestion Flow
 *
 * <pre>
 * 1. Open SQLite RAG index database
 * 2. Load sqlite3-vec extension (if RAG_VEC0_EXT is set)
 * 3. Load enabled sources from rag_sources table
 * 4. For each source:
 *    a. Parse chunking_json and embedding_json configurations
 *    b. Load sync cursor (watermark) from rag_sync_state
 *    c. Connect to MySQL backend
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
 * 5. Commit transaction or rollback on error
 * </pre>
 *
 * @subsection json_specs JSON Configuration Specifications
 *
 * @subsubsection doc_map_json doc_map_json (Required)
 *
 * Defines how to transform a source row into a canonical document:
 *
 * @verbatim
 * {
 *   "doc_id": { "format": "posts:{Id}" },
 *   "title":  { "concat": [ {"col":"Title"} ] },
 *   "body":   { "concat": [ {"col":"Body"} ] },
 *   "metadata": {
 *     "pick": ["Id","Tags","Score","CreationDate"],
 *     "rename": {"CreationDate":"Created"}
 *   }
 * }
 * @endverbatim
 *
 * Fields:
 * - doc_id.format: Template string with {ColumnName} placeholders
 * - title.concat: Array of column references and literals
 * - body.concat: Array of column references and literals
 * - metadata.pick: Columns to include in metadata JSON
 * - metadata.rename: Map of old_name -> new_name for metadata keys
 *
 * @subsubsection chunking_json chunking_json (Required)
 *
 * Defines how to split document bodies into chunks:
 *
 * @verbatim
 * {
 *   "enabled": true,
 *   "unit": "chars",         // v0 only supports "chars"
 *   "chunk_size": 4000,      // Target chunk size in characters
 *   "overlap": 400,          // Overlap between consecutive chunks
 *   "min_chunk_size": 800    // Minimum chunk size (avoid tiny tail chunks)
 * }
 * @endverbatim
 *
 * @subsubsection embedding_json embedding_json (Optional)
 *
 * Defines how to generate embeddings for chunks:
 *
 * @verbatim
 * {
 *   "enabled": true,
 *   "dim": 1536,
 *   "model": "text-embedding-3-large",
 *   "provider": "openai",    // "stub" or "openai"
 *   "api_base": "https://api.openai.com/v1",
 *   "api_key": "sk-...",
 *   "batch_size": 16,
 *   "timeout_ms": 20000,
 *   "input": { "concat": [
 *     {"col":"Title"},
 *     {"lit":"\nTags: "}, {"col":"Tags"},
 *     {"lit":"\n\n"},
 *     {"chunk_body": true}
 *   ]}
 * }
 * @endverbatim
 *
 * The concat array supports:
 * - {"col":"ColumnName"}: Include column value
 * - {"lit":"literal text"}: Include literal string
 * - {"chunk_body":true}: Include the chunk body text
 *
 * @subsection concat_spec Concat Specification
 *
 * The concat specification is used in multiple places (title, body, embedding input).
 * It's a JSON array of objects, each describing one part to concatenate:
 *
 * @verbatim
 * [
 *   {"col": "Title"},              // Use value from "Title" column
 *   {"lit": "\nTags: "},           // Use literal string
 *   {"col": "Tags"},               // Use value from "Tags" column
 *   {"lit": "\n\n"},
 *   {"chunk_body": true}           // Use chunk body (embedding only)
 * ]
 * @endverbatim
 *
 * @subsection sqlite3_vec sqlite3-vec Integration
 *
 * The sqlite3-vec extension provides vector similarity search capabilities.
 * This program binds float32 arrays as BLOBs for the embedding column.
 *
 * The binding format may vary by sqlite3-vec build. If your build expects
 * a different format, modify bind_vec_embedding() accordingly.
 *
 * @subsection sync_cursor Sync Cursor (Watermark)
 *
 * The sync cursor enables incremental ingestion by tracking the last processed
 * value from a monotonic column (e.g., auto-increment ID, timestamp).
 *
 * Stored in rag_sync_state.cursor_json:
 * @verbatim
 * {
 *   "column": "Id",       // Column name for watermark
 *   "value": 12345        // Last processed value
 * }
 * @endverbatim
 *
 * On next run, only rows WHERE column > value are fetched.
 *
 * @section error_handling Error Handling
 *
 * This program uses a "fail-fast" approach:
 * - JSON parsing errors are fatal (invalid configuration)
 * - Database connection errors are fatal
 * - SQL execution errors are fatal
 * - Errors during ingestion rollback the entire transaction
 *
 * All fatal errors call fatal() which prints the message and exits with code 1.
 *
 * @section threading Threading Model
 *
 * v0 is single-threaded. Future versions may support:
 * - Concurrent source ingestion
 * - Async embedding generation
 * - Parallel chunk processing
 *
 * @author ProxySQL Development Team
 * @version 0.1.0
 * @date 2024
 */

#include "sqlite3.h"
#include "mysql.h"
#include "crypt.h"
#include "curl/curl.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

#include "json.hpp"
using json = nlohmann::json;

/**
 * @brief Weak alias for sha256_crypt_r function
 *
 * This weak symbol alias provides compatibility across platforms where
 * sha256_crypt_r may or may not be available in libcrypt. If the
 * symbol exists in libcrypt, it will be used. Otherwise, this
 * implementation using crypt_r() will be linked.
 *
 * @param key The key/password to hash
 * @param salt The salt string
 * @param buffer Output buffer for the hashed result
 * @param buflen Size of the output buffer
 * @return Pointer to hashed result on success, nullptr on failure
 *
 * @note This is a workaround for library inconsistencies across platforms.
 *       The actual hashing is delegated to crypt_r().
 */
extern "C" __attribute__((weak)) char *sha256_crypt_r(
    const char *key,
    const char *salt,
    char *buffer,
    int buflen) {
  if (!key || !salt || !buffer || buflen <= 0) {
    return nullptr;
  }
  struct crypt_data data;
  std::memset(&data, 0, sizeof(data));
  char *res = crypt_r(key, salt, &data);
  if (!res) {
    return nullptr;
  }
  size_t len = std::strlen(res);
  if (len + 1 > static_cast<size_t>(buflen)) {
    return nullptr;
  }
  std::memcpy(buffer, res, len + 1);
  return buffer;
}

// ===========================================================================
// Utility Functions
// ===========================================================================

/**
 * @brief Print fatal error message and exit
 *
 * This function prints an error message to stderr and terminates the
 * program with exit code 1. It is used for unrecoverable errors where
 * continuing execution is impossible or unsafe.
 *
 * @param msg The error message to print
 *
 * @note This function does not return. It calls std::exit(1).
 */
static void fatal(const std::string& msg) {
  std::cerr << "FATAL: " << msg << "\n";
  std::exit(1);
}

/**
 * @brief Safely convert C string to std::string
 *
 * Converts a potentially null C string pointer to a std::string.
 * If the pointer is null, returns an empty string. This prevents
 * undefined behavior from constructing std::string(nullptr).
 *
 * @param p Pointer to C string (may be null)
 * @return std::string containing the C string content, or empty string if p is null
 */
static std::string str_or_empty(const char* p) {
  return p ? std::string(p) : std::string();
}

/**
 * @brief Execute a SQL statement on SQLite
 *
 * Executes a SQL statement that does not return rows (e.g., INSERT,
 * UPDATE, DELETE, PRAGMA). If an error occurs, it prints the error
 * message and SQL to stderr.
 *
 * @param db SQLite database connection
 * @param sql SQL statement to execute
 * @return int SQLite return code (SQLITE_OK on success, error code otherwise)
 */
static int sqlite_exec(sqlite3* db, const std::string& sql) {
  char* err = nullptr;
  int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
  if (rc != SQLITE_OK) {
    std::string e = err ? err : "(unknown sqlite error)";
    sqlite3_free(err);
    std::cerr << "SQLite error: " << e << "\nSQL: " << sql << "\n";
  }
  return rc;
}

/**
 * @brief Check if a string represents an integer
 *
 * Determines if the given string consists only of digits, optionally
 * preceded by a minus sign. Used for watermark value type detection.
 *
 * @param s String to check
 * @return true if string is a valid integer representation, false otherwise
 */
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

/**
 * @brief Escape single quotes in SQL string literals
 *
 * Doubles single quotes in a string for safe SQL literal construction.
 * This is used for building incremental filter conditions.
 *
 * @param s Input string to escape
 * @return std::string with single quotes doubled (e.g., "it's" -> "it''s")
 *
 * @note This is basic escaping. For user input, prefer parameter binding.
 */
static std::string sql_escape_single_quotes(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    if (c == '\'') out.push_back('\'');
    out.push_back(c);
  }
  return out;
}

/**
 * @brief Serialize JSON to compact string
 *
 * Converts a JSON object to a compact string representation without
 * whitespace or pretty-printing. Used for efficient storage.
 *
 * @param j JSON object to serialize
 * @return std::string Compact JSON representation
 */
static std::string json_dump_compact(const json& j) {
  return j.dump();
}

/**
 * @brief Load sqlite3-vec extension if configured
 *
 * Loads the sqlite3-vec extension from the path specified in the
 * RAG_VEC0_EXT environment variable. This is required for vector
 * similarity search functionality.
 *
 * @param db SQLite database connection
 *
 * @note If RAG_VEC0_EXT is not set or empty, this function does nothing.
 *       The vec0 extension is only required when embedding generation is enabled.
 */
static void sqlite_load_vec_extension(sqlite3* db) {
  const char* ext = std::getenv("RAG_VEC0_EXT");
  if (!ext || std::strlen(ext) == 0) return;

  sqlite3_enable_load_extension(db, 1);
  char* err = nullptr;
  int rc = sqlite3_load_extension(db, ext, nullptr, &err);
  if (rc != SQLITE_OK) {
    std::string e = err ? err : "(unknown error)";
    sqlite3_free(err);
    fatal("Failed to load vec0 extension: " + e + " (" + std::string(ext) + ")");
  }
}

// ===========================================================================
// Data Structures
// ===========================================================================

/**
 * @brief Configuration for a single RAG data source
 *
 * Represents all configuration needed to ingest data from a single
 * external source into the RAG index. Loaded from the rag_sources table.
 */
struct RagSource {
  int source_id = 0;          ///< Unique source identifier from database
  std::string name;           ///< Human-readable source name
  int enabled = 0;            ///< Whether this source is enabled (0/1)

  // Backend connection settings
  std::string backend_type;   ///< Type of backend ("mysql" in v0)
  std::string host;           ///< Backend server hostname or IP
  int port = 3306;            ///< Backend server port
  std::string user;           ///< Backend authentication username
  std::string pass;           ///< Backend authentication password
  std::string db;             ///< Backend database name

  // Source table settings
  std::string table_name;     ///< Name of the table to read from
  std::string pk_column;      ///< Primary key column name
  std::string where_sql;      ///< Optional WHERE clause for row filtering

  // Transformation configuration (JSON)
  json doc_map_json;          ///< Document transformation specification
  json chunking_json;         ///< Chunking configuration
  json embedding_json;        ///< Embedding configuration (may be null)
};

/**
 * @brief Parsed chunking configuration
 *
 * Controls how document bodies are split into chunks for indexing.
 * Chunks improve retrieval precision by matching smaller, more
 * focused text segments.
 */
struct ChunkingConfig {
  bool enabled = true;               ///< Whether chunking is enabled
  std::string unit = "chars";        ///< Unit of measurement ("chars" in v0)
  int chunk_size = 4000;             ///< Target size of each chunk
  int overlap = 400;                 ///< Overlap between consecutive chunks
  int min_chunk_size = 800;          ///< Minimum size to avoid tiny tail chunks
};

/**
 * @brief Parsed embedding configuration
 *
 * Controls how vector embeddings are generated for chunks.
 * Embeddings enable semantic similarity search.
 */
struct EmbeddingConfig {
  bool enabled = false;              ///< Whether embedding generation is enabled
  int dim = 1536;                    ///< Vector dimension (model-specific)
  std::string model = "unknown";     ///< Model name (for observability)
  json input_spec;                   ///< Embedding input template {"concat":[...]}
  std::string provider = "stub";     ///< Provider type: "stub" or "openai"
  std::string api_base;              ///< API endpoint URL (for "openai" provider)
  std::string api_key;               ///< API authentication key
  int batch_size = 16;               ///< Maximum inputs per API call (unused in v0)
  int timeout_ms = 20000;            ///< Request timeout in milliseconds
};

/**
 * @brief Sync cursor for incremental ingestion
 *
 * Tracks the last processed watermark value for incremental sync.
 * Only rows with watermark > cursor.value are fetched on subsequent runs.
 */
struct SyncCursor {
  std::string column;         ///< Column name used for watermark
  bool has_value = false;     ///< Whether a cursor value has been set
  bool numeric = false;       ///< Whether the value is numeric (vs string)
  std::int64_t num_value = 0; ///< Numeric watermark value (if numeric=true)
  std::string str_value;      ///< String watermark value (if numeric=false)
};

/**
 * @brief Row representation from MySQL backend
 *
 * A map from column name to string value. All MySQL values are
 * represented as strings for simplicity; conversion happens
 * during document building.
 */
typedef std::unordered_map<std::string, std::string> RowMap;

// ===========================================================================
// JSON Parsing Functions
// ===========================================================================

/**
 * @brief Parse chunking_json into ChunkingConfig struct
 *
 * Extracts and validates chunking configuration from JSON.
 * Applies sensible defaults for missing or invalid values.
 *
 * @param j JSON object containing chunking configuration
 * @return ChunkingConfig Parsed configuration with defaults applied
 *
 * @note Only "chars" unit is supported in v0. Other units fall back to "chars".
 */
static ChunkingConfig parse_chunking_json(const json& j) {
  ChunkingConfig cfg;
  if (!j.is_object()) return cfg;

  if (j.contains("enabled")) cfg.enabled = j["enabled"].get<bool>();
  if (j.contains("unit")) cfg.unit = j["unit"].get<std::string>();
  if (j.contains("chunk_size")) cfg.chunk_size = j["chunk_size"].get<int>();
  if (j.contains("overlap")) cfg.overlap = j["overlap"].get<int>();
  if (j.contains("min_chunk_size")) cfg.min_chunk_size = j["min_chunk_size"].get<int>();

  // Apply sanity checks and defaults
  if (cfg.chunk_size <= 0) cfg.chunk_size = 4000;
  if (cfg.overlap < 0) cfg.overlap = 0;
  if (cfg.overlap >= cfg.chunk_size) cfg.overlap = cfg.chunk_size / 4;
  if (cfg.min_chunk_size < 0) cfg.min_chunk_size = 0;

  // v0 only supports chars
  if (cfg.unit != "chars") {
    std::cerr << "WARN: chunking_json.unit=" << cfg.unit
              << " not supported in v0. Falling back to chars.\n";
    cfg.unit = "chars";
  }

  return cfg;
}

/**
 * @brief Parse embedding_json into EmbeddingConfig struct
 *
 * Extracts and validates embedding configuration from JSON.
 * Applies sensible defaults for missing or invalid values.
 *
 * @param j JSON object containing embedding configuration (may be null)
 * @return EmbeddingConfig Parsed configuration with defaults applied
 */
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

  // Apply defaults
  if (cfg.dim <= 0) cfg.dim = 1536;
  if (cfg.batch_size <= 0) cfg.batch_size = 16;
  if (cfg.timeout_ms <= 0) cfg.timeout_ms = 20000;
  return cfg;
}

// ===========================================================================
// Row Access Helpers
// ===========================================================================

/**
 * @brief Get value from RowMap by key
 *
 * Safely retrieves a value from a RowMap (column name -> value mapping).
 * Returns std::nullopt if the key is not present, allowing the caller
 * to distinguish between missing keys and empty values.
 *
 * @param row The RowMap to query
 * @param key Column name to look up
 * @return std::optional<std::string> Value if present, nullopt otherwise
 */
static std::optional<std::string> row_get(const RowMap& row, const std::string& key) {
  auto it = row.find(key);
  if (it == row.end()) return std::nullopt;
  return it->second;
}

// ===========================================================================
// Format String Template Engine
// ===========================================================================

/**
 * @brief Apply format template with row data substitution
 *
 * Replaces {ColumnName} placeholders in a format string with actual
 * values from the row. Used for generating document IDs.
 *
 * Example: "posts:{Id}" with row["Id"] = "123" becomes "posts:123"
 *
 * @param fmt Format string with {ColumnName} placeholders
 * @param row Row data for substitution
 * @return std::string Formatted string with substitutions applied
 *
 * @note Unmatched '{' characters are treated as literals.
 *       Missing column names result in empty substitution.
 */
static std::string apply_format(const std::string& fmt, const RowMap& row) {
  std::string out;
  out.reserve(fmt.size() + 32);

  for (size_t i = 0; i < fmt.size(); i++) {
    char c = fmt[i];
    if (c == '{') {
      size_t j = fmt.find('}', i + 1);
      if (j == std::string::npos) {
        // unmatched '{' -> treat as literal
        out.push_back(c);
        continue;
      }
      std::string col = fmt.substr(i + 1, j - (i + 1));
      auto v = row_get(row, col);
      if (v.has_value()) out += v.value();
      i = j; // jump past '}'
    } else {
      out.push_back(c);
    }
  }
  return out;
}

// ===========================================================================
// Concat Specification Evaluator
// ===========================================================================

/**
 * @brief Evaluate concat specification to build string
 *
 * Processes a concat specification (JSON array) to build a string by
 * concatenating column values, literals, and optionally the chunk body.
 *
 * Supported concat elements:
 * - {"col":"ColumnName"} - Include value from column
 * - {"lit":"literal"} - Include literal string
 * - {"chunk_body":true} - Include chunk body (only for embedding input)
 *
 * @param concat_spec JSON array with concat specification
 * @param row Row data for column substitutions
 * @param chunk_body Chunk body text (used if allow_chunk_body=true)
 * @param allow_chunk_body Whether to allow chunk_body references
 * @return std::string Concatenated result
 */
static std::string eval_concat(const json& concat_spec,
                               const RowMap& row,
                               const std::string& chunk_body,
                               bool allow_chunk_body) {
  if (!concat_spec.is_array()) return "";

  std::string out;
  for (const auto& part : concat_spec) {
    if (!part.is_object()) continue;

    if (part.contains("col")) {
      // Column reference: {"col":"ColumnName"}
      std::string col = part["col"].get<std::string>();
      auto v = row_get(row, col);
      if (v.has_value()) out += v.value();
    } else if (part.contains("lit")) {
      // Literal string: {"lit":"some text"}
      out += part["lit"].get<std::string>();
    } else if (allow_chunk_body && part.contains("chunk_body")) {
      // Chunk body reference: {"chunk_body":true}
      bool yes = part["chunk_body"].get<bool>();
      if (yes) out += chunk_body;
    }
  }
  return out;
}

// ===========================================================================
// Metadata Builder
// ===========================================================================

/**
 * @brief Build metadata JSON from row using specification
 *
 * Creates a metadata JSON object by picking specified columns from
 * the row and optionally renaming keys.
 *
 * @param meta_spec Metadata specification with "pick" and "rename" keys
 * @param row Source row data
 * @return json Metadata object with picked and renamed fields
 *
 * The meta_spec format:
 * @verbatim
 * {
 *   "pick": ["Col1", "Col2"],    // Columns to include
 *   "rename": {"Col1": "col1"}   // Old name -> new name mapping
 * }
 * @endverbatim
 */
static json build_metadata(const json& meta_spec, const RowMap& row) {
  json meta = json::object();

  if (meta_spec.is_object()) {
    // Pick specified fields
    if (meta_spec.contains("pick") && meta_spec["pick"].is_array()) {
      for (const auto& colv : meta_spec["pick"]) {
        if (!colv.is_string()) continue;
        std::string col = colv.get<std::string>();
        auto v = row_get(row, col);
        if (v.has_value()) meta[col] = v.value();
      }
    }

    // Rename keys (must be done in two passes to avoid iterator invalidation)
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

/**
 * @brief Split text into chunks based on character count
 *
 * Divides a text string into overlapping chunks of approximately
 * chunk_size characters. Chunks overlap by 'overlap' characters to
 * preserve context at boundaries. Tiny final chunks are appended
 * to the previous chunk to avoid fragmentation.
 *
 * @param text Input text to chunk
 * @param cfg Chunking configuration
 * @return std::vector<std::string> Vector of chunk strings
 *
 * @note If chunking is disabled, returns a single chunk containing the full text.
 * @note If text is smaller than chunk_size, returns a single chunk.
 */
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

    // Avoid tiny final chunk by appending it to the previous chunk
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

/**
 * @brief Connect to MySQL backend or terminate
 *
 * Establishes a connection to a MySQL server using the provided
 * source configuration. Sets charset to utf8mb4 for proper handling
 * of Unicode content (e.g., emojis, international text).
 *
 * @param s Source configuration with connection parameters
 * @return MYSQL* MySQL connection handle
 *
 * @note On failure, prints error message and calls fatal() to exit.
 */
static MYSQL* mysql_connect_or_die(const RagSource& s) {
  MYSQL* conn = mysql_init(nullptr);
  if (!conn) fatal("mysql_init failed");

  // Set utf8mb4 for safety with StackOverflow-like content
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

/**
 * @brief Convert MySQL result row to RowMap
 *
 * Transforms a raw MySQL row into a column-name -> value map.
 * All values are converted to strings; NULL values become empty strings.
 *
 * @param res MySQL result set (for field metadata)
 * @param row Raw MySQL row data
 * @return RowMap Map of column names to string values
 *
 * @note Uses str_or_empty() to safely handle NULL column values.
 */
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

/**
 * @brief Add string to vector if not already present
 *
 * Helper function to maintain a list of unique column names.
 * Used when building the SELECT query to avoid duplicate columns.
 *
 * @param cols Vector of column names (modified in-place)
 * @param c Column name to add (if not present)
 */
static void add_unique(std::vector<std::string>& cols, const std::string& c) {
  for (size_t i = 0; i < cols.size(); i++) {
    if (cols[i] == c) return;
  }
  cols.push_back(c);
}

/**
 * @brief Extract column names from concat specification
 *
 * Parses a concat specification and adds all referenced column names
 * to the output vector. Used to build the minimal SELECT query.
 *
 * @param cols Vector of column names (modified in-place)
 * @param concat_spec JSON concat specification to scan
 */
static void collect_cols_from_concat(std::vector<std::string>& cols, const json& concat_spec) {
  if (!concat_spec.is_array()) return;
  for (const auto& part : concat_spec) {
    if (part.is_object() && part.contains("col") && part["col"].is_string()) {
      add_unique(cols, part["col"].get<std::string>());
    }
  }
}

/**
 * @brief Collect all columns needed for source ingestion
 *
 * Analyzes doc_map_json and embedding_json to determine which columns
 * must be fetched from the source table. Builds a minimal SELECT query
 * by only including required columns.
 *
 * @param s Source configuration with JSON specifications
 * @param ecfg Embedding configuration
 * @return std::vector<std::string> List of required column names
 *
 * @note The primary key column is always included.
 * @note Columns in doc_id.format must be manually included in metadata.pick or concat.
 */
static std::vector<std::string> collect_needed_columns(const RagSource& s, const EmbeddingConfig& ecfg) {
  std::vector<std::string> cols;
  add_unique(cols, s.pk_column);

  // title/body concat
  if (s.doc_map_json.contains("title") && s.doc_map_json["title"].contains("concat"))
    collect_cols_from_concat(cols, s.doc_map_json["title"]["concat"]);
  if (s.doc_map_json.contains("body") && s.doc_map_json["body"].contains("concat"))
    collect_cols_from_concat(cols, s.doc_map_json["body"]["concat"]);

  // metadata.pick
  if (s.doc_map_json.contains("metadata") && s.doc_map_json["metadata"].contains("pick")) {
    const auto& pick = s.doc_map_json["metadata"]["pick"];
    if (pick.is_array()) {
      for (const auto& c : pick) if (c.is_string()) add_unique(cols, c.get<std::string>());
    }
  }

  // embedding input concat (optional)
  if (ecfg.enabled && ecfg.input_spec.is_object() && ecfg.input_spec.contains("concat")) {
    collect_cols_from_concat(cols, ecfg.input_spec["concat"]);
  }

  return cols;
}

/**
 * @brief Build SELECT SQL query for source
 *
 * Constructs a SELECT query that fetches only the required columns
 * from the source table, with optional WHERE clause combining the
 * source's where_sql and an incremental filter.
 *
 * @param s Source configuration
 * @param cols List of column names to SELECT
 * @param extra_filter Additional WHERE clause (e.g., incremental filter)
 * @return std::string Complete SELECT SQL statement
 */
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

// Forward declarations
static void sqlite_prepare_or_die(sqlite3* db, sqlite3_stmt** st, const char* sql);
static void bind_text(sqlite3_stmt* st, int idx, const std::string& v);

/**
 * @brief Load sync cursor JSON from database
 *
 * Retrieves the cursor_json for a source from rag_sync_state.
 * Returns empty object if no cursor exists or on error.
 *
 * @param db SQLite database connection
 * @param source_id Source identifier
 * @return json Cursor JSON object (empty if not found)
 */
static json load_sync_cursor_json(sqlite3* db, int source_id) {
  sqlite3_stmt* st = nullptr;
  json out = json::object();
  const char* sql = "SELECT cursor_json FROM rag_sync_state WHERE source_id=?";
  if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
    return out;
  }
  sqlite3_bind_int(st, 1, source_id);
  int rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    const unsigned char* txt = sqlite3_column_text(st, 0);
    if (txt) {
      try {
        out = json::parse(reinterpret_cast<const char*>(txt));
      } catch (...) {
        out = json::object();
      }
    }
  }
  sqlite3_finalize(st);
  if (!out.is_object()) out = json::object();
  return out;
}

/**
 * @brief Parse sync cursor JSON into SyncCursor struct
 *
 * Extracts cursor configuration from JSON and determines the
 * value type (numeric vs string). Used for incremental ingestion.
 *
 * @param cursor_json JSON cursor configuration
 * @param default_col Default column name if not specified
 * @return SyncCursor Parsed cursor configuration
 */
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

/**
 * @brief Build incremental filter SQL from cursor
 *
 * Constructs a WHERE clause fragment for incremental ingestion.
 * Returns empty string if cursor has no value set.
 *
 * @param c Sync cursor configuration
 * @return std::string SQL filter (e.g., "`Id` > 123") or empty string
 *
 * @note String values are escaped to prevent SQL injection.
 */
static std::string build_incremental_filter(const SyncCursor& c) {
  if (!c.has_value || c.column.empty()) return "";
  std::string col = "`" + c.column + "`";
  if (c.numeric) {
    return col + " > " + std::to_string(c.num_value);
  }
  return col + " > '" + sql_escape_single_quotes(c.str_value) + "'";
}

/**
 * @brief Update sync state in database
 *
 * Upserts the cursor state into rag_sync_state after successful
 * (or partial) ingestion. Updates the watermark value and last_ok_at.
 *
 * @param db SQLite database connection
 * @param source_id Source identifier
 * @param cursor_json Updated cursor JSON to store
 *
 * @note On error, calls fatal() to terminate the program.
 */
static void update_sync_state(sqlite3* db, int source_id, const json& cursor_json) {
  const char* sql =
    "INSERT INTO rag_sync_state(source_id, mode, cursor_json, last_ok_at, last_error) "
    "VALUES(?, 'poll', ?, unixepoch(), NULL) "
    "ON CONFLICT(source_id) DO UPDATE SET "
    "cursor_json=excluded.cursor_json, last_ok_at=excluded.last_ok_at, last_error=NULL";
  sqlite3_stmt* st = nullptr;
  sqlite_prepare_or_die(db, &st, sql);
  sqlite3_bind_int(st, 1, source_id);
  std::string cursor_str = json_dump_compact(cursor_json);
  bind_text(st, 2, cursor_str);
  int rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) {
    fatal(std::string("SQLite upsert rag_sync_state failed: ") + sqlite3_errmsg(db));
  }
}

// ===========================================================================
// SQLite Prepared Statements
// ===========================================================================

/**
 * @brief Collection of prepared SQLite statements
 *
 * Holds all prepared statements needed for ingestion.
 * Prepared statements are reused for efficiency and SQL injection safety.
 */
struct SqliteStmts {
  sqlite3_stmt* doc_exists = nullptr;  ///< Check if document exists
  sqlite3_stmt* ins_doc = nullptr;     ///< Insert document
  sqlite3_stmt* ins_chunk = nullptr;   ///< Insert chunk
  sqlite3_stmt* ins_fts = nullptr;     ///< Insert into FTS index
  sqlite3_stmt* ins_vec = nullptr;     ///< Insert vector embedding
};

/**
 * @brief Prepare SQLite statement or terminate
 *
 * Prepares a SQLite statement and calls fatal() on failure.
 * Used for statements that must succeed for the program to continue.
 *
 * @param db SQLite database connection
 * @param st Output parameter for prepared statement handle
 * @param sql SQL statement to prepare
 *
 * @note On failure, prints error and calls fatal() to exit.
 */
static void sqlite_prepare_or_die(sqlite3* db, sqlite3_stmt** st, const char* sql) {
  if (sqlite3_prepare_v2(db, sql, -1, st, nullptr) != SQLITE_OK) {
    fatal(std::string("SQLite prepare failed: ") + sqlite3_errmsg(db) + "\nSQL: " + sql);
  }
}

/**
 * @brief Finalize all statements in SqliteStmts
 *
 * Releases all prepared statement resources.
 *
 * @param s Statement collection to finalize (reset to default state)
 */
static void sqlite_finalize_all(SqliteStmts& s) {
  if (s.doc_exists) sqlite3_finalize(s.doc_exists);
  if (s.ins_doc) sqlite3_finalize(s.ins_doc);
  if (s.ins_chunk) sqlite3_finalize(s.ins_chunk);
  if (s.ins_fts) sqlite3_finalize(s.ins_fts);
  if (s.ins_vec) sqlite3_finalize(s.ins_vec);
  s = SqliteStmts{};
}

/**
 * @brief Bind text parameter to SQLite statement
 *
 * Binds a std::string value to a prepared statement parameter.
 * Uses SQLITE_TRANSIENT for string management (SQLite makes a copy).
 *
 * @param st Prepared statement
 * @param idx Parameter index (1-based)
 * @param v String value to bind
 */
static void bind_text(sqlite3_stmt* st, int idx, const std::string& v) {
  sqlite3_bind_text(st, idx, v.c_str(), -1, SQLITE_TRANSIENT);
}

/**
 * @brief Bind vector embedding to SQLite statement
 *
 * Binds a float32 array as a BLOB for sqlite3-vec.
 * This is the "best effort" binding format that works with most
 * sqlite3-vec builds. Modify if your build expects different format.
 *
 * @param st Prepared statement
 * @param idx Parameter index (1-based)
 * @param emb Float vector to bind
 *
 * @note The binding format is build-dependent. If vec operations fail,
 *       check your sqlite3-vec build's expected format.
 */
static void bind_vec_embedding(sqlite3_stmt* st, int idx, const std::vector<float>& emb) {
  const void* data = (const void*)emb.data();
  int bytes = (int)(emb.size() * sizeof(float));
  sqlite3_bind_blob(st, idx, data, bytes, SQLITE_TRANSIENT);
}

/**
 * @brief Check if document exists in database
 *
 * Tests whether a document with the given doc_id already exists
 * in rag_documents. Used for skip-if-exists logic in v0.
 *
 * @param ss Statement collection
 * @param doc_id Document identifier to check
 * @return true if document exists, false otherwise
 */
static bool sqlite_doc_exists(SqliteStmts& ss, const std::string& doc_id) {
  sqlite3_reset(ss.doc_exists);
  sqlite3_clear_bindings(ss.doc_exists);

  bind_text(ss.doc_exists, 1, doc_id);

  int rc = sqlite3_step(ss.doc_exists);
  return (rc == SQLITE_ROW);
}

/**
 * @brief Insert document into rag_documents table
 *
 * Inserts a new document record with all metadata.
 *
 * @param ss Statement collection
 * @param source_id Source identifier
 * @param source_name Source name
 * @param doc_id Document identifier
 * @param pk_json Primary key JSON (for refetch)
 * @param title Document title
 * @param body Document body
 * @param meta_json Metadata JSON object
 *
 * @note On failure, calls fatal() to terminate.
 */
static void sqlite_insert_doc(SqliteStmts& ss,
                              int source_id,
                              const std::string& source_name,
                              const std::string& doc_id,
                              const std::string& pk_json,
                              const std::string& title,
                              const std::string& body,
                              const std::string& meta_json) {
  sqlite3_reset(ss.ins_doc);
  sqlite3_clear_bindings(ss.ins_doc);

  bind_text(ss.ins_doc, 1, doc_id);
  sqlite3_bind_int(ss.ins_doc, 2, source_id);
  bind_text(ss.ins_doc, 3, source_name);
  bind_text(ss.ins_doc, 4, pk_json);
  bind_text(ss.ins_doc, 5, title);
  bind_text(ss.ins_doc, 6, body);
  bind_text(ss.ins_doc, 7, meta_json);

  int rc = sqlite3_step(ss.ins_doc);
  if (rc != SQLITE_DONE) {
    fatal(std::string("SQLite insert rag_documents failed: ") + sqlite3_errmsg(sqlite3_db_handle(ss.ins_doc)));
  }
}

/**
 * @brief Insert chunk into rag_chunks table
 *
 * Inserts a new chunk record with title, body, and metadata.
 *
 * @param ss Statement collection
 * @param chunk_id Chunk identifier (typically doc_id#index)
 * @param doc_id Parent document identifier
 * @param source_id Source identifier
 * @param chunk_index Zero-based chunk index within document
 * @param title Chunk title
 * @param body Chunk body text
 * @param meta_json Chunk metadata JSON
 *
 * @note On failure, calls fatal() to terminate.
 */
static void sqlite_insert_chunk(SqliteStmts& ss,
                                const std::string& chunk_id,
                                const std::string& doc_id,
                                int source_id,
                                int chunk_index,
                                const std::string& title,
                                const std::string& body,
                                const std::string& meta_json) {
  sqlite3_reset(ss.ins_chunk);
  sqlite3_clear_bindings(ss.ins_chunk);

  bind_text(ss.ins_chunk, 1, chunk_id);
  bind_text(ss.ins_chunk, 2, doc_id);
  sqlite3_bind_int(ss.ins_chunk, 3, source_id);
  sqlite3_bind_int(ss.ins_chunk, 4, chunk_index);
  bind_text(ss.ins_chunk, 5, title);
  bind_text(ss.ins_chunk, 6, body);
  bind_text(ss.ins_chunk, 7, meta_json);

  int rc = sqlite3_step(ss.ins_chunk);
  if (rc != SQLITE_DONE) {
    fatal(std::string("SQLite insert rag_chunks failed: ") + sqlite3_errmsg(sqlite3_db_handle(ss.ins_chunk)));
  }
}

/**
 * @brief Insert chunk into FTS index
 *
 * Inserts a chunk into the rag_fts_chunks FTS5 table for
 * full-text search. The FTS table is contentless (text stored
 * only in rag_chunks, FTS only maintains index).
 *
 * @param ss Statement collection
 * @param chunk_id Chunk identifier
 * @param title Chunk title
 * @param body Chunk body text
 *
 * @note On failure, calls fatal() to terminate.
 */
static void sqlite_insert_fts(SqliteStmts& ss,
                              const std::string& chunk_id,
                              const std::string& title,
                              const std::string& body) {
  sqlite3_reset(ss.ins_fts);
  sqlite3_clear_bindings(ss.ins_fts);

  bind_text(ss.ins_fts, 1, chunk_id);
  bind_text(ss.ins_fts, 2, title);
  bind_text(ss.ins_fts, 3, body);

  int rc = sqlite3_step(ss.ins_fts);
  if (rc != SQLITE_DONE) {
    fatal(std::string("SQLite insert rag_fts_chunks failed: ") + sqlite3_errmsg(sqlite3_db_handle(ss.ins_fts)));
  }
}

/**
 * @brief Insert vector embedding into rag_vec_chunks table
 *
 * Inserts a vector embedding along with metadata for vector
 * similarity search using sqlite3-vec.
 *
 * Schema: rag_vec_chunks(embedding, chunk_id, doc_id, source_id, updated_at)
 *
 * @param ss Statement collection
 * @param emb Float32 vector embedding
 * @param chunk_id Chunk identifier
 * @param doc_id Parent document identifier
 * @param source_id Source identifier
 * @param updated_at_unixepoch Unix epoch timestamp (0 for "now")
 *
 * @note If ss.ins_vec is null (embedding disabled), returns without error.
 * @note On failure, calls fatal() with vec-specific error message.
 */
static void sqlite_insert_vec(SqliteStmts& ss,
                              const std::vector<float>& emb,
                              const std::string& chunk_id,
                              const std::string& doc_id,
                              int source_id,
                              std::int64_t updated_at_unixepoch) {
  if (!ss.ins_vec) return;

  sqlite3_reset(ss.ins_vec);
  sqlite3_clear_bindings(ss.ins_vec);

  bind_vec_embedding(ss.ins_vec, 1, emb);
  bind_text(ss.ins_vec, 2, chunk_id);
  bind_text(ss.ins_vec, 3, doc_id);
  sqlite3_bind_int(ss.ins_vec, 4, source_id);
  sqlite3_bind_int64(ss.ins_vec, 5, (sqlite3_int64)updated_at_unixepoch);

  int rc = sqlite3_step(ss.ins_vec);
  if (rc != SQLITE_DONE) {
    // Vec-specific error message for troubleshooting
    fatal(std::string("SQLite insert rag_vec_chunks failed (check vec binding format): ")
          + sqlite3_errmsg(sqlite3_db_handle(ss.ins_vec)));
  }
}

// ===========================================================================
// Embedding Generation
// ===========================================================================

/**
 * @brief Generate deterministic pseudo-embedding from text
 *
 * This is a stub implementation that generates a deterministic but
 * non-semantic embedding from input text. Used for testing when
 * a real embedding service is not available.
 *
 * The algorithm uses a rolling hash to distribute values across
 * vector dimensions, then normalizes. Results are deterministic
 * (same input always produces same output) but NOT semantic.
 *
 * @param text Input text to "embed"
 * @param dim Vector dimension
 * @return std::vector<float> Deterministic pseudo-embedding
 *
 * @warning This does NOT produce semantic embeddings. Only for testing.
 */
static std::vector<float> pseudo_embedding(const std::string& text, int dim) {
  std::vector<float> v;
  v.resize((size_t)dim, 0.0f);

  // FNV-1a-like rolling hash accumulation into float bins
  std::uint64_t h = 1469598103934665603ULL; // FNV offset basis
  for (size_t i = 0; i < text.size(); i++) {
    h ^= (unsigned char)text[i];
    h *= 1099511628211ULL; // FNV prime

    // Spread influence into bins based on hash
    size_t idx = (size_t)(h % (std::uint64_t)dim);
    float val = (float)((h >> 32) & 0xFFFF) / 65535.0f; // Normalize to 0..1
    v[idx] += (val - 0.5f); // Center around 0
  }

  // L2 normalization
  double norm = 0.0;
  for (int i = 0; i < dim; i++) norm += (double)v[(size_t)i] * (double)v[(size_t)i];
  norm = std::sqrt(norm);
  if (norm > 1e-12) {
    for (int i = 0; i < dim; i++) v[(size_t)i] = (float)(v[(size_t)i] / norm);
  }
  return v;
}

/**
 * @brief Abstract embedding provider interface
 *
 * Base class for embedding providers. Concrete implementations
 * include StubEmbeddingProvider and OpenAIEmbeddingProvider.
 */
struct EmbeddingProvider {
  /**
   * @brief Virtual destructor for safe polymorphic deletion
   */
  virtual ~EmbeddingProvider() = default;

  /**
   * @brief Generate embeddings for multiple input strings
   *
   * @param inputs Vector of input texts to embed
   * @param dim Expected embedding dimension
   * @return std::vector<std::vector<float>> Vector of embeddings (one per input)
   *
   * @note The returned vector must have exactly inputs.size() embeddings.
   * @note Each embedding must have exactly dim float values.
   *
   * @throws std::runtime_error on embedding generation failure
   */
  virtual std::vector<std::vector<float>> embed(const std::vector<std::string>& inputs, int dim) = 0;
};

/**
 * @brief Stub embedding provider for testing
 *
 * Uses pseudo_embedding() to generate deterministic but non-semantic
 * embeddings. Used when no real embedding service is available.
 */
struct StubEmbeddingProvider : public EmbeddingProvider {
  /**
   * @brief Generate pseudo-embeddings for inputs
   *
   * @param inputs Vector of input texts
   * @param dim Embedding dimension
   * @return std::vector<std::vector<float>> Deterministic pseudo-embeddings
   */
  std::vector<std::vector<float>> embed(const std::vector<std::string>& inputs, int dim) override {
    std::vector<std::vector<float>> out;
    out.reserve(inputs.size());
    for (const auto& s : inputs) out.push_back(pseudo_embedding(s, dim));
    return out;
  }
};

/**
 * @brief Buffer for curl HTTP response data
 *
 * Simple string buffer used by curl write callback to accumulate
 * HTTP response data.
 */
struct CurlBuffer {
  std::string data;  ///< Accumulated response data
};

/**
 * @brief Curl write callback function
 *
 * Callback function passed to libcurl to handle incoming response data.
 * Appends received data to the CurlBuffer.
 *
 * @param contents Pointer to received data
 * @param size Size of each data element
 * @param nmemb Number of elements
 * @param userp User pointer (must point to CurlBuffer)
 * @return size_t Total bytes processed
 */
static size_t curl_write_cb(void* contents, size_t size, size_t nmemb, void* userp) {
  size_t total = size * nmemb;
  CurlBuffer* buf = static_cast<CurlBuffer*>(userp);
  buf->data.append(static_cast<const char*>(contents), total);
  return total;
}

/**
 * @brief OpenAI-compatible embedding provider
 *
 * Calls an OpenAI-compatible HTTP API to generate embeddings.
 * Works with OpenAI, Azure OpenAI, or any compatible service.
 */
struct OpenAIEmbeddingProvider : public EmbeddingProvider {
  std::string api_base;      ///< API base URL (e.g., "https://api.openai.com/v1")
  std::string api_key;       ///< API authentication key
  std::string model;         ///< Model name (e.g., "text-embedding-3-large")
  int timeout_ms = 20000;    ///< Request timeout in milliseconds

  /**
   * @brief Construct OpenAI embedding provider
   *
   * @param base API base URL
   * @param key API key
   * @param mdl Model name
   * @param timeout Request timeout
   */
  OpenAIEmbeddingProvider(std::string base, std::string key, std::string mdl, int timeout)
      : api_base(std::move(base)), api_key(std::move(key)), model(std::move(mdl)), timeout_ms(timeout) {}

  /**
   * @brief Generate embeddings via OpenAI-compatible API
   *
   * Sends a batch of texts to the embedding API and returns
   * the generated embeddings.
   *
   * @param inputs Vector of input texts to embed
   * @param dim Expected embedding dimension
   * @return std::vector<std::vector<float>> Generated embeddings
   *
   * @throws std::runtime_error on API error, timeout, or invalid response
   *
   * @note The inputs are sent in a single batch. For large batches,
   *       consider splitting into multiple calls.
   */
  std::vector<std::vector<float>> embed(const std::vector<std::string>& inputs, int dim) override {
    // Validate configuration
    if (api_base.empty()) {
      throw std::runtime_error("embedding api_base is empty");
    }
    if (api_key.empty()) {
      throw std::runtime_error("embedding api_key is empty");
    }
    if (model.empty()) {
      throw std::runtime_error("embedding model is empty");
    }
    // Note: Some providers expect "hf:" prefix for HuggingFace models
    if (model.rfind("hf:", 0) != 0) {
      std::cerr << "WARN: embedding model should be prefixed with 'hf:' per Synthetic docs\n";
    }

    // Build request JSON
    json req;
    req["model"] = model;
    req["input"] = inputs;
    if (dim > 0) {
      req["dimensions"] = dim;
    }
    std::string body = req.dump();

    // Build URL
    std::string url = api_base;
    if (!url.empty() && url.back() == '/') url.pop_back();
    url += "/embeddings";

    // Execute HTTP request
    CURL* curl = curl_easy_init();
    if (!curl) {
      throw std::runtime_error("curl_easy_init failed");
    }

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

    // Check for errors
    if (res != CURLE_OK) {
      throw std::runtime_error(std::string("curl error: ") + curl_easy_strerror(res));
    }
    if (status < 200 || status >= 300) {
      throw std::runtime_error("embedding request failed with status " + std::to_string(status));
    }

    // Parse response
    json resp = json::parse(buf.data);
    if (!resp.contains("data") || !resp["data"].is_array()) {
      throw std::runtime_error("embedding response missing data array");
    }

    // Extract embeddings
    std::vector<std::vector<float>> out;
    out.reserve(resp["data"].size());
    for (const auto& item : resp["data"]) {
      if (!item.contains("embedding") || !item["embedding"].is_array()) {
        throw std::runtime_error("embedding item missing embedding array");
      }
      std::vector<float> vec;
      vec.reserve(item["embedding"].size());
      for (const auto& v : item["embedding"]) {
        vec.push_back(v.get<float>());
      }
      if ((int)vec.size() != dim) {
        throw std::runtime_error("embedding dimension mismatch: expected " + std::to_string(dim)
                                 + ", got " + std::to_string(vec.size()));
      }
      out.push_back(std::move(vec));
    }

    if (out.size() != inputs.size()) {
      throw std::runtime_error("embedding response size mismatch");
    }
    return out;
  }
};

/**
 * @brief Build embedding provider from configuration
 *
 * Factory function that creates the appropriate embedding provider
 * based on the configuration.
 *
 * @param cfg Embedding configuration
 * @return std::unique_ptr<EmbeddingProvider> Configured provider instance
 *
 * @note Currently supports "stub" and "openai" providers.
 *       "stub" is returned for unknown provider types.
 */
static std::unique_ptr<EmbeddingProvider> build_embedding_provider(const EmbeddingConfig& cfg) {
  if (cfg.provider == "openai") {
    return std::make_unique<OpenAIEmbeddingProvider>(cfg.api_base, cfg.api_key, cfg.model, cfg.timeout_ms);
  }
  return std::make_unique<StubEmbeddingProvider>();
}

// ===========================================================================
// Source Loading
// ===========================================================================

/**
 * @brief Load enabled sources from rag_sources table
 *
 * Queries the rag_sources table and parses all enabled sources
 * into RagSource structs. Validates JSON configurations.
 *
 * @param db SQLite database connection
 * @return std::vector<RagSource> Vector of enabled source configurations
 *
 * @note On JSON parsing error, calls fatal() to terminate.
 * @note Only sources with enabled=1 are loaded.
 */
static std::vector<RagSource> load_sources(sqlite3* db) {
  std::vector<RagSource> out;

  const char* sql =
    "SELECT source_id, name, enabled, "
    "backend_type, backend_host, backend_port, backend_user, backend_pass, backend_db, "
    "table_name, pk_column, COALESCE(where_sql,''), "
    "doc_map_json, chunking_json, COALESCE(embedding_json,'') "
    "FROM rag_sources WHERE enabled = 1";

  sqlite3_stmt* st = nullptr;
  sqlite_prepare_or_die(db, &st, sql);

  while (sqlite3_step(st) == SQLITE_ROW) {
    RagSource s;
    s.source_id = sqlite3_column_int(st, 0);
    s.name      = str_or_empty((const char*)sqlite3_column_text(st, 1));
    s.enabled   = sqlite3_column_int(st, 2);

    s.backend_type = str_or_empty((const char*)sqlite3_column_text(st, 3));
    s.host         = str_or_empty((const char*)sqlite3_column_text(st, 4));
    s.port         = sqlite3_column_int(st, 5);
    s.user         = str_or_empty((const char*)sqlite3_column_text(st, 6));
    s.pass         = str_or_empty((const char*)sqlite3_column_text(st, 7));
    s.db           = str_or_empty((const char*)sqlite3_column_text(st, 8));

    s.table_name   = str_or_empty((const char*)sqlite3_column_text(st, 9));
    s.pk_column    = str_or_empty((const char*)sqlite3_column_text(st, 10));
    s.where_sql    = str_or_empty((const char*)sqlite3_column_text(st, 11));

    const char* doc_map = (const char*)sqlite3_column_text(st, 12);
    const char* chunk_j = (const char*)sqlite3_column_text(st, 13);
    const char* emb_j   = (const char*)sqlite3_column_text(st, 14);

    try {
      s.doc_map_json = json::parse(doc_map ? doc_map : "{}");
      s.chunking_json = json::parse(chunk_j ? chunk_j : "{}");
      if (emb_j && std::strlen(emb_j) > 0) s.embedding_json = json::parse(emb_j);
      else s.embedding_json = json(); // null
    } catch (const std::exception& e) {
      sqlite3_finalize(st);
      fatal("Invalid JSON in rag_sources.source_id=" + std::to_string(s.source_id) + ": " + e.what());
    }

    // Basic validation (fail fast)
    if (!s.doc_map_json.is_object()) {
      sqlite3_finalize(st);
      fatal("doc_map_json must be a JSON object for source_id=" + std::to_string(s.source_id));
    }
    if (!s.chunking_json.is_object()) {
      sqlite3_finalize(st);
      fatal("chunking_json must be a JSON object for source_id=" + std::to_string(s.source_id));
    }

    out.push_back(std::move(s));
  }

  sqlite3_finalize(st);
  return out;
}

// ===========================================================================
// Document Building
// ===========================================================================

/**
 * @brief Canonical document representation
 *
 * Contains all fields of a document in its canonical form,
 * ready for insertion into rag_documents and chunking.
 */
struct BuiltDoc {
  std::string doc_id;          ///< Unique document identifier
  std::string pk_json;         ///< Primary key JSON (for refetch)
  std::string title;           ///< Document title
  std::string body;            ///< Document body (to be chunked)
  std::string metadata_json;   ///< Metadata JSON object
};

/**
 * @brief Build canonical document from source row
 *
 * Transforms a raw backend row into a canonical document using
 * the doc_map_json specification. Handles doc_id formatting,
 * title/body concatenation, and metadata building.
 *
 * @param src Source configuration with doc_map_json
 * @param row Raw row data from backend
 * @return BuiltDoc Canonical document representation
 */
static BuiltDoc build_document_from_row(const RagSource& src, const RowMap& row) {
  BuiltDoc d;

  // Build doc_id from format template
  if (src.doc_map_json.contains("doc_id") && src.doc_map_json["doc_id"].is_object()
      && src.doc_map_json["doc_id"].contains("format") && src.doc_map_json["doc_id"]["format"].is_string()) {
    d.doc_id = apply_format(src.doc_map_json["doc_id"]["format"].get<std::string>(), row);
  } else {
    // Fallback: table:pk format
    auto pk = row_get(row, src.pk_column).value_or("");
    d.doc_id = src.table_name + ":" + pk;
  }

  // Build pk_json (refetch pointer)
  json pk = json::object();
  pk[src.pk_column] = row_get(row, src.pk_column).value_or("");
  d.pk_json = json_dump_compact(pk);

  // Build title from concat spec
  if (src.doc_map_json.contains("title") && src.doc_map_json["title"].is_object()
      && src.doc_map_json["title"].contains("concat")) {
    d.title = eval_concat(src.doc_map_json["title"]["concat"], row, "", false);
  } else {
    d.title = "";
  }

  // Build body from concat spec
  if (src.doc_map_json.contains("body") && src.doc_map_json["body"].is_object()
      && src.doc_map_json["body"].contains("concat")) {
    d.body = eval_concat(src.doc_map_json["body"]["concat"], row, "", false);
  } else {
    d.body = "";
  }

  // Build metadata JSON
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

/**
 * @brief Build embedding input text for a chunk
 *
 * Constructs the text to be embedded by applying the embedding_json
 * input specification. Typically includes title, tags, and chunk body.
 *
 * @param ecfg Embedding configuration
 * @param row Source row data (for column values)
 * @param chunk_body Chunk body text
 * @return std::string Text to embed (empty if embedding disabled)
 */
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
// Statement Preparation
// ===========================================================================

/**
 * @brief Prepare all SQLite statements for ingestion
 *
 * Creates prepared statements for document existence check,
 * document insertion, chunk insertion, FTS insertion, and
 * optionally vector insertion.
 *
 * @param db SQLite database connection
 * @param want_vec Whether to prepare vector insert statement
 * @return SqliteStmts Collection of prepared statements
 *
 * @note On failure, calls fatal() to terminate.
 */
static SqliteStmts prepare_sqlite_statements(sqlite3* db, bool want_vec) {
  SqliteStmts ss;

  // Existence check
  sqlite_prepare_or_die(db, &ss.doc_exists,
    "SELECT 1 FROM rag_documents WHERE doc_id = ? LIMIT 1");

  // Insert document (v0: no upsert)
  sqlite_prepare_or_die(db, &ss.ins_doc,
    "INSERT INTO rag_documents(doc_id, source_id, source_name, pk_json, title, body, metadata_json) "
    "VALUES(?,?,?,?,?,?,?)");

  // Insert chunk
  sqlite_prepare_or_die(db, &ss.ins_chunk,
    "INSERT INTO rag_chunks(chunk_id, doc_id, source_id, chunk_index, title, body, metadata_json) "
    "VALUES(?,?,?,?,?,?,?)");

  // Insert FTS
  sqlite_prepare_or_die(db, &ss.ins_fts,
    "INSERT INTO rag_fts_chunks(chunk_id, title, body) VALUES(?,?,?)");

  // Insert vector (optional)
  if (want_vec) {
    sqlite_prepare_or_die(db, &ss.ins_vec,
      "INSERT INTO rag_vec_chunks(embedding, chunk_id, doc_id, source_id, updated_at) "
      "VALUES(?,?,?,?,?)");
  }

  return ss;
}

// ===========================================================================
// Source Ingestion
// ===========================================================================

/**
 * @brief Ingest data from a single source
 *
 * Main ingestion function for a single source. Performs the following:
 * 1. Parse chunking and embedding configurations
 * 2. Load sync cursor (watermark)
 * 3. Connect to backend
 * 4. Build and execute SELECT query with incremental filter
 * 5. For each row: build document, check existence, insert, chunk, embed
 * 6. Update sync cursor with max watermark value
 *
 * @param sdb SQLite database connection
 * @param src Source configuration
 *
 * @note Only "mysql" backend_type is supported in v0.
 * @note Skips documents that already exist (no update in v0).
 * @note All inserts happen in a single transaction (managed by caller).
 */
static void ingest_source(sqlite3* sdb, const RagSource& src) {
  std::cerr << "Ingesting source_id=" << src.source_id
            << " name=" << src.name
            << " backend=" << src.backend_type
            << " table=" << src.table_name << "\n";

  // v0 only supports MySQL
  if (src.backend_type != "mysql") {
    std::cerr << "  Skipping: backend_type not supported in v0.\n";
    return;
  }

  // Parse configurations
  ChunkingConfig ccfg = parse_chunking_json(src.chunking_json);
  EmbeddingConfig ecfg = parse_embedding_json(src.embedding_json);
  std::unique_ptr<EmbeddingProvider> embedder;
  if (ecfg.enabled) {
    embedder = build_embedding_provider(ecfg);
  }

  // Load sync cursor (watermark for incremental sync)
  json cursor_json = load_sync_cursor_json(sdb, src.source_id);
  SyncCursor cursor = parse_sync_cursor(cursor_json, src.pk_column);

  // Prepare SQLite statements
  SqliteStmts ss = prepare_sqlite_statements(sdb, ecfg.enabled);

  // Connect to MySQL
  MYSQL* mdb = mysql_connect_or_die(src);

  // Build SELECT with incremental filter
  std::vector<std::string> cols = collect_needed_columns(src, ecfg);
  if (!cursor.column.empty()) add_unique(cols, cursor.column);
  std::string extra_filter = build_incremental_filter(cursor);
  std::string sel = build_select_sql(src, cols, extra_filter);

  if (mysql_query(mdb, sel.c_str()) != 0) {
    std::string err = mysql_error(mdb);
    mysql_close(mdb);
    sqlite_finalize_all(ss);
    fatal("MySQL query failed: " + err + "\nSQL: " + sel);
  }

  MYSQL_RES* res = mysql_store_result(mdb);
  if (!res) {
    std::string err = mysql_error(mdb);
    mysql_close(mdb);
    sqlite_finalize_all(ss);
    fatal("mysql_store_result failed: " + err);
  }

  std::uint64_t ingested_docs = 0;
  std::uint64_t skipped_docs = 0;

  // Track max watermark value (for next run)
  MYSQL_ROW r;
  bool max_set = false;
  bool max_numeric = false;
  std::int64_t max_num = 0;
  std::string max_str;

  // Process each row
  while ((r = mysql_fetch_row(res)) != nullptr) {
    RowMap row = mysql_row_to_map(res, r);

    // Track max watermark value (even for skipped docs)
    if (!cursor.column.empty()) {
      auto it = row.find(cursor.column);
      if (it != row.end()) {
        const std::string& v = it->second;
        if (!v.empty()) {
          if (!max_set) {
            // First value - determine type and store
            if (cursor.numeric || is_integer_string(v)) {
              try {
                max_numeric = true;
                max_num = std::stoll(v);
              } catch (const std::out_of_range& e) {
                // Huge integer - fall back to string comparison
                max_numeric = false;
                max_str = v;
              } catch (const std::invalid_argument& e) {
                // Not actually a number despite is_integer_string check
                max_numeric = false;
                max_str = v;
              }
            } else {
              max_numeric = false;
              max_str = v;
            }
            max_set = true;
          } else if (max_numeric) {
            // Already numeric - try to compare as number
            if (is_integer_string(v)) {
              try {
                std::int64_t nv = std::stoll(v);
                if (nv > max_num) max_num = nv;
              } catch (const std::out_of_range& e) {
                // Huge integer - fall back to string comparison
                max_numeric = false;
                max_str = v;
              } catch (const std::invalid_argument& e) {
                // Not actually a number - skip this value
              }
            }
          } else {
            // Already string - lexicographic comparison
            if (v > max_str) max_str = v;
          }
        }
      }
    }

    // Build document from row
    BuiltDoc doc = build_document_from_row(src, row);

    // v0: Skip if document already exists
    if (sqlite_doc_exists(ss, doc.doc_id)) {
      skipped_docs++;
      continue;
    }

    // Insert document
    sqlite_insert_doc(ss, src.source_id, src.name,
                      doc.doc_id, doc.pk_json, doc.title, doc.body, doc.metadata_json);

    // Chunk document body
    std::vector<std::string> chunks = chunk_text_chars(doc.body, ccfg);

    // Note: updated_at is set to 0 for v0. For accurate timestamps,
    // query SELECT unixepoch() once at the start of main().
    std::int64_t now_epoch = 0;

    // Process each chunk
    for (size_t i = 0; i < chunks.size(); i++) {
      std::string chunk_id = doc.doc_id + "#" + std::to_string(i);

      // Chunk metadata (minimal - just index)
      json cmeta = json::object();
      cmeta["chunk_index"] = (int)i;

      // Use document title as chunk title (simple approach)
      std::string chunk_title = doc.title;

      // Insert chunk
      sqlite_insert_chunk(ss, chunk_id, doc.doc_id, src.source_id, (int)i,
                          chunk_title, chunks[i], json_dump_compact(cmeta));

      // Insert into FTS index
      sqlite_insert_fts(ss, chunk_id, chunk_title, chunks[i]);

      // Generate and insert embedding (if enabled)
      if (ecfg.enabled) {
        std::string emb_input = build_embedding_input(ecfg, row, chunks[i]);
        std::vector<std::string> batch_inputs = {emb_input};
        std::vector<std::vector<float>> vecs = embedder->embed(batch_inputs, ecfg.dim);
        sqlite_insert_vec(ss, vecs[0], chunk_id, doc.doc_id, src.source_id, now_epoch);
      }
    }

    ingested_docs++;
    if (ingested_docs % 1000 == 0) {
      std::cerr << "  progress: ingested_docs=" << ingested_docs
                << " skipped_docs=" << skipped_docs << "\n";
    }
  }

  // Cleanup
  mysql_free_result(res);
  mysql_close(mdb);
  sqlite_finalize_all(ss);

  // Update sync cursor with max watermark value
  if (!cursor_json.is_object()) cursor_json = json::object();
  if (!cursor.column.empty()) cursor_json["column"] = cursor.column;
  if (max_set) {
    if (max_numeric) {
      cursor_json["value"] = max_num;
    } else {
      cursor_json["value"] = max_str;
    }
  }
  update_sync_state(sdb, src.source_id, cursor_json);

  std::cerr << "Done source " << src.name
            << " ingested_docs=" << ingested_docs
            << " skipped_docs=" << skipped_docs << "\n";
}

// ===========================================================================
// Main Entry Point
// ===========================================================================

/**
 * @brief Main entry point for RAG ingestion tool
 *
 * Entry point for the RAG ingestion tool. Orchestrates the entire
 * ingestion process:
 *
 * 1. Validates command-line arguments
 * 2. Initializes libcurl
 * 3. Opens SQLite RAG index database
 * 4. Loads sqlite3-vec extension (if configured)
 * 5. Sets SQLite pragmas (foreign keys, WAL mode)
 * 6. Begins transaction
 * 7. Loads and ingests all enabled sources
 * 8. Commits or rolls back transaction
 * 9. Cleanup and exit
 *
 * @param argc Argument count
 * @param argv Argument values
 * @return int Exit code (0 on success, 1 on error, 2 on usage error)
 *
 * Usage:
 * @verbatim
 * ./rag_ingest /path/to/rag_index.sqlite
 * @endverbatim
 */
int main(int argc, char** argv) {
  // Validate arguments
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <sqlite_db_path>\n";
    return 2;
  }

  // Initialize libcurl (for embedding API calls)
  curl_global_init(CURL_GLOBAL_DEFAULT);

  const char* sqlite_path = argv[1];

  // Open SQLite database
  sqlite3* db = nullptr;
  if (sqlite3_open(sqlite_path, &db) != SQLITE_OK) {
    fatal("Could not open SQLite DB: " + std::string(sqlite_path));
  }

  // Load sqlite3-vec extension if configured
  sqlite_load_vec_extension(db);

  // Set safe SQLite pragmas
  sqlite_exec(db, "PRAGMA foreign_keys = ON;");
  sqlite_exec(db, "PRAGMA journal_mode = WAL;");
  sqlite_exec(db, "PRAGMA synchronous = NORMAL;");

  // Begin single transaction for speed
  if (sqlite_exec(db, "BEGIN IMMEDIATE;") != SQLITE_OK) {
    sqlite3_close(db);
    fatal("Failed to begin transaction");
  }

  bool ok = true;
  try {
    // Load and ingest all enabled sources
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

  // Commit or rollback
  if (ok) {
    if (sqlite_exec(db, "COMMIT;") != SQLITE_OK) {
      sqlite_exec(db, "ROLLBACK;");
      sqlite3_close(db);
      fatal("Failed to commit transaction");
    }
  } else {
    sqlite_exec(db, "ROLLBACK;");
    sqlite3_close(db);
    curl_global_cleanup();
    return 1;
  }

  // Cleanup
  sqlite3_close(db);
  curl_global_cleanup();
  return 0;
}
