// rag_ingest.cpp
//
// ------------------------------------------------------------
// ProxySQL RAG Ingestion PoC (General-Purpose)
// ------------------------------------------------------------
//
// What this program does (v0):
//   1) Opens the SQLite "RAG index" database (schema.sql must already be applied).
//   2) Reads enabled sources from rag_sources.
//   3) For each source:
//        - Connects to MySQL (for now).
//        - Builds a SELECT that fetches only needed columns.
//        - For each row:
//            * Builds doc_id / title / body / metadata_json using doc_map_json.
//            * Chunks body using chunking_json.
//            * Inserts into:
//                  rag_documents
//                  rag_chunks
//                  rag_fts_chunks (FTS5 contentless table)
//            * Optionally builds embedding input text using embedding_json and inserts
//              embeddings into rag_vec_chunks (sqlite3-vec) via a stub embedding provider.
//        - Skips docs that already exist (v0 requirement).
//
// Later (v1+):
//   - Add rag_sync_state usage for incremental ingestion (watermark/CDC).
//   - Add hashing to detect changed docs/chunks and update/reindex accordingly.
//   - Replace the embedding stub with a real embedding generator.
//
// ------------------------------------------------------------
// Dependencies
// ------------------------------------------------------------
//   - sqlite3
//   - MySQL client library (mysqlclient / libmysqlclient)
//   - nlohmann/json (single header json.hpp)
//
// Build example (Linux/macOS):
//   g++ -std=c++17 -O2 rag_ingest.cpp -o rag_ingest \
//       -lsqlite3 -lmysqlclient
//
// Usage:
//   ./rag_ingest /path/to/rag_index.sqlite
//
// Notes:
//   - This is a blueprint-grade PoC, written to be readable and modifiable.
//   - It uses a conservative JSON mapping language so ingestion is deterministic.
//   - It avoids advanced C++ patterns on purpose.
//
// ------------------------------------------------------------
// Supported JSON Specs
// ------------------------------------------------------------
//
// doc_map_json (required):
//   {
//     "doc_id": { "format": "posts:{Id}" },
//     "title":  { "concat": [ {"col":"Title"} ] },
//     "body":   { "concat": [ {"col":"Body"} ] },
//     "metadata": {
//       "pick": ["Id","Tags","Score","CreaionDate"],
//       "rename": {"CreaionDate":"CreationDate"}
//     }
//   }
//
// chunking_json (required, v0 chunks doc "body" only):
//   {
//     "enabled": true,
//     "unit": "chars",         // v0 supports "chars" only
//     "chunk_size": 4000,
//     "overlap": 400,
//     "min_chunk_size": 800
//   }
//
// embedding_json (optional):
//   {
//     "enabled": true,
//     "dim": 1536,
//     "model": "text-embedding-3-large",  // informational
//     "input": { "concat": [
//        {"col":"Title"},
//        {"lit":"\nTags: "}, {"col":"Tags"},
//        {"lit":"\n\n"},
//        {"chunk_body": true}
//     ]}
//   }
//
// ------------------------------------------------------------
// sqlite3-vec binding note
// ------------------------------------------------------------
// sqlite3-vec "vec0(embedding float[N])" generally expects a vector value.
// The exact binding format can vary by build/config of sqlite3-vec.
// This program includes a "best effort" binder that binds a float array as a BLOB.
// If your sqlite3-vec build expects a different representation (e.g. a function to
// pack vectors), adapt bind_vec_embedding() accordingly.
// ------------------------------------------------------------

#include <sqlite3.h>
#include <mysql/mysql.h>

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

// -------------------------
// Small helpers
// -------------------------

static void fatal(const std::string& msg) {
  std::cerr << "FATAL: " << msg << "\n";
  std::exit(1);
}

static std::string str_or_empty(const char* p) {
  return p ? std::string(p) : std::string();
}

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

static std::string json_dump_compact(const json& j) {
  // Compact output (no pretty printing) to keep storage small.
  return j.dump();
}

// -------------------------
// Data model
// -------------------------

struct RagSource {
  int source_id = 0;
  std::string name;
  int enabled = 0;

  // backend connection
  std::string backend_type;  // "mysql" for now
  std::string host;
  int port = 3306;
  std::string user;
  std::string pass;
  std::string db;

  // table
  std::string table_name;
  std::string pk_column;
  std::string where_sql; // optional

  // transformation config
  json doc_map_json;
  json chunking_json;
  json embedding_json; // optional; may be null/object
};

struct ChunkingConfig {
  bool enabled = true;
  std::string unit = "chars"; // v0 only supports chars
  int chunk_size = 4000;
  int overlap = 400;
  int min_chunk_size = 800;
};

struct EmbeddingConfig {
  bool enabled = false;
  int dim = 1536;
  std::string model = "unknown";
  json input_spec; // expects {"concat":[...]}
};

// A row fetched from MySQL, as a name->string map.
typedef std::unordered_map<std::string, std::string> RowMap;

// -------------------------
// JSON parsing
// -------------------------

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

  // v0 only supports chars
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

  if (cfg.dim <= 0) cfg.dim = 1536;
  return cfg;
}

// -------------------------
// Row access
// -------------------------

static std::optional<std::string> row_get(const RowMap& row, const std::string& key) {
  auto it = row.find(key);
  if (it == row.end()) return std::nullopt;
  return it->second;
}

// -------------------------
// doc_id.format implementation
// -------------------------
// Replaces occurrences of {ColumnName} with the value from the row map.
// Example: "posts:{Id}" -> "posts:12345"
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

// -------------------------
// concat spec implementation
// -------------------------
// Supported elements in concat array:
//   {"col":"Title"}          -> append row["Title"] if present
//   {"lit":"\n\n"}           -> append literal
//   {"chunk_body": true}     -> append chunk body (only in embedding_json input)
//
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

// -------------------------
// metadata builder
// -------------------------
// metadata spec:
//   "metadata": { "pick":[...], "rename":{...} }
static json build_metadata(const json& meta_spec, const RowMap& row) {
  json meta = json::object();

  if (meta_spec.is_object()) {
    // pick fields
    if (meta_spec.contains("pick") && meta_spec["pick"].is_array()) {
      for (const auto& colv : meta_spec["pick"]) {
        if (!colv.is_string()) continue;
        std::string col = colv.get<std::string>();
        auto v = row_get(row, col);
        if (v.has_value()) meta[col] = v.value();
      }
    }

    // rename keys
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

// -------------------------
// Chunking (chars-based)
// -------------------------

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

// -------------------------
// MySQL helpers
// -------------------------

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

// Collect columns used by doc_map_json + embedding_json so SELECT is minimal.
// v0: we intentionally keep this conservative (include pk + all referenced col parts + metadata.pick).
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

  // doc_id.format: we do not try to parse all placeholders; best practice is doc_id uses pk only.
  // If you want doc_id.format to reference other columns, include them in metadata.pick or concat.

  return cols;
}

static std::string build_select_sql(const RagSource& s, const std::vector<std::string>& cols) {
  std::string sql = "SELECT ";
  for (size_t i = 0; i < cols.size(); i++) {
    if (i) sql += ", ";
    sql += "`" + cols[i] + "`";
  }
  sql += " FROM `" + s.table_name + "`";
  if (!s.where_sql.empty()) {
    sql += " WHERE " + s.where_sql;
  }
  return sql;
}

// -------------------------
// SQLite prepared statements (batched insertion)
// -------------------------

struct SqliteStmts {
  sqlite3_stmt* doc_exists = nullptr;
  sqlite3_stmt* ins_doc = nullptr;
  sqlite3_stmt* ins_chunk = nullptr;
  sqlite3_stmt* ins_fts = nullptr;
  sqlite3_stmt* ins_vec = nullptr; // optional (only used if embedding enabled)
};

static void sqlite_prepare_or_die(sqlite3* db, sqlite3_stmt** st, const char* sql) {
  if (sqlite3_prepare_v2(db, sql, -1, st, nullptr) != SQLITE_OK) {
    fatal(std::string("SQLite prepare failed: ") + sqlite3_errmsg(db) + "\nSQL: " + sql);
  }
}

static void sqlite_finalize_all(SqliteStmts& s) {
  if (s.doc_exists) sqlite3_finalize(s.doc_exists);
  if (s.ins_doc) sqlite3_finalize(s.ins_doc);
  if (s.ins_chunk) sqlite3_finalize(s.ins_chunk);
  if (s.ins_fts) sqlite3_finalize(s.ins_fts);
  if (s.ins_vec) sqlite3_finalize(s.ins_vec);
  s = SqliteStmts{};
}

static void sqlite_bind_text(sqlite3_stmt* st, int idx, const std::string& v) {
  sqlite3_bind_text(st, idx, v.c_str(), -1, SQLITE_TRANSIENT);
}

// Best-effort binder for sqlite3-vec embeddings (float32 array).
// If your sqlite3-vec build expects a different encoding, change this function only.
static void bind_vec_embedding(sqlite3_stmt* st, int idx, const std::vector<float>& emb) {
  const void* data = (const void*)emb.data();
  int bytes = (int)(emb.size() * sizeof(float));
  sqlite3_bind_blob(st, idx, data, bytes, SQLITE_TRANSIENT);
}

// Check if doc exists
static bool sqlite_doc_exists(SqliteStmts& ss, const std::string& doc_id) {
  sqlite3_reset(ss.doc_exists);
  sqlite3_clear_bindings(ss.doc_exists);

  sqlite_bind_text(ss.doc_exists, 1, doc_id);

  int rc = sqlite3_step(ss.doc_exists);
  return (rc == SQLITE_ROW);
}

// Insert doc
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

  sqlite_bind_text(ss.ins_doc, 1, doc_id);
  sqlite3_bind_int(ss.ins_doc, 2, source_id);
  sqlite_bind_text(ss.ins_doc, 3, source_name);
  sqlite_bind_text(ss.ins_doc, 4, pk_json);
  sqlite_bind_text(ss.ins_doc, 5, title);
  sqlite_bind_text(ss.ins_doc, 6, body);
  sqlite_bind_text(ss.ins_doc, 7, meta_json);

  int rc = sqlite3_step(ss.ins_doc);
  if (rc != SQLITE_DONE) {
    fatal(std::string("SQLite insert rag_documents failed: ") + sqlite3_errmsg(sqlite3_db_handle(ss.ins_doc)));
  }
}

// Insert chunk
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

  sqlite_bind_text(ss.ins_chunk, 1, chunk_id);
  sqlite_bind_text(ss.ins_chunk, 2, doc_id);
  sqlite3_bind_int(ss.ins_chunk, 3, source_id);
  sqlite3_bind_int(ss.ins_chunk, 4, chunk_index);
  sqlite_bind_text(ss.ins_chunk, 5, title);
  sqlite_bind_text(ss.ins_chunk, 6, body);
  sqlite_bind_text(ss.ins_chunk, 7, meta_json);

  int rc = sqlite3_step(ss.ins_chunk);
  if (rc != SQLITE_DONE) {
    fatal(std::string("SQLite insert rag_chunks failed: ") + sqlite3_errmsg(sqlite3_db_handle(ss.ins_chunk)));
  }
}

// Insert into FTS
static void sqlite_insert_fts(SqliteStmts& ss,
                              const std::string& chunk_id,
                              const std::string& title,
                              const std::string& body) {
  sqlite3_reset(ss.ins_fts);
  sqlite3_clear_bindings(ss.ins_fts);

  sqlite_bind_text(ss.ins_fts, 1, chunk_id);
  sqlite_bind_text(ss.ins_fts, 2, title);
  sqlite_bind_text(ss.ins_fts, 3, body);

  int rc = sqlite3_step(ss.ins_fts);
  if (rc != SQLITE_DONE) {
    fatal(std::string("SQLite insert rag_fts_chunks failed: ") + sqlite3_errmsg(sqlite3_db_handle(ss.ins_fts)));
  }
}

// Insert vector row (sqlite3-vec)
// Schema: rag_vec_chunks(embedding, chunk_id, doc_id, source_id, updated_at)
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
  sqlite_bind_text(ss.ins_vec, 2, chunk_id);
  sqlite_bind_text(ss.ins_vec, 3, doc_id);
  sqlite3_bind_int(ss.ins_vec, 4, source_id);
  sqlite3_bind_int64(ss.ins_vec, 5, (sqlite3_int64)updated_at_unixepoch);

  int rc = sqlite3_step(ss.ins_vec);
  if (rc != SQLITE_DONE) {
    // In practice, sqlite3-vec may return errors if binding format is wrong.
    // Keep the message loud and actionable.
    fatal(std::string("SQLite insert rag_vec_chunks failed (check vec binding format): ")
          + sqlite3_errmsg(sqlite3_db_handle(ss.ins_vec)));
  }
}

// -------------------------
// Embedding stub
// -------------------------
// This function is a placeholder. It returns a deterministic pseudo-embedding from the text.
// Replace it with a real embedding model call in ProxySQL later.
//
// Why deterministic?
//   - Helps test end-to-end ingestion + vector SQL without needing an ML runtime.
//   - Keeps behavior stable across runs.
//
static std::vector<float> pseudo_embedding(const std::string& text, int dim) {
  std::vector<float> v;
  v.resize((size_t)dim, 0.0f);

  // Simple rolling hash-like accumulation into float bins.
  // NOT a semantic embedding; only for wiring/testing.
  std::uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < text.size(); i++) {
    h ^= (unsigned char)text[i];
    h *= 1099511628211ULL;

    // Spread influence into bins
    size_t idx = (size_t)(h % (std::uint64_t)dim);
    float val = (float)((h >> 32) & 0xFFFF) / 65535.0f; // 0..1
    v[idx] += (val - 0.5f);
  }

  // Very rough normalization
  double norm = 0.0;
  for (int i = 0; i < dim; i++) norm += (double)v[(size_t)i] * (double)v[(size_t)i];
  norm = std::sqrt(norm);
  if (norm > 1e-12) {
    for (int i = 0; i < dim; i++) v[(size_t)i] = (float)(v[(size_t)i] / norm);
  }
  return v;
}

// -------------------------
// Load rag_sources from SQLite
// -------------------------

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
    s.name      = (const char*)sqlite3_column_text(st, 1);
    s.enabled   = sqlite3_column_int(st, 2);

    s.backend_type = (const char*)sqlite3_column_text(st, 3);
    s.host         = (const char*)sqlite3_column_text(st, 4);
    s.port         = sqlite3_column_int(st, 5);
    s.user         = (const char*)sqlite3_column_text(st, 6);
    s.pass         = (const char*)sqlite3_column_text(st, 7);
    s.db           = (const char*)sqlite3_column_text(st, 8);

    s.table_name   = (const char*)sqlite3_column_text(st, 9);
    s.pk_column    = (const char*)sqlite3_column_text(st, 10);
    s.where_sql    = (const char*)sqlite3_column_text(st, 11);

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

// -------------------------
// Build a canonical document from a source row
// -------------------------

struct BuiltDoc {
  std::string doc_id;
  std::string pk_json;
  std::string title;
  std::string body;
  std::string metadata_json;
};

static BuiltDoc build_document_from_row(const RagSource& src, const RowMap& row) {
  BuiltDoc d;

  // doc_id
  if (src.doc_map_json.contains("doc_id") && src.doc_map_json["doc_id"].is_object()
      && src.doc_map_json["doc_id"].contains("format") && src.doc_map_json["doc_id"]["format"].is_string()) {
    d.doc_id = apply_format(src.doc_map_json["doc_id"]["format"].get<std::string>(), row);
  } else {
    // fallback: table:pk
    auto pk = row_get(row, src.pk_column).value_or("");
    d.doc_id = src.table_name + ":" + pk;
  }

  // pk_json (refetch pointer)
  json pk = json::object();
  pk[src.pk_column] = row_get(row, src.pk_column).value_or("");
  d.pk_json = json_dump_compact(pk);

  // title/body
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

  // metadata_json
  json meta = json::object();
  if (src.doc_map_json.contains("metadata")) {
    meta = build_metadata(src.doc_map_json["metadata"], row);
  }
  d.metadata_json = json_dump_compact(meta);

  return d;
}

// -------------------------
// Embedding input builder (optional)
// -------------------------

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

// -------------------------
// Ingest one source
// -------------------------

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
    // NOTE: If your sqlite3-vec build expects different binding format, adapt bind_vec_embedding().
    sqlite_prepare_or_die(db, &ss.ins_vec,
      "INSERT INTO rag_vec_chunks(embedding, chunk_id, doc_id, source_id, updated_at) "
      "VALUES(?,?,?,?,?)");
  }

  return ss;
}

static void ingest_source(sqlite3* sdb, const RagSource& src) {
  std::cerr << "Ingesting source_id=" << src.source_id
            << " name=" << src.name
            << " backend=" << src.backend_type
            << " table=" << src.table_name << "\n";

  if (src.backend_type != "mysql") {
    std::cerr << "  Skipping: backend_type not supported in v0.\n";
    return;
  }

  // Parse chunking & embedding config
  ChunkingConfig ccfg = parse_chunking_json(src.chunking_json);
  EmbeddingConfig ecfg = parse_embedding_json(src.embedding_json);

  // Prepare SQLite statements for this run
  SqliteStmts ss = prepare_sqlite_statements(sdb, ecfg.enabled);

  // Connect MySQL
  MYSQL* mdb = mysql_connect_or_die(src);

  // Build SELECT
  std::vector<std::string> cols = collect_needed_columns(src, ecfg);
  std::string sel = build_select_sql(src, cols);

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

  MYSQL_ROW r;
  while ((r = mysql_fetch_row(res)) != nullptr) {
    RowMap row = mysql_row_to_map(res, r);

    BuiltDoc doc = build_document_from_row(src, row);

    // v0: skip if exists
    if (sqlite_doc_exists(ss, doc.doc_id)) {
      skipped_docs++;
      continue;
    }

    // Insert document
    sqlite_insert_doc(ss, src.source_id, src.name,
                      doc.doc_id, doc.pk_json, doc.title, doc.body, doc.metadata_json);

    // Chunk and insert chunks + FTS (+ optional vec)
    std::vector<std::string> chunks = chunk_text_chars(doc.body, ccfg);

    // Use SQLite's unixepoch() for updated_at normally; vec table also stores updated_at as unix epoch.
    // Here we store a best-effort "now" from SQLite (unixepoch()) would require a query; instead store 0
    // or a local time. For v0, we store 0 and let schema default handle other tables.
    // If you want accuracy, query SELECT unixepoch() once per run and reuse it.
    std::int64_t now_epoch = 0;

    for (size_t i = 0; i < chunks.size(); i++) {
      std::string chunk_id = doc.doc_id + "#" + std::to_string(i);

      // Chunk metadata (minimal)
      json cmeta = json::object();
      cmeta["chunk_index"] = (int)i;

      std::string chunk_title = doc.title; // simple: repeat doc title

      sqlite_insert_chunk(ss, chunk_id, doc.doc_id, src.source_id, (int)i,
                          chunk_title, chunks[i], json_dump_compact(cmeta));

      sqlite_insert_fts(ss, chunk_id, chunk_title, chunks[i]);

      // Optional vectors
      if (ecfg.enabled) {
        // Build embedding input text, then generate pseudo embedding.
        // Replace pseudo_embedding() with a real embedding provider in ProxySQL.
        std::string emb_input = build_embedding_input(ecfg, row, chunks[i]);
        std::vector<float> emb = pseudo_embedding(emb_input, ecfg.dim);

        // Insert into sqlite3-vec table
        sqlite_insert_vec(ss, emb, chunk_id, doc.doc_id, src.source_id, now_epoch);
      }
    }

    ingested_docs++;
    if (ingested_docs % 1000 == 0) {
      std::cerr << "  progress: ingested_docs=" << ingested_docs
                << " skipped_docs=" << skipped_docs << "\n";
    }
  }

  mysql_free_result(res);
  mysql_close(mdb);
  sqlite_finalize_all(ss);

  std::cerr << "Done source " << src.name
            << " ingested_docs=" << ingested_docs
            << " skipped_docs=" << skipped_docs << "\n";
}

// -------------------------
// Main
// -------------------------

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <sqlite_db_path>\n";
    return 2;
  }

  const char* sqlite_path = argv[1];

  sqlite3* db = nullptr;
  if (sqlite3_open(sqlite_path, &db) != SQLITE_OK) {
    fatal("Could not open SQLite DB: " + std::string(sqlite_path));
  }

  // Pragmas (safe defaults)
  sqlite_exec(db, "PRAGMA foreign_keys = ON;");
  sqlite_exec(db, "PRAGMA journal_mode = WAL;");
  sqlite_exec(db, "PRAGMA synchronous = NORMAL;");

  // Single transaction for speed
  if (sqlite_exec(db, "BEGIN IMMEDIATE;") != SQLITE_OK) {
    sqlite3_close(db);
    fatal("Failed to begin transaction");
  }

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

  if (ok) {
    if (sqlite_exec(db, "COMMIT;") != SQLITE_OK) {
      sqlite_exec(db, "ROLLBACK;");
      sqlite3_close(db);
      fatal("Failed to commit transaction");
    }
  } else {
    sqlite_exec(db, "ROLLBACK;");
    sqlite3_close(db);
    return 1;
  }

  sqlite3_close(db);
  return 0;
}

