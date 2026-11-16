#pragma once
#include "Embedded_Execution.h"
#include <functional>
#include <string>
struct sqlite3;
namespace embedded {
enum class SQLSourceDialect { mysql, postgresql };
bool sqlite_prepared_function_allowed(const std::string& name);
// The connection and callbacks must outlive this policy. Calls are synchronous.
//
// This policy authorizes the source AST and transaction state; it is not a
// sandbox for arbitrary native callback implementations. The connection provider
// must maintain standard, immutable SQLite built-ins: no overrides of the
// allowed names, and no unsafe extension or UDF reachable indirectly through a
// view or trigger. In particular, extension loading and process autoextensions
// are the provider's responsibility. This policy does not install an authorizer.
//
// Allowed function names (case-insensitive): count, sum, avg, min, max, abs,
// round, length, lower, upper, coalesce, ifnull, nullif, substr, substring,
// hex, typeof, sqlite_version, last_insert_rowid, changes, total_changes,
// date, time, datetime, julianday, strftime, printf, random, randomblob,
// zeroblob, json, json_array, json_object, json_quote, json_extract,
// json_array_length, json_type, json_valid, json_error_position, json_pretty,
// jsonb, jsonb_array, jsonb_object, jsonb_extract. The native SQLite build
// determines whether an admitted function exists.
class SQLitePolicy final : public EndpointPolicy {
public:
 SQLitePolicy(sqlite3* connection, std::function<bool()> client_autocommit,
              std::function<bool()> read_only = [] { return false; },
              SQLSourceDialect dialect = SQLSourceDialect::mysql);
 Status authorize_prepare(const std::string&) override;
 Status authorize_execute(const std::string&, const std::vector<Value>&) override;
 Status authorize_fetch(const std::string&) override;
private:
 Status admit(const std::string&, bool fetch);
 SQLSourceDialect dialect_;
 sqlite3* connection_;
 std::function<bool()> autocommit_, read_only_;
 std::string cached_sql_;
 Status cached_status_;
 bool cached_ = false, cached_select_ = false;
};
}
