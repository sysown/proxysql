#include "Embedded_SQLite_Adapter.h"

#include "sqlite3db.h"

#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace embedded {
namespace {

constexpr size_t kIntMax = static_cast<size_t>(std::numeric_limits<int>::max());

Error make_error(ErrorKind kind, int native_code, std::string message) {
    return Error{kind, native_code, std::move(message), std::string{}};
}

Status affinity_error() {
    return make_error(ErrorKind::invalid_parameter, 0,
                      "statement does not belong to this adapter/connection");
}

int primary_code(int rc) {
    return rc & 0xff;
}

bool resource_code(int rc) {
    const int code = primary_code(rc);
    return code == SQLITE_NOMEM || code == SQLITE_FULL || code == SQLITE_TOOBIG;
}

ErrorKind prepare_error_kind(int rc) {
    // SQLITE_ERROR covers missing objects and many other native failures, not
    // just syntax. Only a native resource code carries a typed meaning here.
    return resource_code(rc) ? ErrorKind::resource : ErrorKind::engine;
}

ErrorKind step_error_kind(int rc) {
    if (primary_code(rc) == SQLITE_SCHEMA) return ErrorKind::schema_changed;
    return resource_code(rc) ? ErrorKind::resource : ErrorKind::engine;
}

ErrorKind bind_error_kind(int rc) {
    if (primary_code(rc) == SQLITE_RANGE) return ErrorKind::range;
    return resource_code(rc) ? ErrorKind::resource : ErrorKind::engine;
}

Status native_error(ErrorKind kind, sqlite3* db, int rc) {
    std::string message;
    if (db != nullptr && proxy_sqlite3_errmsg != nullptr) message = proxy_sqlite3_errmsg(db);
    if (message.empty() && proxy_sqlite3_errstr != nullptr) message = proxy_sqlite3_errstr(rc);
    if (message.empty()) message = "SQLite error";
    return make_error(kind, rc, std::move(message));
}

// The initial boundary permits only SQLite framing whitespace after the first
// prepared statement. This is deliberately not SQL tokenization: comments,
// extra semicolons, and any second statement are rejected without compiling
// or executing them.
bool is_framing_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
           c == '\v';
}

Status trailing_framing_status(std::string_view rest) {
    for (const char c : rest) {
        if (!is_framing_space(c)) {
            return make_error(ErrorKind::unsupported, 0,
                              "only whitespace may follow the first statement");
        }
    }
    return {};
}

Status reserve_payload(size_t bytes, size_t budget, size_t& used) {
    if (used > budget || bytes > budget - used)
        return make_error(ErrorKind::resource, 0, "row payload exceeds the fetch budget");
    used += bytes;
    return {};
}

char ascii_lower(char c) {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
}

// Exact whole-name comparison, ASCII case-insensitive only. The declared type
// is never trimmed, tokenized, or interpreted as SQLite affinity.
bool ascii_iequals(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        if (ascii_lower(left[i]) != ascii_lower(right[i])) return false;
    }
    return true;
}

TypeKind declared_result_kind(const char* declared) {
    if (declared == nullptr) return TypeKind::dynamic;
    const std::string_view name(declared);
    if (ascii_iequals(name, "BLOB")) return TypeKind::bytes;
    if (ascii_iequals(name, "TEXT")) return TypeKind::text;
    if (ascii_iequals(name, "INTEGER") || ascii_iequals(name, "INT") ||
        ascii_iequals(name, "BIGINT")) {
        return TypeKind::signed_integer;
    }
    if (ascii_iequals(name, "REAL") || ascii_iequals(name, "DOUBLE") ||
        ascii_iequals(name, "FLOAT")) {
        return TypeKind::floating;
    }
    return TypeKind::dynamic;
}

}  // namespace

struct SQLiteAdapter::StatementState final : Statement {
    StatementState(SQLiteAdapter* adapter, sqlite3_stmt* native, int parameters,
                   int columns, std::vector<std::string> names,
                   std::vector<Type> types, ResultProfile result_profile)
        : owner(adapter),
          db(adapter != nullptr ? adapter->connection_ : nullptr),
          stmt(native),
          parameter_count(parameters),
          column_count(columns),
          column_names(std::move(names)),
          column_types(std::move(types)),
          profile(result_profile) {}

    ~StatementState() noexcept override {
        if (stmt != nullptr && proxy_sqlite3_finalize != nullptr)
            proxy_sqlite3_finalize(stmt);
    }

    SQLiteAdapter* owner;
    sqlite3* db;
    sqlite3_stmt* stmt;
    int parameter_count;
    int column_count;
    std::vector<std::string> column_names;
    std::vector<Type> column_types;
    ResultProfile profile;
    bool needs_reset = false;
    bool row_ready = false;
    bool exhausted = false;
    bool active_result = false;
    int pending_step_error = SQLITE_OK;
    bool pending_step_error_reported = false;
};

SQLiteAdapter::SQLiteAdapter(sqlite3* connection, ResultProfile profile,
                             const Command* command) noexcept
    : connection_(connection), profile_(profile), command_(command) {}

SQLiteAdapter::~SQLiteAdapter() = default;

SQLiteAdapter::StatementState* SQLiteAdapter::checked(Statement& statement) const noexcept {
    auto* state = dynamic_cast<StatementState*>(&statement);
    if (state == nullptr || state->owner != this || state->stmt == nullptr ||
        state->db != connection_ || connection_ == nullptr ||
        proxy_sqlite3_db_handle == nullptr ||
        proxy_sqlite3_db_handle(state->stmt) != connection_) {
        return nullptr;
    }
    return state;
}

Status SQLiteAdapter::verify_result_metadata(StatementState& state) const {
    if (proxy_sqlite3_column_count == nullptr ||
        proxy_sqlite3_column_name == nullptr) {
        return make_error(ErrorKind::internal, 0,
                          "result metadata symbols are unavailable");
    }
    if (proxy_sqlite3_column_count(state.stmt) != state.column_count)
        return make_error(ErrorKind::schema_changed, 0,
                          "result column count changed");
    for (int i = 0; i < state.column_count; ++i) {
        const char* name = proxy_sqlite3_column_name(state.stmt, i);
        const std::string current(name != nullptr ? name : "");
        if (current != state.column_names[static_cast<size_t>(i)])
            return make_error(ErrorKind::schema_changed, 0,
                              "result column name changed");
    }
    if (state.profile == ResultProfile::strict_declared) {
        if (proxy_sqlite3_column_decltype == nullptr) {
            return make_error(ErrorKind::unsupported, 0,
                              "SQLite declared-type metadata is unavailable");
        }
        for (int i = 0; i < state.column_count; ++i) {
            const char* declared = proxy_sqlite3_column_decltype(state.stmt, i);
            if (declared_result_kind(declared) !=
                state.column_types[static_cast<size_t>(i)].kind) {
                return make_error(ErrorKind::schema_changed, 0,
                                  "result column declared type changed");
            }
        }
    }
    return {};
}

Status SQLiteAdapter::prepare(const std::string& sql, std::unique_ptr<Statement>& out) {
    out.reset();
    if (connection_ == nullptr)
        return make_error(ErrorKind::internal, 0, "SQLite adapter has no connection");
    if (profile_ == ResultProfile::strict_declared &&
        proxy_sqlite3_column_decltype == nullptr) {
        return make_error(ErrorKind::unsupported, 0,
                          "SQLite declared-type metadata is unavailable");
    }
    if (proxy_sqlite3_prepare_v2 == nullptr || proxy_sqlite3_finalize == nullptr ||
        proxy_sqlite3_column_count == nullptr || proxy_sqlite3_column_name == nullptr ||
        proxy_sqlite3_bind_parameter_count == nullptr ||
        proxy_sqlite3_stmt_readonly == nullptr) {
        return make_error(ErrorKind::internal, 0, "required SQLite symbols are unavailable");
    }
    if (sql.find('\0') != std::string::npos)
        return make_error(ErrorKind::syntax, 0, "embedded NUL in SQL");
    if (sql.size() > kIntMax)
        return make_error(ErrorKind::resource, 0, "SQL exceeds the native length limit");

    sqlite3_stmt* native = nullptr;
    const char* tail = nullptr;
    const int rc = proxy_sqlite3_prepare_v2(connection_, sql.data(),
                                            static_cast<int>(sql.size()), &native, &tail);
    if (rc != SQLITE_OK) {
        if (native != nullptr) proxy_sqlite3_finalize(native);
        return native_error(prepare_error_kind(rc), connection_, rc);
    }
    if (native == nullptr)
        return make_error(ErrorKind::syntax, 0, "no SQL statement to prepare");

    struct NativeGuard {
        sqlite3_stmt*& statement;
        ~NativeGuard() {
            if (statement != nullptr && proxy_sqlite3_finalize != nullptr)
                proxy_sqlite3_finalize(statement);
        }
    } guard{native};

    const char* const begin = sql.data();
    const char* const end = begin + sql.size();
    if (tail == nullptr) tail = end;
    if (tail < begin || tail > end)
        return make_error(ErrorKind::internal, 0, "SQLite returned an invalid prepare tail");
    if (auto err = trailing_framing_status(
            std::string_view(tail, static_cast<size_t>(end - tail))))
        return err;

    const int readonly = proxy_sqlite3_stmt_readonly(native);
    const int columns = proxy_sqlite3_column_count(native);
    if (!command_ && !readonly && columns > 0) {
        return make_error(ErrorKind::unsupported, 0,
                          "write statements with result columns are not supported");
    }

    std::vector<std::string> names;
    std::vector<Type> types;
    names.reserve(static_cast<size_t>(columns));
    types.reserve(static_cast<size_t>(columns));
    for (int i = 0; i < columns; ++i) {
        const char* name = proxy_sqlite3_column_name(native, i);
        names.emplace_back(name != nullptr ? name : "");
        Type type;
        if (profile_ == ResultProfile::strict_declared) {
            type.kind = declared_result_kind(
                proxy_sqlite3_column_decltype(native, i));
        } else {
            type.kind = TypeKind::dynamic;
        }
        type.nullable = true;
        types.push_back(type);
    }

    std::unique_ptr<StatementState> state(new StatementState(
        this, native, proxy_sqlite3_bind_parameter_count(native), columns,
        std::move(names), std::move(types), profile_));
    native = nullptr;
    out.reset(state.release());
    return {};
}

Status SQLiteAdapter::describe_parameters(Statement& statement, std::vector<Type>& out) {
    out.clear();
    StatementState* state = checked(statement);
    if (state == nullptr) return affinity_error();
    out.assign(static_cast<size_t>(state->parameter_count), Type{});
    return {};
}

Status SQLiteAdapter::describe_parameter_positions(Statement& statement, std::vector<uint32_t>& out) {
    out.clear();
    StatementState* state = checked(statement);
    if (!state) return affinity_error();
    if (!proxy_sqlite3_bind_parameter_count)
        return make_error(ErrorKind::internal, 0, "bind parameter count symbol is unavailable");
    const int count = proxy_sqlite3_bind_parameter_count(state->stmt);
    if (count != state->parameter_count)
        return make_error(ErrorKind::schema_changed, 0, "native parameter count changed");
    if (!count) return {};
    if (!proxy_sqlite3_bind_parameter_name)
        return make_error(ErrorKind::unsupported, 0, "bind parameter names unavailable");
    std::vector<uint32_t> positions;
    positions.reserve(static_cast<size_t>(count));
    for (int i = 1; i <= count; ++i) {
        const char* name = proxy_sqlite3_bind_parameter_name(state->stmt, i);
        uint32_t position = 0;
        if (name && name[0] == '$' && name[1]) {
            std::string_view digits(name + 1);
            bool numeric = true;
            for (char c : digits) if (c < '0' || c > '9') { numeric = false; break; }
            if (numeric) {
                auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), position);
                if (parsed.ec == std::errc::result_out_of_range)
                    return make_error(ErrorKind::range, 0, "parameter position out of range");
                if (parsed.ec != std::errc{} || position == 0)
                    return make_error(ErrorKind::invalid_parameter, 0, "invalid parameter position");
            }
        }
        positions.push_back(position);
    }
    out = std::move(positions);
    return {};
}

Status SQLiteAdapter::describe_result(Statement& statement, std::vector<Column>& out) {
    out.clear();
    StatementState* state = checked(statement);
    if (state == nullptr) return affinity_error();
    out.reserve(state->column_names.size());
    for (size_t i = 0; i < state->column_names.size(); ++i) {
        out.push_back(Column{state->column_names[i],
                             state->column_types[i]});
    }
    return {};
}

Status SQLiteAdapter::bind(Statement& statement, const std::vector<Value>& values) {
    StatementState* state = checked(statement);
    if (state == nullptr) return affinity_error();
    if (state->needs_reset)
        return make_error(ErrorKind::invalid_parameter, 0,
                          "statement must be reset before binding");
    if (proxy_sqlite3_bind_parameter_count == nullptr)
        return make_error(ErrorKind::internal, 0, "bind parameter count symbol is unavailable");
    if (proxy_sqlite3_bind_parameter_count(state->stmt) != state->parameter_count)
        return make_error(ErrorKind::schema_changed, 0, "native parameter count changed");
    if (values.size() != static_cast<size_t>(state->parameter_count))
        return make_error(ErrorKind::invalid_parameter, 0, "parameter count mismatch");

    for (size_t index = 0; index < values.size(); ++index) {
        const int native_index = static_cast<int>(index) + 1;
        const Value& value = values[index];
        int rc = SQLITE_OK;

        if (std::holds_alternative<std::monostate>(value)) {
            if (proxy_sqlite3_bind_null == nullptr)
                return make_error(ErrorKind::internal, 0, "bind NULL symbol is unavailable");
            rc = proxy_sqlite3_bind_null(state->stmt, native_index);
        } else if (const auto* signed_value = std::get_if<int64_t>(&value)) {
            if (proxy_sqlite3_bind_int64 == nullptr)
                return make_error(ErrorKind::internal, 0, "bind int64 symbol is unavailable");
            rc = proxy_sqlite3_bind_int64(state->stmt, native_index,
                                          static_cast<sqlite3_int64>(*signed_value));
        } else if (const auto* unsigned_value = std::get_if<uint64_t>(&value)) {
            if (*unsigned_value >
                static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
                return make_error(ErrorKind::range, 0, "uint64 value exceeds INT64_MAX");
            }
            if (proxy_sqlite3_bind_int64 == nullptr)
                return make_error(ErrorKind::internal, 0, "bind int64 symbol is unavailable");
            rc = proxy_sqlite3_bind_int64(state->stmt, native_index,
                                          static_cast<sqlite3_int64>(*unsigned_value));
        } else if (const auto* boolean = std::get_if<bool>(&value)) {
            if (proxy_sqlite3_bind_int64 == nullptr)
                return make_error(ErrorKind::internal, 0, "bind int64 symbol is unavailable");
            rc = proxy_sqlite3_bind_int64(state->stmt, native_index, *boolean ? 1 : 0);
        } else if (const auto* real_value = std::get_if<double>(&value)) {
            if (std::isnan(*real_value))
                return make_error(ErrorKind::invalid_parameter, 0,
                                  "NaN cannot be bound because SQLite converts it to NULL");
            if (proxy_sqlite3_bind_double == nullptr)
                return make_error(ErrorKind::internal, 0, "bind double symbol is unavailable");
            rc = proxy_sqlite3_bind_double(state->stmt, native_index, *real_value);
        } else if (const auto* text = std::get_if<Text>(&value)) {
            if (text->bytes.size() > kIntMax)
                return make_error(ErrorKind::range, 0, "text exceeds the native INT_MAX length");
            if (proxy_sqlite3_bind_text == nullptr)
                return make_error(ErrorKind::internal, 0, "bind text symbol is unavailable");
            const char* data = text->bytes.empty() ? "" : text->bytes.data();
            rc = proxy_sqlite3_bind_text(state->stmt, native_index, data,
                                         static_cast<int>(text->bytes.size()), SQLITE_TRANSIENT);
        } else if (const auto* bytes = std::get_if<Bytes>(&value)) {
            if (bytes->bytes.size() > kIntMax)
                return make_error(ErrorKind::range, 0, "blob exceeds the native INT_MAX length");
            if (proxy_sqlite3_bind_blob == nullptr)
                return make_error(ErrorKind::internal, 0, "bind blob symbol is unavailable");
            static const unsigned char empty_blob = 0;
            const void* data = bytes->bytes.empty()
                                   ? static_cast<const void*>(&empty_blob)
                                   : static_cast<const void*>(bytes->bytes.data());
            rc = proxy_sqlite3_bind_blob(state->stmt, native_index, data,
                                         static_cast<int>(bytes->bytes.size()), SQLITE_TRANSIENT);
        } else if (std::holds_alternative<Decimal>(value)) {
            return make_error(ErrorKind::unsupported, 0,
                              "decimal binding is not supported by this adapter");
        } else {
            return make_error(ErrorKind::unsupported, 0, "unsupported bind value");
        }

        if (rc != SQLITE_OK)
            return native_error(bind_error_kind(rc), connection_, rc);
    }
    return {};
}

Status SQLiteAdapter::execute(Statement& statement, ExecInfo& info) {
    info = {};
    if (command_) info.command = *command_;
    StatementState* state = checked(statement);
    if (state == nullptr) return affinity_error();
    if (proxy_sqlite3_step == nullptr)
        return make_error(ErrorKind::internal, 0, "step symbol is unavailable");
    if (state->needs_reset)
        return make_error(ErrorKind::invalid_parameter, 0,
                          "statement must be reset before execution");
    if (proxy_sqlite3_bind_parameter_count == nullptr ||
        proxy_sqlite3_bind_parameter_count(state->stmt) != state->parameter_count) {
        return make_error(ErrorKind::schema_changed, 0, "native parameter count changed");
    }

    const bool track_changes = state->column_count == 0;
    long long total_before = 0;
    if (track_changes && proxy_sqlite3_total_changes64 != nullptr)
        total_before = proxy_sqlite3_total_changes64(connection_);

    const int rc = proxy_sqlite3_step(state->stmt);
    state->needs_reset = true;
    state->row_ready = false;
    state->exhausted = false;
    state->active_result = false;

    if (rc == SQLITE_ROW) {
        if (state->column_count <= 0) {
            return make_error(ErrorKind::internal, 0,
                              "SQLite returned a row for a statement without columns");
        }
        if (auto err = verify_result_metadata(*state)) return err;
        state->row_ready = true;
        state->active_result = true;
        info.has_result = true;
        info.last_insert_id = 0;
        return {};
    }

    if (rc == SQLITE_DONE) {
        state->exhausted = true;
        if (state->column_count > 0) {
            if (auto err = verify_result_metadata(*state)) return err;
            state->active_result = true;
            info.has_result = true;
        } else if (track_changes && proxy_sqlite3_total_changes64 != nullptr) {
            const long long total_after = proxy_sqlite3_total_changes64(connection_);
            if (total_after > total_before && proxy_sqlite3_changes != nullptr) {
                const int changed = proxy_sqlite3_changes(connection_);
                if (changed > 0) info.affected_rows = static_cast<uint64_t>(changed);
            }
        }
        info.last_insert_id = 0;
        return {};
    }

    state->pending_step_error = rc;
    state->pending_step_error_reported = true;
    return native_error(step_error_kind(rc), connection_, rc);
}

Status SQLiteAdapter::fetch(Statement& statement, Row& row, bool& done, size_t budget) {
    row.clear();
    done = false;
    StatementState* state = checked(statement);
    if (state == nullptr) return affinity_error();
    if (!state->active_result)
        return make_error(ErrorKind::invalid_parameter, 0, "no active result");
    if (proxy_sqlite3_step == nullptr)
        return make_error(ErrorKind::internal, 0, "step symbol is unavailable");

    const auto read_current_row = [&](Row& out) -> Status {
        if (proxy_sqlite3_column_count == nullptr || proxy_sqlite3_column_name == nullptr ||
            proxy_sqlite3_column_type == nullptr || proxy_sqlite3_column_bytes == nullptr ||
            proxy_sqlite3_column_int64 == nullptr || proxy_sqlite3_column_double == nullptr ||
            proxy_sqlite3_column_text == nullptr || proxy_sqlite3_column_blob == nullptr) {
            return make_error(ErrorKind::internal, 0,
                              "result column symbols are unavailable");
        }
        if (auto err = verify_result_metadata(*state)) return err;

        Row result;
        result.reserve(static_cast<size_t>(state->column_count));
        size_t used = 0;
        const auto append = [&](Value value) -> Status {
            if (auto err = reserve_payload(value_payload_bytes(value), budget, used))
                return err;
            result.push_back(std::move(value));
            return {};
        };

        for (int i = 0; i < state->column_count; ++i) {
            // Inspect the original storage class before any column getter that
            // could ask SQLite to coerce it.
            const int type = proxy_sqlite3_column_type(state->stmt, i);
            const Type& advertised = state->column_types[static_cast<size_t>(i)];
            if (advertised.kind != TypeKind::dynamic) {
                if (type == SQLITE_NULL) {
                    if (!advertised.nullable)
                        return make_error(ErrorKind::schema_changed, 0,
                                          "NULL is not allowed by the result profile");
                } else {
                    const bool matches =
                        (advertised.kind == TypeKind::signed_integer &&
                         type == SQLITE_INTEGER) ||
                        (advertised.kind == TypeKind::floating &&
                         type == SQLITE_FLOAT) ||
                        (advertised.kind == TypeKind::text &&
                         type == SQLITE_TEXT) ||
                        (advertised.kind == TypeKind::bytes &&
                         type == SQLITE_BLOB);
                    if (!matches)
                        return make_error(
                            ErrorKind::schema_changed, 0,
                            "native storage class does not match the declared result type");
                }
            }
            Status status;
            if (type == SQLITE_INTEGER) {
                status = append(Value{static_cast<int64_t>(
                    proxy_sqlite3_column_int64(state->stmt, i))});
            } else if (type == SQLITE_FLOAT) {
                status = append(Value{proxy_sqlite3_column_double(state->stmt, i)});
            } else if (type == SQLITE_TEXT) {
                const unsigned char* text = proxy_sqlite3_column_text(state->stmt, i);
                const int native_bytes = proxy_sqlite3_column_bytes(state->stmt, i);
                if (native_bytes < 0)
                    return make_error(ErrorKind::internal, 0, "negative native text length");
                const size_t bytes = static_cast<size_t>(native_bytes);
                if (used > budget || bytes > budget - used)
                    return make_error(ErrorKind::resource, 0,
                                      "row payload exceeds the fetch budget");
                // SQLite reports a conversion or allocation failure as a null
                // text pointer. This includes zero-length text, so a null
                // pointer can never be treated as a successfully empty value.
                if (text == nullptr)
                    return make_error(ErrorKind::internal, 0, "missing native text data");
                std::string copied;
                if (bytes > 0)
                    copied.assign(reinterpret_cast<const char*>(text), bytes);
                status = append(Text{std::move(copied)});
            } else if (type == SQLITE_BLOB) {
                const void* data = proxy_sqlite3_column_blob(state->stmt, i);
                const int native_bytes = proxy_sqlite3_column_bytes(state->stmt, i);
                if (native_bytes < 0)
                    return make_error(ErrorKind::internal, 0, "negative native blob length");
                const size_t bytes = static_cast<size_t>(native_bytes);
                if (used > budget || bytes > budget - used)
                    return make_error(ErrorKind::resource, 0,
                                      "row payload exceeds the fetch budget");
                if (bytes > 0 && data == nullptr)
                    return make_error(ErrorKind::internal, 0, "missing native blob data");
                std::vector<uint8_t> copied;
                if (bytes > 0) {
                    const auto* first = static_cast<const uint8_t*>(data);
                    copied.assign(first, first + bytes);
                }
                status = append(Bytes{std::move(copied)});
            } else if (type == SQLITE_NULL) {
                status = append(Value{std::monostate{}});
            } else {
                return make_error(ErrorKind::internal, 0, "unknown native column type");
            }
            if (status) return status;
        }
        out = std::move(result);
        return {};
    };

    if (state->row_ready) {
        Row result;
        if (auto err = read_current_row(result)) {
            state->active_result = false;
            return err;
        }
        state->row_ready = false;
        row = std::move(result);
        done = false;
        return {};
    }
    if (state->exhausted) {
        done = true;
        return {};
    }

    const int rc = proxy_sqlite3_step(state->stmt);
    if (rc == SQLITE_ROW) {
        Row result;
        if (auto err = read_current_row(result)) {
            state->active_result = false;
            state->needs_reset = true;
            return err;
        }
        row = std::move(result);
        done = false;
        return {};
    }
    if (rc == SQLITE_DONE) {
        state->exhausted = true;
        state->row_ready = false;
        done = true;
        return {};
    }

    state->pending_step_error = rc;
    state->pending_step_error_reported = true;
    state->active_result = false;
    state->needs_reset = true;
    return native_error(step_error_kind(rc), connection_, rc);
}

Status SQLiteAdapter::reset(Statement& statement) {
    StatementState* state = checked(statement);
    if (state == nullptr) return affinity_error();
    if (proxy_sqlite3_reset == nullptr || proxy_sqlite3_clear_bindings == nullptr)
        return make_error(ErrorKind::internal, 0, "reset symbols are unavailable");

    const int reset_rc = proxy_sqlite3_reset(state->stmt);
    // sqlite3_reset always resets the statement. A non-OK return is normally the
    // error from the most recent step. Acknowledge it only when execute or
    // fetch already reported an error with the same primary code; any other
    // reset failure must not be converted into success.
    if (reset_rc != SQLITE_OK) {
        const bool acknowledges_reported_step =
            state->pending_step_error_reported &&
            state->pending_step_error != SQLITE_OK &&
            primary_code(reset_rc) == primary_code(state->pending_step_error);
        if (!acknowledges_reported_step)
            return native_error(ErrorKind::engine, connection_, reset_rc);
    }

    const int clear_rc = proxy_sqlite3_clear_bindings(state->stmt);
    state->needs_reset = false;
    state->row_ready = false;
    state->exhausted = false;
    state->active_result = false;
    state->pending_step_error = SQLITE_OK;
    state->pending_step_error_reported = false;

    if (clear_rc != SQLITE_OK)
        return native_error(ErrorKind::engine, connection_, clear_rc);
    return {};
}

void SQLiteAdapter::finalize(std::unique_ptr<Statement> statement) noexcept {
    // StatementState's destructor finalizes the native handle. This also keeps
    // cleanup safe for a handle moved to the wrong adapter by a programming
    // error; such a handle is never used for SQL operations.
    statement.reset();
}

}  // namespace embedded
