#include "duckdb_prepared_provider.h"
#include "duckdb_mysql_select_context.h"
#include "duckdb_prepared_adapter.h"
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace embedded;
using E = ProxySQL_Embedded_Error;
using V = ProxySQL_Embedded_Value;
using T = ProxySQL_Embedded_Type;
ProxySQL_Embedded_BytesView view(const std::string &s) {
    return {reinterpret_cast<const uint8_t *>(s.data()), s.size()};
}
T convert(const Type &t) {
    uint32_t kind = ProxySQL_Embedded_TYPE_UNKNOWN;
    switch (t.kind) {
    case TypeKind::dynamic:
        kind = ProxySQL_Embedded_TYPE_DYNAMIC;
        break;
    case TypeKind::signed_integer:
        kind = ProxySQL_Embedded_TYPE_INT64;
        break;
    case TypeKind::unsigned_integer:
        kind = ProxySQL_Embedded_TYPE_UINT64;
        break;
    case TypeKind::floating:
        kind = ProxySQL_Embedded_TYPE_FLOAT64;
        break;
    case TypeKind::text:
        kind = ProxySQL_Embedded_TYPE_TEXT;
        break;
    case TypeKind::bytes:
        kind = ProxySQL_Embedded_TYPE_BYTES;
        break;
    case TypeKind::decimal:
        kind = ProxySQL_Embedded_TYPE_DECIMAL;
        break;
    case TypeKind::boolean:
        kind = ProxySQL_Embedded_TYPE_BOOLEAN;
        break;
    default:
        break;
    }
    return {kind, t.precision, t.scale, static_cast<uint8_t>(t.nullable)};
}
struct NativeStatement {
    std::unique_ptr<Statement> stmt;
    std::vector<Type> native_types;
    std::vector<T> types;
    std::vector<uint32_t> positions;
    std::vector<Column> native_columns;
    std::vector<ProxySQL_Embedded_Column> columns;
    Row native_row;
    std::vector<V> row;
};
} // namespace
struct DuckDBPreparedProvider::Impl {
    duckdb_connection conn;
    Status status;
    Failure failure;
    ResetClient reset_client;
    void *status_arg;
    DuckDBSourceDialect dialect;
    DuckDBAdapter adapter;
    ProxySQL_Embedded_EngineV1 api{};
    ProxySQL_Embedded_PolicyV1 policy{};
    std::string message;
    bool active = false, failed = false, poisoned = false;
    bool mysql_analytical = false;
    char passive_guard = 0;
    char session_reset_guard = 0;
    Impl(duckdb_connection c, Status s, Failure f, ResetClient r, void *arg, DuckDBSourceDialect d)
        : conn(c), status(s), failure(f), reset_client(r), status_arg(arg), dialect(d), adapter(c) {
        api = {ProxySQL_Embedded_ABI_V1,
               sizeof(api),
               this,
               ProxySQL_Embedded_CAP_READ_ONLY | ProxySQL_Embedded_CAP_PARAMETER_POSITIONS,
               ((UINT64_C(1) << ProxySQL_Embedded_VALUE_NULL) |
                (UINT64_C(1) << ProxySQL_Embedded_VALUE_INT64) |
                (UINT64_C(1) << ProxySQL_Embedded_VALUE_UINT64) |
                (UINT64_C(1) << ProxySQL_Embedded_VALUE_FLOAT64) |
                (UINT64_C(1) << ProxySQL_Embedded_VALUE_TEXT) |
                (UINT64_C(1) << ProxySQL_Embedded_VALUE_BYTES) |
                (UINT64_C(1) << ProxySQL_Embedded_VALUE_DECIMAL) |
                (UINT64_C(1) << ProxySQL_Embedded_VALUE_BOOLEAN)),
               prepare,
               parameters,
               columns,
               bind,
               execute,
               fetch,
               reset,
               finalize,
               enter,
               leave};
        policy = {ProxySQL_Embedded_ABI_V1, sizeof(policy),    this,
                  authorize_prepare,        authorize_execute, authorize_fetch};
    }
    int error(E *e, ErrorKind k, const char *text) noexcept {
        failed = true;
        try {
            message = text ? text : "DuckDB provider failure";
            if (e) {
                *e = {};
                switch (k) {
                case ErrorKind::syntax:
                    e->kind = ProxySQL_Embedded_ERROR_SYNTAX;
                    break;
                case ErrorKind::unsupported:
                    e->kind = ProxySQL_Embedded_ERROR_UNSUPPORTED;
                    break;
                case ErrorKind::policy:
                    e->kind = ProxySQL_Embedded_ERROR_POLICY;
                    break;
                case ErrorKind::invalid_parameter:
                    e->kind = ProxySQL_Embedded_ERROR_INVALID_PARAMETER;
                    break;
                case ErrorKind::range:
                    e->kind = ProxySQL_Embedded_ERROR_RANGE;
                    break;
                case ErrorKind::resource:
                    e->kind = ProxySQL_Embedded_ERROR_RESOURCE;
                    break;
                case ErrorKind::schema_changed:
                    e->kind = ProxySQL_Embedded_ERROR_SCHEMA_CHANGED;
                    break;
                case ErrorKind::transaction:
                    e->kind = ProxySQL_Embedded_ERROR_TRANSACTION;
                    break;
                case ErrorKind::engine:
                    e->kind = ProxySQL_Embedded_ERROR_ENGINE;
                    break;
                case ErrorKind::internal:
                    e->kind = ProxySQL_Embedded_ERROR_INTERNAL;
                    break;
                }
                e->message = view(message);
            }
        } catch (...) {
            if (e) {
                *e = {};
                e->kind = ProxySQL_Embedded_ERROR_INTERNAL;
            }
        }
        return 1;
    }
    int result(E *e, const embedded::Status &s) noexcept {
        if (!s)
            return 0;
        int r = error(e, s->kind, s->message.c_str());
        if (e) {
            e->native_code = s->native_code;
            if (s->sqlstate.size() == 5) {
                memcpy(e->sqlstate, s->sqlstate.data(), 5);
                e->sqlstate[5] = 0;
            }
        }
        return r;
    }
    int translate(ProxySQL_Embedded_BytesView sql, std::string &emitted, E *e,
                  bool schema_recheck) {
        if (!active)
            return error(e, ErrorKind::transaction,
                         "analytical operation requires a read-only guard");
        if (!sql.data && sql.size)
            return error(e, ErrorKind::invalid_parameter, "invalid SQL");
        if (sql.size > 65536)
            return error(e, ErrorKind::resource, "analytical SQL input limit exceeded");
        std::string text(reinterpret_cast<const char *>(
                             sql.data ? sql.data : reinterpret_cast<const uint8_t *>("")),
                         sql.size);
        auto context = duckdb_mysql_select_context(conn);
        auto translated = duckdb_translate_mysql_select(text, context);
        if (translated.decision != DuckDBMySQLSelectDecision::supported) {
            if (schema_recheck)
                return error(e, ErrorKind::schema_changed,
                             "analytical statement no longer admitted");
            return error(e,
                         translated.decision == DuckDBMySQLSelectDecision::invalid
                             ? ErrorKind::syntax
                             : ErrorKind::unsupported,
                         "analytical SQL not admitted");
        }
        emitted = std::move(translated.sql);
        return 0;
    }
    static Impl &self(void *p) {
        return *static_cast<Impl *>(p);
    }
    static NativeStatement &statement(void *p) {
        return *static_cast<NativeStatement *>(p);
    }
#define CATCH(c, e)                                                                                \
    catch (...) {                                                                                  \
        return self(c).error(e, ErrorKind::internal, "DuckDB provider exception");                 \
    }
    static int prepare(void *c, ProxySQL_Embedded_BytesView sql, void **out, E *e) noexcept {
        try {
            auto &p = self(c);
            if (!out || (!sql.data && sql.size))
                return p.error(e, ErrorKind::invalid_parameter, "invalid SQL");
            *out = nullptr;
            auto s = std::make_unique<NativeStatement>();
            std::string prepared_sql;
            if (p.mysql_analytical) {
                if (p.translate(sql, prepared_sql, e, false))
                    return 1;
            } else {
                prepared_sql.assign(
                    reinterpret_cast<const char *>(
                        sql.data ? sql.data : reinterpret_cast<const uint8_t *>("")),
                    sql.size);
            }
            auto r = p.adapter.prepare(prepared_sql, s->stmt);
            if (r)
                return p.result(e, r);
            *out = s.release();
            return 0;
        }
        CATCH(c, e)
    }
    static int parameters(void *c, void *st, const T **out, size_t *n, const uint32_t **positions,
                          E *e) noexcept {
        try {
            auto &p = self(c);
            if (!st || !out || !n || !positions)
                return p.error(e, ErrorKind::invalid_parameter,
                               "invalid parameter metadata request");
            auto &s = statement(st);
            auto r = p.adapter.describe_parameters(*s.stmt, s.native_types);
            if (r)
                return p.result(e, r);
            r = p.adapter.describe_parameter_positions(*s.stmt, s.positions);
            if (r)
                return p.result(e, r);
            s.types.clear();
            for (const auto &t : s.native_types)
                s.types.push_back(convert(t));
            *out = s.types.data();
            *n = s.types.size();
            *positions = s.positions.data();
            return 0;
        }
        CATCH(c, e)
    }
    static int columns(void *c, void *st, const ProxySQL_Embedded_Column **out, size_t *n,
                       E *e) noexcept {
        try {
            auto &p = self(c);
            if (!st || !out || !n)
                return p.error(e, ErrorKind::invalid_parameter, "invalid result metadata request");
            auto &s = statement(st);
            auto r = p.adapter.describe_result(*s.stmt, s.native_columns);
            if (r)
                return p.result(e, r);
            s.columns.clear();
            for (const auto &col : s.native_columns)
                s.columns.push_back({view(col.name), convert(col.type)});
            *out = s.columns.data();
            *n = s.columns.size();
            return 0;
        }
        CATCH(c, e)
    }
    static int bind(void *c, void *st, const V *values, size_t n, E *e) noexcept {
        try {
            auto &p = self(c);
            if (!st || (!values && n))
                return p.error(e, ErrorKind::invalid_parameter, "invalid bindings");
            std::vector<Value> vals;
            vals.reserve(n);
            for (size_t i = 0; i < n; ++i) {
                const auto &v = values[i];
                switch (v.kind) {
                case ProxySQL_Embedded_VALUE_NULL:
                    vals.emplace_back(std::monostate{});
                    break;
                case ProxySQL_Embedded_VALUE_INT64:
                    vals.emplace_back(v.payload.int64_value);
                    break;
                case ProxySQL_Embedded_VALUE_UINT64:
                    vals.emplace_back(v.payload.uint64_value);
                    break;
                case ProxySQL_Embedded_VALUE_FLOAT64:
                    vals.emplace_back(v.payload.float64_value);
                    break;
                case ProxySQL_Embedded_VALUE_BOOLEAN:
                    vals.emplace_back(bool(v.payload.boolean_value));
                    break;
                case ProxySQL_Embedded_VALUE_TEXT:
                case ProxySQL_Embedded_VALUE_BYTES:
                case ProxySQL_Embedded_VALUE_DECIMAL: {
                    auto b = v.payload.bytes;
                    if (!b.data && b.size)
                        return p.error(e, ErrorKind::invalid_parameter, "invalid bytes");
                    std::string text(reinterpret_cast<const char *>(
                                         b.data ? b.data : reinterpret_cast<const uint8_t *>("")),
                                     b.size);
                    if (v.kind == ProxySQL_Embedded_VALUE_TEXT)
                        vals.emplace_back(Text{std::move(text)});
                    else if (v.kind == ProxySQL_Embedded_VALUE_DECIMAL)
                        vals.emplace_back(Decimal{std::move(text)});
                    else
                        vals.emplace_back(Bytes{std::vector<uint8_t>(text.begin(), text.end())});
                    break;
                }
                default:
                    return p.error(e, ErrorKind::invalid_parameter, "invalid value kind");
                }
            }
            return p.result(e, p.adapter.bind(*statement(st).stmt, vals));
        }
        CATCH(c, e)
    }
    static int execute(void *c, void *st, ProxySQL_Embedded_ExecInfo *info, E *e) noexcept {
        try {
            auto &p = self(c);
            if (!st || !info)
                return p.error(e, ErrorKind::invalid_parameter, "invalid execute");
            ExecInfo x;
            auto r = p.adapter.execute(*statement(st).stmt, x);
            if (r)
                return p.result(e, r);
            *info = {static_cast<uint8_t>(x.has_result), x.affected_rows, x.last_insert_id};
            return 0;
        }
        CATCH(c, e)
    }
    static int fetch(void *c, void *st, const V **out, size_t *n, uint8_t *done, size_t budget,
                     E *e) noexcept {
        try {
            auto &p = self(c);
            if (!st || !out || !n || !done)
                return p.error(e, ErrorKind::invalid_parameter, "invalid fetch");
            auto &s = statement(st);
            bool end = false;
            auto r = p.adapter.fetch(*s.stmt, s.native_row, end, budget);
            if (r)
                return p.result(e, r);
            s.row.clear();
            for (const auto &value : s.native_row) {
                V v{};
                std::visit(
                    [&](const auto &x) {
                        using X = std::decay_t<decltype(x)>;
                        if constexpr (std::is_same_v<X, std::monostate>)
                            v.kind = ProxySQL_Embedded_VALUE_NULL;
                        else if constexpr (std::is_same_v<X, int64_t>) {
                            v.kind = ProxySQL_Embedded_VALUE_INT64;
                            v.payload.int64_value = x;
                        } else if constexpr (std::is_same_v<X, uint64_t>) {
                            v.kind = ProxySQL_Embedded_VALUE_UINT64;
                            v.payload.uint64_value = x;
                        } else if constexpr (std::is_same_v<X, double>) {
                            v.kind = ProxySQL_Embedded_VALUE_FLOAT64;
                            v.payload.float64_value = x;
                        } else if constexpr (std::is_same_v<X, bool>) {
                            v.kind = ProxySQL_Embedded_VALUE_BOOLEAN;
                            v.payload.boolean_value = x;
                        } else if constexpr (std::is_same_v<X, Text>) {
                            v.kind = ProxySQL_Embedded_VALUE_TEXT;
                            v.payload.bytes = view(x.bytes);
                        } else if constexpr (std::is_same_v<X, Decimal>) {
                            v.kind = ProxySQL_Embedded_VALUE_DECIMAL;
                            v.payload.bytes = view(x.exact);
                        } else {
                            v.kind = ProxySQL_Embedded_VALUE_BYTES;
                            v.payload.bytes = {x.bytes.data(), x.bytes.size()};
                        }
                    },
                    value);
                s.row.push_back(v);
            }
            *out = s.row.data();
            *n = s.row.size();
            *done = end;
            return 0;
        }
        CATCH(c, e)
    }
    static int reset(void *c, void *st, E *e) noexcept {
        try {
            auto &p = self(c);
            if (!st)
                return p.error(e, ErrorKind::invalid_parameter, "invalid reset");
            return p.result(e, p.adapter.reset(*statement(st).stmt));
        }
        CATCH(c, e)
    }
    static void finalize(void *, void *st) noexcept {
        try {
            delete static_cast<NativeStatement *>(st);
        } catch (...) {
        }
    }
    bool query(const char *sql) noexcept {
        duckdb_result r{};
        auto rc = duckdb_query(conn, sql, &r);
        duckdb_destroy_result(&r);
        return rc == DuckDBSuccess;
    }
    static int enter(void *c, uint32_t op, ProxySQL_Embedded_BytesView, void **guard,
                     E *e) noexcept {
        try {
            auto &p = self(c);
            if (!guard)
                return p.error(e, ErrorKind::invalid_parameter, "invalid guard");
            *guard = nullptr;
            if (op == ProxySQL_Embedded_OPERATION_SESSION_RESET) {
                if (p.active) {
                    const bool cleaned = p.query("ROLLBACK");
                    p.active = false;
                    if (!cleaned)
                        p.poisoned = true;
                }
                if (p.poisoned || !p.reset_client) {
                    p.poisoned = true;
                    if (p.failure)
                        p.failure(p.status_arg);
                    return p.error(e, ErrorKind::transaction, "cannot reset client transaction");
                }
                *guard = &p.session_reset_guard;
                return 0;
            }
            if (op != ProxySQL_Embedded_OPERATION_PREPARE &&
                op != ProxySQL_Embedded_OPERATION_EXECUTE &&
                op != ProxySQL_Embedded_OPERATION_FETCH) {
                *guard = &p.passive_guard;
                return 0;
            }
            if (p.poisoned || p.active || !p.status || p.status(p.status_arg) != 'I')
                return p.error(e, ErrorKind::transaction,
                               "prepared execution requires an idle autocommit session");
            if (!p.query("BEGIN TRANSACTION READ ONLY")) {
                p.poisoned = true;
                if (p.failure)
                    p.failure(p.status_arg);
                return p.error(e, ErrorKind::transaction,
                               "cannot begin private read-only transaction");
            }
            p.active = true;
            p.failed = false;
            *guard = &p;
            return 0;
        }
        CATCH(c, e)
    }
    static void leave(void *c, void *guard) noexcept {
        auto &p = self(c);
        if (!guard || guard == &p.passive_guard)
            return;
        if (guard == &p.session_reset_guard) {
            duckdb_connection conn = nullptr;
            if (!p.reset_client(p.status_arg, &conn) || !conn) {
                p.conn = nullptr;
                p.adapter.reset_connection(nullptr);
                p.poisoned = true;
                if (p.failure)
                    p.failure(p.status_arg);
                return;
            }
            p.conn = conn;
            p.adapter.reset_connection(conn);
            return;
        }
        if (!p.active || guard != &p) {
            p.poisoned = true;
            if (p.failure)
                p.failure(p.status_arg);
            return;
        }
        bool ok = p.query(p.failed ? "ROLLBACK" : "COMMIT");
        p.active = false;
        if (!ok) {
            p.query("ROLLBACK");
            p.poisoned = true;
            if (p.failure)
                p.failure(p.status_arg);
        }
    }
    static int authorize_prepare(void *c, ProxySQL_Embedded_BytesView sql, E *e) noexcept {
        try {
            auto &p = self(c);
            if (!sql.data && sql.size)
                return p.error(e, ErrorKind::invalid_parameter, "invalid SQL");
            if (p.mysql_analytical) {
                std::string emitted;
                return p.translate(sql, emitted, e, false);
            }
            std::string text(reinterpret_cast<const char *>(
                                 sql.data ? sql.data : reinterpret_cast<const uint8_t *>("")),
                             sql.size);
            if (!duckdb_readonly_prepared_select(text, p.dialect))
                return p.error(e, ErrorKind::unsupported,
                               "prepared SQL is not an allowed read-only SELECT");
            return 0;
        }
        CATCH(c, e)
    }
    static int authorize_execute(void *c, ProxySQL_Embedded_BytesView sql, const V *, size_t,
                                 E *e) noexcept {
        try {
            auto &p = self(c);
            if (!p.mysql_analytical)
                return 0;
            std::string emitted;
            return p.translate(sql, emitted, e, true);
        }
        CATCH(c, e)
    }
    static int authorize_fetch(void *, ProxySQL_Embedded_BytesView, E *) noexcept {
        return 0;
    }
#undef CATCH
};
DuckDBPreparedProvider::DuckDBPreparedProvider(duckdb_connection c, Status s, Failure f,
                                               ResetClient r, void *p, DuckDBSourceDialect d)
    : impl_(std::make_unique<Impl>(c, s, f, r, p, d)) {}
DuckDBPreparedProvider::~DuckDBPreparedProvider() = default;
void DuckDBPreparedProvider::set_mysql_analytical(bool enabled) noexcept {
    impl_->mysql_analytical = enabled && impl_->dialect == embedded::DuckDBSourceDialect::mysql;
}
const ProxySQL_Embedded_EngineV1 *DuckDBPreparedProvider::engine() const noexcept {
    return &impl_->api;
}
const ProxySQL_Embedded_PolicyV1 *DuckDBPreparedProvider::policy() const noexcept {
    return &impl_->policy;
}
