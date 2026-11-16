#include "Embedded_Plugin_Adapter.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

namespace embedded {
namespace {
using BV = ProxySQL_Embedded_BytesView;
using PV = ProxySQL_Embedded_Value;
using PT = ProxySQL_Embedded_Type;
using PE = ProxySQL_Embedded_Error;
Status error(ErrorKind kind, const char *message, const char *state = "") {
    return Error{kind, 0, message, state};
}
Status internal(const char *message) {
    return error(ErrorKind::internal, message);
}
Status resource() {
    return error(ErrorKind::resource, "allocation failed", "53200");
}
Status limit() {
    return error(ErrorKind::resource, "size limit exceeded", "54000");
}
bool add(size_t &total, size_t n, size_t max) {
    if (n > max || total > max - n)
        return false;
    total += n;
    return true;
}
BV view(const std::string &s) {
    return {reinterpret_cast<const uint8_t *>(s.data()), s.size()};
}
Status callback(int rc, const PE &e) {
    if (rc == 0)
        return {};
    if (rc != 1)
        return internal("invalid callback return code");
    ErrorKind kind = ErrorKind::engine;
    switch (e.kind) {
    case ProxySQL_Embedded_ERROR_SYNTAX:
        kind = ErrorKind::syntax;
        break;
    case ProxySQL_Embedded_ERROR_UNSUPPORTED:
        kind = ErrorKind::unsupported;
        break;
    case ProxySQL_Embedded_ERROR_POLICY:
        kind = ErrorKind::policy;
        break;
    case ProxySQL_Embedded_ERROR_INVALID_PARAMETER:
        kind = ErrorKind::invalid_parameter;
        break;
    case ProxySQL_Embedded_ERROR_RANGE:
        kind = ErrorKind::range;
        break;
    case ProxySQL_Embedded_ERROR_RESOURCE:
        kind = ErrorKind::resource;
        break;
    case ProxySQL_Embedded_ERROR_SCHEMA_CHANGED:
        kind = ErrorKind::schema_changed;
        break;
    case ProxySQL_Embedded_ERROR_TRANSACTION:
        kind = ErrorKind::transaction;
        break;
    case ProxySQL_Embedded_ERROR_ENGINE:
        kind = ErrorKind::engine;
        break;
    case ProxySQL_Embedded_ERROR_INTERNAL:
        kind = ErrorKind::internal;
        break;
    default:
        break;
    }
    if (e.message.size > 4096 || (e.message.size && !e.message.data))
        return internal("invalid callback error message");
    std::string state;
    bool valid = e.sqlstate[5] == 0 && !(e.sqlstate[0] == '0' && e.sqlstate[1] == '0');
    for (size_t i = 0; i < 5; ++i)
        valid = valid && ((e.sqlstate[i] >= 'A' && e.sqlstate[i] <= 'Z') ||
                          (e.sqlstate[i] >= '0' && e.sqlstate[i] <= '9'));
    if (valid)
        state.assign(e.sqlstate, 5);
    return Error{kind, e.native_code,
                 e.message.size
                     ? std::string(reinterpret_cast<const char *>(e.message.data), e.message.size)
                     : "",
                 std::move(state)};
}
bool type_convert(const PT &in, bool parameter, uint64_t mask, Type &out) {
    if (in.nullable > 1)
        return false;
    uint32_t bit = 0;
    switch (in.kind) {
    case ProxySQL_Embedded_TYPE_UNKNOWN:
        if (!parameter)
            return false;
        out.kind = TypeKind::unknown;
        break;
    case ProxySQL_Embedded_TYPE_DYNAMIC:
        if (parameter)
            return false;
        out.kind = TypeKind::dynamic;
        break;
    case ProxySQL_Embedded_TYPE_INT64:
        out.kind = TypeKind::signed_integer;
        bit = ProxySQL_Embedded_VALUE_INT64;
        break;
    case ProxySQL_Embedded_TYPE_UINT64:
        out.kind = TypeKind::unsigned_integer;
        bit = ProxySQL_Embedded_VALUE_UINT64;
        break;
    case ProxySQL_Embedded_TYPE_FLOAT64:
        out.kind = TypeKind::floating;
        bit = ProxySQL_Embedded_VALUE_FLOAT64;
        break;
    case ProxySQL_Embedded_TYPE_TEXT:
        out.kind = TypeKind::text;
        bit = ProxySQL_Embedded_VALUE_TEXT;
        break;
    case ProxySQL_Embedded_TYPE_BYTES:
        out.kind = TypeKind::bytes;
        bit = ProxySQL_Embedded_VALUE_BYTES;
        break;
    case ProxySQL_Embedded_TYPE_DECIMAL:
        out.kind = TypeKind::decimal;
        bit = ProxySQL_Embedded_VALUE_DECIMAL;
        break;
    case ProxySQL_Embedded_TYPE_BOOLEAN:
        out.kind = TypeKind::boolean;
        bit = ProxySQL_Embedded_VALUE_BOOLEAN;
        break;
    default:
        return false;
    }
    if (bit && !(mask & (UINT64_C(1) << bit)))
        return false;
    if (out.kind == TypeKind::decimal) {
        if (in.precision < 1 || in.precision > 1000 || in.scale < 0 || in.scale > in.precision)
            return false;
    } else if (in.precision || in.scale)
        return false;
    out.precision = in.precision;
    out.scale = in.scale;
    out.nullable = in.nullable != 0;
    return true;
}
bool same(const Type &a, const Type &b) {
    return a.kind == b.kind && a.precision == b.precision && a.scale == b.scale &&
           a.nullable == b.nullable;
}
uint32_t value_kind(const Value &v) {
    if (std::holds_alternative<std::monostate>(v))
        return ProxySQL_Embedded_VALUE_NULL;
    if (std::holds_alternative<int64_t>(v))
        return ProxySQL_Embedded_VALUE_INT64;
    if (std::holds_alternative<uint64_t>(v))
        return ProxySQL_Embedded_VALUE_UINT64;
    if (std::holds_alternative<double>(v))
        return ProxySQL_Embedded_VALUE_FLOAT64;
    if (std::holds_alternative<Text>(v))
        return ProxySQL_Embedded_VALUE_TEXT;
    if (std::holds_alternative<Bytes>(v))
        return ProxySQL_Embedded_VALUE_BYTES;
    if (std::holds_alternative<Decimal>(v))
        return ProxySQL_Embedded_VALUE_DECIMAL;
    return ProxySQL_Embedded_VALUE_BOOLEAN;
}
Status values_view(const std::vector<Value> &values, uint64_t mask, size_t max,
                   std::vector<PV> &out) {
    size_t total = 0;
    for (const auto &v : values) {
        if (!(mask & (UINT64_C(1) << value_kind(v))))
            return error(ErrorKind::unsupported, "unsupported value");
        if (!add(total, value_payload_bytes(v), max))
            return limit();
    }
    out.resize(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        const auto &v = values[i];
        auto &p = out[i];
        p = {};
        p.kind = value_kind(v);
        switch (p.kind) {
        case ProxySQL_Embedded_VALUE_INT64:
            p.payload.int64_value = std::get<int64_t>(v);
            break;
        case ProxySQL_Embedded_VALUE_UINT64:
            p.payload.uint64_value = std::get<uint64_t>(v);
            break;
        case ProxySQL_Embedded_VALUE_FLOAT64:
            p.payload.float64_value = std::get<double>(v);
            break;
        case ProxySQL_Embedded_VALUE_TEXT:
            p.payload.bytes = view(std::get<Text>(v).bytes);
            break;
        case ProxySQL_Embedded_VALUE_DECIMAL:
            p.payload.bytes = view(std::get<Decimal>(v).exact);
            break;
        case ProxySQL_Embedded_VALUE_BYTES: {
            const auto &b = std::get<Bytes>(v).bytes;
            p.payload.bytes = {b.data(), b.size()};
            break;
        }
        case ProxySQL_Embedded_VALUE_BOOLEAN:
            p.payload.boolean_value = std::get<bool>(v);
            break;
        default:
            break;
        }
    }
    return {};
}
struct Native : Statement {
    QuotaLease lease;
    const void *owner;
    ProxySQL_Embedded_EngineV1 engine;
    void *handle;
    std::vector<Type> params;
    std::vector<uint32_t> positions;
    std::vector<Column> columns;
    bool executed = false;
    Native(const void *o, ProxySQL_Embedded_EngineV1 e, void *h, QuotaPool &pool) : lease(pool), owner(o), engine(e), handle(h) {}
    ~Native() override {
        if (handle)
            engine.finalize(engine.context, handle);
    }
};
class PluginAdapter : public Adapter {
    ProxySQL_Embedded_EngineV1 e_;
    PluginLimits limits_;
    QuotaPool &quota_;
    Native *native(Statement &s) {
        auto *n = dynamic_cast<Native *>(&s);
        return n && n->owner == this && n->handle ? n : nullptr;
    }
    Status clear(Native &n, Status first) {
        n.executed = false;
        if (!n.handle)
            return first ? first : internal("closed statement");
        PE e{};
        int rc = e_.reset(e_.context, n.handle, &e);
        if (rc == ProxySQL_Embedded_SUCCESS)
            return first;
        auto finalize = [&]() noexcept {
            void *handle = n.handle;
            n.handle = nullptr;
            e_.finalize(e_.context, handle);
        };
        Status reset_error;
        try {
            // The reset error is borrowed until finalize invokes the provider again.
            reset_error = callback(rc, e);
        } catch (...) {
            finalize();
            throw;
        }
        finalize();
        return first ? first : reset_error;
    }
    Status metadata(Native &n, std::vector<Type> &ps, std::vector<uint32_t> &positions,
                    std::vector<Column> &cols, bool persistent = false) {
        const PT *types = nullptr;
        const uint32_t *pos = nullptr;
        size_t count = 0;
        PE err{};
        int rc = e_.describe_parameters(e_.context, n.handle, &types, &count, &pos, &err);
        if (auto st = callback(rc, err))
            return st;
        if (count > limits_.parameters)
            return limit();
        if (count && (!types || !pos))
            return internal("invalid parameter metadata");
        size_t used = 0;
        if (count > limits_.metadata / (sizeof(Type) + sizeof(uint32_t)))
            return limit();
        used = count * (sizeof(Type) + sizeof(uint32_t));
        if (persistent) {
            ResourceUsage usage{};
            usage[static_cast<size_t>(Resource::metadata_bytes)] = used;
            if (!n.lease.resize(usage)) return limit();
        }
        ps.reserve(count);
        positions.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            Type t;
            if (!type_convert(types[i], true, e_.value_type_mask, t))
                return internal("invalid parameter type");
            ps.push_back(t);
            positions.push_back(pos[i]);
        }
        const ProxySQL_Embedded_Column *c = nullptr;
        count = 0;
        err = {};
        rc = e_.describe_result(e_.context, n.handle, &c, &count, &err);
        if (auto st = callback(rc, err))
            return st;
        if (count > limits_.columns || count > (limits_.metadata - used) / sizeof(Column))
            return limit();
        used += count * sizeof(Column);
        if (count && !c)
            return internal("invalid result metadata");
        for (size_t i = 0; i < count; ++i) {
            if ((c[i].name.size && !c[i].name.data) || !add(used, c[i].name.size, limits_.metadata))
                return limit();
            if (c[i].name.size && std::memchr(c[i].name.data, 0, c[i].name.size))
                return internal("invalid column name");
            if (c[i].type.kind == ProxySQL_Embedded_TYPE_UNKNOWN)
                return error(ErrorKind::unsupported, "unknown result type");
            Type t;
            if (!type_convert(c[i].type, false, e_.value_type_mask, t))
                return internal("invalid result type");
        }
        if (persistent) {
            auto usage = n.lease.usage();
            usage[static_cast<size_t>(Resource::metadata_bytes)] = used;
            if (!n.lease.resize(usage)) return limit();
        }
        cols.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            Type t;
            type_convert(c[i].type, false, e_.value_type_mask, t);
            cols.push_back(
                {c[i].name.size
                     ? std::string(reinterpret_cast<const char *>(c[i].name.data), c[i].name.size)
                     : "",
                 t});
        }
        return {};
    }
    Status check(Native &n) {
        std::vector<Type> p;
        std::vector<uint32_t> pos;
        std::vector<Column> c;
        if (auto st = metadata(n, p, pos, c))
            return st;
        bool equal =
            p.size() == n.params.size() && pos == n.positions && c.size() == n.columns.size();
        if (equal)
            for (size_t i = 0; i < p.size(); ++i)
                equal = equal && same(p[i], n.params[i]);
        if (equal)
            for (size_t i = 0; i < c.size(); ++i)
                equal =
                    equal && c[i].name == n.columns[i].name && same(c[i].type, n.columns[i].type);
        return equal ? Status{}
                     : error(ErrorKind::schema_changed, "statement metadata changed", "0A000");
    }

  public:
    PluginAdapter(ProxySQL_Embedded_EngineV1 e, PluginLimits l, QuotaPool &q) : e_(e), limits_(l), quota_(q) {}
    Status prepare(const std::string &sql, std::unique_ptr<Statement> &out) override {
        out.reset();
        try {
            if (sql.size() > limits_.sql)
                return limit();
            if (sql.find('\0') != std::string::npos)
                return error(ErrorKind::invalid_parameter, "SQL contains NUL");
            void *h = nullptr;
            PE e{};
            int rc = e_.prepare(e_.context, view(sql), &h, &e);
            // Copy the borrowed error before finalization can invalidate it.
            Status st;
            try {
                st = callback(rc, e);
            } catch (...) {
                if (h)
                    e_.finalize(e_.context, h);
                throw;
            }
            if (st || !h) {
                if (h)
                    e_.finalize(e_.context, h);
                return st ? st : internal("missing statement handle");
            }
            std::unique_ptr<Native> n;
            try {
                n.reset(new Native(this, e_, h, quota_));
            } catch (...) {
                e_.finalize(e_.context, h);
                throw;
            }
            try {
                if (auto s = metadata(*n, n->params, n->positions, n->columns, true))
                    return clear(*n, s);
            } catch (const std::bad_alloc &) {
                return clear(*n, resource());
            } catch (const std::length_error &) {
                return clear(*n, limit());
            }
            out = std::move(n);
            return {};
        } catch (const std::bad_alloc &) {
            return resource();
        } catch (const std::length_error &) {
            return limit();
        }
    }
    Status describe_parameters(Statement &s, std::vector<Type> &out) override {
        out.clear();
        try {
            auto *n = native(s);
            if (!n)
                return internal("foreign statement");
            auto copy = n->params;
            out.swap(copy);
            return {};
        } catch (const std::bad_alloc &) {
            return resource();
        } catch (const std::length_error &) {
            return limit();
        }
    }
    Status describe_parameter_positions(Statement &s, std::vector<uint32_t> &out) override {
        out.clear();
        try {
            auto *n = native(s);
            if (!n)
                return internal("foreign statement");
            auto copy = n->positions;
            out.swap(copy);
            return {};
        } catch (const std::bad_alloc &) {
            return resource();
        } catch (const std::length_error &) {
            return limit();
        }
    }
    Status describe_result(Statement &s, std::vector<Column> &out) override {
        out.clear();
        try {
            auto *n = native(s);
            if (!n)
                return internal("foreign statement");
            auto copy = n->columns;
            out.swap(copy);
            return {};
        } catch (const std::bad_alloc &) {
            return resource();
        } catch (const std::length_error &) {
            return limit();
        }
    }
    Status bind(Statement &s, const std::vector<Value> &v) override {
        auto *n = native(s);
        if (!n)
            return internal("foreign statement");
        try {
            if (v.size() != n->params.size())
                return error(ErrorKind::invalid_parameter, "parameter count mismatch");
            std::vector<PV> p;
            if (auto st = values_view(v, e_.value_type_mask, limits_.bind, p))
                return clear(*n, st);
            PE e{};
            int rc = e_.bind(e_.context, n->handle, p.data(), p.size(), &e);
            if (auto st = callback(rc, e))
                return clear(*n, st);
            return {};
        } catch (const std::bad_alloc &) {
            return clear(*n, resource());
        } catch (const std::length_error &) {
            return clear(*n, limit());
        }
    }
    Status execute(Statement &s, ExecInfo &out) override {
        out = {};
        auto *n = native(s);
        if (!n)
            return internal("foreign statement");
        try {
            if (auto st = check(*n))
                return clear(*n, st);
            ProxySQL_Embedded_ExecInfo info{};
            PE e{};
            int rc = e_.execute(e_.context, n->handle, &info, &e);
            if (auto st = callback(rc, e))
                return clear(*n, st);
            if (info.has_result > 1 || (info.has_result != !n->columns.empty()))
                return clear(*n, internal("invalid result flag"));
            if (auto st = check(*n))
                return clear(*n, st);
            out = {info.affected_rows, info.last_insert_id, info.has_result != 0};
            n->executed = true;
            return {};
        } catch (const std::bad_alloc &) {
            return clear(*n, resource());
        } catch (const std::length_error &) {
            return clear(*n, limit());
        }
    }
    Status fetch(Statement &s, Row &out, bool &done, size_t budget) override {
        out.clear();
        done = false;
        auto *n = native(s);
        if (!n)
            return internal("foreign statement");
        try {
            if (!n->executed)
                return clear(*n, internal("statement not executed"));
            budget = std::min(budget, limits_.fetch);
            const PV *values = nullptr;
            size_t count = 0;
            uint8_t end = 0;
            PE e{};
            int rc = e_.fetch(e_.context, n->handle, &values, &count, &end, budget, &e);
            if (auto st = callback(rc, e))
                return clear(*n, st);
            if (end > 1 || (end && count) || (!end && count != n->columns.size()) ||
                (count && !values))
                return clear(*n, internal("invalid row shape"));
            size_t total = 0;
            for (size_t i = 0; i < count; ++i) {
                const PV &v = values[i];
                const Type &t = n->columns[i].type;
                size_t size = 0;
                if (v.kind < 1 || v.kind > 8 || !(e_.value_type_mask & (UINT64_C(1) << v.kind)))
                    return clear(*n, internal("invalid row value kind"));
                bool compatible =
                    t.kind == TypeKind::dynamic ||
                    (v.kind == ProxySQL_Embedded_VALUE_NULL && t.nullable) ||
                    (v.kind == ProxySQL_Embedded_VALUE_INT64 &&
                     t.kind == TypeKind::signed_integer) ||
                    (v.kind == ProxySQL_Embedded_VALUE_UINT64 &&
                     t.kind == TypeKind::unsigned_integer) ||
                    (v.kind == ProxySQL_Embedded_VALUE_FLOAT64 && t.kind == TypeKind::floating) ||
                    (v.kind == ProxySQL_Embedded_VALUE_TEXT && t.kind == TypeKind::text) ||
                    (v.kind == ProxySQL_Embedded_VALUE_BYTES && t.kind == TypeKind::bytes) ||
                    (v.kind == ProxySQL_Embedded_VALUE_DECIMAL && t.kind == TypeKind::decimal) ||
                    (v.kind == ProxySQL_Embedded_VALUE_BOOLEAN && t.kind == TypeKind::boolean);
                if (v.kind == ProxySQL_Embedded_VALUE_NULL && !t.nullable)
                    compatible = false;
                if (!compatible)
                    return clear(*n, internal("row type mismatch"));
                if (v.kind >= ProxySQL_Embedded_VALUE_TEXT &&
                    v.kind <= ProxySQL_Embedded_VALUE_DECIMAL) {
                    size = v.payload.bytes.size;
                    if (size && !v.payload.bytes.data)
                        return clear(*n, internal("invalid row bytes"));
                } else if (v.kind == ProxySQL_Embedded_VALUE_BOOLEAN) {
                    if (v.payload.boolean_value > 1)
                        return clear(*n, internal("invalid boolean"));
                    size = 1;
                } else if (v.kind != ProxySQL_Embedded_VALUE_NULL)
                    size = 8;
                if (!add(total, size, budget))
                    return clear(*n, limit());
            }
            Row row;
            row.reserve(count);
            for (size_t i = 0; i < count; ++i) {
                const auto &v = values[i];
                switch (v.kind) {
                case ProxySQL_Embedded_VALUE_NULL:
                    row.emplace_back(std::monostate{});
                    break;
                case ProxySQL_Embedded_VALUE_INT64:
                    row.emplace_back(v.payload.int64_value);
                    break;
                case ProxySQL_Embedded_VALUE_UINT64:
                    row.emplace_back(v.payload.uint64_value);
                    break;
                case ProxySQL_Embedded_VALUE_FLOAT64:
                    row.emplace_back(v.payload.float64_value);
                    break;
                case ProxySQL_Embedded_VALUE_BOOLEAN:
                    row.emplace_back(v.payload.boolean_value != 0);
                    break;
                case ProxySQL_Embedded_VALUE_TEXT: {
                    const auto bytes = v.payload.bytes;
                    row.emplace_back(Text{
                        bytes.size
                            ? std::string(reinterpret_cast<const char *>(bytes.data), bytes.size)
                            : ""});
                    break;
                }
                case ProxySQL_Embedded_VALUE_DECIMAL: {
                    const auto bytes = v.payload.bytes;
                    row.emplace_back(Decimal{
                        bytes.size
                            ? std::string(reinterpret_cast<const char *>(bytes.data), bytes.size)
                            : ""});
                    break;
                }
                case ProxySQL_Embedded_VALUE_BYTES: {
                    const auto bytes = v.payload.bytes;
                    Bytes b;
                    if (bytes.size)
                        b.bytes.assign(bytes.data, bytes.data + bytes.size);
                    row.emplace_back(std::move(b));
                    break;
                }
                default:
                    break;
                }
            }
            out = std::move(row);
            done = end != 0;
            return {};
        } catch (const std::bad_alloc &) {
            return clear(*n, resource());
        } catch (const std::length_error &) {
            return clear(*n, limit());
        }
    }
    Status reset(Statement &s) override {
        auto *n = native(s);
        return n ? clear(*n, {}) : internal("foreign statement");
    }
    void finalize(std::unique_ptr<Statement> s) noexcept override {
        s.reset();
    }
};
class PluginPolicy : public EndpointPolicy {
    ProxySQL_Embedded_PolicyV1 p_;
    uint64_t mask_;
    PluginLimits limits_;

  public:
    PluginPolicy(ProxySQL_Embedded_PolicyV1 p, uint64_t m, PluginLimits l)
        : p_(p), mask_(m), limits_(l) {}
    Status authorize_prepare(const std::string &sql) override {
        try {
            if (sql.size() > limits_.sql)
                return limit();
            if (sql.find('\0') != std::string::npos)
                return internal("SQL contains NUL");
            PE e{};
            int rc = p_.authorize_prepare(p_.context, view(sql), &e);
            return callback(rc, e);
        } catch (const std::bad_alloc &) {
            return resource();
        } catch (const std::length_error &) {
            return limit();
        }
    }
    Status authorize_execute(const std::string &sql, const std::vector<Value> &values) override {
        try {
            if (sql.size() > limits_.sql || values.size() > limits_.parameters)
                return limit();
            if (sql.find('\0') != std::string::npos)
                return internal("SQL contains NUL");
            std::vector<PV> p;
            if (auto st = values_view(values, mask_, limits_.bind, p))
                return st;
            PE e{};
            int rc = p_.authorize_execute(p_.context, view(sql), p.data(), p.size(), &e);
            return callback(rc, e);
        } catch (const std::bad_alloc &) {
            return resource();
        } catch (const std::length_error &) {
            return limit();
        }
    }
    Status authorize_fetch(const std::string &sql) override {
        try {
            if (sql.size() > limits_.sql)
                return limit();
            if (sql.find('\0') != std::string::npos)
                return internal("SQL contains NUL");
            PE e{};
            int rc = p_.authorize_fetch(p_.context, view(sql), &e);
            return callback(rc, e);
        } catch (const std::bad_alloc &) {
            return resource();
        } catch (const std::length_error &) {
            return limit();
        }
    }
};
struct Guard : OperationGuard {
    ProxySQL_Embedded_EngineV1 e;
    void *h;
    Guard(ProxySQL_Embedded_EngineV1 engine, void *handle) : e(engine), h(handle) {}
    ~Guard() override {
        if (e.guard_leave && h)
            e.guard_leave(e.context, h);
    }
};
uint32_t operation(Operation op) {
    switch (op) {
    case Operation::prepare:
        return ProxySQL_Embedded_OPERATION_PREPARE;
    case Operation::execute:
        return ProxySQL_Embedded_OPERATION_EXECUTE;
    case Operation::fetch:
        return ProxySQL_Embedded_OPERATION_FETCH;
    case Operation::reset:
        return ProxySQL_Embedded_OPERATION_RESET;
    case Operation::close:
        return ProxySQL_Embedded_OPERATION_CLOSE;
    case Operation::disconnect:
        return ProxySQL_Embedded_OPERATION_DISCONNECT;
    case Operation::long_data:
        return ProxySQL_Embedded_OPERATION_LONG_DATA;
    case Operation::session_reset:
        return ProxySQL_Embedded_OPERATION_SESSION_RESET;
    }
    return 0;
}
class Provider : public PluginProvider {
    ProxySQL_Embedded_EngineV1 engine_;
    PluginAdapter adapter_;
    PluginPolicy policy_;
    uint16_t (*status_)(void *) noexcept;
    void *status_context_;
    uint8_t (*pg_status_)(void *) noexcept;
    void *pg_status_context_;

  public:
    Provider(const ProxySQL_Embedded_RequestV1 &r, PluginLimits l, QuotaPool &q)
        : engine_(*r.engine), adapter_(engine_, l, q), policy_(*r.policy, engine_.value_type_mask, l),
          status_(r.mysql_status), status_context_(r.status_context), pg_status_(r.pgsql_status),
          pg_status_context_(r.pgsql_status_context) {}
    Adapter &adapter() override {
        return adapter_;
    }
    EndpointPolicy &policy() override {
        return policy_;
    }
    uint16_t (*mysql_status() const)(void *) noexcept override {
        return status_;
    }
    void *status_context() const override {
        return status_context_;
    }
    uint8_t (*pgsql_status() const)(void *) noexcept override {
        return pg_status_;
    }
    void *pgsql_status_context() const override {
        return pg_status_context_;
    }
    GuardFactory guard_factory() override {
        auto engine = engine_;
        return
            [engine](const OperationContext &ctx, std::unique_ptr<OperationGuard> &out) -> Status {
                out.reset();
                void *h = nullptr;
                try {
                    const uint32_t tag = operation(ctx.operation);
                    if (!tag)
                        return internal("invalid operation");
                    if (engine.guard_enter) {
                        PE e{};
                        BV sql = ctx.sql ? view(*ctx.sql) : BV{};
                        int rc = engine.guard_enter(engine.context, tag, sql, &h, &e);
                        Status st;
                        try {
                            st = callback(rc, e);
                        } catch (...) {
                            if (h)
                                engine.guard_leave(engine.context, h);
                            throw;
                        }
                        if (st || !h) {
                            if (h)
                                engine.guard_leave(engine.context, h);
                            return st ? st : internal("missing guard handle");
                        }
                    }
                    try {
                        out.reset(new Guard(engine, h));
                    } catch (...) {
                        if (h)
                            engine.guard_leave(engine.context, h);
                        throw;
                    }
                    return {};
                } catch (const std::bad_alloc &) {
                    return resource();
                } catch (const std::length_error &) {
                    return limit();
                }
            };
    }
};
} // namespace
Status make_plugin_provider(const ProxySQL_Embedded_RequestV1 *r, bool pgsql,
                            PluginProviderResult &out, PluginLimits l, QuotaPool *quota) {
    out.reset();
    try {
        if (!r || r->abi_version != 1 || r->struct_size < sizeof(*r))
            return internal("invalid request descriptor");
        auto *e = r->engine;
        auto *p = r->policy;
        if (!e || e->abi_version != 1 || e->struct_size < sizeof(*e) || !p || p->abi_version != 1 ||
            p->struct_size < sizeof(*p))
            return internal("invalid callback descriptor");
        constexpr uint64_t caps =
            ProxySQL_Embedded_CAP_READ_ONLY | ProxySQL_Embedded_CAP_PARAMETER_POSITIONS;
        constexpr uint64_t mask = (UINT64_C(1) << 9) - 2;
        const uint64_t flags = ProxySQL_Embedded_REQUEST_READ_ONLY |
                               (pgsql ? ProxySQL_Embedded_REQUEST_PG_IMPLICIT_CYCLES : 0);
        if (r->flags != flags || (pgsql && !r->pgsql_status) || (!pgsql && !r->mysql_status) ||
            (e->capabilities & ~caps) || !(e->capabilities & ProxySQL_Embedded_CAP_READ_ONLY) ||
            (pgsql && !(e->capabilities & ProxySQL_Embedded_CAP_PARAMETER_POSITIONS)) ||
            (e->value_type_mask & ~mask) ||
            !(e->value_type_mask & (UINT64_C(1) << ProxySQL_Embedded_VALUE_NULL)))
            return internal("invalid provider capabilities");
        if (!e->prepare || !e->describe_parameters || !e->describe_result || !e->bind ||
            !e->execute || !e->fetch || !e->reset || !e->finalize ||
            (!!e->guard_enter != !!e->guard_leave) || !p->authorize_prepare ||
            !p->authorize_execute || !p->authorize_fetch)
            return internal("missing callback");
        PluginLimits hard;
        l.sql = std::min(l.sql, hard.sql);
        l.parameters = std::min(l.parameters, hard.parameters);
        l.columns = std::min(l.columns, hard.columns);
        l.metadata = std::min(l.metadata, hard.metadata);
        l.bind = std::min(l.bind, hard.bind);
        l.fetch = std::min(l.fetch, hard.fetch);
        out.reset(new Provider(*r, l, quota ? *quota : process_quota_pool()));
        return {};
    } catch (const std::bad_alloc &) {
        return resource();
    } catch (const std::length_error &) {
        return limit();
    }
}
} // namespace embedded
