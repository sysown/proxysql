#include "Embedded_PgSQL_Prepared.h"
#include "Embedded_PgSQL_Value.h"
#include <algorithm>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>

namespace embedded {
namespace {
Status err(ErrorKind kind, const char *message, const char *state) {
    return Error{kind, 0, message, state};
}
Status limit() {
    return err(ErrorKind::resource, "prepared query resource limit exceeded", "54000");
}
uint32_t infer(TypeKind k) {
    switch (k) {
    case TypeKind::signed_integer:
        return pgsql_oid_int8;
    case TypeKind::floating:
        return pgsql_oid_float8;
    case TypeKind::text:
        return pgsql_oid_text;
    case TypeKind::bytes:
        return pgsql_oid_bytea;
    case TypeKind::decimal:
        return pgsql_oid_numeric;
    default:
        return 0;
    }
}
struct EmptyGuard : OperationGuard {};
} // namespace
struct PgSQLPrepared::Impl {
    struct Stmt {
        uint64_t id = 0;
        std::string sql;
        std::vector<uint32_t> oids, positions;
        std::vector<Type> types;
        std::vector<PgSQLColumn> columns;
    };
    struct Portal {
        uint64_t id = 0;
        std::string sql;
        std::vector<Value> values;
        std::vector<PgSQLColumn> columns;
        std::vector<int16_t> formats;
        std::vector<PgSQLFieldRow> rows;
        size_t cursor = 0, bind_bytes = 0, result_bytes = 0;
        bool started = false, complete = false;
    };
    Session session;
    GuardFactory factory;
    PgSQLPreparedLimits limits;
    std::map<std::string, Stmt> statements;
    std::map<std::string, Portal> portals;
    bool poisoned = false, disconnected = false;
    static PgSQLPreparedLimits bounded(PgSQLPreparedLimits l) {
        PgSQLPreparedLimits hard;
        l.statements = std::min(l.statements, hard.statements);
        l.portals = std::min(l.portals, hard.portals);
        l.parameters = std::min(l.parameters, hard.parameters);
        l.columns = std::min(l.columns, hard.columns);
        l.name_per = std::min(l.name_per, hard.name_per);
        l.sql_per = std::min(l.sql_per, hard.sql_per);
        l.metadata_total = std::min(l.metadata_total, hard.metadata_total);
        l.sql_total = std::min(l.sql_total, hard.sql_total);
        l.bind_total = std::min(l.bind_total, hard.bind_total);
        l.result_total = std::min(l.result_total, hard.result_total);
        return l;
    }
    Impl(Adapter &a, EndpointPolicy &p, GuardFactory f, PgSQLPreparedLimits l)
        : session(a, p, bounded(l).statements + bounded(l).portals + 2, bounded(l).result_total),
          factory(std::move(f)), limits(bounded(l)) {}
    Status guard(Operation op, const std::string *sql, std::unique_ptr<OperationGuard> &g) {
        if (!factory) {
            g.reset(new EmptyGuard);
            return {};
        }
        Status e;
        try {
            e = factory({op, sql}, g);
        } catch (...) {
            return err(ErrorKind::internal, "guard factory threw", "XX000");
        }
        if (e)
            return e;
        if (!g)
            return err(ErrorKind::internal, "guard factory returned no guard", "XX000");
        return {};
    }
    Status fail(Status e) {
        if (e)
            poisoned = true;
        return e;
    }
    // Includes vector element storage and conservative map/node overhead.
    static size_t metadata(const std::string &name, const std::vector<PgSQLColumn> &cols,
                           size_t oids, size_t positions, size_t types, size_t formats) {
        size_t n = 256 + name.size() + oids * sizeof(uint32_t) + positions * sizeof(uint32_t) +
                   types * sizeof(Type) + formats * sizeof(int16_t) +
                   cols.size() * sizeof(PgSQLColumn);
        for (const auto &col : cols) {
            if (col.name.size() > SIZE_MAX - n)
                return SIZE_MAX;
            n += col.name.size();
        }
        return n;
    }
    size_t metadata_bytes() const {
        size_t n = 0;
        for (const auto &entry : statements) {
            const auto &x = entry.second;
            size_t part = metadata(entry.first, x.columns, x.oids.size(), x.positions.size(),
                                   x.types.size(), 0);
            if (part > SIZE_MAX - n)
                return SIZE_MAX;
            n += part;
        }
        for (const auto &entry : portals) {
            const auto &x = entry.second;
            size_t part = metadata(entry.first, x.columns, 0, 0, 0, x.formats.size());
            if (part > SIZE_MAX - n)
                return SIZE_MAX;
            n += part;
        }
        return n;
    }
    size_t sql_bytes() const {
        size_t n = 0;
        for (auto &x : statements)
            n += x.second.sql.size();
        for (auto &x : portals)
            n += x.second.sql.size();
        return n;
    }
    size_t bind_bytes() const {
        size_t n = 0;
        for (auto &x : portals)
            n += x.second.bind_bytes;
        return n;
    }
    size_t result_bytes() const {
        size_t n = 0;
        for (auto &x : portals)
            n += x.second.result_bytes;
        return n;
    }
};
PgSQLPrepared::PgSQLPrepared(Adapter &a, EndpointPolicy &p, GuardFactory f, PgSQLPreparedLimits l)
    : impl_(new Impl(a, p, std::move(f), l)) {}
PgSQLPrepared::~PgSQLPrepared() {
    disconnect();
}
bool PgSQLPrepared::ignoring() const noexcept {
    return impl_->poisoned || impl_->disconnected;
}
Status PgSQLPrepared::parse(const std::string &name, const std::string &sql,
                            const std::vector<uint32_t> &supplied) {
    auto &s = *impl_;
    if (ignoring())
        return {};
    try {
        if (name.size() > s.limits.name_per || sql.size() > s.limits.sql_per)
            return s.fail(limit());
        auto old = s.statements.find(name);
        if (old != s.statements.end() && !name.empty())
            return s.fail(err(ErrorKind::invalid_parameter, "duplicate statement", "42P05"));
        if (supplied.size() > s.limits.parameters ||
            (old == s.statements.end() && s.statements.size() >= s.limits.statements))
            return s.fail(limit());
        size_t existing = s.sql_bytes() - (old == s.statements.end() ? 0 : old->second.sql.size());
        if (sql.size() > s.limits.sql_total || existing > s.limits.sql_total - sql.size())
            return s.fail(limit());
        std::unique_ptr<OperationGuard> g;
        if (auto e = s.guard(Operation::prepare, &sql, g))
            return s.fail(e);
        Impl::Stmt st;
        st.sql = sql;
        if (auto e = s.session.prepare(sql, st.id))
            return s.fail(e);
        struct Cleanup {
            Session &s;
            uint64_t &id;
            ~Cleanup() {
                if (id)
                    s.close(id);
            }
        } cleanup{s.session, st.id};
        std::vector<Type> types;
        std::vector<Column> columns;
        if (auto e = s.session.describe(st.id, types, columns))
            return s.fail(e);
        if (types.size() > s.limits.parameters || columns.size() > s.limits.columns)
            return s.fail(limit());
        if (auto e = s.session.describe_parameter_positions(st.id, st.positions))
            return s.fail(e);
        size_t count = supplied.size();
        for (auto pos : st.positions) {
            if (!pos)
                return s.fail(
                    err(ErrorKind::invalid_parameter, "unresolved parameter position", "42P18"));
            if (pos > s.limits.parameters)
                return s.fail(limit());
            count = std::max(count, size_t(pos));
        }
        size_t old_meta =
            old == s.statements.end()
                ? 0
                : Impl::metadata(old->first, old->second.columns, old->second.oids.size(),
                                 old->second.positions.size(), old->second.types.size(), 0);
        size_t new_meta = 256 + name.size() + count * sizeof(uint32_t) +
                          st.positions.size() * sizeof(uint32_t) + types.size() * sizeof(Type) +
                          columns.size() * sizeof(PgSQLColumn);
        for (const auto &column : columns) {
            if (column.name.size() > s.limits.metadata_total ||
                new_meta > s.limits.metadata_total - column.name.size())
                return s.fail(limit());
            new_meta += column.name.size();
        }
        if (new_meta > s.limits.metadata_total ||
            s.metadata_bytes() - old_meta > s.limits.metadata_total - new_meta)
            return s.fail(limit());
        st.oids = supplied;
        st.oids.resize(count, 0);
        for (size_t i = 0; i < types.size(); ++i) {
            auto pos = st.positions[i] - 1;
            uint32_t candidate = infer(types[i].kind);
            if (!st.oids[pos]) {
                st.oids[pos] = candidate;
            } else if (pos >= supplied.size() || supplied[pos] == 0) {
                if (candidate && st.oids[pos] != candidate)
                    return s.fail(err(ErrorKind::invalid_parameter,
                                      "conflicting inferred parameter types", "42P18"));
            }
        }
        for (auto oid : st.oids)
            if (!oid)
                return s.fail(err(ErrorKind::invalid_parameter,
                                  "could not determine parameter type", "42P18"));
        for (uint32_t oid : st.oids) {
            Value null_value;
            if (auto e =
                    pgsql_decode_parameter(oid, 0, nullptr, -1, null_value, s.limits.bind_total))
                return s.fail(e);
        }
        if (auto e = pgsql_describe_columns(columns, st.columns))
            return s.fail(e);
        st.types = types;
        if (old != s.statements.end()) {
            s.session.close(old->second.id);
            s.statements.erase(old);
        }
        auto inserted = s.statements.emplace(name, std::move(st));
        cleanup.id = 0;
        (void)inserted;
        return {};
    } catch (const std::bad_alloc &) {
        return s.fail(err(ErrorKind::resource, "out of memory", "53200"));
    } catch (const std::length_error &) {
        return s.fail(limit());
    } catch (...) {
        return s.fail(err(ErrorKind::internal, "controller operation threw", "XX000"));
    }
}
Status PgSQLPrepared::bind(const std::string &name, const std::string &statement,
                           const std::vector<PgSQLDatum> &input,
                           const std::vector<int16_t> &formats) {
    auto &s = *impl_;
    if (ignoring())
        return {};
    try {
        if (name.size() > s.limits.name_per || statement.size() > s.limits.name_per)
            return s.fail(limit());
        auto it = s.statements.find(statement);
        if (it == s.statements.end())
            return s.fail(err(ErrorKind::invalid_parameter, "unknown statement", "26000"));
        auto old = s.portals.find(name);
        if (old != s.portals.end() && !name.empty())
            return s.fail(err(ErrorKind::invalid_parameter, "duplicate portal", "42P03"));
        if (old == s.portals.end() && s.portals.size() >= s.limits.portals)
            return s.fail(limit());
        auto &st = it->second;
        if (input.size() != st.oids.size())
            return s.fail(err(ErrorKind::invalid_parameter, "parameter count mismatch", "08P01"));
        if (formats.size() != 0 && formats.size() != 1 && formats.size() != st.columns.size())
            return s.fail(
                err(ErrorKind::invalid_parameter, "result format count mismatch", "08P01"));
        size_t bytes = input.size() * sizeof(Value);
        for (auto &d : input) {
            if (d.length < -1)
                return s.fail(err(ErrorKind::invalid_parameter, "invalid datum length", "08P01"));
            size_t n = d.length < 0 ? 0 : size_t(d.length);
            if (n > s.limits.bind_total || bytes > s.limits.bind_total - n)
                return s.fail(limit());
            bytes += n;
        }
        size_t prior = old == s.portals.end() ? 0 : old->second.bind_bytes;
        if (bytes > s.limits.bind_total || s.bind_bytes() - prior > s.limits.bind_total - bytes)
            return s.fail(limit());
        size_t sqlprior = old == s.portals.end() ? 0 : old->second.sql.size();
        if (st.sql.size() > s.limits.sql_total ||
            s.sql_bytes() - sqlprior > s.limits.sql_total - st.sql.size())
            return s.fail(limit());
        size_t old_meta = old == s.portals.end()
                              ? 0
                              : Impl::metadata(old->first, old->second.columns, 0, 0, 0,
                                               old->second.formats.size());
        size_t new_meta = Impl::metadata(name, st.columns, 0, 0, 0, st.columns.size());
        if (new_meta > s.limits.metadata_total ||
            s.metadata_bytes() - old_meta > s.limits.metadata_total - new_meta)
            return s.fail(limit());
        Impl::Portal p;
        p.sql = st.sql;
        p.columns = st.columns;
        p.bind_bytes = bytes;
        p.formats.resize(st.columns.size());
        for (size_t i = 0; i < p.formats.size(); ++i) {
            p.formats[i] = formats.empty() ? 0 : formats.size() == 1 ? formats[0] : formats[i];
            if (auto e = pgsql_result_format_supported(p.columns[i], p.formats[i]))
                return s.fail(e);
        }
        if (formats.size() == 1 && formats[0] != 0 && formats[0] != 1)
            return s.fail(err(ErrorKind::invalid_parameter, "invalid result format", "08P01"));
        std::vector<Value> logical(input.size());
        for (size_t i = 0; i < input.size(); ++i)
            if (auto e = pgsql_decode_parameter(st.oids[i], input[i].format, input[i].data,
                                                input[i].length, logical[i], s.limits.bind_total))
                return s.fail(e);
        // Account for each owned native-slot copy, including repeated $n references.
        size_t expanded = st.positions.size() * sizeof(Value);
        for (auto pos : st.positions) {
            size_t n = value_payload_bytes(logical[pos - 1]);
            if (n > s.limits.bind_total || expanded > s.limits.bind_total - n)
                return s.fail(limit());
            expanded += n;
        }
        if (expanded > s.limits.bind_total ||
            s.bind_bytes() - prior > s.limits.bind_total - expanded)
            return s.fail(limit());
        p.bind_bytes = expanded;
        p.values.reserve(st.positions.size());
        for (auto pos : st.positions)
            p.values.push_back(logical[pos - 1]);
        std::unique_ptr<OperationGuard> g;
        if (auto e = s.guard(Operation::prepare, &p.sql, g))
            return s.fail(e);
        if (auto e = s.session.prepare(p.sql, p.id))
            return s.fail(e);
        struct Cleanup {
            Session &s;
            uint64_t &id;
            ~Cleanup() {
                if (id)
                    s.close(id);
            }
        } cleanup{s.session, p.id};
        std::vector<Type> types;
        std::vector<Column> cols;
        std::vector<uint32_t> positions;
        if (auto e = s.session.describe(p.id, types, cols))
            return s.fail(e);
        if (auto e = s.session.describe_parameter_positions(p.id, positions))
            return s.fail(e);
        if (cols.size() != st.columns.size() || types.size() != st.types.size() ||
            positions != st.positions)
            return s.fail(err(ErrorKind::schema_changed, "prepared metadata changed", "0A000"));
        for (size_t i = 0; i < cols.size(); ++i) {
            // Reject a changed name before cloning an adapter-owned name.
            if (cols[i].name != st.columns[i].name)
                return s.fail(err(ErrorKind::schema_changed, "prepared metadata changed", "0A000"));
        }
        std::vector<PgSQLColumn> clone_columns;
        if (auto e = pgsql_describe_columns(cols, clone_columns))
            return s.fail(e);
        bool changed = positions != st.positions || types.size() != st.types.size() ||
                       clone_columns.size() != st.columns.size();
        for (size_t i = 0; !changed && i < types.size(); ++i) {
            const auto &a = types[i];
            const auto &b = st.types[i];
            changed = a.kind != b.kind || a.precision != b.precision || a.scale != b.scale ||
                      a.nullable != b.nullable;
        }
        for (size_t i = 0; !changed && i < clone_columns.size(); ++i) {
            const auto &a = clone_columns[i];
            const auto &b = st.columns[i];
            changed = a.kind != b.kind || a.nullable != b.nullable || a.name != b.name ||
                      a.oid != b.oid || a.length != b.length || a.modifier != b.modifier;
        }
        if (changed)
            return s.fail(err(ErrorKind::schema_changed, "prepared metadata changed", "0A000"));
        if (old != s.portals.end()) {
            s.session.close(old->second.id);
            s.portals.erase(old);
        }
        s.portals.emplace(name, std::move(p));
        cleanup.id = 0;
        return {};
    } catch (const std::bad_alloc &) {
        return s.fail(err(ErrorKind::resource, "out of memory", "53200"));
    } catch (const std::length_error &) {
        return s.fail(limit());
    } catch (...) {
        return s.fail(err(ErrorKind::internal, "controller operation threw", "XX000"));
    }
}
Status PgSQLPrepared::describe_statement(const std::string &name, PgSQLDescription &out) {
    out = {};
    auto &s = *impl_;
    if (ignoring())
        return {};
    try {
        auto it = s.statements.find(name);
        if (it == s.statements.end())
            return s.fail(err(ErrorKind::invalid_parameter, "unknown statement", "26000"));
        PgSQLDescription result;
        result.parameter_oids = it->second.oids;
        result.columns = it->second.columns;
        result.formats.resize(result.columns.size());
        out = std::move(result);
        return {};
    } catch (const std::bad_alloc &) {
        return s.fail(err(ErrorKind::resource, "out of memory", "53200"));
    } catch (const std::length_error &) {
        return s.fail(limit());
    } catch (...) {
        return s.fail(err(ErrorKind::internal, "controller operation threw", "XX000"));
    }
}
Status PgSQLPrepared::describe_portal(const std::string &name, PgSQLDescription &out) {
    out = {};
    auto &s = *impl_;
    if (ignoring())
        return {};
    try {
        auto it = s.portals.find(name);
        if (it == s.portals.end())
            return s.fail(err(ErrorKind::invalid_parameter, "unknown portal", "34000"));
        PgSQLDescription result;
        result.columns = it->second.columns;
        result.formats = it->second.formats;
        out = std::move(result);
        return {};
    } catch (const std::bad_alloc &) {
        return s.fail(err(ErrorKind::resource, "out of memory", "53200"));
    } catch (const std::length_error &) {
        return s.fail(limit());
    } catch (...) {
        return s.fail(err(ErrorKind::internal, "controller operation threw", "XX000"));
    }
}
Status PgSQLPrepared::execute(const std::string &name, uint32_t max_rows, PgSQLExecution &out) {
    out = {};
    auto &s = *impl_;
    if (ignoring())
        return {};
    auto it = s.portals.find(name);
    if (it == s.portals.end())
        return s.fail(err(ErrorKind::invalid_parameter, "unknown portal", "34000"));
    auto &p = it->second;
    try {
        if (p.complete)
            return {};
        if (!p.started) {
            p.started = true;
            std::unique_ptr<OperationGuard> g;
            if (auto e = s.guard(Operation::execute, &p.sql, g))
                return s.fail(e);
            ExecInfo info;
            if (auto e = s.session.execute(p.id, p.values, info))
                return s.fail(e);
            size_t used = s.result_bytes();
            std::vector<PgSQLFieldRow> rows;
            if (info.has_result)
                for (;;) {
                    Row row;
                    bool done = false;
                    if (auto e = s.session.fetch(p.id, row, done))
                        return s.fail(e);
                    if (done)
                        break;
                    size_t overhead =
                        5 + 2 + sizeof(PgSQLFieldRow) + row.size() * (sizeof(PgSQLField) + 4);
                    if (overhead > s.limits.result_total || used > s.limits.result_total - overhead)
                        return s.fail(limit());
                    used += overhead;
                    PgSQLFieldRow fields(row.size());
                    for (size_t i = 0; i < row.size(); ++i) {
                        if (auto e = pgsql_encode_field(p.columns[i], p.formats[i], row[i],
                                                        fields[i].payload, fields[i].is_null,
                                                        s.limits.result_total - used))
                            return s.fail(e);
                        size_t n = fields[i].payload.size();
                        if (n > size_t(INT32_MAX) || n > s.limits.result_total - used)
                            return s.fail(limit());
                        used += n;
                    }
                    size_t frame = 2 + row.size() * 4;
                    for (const auto &field : fields) {
                        if (field.payload.size() > size_t(INT32_MAX) - frame)
                            return s.fail(limit());
                        frame += field.payload.size();
                    }
                    if (frame > size_t(INT32_MAX) - 4)
                        return s.fail(limit());
                    rows.push_back(std::move(fields));
                }
            p.result_bytes = used - s.result_bytes();
            p.rows = std::move(rows);
        }
        size_t remaining = p.rows.size() - p.cursor;
        size_t n = max_rows ? std::min(remaining, size_t(max_rows)) : remaining;
        out.rows.reserve(n);
        for (size_t i = 0; i < n; ++i)
            out.rows.push_back(std::move(p.rows[p.cursor + i]));
        p.cursor += n;
        out.row_count = n;
        out.suspended = max_rows && n == max_rows;
        if (!out.suspended)
            p.complete = true;
        return {};
    } catch (const std::bad_alloc &) {
        out = {};
        return s.fail(err(ErrorKind::resource, "out of memory", "53200"));
    } catch (const std::length_error &) {
        out = {};
        return s.fail(limit());
    } catch (...) {
        out = {};
        return s.fail(err(ErrorKind::internal, "controller operation threw", "XX000"));
    }
}
Status PgSQLPrepared::close_statement(const std::string &name) {
    auto &s = *impl_;
    if (ignoring())
        return {};
    try {
        auto it = s.statements.find(name);
        if (it == s.statements.end())
            return {};
        std::unique_ptr<OperationGuard> guard;
        if (auto e = s.guard(Operation::close, &it->second.sql, guard))
            return s.fail(e);
        s.session.close(it->second.id);
        s.statements.erase(it);
        return {};
    } catch (const std::bad_alloc &) {
        return s.fail(err(ErrorKind::resource, "out of memory", "53200"));
    } catch (const std::length_error &) {
        return s.fail(limit());
    } catch (...) {
        return s.fail(err(ErrorKind::internal, "controller operation threw", "XX000"));
    }
}
Status PgSQLPrepared::close_portal(const std::string &name) {
    auto &s = *impl_;
    if (ignoring())
        return {};
    try {
        auto it = s.portals.find(name);
        if (it == s.portals.end())
            return {};
        std::unique_ptr<OperationGuard> guard;
        if (auto e = s.guard(Operation::close, &it->second.sql, guard))
            return s.fail(e);
        s.session.close(it->second.id);
        s.portals.erase(it);
        return {};
    } catch (const std::bad_alloc &) {
        return s.fail(err(ErrorKind::resource, "out of memory", "53200"));
    } catch (const std::length_error &) {
        return s.fail(limit());
    } catch (...) {
        return s.fail(err(ErrorKind::internal, "controller operation threw", "XX000"));
    }
}
Status PgSQLPrepared::sync() {
    auto &s = *impl_;
    if (s.disconnected)
        return {};
    try {
        std::unique_ptr<OperationGuard> guard;
        if (auto error = s.guard(Operation::close, nullptr, guard))
            return s.fail(error);
        for (auto &portal : s.portals)
            s.session.close(portal.second.id);
        s.portals.clear();
        s.poisoned = false;
        return {};
    } catch (const std::bad_alloc &) {
        return s.fail(err(ErrorKind::resource, "out of memory", "53200"));
    } catch (const std::length_error &) {
        return s.fail(limit());
    } catch (...) {
        return s.fail(err(ErrorKind::internal, "controller operation threw", "XX000"));
    }
}
Status PgSQLPrepared::reject(const Error &error) {
    auto &s = *impl_;
    if (ignoring())
        return {};
    try {
        return s.fail(error);
    } catch (const std::bad_alloc &) {
        return s.fail(err(ErrorKind::resource, "out of memory", "53200"));
    } catch (const std::length_error &) {
        return s.fail(limit());
    } catch (...) {
        return s.fail(err(ErrorKind::internal, "controller operation threw", "XX000"));
    }
}
Status PgSQLPrepared::simple_query() {
    auto &s = *impl_;
    if (ignoring())
        return {};
    try {
        std::unique_ptr<OperationGuard> guard;
        if (auto error = s.guard(Operation::close, nullptr, guard))
            return s.fail(error);
        for (auto &portal : s.portals)
            s.session.close(portal.second.id);
        s.portals.clear();
        auto unnamed = s.statements.find("");
        if (unnamed != s.statements.end()) {
            s.session.close(unnamed->second.id);
            s.statements.erase(unnamed);
        }
        return {};
    } catch (const std::bad_alloc &) {
        return s.fail(err(ErrorKind::resource, "out of memory", "53200"));
    } catch (const std::length_error &) {
        return s.fail(limit());
    } catch (...) {
        return s.fail(err(ErrorKind::internal, "controller operation threw", "XX000"));
    }
}
void PgSQLPrepared::disconnect() noexcept {
    auto &s = *impl_;
    if (s.disconnected)
        return;
    try {
        std::unique_ptr<OperationGuard> g;
        if (s.guard(Operation::disconnect, nullptr, g))
            std::terminate();
        for (auto &p : s.portals)
            s.session.close(p.second.id);
        for (auto &p : s.statements)
            s.session.close(p.second.id);
        s.portals.clear();
        s.statements.clear();
        s.disconnected = true;
    } catch (...) {
        std::terminate();
    }
}
} // namespace embedded
