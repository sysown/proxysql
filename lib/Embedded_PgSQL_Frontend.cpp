#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Extended_Query_Message.h"
#include "PgSQL_Protocol.h"
#include "Embedded_PgSQL_Frontend.h"
#include <algorithm>
#include <climits>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace embedded {
namespace {
PgSQLPreparedLimits bounded(PgSQLPreparedLimits limits) {
    const PgSQLPreparedLimits hard;
    limits.statements = std::min(limits.statements, hard.statements);
    limits.portals = std::min(limits.portals, hard.portals);
    limits.parameters = std::min(limits.parameters, hard.parameters);
    limits.columns = std::min(limits.columns, hard.columns);
    limits.name_per = std::min(limits.name_per, hard.name_per);
    limits.sql_per = std::min(limits.sql_per, hard.sql_per);
    limits.metadata_total = std::min(limits.metadata_total, hard.metadata_total);
    limits.sql_total = std::min(limits.sql_total, hard.sql_total);
    limits.bind_total = std::min(limits.bind_total, hard.bind_total);
    limits.result_total = std::min(limits.result_total, hard.result_total);
    return limits;
}
struct Entry {
    Entry(Adapter &a, EndpointPolicy &p, GuardFactory g, PgSQLPreparedLimits l,
          std::function<uint8_t()> st)
        : adapter(a), policy(p), guard(std::move(g)), controller(a, p, guard, bounded(l)),
          limits(bounded(l)), status(st ? std::move(st) : [] { return uint8_t('I'); }),
          owner(std::this_thread::get_id()) {}
    Adapter &adapter;
    EndpointPolicy &policy;
    GuardFactory guard;
    PgSQLPrepared controller;
    PgSQLPreparedLimits limits;
    std::function<uint8_t()> status;
    std::thread::id owner;
};
bool transaction_status(Entry &entry, uint8_t &state) noexcept {
    try {
        state = entry.status();
        return state == 'I' || state == 'T' || state == 'E';
    } catch (...) {
        return false;
    }
}
struct Registry {
    std::mutex mutex;
    std::unordered_map<PgSQL_Session *, std::shared_ptr<Entry>> entries;
};
Registry &registry() {
    static Registry *r = new Registry;
    return *r;
}
std::shared_ptr<Entry> lookup(PgSQL_Session &s) {
    auto &r = registry();
    std::lock_guard<std::mutex> lock(r.mutex);
    auto it = r.entries.find(&s);
    return it == r.entries.end() ? nullptr : it->second;
}
Error error(ErrorKind k, const char *message, const char *state = "") {
    return {k, 0, message, state};
}
Error protocol(const char *m) {
    return error(ErrorKind::invalid_parameter, m, "08P01");
}
const char *fallback(ErrorKind k) {
    switch (k) {
    case ErrorKind::syntax:
        return "42601";
    case ErrorKind::unsupported:
        return "0A000";
    case ErrorKind::policy:
        return "42501";
    case ErrorKind::invalid_parameter:
        return "22023";
    case ErrorKind::range:
        return "22003";
    case ErrorKind::resource:
        return "54000";
    case ErrorKind::schema_changed:
        return "0A000";
    case ErrorKind::transaction:
        return "25000";
    default:
        return "XX000";
    }
}
std::string sqlstate(const Error &e) {
    if (e.sqlstate.size() == 5 && std::all_of(e.sqlstate.begin(), e.sqlstate.end(), [](char c) {
            return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        }))
        return e.sqlstate;
    return fallback(e.kind);
}
using Buffer = std::unique_ptr<void, decltype(&free)>;
struct Packet {
    Buffer data{nullptr, free};
    unsigned size = 0;
};
struct Batch {
    std::vector<Packet> packets;
    size_t bytes = 0;
    size_t limit;
    explicit Batch(size_t n) : limit(std::min(n, size_t(64u * 1024u * 1024u))) {}
    template <class F> void add(char type, size_t payload, F fill) {
        if (payload > INT32_MAX - 4 || payload + 5 > limit || bytes > limit - payload - 5)
            throw error(ErrorKind::resource, "response exceeds limit");
        unsigned n = static_cast<unsigned>(payload + 5);
        Buffer p(malloc(n), free);
        if (!p)
            throw std::bad_alloc();
        PG_pkt pkt(p.get(), n);
        try {
            pkt.put_char(type);
            pkt.put_uint32(static_cast<uint32_t>(payload + 4));
            fill(pkt);
        } catch (...) {
            pkt.detach();
            throw;
        }
        pkt.detach();
        packets.push_back({std::move(p), n});
        bytes += n;
    }
    void empty(char type) {
        add(type, 0, [](PG_pkt &) {});
    }
    void publish(PgSQL_Session &s) {
        // PtrSizeArray::add follows the core allocator contract and has no fallible reserve API.
        for (auto &p : packets) {
            s.client_myds->PSarrayOUT->add(p.data.get(), p.size);
            p.data.release();
        }
        s.status = WAITING_CLIENT_DATA;
        s.client_myds->DSS = STATE_SLEEP;
    }
};
void add_error(Batch &b, const Error &e) {
    std::string msg = e.message.substr(0, 4096);
    std::replace(msg.begin(), msg.end(), '\0', ' ');
    auto state = sqlstate(e);
    b.add('E', 1 + 6 + 1 + 6 + 1 + msg.size() + 1 + 1, [&](PG_pkt &p) {
        p.put_char('S');
        p.put_string("ERROR");
        p.put_char('C');
        p.put_string(state.c_str());
        p.put_char('M');
        p.put_string(msg.c_str());
        p.put_char(0);
    });
}
void describe(Batch &b, const PgSQLDescription &d, bool statement) {
    if (d.parameter_oids.size() > UINT16_MAX || d.columns.size() > UINT16_MAX)
        throw error(ErrorKind::resource, "too many description fields");
    if (statement)
        b.add('t', 2 + d.parameter_oids.size() * 4, [&](PG_pkt &p) {
            p.put_uint16(d.parameter_oids.size());
            for (auto oid : d.parameter_oids)
                p.put_uint32(oid);
        });
    if (d.columns.empty()) {
        b.empty('n');
        return;
    }
    size_t size = 2;
    for (auto &c : d.columns)
        size += c.name.size() + 1 + 18;
    b.add('T', size, [&](PG_pkt &p) {
        p.put_uint16(d.columns.size());
        for (size_t i = 0; i < d.columns.size(); ++i) {
            auto &c = d.columns[i];
            p.put_string(c.name.c_str());
            p.put_uint32(0);
            p.put_uint16(0);
            p.put_uint32(c.oid);
            p.put_uint16(static_cast<uint16_t>(c.length));
            p.put_uint32(static_cast<uint32_t>(c.modifier));
            p.put_uint16(statement ? 0 : d.formats[i]);
        }
    });
}
void execute(Batch &b, const PgSQLExecution &result) {
    for (auto &row : result.rows) {
        size_t size = 2;
        for (auto &field : row) {
            if (field.payload.size() > INT32_MAX || size > SIZE_MAX - 4 - field.payload.size())
                throw error(ErrorKind::resource, "row exceeds limit");
            size += 4 + (field.is_null ? 0 : field.payload.size());
        }
        if (row.size() > UINT16_MAX)
            throw error(ErrorKind::resource, "too many fields");
        b.add('D', size, [&](PG_pkt &p) {
            p.put_uint16(row.size());
            for (auto &field : row) {
                p.put_uint32(field.is_null ? UINT32_MAX
                                           : static_cast<uint32_t>(field.payload.size()));
                if (!field.is_null && !field.payload.empty())
                    p.put_bytes(field.payload.data(), field.payload.size());
            }
        });
    }
    if (result.suspended)
        b.empty('s');
    else {
        auto tag = std::string("SELECT ") + std::to_string(result.row_count);
        b.add('C', tag.size() + 1, [&](PG_pkt &p) { p.put_string(tag.c_str()); });
    }
}
void consume(PtrSize_t &p) {
    free(p.ptr);
    p = {};
}
} // namespace
Status register_pgsql_prepared(PgSQL_Session &s, Adapter &a, EndpointPolicy &p,
                               PgSQLPreparedLimits limits, GuardFactory guard,
                               std::function<uint8_t()> status) {
    if (s.session_type == PROXYSQL_SESSION_PGSQL)
        return error(ErrorKind::unsupported, "proxy session");
    try {
        auto entry = std::make_shared<Entry>(a, p, std::move(guard), limits, std::move(status));
        auto &r = registry();
        std::lock_guard<std::mutex> lock(r.mutex);
        if (r.entries.find(&s) != r.entries.end())
            return error(ErrorKind::invalid_parameter, "session already registered");
        r.entries.emplace(&s, entry);
        return {};
    } catch (...) {
        return error(ErrorKind::resource, "unable to register session");
    }
}
void unregister_pgsql_prepared(PgSQL_Session &s) noexcept {
    // Embedded endpoints register here; an ordinary proxy session skips the registry lock.
    if (s.session_type == PROXYSQL_SESSION_PGSQL)
        return;
    std::shared_ptr<Entry> entry;
    {
        auto &r = registry();
        std::lock_guard<std::mutex> lock(r.mutex);
        auto it = r.entries.find(&s);
        if (it == r.entries.end())
            return;
        if (it->second->owner != std::this_thread::get_id())
            return;
        entry = std::move(it->second);
        r.entries.erase(it);
    }
    entry->controller.disconnect();
}
Status reset_pgsql_prepared(PgSQL_Session &s) {
    auto entry = lookup(s);
    if (!entry)
        return error(ErrorKind::invalid_parameter, "session not registered");
    if (entry->owner != std::this_thread::get_id())
        return error(ErrorKind::internal, "wrong session thread");
    try {
        auto replacement =
            std::make_shared<Entry>(entry->adapter, entry->policy, entry->guard, entry->limits, entry->status);
        auto &r = registry();
        {
            std::lock_guard<std::mutex> lock(r.mutex);
            auto it = r.entries.find(&s);
            if (it == r.entries.end() || it->second != entry)
                return error(ErrorKind::internal, "session registration changed");
            it->second = std::move(replacement);
        }
        entry->controller.disconnect();
        return {};
    } catch (...) {
        return error(ErrorKind::resource, "unable to reset session");
    }
}
bool handle_pgsql_prepared(PgSQL_Session &s, PtrSize_t &pkt) {
    auto entry = lookup(s);
    if (!entry || s.session_type == PROXYSQL_SESSION_PGSQL || !pkt.ptr || !pkt.size)
        return false;
    char type = *static_cast<char *>(pkt.ptr);
    if (type == 'X')
        return false;
    if (type != 'P' && type != 'B' && type != 'D' && type != 'E' && type != 'C' && type != 'H' &&
        type != 'S' && type != 'Q')
        return false;
    if (entry->owner != std::this_thread::get_id())
        return false;
    auto &ctl = entry->controller;
    if (ctl.ignoring() && type != 'S') {
        consume(pkt);
        return true;
    }
    if (type == 'Q') {
        auto status = ctl.simple_query();
        if (!status)
            return false;
        consume(pkt);
        ctl.reject(*status);
        if (ctl.sync()) {
            s.healthy = false;
            return true;
        }
        try {
            Batch errors(8192);
            uint8_t state;
            if (!transaction_status(*entry, state)) {
                add_error(errors, error(ErrorKind::internal, "invalid transaction status", "XX000"));
                s.healthy = false;
            } else {
                add_error(errors, *status);
                errors.add('Z', 1, [state](PG_pkt &p) { p.put_char(state); });
            }
            errors.publish(s);
        } catch (...) {
            s.healthy = false;
        }
        return true;
    }
    try {
        Batch batch(entry->limits.result_total);
        Status status;
        if (pkt.size > 16u * 1024u * 1024u +
                           std::min(entry->limits.metadata_total, size_t(16u * 1024u * 1024u)))
            status = error(ErrorKind::resource, "packet exceeds limit");
        else if (type == 'H' || type == 'S') {
            uint32_t len = 0;
            if (pkt.size != 5 || !get_uint32be(static_cast<unsigned char *>(pkt.ptr) + 1, &len) ||
                len != 4)
                status = protocol("invalid control packet");
            else if (type == 'S') {
                status = ctl.sync();
                if (!status) {
                    uint8_t state;
                    if (!transaction_status(*entry, state)) {
                        status = error(ErrorKind::internal, "invalid transaction status", "XX000");
                        s.healthy = false;
                    } else {
                        batch.add('Z', 1, [state](PG_pkt &p) { p.put_char(state); });
                    }
                }
            }
            consume(pkt);
        } else if (type == 'P') {
            PgSQL_Parse_Message msg;
            if (!msg.parse(pkt))
                status = protocol("invalid Parse message");
            else {
                auto &d = msg.data();
                if (strnlen(d.stmt_name, entry->limits.name_per + 1) > entry->limits.name_per ||
                    strnlen(d.query_string, entry->limits.sql_per + 1) > entry->limits.sql_per ||
                    d.num_param_types > entry->limits.parameters)
                    status = error(ErrorKind::resource, "Parse limits exceeded");
                else {
                    std::vector<uint32_t> oids;
                    oids.reserve(d.num_param_types);
                    auto reader = msg.get_param_types_reader();
                    uint32_t oid;
                    while (reader.next(&oid))
                        oids.push_back(oid);
                    status = ctl.parse(d.stmt_name, d.query_string, oids);
                    if (!status)
                        batch.empty('1');
                }
            }
        } else if (type == 'B') {
            PgSQL_Bind_Message msg;
            if (!msg.parse(pkt))
                status = protocol("invalid Bind message");
            else {
                auto &d = msg.data();
                if (strnlen(d.portal_name, entry->limits.name_per + 1) > entry->limits.name_per ||
                    strnlen(d.stmt_name, entry->limits.name_per + 1) > entry->limits.name_per ||
                    d.num_param_values > entry->limits.parameters ||
                    d.num_result_formats > entry->limits.columns)
                    status = error(ErrorKind::resource, "Bind limits exceeded");
                else if (d.num_param_formats != 0 && d.num_param_formats != 1 &&
                         d.num_param_formats != d.num_param_values)
                    status = protocol("parameter format count mismatch");
                else {
                    std::vector<int16_t> formats, result_formats;
                    auto fr = msg.get_param_format_reader();
                    uint16_t v;
                    while (fr.next(&v)) {
                        if (v > 1) {
                            status = protocol("invalid parameter format");
                            break;
                        }
                        formats.push_back(v);
                    }
                    auto rr = msg.get_result_format_reader();
                    while (rr.next(&v)) {
                        if (v > 1) {
                            status = protocol("invalid result format");
                            break;
                        }
                        result_formats.push_back(v);
                    }
                    if (!status) {
                        std::vector<PgSQLDatum> values;
                        values.reserve(d.num_param_values);
                        auto vr = msg.get_param_value_reader();
                        PgSQL_Param_Value value;
                        while (vr.next(&value)) {
                            auto i = values.size();
                            values.push_back(
                                {value.value, value.len,
                                 static_cast<int16_t>(formats.empty()       ? 0
                                                      : formats.size() == 1 ? formats[0]
                                                                            : formats[i])});
                        }
                        status = ctl.bind(d.portal_name, d.stmt_name, values, result_formats);
                        if (!status)
                            batch.empty('2');
                    }
                }
            }
        } else if (type == 'D') {
            PgSQL_Describe_Message msg;
            if (!msg.parse(pkt))
                status = protocol("invalid Describe message");
            else if (strnlen(msg.data().stmt_name, entry->limits.name_per + 1) >
                     entry->limits.name_per)
                status = error(ErrorKind::resource, "name exceeds limit");
            else {
                PgSQLDescription d;
                bool stmt = msg.data().stmt_type == 'S';
                status = stmt ? ctl.describe_statement(msg.data().stmt_name, d)
                              : ctl.describe_portal(msg.data().stmt_name, d);
                if (!status)
                    describe(batch, d, stmt);
            }
        } else if (type == 'E') {
            PgSQL_Execute_Message msg;
            if (!msg.parse(pkt))
                status = protocol("invalid Execute message");
            else if (strnlen(msg.data().portal_name, entry->limits.name_per + 1) >
                     entry->limits.name_per)
                status = error(ErrorKind::resource, "name exceeds limit");
            else if (msg.data().max_rows > INT32_MAX)
                status = protocol("invalid Execute row limit");
            else {
                PgSQLExecution result;
                status = ctl.execute(msg.data().portal_name, msg.data().max_rows, result);
                if (!status)
                    execute(batch, result);
            }
        } else {
            PgSQL_Close_Message msg;
            if (!msg.parse(pkt))
                status = protocol("invalid Close message");
            else if (strnlen(msg.data().stmt_name, entry->limits.name_per + 1) >
                     entry->limits.name_per)
                status = error(ErrorKind::resource, "name exceeds limit");
            else {
                status = msg.data().stmt_type == 'S' ? ctl.close_statement(msg.data().stmt_name)
                                                     : ctl.close_portal(msg.data().stmt_name);
                if (!status)
                    batch.empty('3');
            }
        }
        if (pkt.ptr)
            consume(pkt);
        if (status) {
            ctl.reject(*status);
            Batch errors(8192);
            add_error(errors, *status);
            errors.publish(s);
        } else {
            batch.publish(s);
            if (type == 'H')
                s.writeout();
        }
    } catch (const Error &e) {
        if (pkt.ptr)
            consume(pkt);
        ctl.reject(e);
        try {
            Batch errors(8192);
            add_error(errors, e);
            errors.publish(s);
        } catch (...) {
            s.healthy = false;
        }
    } catch (...) {
        if (pkt.ptr)
            consume(pkt);
        auto e = error(ErrorKind::resource, "unable to process message");
        ctl.reject(e);
        try {
            Batch errors(8192);
            add_error(errors, e);
            errors.publish(s);
        } catch (...) {
            s.healthy = false;
        }
    }
    return true;
}
} // namespace embedded
