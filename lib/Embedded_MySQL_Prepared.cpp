#include "Embedded_MySQL_Prepared.h"
#include "Embedded_MySQL_Result.h"

#include "MySQL_Protocol.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "gen_utils.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace embedded {
namespace {

struct StmtState {
    uint32_t wire_id = 0;
    uint64_t core_id = 0;
    std::string sql;
    std::vector<Type> params;
    std::vector<Column> columns;
    std::vector<MySQLColumn> mysql_columns;
    std::vector<unsigned char> effective_types;
    size_t longdata_bytes = 0;
    std::set<uint16_t> longdata_entries;
    bool has_deferred_error = false;
    uint16_t deferred_code = 0;
    std::string deferred_sqlstate = "HY000";
    std::string deferred_message;
    size_t metadata_bytes = 0;
};

struct SharedState {
    MySQL_Session* session = nullptr;
    std::thread::id owner_thread;
    Adapter* adapter = nullptr;
    EndpointPolicy* policy = nullptr;
    MySQLStatus status_cb;
    MySQLPreparedLimits limits;
    GuardFactory guard_factory;
    Session core;
    StmtLongDataHandler longdata;
    uint64_t next_wire_id = 1;
    std::map<uint32_t, std::unique_ptr<StmtState>> statements;
    size_t sql_total_used = 0;
    size_t longdata_total_used = 0;
    size_t metadata_total_used = 0;
    SharedState(MySQL_Session& s, Adapter& a, EndpointPolicy& p, MySQLStatus cb,
               MySQLPreparedLimits l, GuardFactory factory)
        : session(&s), owner_thread(std::this_thread::get_id()), adapter(&a),
          policy(&p), status_cb(std::move(cb)), limits(l), guard_factory(std::move(factory)),
          core(a, p, l.statements, l.response_bytes) {}
};

// Intentionally process-lifetime objects: sessions may be destroyed during static teardown.
std::mutex& registry_mutex() { static auto* mutex = new std::mutex; return *mutex; }
std::map<MySQL_Session*, std::shared_ptr<SharedState>>& registry() {
    static auto* states = new std::map<MySQL_Session*, std::shared_ptr<SharedState>>;
    return *states;
}
void free_temp_packets(PtrSizeArray& temp);
struct OutputSwap {
    MySQL_Data_Stream& stream;
    PtrSizeArray* original;
    uint8_t old_sid;
    PtrSizeArray& temporary;
    bool committed = false;
    explicit OutputSwap(MySQL_Data_Stream& ds, PtrSizeArray& temporary)
        : stream(ds), original(ds.PSarrayOUT), old_sid(ds.pkt_sid), temporary(temporary) { stream.PSarrayOUT = &temporary; }
    ~OutputSwap() { stream.PSarrayOUT = original; if (!committed) { stream.pkt_sid = old_sid; free_temp_packets(temporary); } }
};

bool is_ordinary_proxy_mysql(MySQL_Session& session) {
    return session.session_type == PROXYSQL_SESSION_MYSQL;
}

// Adapter native codes belong to their engine, not the MySQL protocol namespace.
uint16_t mysql_error_code(const Error& error) {
    switch (error.kind) {
        case ErrorKind::syntax: return 1064;
        case ErrorKind::unsupported: case ErrorKind::policy: return 1235;
        case ErrorKind::invalid_parameter: return 1210;
        case ErrorKind::range: return 1264;
        case ErrorKind::resource: return 1041;
        case ErrorKind::schema_changed: return 1615;
        default: return 1105;
    }
}

std::string valid_sqlstate_or_hy000(const std::string& in) {
    if (in == "HY000") return in;
    if (in.size() != 5) return "HY000";
    for (char c : in) {
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) return "HY000";
    }
    return in;
}

void send_err(MySQL_Session& session, uint8_t seq, uint16_t code, const std::string& state,
              const std::string& msg) {
    MySQL_Data_Stream* ds = session.client_myds;
    if (!ds) return;
    std::string ss = valid_sqlstate_or_hy000(state);
    ds->setDSS_STATE_QUERY_SENT_NET();
    ds->myprot.generate_pkt_ERR(true, nullptr, nullptr, seq, code, ss.c_str(),
                                msg.empty() ? (char*)"error" : (char*)msg.c_str());
    ds->DSS = STATE_SLEEP;
    session.status = WAITING_CLIENT_DATA;
}

uint8_t request_seq(PtrSize_t& pkt) {
    if (pkt.size >= 4 && pkt.ptr) return static_cast<unsigned char*>(pkt.ptr)[3];
    return 0;
}

void free_packet(PtrSize_t& pkt) {
    if (pkt.ptr) {
        l_free(pkt.size, pkt.ptr);
        pkt.ptr = nullptr;
        pkt.size = 0;
    }
}

std::shared_ptr<SharedState> lookup(MySQL_Session& session) {
    std::lock_guard<std::mutex> lock(registry_mutex());
    auto it = registry().find(&session);
    if (it == registry().end()) return nullptr;
    return it->second;
}

bool owner_ok(const SharedState& state) {
    return state.owner_thread == std::this_thread::get_id();
}

void free_temp_packets(PtrSizeArray& temp) {
    for (unsigned i = 0; i < temp.len; i++) {
        PtrSize_t* p = temp.index(i);
        if (p->ptr) l_free(p->size, p->ptr);
    }
    temp.len = 0;
}

void add_fragmented_row(PtrSizeArray& temp, uint8_t& seq, const std::vector<unsigned char>& payload) {
    const size_t hdr = sizeof(mysql_hdr);
    if (payload.size() < 0xFFFFFFu) {
        unsigned int size = static_cast<unsigned int>(payload.size() + hdr);
        unsigned char* buf = static_cast<unsigned char*>(l_alloc(size));
        mysql_hdr myhdr;
        myhdr.pkt_id = seq;
        myhdr.pkt_length = static_cast<uint32_t>(payload.size());
        memcpy(buf, &myhdr, hdr);
        memcpy(buf + hdr, payload.data(), payload.size());
        temp.add(buf, size);
        seq++;
        return;
    }
    size_t copied = 0;
    while (copied + 0xFFFFFFu <= payload.size()) {
        unsigned int size = 0xFFFFFFu + static_cast<unsigned int>(hdr);
        unsigned char* buf = static_cast<unsigned char*>(l_alloc(size));
        mysql_hdr myhdr;
        myhdr.pkt_id = seq;
        myhdr.pkt_length = 0xFFFFFFu;
        memcpy(buf, &myhdr, hdr);
        memcpy(buf + hdr, payload.data() + copied, 0xFFFFFFu);
        temp.add(buf, size);
        seq++;
        copied += 0xFFFFFFu;
    }
    size_t left = payload.size() - copied;
    // empty terminator if exact multiple
    if (left == 0) {
        unsigned int size = static_cast<unsigned int>(hdr);
        unsigned char* buf = static_cast<unsigned char*>(l_alloc(size));
        mysql_hdr myhdr;
        myhdr.pkt_id = seq;
        myhdr.pkt_length = 0;
        memcpy(buf, &myhdr, hdr);
        temp.add(buf, size);
        seq++;
        return;
    }
    unsigned int size = static_cast<unsigned int>(left + hdr);
    unsigned char* buf = static_cast<unsigned char*>(l_alloc(size));
    mysql_hdr myhdr;
    myhdr.pkt_id = seq;
    myhdr.pkt_length = static_cast<uint32_t>(left);
    memcpy(buf, &myhdr, hdr);
    memcpy(buf + hdr, payload.data() + copied, left);
    temp.add(buf, size);
    seq++;
}

// Exact size of the standard field packet emitted by generate_pkt_field.
size_t field_packet_size(const std::string& name) {
    return 25 + mysql_encode_length(name.size(), nullptr) + name.size();
}
bool charge(size_t& remaining, size_t size) {
    if (size > remaining) return false;
    remaining -= size;
    return true;
}
size_t max_ok_packet_size(const MySQL_Session& session) {
    // Two maximum-width length-encoded integers, status and warnings.
    size_t size = 27;
    if (session.client_myds && session.client_myds->myconn &&
        (session.client_myds->myconn->options.client_flag & CLIENT_SESSION_TRACKING) &&
        mysql_thread___client_session_track_gtid && session.gtid_hid >= 0) {
        size += 5 + 9 + strlen(session.gtid_buf);
    }
    return size;
}
bool metadata_fits(const std::vector<Column>& columns, size_t params, bool prepare,
                   bool deprecate, size_t budget, size_t* remaining = nullptr) {
    if (!charge(budget, prepare ? 16 : 4 + mysql_encode_length(columns.size(), nullptr))) return false;
    if (prepare) {
        for (size_t i = 0; i < params; ++i) if (!charge(budget, 27)) return false;
        if (params && !deprecate && !charge(budget, 9)) return false;
    }
    for (const auto& c : columns) if (!charge(budget, field_packet_size(c.name))) return false;
    if (!deprecate && !columns.empty() && !charge(budget, 9)) return false;
    if (remaining) *remaining = budget;
    return true;
}
size_t row_frame_bytes(size_t payload) {
    return (payload / 0xFFFFFFu + 1) * sizeof(mysql_hdr);
}

// Decode fixed integer little endian
uint64_t read_uint_le(const unsigned char* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

Status make_status(ErrorKind kind, int code, const std::string& message, const std::string& sqlstate) {
    return Error{kind, code, message, valid_sqlstate_or_hy000(sqlstate.empty() ? std::string("HY000") : sqlstate)};
}

Status acquire_guard(SharedState& state, Operation operation, std::unique_ptr<OperationGuard>& guard,
                     const std::string* sql = nullptr) {
    if (!state.guard_factory) return {};
    try {
        auto error = state.guard_factory(OperationContext{operation, sql}, guard);
        if (error) { guard.reset(); return error; }
        if (!guard) return make_status(ErrorKind::internal, 0, "operation guard factory returned no guard", "HY000");
        return {};
    } catch (const std::bad_alloc&) {
        guard.reset();
        return make_status(ErrorKind::resource, 0, "operation guard allocation failed", "HY000");
    } catch (const std::exception&) {
        guard.reset();
        return make_status(ErrorKind::internal, 0, "operation guard factory threw", "HY000");
    } catch (...) {
        guard.reset();
        return make_status(ErrorKind::internal, 0, "operation guard factory threw", "HY000");
    }
}

void close_all(SharedState& state) {
    for (auto& kv : state.statements) {
        state.core.close(kv.second->core_id);
        state.longdata.reset(kv.first);
    }
    state.statements.clear();
    state.sql_total_used = state.longdata_total_used = state.metadata_total_used = 0;
}

}  // namespace

Status register_mysql_prepared(MySQL_Session& session, Adapter& adapter,
                              EndpointPolicy& policy, MySQLStatus status,
                              MySQLPreparedLimits limits, GuardFactory guard_factory) {
    if (is_ordinary_proxy_mysql(session)) {
        return make_status(ErrorKind::unsupported, 1235, "ordinary proxy MySQL sessions are not prepared endpoints", "HY000");
    }
    std::lock_guard<std::mutex> lock(registry_mutex());
    if (registry().count(&session)) {
        return make_status(ErrorKind::invalid_parameter, 1105, "session already registered", "HY000");
    }
    auto state = std::make_shared<SharedState>(session, adapter, policy, std::move(status), limits, std::move(guard_factory));
    registry()[&session] = state;
    return {};
}

void unregister_mysql_prepared(MySQL_Session& session) noexcept {
    auto state = lookup(session);
    if (!state || !owner_ok(*state)) return;
    try {
        std::unique_ptr<OperationGuard> guard;
        if (acquire_guard(*state, Operation::disconnect, guard)) {
            std::fprintf(stderr, "embedded prepared: disconnect guard failed; terminating\n");
            std::terminate();
        }
        close_all(*state);
        std::lock_guard<std::mutex> lock(registry_mutex());
        registry().erase(&session);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "embedded prepared: disconnect guard threw: %s; terminating\n", e.what());
        std::terminate();
    } catch (...) {
        std::fprintf(stderr, "embedded prepared: disconnect guard threw; terminating\n");
        std::terminate();
    }
}

Status reset_mysql_prepared(MySQL_Session& session) {
    auto state = lookup(session);
    if (!state) return {};
    if (!owner_ok(*state)) return make_status(ErrorKind::invalid_parameter, 1105, "owner thread mismatch", "HY000");
    std::unique_ptr<OperationGuard> guard;
    if (auto error = acquire_guard(*state, Operation::reset, guard)) return error;
    close_all(*state);
    return {};
}

bool handle_mysql_prepared(MySQL_Session& session, PtrSize_t& pkt) {
    auto state = lookup(session);
    if (!state) return false;
    if (!owner_ok(*state)) return false;


    // Need at least command byte
    if (!pkt.ptr || pkt.size < 5) {
        // No command byte is available for this controller to dispatch.
        return false;
    }
    unsigned char* base = static_cast<unsigned char*>(pkt.ptr);
    uint8_t cmd = base[4];
    uint8_t rseq = request_seq(pkt);

    auto finish_consume = [&]() {
        free_packet(pkt);
        session.client_myds->setDSS_STATE_QUERY_SENT_NET();
        session.client_myds->DSS = STATE_SLEEP;
        session.status = WAITING_CLIENT_DATA;
    };

    Operation operation;
    switch (cmd) {
        case 0x16: operation = Operation::prepare; break;
        case 0x17: operation = Operation::execute; break;
        case 0x18: operation = Operation::long_data; break;
        case 0x19: operation = Operation::close; break;
        case 0x1a: operation = Operation::reset; break;
        case 0x1c: operation = Operation::fetch; break;
        default: return false;
    }
    const std::string* operation_sql = nullptr;
    if (operation == Operation::execute && pkt.size >= 9) {
        uint32_t id = static_cast<uint32_t>(read_uint_le(base + 5, 4));
        auto it = state->statements.find(id);
        if (it != state->statements.end()) operation_sql = &it->second->sql;
    }
    std::unique_ptr<OperationGuard> guard;
    if (auto error = acquire_guard(*state, operation, guard, operation_sql)) {
        if (operation == Operation::execute && pkt.size >= 9) {
            uint32_t id = static_cast<uint32_t>(read_uint_le(base + 5, 4));
            auto it = state->statements.find(id);
            if (it != state->statements.end()) {
                auto& stmt = *it->second;
                state->longdata.reset(id);
                state->longdata_total_used -= stmt.longdata_bytes;
                stmt.longdata_bytes = 0;
                stmt.longdata_entries.clear();
                stmt.has_deferred_error = false;
                stmt.deferred_sqlstate = "HY000";
            }
        }
        if (operation == Operation::long_data) {
            if (pkt.size >= 9) {
                uint32_t id = static_cast<uint32_t>(read_uint_le(base + 5, 4));
                auto it = state->statements.find(id);
                if (it != state->statements.end() && !it->second->has_deferred_error) {
                    auto& stmt = *it->second;
                    stmt.has_deferred_error = true;
                    stmt.deferred_code = mysql_error_code(*error);
                    stmt.deferred_sqlstate = valid_sqlstate_or_hy000(error->sqlstate);
                    stmt.deferred_message = error->message.substr(0, 1024);
                }
            }
        } else if (operation != Operation::close) {
            send_err(session, rseq + 1, mysql_error_code(*error), error->sqlstate, error->message);
        }
        finish_consume();
        return true;
    }

    if (cmd == 0x16) { // PREPARE
        // SQL from offset 5
        size_t sql_len = (pkt.size >= 5) ? (pkt.size - 5) : 0;
        const char* sql_ptr = (pkt.size >= 5) ? reinterpret_cast<const char*>(base + 5) : "";
        // enforce limits before allocating the SQL string
        if (sql_len > state->limits.sql_per_statement || sql_len > state->limits.sql_total - std::min(state->limits.sql_total, state->sql_total_used)) {
            send_err(session, rseq + 1, 1105, "HY000", "sql limit exceeded");
            finish_consume();
            return true;
        }
        std::string sql(sql_ptr, sql_len);

        // enforce sql limits
        if (sql.size() > state->limits.sql_per_statement) {
            send_err(session, rseq + 1, 1105, "HY000", "sql per statement limit exceeded");
            finish_consume();
            return true;
        }
        if (state->sql_total_used + sql.size() > state->limits.sql_total) {
            send_err(session, rseq + 1, 1105, "HY000", "sql total limit exceeded");
            finish_consume();
            return true;
        }
        if (state->statements.size() >= state->limits.statements) {
            send_err(session, rseq + 1, 1105, "HY000", "statement limit exceeded");
            finish_consume();
            return true;
        }

        // core prepare
        uint64_t core_id = 0;
        if (auto err = state->core.prepare(sql, core_id)) {
            send_err(session, rseq + 1, mysql_error_code(*err),
                     err->sqlstate, err->message);
            finish_consume();
            return true;
        }

        // describe
        std::vector<Type> params;
        std::vector<Column> columns;
        if (auto err = state->core.describe(core_id, params, columns)) {
            state->core.close(core_id);
            send_err(session, rseq + 1, mysql_error_code(*err),
                     err->sqlstate, err->message);
            finish_consume();
            return true;
        }

        // limits params/columns
        if (params.size() > std::min<size_t>(65535, state->limits.parameters_per_statement)) {
            state->core.close(core_id);
            send_err(session, rseq + 1, 1105, "HY000", "parameter count limit exceeded");
            finish_consume();
            return true;
        }
        if (columns.size() > state->limits.columns_per_statement) {
            state->core.close(core_id);
            send_err(session, rseq + 1, 1105, "HY000", "column count limit exceeded");
            finish_consume();
            return true;
        }

        // mysql describe columns
        std::vector<MySQLColumn> mysql_columns;
        if (auto st = mysql_describe_columns(columns, mysql_columns)) {
            state->core.close(core_id);
            send_err(session, rseq + 1, 1105, "HY000", st->message);
            finish_consume();
            return true;
        }

        // metadata bytes
        size_t meta = 0;
        for (const auto& c : columns) meta += c.name.size() + 64;
        meta += params.size() * 16;
        if (state->metadata_total_used + meta > state->limits.metadata_total) {
            state->core.close(core_id);
            send_err(session, rseq + 1, 1105, "HY000", "metadata total limit exceeded");
            finish_consume();
            return true;
        }

        bool deprecate_prepare = session.client_myds->myconn &&
            (session.client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF);
        if (!metadata_fits(columns, params.size(), true, deprecate_prepare, state->limits.response_bytes)) {
            state->core.close(core_id);
            send_err(session, rseq + 1, 1105, "HY000", "response bytes limit exceeded");
            finish_consume();
            return true;
        }

        // build MYSQL_FIELD descriptors
        std::vector<std::string> names;
        names.reserve(columns.size());
        for (const auto& c : columns) names.push_back(c.name);
        std::vector<MYSQL_FIELD> fields(columns.size());
        std::vector<char> dbbuf, tablebuf, orgtablebuf, orgnamebuf;
        // use static empty strings
        const char* empty = "";
        for (size_t i = 0; i < columns.size(); i++) {
            memset(&fields[i], 0, sizeof(MYSQL_FIELD));
            fields[i].db = (char*)empty;
            fields[i].table = (char*)empty;
            fields[i].org_table = (char*)empty;
            fields[i].name = strdup(names[i].c_str());
            fields[i].org_name = (char*)empty;
            fields[i].db_length = 0;
            fields[i].table_length = 0;
            fields[i].org_table_length = 0;
            fields[i].name_length = (unsigned long)names[i].size();
            fields[i].org_name_length = 0;
            fields[i].catalog = (char*)"def";
            fields[i].catalog_length = 3;
            fields[i].charsetnr = mysql_columns[i].charset;
            fields[i].length = mysql_columns[i].length;
            fields[i].type = (enum_field_types)mysql_columns[i].wire_type;
            fields[i].flags = mysql_columns[i].flags;
            fields[i].decimals = mysql_columns[i].decimals;
        }

        std::vector<MYSQL_FIELD*> fieldptrs(columns.size());
        for (size_t i = 0; i < columns.size(); i++) fieldptrs[i] = &fields[i];

        // temp buffer
        MySQL_Data_Stream* ds = session.client_myds;
        MySQL_Protocol& proto = ds->myprot;
        // We'll swap pointer instead
        PtrSizeArray* original_ptr = ds->PSarrayOUT;
        PtrSizeArray temp(0);
        OutputSwap output_swap(*ds, temp);

        uint16_t warnings = 0;
        uint16_t server_status = state->status_cb ? state->status_cb() : 0;
        if (state->next_wire_id > std::numeric_limits<uint32_t>::max()) {
            ds->PSarrayOUT = original_ptr;
            ds->pkt_sid = output_swap.old_sid;
            output_swap.committed = true;
            state->core.close(core_id);
            for (auto& f : fields) free(f.name);
            send_err(session, rseq + 1, 1105, "HY000", "statement IDs exhausted");
            finish_consume();
            return true;
        }
        uint32_t wire_id = static_cast<uint32_t>(state->next_wire_id++);

        bool ok = true;
        if (columns.empty()) {
            ok = proto.generate_STMT_PREPARE_RESPONSE(rseq + 1, wire_id, (uint16_t)params.size(),
                                                     (uint16_t)columns.size(), nullptr, warnings, server_status);
        } else {
            ok = proto.generate_STMT_PREPARE_RESPONSE(rseq + 1, wire_id, (uint16_t)params.size(),
                                                     (uint16_t)columns.size(),
                                                     fieldptrs.data(), warnings, server_status);
        }

        // cleanup fields
        for (size_t i = 0; i < columns.size(); i++) free(fields[i].name);

        size_t prepare_size = 0;
        for (unsigned i = 0; i < temp.len; ++i) prepare_size += temp.index(i)->size;
        if (!ok || prepare_size > state->limits.response_bytes) {
            // discard temp
            free_temp_packets(temp);
            ds->PSarrayOUT = original_ptr;
            ds->pkt_sid = output_swap.old_sid;
            output_swap.committed = true;
            state->core.close(core_id);
            send_err(session, rseq + 1, 1105, "HY000", "prepare response failed");
            finish_consume();
            return true;
        }

        // commit temp
        original_ptr->copy_add(&temp, 0, temp.len);
        temp.len = 0;
        output_swap.committed = true;
        ds->PSarrayOUT = original_ptr;

        // allocate state
        auto stmt = std::make_unique<StmtState>();
        stmt->wire_id = wire_id;
        stmt->core_id = core_id;
        stmt->sql = sql;
        stmt->params = params;
        stmt->columns = columns;
        stmt->mysql_columns = mysql_columns;
        stmt->metadata_bytes = meta;
        state->statements[wire_id] = std::move(stmt);
        state->sql_total_used += sql.size();
        state->metadata_total_used += meta;

        finish_consume();
        return true;
    }

    if (cmd == 0x19) { // CLOSE
        // parse wire id if available
        if (pkt.size == 9) {
            uint32_t wid = 0;
            memcpy(&wid, base + 5, 4);
            auto it = state->statements.find(wid);
            if (it != state->statements.end()) {
                state->core.close(it->second->core_id);
                state->longdata.reset(wid);
                state->sql_total_used -= it->second->sql.size();
                state->metadata_total_used -= it->second->metadata_bytes;
                state->longdata_total_used -= it->second->longdata_bytes;
                state->statements.erase(it);
            }
        }
        // ignored if unknown/malformed
        finish_consume();
        return true;
    }

    if (cmd == 0x1a) { // RESET
        if (pkt.size != 9) {
            send_err(session, rseq + 1, 1210, "HY000", "Malformed COM_STMT_RESET");
            finish_consume();
            return true;
        }
        uint32_t wid = 0;
        memcpy(&wid, base + 5, 4);
        auto it = state->statements.find(wid);
        if (it == state->statements.end()) {
            send_err(session, rseq + 1, 1243, "HY000", "Unknown prepared statement handler");
            finish_consume();
            return true;
        }
        // Refuse before native effects if even the largest OK cannot fit.
        if (max_ok_packet_size(session) > state->limits.response_bytes) {
            send_err(session, rseq + 1, 1105, "HY000", "response bytes limit exceeded");
            finish_consume();
            return true;
        }
        // reset core
        Status reset_status = state->core.reset(it->second->core_id);
        // clear longdata
        state->longdata.reset(wid);
        state->longdata_total_used -= it->second->longdata_bytes;
        it->second->longdata_bytes = 0;
        it->second->longdata_entries.clear();
        it->second->has_deferred_error = false;
        it->second->deferred_sqlstate = "HY000";
        // Client bindings remain cached even if native reset fails.
        if (reset_status) {
            send_err(session, rseq + 1, mysql_error_code(*reset_status),
                     reset_status->sqlstate, reset_status->message);
            finish_consume();
            return true;
        }
        // preserve effective_types
        MySQL_Data_Stream* ds = session.client_myds;
        uint8_t seq = rseq + 1;
        void* okptr = nullptr; unsigned int oksz = 0;
        ds->myprot.generate_pkt_OK64(false, &okptr, &oksz, seq, 0, 0,
                                  state->status_cb ? state->status_cb() : 0, 0, nullptr, false);
        if (okptr) ds->PSarrayOUT->add(okptr, oksz);
        finish_consume();
        return true;
    }

    if (cmd == 0x18) { // SEND_LONG_DATA
        // packet: header4 + cmd1 + stmt_id4 + param_id2 + data
        if (pkt.size < 11) {
            // malformed ignored
            finish_consume();
            return true;
        }
        uint32_t wid = 0;
        uint16_t param_id = 0;
        memcpy(&wid, base + 5, 4);
        memcpy(&param_id, base + 9, 2);
        auto it = state->statements.find(wid);
        if (it == state->statements.end()) {
            // unknown creates no state
            finish_consume();
            return true;
        }
        StmtState& st = *it->second;
        // validate param_id
        bool invalid_param = (param_id >= st.params.size());
        size_t chunk_size = pkt.size - 11;
        const void* chunk_data = base + 11;

        // limits check before add
        if (invalid_param) {
            if (!st.has_deferred_error) {
                st.has_deferred_error = true;
                st.deferred_code = 1210;
                st.deferred_message = "invalid parameter index for long data";
            }
            finish_consume();
            return true;
        }
        // longdata param type? accept; deferred invalid type checked at execute
        // per-statement bytes
        if (chunk_size > state->limits.longdata_per_statement - std::min(st.longdata_bytes, state->limits.longdata_per_statement)) {
            if (!st.has_deferred_error) {
                st.has_deferred_error = true;
                st.deferred_code = 1210;
                st.deferred_message = "long data per statement limit exceeded";
            }
            finish_consume();
            return true;
        }
        if (chunk_size > state->limits.longdata_total - std::min(state->longdata_total_used, state->limits.longdata_total)) {
            if (!st.has_deferred_error) {
                st.has_deferred_error = true;
                st.deferred_code = 1105;
                st.deferred_message = "long data total limit exceeded";
            }
            finish_consume();
            return true;
        }
        // entry count cap
        bool new_entry = (st.longdata_entries.find(param_id) == st.longdata_entries.end());
        if (new_entry && st.longdata_entries.size() >= state->limits.longdata_parameters) {
            if (!st.has_deferred_error) {
                st.has_deferred_error = true;
                st.deferred_code = 1210;
                st.deferred_message = "long data parameter count exceeded";
            }
            finish_consume();
            return true;
        }
        // empty chunks count as present
        char empty = 0;
        const void* data_ptr = chunk_size > 0 ? chunk_data : &empty;
        if (chunk_size > std::numeric_limits<unsigned long>::max() ||
            !state->longdata.add_checked(wid, param_id, data_ptr, static_cast<unsigned long>(chunk_size))) {
            st.has_deferred_error = true;
            st.deferred_code = 1105;
            st.deferred_message = "long data allocation failed";
            finish_consume();
            return true;
        }
        unsigned long* stored_size = nullptr; my_bool* stored_null = nullptr;
        void* stored = state->longdata.get(wid, param_id, &stored_size, &stored_null);
        if (!stored_size || (chunk_size && !stored)) {
            st.has_deferred_error = true;
            st.deferred_code = 1105;
            st.deferred_message = "long data allocation failed";
            finish_consume();
            return true;
        }
        if (new_entry) st.longdata_entries.insert(param_id);
        st.longdata_bytes += chunk_size;
        state->longdata_total_used += chunk_size;
        finish_consume();
        return true;
    }

    if (cmd == 0x17) { // EXECUTE
        if (pkt.size < 14) {
            // A short fixed header can still identify the statement. An
            // attempted execute consumes its pending long data on error too.
            if (pkt.size >= 9) {
                uint32_t id = static_cast<uint32_t>(read_uint_le(base + 5, 4));
                auto it = state->statements.find(id);
                if (it != state->statements.end()) {
                    auto& stmt = *it->second;
                    state->longdata.reset(id);
                    state->longdata_total_used -= stmt.longdata_bytes;
                    stmt.longdata_bytes = 0;
                    stmt.longdata_entries.clear();
                    stmt.has_deferred_error = false;
                    stmt.deferred_sqlstate = "HY000";
                }
            }
            send_err(session, rseq + 1, 1210, "HY000", "Malformed COM_STMT_EXECUTE");
            finish_consume();
            return true;
        }
        uint32_t wid = 0;
        memcpy(&wid, base + 5, 4);
        auto it = state->statements.find(wid);
        if (it == state->statements.end()) {
            send_err(session, rseq + 1, 1243, "HY000", "Unknown prepared statement handler");
            finish_consume();
            return true;
        }
        StmtState& st = *it->second;
        struct ExecuteCleanup {
            SharedState& state; StmtState& stmt; uint32_t id;
            ~ExecuteCleanup() {
                state.longdata.reset(id);
                state.longdata_total_used -= stmt.longdata_bytes;
                stmt.longdata_bytes = 0;
                stmt.longdata_entries.clear();
                stmt.has_deferred_error = false;
                stmt.deferred_sqlstate = "HY000";
            }
        } cleanup{*state, st, wid};
        uint32_t iteration = static_cast<uint32_t>(read_uint_le(base + 10, 4));
        if (base[9] != 0 || iteration != 1) {
            send_err(session, rseq + 1, base[9] ? 1235 : 1210, "HY000", "unsupported cursor or malformed iteration count");
            finish_consume();
            return true;
        }

        // deferred error check
        if (st.has_deferred_error) {
            std::string msg = st.deferred_message;
            uint16_t code = st.deferred_code;
            // clear
            state->longdata.reset(wid);
            state->longdata_total_used -= st.longdata_bytes;
            st.longdata_bytes = 0;
            st.longdata_entries.clear();
            st.has_deferred_error = false;
            send_err(session, rseq + 1, code, st.deferred_sqlstate, msg);
            finish_consume();
            return true;
        }

        // determine flag
        uint16_t num_params = (uint16_t)st.params.size();
        size_t flag_offset = 14 + (static_cast<size_t>(num_params) + 7) / 8;
        bool new_flag = false;
        if (num_params > 0) {
            if (pkt.size <= flag_offset) {
                send_err(session, rseq + 1, 1210, "HY000", "Malformed COM_STMT_EXECUTE");
                finish_consume();
                return true;
            }
            if (base[flag_offset] > 1) {
                send_err(session, rseq + 1, 1210, "HY000", "invalid parameter type flag");
                finish_consume();
                return true;
            }
            new_flag = (base[flag_offset] != 0);
        }

        const unsigned char* eff = nullptr;
        if (num_params > 0 && !new_flag) {
            if (st.effective_types.empty()) {
                send_err(session, rseq + 1, 1210, "HY000", "Missing COM_STMT_EXECUTE parameter types");
                finish_consume();
                return true;
            }
            eff = st.effective_types.data();
        }

        // decode
        stmt_execute_metadata_t* meta = nullptr;
        stmt_execute_metadata_t* meta_ptr = nullptr;
        meta = MySQL_Protocol::decode_stmt_execute(pkt, num_params, &state->longdata,
                                                  &meta_ptr, eff);
        // meta_ptr may be set by decode? decode uses *stmt_meta. We passed &meta_ptr (null). It may allocate and set meta_ptr.
        if (!meta) meta = meta_ptr;
        // If decode succeeded, meta_ptr == meta. Ensure.
        if (!meta) {
            send_err(session, rseq + 1, 1210, "HY000", "Malformed COM_STMT_EXECUTE");
            finish_consume();
            return true;
        }
        // detach pkt
        meta->pkt = nullptr;

        // update effective types if new_flag
        if (num_params > 0 && new_flag) {
            st.effective_types.assign(2 * num_params, 0);
            // Preserve the wire types after successful shared decoding.
            // Re-parse types from packet at known offset.
            size_t null_bitmap_length = (num_params + 7) / 8;
            size_t poff = 14 + null_bitmap_length + 1;
            for (uint16_t i = 0; i < num_params; i++) {
                // type bytes are in packet at poff (only if new_flag)
                if (poff + 2 <= pkt.size) {
                    st.effective_types[2*i] = static_cast<unsigned char*>(pkt.ptr)[poff];
                    st.effective_types[2*i+1] = static_cast<unsigned char*>(pkt.ptr)[poff+1];
                    poff += 2;
                }
            }
        }

        // validate fixed header: flag==0? decode already validates new flag? We inspected.
        // iteration count at offset 9 must be 1
        {
            uint32_t iter = 0;
            memcpy(&iter, base + 10, 4);
            // Actually offset: 5 stmt_id(4), 9 flags(1), 10 iteration count(4)
            memcpy(&iter, base + 10, 4);
            if (iter != 1) {
                // free meta temporal buffers
                for (uint16_t i = 0; i < num_params; i++) {
                    enum_field_types t = meta->binds[i].buffer_type;
                    if (t == MYSQL_TYPE_TIME || t == MYSQL_TYPE_DATE || t == MYSQL_TYPE_TIMESTAMP || t == MYSQL_TYPE_DATETIME) {
                        if (meta->binds[i].buffer) free(meta->binds[i].buffer);
                        meta->binds[i].buffer = nullptr;
                    }
                }
                delete meta;
                send_err(session, rseq + 1, 1210, "HY000", "Malformed COM_STMT_EXECUTE");
                finish_consume();
                return true;
            }
        }
        // flags byte at offset 9 must be 0
        if (base[9] != 0) {
            for (uint16_t i = 0; i < num_params; i++) {
                enum_field_types t = meta->binds[i].buffer_type;
                if (t == MYSQL_TYPE_TIME || t == MYSQL_TYPE_DATE || t == MYSQL_TYPE_TIMESTAMP || t == MYSQL_TYPE_DATETIME) {
                    if (meta->binds[i].buffer) free(meta->binds[i].buffer);
                    meta->binds[i].buffer = nullptr;
                }
            }
            delete meta;
            send_err(session, rseq + 1, 1210, "HY000", "Malformed COM_STMT_EXECUTE");
            finish_consume();
            return true;
        }

        // Convert values
        std::vector<Value> values;
        values.reserve(num_params);
        bool conversion_ok = true;
        std::string conv_msg;
        uint16_t conv_code = 1235;
        for (uint16_t i = 0; i < num_params; i++) {
            MYSQL_BIND& b = meta->binds[i];
            if (*b.is_null) {
                values.emplace_back(std::monostate{});
                // free temporal buffer if any
                if (b.buffer_type == MYSQL_TYPE_TIME || b.buffer_type == MYSQL_TYPE_DATE ||
                    b.buffer_type == MYSQL_TYPE_TIMESTAMP || b.buffer_type == MYSQL_TYPE_DATETIME) {
                    if (b.buffer) free(b.buffer);
                    b.buffer = nullptr;
                }
                continue;
            }
            enum_field_types t = b.buffer_type;
            // temporal unsupported
            if (t == MYSQL_TYPE_TIME || t == MYSQL_TYPE_DATE || t == MYSQL_TYPE_TIMESTAMP || t == MYSQL_TYPE_DATETIME) {
                if (b.buffer) free(b.buffer);
                b.buffer = nullptr;
                conversion_ok = false;
                conv_msg = "temporal binding unsupported";
                break;
            }
            switch (t) {
                case MYSQL_TYPE_TINY: {
                    uint64_t raw = read_uint_le(static_cast<unsigned char*>(b.buffer), 1);
                    if (b.is_unsigned) values.emplace_back(raw);
                    else values.emplace_back(static_cast<int64_t>(static_cast<int8_t>(raw)));
                    break;
                }
                case MYSQL_TYPE_SHORT:
                case MYSQL_TYPE_YEAR: {
                    uint64_t raw = read_uint_le(static_cast<unsigned char*>(b.buffer), 2);
                    if (b.is_unsigned) values.emplace_back(raw);
                    else values.emplace_back(static_cast<int64_t>(static_cast<int16_t>(raw)));
                    break;
                }
                case MYSQL_TYPE_LONG:
                case MYSQL_TYPE_INT24: {
                    uint64_t raw = read_uint_le(static_cast<unsigned char*>(b.buffer), 4);
                    if (b.is_unsigned) values.emplace_back(raw);
                    else values.emplace_back(static_cast<int64_t>(static_cast<int32_t>(raw)));
                    break;
                }
                case MYSQL_TYPE_LONGLONG: {
                    uint64_t raw = read_uint_le(static_cast<unsigned char*>(b.buffer), 8);
                    if (b.is_unsigned) values.emplace_back(raw);
                    else values.emplace_back(static_cast<int64_t>(raw));
                    break;
                }
                case MYSQL_TYPE_FLOAT: {
                    uint32_t raw = (uint32_t)read_uint_le(static_cast<unsigned char*>(b.buffer), 4);
                    float f; memcpy(&f, &raw, 4);
                    values.emplace_back(static_cast<double>(f));
                    break;
                }
                case MYSQL_TYPE_DOUBLE: {
                    uint64_t raw = read_uint_le(static_cast<unsigned char*>(b.buffer), 8);
                    double d; memcpy(&d, &raw, 8);
                    values.emplace_back(d);
                    break;
                }
                case MYSQL_TYPE_STRING:
                case MYSQL_TYPE_VARCHAR:
                case MYSQL_TYPE_VAR_STRING:
                case MYSQL_TYPE_JSON: {
                    unsigned long len = *b.length;
                    Text txt; txt.bytes.assign(reinterpret_cast<const char*>(b.buffer), len);
                    values.emplace_back(txt);
                    break;
                }
                case MYSQL_TYPE_TINY_BLOB:
                case MYSQL_TYPE_MEDIUM_BLOB:
                case MYSQL_TYPE_LONG_BLOB:
                case MYSQL_TYPE_BLOB: {
                    unsigned long len = *b.length;
                    Bytes bytes; bytes.bytes.assign(static_cast<unsigned char*>(b.buffer),
                                                   static_cast<unsigned char*>(b.buffer) + len);
                    values.emplace_back(bytes);
                    break;
                }
                case MYSQL_TYPE_DECIMAL:
                case MYSQL_TYPE_NEWDECIMAL: {
                    unsigned long len = *b.length;
                    Decimal dec; dec.exact.assign(reinterpret_cast<const char*>(b.buffer), len);
                    values.emplace_back(dec);
                    break;
                }
                default:
                    conversion_ok = false;
                    conv_msg = "unsupported parameter type";
                    conv_code = 1235;
                    break;
            }
            if (!conversion_ok) break;
        }

        // free temporal buffers (none for supported) already handled
        // free meta temporal buffers just in case
        for (uint16_t i = 0; i < num_params; i++) {
            enum_field_types t = meta->binds[i].buffer_type;
            if (t == MYSQL_TYPE_TIME || t == MYSQL_TYPE_DATE || t == MYSQL_TYPE_TIMESTAMP || t == MYSQL_TYPE_DATETIME) {
                if (meta->binds[i].buffer) free(meta->binds[i].buffer);
                meta->binds[i].buffer = nullptr;
            }
        }

        if (!conversion_ok) {
            delete meta;
            send_err(session, rseq + 1, conv_code, "HY000", conv_msg);
            finish_consume();
            return true;
        }

        bool result_deprecate = session.client_myds->myconn &&
            (session.client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF);
        size_t response_remaining = state->limits.response_bytes;
        bool budget_ok = st.columns.empty()
            ? charge(response_remaining, max_ok_packet_size(session))
            : metadata_fits(st.columns, 0, false, result_deprecate, response_remaining, &response_remaining) &&
              charge(response_remaining, result_deprecate ? max_ok_packet_size(session) : 9);
        if (!budget_ok) {
            delete meta;
            send_err(session, rseq + 1, 1105, "HY000", "response bytes limit exceeded");
            finish_consume();
            return true;
        }

        // execute core
        ExecInfo info;
        if (auto err = state->core.execute(st.core_id, values, info)) {
            delete meta;
            // clear longdata
            state->longdata.reset(wid);
            state->longdata_total_used -= st.longdata_bytes;
            st.longdata_bytes = 0;
            st.longdata_entries.clear();
            st.has_deferred_error = false;
            send_err(session, rseq + 1, mysql_error_code(*err),
                     err->sqlstate, err->message);
            finish_consume();
            return true;
        }

        // success: handle result
        MySQL_Data_Stream* ds = session.client_myds;
        MySQL_Protocol& proto = ds->myprot;
        uint8_t seq = rseq + 1;

        // clear longdata after execute
        auto clear_longdata = [&]() {
            state->longdata.reset(wid);
            state->longdata_total_used -= st.longdata_bytes;
            st.longdata_bytes = 0;
            st.longdata_entries.clear();
            st.has_deferred_error = false;
        };

        if (!info.has_result) {
            // DML no result: OK
            void* okptr = nullptr; unsigned int oksz = 0;
            ds->myprot.generate_pkt_OK64(false, &okptr, &oksz, seq, info.affected_rows, info.last_insert_id,
                                       state->status_cb ? state->status_cb() : 0, 0, nullptr, false);
            if (okptr) ds->PSarrayOUT->add(okptr, oksz);
            clear_longdata();
            delete meta;
            finish_consume();
            return true;
        }

        // result set path with private buffering
        PtrSizeArray* original_ptr = ds->PSarrayOUT;
        PtrSizeArray temp(0);
        OutputSwap output_swap(*ds, temp);

        bool ok = true;
        std::string fail_msg = "execute failed";
        // column count
        {
            void* p = nullptr; unsigned int sz = 0;
            proto.generate_pkt_column_count(false, &p, &sz, seq, st.columns.size(), nullptr);
            if (p) temp.add(p, sz);
        }
        seq++;
        // fields
        std::vector<MYSQL_FIELD> fields(st.columns.size());
        const char* empty = "";
        std::vector<std::string> names;
        for (const auto& c : st.columns) names.push_back(c.name);
        for (size_t i = 0; i < st.columns.size(); i++) {
            memset(&fields[i], 0, sizeof(MYSQL_FIELD));
            fields[i].db = (char*)empty;
            fields[i].table = (char*)empty;
            fields[i].org_table = (char*)empty;
            fields[i].name = strdup(names[i].c_str());
            fields[i].org_name = (char*)empty;
            fields[i].name_length = (unsigned long)names[i].size();
            fields[i].charsetnr = st.mysql_columns[i].charset;
            fields[i].length = st.mysql_columns[i].length;
            fields[i].type = (enum_field_types)st.mysql_columns[i].wire_type;
            fields[i].flags = st.mysql_columns[i].flags;
            fields[i].decimals = st.mysql_columns[i].decimals;
            fields[i].catalog = (char*)"def";
            fields[i].catalog_length = 3;
            void* p = nullptr; unsigned int sz = 0;
            proto.generate_pkt_field(false, &p, &sz, seq,
                fields[i].db, fields[i].table, fields[i].org_table,
                fields[i].name, fields[i].org_name,
                fields[i].charsetnr, fields[i].length, fields[i].type,
                fields[i].flags, fields[i].decimals, false, 0, nullptr, nullptr);
            if (p) temp.add(p, sz);
            seq++;
        }
        for (size_t i = 0; i < st.columns.size(); i++) free(fields[i].name);

        // first EOF if not deprecate
        bool deprecate = (session.client_myds->myconn &&
                          (session.client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF));
        if (!deprecate) {
            void* p = nullptr; unsigned int sz = 0;
            proto.generate_pkt_EOF(false, &p, &sz, seq, 0, 0, nullptr);
            if (p) temp.add(p, sz);
            seq++;
        }

        // fetch rows
        bool done = false;
        while (true) {
            Row row;
            bool row_done = false;
            if (auto err = state->core.fetch(st.core_id, row, row_done)) {
                ok = false;
                fail_msg = err->message;
                break;
            }
            if (row_done) {
                done = true;
                break;
            }
            // encode row
            std::vector<unsigned char> payload;
            if (auto stt = mysql_encode_binary_row(st.mysql_columns, row, payload, response_remaining)) {
                ok = false;
                fail_msg = stt->message;
                break;
            }
            size_t framing = row_frame_bytes(payload.size());
            if (!charge(response_remaining, framing) || !charge(response_remaining, payload.size())) {
                ok = false;
                fail_msg = "response bytes limit exceeded";
                break;
            }
            add_fragmented_row(temp, seq, payload);
        }

        if (!ok) {
            free_temp_packets(temp);
            temp.len = 0;
            ds->PSarrayOUT = original_ptr;
            ds->pkt_sid = output_swap.old_sid;
            output_swap.committed = true;
            // reset core
            state->core.reset(st.core_id);
            clear_longdata();
            delete meta;
            send_err(session, rseq + 1, 1105, "HY000", fail_msg);
            finish_consume();
            return true;
        }

        // final EOF/OK
        if (deprecate) {
            void* p = nullptr; unsigned int sz = 0;
            proto.generate_pkt_OK64(false, &p, &sz, seq, 0, 0, state->status_cb ? state->status_cb() : 0, 0, nullptr, true);
            if (p) temp.add(p, sz);
            seq++;
        } else {
            void* p = nullptr; unsigned int sz = 0;
            proto.generate_pkt_EOF(false, &p, &sz, seq, 0, state->status_cb ? state->status_cb() : 0, nullptr);
            if (p) temp.add(p, sz);
            seq++;
        }

        // check total response size
        size_t total = 0;
        for (unsigned i = 0; i < temp.len; i++) total += temp.index(i)->size;
        if (total > state->limits.response_bytes) {
            free_temp_packets(temp);
            temp.len = 0;
            ds->PSarrayOUT = original_ptr;
            ds->pkt_sid = output_swap.old_sid;
            output_swap.committed = true;
            state->core.reset(st.core_id);
            clear_longdata();
            delete meta;
            send_err(session, rseq + 1, 1105, "HY000", "response bytes limit exceeded");
            finish_consume();
            return true;
        }

        // commit
        original_ptr->copy_add(&temp, 0, temp.len);
        temp.len = 0;
        output_swap.committed = true;
        ds->PSarrayOUT = original_ptr;

        clear_longdata();
        delete meta;
        finish_consume();
        return true;
    }

    if (cmd == 0x1c) { // FETCH cursor unsupported
        send_err(session, rseq + 1, 1235, "HY000", "cursor fetch unsupported");
        finish_consume();
        return true;
    }

    // unrecognized command: not consumed
    return false;
}

}  // namespace embedded
