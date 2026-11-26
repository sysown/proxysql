#include <new>
#include "Embedded_Admin_PgSQL_Prepared.h"
#include "Embedded_Admin_SQLite_Policy.h"
#include "Embedded_SQLite_Adapter.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Session.h"
#include "PgSQL_Variables.h"
#include "ProxySQL_StartupGate.h"
#include "proxysql.h"
#include "proxysql_admin.h"
#include "proxysql_admin_global_sql_lock.h"
#include "sqlite3db.h"
#include <cstdio>
#include <exception>
#include <memory>
#include <mutex>
#include <strings.h>
#include <unordered_map>

extern ProxySQL_Admin *GloAdmin;

namespace embedded {
namespace {
Status failure(ErrorKind kind, const char *message) {
    return Error{kind, 0, message, "HY000"};
}
bool utf8_client(PgSQL_Session &session) {
    const char *encoding = pgsql_variables.client_get_value(&session, PGSQL_CLIENT_ENCODING);
    return !encoding || !*encoding || strcasecmp(encoding, "UTF8") == 0 ||
           strcasecmp(encoding, "UTF-8") == 0;
}
PGSQL_ERROR_CODES error_code(ErrorKind kind) {
    switch (kind) {
    case ErrorKind::syntax:
        return PGSQL_ERROR_CODES::ERRCODE_SYNTAX_ERROR;
    case ErrorKind::unsupported:
        return PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED;
    case ErrorKind::policy:
        return PGSQL_ERROR_CODES::ERRCODE_INSUFFICIENT_PRIVILEGE;
    case ErrorKind::invalid_parameter:
        return PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE;
    case ErrorKind::range:
        return PGSQL_ERROR_CODES::ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE;
    case ErrorKind::resource:
        return PGSQL_ERROR_CODES::ERRCODE_OUT_OF_MEMORY;
    case ErrorKind::transaction:
        return PGSQL_ERROR_CODES::ERRCODE_INVALID_TRANSACTION_STATE;
    default:
        return PGSQL_ERROR_CODES::ERRCODE_INTERNAL_ERROR;
    }
}
bool consume_error(PgSQL_Session &session, PtrSize_t &packet, const Error &error,
                   bool &discard_until_sync) {
    session.client_myds->setDSS_STATE_QUERY_SENT_NET();
    session.client_myds->myprot.generate_error_packet(true, false, error.message.c_str(),
                                                      error_code(error.kind), false, true);
    session.client_myds->DSS = STATE_SLEEP;
    session.status = WAITING_CLIENT_DATA;
    discard_until_sync = true;
    l_free(packet.size, packet.ptr);
    packet = {};
    return true;
}
struct Provider;
struct Guard final : OperationGuard {
    Provider &provider;
    bool locked = false;
    std::unique_ptr<OperationGuard> lease;
    explicit Guard(Provider &p) : provider(p) {}
    ~Guard() override;
    Status finish() override { return lease ? lease->finish() : Status{}; }
};
struct Provider {
    ProxySQL_Admin *admin;
    PgSQL_Session &session;
    bool is_admin;
    sqlite3 *db;
    AdminSQLitePolicy policy;
    SQLiteAdapter adapter;
    Provider(ProxySQL_Admin *a, PgSQL_Session &s, bool role, sqlite3 *d)
        : admin(a), session(s), is_admin(role), db(d), policy(*a, d, role),
          adapter(d, ResultProfile::strict_declared, &policy.command()) {}
    Status guard(const OperationContext &context, std::unique_ptr<OperationGuard> &out) {
        std::unique_ptr<Guard> g(new Guard(*this));
        bool cleanup = context.operation == Operation::reset ||
                       context.operation == Operation::close ||
                       context.operation == Operation::disconnect;
        if (!cleanup) {
            if (!utf8_client(session))
                return failure(ErrorKind::unsupported,
                               "Prepared queries require UTF8 client encoding");
        }
#ifdef PROXYSQL40
        if (!cleanup) {
            bool ready = proxysql_startup_gate_lock_for_admin(
                [this] { proxysql_admin_global_sql_lock(admin->sql_query_global_mutex); },
                [this] { proxysql_admin_global_sql_unlock(admin->sql_query_global_mutex); },
                [] { return glovars.shutdown != 0; });
            g->locked = true;
            if (!ready)
                return failure(ErrorKind::internal, "Admin is shutting down");
        } else
#endif
        {
            proxysql_admin_global_sql_lock(admin->sql_query_global_mutex);
            g->locked = true;
        }
        if ((context.operation == Operation::prepare || context.operation == Operation::execute) &&
            (!proxy_sqlite3_get_autocommit || !proxy_sqlite3_get_autocommit(db)))
            return Error{ErrorKind::transaction, 0, "Admin connection is in a transaction", "25000"};
        if (context.operation == Operation::prepare || context.operation == Operation::execute ||
            context.operation == Operation::fetch) {
            if (auto error = policy.guard(g->lease))
                return error;
        }
        out = std::move(g);
        return {};
    }
};
Guard::~Guard() {
    lease.reset();
    if (locked)
        proxysql_admin_global_sql_unlock(provider.admin->sql_query_global_mutex);
}
std::mutex &providers_mutex() {
    // Static storage, never destroyed: unregistration can run during static teardown.
    alignas(std::mutex) static unsigned char storage[sizeof(std::mutex)];
    static std::mutex *mutex = new (storage) std::mutex;
    return *mutex;
}
using Providers = std::unordered_map<PgSQL_Session *, std::shared_ptr<Provider>>;
Providers &providers() {
    static auto *map = new Providers;
    return *map;
}
} // namespace
void unregister_admin_pgsql_prepared(PgSQL_Session &session) noexcept {
    // Only Admin/STATS sessions own a provider; skip the registry lock for ordinary sessions.
    if (session.session_type != PROXYSQL_SESSION_ADMIN &&
        session.session_type != PROXYSQL_SESSION_STATS)
        return;
    std::shared_ptr<Provider> owned;
    {
        std::lock_guard<std::mutex> lock(providers_mutex());
        auto it = providers().find(&session);
        if (it == providers().end())
            return;
        owned = it->second;
    }
    // The controller closes all native statements while the provider still lives.
    unregister_pgsql_prepared(session);
    std::lock_guard<std::mutex> lock(providers_mutex());
    providers().erase(&session);
}
bool handle_admin_pgsql_prepared(PgSQL_Session &session, PtrSize_t &packet,
                                 bool &discard_until_sync, bool &registered) {
    if (session.session_type != PROXYSQL_SESSION_ADMIN &&
        session.session_type != PROXYSQL_SESSION_STATS)
        return false;
    if (!packet.ptr || packet.size < 1)
        return false;
    const auto cmd = static_cast<unsigned char *>(packet.ptr)[0];
    std::shared_ptr<Provider> owned;
    {
        std::lock_guard<std::mutex> lock(providers_mutex());
        auto it = providers().find(&session);
        if (it != providers().end())
            owned = it->second;
    }
    const bool is_admin = session.session_type == PROXYSQL_SESSION_ADMIN;
    if (owned && owned->is_admin != is_admin) {
        unregister_admin_pgsql_prepared(session);
        owned.reset();
        registered = false;
    }
    if (cmd == 'Q')
        return owned && handle_pgsql_prepared(session, packet);
    if (cmd != 'P' && cmd != 'B' && cmd != 'D' && cmd != 'E' && cmd != 'C' && cmd != 'H' &&
        cmd != 'S')
        return false;
    if (!owned && (cmd == 'H' || cmd == 'S'))
        return false;
    if (!owned) {
        if (!utf8_client(session))
            return consume_error(
                session, packet,
                *failure(ErrorKind::unsupported, "Prepared queries require UTF8 client encoding"),
                discard_until_sync);
        try {
            ProxySQL_Admin *admin = GloAdmin;
            SQLite3DB *wrapper = admin ? (is_admin ? admin->admindb : admin->statsdb) : nullptr;
            sqlite3 *db = wrapper ? wrapper->get_db() : nullptr;
            if (!db || !proxy_sqlite3_exec)
                return consume_error(session, packet,
                                     *failure(ErrorKind::internal, "Admin database unavailable"),
                                     discard_until_sync);
            owned = std::make_shared<Provider>(admin, session, is_admin, db);
            Provider *provider = owned.get();
            auto error = register_pgsql_prepared(
                session, provider->adapter, provider->policy, {},
                [provider](const OperationContext &c, std::unique_ptr<OperationGuard> &g) {
                    return provider->guard(c, g);
                });
            if (error)
                return consume_error(session, packet, *error, discard_until_sync);
            try {
                std::lock_guard<std::mutex> lock(providers_mutex());
                providers().emplace(&session, owned);
                registered = true;
            } catch (...) {
                unregister_pgsql_prepared(session);
                throw;
            }
        } catch (const std::bad_alloc &) {
            return consume_error(session, packet,
                                 *failure(ErrorKind::resource, "Admin prepared allocation failed"),
                                 discard_until_sync);
        } catch (...) {
            return consume_error(session, packet,
                                 *failure(ErrorKind::internal, "Admin prepared setup failed"),
                                 discard_until_sync);
        }
    }
    return handle_pgsql_prepared(session, packet);
}
} // namespace embedded
