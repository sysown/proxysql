#include "Embedded_Plugin_Service.h"
#include "Embedded_Plugin_Adapter.h"
#include "Embedded_MySQL_Prepared.h"
#include "Embedded_PgSQL_Frontend.h"
#include "PgSQL_Session.h"
#include <algorithm>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace {
using namespace embedded;
struct Record {
    std::shared_ptr<PluginProvider> provider;
    std::thread::id owner;
    decltype(ProxySQL_Embedded_RequestV1::mysql_select_database) select_database = nullptr;
    void* select_database_context = nullptr;
};
template<class S> struct Registry {
    std::mutex mutex;
    std::unordered_map<S*, Record> entries;
};
template<class S> Registry<S>& registry() {
    static auto* r = new Registry<S>;
    return *r;
}
thread_local char message[4097];
int report(const Error& e, ProxySQL_Embedded_Error* out) noexcept {
    if (out) {
        *out = {};
        switch (e.kind) {
#define MAP(k, v) case ErrorKind::k: out->kind = ProxySQL_Embedded_ERROR_##v; break
        MAP(syntax, SYNTAX);
        MAP(unsupported, UNSUPPORTED);
        MAP(policy, POLICY);
        MAP(invalid_parameter, INVALID_PARAMETER);
        MAP(range, RANGE);
        MAP(resource, RESOURCE);
        MAP(schema_changed, SCHEMA_CHANGED);
        MAP(transaction, TRANSACTION);
        MAP(engine, ENGINE);
        MAP(internal, INTERNAL);
#undef MAP
        }
        out->native_code = e.native_code;
        if (e.sqlstate.size() == 5 && std::all_of(e.sqlstate.begin(), e.sqlstate.end(),
            [](char c) { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); }))
            std::memcpy(out->sqlstate, e.sqlstate.data(), 5);
        size_t n = std::min(e.message.size(), sizeof(message) - 1);
        std::memcpy(message, e.message.data(), n);
        message[n] = 0;
        out->message = {reinterpret_cast<const uint8_t*>(message), n};
    }
    return 1;
}
Error failure(ErrorKind k, const char* text) {
    return {k, 0, text, ""};
}
int exception_failure(ProxySQL_Embedded_Error* out) noexcept {
    if (out) {
        static constexpr char text[] = "service operation failed";
        *out = {};
        out->kind = ProxySQL_Embedded_ERROR_RESOURCE;
        std::memcpy(message, text, sizeof(text));
        out->message = {reinterpret_cast<const uint8_t*>(message), sizeof(text) - 1};
    }
    return 1;
}
template<class S> int unregister_impl(S* s, ProxySQL_Embedded_Error* out, bool teardown) {
    std::shared_ptr<PluginProvider> provider;
    {
        auto& r = registry<S>();
        std::lock_guard<std::mutex> lock(r.mutex);
        auto it = r.entries.find(s);
        if (it == r.entries.end())
            return teardown ? 0 : report(failure(ErrorKind::invalid_parameter,
                                                   "session not registered"), out);
        if (it->second.owner != std::this_thread::get_id()) {
            if (teardown)
                std::terminate();
            return report(failure(ErrorKind::internal, "wrong session thread"), out);
        }
        provider = std::move(it->second.provider);
        r.entries.erase(it);
    }
    if constexpr (std::is_same_v<S, MySQL_Session>)
        unregister_mysql_prepared(*s);
    else
        unregister_pgsql_prepared(*s);
    return 0;
}
template<class S> int register_impl(void* opaque, const ProxySQL_Embedded_RequestV1* req,
                                     ProxySQL_Embedded_Error* out) {
    auto* s = static_cast<S*>(opaque);
    if (!s || s->session_type != PROXYSQL_SESSION_SQLITE)
        return report(failure(ErrorKind::invalid_parameter,
                              "session must be a plugin SQLite session"), out);
    auto& r = registry<S>();
    {
        std::lock_guard<std::mutex> lock(r.mutex);
        if (r.entries.count(s))
            return report(failure(ErrorKind::invalid_parameter, "session already registered"), out);
    }
    PluginProviderResult owned;
    auto status = make_plugin_provider(req, std::is_same_v<S, PgSQL_Session>, owned);
    if (status)
        return report(*status, out);
    std::shared_ptr<PluginProvider> p(std::move(owned));
    if constexpr (std::is_same_v<S, MySQL_Session>) {
        auto fn = p->mysql_status();
        auto ctx = p->status_context();
        status = register_mysql_prepared(*s, p->adapter(), p->policy(),
                                         [fn, ctx] { return fn(ctx); }, {}, p->guard_factory());
    } else {
        auto fn = p->pgsql_status();
        auto ctx = p->pgsql_status_context();
        status = register_pgsql_prepared(*s, p->adapter(), p->policy(), {}, p->guard_factory(),
                                         [fn, ctx] { return fn(ctx); });
    }
    if (status)
        return report(*status, out);
    try {
        std::lock_guard<std::mutex> lock(r.mutex);
        Record record{p, std::this_thread::get_id()};
        if constexpr (std::is_same_v<S, MySQL_Session>) {
            if (req->struct_size >= sizeof(*req)) {
                record.select_database = req->mysql_select_database;
                record.select_database_context = req->status_context;
            }
        }
        if (r.entries.emplace(s, std::move(record)).second)
            return 0;
    } catch (...) {
        // Roll back the private registration before releasing the provider.
    }
    if constexpr (std::is_same_v<S, MySQL_Session>)
        unregister_mysql_prepared(*s);
    else
        unregister_pgsql_prepared(*s);
    return report(failure(ErrorKind::resource, "unable to record registration"), out);
}
template<class S>
int reg(void* s, const ProxySQL_Embedded_RequestV1* r, ProxySQL_Embedded_Error* e) noexcept {
    try {
        return register_impl<S>(s, r, e);
    } catch (...) {
        return exception_failure(e);
    }
}
template<class S> int unreg(void* s, ProxySQL_Embedded_Error* e) noexcept {
    try {
        return unregister_impl(static_cast<S*>(s), e, false);
    } catch (...) {
        return exception_failure(e);
    }
}
const ProxySQL_Embedded_ServiceV1 service = {ProxySQL_Embedded_ABI_V1, sizeof(service),
    &reg<MySQL_Session>, &reg<PgSQL_Session>, &unreg<MySQL_Session>, &unreg<PgSQL_Session>};
}
const ProxySQL_Embedded_ServiceV1* proxysql_embedded_execution_service() noexcept {
    return &service;
}
namespace embedded {
uint16_t plugin_mysql_select_database(MySQL_Session& s, const char* database,
                                      size_t size) noexcept {
    if (s.session_type != PROXYSQL_SESSION_SQLITE)
        return 0;
    try {
        auto& r = registry<MySQL_Session>();
        decltype(Record::select_database) fn = nullptr;
        void* ctx = nullptr;
        {
            std::lock_guard<std::mutex> lock(r.mutex);
            auto it = r.entries.find(&s);
            if (it == r.entries.end() || !it->second.select_database)
                return 0;
            if (it->second.owner != std::this_thread::get_id())
                return 1105;
            fn = it->second.select_database;
            ctx = it->second.select_database_context;
        }
        return fn(ctx, {reinterpret_cast<const uint8_t*>(database), size});
    } catch (...) {
        return 1105;
    }
}
void teardown_plugin_mysql(MySQL_Session& s) noexcept {
    // An ordinary proxy session is never plugin-registered; do not lock the registry for it.
    if (s.session_type == PROXYSQL_SESSION_MYSQL) return;
    try {
        unregister_impl(&s, nullptr, true);
    } catch (...) {
        std::terminate();
    }
}
void teardown_plugin_pgsql(PgSQL_Session& s) noexcept {
    if (s.session_type == PROXYSQL_SESSION_PGSQL) return;
    try {
        unregister_impl(&s, nullptr, true);
    } catch (...) {
        std::terminate();
    }
}
}
