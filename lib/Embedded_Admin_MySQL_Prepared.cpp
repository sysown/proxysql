#include "Embedded_Admin_MySQL_Prepared.h"
#include "Embedded_Admin_SQLite_Policy.h"
#include "Embedded_SQLite_Adapter.h"
#include "ProxySQL_StartupGate.h"
#include "proxysql_admin.h"
#include "proxysql_admin_global_sql_lock.h"
#include "sqlite3db.h"
#include <cstdio>
#include <new>
#include <exception>
#include <memory>
#include <mutex>
#include <unordered_map>

extern ProxySQL_Admin* GloAdmin;

namespace embedded {
namespace {
Status failure(ErrorKind kind, const char* message) { return Error{kind, 0, message, "HY000"}; }
bool consume_error(MySQL_Session& session, PtrSize_t& packet, Status error) {
 consume_mysql_prepared_error(session, packet, *error);
 return true;
}
struct Provider;
struct Guard final : OperationGuard {
 Provider& provider;
 bool locked = false;
 std::unique_ptr<OperationGuard> lease;
 explicit Guard(Provider& p) : provider(p) {}
 ~Guard() override;
};
struct Provider {
 ProxySQL_Admin* admin;
 bool is_admin;
 sqlite3* db;
 SQLiteAdapter adapter;
 bool query_only = false;
 bool needs_vacuum = false;
 AdminSQLitePolicy policy;
 Provider(ProxySQL_Admin* a, bool role, sqlite3* d)
  : admin(a), is_admin(role), db(d), adapter(d),
    policy(d, [this] { return !is_admin || admin->get_read_only(); },
      [] { return proxysql_admin_global_sql_lock_depth() > 0; },
      {"mysql_servers", "mysql_users", "mysql_query_rules"},
      [this](const std::string& refresh) -> Status {
       // This is a canonical request derived only from admitted relation ASTs.
       // Passing original SQL would mistake literals for destructive reset views.
       if (!refresh.empty()) needs_vacuum = admin->GenericRefreshStatistics(refresh.data(), static_cast<unsigned int>(refresh.size()), is_admin);
       if (!is_admin || admin->get_read_only()) {
        query_only = true; // Restore even if SQLite reports a failed state change.
        if (proxy_sqlite3_exec(db, "PRAGMA query_only=ON", nullptr, nullptr, nullptr) != SQLITE_OK)
         return failure(ErrorKind::engine, "Cannot enable Admin query-only mode");
       }
       return {};
      }) {}
 Status guard(const OperationContext& context, std::unique_ptr<OperationGuard>& out) {
  std::unique_ptr<Guard> g(new Guard(*this));
  bool cleanup = context.operation == Operation::reset || context.operation == Operation::close || context.operation == Operation::disconnect;
#ifdef PROXYSQL40
  if (!cleanup) {
   bool ready = proxysql_startup_gate_lock_for_admin(
    [this] { proxysql_admin_global_sql_lock(admin->sql_query_global_mutex); },
    [this] { proxysql_admin_global_sql_unlock(admin->sql_query_global_mutex); },
    [] { return glovars.shutdown != 0; });
   g->locked = true;
   if (!ready) return failure(ErrorKind::internal, "Admin is shutting down");
  } else
#endif
  { proxysql_admin_global_sql_lock(admin->sql_query_global_mutex); g->locked = true; }
  if ((context.operation == Operation::prepare || context.operation == Operation::execute) &&
      (!proxy_sqlite3_get_autocommit || !proxy_sqlite3_get_autocommit(db)))
   return failure(ErrorKind::transaction, "Admin connection is in a transaction");
  if (context.operation == Operation::prepare || context.operation == Operation::execute || context.operation == Operation::fetch) {
   if (auto error = policy.guard(g->lease)) return error;
  }
  out = std::move(g);
  return {};
 }
};
Guard::~Guard() {
 lease.reset();
 if (provider.query_only) {
  if (!proxy_sqlite3_exec || proxy_sqlite3_exec(provider.db, "PRAGMA query_only=OFF", nullptr, nullptr, nullptr) != SQLITE_OK) {
   std::fprintf(stderr, "Admin prepared: cannot restore query-only state\n");
   std::terminate();
  }
  provider.query_only = false;
 }
 if (provider.needs_vacuum) {
  provider.needs_vacuum = false;
  try { provider.admin->vacuum_stats(provider.is_admin); } catch (...) { std::terminate(); }
 }
 if (locked) proxysql_admin_global_sql_unlock(provider.admin->sql_query_global_mutex);
}
std::mutex& providers_mutex() {
 // Static storage, never destroyed: unregistration can run during static teardown.
 alignas(std::mutex) static unsigned char storage[sizeof(std::mutex)];
 static std::mutex* mutex = new (storage) std::mutex;
 return *mutex;
}
using Providers = std::unordered_map<MySQL_Session*, std::shared_ptr<Provider>>;
Providers& providers() { static auto* map = new Providers; return *map; }
}
void unregister_admin_mysql_prepared(MySQL_Session& session) noexcept {
 std::shared_ptr<Provider> owned;
 {
  std::lock_guard<std::mutex> lock(providers_mutex());
  auto it = providers().find(&session);
  if (it == providers().end()) return;
  owned = it->second;
 }
 // The controller closes all native statements while the provider still lives.
 unregister_mysql_prepared(session);
 std::lock_guard<std::mutex> lock(providers_mutex());
 providers().erase(&session);
}
bool handle_admin_mysql_prepared(MySQL_Session& session, PtrSize_t& packet) {
 if (session.session_type != PROXYSQL_SESSION_ADMIN && session.session_type != PROXYSQL_SESSION_STATS) return false;
 if (!packet.ptr || packet.size < 5) return false;
 const auto cmd = static_cast<unsigned char*>(packet.ptr)[4];
 if (cmd != 0x16 && cmd != 0x17 && cmd != 0x18 && cmd != 0x19 && cmd != 0x1a && cmd != 0x1c) return false;
 const bool is_admin = session.session_type == PROXYSQL_SESSION_ADMIN;
 Provider* provider = nullptr;
 {
  std::lock_guard<std::mutex> lock(providers_mutex());
  auto it = providers().find(&session);
  if (it != providers().end()) provider = it->second.get();
 }
 if (provider && provider->is_admin != is_admin) { unregister_admin_mysql_prepared(session); provider = nullptr; }
 if (!provider) {
  try {
   ProxySQL_Admin* admin = GloAdmin;
   SQLite3DB* wrapper = admin ? (is_admin ? admin->admindb : admin->statsdb) : nullptr;
   sqlite3* db = wrapper ? wrapper->get_db() : nullptr;
   if (!db || !proxy_sqlite3_exec) return consume_error(session, packet, failure(ErrorKind::internal, "Admin database unavailable"));
   auto owned = std::make_shared<Provider>(admin, is_admin, db);
   provider = owned.get();
   auto error = register_mysql_prepared(session, provider->adapter, provider->policy,
    [] { return static_cast<uint16_t>(SERVER_STATUS_AUTOCOMMIT); }, {},
    [provider](const OperationContext& c, std::unique_ptr<OperationGuard>& g) { return provider->guard(c, g); });
   if (error) return consume_error(session, packet, error);
   try { std::lock_guard<std::mutex> lock(providers_mutex()); providers().emplace(&session, owned); }
   catch (...) { unregister_mysql_prepared(session); throw; }
  } catch (const std::bad_alloc&) { return consume_error(session, packet, failure(ErrorKind::resource, "Admin prepared allocation failed")); }
  catch (...) { return consume_error(session, packet, failure(ErrorKind::internal, "Admin prepared setup failed")); }
 }
 return handle_mysql_prepared(session, packet);
}
}
