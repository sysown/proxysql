// Core-owned raw TCP backend service (plugin ABI 18).
//
// A raw stream is not a SQL session: this translation unit never fabricates a
// MySQL_Session/PgSQL_Session, never performs protocol I/O, and never touches a
// protocol socket.  It selects through the real protocol hostgroup manager and
// keeps a fresh accounting object in that server's actual ConnectionsUsed list
// for the lifetime of the plugin-owned OS socket.
#ifdef PROXYSQL40

#include "ProxySQL_PluginRawBackend.h"

#include "MySQL_HostGroups_Manager.h"
#include "PgSQL_HostGroups_Manager.h"
#include "MySQL_Thread.h"
#include "PgSQL_Thread.h"
#include "mysql_connection.h"
#include "PgSQL_Connection.h"
#include "MySQL_Monitor.hpp"
#include "PgSQL_Monitor.hpp"
#include "ConnectionPoolDecision.h"
#include "proxysql.h"
#include "proxysql_glovars.hpp"
#include "proxysql_structs.h"
#include "cpp.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

extern ProxySQL_GlobalVariables GloVars;
extern MySQL_Threads_Handler* GloMTH;
extern PgSQL_Threads_Handler* GloPTH;

struct ProxySQL_RawBackend {
	ProxySQL_RawBackendProtocol protocol;
	void* object { nullptr };   // MySQL_Connection* or PgSQL_Connection*
	void* parent { nullptr };   // MySrvC* or PgSQL_SrvC*
	uint32_t hostgroup { 0 };
	std::atomic<bool> outcome_reported { false };
	std::atomic<bool> connected { false };
	std::atomic<bool> destroyed { false };
	std::atomic<bool> hard_latched { false };
	std::atomic<bool> registered { false };

	ProxySQL_RawBackend(ProxySQL_RawBackendProtocol p, uint32_t hg)
		: protocol(p), hostgroup(hg) {}
};

namespace {

// Per-operation native selection policy.  A SQL MySQL_Thread/PgSQL_Thread
// leaves this at zero; RawPolicyGuard temporarily installs the live handler
// snapshot for a mapped acquisition and restores the caller's value.
thread_local int g_raw_latency_awareness_min_servers = 0;

// ---------------------------------------------------------------------------
// Bounded live-handle registry.
//
// The registry is intentionally process-lifetime (heap allocated once, never
// destroyed): SIGTERM shutdown may destroy function-static storage before the
// plugin manager stops, and a transition hook must never run through a dead
// mutex.  Every live handle unregisters before its protocol object is deleted,
// so the registry is finite and contains no DSO-owned callbacks.
// ---------------------------------------------------------------------------
struct RawLiveRegistry {
	std::mutex mutex;
	std::unordered_map<const void*, std::vector<ProxySQL_RawBackend*>> by_server;
};

std::atomic<RawLiveRegistry*> g_raw_live_registry { nullptr };

RawLiveRegistry* ensure_live_registry() {
	RawLiveRegistry* registry = g_raw_live_registry.load(std::memory_order_acquire);
	if (registry != nullptr) return registry;
	RawLiveRegistry* candidate = new RawLiveRegistry();
	RawLiveRegistry* expected = nullptr;
	if (g_raw_live_registry.compare_exchange_strong(expected, candidate,
			std::memory_order_release, std::memory_order_acquire)) {
		return candidate;
	}
	delete candidate;
	return expected;
}

void register_live_handle(ProxySQL_RawBackend* handle) {
	if (handle == nullptr || handle->parent == nullptr) return;
	RawLiveRegistry* registry = ensure_live_registry();
	if (registry == nullptr) return;
	std::lock_guard<std::mutex> lock(registry->mutex);
	auto insertion = registry->by_server.try_emplace(handle->parent);
	try {
		insertion.first->second.push_back(handle);
	} catch (...) {
		// Strong guarantee: a failed vector allocation must not leave an
		// empty server key behind.  The handle itself is unwound by the
		// acquire caller, so the registry contains only live handles.
		if (insertion.second) registry->by_server.erase(insertion.first);
		throw;
	}
	handle->registered.store(true, std::memory_order_release);
}

// Returns the final per-handle HARD latch sampled under the registry mutex.
// The HARD transition hook takes the same mutex, so a transition serialized
// before retirement is observed; a transition after this old handle is
// unregistered legitimately belongs to a later attempt.
bool unregister_live_handle(ProxySQL_RawBackend* handle) noexcept {
	if (handle == nullptr) return false;
	if (!handle->registered.exchange(false, std::memory_order_acq_rel)) {
		return handle->hard_latched.load(std::memory_order_acquire);
	}
	RawLiveRegistry* registry = g_raw_live_registry.load(std::memory_order_acquire);
	if (registry == nullptr) return handle->hard_latched.load(std::memory_order_acquire);
	std::lock_guard<std::mutex> lock(registry->mutex);
	const bool final_hard = handle->hard_latched.load(std::memory_order_acquire);
	auto it = registry->by_server.find(handle->parent);
	if (it == registry->by_server.end()) return final_hard;
	auto& handles = it->second;
	handles.erase(std::remove(handles.begin(), handles.end(), handle), handles.end());
	if (handles.empty()) registry->by_server.erase(it);
	return final_hard;
}

// Reads only the already-published registry pointer.  Registration installs
// the registry before any live handle exists, so this hook never allocates.
void mark_live_handles_hard(const void* server_identity) noexcept {
	RawLiveRegistry* registry = g_raw_live_registry.load(std::memory_order_acquire);
	if (registry == nullptr || server_identity == nullptr) return;
	try {
		std::lock_guard<std::mutex> lock(registry->mutex);
		auto it = registry->by_server.find(server_identity);
		if (it == registry->by_server.end()) return;
		for (ProxySQL_RawBackend* handle : it->second) {
			if (handle != nullptr) {
				handle->hard_latched.store(true, std::memory_order_release);
			}
		}
	} catch (...) {
		// noexcept transition hook: a failed lookup must not escape into HGM code.
	}
}

// ---------------------------------------------------------------------------
// Exact native thread policy save/restore.
//
// A raw service caller is an epoll/acceptor worker, not a MySQL_Thread or
// PgSQL_Thread.  Its per-thread policy words may be zero/stale, so read the
// live handler values under the same ext_mutex -> handler wrlock order used by
// refresh_variables(), release both locks, then install the snapshot for this
// operation.  HGM locks are never taken while holding either handler lock.
// ---------------------------------------------------------------------------
class RawPolicyGuard {
public:
	explicit RawPolicyGuard(ProxySQL_RawBackendProtocol protocol) : protocol_(protocol) {
		if (protocol_ == ProxySQL_RawBackendProtocol::mysql) {
			load_mysql();
		} else {
			load_pgsql();
		}
	}

	~RawPolicyGuard() { restore(); }

	RawPolicyGuard(const RawPolicyGuard&) = delete;
	RawPolicyGuard& operator=(const RawPolicyGuard&) = delete;

private:
	void load_mysql() {
		m_latency_awareness_min_servers = proxysql_raw_backend_latency_awareness_min_servers();
		m_default_max_latency_ms = mysql_thread___default_max_latency_ms;
		m_shun_recovery_time_sec = mysql_thread___shun_recovery_time_sec;
		m_connect_timeout_server_max = mysql_thread___connect_timeout_server_max;
		m_unshun_algorithm = mysql_thread___unshun_algorithm;
		m_connect_retries_on_failure = mysql_thread___connect_retries_on_failure;
		m_shun_on_failures = mysql_thread___shun_on_failures;
		m_throttle_connections_per_sec_to_hostgroup =
			mysql_thread___throttle_connections_per_sec_to_hostgroup;
		m_aws_locality_awareness = mysql_thread___aws_locality_awareness;

		bool have_handler = false;
		pthread_mutex_lock(&GloVars.global.ext_glomth_mutex);
		if (GloMTH != nullptr) {
			GloMTH->wrlock();
			live_default_max_latency_ms = GloMTH->variables.default_max_latency_ms;
			live_shun_recovery_time_sec = GloMTH->variables.shun_recovery_time_sec;
			live_connect_timeout_server_max = GloMTH->variables.connect_timeout_server_max;
			live_unshun_algorithm = GloMTH->variables.unshun_algorithm;
			live_connect_retries_on_failure = GloMTH->variables.connect_retries_on_failure;
			live_shun_on_failures = GloMTH->variables.shun_on_failures;
			live_throttle_connections_per_sec_to_hostgroup =
				GloMTH->variables.throttle_connections_per_sec_to_hostgroup;
			live_aws_locality_awareness = GloMTH->variables.aws_locality_awareness;
			live_latency_awareness_min_servers =
				GloMTH->variables.min_num_servers_lantency_awareness;
			GloMTH->wrunlock();
			have_handler = true;
		}
		pthread_mutex_unlock(&GloVars.global.ext_glomth_mutex);

		if (have_handler) {
			mysql_thread___default_max_latency_ms = live_default_max_latency_ms;
			mysql_thread___shun_recovery_time_sec = live_shun_recovery_time_sec;
			mysql_thread___connect_timeout_server_max = live_connect_timeout_server_max;
			mysql_thread___unshun_algorithm = live_unshun_algorithm;
			mysql_thread___connect_retries_on_failure = live_connect_retries_on_failure;
			mysql_thread___shun_on_failures = live_shun_on_failures;
			mysql_thread___throttle_connections_per_sec_to_hostgroup =
				live_throttle_connections_per_sec_to_hostgroup;
			mysql_thread___aws_locality_awareness = live_aws_locality_awareness;
			g_raw_latency_awareness_min_servers = live_latency_awareness_min_servers;
		}
	}

	void load_pgsql() {
		m_latency_awareness_min_servers = proxysql_raw_backend_latency_awareness_min_servers();
		p_default_max_latency_ms = pgsql_thread___default_max_latency_ms;
		p_shun_recovery_time_sec = pgsql_thread___shun_recovery_time_sec;
		p_connect_timeout_server_max = pgsql_thread___connect_timeout_server_max;
		p_unshun_algorithm = pgsql_thread___unshun_algorithm;
		p_connect_retries_on_failure = pgsql_thread___connect_retries_on_failure;
		p_shun_on_failures = pgsql_thread___shun_on_failures;
		p_throttle_connections_per_sec_to_hostgroup =
			pgsql_thread___throttle_connections_per_sec_to_hostgroup;

		bool have_handler = false;
		pthread_mutex_lock(&GloVars.global.ext_glopth_mutex);
		if (GloPTH != nullptr) {
			GloPTH->wrlock();
			live_p_default_max_latency_ms = GloPTH->variables.default_max_latency_ms;
			live_p_shun_recovery_time_sec = GloPTH->variables.shun_recovery_time_sec;
			live_p_connect_timeout_server_max = GloPTH->variables.connect_timeout_server_max;
			live_p_unshun_algorithm = GloPTH->variables.unshun_algorithm;
			live_p_connect_retries_on_failure = GloPTH->variables.connect_retries_on_failure;
			live_p_shun_on_failures = GloPTH->variables.shun_on_failures;
			live_p_throttle_connections_per_sec_to_hostgroup =
				GloPTH->variables.throttle_connections_per_sec_to_hostgroup;
			live_latency_awareness_min_servers =
				GloPTH->variables.min_num_servers_lantency_awareness;
			GloPTH->wrunlock();
			have_handler = true;
		}
		pthread_mutex_unlock(&GloVars.global.ext_glopth_mutex);

		if (have_handler) {
			pgsql_thread___default_max_latency_ms = live_p_default_max_latency_ms;
			pgsql_thread___shun_recovery_time_sec = live_p_shun_recovery_time_sec;
			pgsql_thread___connect_timeout_server_max = live_p_connect_timeout_server_max;
			pgsql_thread___unshun_algorithm = live_p_unshun_algorithm;
			pgsql_thread___connect_retries_on_failure = live_p_connect_retries_on_failure;
			pgsql_thread___shun_on_failures = live_p_shun_on_failures;
			pgsql_thread___throttle_connections_per_sec_to_hostgroup =
				live_p_throttle_connections_per_sec_to_hostgroup;
			g_raw_latency_awareness_min_servers = live_latency_awareness_min_servers;
		}
	}

	void restore() {
		g_raw_latency_awareness_min_servers = m_latency_awareness_min_servers;
		if (protocol_ == ProxySQL_RawBackendProtocol::mysql) {
			mysql_thread___default_max_latency_ms = m_default_max_latency_ms;
			mysql_thread___shun_recovery_time_sec = m_shun_recovery_time_sec;
			mysql_thread___connect_timeout_server_max = m_connect_timeout_server_max;
			mysql_thread___unshun_algorithm = m_unshun_algorithm;
			mysql_thread___connect_retries_on_failure = m_connect_retries_on_failure;
			mysql_thread___shun_on_failures = m_shun_on_failures;
			mysql_thread___throttle_connections_per_sec_to_hostgroup =
				m_throttle_connections_per_sec_to_hostgroup;
			mysql_thread___aws_locality_awareness = m_aws_locality_awareness;
		} else {
			pgsql_thread___default_max_latency_ms = p_default_max_latency_ms;
			pgsql_thread___shun_recovery_time_sec = p_shun_recovery_time_sec;
			pgsql_thread___connect_timeout_server_max = p_connect_timeout_server_max;
			pgsql_thread___unshun_algorithm = p_unshun_algorithm;
			pgsql_thread___connect_retries_on_failure = p_connect_retries_on_failure;
			pgsql_thread___shun_on_failures = p_shun_on_failures;
			pgsql_thread___throttle_connections_per_sec_to_hostgroup =
				p_throttle_connections_per_sec_to_hostgroup;
		}
	}

	ProxySQL_RawBackendProtocol protocol_;
	int m_latency_awareness_min_servers { 0 };
	int live_latency_awareness_min_servers { 0 };
	int m_default_max_latency_ms { 0 };
	int m_shun_recovery_time_sec { 0 };
	int m_connect_timeout_server_max { 0 };
	int m_unshun_algorithm { 0 };
	int m_connect_retries_on_failure { 0 };
	int m_shun_on_failures { 0 };
	int m_throttle_connections_per_sec_to_hostgroup { 0 };
	bool m_aws_locality_awareness { false };
	int live_default_max_latency_ms { 0 };
	int live_shun_recovery_time_sec { 0 };
	int live_connect_timeout_server_max { 0 };
	int live_unshun_algorithm { 0 };
	int live_connect_retries_on_failure { 0 };
	int live_shun_on_failures { 0 };
	int live_throttle_connections_per_sec_to_hostgroup { 0 };
	bool live_aws_locality_awareness { false };

	int p_default_max_latency_ms { 0 };
	int p_shun_recovery_time_sec { 0 };
	int p_connect_timeout_server_max { 0 };
	int p_unshun_algorithm { 0 };
	int p_connect_retries_on_failure { 0 };
	int p_shun_on_failures { 0 };
	int p_throttle_connections_per_sec_to_hostgroup { 0 };
	int live_p_default_max_latency_ms { 0 };
	int live_p_shun_recovery_time_sec { 0 };
	int live_p_connect_timeout_server_max { 0 };
	int live_p_unshun_algorithm { 0 };
	int live_p_connect_retries_on_failure { 0 };
	int live_p_shun_on_failures { 0 };
	int live_p_throttle_connections_per_sec_to_hostgroup { 0 };
};

template <typename Manager>
class ScopedHgmWrite {
public:
	explicit ScopedHgmWrite(Manager* manager) : manager_(manager) {
		if (manager_ != nullptr) manager_->wrlock();
	}
	~ScopedHgmWrite() {
		if (manager_ != nullptr) manager_->wrunlock();
	}
	ScopedHgmWrite(const ScopedHgmWrite&) = delete;
	ScopedHgmWrite& operator=(const ScopedHgmWrite&) = delete;
private:
	Manager* manager_;
};

// Releases the protocol accounting object and exactly one ownership link.  The
// raw handle itself is deleted by destroy() (or by the acquire caller's
// unique_ptr on unwind), never here.
bool release_accounted_object(ProxySQL_RawBackend* handle) noexcept {
	if (handle == nullptr) return false;
	if (handle->destroyed.exchange(true, std::memory_order_acq_rel)) {
		return handle->hard_latched.load(std::memory_order_acquire);
	}

	void* object = handle->object;
	void* parent = handle->parent;
	bool final_hard = handle->hard_latched.load(std::memory_order_acquire);

	if (handle->protocol == ProxySQL_RawBackendProtocol::mysql) {
		{
			ScopedHgmWrite<MySQL_HostGroups_Manager> lock(MyHGM);
			final_hard = unregister_live_handle(handle);
			if (object != nullptr && parent != nullptr) {
				static_cast<MySrvC*>(parent)->ConnectionsUsed->remove(
					static_cast<MySQL_Connection*>(object));
				if (MyHGM != nullptr) {
					__sync_fetch_and_add(&MyHGM->status.myconnpoll_destroy, 1);
					if (handle->connected.load(std::memory_order_acquire)) {
						__sync_fetch_and_sub(&MyHGM->status.server_connections_connected, 1);
					}
				}
			}
		}
		if (object != nullptr) {
			auto* connection = static_cast<MySQL_Connection*>(object);
			connection->fd = -1;
			connection->mysql = nullptr;
			connection->ret_mysql = nullptr;
			delete connection;
		}
	} else {
		{
			ScopedHgmWrite<PgSQL_HostGroups_Manager> lock(PgHGM);
			final_hard = unregister_live_handle(handle);
			if (object != nullptr && parent != nullptr) {
				static_cast<PgSQL_SrvC*>(parent)->ConnectionsUsed->remove(
					static_cast<PgSQL_Connection*>(object));
				if (PgHGM != nullptr) {
					__sync_fetch_and_add(&PgHGM->status.pgconnpoll_destroy, 1);
					if (handle->connected.load(std::memory_order_acquire)) {
						__sync_fetch_and_sub(&PgHGM->status.server_connections_connected, 1);
					}
				}
			}
		}
		if (object != nullptr) {
			auto* connection = static_cast<PgSQL_Connection*>(object);
			connection->fd = -1;
			connection->pgsql_conn = nullptr;
			delete connection;
		}
	}

	handle->object = nullptr;
	handle->parent = nullptr;
	return final_hard;
}

ProxySQL_RawBackend* acquire_impl(ProxySQL_RawBackendProtocol protocol, uint32_t hostgroup,
	ProxySQL_RawBackendEndpoint& endpoint, std::string& error) {
	endpoint.address.clear();
	endpoint.port = 0;
	error.clear();

	if (protocol != ProxySQL_RawBackendProtocol::mysql &&
		protocol != ProxySQL_RawBackendProtocol::pgsql) {
		error = "invalid raw backend protocol";
		return nullptr;
	}

	RawPolicyGuard policy(protocol);
	ensure_live_registry();

	std::unique_ptr<ProxySQL_RawBackend> handle(new ProxySQL_RawBackend(protocol, hostgroup));
	struct AcquireUnwind {
		ProxySQL_RawBackend* handle;
		bool armed { true };
		~AcquireUnwind() {
			if (armed) release_accounted_object(handle);
		}
	} unwind { handle.get() };

	if (protocol == ProxySQL_RawBackendProtocol::mysql) {
		if (MyHGM == nullptr) {
			error = "MySQL hostgroup manager is not available";
			return nullptr;
		}

		std::string host;
		uint16_t port = 0;
		{
			ScopedHgmWrite<MySQL_HostGroups_Manager> lock(MyHGM);
			__sync_fetch_and_add(&MyHGM->status.myconnpoll_get, 1);
			MyHGC* hostgroup_ptr = MyHGM->MyHGC_find(hostgroup);
			if (hostgroup_ptr == nullptr) {
				error = "MySQL hostgroup " + std::to_string(hostgroup) + " is not configured";
				return nullptr;
			}

			MySrvC* server = hostgroup_ptr->get_random_MySrvC(nullptr, 0, -1, nullptr);
			if (server == nullptr) {
				error = "MySQL hostgroup " + std::to_string(hostgroup) + " has no eligible server";
				return nullptr;
			}

			const unsigned long long now = monotonic_time() / 1000 / 1000;
			if (now > hostgroup_ptr->current_time_now) {
				hostgroup_ptr->current_time_now = now;
				hostgroup_ptr->new_connections_now = 0;
			}
			hostgroup_ptr->new_connections_now++;

			unsigned int throttle =
				static_cast<unsigned int>(mysql_thread___throttle_connections_per_sec_to_hostgroup);
			if (hostgroup_ptr->attributes.configured == true) {
				throttle = hostgroup_ptr->attributes.throttle_connections_per_sec;
			}
			if (should_throttle_connection_creation(hostgroup_ptr->new_connections_now, throttle)) {
				__sync_fetch_and_add(&MyHGM->status.server_connections_delayed, 1);
				error = "MySQL hostgroup " + std::to_string(hostgroup) +
					" connection creation is throttled";
				return nullptr;
			}

			auto* connection = new MySQL_Connection();
			connection->parent = server;
			connection->set_status(
				!connection->parent->myhgc->attributes.multiplex,
				STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
			connection->send_quit = false;
			connection->reusable = false;
			connection->fd = -1;
			connection->mysql = nullptr;
			connection->ret_mysql = nullptr;

			__sync_fetch_and_add(&MyHGM->status.server_connections_created, 1);
			server->ConnectionsUsed->add(connection);
			__sync_fetch_and_add(&MyHGM->status.myconnpoll_get_ok, 1);
			server->update_max_connections_used();

			handle->object = connection;
			handle->parent = server;
			host = server->address != nullptr ? server->address : "";
			port = server->port;
			register_live_handle(handle.get());
		}

		std::string resolved = host;
		if (!host.empty() && !validate_ip(host)) {
			resolved = MySQL_Monitor::dns_lookup(host, false);
		}
		if (resolved.empty() || !validate_ip(resolved)) {
			release_accounted_object(handle.get());
			unwind.armed = false;
			error = "DNS cache lookup failed for MySQL backend '" + host +
				"'; a numeric address or a warm monitor DNS cache entry is required";
			return nullptr;
		}
		endpoint.address = resolved;
		endpoint.port = port;
		unwind.armed = false;
		return handle.release();
	}

	if (PgHGM == nullptr) {
		error = "PgSQL hostgroup manager is not available";
		return nullptr;
	}

	std::string host;
	uint16_t port = 0;
	{
		ScopedHgmWrite<PgSQL_HostGroups_Manager> lock(PgHGM);
		__sync_fetch_and_add(&PgHGM->status.pgconnpoll_get, 1);
		PgSQL_HGC* hostgroup_ptr = PgHGM->MyHGC_find(hostgroup);
		if (hostgroup_ptr == nullptr) {
			error = "PgSQL hostgroup " + std::to_string(hostgroup) + " is not configured";
			return nullptr;
		}

		PgSQL_SrvC* server = hostgroup_ptr->get_random_MySrvC(nullptr, 0, -1, nullptr);
		if (server == nullptr) {
			error = "PgSQL hostgroup " + std::to_string(hostgroup) + " has no eligible server";
			return nullptr;
		}

		const unsigned long long now = monotonic_time() / 1000 / 1000;
		if (now > hostgroup_ptr->current_time_now) {
			hostgroup_ptr->current_time_now = now;
			hostgroup_ptr->new_connections_now = 0;
		}
		hostgroup_ptr->new_connections_now++;

		unsigned int throttle =
			static_cast<unsigned int>(pgsql_thread___throttle_connections_per_sec_to_hostgroup);
		if (hostgroup_ptr->attributes.configured == true) {
			throttle = hostgroup_ptr->attributes.throttle_connections_per_sec;
		}
		if (should_throttle_connection_creation(hostgroup_ptr->new_connections_now, throttle)) {
			__sync_fetch_and_add(&PgHGM->status.server_connections_delayed, 1);
			error = "PgSQL hostgroup " + std::to_string(hostgroup) +
				" connection creation is throttled";
			return nullptr;
		}

		auto* connection = new PgSQL_Connection(false);
		connection->parent = server;
		connection->send_quit = false;
		connection->reusable = false;
		connection->fd = -1;
		connection->pgsql_conn = nullptr;

		__sync_fetch_and_add(&PgHGM->status.server_connections_created, 1);
		server->ConnectionsUsed->add(connection);
		__sync_fetch_and_add(&PgHGM->status.pgconnpoll_get_ok, 1);
		server->update_max_connections_used();

		handle->object = connection;
		handle->parent = server;
		host = server->address != nullptr ? server->address : "";
		port = server->port;
		register_live_handle(handle.get());
	}

	std::string resolved = host;
	if (!host.empty() && !validate_ip(host)) {
		resolved = PgSQL_Monitor::dns_lookup(host, false);
	}
	if (resolved.empty() || !validate_ip(resolved)) {
		release_accounted_object(handle.get());
		unwind.armed = false;
		error = "DNS cache lookup failed for PgSQL backend '" + host +
			"'; a numeric address or a warm monitor DNS cache entry is required";
		return nullptr;
	}
	endpoint.address = resolved;
	endpoint.port = port;
	unwind.armed = false;
	return handle.release();
}

void connect_result_impl(ProxySQL_RawBackend* handle, int socket_errno) noexcept {
	if (handle == nullptr) return;
	try {
	bool expected = false;
	if (!handle->outcome_reported.compare_exchange_strong(expected, true,
			std::memory_order_acq_rel)) {
		return;
	}
	if (handle->destroyed.load(std::memory_order_acquire)) return;

	if (socket_errno == 0) {
		handle->connected.store(true, std::memory_order_release);
		if (handle->protocol == ProxySQL_RawBackendProtocol::mysql) {
			ScopedHgmWrite<MySQL_HostGroups_Manager> lock(MyHGM);
			if (MyHGM != nullptr && handle->parent != nullptr) {
				__sync_fetch_and_add(&static_cast<MySrvC*>(handle->parent)->connect_OK, 1);
				__sync_fetch_and_add(&MyHGM->status.server_connections_connected, 1);
			}
		} else {
			ScopedHgmWrite<PgSQL_HostGroups_Manager> lock(PgHGM);
			if (PgHGM != nullptr && handle->parent != nullptr) {
				__sync_fetch_and_add(&static_cast<PgSQL_SrvC*>(handle->parent)->connect_OK, 1);
				__sync_fetch_and_add(&PgHGM->status.server_connections_connected, 1);
			}
		}
		return;
	}

	RawPolicyGuard policy(handle->protocol);
	if (handle->protocol == ProxySQL_RawBackendProtocol::mysql) {
		{
			ScopedHgmWrite<MySQL_HostGroups_Manager> lock(MyHGM);
			if (MyHGM != nullptr && handle->parent != nullptr) {
				static_cast<MySrvC*>(handle->parent)->connect_error(2003, false);
			}
		}

		if (MyHGM != nullptr && handle->parent != nullptr) {
			auto* server = static_cast<MySrvC*>(handle->parent);
			std::string message = "Can't connect to MySQL server: ";
			message += std::strerror(socket_errno);
			char empty[] = "";
			char unknown[] = "unknown";
			char* hostname = server->address != nullptr ? server->address : empty;
			MyHGM->add_mysql_errors(static_cast<int>(server->myhgc->hid), hostname,
				server->port, empty, unknown, empty, 2003, &message[0]);
		}
	} else {
		{
			ScopedHgmWrite<PgSQL_HostGroups_Manager> lock(PgHGM);
			if (PgHGM != nullptr && handle->parent != nullptr) {
				static_cast<PgSQL_SrvC*>(handle->parent)->connect_error(2003, false);
			}
		}

		if (PgHGM != nullptr && handle->parent != nullptr) {
			auto* server = static_cast<PgSQL_SrvC*>(handle->parent);
			std::string message = "could not connect to server: ";
			message += std::strerror(socket_errno);
			char empty[] = "";
			char unknown[] = "unknown";
			const char* hostname = server->address != nullptr ? server->address : empty;
			PgHGM->add_pgsql_errors(static_cast<int>(server->myhgc->hid), hostname,
				server->port, empty, unknown, empty, "08001", message.c_str());
		}
	}
	} catch (...) {
		// The callback is noexcept; the outcome latch already prevents retries.
	}
}

void account_io_impl(ProxySQL_RawBackend* handle, uint64_t sent, uint64_t received) noexcept {
	if (handle == nullptr || handle->destroyed.load(std::memory_order_acquire)) return;
	try {
	if (handle->protocol == ProxySQL_RawBackendProtocol::mysql) {
		auto* connection = static_cast<MySQL_Connection*>(handle->object);
		auto* server = static_cast<MySrvC*>(handle->parent);
		if (connection != nullptr) {
			connection->bytes_info.bytes_sent += sent;
			connection->bytes_info.bytes_recv += received;
		}
		if (server != nullptr) {
			if (sent != 0) __sync_fetch_and_add(&server->bytes_sent, sent);
			if (received != 0) __sync_fetch_and_add(&server->bytes_recv, received);
		}
	} else {
		auto* connection = static_cast<PgSQL_Connection*>(handle->object);
		auto* server = static_cast<PgSQL_SrvC*>(handle->parent);
		if (connection != nullptr) {
			connection->bytes_info.bytes_sent += sent;
			connection->bytes_info.bytes_recv += received;
		}
		if (server != nullptr) {
			if (sent != 0) __sync_fetch_and_add(&server->bytes_sent, sent);
			if (received != 0) __sync_fetch_and_add(&server->bytes_recv, received);
		}
	}
	} catch (...) {
	}
}

bool offline_hard_impl(const ProxySQL_RawBackend* handle) noexcept {
	// Every actual protocol HGM OFFLINE_HARD write is audited and latches this
	// handle from the transition hook.  Polling reads only the atomic fact, so
	// idle streams never contend on the HGM lock or observe a later ONLINE.
	return handle != nullptr &&
		handle->hard_latched.load(std::memory_order_acquire);
}

bool destroy_impl(ProxySQL_RawBackend* handle) noexcept {
	if (handle == nullptr) return false;
	bool final_hard = false;
	try {
		final_hard = release_accounted_object(handle);
	} catch (...) {
		final_hard = handle->hard_latched.load(std::memory_order_acquire);
	}
	delete handle;
	return final_hard;
}

const ProxySQL_RawBackendServiceV2 raw_backend_service_v2 {
	2,
	&acquire_impl,
	&connect_result_impl,
	&account_io_impl,
	&offline_hard_impl,
	&destroy_impl
};

} // namespace

const ProxySQL_RawBackendServiceV2* proxysql_raw_backend_service() noexcept {
	return &raw_backend_service_v2;
}

void proxysql_raw_backend_mark_offline_hard(const void* server_identity) noexcept {
	mark_live_handles_hard(server_identity);
}

int proxysql_raw_backend_latency_awareness_min_servers() noexcept {
	return g_raw_latency_awareness_min_servers;
}

#endif // PROXYSQL40
