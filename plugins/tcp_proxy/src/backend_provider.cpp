/*
 * Core ABI adapter for mapped-hostgroup backend acquisition.
 *
 * The Engine is deliberately independent of ProxySQL types.  This unit is the
 * only production plugin code that touches the borrowed ABI-18 raw-backend
 * service table; the standalone engine test target does not compile it.
 *
 * Ownership contract:
 *   - the provider borrows the process-resident V2 table for the plugin
 *     lifetime (the core owns it);
 *   - each acquire() returns one core-owned raw backend handle to the Engine;
 *   - the Engine creates/owns the socket; this adapter never performs I/O;
 *   - the connection destructor performs the single core destroy() call.
 */

#include "tcp_proxy_plugin.h"

#ifdef PROXYSQL40
#include "ProxySQL_PluginRawBackend.h"
#endif

#include <atomic>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

namespace tcp_proxy_plugin {

#ifdef PROXYSQL40

namespace {

#ifdef TCP_PROXY_BACKEND_PROVIDER_TESTING
std::atomic<bool> g_fail_wrapper_allocation { false };
#endif

bool backend_service_usable(const ProxySQL_RawBackendServiceV2* service) {
	return service != nullptr && service->version == 2 &&
		service->acquire != nullptr && service->connect_result != nullptr &&
		service->account_io != nullptr && service->offline_hard != nullptr &&
		service->destroy != nullptr;
}

class RawBackendConnection final : public tcp_proxy::BackendConnection {
public:
	RawBackendConnection(const ProxySQL_RawBackendServiceV2* service,
		ProxySQL_RawBackend* handle, std::string hostname, int port)
		: service_(service), handle_(handle), hostname_(std::move(hostname)),
		  port_(port) {}

	~RawBackendConnection() override {
		// Unwind fallback; repeated/late calls return the cached fence.
		destroy();
	}

	RawBackendConnection(const RawBackendConnection&) = delete;
	RawBackendConnection& operator=(const RawBackendConnection&) = delete;

	bool destroy() noexcept override {
		bool expected = false;
		if (!retired_.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel)) {
			return final_hard_.load(std::memory_order_acquire);
		}
		bool final_hard = false;
		if (service_ != nullptr && handle_ != nullptr) {
			final_hard = service_->destroy(handle_);
			handle_ = nullptr;
		}
		final_hard_.store(final_hard, std::memory_order_release);
		return final_hard;
	}

	const std::string& hostname() const noexcept override { return hostname_; }
	int port() const noexcept override { return port_; }

	void connect_result(int socket_errno) noexcept override {
		if (service_ == nullptr || handle_ == nullptr) {
			return;
		}
		// The core also ignores duplicates; keep the engine-side guarantee
		// explicit so a future core implementation cannot be double counted.
		if (reported_.exchange(true, std::memory_order_acq_rel)) {
			return;
		}
		service_->connect_result(handle_, socket_errno);
	}

	void account_io(uint64_t sent, uint64_t received) noexcept override {
		if (service_ == nullptr || handle_ == nullptr) {
			return;
		}
		service_->account_io(handle_, sent, received);
	}

	bool offline_hard() const noexcept override {
		if (retired_.load(std::memory_order_acquire)) {
			return final_hard_.load(std::memory_order_acquire);
		}
		return service_ != nullptr && handle_ != nullptr &&
			service_->offline_hard(handle_);
	}

private:
	const ProxySQL_RawBackendServiceV2* service_ { nullptr };
	ProxySQL_RawBackend* handle_ { nullptr };
	std::string hostname_ {};
	int port_ { 0 };
	std::atomic<bool> reported_ { false };
	std::atomic<bool> retired_ { false };
	std::atomic<bool> final_hard_ { false };
};

/**
 * Owns one freshly acquired core handle until the C++ wrapper has taken over.
 * This closes the allocation-failure window between core acquire() and
 * unique_ptr construction without leaking the ConnectionsUsed reservation.
 */
class RawHandleGuard final {
public:
	RawHandleGuard(const ProxySQL_RawBackendServiceV2* service,
		ProxySQL_RawBackend* handle) noexcept
		: service_(service), handle_(handle) {}

	~RawHandleGuard() {
		if (service_ != nullptr && handle_ != nullptr) {
			service_->destroy(handle_);
		}
	}

	RawHandleGuard(const RawHandleGuard&) = delete;
	RawHandleGuard& operator=(const RawHandleGuard&) = delete;

	void release() noexcept { handle_ = nullptr; }

private:
	const ProxySQL_RawBackendServiceV2* service_ { nullptr };
	ProxySQL_RawBackend* handle_ { nullptr };
};

class RawBackendProvider final : public tcp_proxy::BackendProvider {
public:
	explicit RawBackendProvider(const ProxySQL_RawBackendServiceV2* service)
		: service_(service), usable_(backend_service_usable(service)) {}

	bool available() const noexcept override { return usable_; }

	std::unique_ptr<tcp_proxy::BackendConnection> acquire(
		const std::string& protocol, int source_hostgroup) override {
		if (!usable_) {
			throw std::runtime_error("core raw backend service is unavailable");
		}
		if (source_hostgroup < 0) {
			throw std::runtime_error("invalid source hostgroup");
		}
		ProxySQL_RawBackendProtocol core_protocol;
		if (protocol == "MYSQL") {
			core_protocol = ProxySQL_RawBackendProtocol::mysql;
		} else if (protocol == "PGSQL") {
			core_protocol = ProxySQL_RawBackendProtocol::pgsql;
		} else {
			throw std::runtime_error("unsupported mapped source protocol: " +
				protocol);
		}

		ProxySQL_RawBackendEndpoint endpoint;
		std::string error;
		ProxySQL_RawBackend* handle = service_->acquire(core_protocol,
			static_cast<uint32_t>(source_hostgroup), endpoint, error);
		if (handle == nullptr) {
			throw std::runtime_error(error.empty()
				? "core raw backend acquisition failed"
				: error);
		}
		// From here every failure path must release the actual core handle.
		RawHandleGuard guard(service_, handle);
		if (endpoint.address.empty() || endpoint.port == 0) {
			throw std::runtime_error(
				"core raw backend returned an invalid numeric endpoint");
		}
#ifdef TCP_PROXY_BACKEND_PROVIDER_TESTING
		if (g_fail_wrapper_allocation.exchange(false,
				std::memory_order_acq_rel)) {
			throw std::bad_alloc();
		}
#endif
		auto connection = std::make_unique<RawBackendConnection>(service_,
			handle, std::move(endpoint.address), static_cast<int>(endpoint.port));
		guard.release();
		return connection;
	}

private:
	const ProxySQL_RawBackendServiceV2* service_ { nullptr };
	bool usable_ { false };
};

} // namespace

#endif // PROXYSQL40

void raw_backend_provider_test_fail_wrapper_allocation_once(bool fail) {
#ifdef PROXYSQL40
#ifdef TCP_PROXY_BACKEND_PROVIDER_TESTING
	g_fail_wrapper_allocation.store(fail, std::memory_order_release);
#else
	(void)fail;
#endif
#else
	(void)fail;
#endif
}

std::shared_ptr<tcp_proxy::BackendProvider> make_raw_backend_provider(
	const ProxySQL_RawBackendServiceV2* service) {
#ifdef PROXYSQL40
	try {
		return std::make_shared<RawBackendProvider>(service);
	} catch (...) {
		return nullptr;
	}
#else
	(void)service;
	return nullptr;
#endif
}

std::shared_ptr<tcp_proxy::BackendProvider> core_backend_provider(
	ProxySQL_PluginServices* services) {
#ifdef PROXYSQL40
	if (services == nullptr || services->get_raw_backend_service == nullptr) {
		return nullptr;
	}
	return make_raw_backend_provider(services->get_raw_backend_service());
#else
	(void)services;
	return nullptr;
#endif
}

} // namespace tcp_proxy_plugin
