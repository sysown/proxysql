#include "Aws_Iam_Sdk.h"
#include "ProxySQL_Plugin.h"

#include <aws/core/Aws.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/rds/RDSClient.h>

#include <dlfcn.h>
#include <openssl/crypto.h>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace {

class AwsIamSdkRuntime final {
public:
	AwsIamSdkRuntime() { Aws::InitAPI(options_); }
	~AwsIamSdkRuntime() { Aws::ShutdownAPI(options_); }

	AwsIamSdkRuntime(const AwsIamSdkRuntime&) = delete;
	AwsIamSdkRuntime& operator=(const AwsIamSdkRuntime&) = delete;

private:
	Aws::SDKOptions options_;
};

class AwsIamSensitiveStringCleanup final {
public:
	explicit AwsIamSensitiveStringCleanup(Aws::String& value) : value_(value) {}
	~AwsIamSensitiveStringCleanup() noexcept {
		if (!value_.empty()) {
			OPENSSL_cleanse(&value_[0], value_.size());
		}
	}

	AwsIamSensitiveStringCleanup(const AwsIamSensitiveStringCleanup&) = delete;
	AwsIamSensitiveStringCleanup& operator=(const AwsIamSensitiveStringCleanup&) = delete;

private:
	Aws::String& value_;
};

class AwsIamRdsSigner final : public AwsIamTokenSigner {
public:
	AwsIamSignResult sign(const AwsIamTokenKey& key) override {
		Aws::RDS::RDSClient& rds_client = client_for_region(key.region);
		Aws::String token = rds_client.GenerateConnectAuthToken(
			key.endpoint.c_str(), key.region.c_str(), key.port,
			key.database_user.c_str());
		AwsIamSensitiveStringCleanup token_cleanup(token);

		AwsIamSignResult result;
		if (token.empty()) {
			result.status = AwsIamStatus::CREDENTIAL_PROVIDER_ERROR;
			return result;
		}
		result.status = AwsIamStatus::OK;
		result.token = SecureString(std::string_view(token.data(), token.size()));
		return result;
	}

private:
	Aws::RDS::RDSClient& client_for_region(const std::string& region) {
		std::lock_guard<std::mutex> lock(clients_mutex_);
		auto found = regional_clients_.find(region);
		if (found == regional_clients_.end()) {
			Aws::Client::ClientConfiguration client_config;
			client_config.region = region.c_str();
			found = regional_clients_.emplace(
				region, std::make_unique<Aws::RDS::RDSClient>(client_config)).first;
		}
		return *found->second;
	}

	std::mutex clients_mutex_;
	std::unordered_map<std::string, std::unique_ptr<Aws::RDS::RDSClient>> regional_clients_;
};

class AwsIamSdkTokenSource final : public AwsIamTokenSource {
public:
	explicit AwsIamSdkTokenSource(const AwsIamRuntimeConfig& config)
		: signer_(std::make_shared<AwsIamRdsSigner>()) {
		AwsIamTokenManagerConfig manager_config(config.max_total_waiters);
		manager_config.max_total_waiters = config.max_total_waiters;
		manager_config.max_waiters_per_key = config.max_waiters_per_key;
		manager_ = std::make_unique<AwsIamTokenManager>(signer_, std::move(manager_config));
	}

	AwsIamRequestHandle request(const AwsIamTokenKey& key, uint64_t opaque_id,
		std::weak_ptr<AwsIamCompletionSink> sink) override {
		return manager_->request(key, opaque_id, std::move(sink));
	}

	AwsIamTokenResult request_blocking(const AwsIamTokenKey& key,
		std::chrono::steady_clock::time_point deadline) override {
		return manager_->request_blocking(key, deadline);
	}

	void cancel(AwsIamRequestHandle handle) override { manager_->cancel(handle); }
	void invalidate(const AwsIamTokenKey& key, uint64_t generation) override {
		manager_->invalidate(key, generation);
	}
	void record_backend_connection(bool success) override {
		manager_->record_backend_connection(success);
	}
	void record_waiting_session(bool waiting) override {
		manager_->record_waiting_session(waiting);
	}
	AwsIamStatsSnapshot snapshot() const override { return manager_->snapshot(); }

private:
	// Destruction is reverse declaration order: workers, regional clients,
	// then ShutdownAPI. The core registry calls this only after all leases
	// drain, while the retained module handle keeps this code mapped.
	AwsIamSdkRuntime runtime_;
	std::shared_ptr<AwsIamRdsSigner> signer_;
	std::unique_ptr<AwsIamTokenManager> manager_;
};

void destroy_source(AwsIamTokenSource *source) {
	delete static_cast<AwsIamSdkTokenSource *>(source);
}

void *retain_own_module() {
	Dl_info info {};
	if (dladdr(reinterpret_cast<void *>(&retain_own_module), &info) == 0 ||
		info.dli_fname == nullptr) {
		return nullptr;
	}
	return dlopen(info.dli_fname, RTLD_NOW | RTLD_LOCAL);
}

bool aws_plugin_init(ProxySQL_PluginServices *services) {
	if (services == nullptr || services->install_aws_iam_token_source == nullptr ||
		services->get_aws_iam_limits == nullptr) {
		return false;
	}

	size_t max_total_waiters = 0;
	size_t max_waiters_per_key = 0;
	services->get_aws_iam_limits(&max_total_waiters, &max_waiters_per_key);
	auto source = std::make_unique<AwsIamSdkTokenSource>(AwsIamRuntimeConfig {
		max_total_waiters, max_waiters_per_key
	});
	void *module_handle = retain_own_module();
	if (module_handle == nullptr ||
		!services->install_aws_iam_token_source(source.get(), &destroy_source, module_handle)) {
		if (module_handle != nullptr) dlclose(module_handle);
		return false;
	}
	source.release();
	return true;
}

bool aws_plugin_start() { return true; }

// Core owns the registered source. It drains and destroys it after MySQL
// workers have stopped, using the extra dlopen() reference retained above.
bool aws_plugin_stop() { return true; }

const char *aws_plugin_status_json() {
	return "{\"status\":\"ready\",\"provider\":\"aws\","
		"\"capabilities\":[\"aws_iam\"]}";
}

} // namespace

// The module is built with -fvisibility=hidden; the chassis reaches this
// sole exported entry point with dlsym().
extern "C" __attribute__((visibility("default")))
const ProxySQL_PluginDescriptor *proxysql_plugin_descriptor_v1() {
	static const ProxySQL_PluginDescriptor descriptor {
		"aws",
		PROXYSQL_PLUGIN_ABI_VERSION,
		&aws_plugin_init,
		&aws_plugin_start,
		&aws_plugin_stop,
		&aws_plugin_status_json,
		nullptr,
	};
	return &descriptor;
}
