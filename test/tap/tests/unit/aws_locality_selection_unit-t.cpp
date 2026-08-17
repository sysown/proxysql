#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "Aws_Locality_Manager.h"
#include "GTID_Server_Data.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Logger.hpp"
#include "MySQL_Thread.h"

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {
thread_local bool track_hot_path_allocations = false;
thread_local size_t hot_path_allocations = 0;
}

void* operator new(std::size_t size) {
	if (track_hot_path_allocations) ++hot_path_allocations;
	if (void* memory = std::malloc(size)) return memory;
	throw std::bad_alloc();
}

void* operator new[](std::size_t size) {
	return ::operator new(size);
}

void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete[](void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }
void operator delete[](void* memory, std::size_t) noexcept { std::free(memory); }

extern MySQL_HostGroups_Manager* MyHGM;
extern MySQL_Threads_Handler* GloMTH;
extern MySQL_Logger* GloMyLogger;

void init_myhgc_hostgroup_settings(const char* hostgroup_settings, MyHGC* myhgc);

namespace {

constexpr unsigned int kHostgroup = 740;
constexpr const char* kUser = "locality_user";
constexpr const char* kSchema = "locality_schema";
constexpr const char* kLocal = "db-local.abcdefghijkl.us-east-1.rds.amazonaws.com";
constexpr const char* kRegional = "cluster-regional.abcdefghijkl.us-east-1.rds.amazonaws.com";
constexpr const char* kRemote = "db-remote.abcdefghijkl.eu-west-1.rds.amazonaws.com";

struct ProviderState {
	struct Pending {
		AwsMetadataRequestHandle handle;
		AwsMetadataRequest request;
		std::weak_ptr<AwsMetadataCompletionSink> sink;
	};

	std::mutex mutex;
	std::condition_variable cv;
	std::vector<Pending> pending;
	uint64_t next_handle { 1 };
};

struct NoDeleteMySQLDataStream {
	void operator()(MySQL_Data_Stream* value) const noexcept { (void)value; }
};

struct NoDeleteMySQLConnection {
	void operator()(MySQL_Connection* value) const noexcept { (void)value; }
};

class FakeProvider final : public AwsMetadataProvider {
public:
	explicit FakeProvider(std::shared_ptr<ProviderState> state)
		: state_(std::move(state)) {}

	AwsMetadataRequestHandle request(
		const AwsMetadataRequest& request,
		std::weak_ptr<AwsMetadataCompletionSink> sink) override {
		std::lock_guard<std::mutex> lock(state_->mutex);
		AwsMetadataRequestHandle handle { state_->next_handle++ };
		state_->pending.push_back({handle, request, std::move(sink)});
		state_->cv.notify_all();
		return handle;
	}

	void cancel(AwsMetadataRequestHandle) override {
		// No cancellation side effects are required for this provider fake.
	}
	void shutdown() override {
		// No shutdown side effects are required for this provider fake.
	}

private:
	std::shared_ptr<ProviderState> state_;
};

void destroy_provider(AwsMetadataProvider* provider) {
	std::unique_ptr<AwsMetadataProvider> owned(provider);
}

bool wait_for_requests(const std::shared_ptr<ProviderState>& state, size_t count) {
	std::unique_lock<std::mutex> lock(state->mutex);
	return state->cv.wait_for(lock, 2s, [&state, count] {
		return state->pending.size() >= count;
	});
}

bool complete(
	const std::shared_ptr<ProviderState>& state,
	AwsMetadataRequestKind kind,
	const char* region,
	AwsMetadataResult result) {
	ProviderState::Pending selected;
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		for (const auto& pending : state->pending) {
			if (pending.request.kind == kind && pending.request.region == region) {
				selected = pending;
				break;
			}
		}
	}
	if (selected.handle.value == 0) return false;
	auto sink = selected.sink.lock();
	if (!sink) return false;
	AwsMetadataCompletion completion;
	completion.opaque_id = selected.request.opaque_id;
	completion.generation = selected.request.generation;
	completion.result = std::move(result);
	sink->post(std::move(completion));
	return true;
}

template <typename Predicate>
bool wait_until(Predicate predicate) {
	const auto deadline = std::chrono::steady_clock::now() + 2s;
	while (std::chrono::steady_clock::now() < deadline) {
		if (predicate()) return true;
		std::this_thread::yield();
	}
	return predicate();
}

MySrvC* add_server(const char* hostname, int64_t weight) {
	srv_info_t info;
	info.addr = hostname;
	info.port = 3306;
	info.kind = "AWS locality selection test";
	srv_opts_t options;
	options.weigth = weight;
	options.max_conns = 100;
	options.use_ssl = 1;

	MyHGM->wrlock();
	const int result = MyHGM->create_new_server_in_hg(kHostgroup, info, options);
	MyHGC* hostgroup = MyHGM->MyHGC_find(kHostgroup);
	MySrvC* server = nullptr;
	if (hostgroup != nullptr) {
		for (unsigned int i = 0; i < hostgroup->mysrvs->cnt(); ++i) {
			MySrvC* candidate = hostgroup->mysrvs->idx(i);
			if (strcmp(candidate->address, hostname) == 0) {
				server = candidate;
				break;
			}
		}
	}
	MyHGM->wrunlock();
	if (result != 0 || server == nullptr) {
		BAIL_OUT("failed to add locality server %s", hostname);
	}
	return server;
}

class SessionFixture {
public:
	explicit SessionFixture(MySQL_Thread& worker) {
		session_owner = std::make_unique<MySQL_Session>();
		session_owner->thread = &worker;
		session_owner->connections_handler = true;

		frontend_stream_owner.reset(new MySQL_Data_Stream());
		frontend_stream_owner->init(MYDS_FRONTEND, session_owner.get(), -1);
		frontend_stream = frontend_stream_owner.get();

		frontend_owner.reset(new MySQL_Connection());
		frontend_stream_owner->attach_connection(frontend_owner.get());
		frontend_stream_owner->myprot.init(&frontend_stream, frontend_owner->userinfo, session_owner.get());
		session_owner->client_myds = frontend_stream_owner.get();
		session = session_owner.get();
		frontend = frontend_owner.get();

		std::string session_user{kUser};
		std::string session_password{"password"};
		std::string session_schema{kSchema};
		frontend_owner->userinfo->set(
			session_user.data(), session_password.data(),
			session_schema.data(), nullptr);
		frontend_owner->set_backend_auth_type(MySQLBackendAuthType::PASSWORD);
	}

	MySQL_Session* session{nullptr};
	MySQL_Data_Stream* frontend_stream{nullptr};
	MySQL_Connection* frontend{nullptr};

private:
	std::unique_ptr<MySQL_Session> session_owner;
	std::unique_ptr<MySQL_Data_Stream, NoDeleteMySQLDataStream> frontend_stream_owner;
	std::unique_ptr<MySQL_Connection, NoDeleteMySQLConnection> frontend_owner;
};

MySQL_Connection* make_connection(MySrvC* server, int fd) {
	auto connection = std::make_unique<MySQL_Connection>();
	connection->mysql = mysql_init(nullptr);
	if (connection->mysql == nullptr) BAIL_OUT("mysql_init failed");
	connection->ret_mysql = connection->mysql;
	connection->mysql->charset = mariadb_get_charset_by_name("utf8mb4");
	connection->parent = server;

	std::string connection_user{kUser};
	std::string connection_password{"password"};
	std::string connection_schema{kSchema};
	connection->userinfo->set(
		connection_user.data(), connection_password.data(),
		connection_schema.data(), nullptr);
	connection->set_backend_auth_type(MySQLBackendAuthType::PASSWORD);
	connection->healthy = true;
	connection->reusable = true;
	connection->send_quit = false;
	connection->fd = fd;
	connection->async_state_machine = ASYNC_IDLE;
	server->ConnectionsUsed->add(connection.get());
	return connection.release();
}

} // namespace

int main() {
	plan(30);
	ok(aws_locality_saturating_add(
		std::numeric_limits<uint64_t>::max() - 2, 5) ==
		std::numeric_limits<uint64_t>::max(),
		"locality weight sums saturate instead of overflowing");
	const uint64_t lottery_weights[] = {40, 40, 30};
	ok(aws_locality_weighted_index(lottery_weights, 3, 0) == 0,
		"locality lottery selects the first candidate at its lower boundary");
	ok(aws_locality_weighted_index(lottery_weights, 3, 39) == 0,
		"locality lottery selects the first candidate at its upper boundary");
	ok(aws_locality_weighted_index(lottery_weights, 3, 40) == 1,
		"locality lottery selects the second candidate at its lower boundary");
	ok(aws_locality_weighted_index(lottery_weights, 3, 79) == 1,
		"locality lottery selects the second candidate at its upper boundary");
	ok(aws_locality_weighted_index(lottery_weights, 3, 80) == 2,
		"locality lottery selects the final candidate at its lower boundary");
	const uint64_t zero_weights[] = {0, 0};
	ok(aws_locality_weighted_index(zero_weights, 2, 17) == 2,
		"shared locality lottery rejects an all-zero candidate set");
	ok(test_init_minimal() == 0 && test_init_auth() == 0 && test_init_query_processor() == 0 &&
		test_init_hostgroups() == 0,
		"minimal worker and Hostgroup Manager fixtures initialize");
	GloMyLogger = new MySQL_Logger();

	auto provider_state = std::make_shared<ProviderState>();
	ok(install_global_aws_metadata_provider(
		new FakeProvider(provider_state), destroy_provider, nullptr),
		"fake metadata provider installs through the production lease registry");

	MySrvC* local = add_server(kLocal, 10);
	MySrvC* regional = add_server(kRegional, 20);
	MySrvC* remote = add_server(kRemote, 30);
	MyHGC* hostgroup = MyHGM->MyHGC_find(kHostgroup);
	init_myhgc_hostgroup_settings(
		R"({"aws":{"locality_awareness":{"same_region_multiplier":2.0,"same_az_multiplier":4.0}}})",
		hostgroup);
	MyHGM->refresh_aws_locality_configuration();
	MyHGM->set_aws_locality_awareness_enabled(true);
	ok(wait_for_requests(provider_state, 3),
		"selection fixture requests local identity and both backend Regions");

	AwsMetadataResult local_result;
	local_result.status = AwsMetadataStatus::ok;
	local_result.local = {"us-east-1", "us-east-1a", "111122223333"};
	ok(complete(provider_state, AwsMetadataRequestKind::local_location, "",
		std::move(local_result)), "local identity completion is accepted");

	AwsMetadataResult east;
	east.status = AwsMetadataStatus::ok;
	east.endpoints.push_back({kLocal, 3306, AwsEndpointType::instance,
		"us-east-1", "us-east-1a", "111122223333"});
	east.endpoints.push_back({kRegional, 3306, AwsEndpointType::cluster,
		"us-east-1", "us-east-1a", "111122223333"});
	ok(complete(provider_state, AwsMetadataRequestKind::rds_region, "us-east-1",
		std::move(east)), "same-Region endpoint completion is accepted");

	AwsMetadataResult west;
	west.status = AwsMetadataStatus::ok;
	west.endpoints.push_back({kRemote, 3306, AwsEndpointType::instance,
		"eu-west-1", "eu-west-1a", "111122223333"});
	ok(complete(provider_state, AwsMetadataRequestKind::rds_region, "eu-west-1",
		std::move(west)), "remote endpoint completion is accepted");

	ok(wait_until([&] {
		auto snapshot = MyHGM->aws_locality_manager()->snapshot();
		const auto* entry = snapshot->find(kHostgroup, kRemote, 3306);
		return entry != nullptr && entry->status == AwsLocalityMetadataStatus::fresh;
	}), "fresh immutable selection snapshot is published");

	auto snapshot = MyHGM->aws_locality_manager()->snapshot();
	ok(snapshot->effective_weight(kHostgroup, kLocal, 3306, 10) == 40 &&
		snapshot->effective_weight(kHostgroup, kRegional, 3306, 20) == 40 &&
		snapshot->effective_weight(kHostgroup, kRemote, 3306, 30) == 30,
		"literal same-AZ, same-Region, and remote weights evaluate to 40/40/30");
	const auto* regional_entry = snapshot->find(kHostgroup, kRegional, 3306);
	ok(regional_entry != nullptr &&
		regional_entry->locality == AwsLocalityClass::same_region &&
		regional_entry->multiplier == 2.0,
		"cluster endpoints receive Region bias only, even when their reported AZ matches");

	GloMTH->set_variable("aws_locality_awareness", "true");
	GloMTH->num_threads = 1;
	{
	MySQL_Thread worker;
	if (!worker.init()) BAIL_OUT("worker init failed");
	worker.curtime = 10000000;
	SessionFixture session(worker);

	int global_counts[3] = {0, 0, 0};
	for (int i = 0; i < 12000; ++i) {
		MySrvC* selected = hostgroup->get_random_MySrvC(nullptr, 0, -1, session.session);
		if (selected == local) ++global_counts[0];
		else if (selected == regional) ++global_counts[1];
		else if (selected == remote) ++global_counts[2];
	}
	const double local_share = static_cast<double>(global_counts[0]) / 12000.0;
	const double regional_share = static_cast<double>(global_counts[1]) / 12000.0;
	const double remote_share = static_cast<double>(global_counts[2]) / 12000.0;
	ok(local_share > 0.31 && local_share < 0.42 &&
		regional_share > 0.31 && regional_share < 0.42 &&
		remote_share > 0.20 && remote_share < 0.34,
		"global server lottery follows effective 40:40:30 weights (%.3f/%.3f/%.3f)",
		local_share, regional_share, remote_share);
	ok(local->weight == 10 && regional->weight == 20 && remote->weight == 30,
		"global locality selection never mutates configured server weights");
	local->weight = 0;
	regional->weight = 0;
	remote->weight = 0;
	ok(hostgroup->get_random_MySrvC(nullptr, 0, -1, session.session) != nullptr,
		"global selection retains an eligible fallback when all configured weights are zero");
	local->weight = 10;
	regional->weight = 20;
	remote->weight = 30;

	MySQL_Connection* local_connection = make_connection(local, 100);
	std::vector<MySQL_Connection*> remote_connections;
	for (int i = 0; i < 5; ++i) {
		remote_connections.push_back(make_connection(remote, 200 + i));
	}
	for (int i = 5; i < 33; ++i) {
		remote_connections.push_back(make_connection(remote, 200 + i));
	}
	worker.push_MyConn_local(local_connection);
	for (auto* connection : remote_connections) worker.push_MyConn_local(connection);

	hot_path_allocations = 0;
	track_hot_path_allocations = true;
	MySQL_Connection* allocation_probe = worker.get_MyConn_local(
		kHostgroup, session.session, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	track_hot_path_allocations = false;
	ok(allocation_probe != nullptr && hot_path_allocations == 0,
		"locality selection performs no heap allocation with more than 32 cached connections");
	if (allocation_probe != nullptr) worker.push_MyConn_local(allocation_probe);

	int local_parent = 0;
	int remote_parent = 0;
	for (int i = 0; i < 6000; ++i) {
		MySQL_Connection* selected = worker.get_MyConn_local(
			kHostgroup, session.session, nullptr, 0, -1,
			MySQLBackendAuthType::PASSWORD);
		if (selected == nullptr) BAIL_OUT("local selection returned no candidate");
		if (selected->parent == local) ++local_parent;
		else if (selected->parent == remote) ++remote_parent;
		worker.push_MyConn_local(selected);
	}
	const double local_parent_share = static_cast<double>(local_parent) / 6000.0;
	ok(local_parent_share > 0.53 && local_parent_share < 0.62 &&
		local_parent + remote_parent == 6000,
		"local cache chooses 40:30 weighted parents, not the 1:5 connection count (%.3f local)",
		local_parent_share);
	local->weight = 0;
	remote->weight = 0;
	MySQL_Connection* zero_weight_selected = worker.get_MyConn_local(
		kHostgroup, session.session, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(zero_weight_selected != nullptr,
		"local cache reuses an eligible connection when all parent weights are zero");
	if (zero_weight_selected != nullptr) worker.push_MyConn_local(zero_weight_selected);
	local->weight = 10;
	remote->weight = 30;

	std::string local_host{kLocal};
	GTID_Server_Data local_gtid(nullptr, local_host.data(), 0, 3306);
	local_gtid.add_gtid_from_ok("aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:42");
	MyHGM->gtid_map.emplace(std::string(kLocal) + ":3306", &local_gtid);
	local->aws_aurora_current_lag_us = 5000;
	char gtid_uuid[] = "aaaaaaaa000011112222aaaaaaaaaaaa";
	MySQL_Connection* gtid_selected = worker.get_MyConn_local(
		kHostgroup, session.session, gtid_uuid, 42, 1,
		MySQLBackendAuthType::PASSWORD);
	ok(gtid_selected != nullptr && gtid_selected->parent == local,
		"GTID-qualified local reuse preserves the legacy max-lag exemption");
	if (gtid_selected != nullptr) worker.push_MyConn_local(gtid_selected);
	local->aws_aurora_current_lag_us = 0;
	MyHGM->gtid_map.erase(std::string(kLocal) + ":3306");

	remote->aws_aurora_current_lag_us = 5000;
	MySQL_Connection* selected = worker.get_MyConn_local(
		kHostgroup, session.session, nullptr, 0, 1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->parent == local,
		"replication-lag eligibility excludes a remote parent before locality weighting");
	worker.push_MyConn_local(selected);
	remote->aws_aurora_current_lag_us = 0;

	MySQL_Connection* incompatible = make_connection(regional, 300);
	std::string incompatible_user{"other_user"};
	std::string incompatible_password{"password"};
	std::string incompatible_schema{kSchema};
	incompatible->userinfo->set(
		incompatible_user.data(), incompatible_password.data(),
		incompatible_schema.data(), nullptr);
	worker.push_MyConn_local(incompatible);
	selected = worker.get_MyConn_local(
		kHostgroup, session.session, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->parent != regional,
		"authentication incompatibility excludes a parent before locality weighting");
	worker.push_MyConn_local(selected);

	local_connection->healthy = false;
	selected = worker.get_MyConn_local(
		kHostgroup, session.session, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->parent == remote,
		"health eligibility excludes a preferred local connection before locality weighting");
	worker.push_MyConn_local(selected);
	local_connection->healthy = true;

	local->session_track_backoff_until.store(worker.curtime + 1);
	mysql_thread___session_track_variables = session_track_variables::ENFORCED;
	selected = worker.get_MyConn_local(
		kHostgroup, session.session, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->parent == remote,
		"session-capability backoff excludes a local parent before locality weighting");
	worker.push_MyConn_local(selected);
	mysql_thread___session_track_variables = session_track_variables::DISABLED;
	local->session_track_backoff_until.store(0);

	local_connection->options.client_flag |= CLIENT_FOUND_ROWS;
	selected = worker.get_MyConn_local(
		kHostgroup, session.session, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->parent == remote,
		"session option incompatibility is enforced before locality weighting");
	worker.push_MyConn_local(selected);
	local_connection->options.client_flag &= ~CLIENT_FOUND_ROWS;
	}
	MyHGM->set_aws_locality_awareness_enabled(false);
	shutdown_global_aws_metadata_provider();
	MyHGM->set_aws_locality_awareness_enabled(true);
	ok(wait_until([&] {
		const auto unavailable = MyHGM->aws_locality_manager()->snapshot();
		const auto* entry = unavailable->find(kHostgroup, kLocal, 3306);
		return entry != nullptr &&
			entry->status == AwsLocalityMetadataStatus::error &&
			entry->failure_category == "provider_unavailable" &&
			unavailable->effective_weight(kHostgroup, kLocal, 3306, 10) == 10;
	}), "missing provider publishes fixed provider_unavailable with neutral weight");
	{
		MySQL_Thread neutral_worker;
		if (!neutral_worker.init()) BAIL_OUT("neutral worker init failed");
		SessionFixture neutral_session(neutral_worker);
		int neutral_counts[3] = {0, 0, 0};
		for (int i = 0; i < 12000; ++i) {
			MySrvC* selected = hostgroup->get_random_MySrvC(
				nullptr, 0, -1, neutral_session.session);
			if (selected == local) ++neutral_counts[0];
			else if (selected == regional) ++neutral_counts[1];
			else if (selected == remote) ++neutral_counts[2];
		}
		const double neutral_local_share =
			static_cast<double>(neutral_counts[0]) / 12000.0;
		const double neutral_regional_share =
			static_cast<double>(neutral_counts[1]) / 12000.0;
		const double neutral_remote_share =
			static_cast<double>(neutral_counts[2]) / 12000.0;
		ok(neutral_local_share > 0.13 && neutral_local_share < 0.20 &&
			neutral_regional_share > 0.29 && neutral_regional_share < 0.38 &&
			neutral_remote_share > 0.45 && neutral_remote_share < 0.55 &&
			local->weight == 10 && regional->weight == 20 && remote->weight == 30,
			"provider absence selects by unchanged configured 10:20:30 weights (%.3f/%.3f/%.3f)",
			neutral_local_share, neutral_regional_share, neutral_remote_share);
	}
	MyHGM->set_aws_locality_awareness_enabled(false);
	test_cleanup_hostgroups();
	std::unique_ptr<MySQL_Logger> logger_guard(GloMyLogger);
	GloMyLogger = nullptr;
	test_cleanup_query_processor();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
