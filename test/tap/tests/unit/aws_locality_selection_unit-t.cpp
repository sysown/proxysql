#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "Aws_Locality_Manager.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Logger.hpp"
#include "MySQL_Thread.h"

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

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

	void cancel(AwsMetadataRequestHandle) override {}
	void shutdown() override {}

private:
	std::shared_ptr<ProviderState> state_;
};

void destroy_provider(AwsMetadataProvider* provider) {
	delete provider;
}

bool wait_for_requests(const std::shared_ptr<ProviderState>& state, size_t count) {
	std::unique_lock<std::mutex> lock(state->mutex);
	return state->cv.wait_for(lock, 2s, [&] { return state->pending.size() >= count; });
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
		session = new MySQL_Session();
		session->thread = &worker;
		session->connections_handler = true;
		frontend_stream = new MySQL_Data_Stream();
		frontend_stream->init(MYDS_FRONTEND, session, -1);
		frontend = new MySQL_Connection();
		frontend_stream->attach_connection(frontend);
		frontend_stream->myprot.init(&frontend_stream, frontend->userinfo, session);
		session->client_myds = frontend_stream;
		frontend->userinfo->set(
			const_cast<char*>(kUser), const_cast<char*>("password"),
			const_cast<char*>(kSchema), nullptr);
		frontend->set_backend_auth_type(MySQLBackendAuthType::PASSWORD);
	}

	~SessionFixture() { delete session; }

	MySQL_Session* session { nullptr };
	MySQL_Data_Stream* frontend_stream { nullptr };
	MySQL_Connection* frontend { nullptr };
};

MySQL_Connection* make_connection(MySrvC* server, int fd) {
	MySQL_Connection* connection = new MySQL_Connection();
	connection->mysql = mysql_init(nullptr);
	if (connection->mysql == nullptr) BAIL_OUT("mysql_init failed");
	connection->ret_mysql = connection->mysql;
	connection->mysql->charset = mariadb_get_charset_by_name("utf8mb4");
	connection->parent = server;
	connection->userinfo->set(
		const_cast<char*>(kUser), const_cast<char*>("password"),
		const_cast<char*>(kSchema), nullptr);
	connection->set_backend_auth_type(MySQLBackendAuthType::PASSWORD);
	connection->healthy = true;
	connection->reusable = true;
	connection->send_quit = false;
	connection->fd = fd;
	connection->async_state_machine = ASYNC_IDLE;
	server->ConnectionsUsed->add(connection);
	return connection;
}

} // namespace

int main() {
	plan(20);
	ok(aws_locality_saturating_add(
		std::numeric_limits<uint64_t>::max() - 2, 5) ==
		std::numeric_limits<uint64_t>::max(),
		"locality weight sums saturate instead of overflowing");
	const uint64_t lottery_weights[] = {40, 40, 30};
	ok(aws_locality_weighted_index(lottery_weights, 3, 0) == 0 &&
		aws_locality_weighted_index(lottery_weights, 3, 39) == 0 &&
		aws_locality_weighted_index(lottery_weights, 3, 40) == 1 &&
		aws_locality_weighted_index(lottery_weights, 3, 79) == 1 &&
		aws_locality_weighted_index(lottery_weights, 3, 80) == 2,
		"shared locality lottery uses exact cumulative weight boundaries");
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

	MySQL_Connection* local_connection = make_connection(local, 100);
	std::vector<MySQL_Connection*> remote_connections;
	for (int i = 0; i < 5; ++i) {
		remote_connections.push_back(make_connection(remote, 200 + i));
	}
	worker.push_MyConn_local(local_connection);
	for (auto* connection : remote_connections) worker.push_MyConn_local(connection);

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

	remote->aws_aurora_current_lag_us = 5000;
	MySQL_Connection* selected = worker.get_MyConn_local(
		kHostgroup, session.session, nullptr, 0, 1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->parent == local,
		"replication-lag eligibility excludes a remote parent before locality weighting");
	worker.push_MyConn_local(selected);
	remote->aws_aurora_current_lag_us = 0;

	MySQL_Connection* incompatible = make_connection(regional, 300);
	incompatible->userinfo->set(
		const_cast<char*>("other_user"), const_cast<char*>("password"),
		const_cast<char*>(kSchema), nullptr);
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

	local->session_track_backoff_until.store(worker.curtime + 1, std::memory_order_relaxed);
	mysql_thread___session_track_variables = session_track_variables::ENFORCED;
	selected = worker.get_MyConn_local(
		kHostgroup, session.session, nullptr, 0, -1,
		MySQLBackendAuthType::PASSWORD);
	ok(selected != nullptr && selected->parent == remote,
		"session-capability backoff excludes a local parent before locality weighting");
	worker.push_MyConn_local(selected);
	mysql_thread___session_track_variables = session_track_variables::DISABLED;
	local->session_track_backoff_until.store(0, std::memory_order_relaxed);

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
	test_cleanup_hostgroups();
	shutdown_global_aws_metadata_provider();
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_query_processor();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
