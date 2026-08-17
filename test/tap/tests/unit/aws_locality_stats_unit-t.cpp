#include "Aws_Locality_Manager.h"
#include "MySQL_HostGroups_Manager.h"
#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"
#include "tap.h"
#include "test_globals.h"

#include <cstdlib>
#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

extern MySQL_HostGroups_Manager* MyHGM;

namespace {

using SQLite3ResultPtr = std::unique_ptr<SQLite3_result>;
using WriteErrorPtr = std::unique_ptr<char, decltype(&std::free)>;

constexpr const char* kLocalityStatsProjectionFixture =
	"CREATE TABLE stats_mysql_aws_locality ("
	"hostgroup_id INT NOT NULL, hostname VARCHAR NOT NULL, port INT NOT NULL, "
	"endpoint_type VARCHAR NOT NULL, configured_weight INT NOT NULL, "
	"effective_weight INT NOT NULL, local_region VARCHAR NOT NULL, "
	"local_az VARCHAR NOT NULL, backend_region VARCHAR NOT NULL, "
	"backend_az VARCHAR NOT NULL, account_match VARCHAR NOT NULL, "
	"locality VARCHAR NOT NULL, active_multiplier REAL NOT NULL, "
	"metadata_status VARCHAR NOT NULL, last_success_timestamp INT NOT NULL, "
	"last_attempt_timestamp INT NOT NULL, last_error_category VARCHAR NOT NULL, "
	"PRIMARY KEY(hostgroup_id, hostname, port))";

class CountingProvider final : public AwsMetadataProvider {
public:
	AwsMetadataRequestHandle request(
		const AwsMetadataRequest&,
		std::weak_ptr<AwsMetadataCompletionSink>) override {
		++requests;
		return {requests.load()};
	}
	void cancel(AwsMetadataRequestHandle) override {
		// No cancellation side effects are required for this provider fake.
	}
	void shutdown() override {
		// No shutdown side effects are required for this provider fake.
	}
	std::atomic<uint64_t> requests {0};
};

std::unique_ptr<CountingProvider> counting_provider;
CountingProvider* counting_provider_raw = nullptr;

void destroy_counting_provider(AwsMetadataProvider* provider) {
	if (provider != nullptr) {
		counting_provider.reset();
	}
	counting_provider_raw = nullptr;
}

AwsLocalityHostgroupConfig disabled_hostgroup(
	uint32_t hostgroup_id, const std::string& hostname, int64_t weight) {
	AwsLocalityHostgroupConfig config;
	config.hostgroup_id = hostgroup_id;
	config.policy.valid = true;
	AwsEndpointCandidate endpoint;
	endpoint.recognized = true;
	endpoint.hostgroup_id = hostgroup_id;
	endpoint.hostname = hostname;
	endpoint.port = 3306;
	endpoint.region = "us-east-1";
	endpoint.partition = "aws";
	config.backends.emplace_back(std::move(endpoint), weight);
	return config;
}

AwsLocalitySnapshotEntry diagnostic_row(
	uint32_t hostgroup_id,
	AwsLocalityMetadataStatus status,
	double multiplier,
	int64_t weight) {
	AwsLocalitySnapshotEntry row;
	row.hostgroup_id = hostgroup_id;
	row.hostname = hostgroup_id == 6
		? "db'quoted.abcdefghijkl.us-east-1.rds.amazonaws.com"
		: "db-" + std::to_string(hostgroup_id) +
			".abcdefghijkl.us-east-1.rds.amazonaws.com";
	row.port = 3306;
	row.endpoint_type = hostgroup_id == 1 ? AwsEndpointType::unknown
		: hostgroup_id == 2 ? AwsEndpointType::instance
		: hostgroup_id == 3 ? AwsEndpointType::cluster
		: hostgroup_id == 4 ? AwsEndpointType::reader
		: AwsEndpointType::custom;
	row.configured_weight = weight;
	row.local = {"us-east-1", "us-east-1a", "111122223333"};
	row.backend.region = hostgroup_id == 4 ? "eu-west-1" : "us-east-1";
	row.backend.availability_zone = hostgroup_id == 2 ? "us-east-1a" : "";
	row.backend.account_id = hostgroup_id == 1 ? ""
		: hostgroup_id == 3 ? "444455556666" : "111122223333";
	row.locality = hostgroup_id == 2 ? AwsLocalityClass::same_az
		: hostgroup_id == 3 ? AwsLocalityClass::same_region
		: hostgroup_id == 4 ? AwsLocalityClass::remote
		: AwsLocalityClass::unknown;
	row.multiplier = multiplier;
	row.status = status;
	row.last_success_timestamp = 1700000000 + hostgroup_id;
	row.last_attempt_timestamp = 1700000100 + hostgroup_id;
	row.failure_category = status == AwsLocalityMetadataStatus::stale
		? "throttled" : status == AwsLocalityMetadataStatus::error
			? "access_denied" : "";
	return row;
}

} // namespace

int main() {
	plan(22);
	if (test_globals_init() != 0) {
		BAIL_OUT("test global initialization failed");
	}

	SQLite3DB statsdb;
	statsdb.open(const_cast<char*>(":memory:"),
		SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	ok(statsdb.return_one_int(
		"SELECT count(*) FROM sqlite_master WHERE name='stats_mysql_aws_locality'") == 0,
		"public core does not register an AWS locality stats table");

	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string error;
	ok(proxysql_load_configured_plugins(manager, {}, error) && manager == nullptr,
		"provider-neutral plugin services expose no always-present locality schema");
	if (!error.empty()) diag("plugin error: %s", error.c_str());

	ok(statsdb.execute(kLocalityStatsProjectionFixture),
		"test-owned schema fixture accepts the public projection callback");
	ok(statsdb.return_one_int(
		"SELECT count(*) FROM pragma_table_info('stats_mysql_aws_locality')") == 17,
		"projection fixture has the external-provider contract's 17 columns");
	ok(statsdb.return_one_int(
		"SELECT count(*) FROM pragma_table_info('stats_mysql_aws_locality') "
		"WHERE name IN ('hostgroup_id','hostname','port','endpoint_type',"
		"'configured_weight','effective_weight','local_region','local_az',"
		"'backend_region','backend_az','account_match','locality',"
		"'active_multiplier','metadata_status','last_success_timestamp',"
		"'last_attempt_timestamp','last_error_category')") == 17,
		"projection callback targets the documented external schema columns");

	std::vector<AwsLocalitySnapshotEntry> rows;
	rows.push_back(diagnostic_row(1, AwsLocalityMetadataStatus::pending, 4.0, 10));
	rows.push_back(diagnostic_row(2, AwsLocalityMetadataStatus::fresh, 2.5, 11));
	rows.push_back(diagnostic_row(3, AwsLocalityMetadataStatus::stale, 4.0, 12));
	rows.push_back(diagnostic_row(4, AwsLocalityMetadataStatus::expired, 5.0, 13));
	rows.push_back(diagnostic_row(5, AwsLocalityMetadataStatus::error, 6.0, 14));
	rows.push_back(diagnostic_row(6, AwsLocalityMetadataStatus::disabled, 7.0, 15));
	ok(MySQL_HostGroups_Manager::project_aws_locality_stats(&statsdb, rows),
		"one retained diagnostics snapshot projects transactionally");
	ok(statsdb.return_one_int("SELECT count(*) FROM stats_mysql_aws_locality") == 6,
		"projection emits one row per configured backend");
	ok(statsdb.return_one_int(
		"SELECT count(DISTINCT metadata_status) FROM stats_mysql_aws_locality") == 6,
		"pending, fresh, stale, expired, error, and disabled are explicit");
	ok(statsdb.return_one_int(
		"SELECT count(*) FROM stats_mysql_aws_locality WHERE "
		"(hostgroup_id=2 AND effective_weight=27 AND active_multiplier=2.5) OR "
		"(hostgroup_id=3 AND effective_weight=48 AND active_multiplier=4.0)") == 2,
		"fresh/stale rows expose integer-cast weighted multipliers");
	ok(statsdb.return_one_int(
		"SELECT count(*) FROM stats_mysql_aws_locality WHERE hostgroup_id IN (1,4,5,6) "
		"AND effective_weight=configured_weight AND active_multiplier=1.0") == 4,
		"pending/expired/error/disabled rows force neutral effective weights");
	ok(statsdb.return_one_int(
		"SELECT count(*) FROM stats_mysql_aws_locality WHERE "
		"(hostgroup_id=2 AND endpoint_type='instance' AND locality='same_az') OR "
		"(hostgroup_id=3 AND endpoint_type='cluster' AND locality='same_region') OR "
		"(hostgroup_id=4 AND endpoint_type='reader' AND locality='remote')") == 3,
		"endpoint and locality classifications use stable strings");
	ok(statsdb.return_one_int(
		"SELECT count(*) FROM stats_mysql_aws_locality WHERE "
		"(hostgroup_id=1 AND account_match='unknown') OR "
		"(hostgroup_id=2 AND account_match='same') OR "
		"(hostgroup_id=3 AND account_match='different')") == 3,
		"account comparison exposes unknown/same/different without identifiers");
	ok(statsdb.return_one_int(
		"SELECT count(*) FROM stats_mysql_aws_locality WHERE hostgroup_id=3 "
		"AND last_success_timestamp=1700000003 AND last_attempt_timestamp=1700000103 "
		"AND last_error_category='throttled'") == 1,
		"timestamps and fixed failure category survive projection");
	ok(statsdb.return_one_int(
		"SELECT count(*) FROM stats_mysql_aws_locality WHERE hostname="
		"'db''quoted.abcdefghijkl.us-east-1.rds.amazonaws.com'") == 1,
		"projection safely quotes endpoint text");

	std::vector<AwsLocalitySnapshotEntry> concurrent_rows_a;
	std::vector<AwsLocalitySnapshotEntry> concurrent_rows_b;
	for (uint32_t index = 0; index < 200; ++index) {
		concurrent_rows_a.push_back(diagnostic_row(1000 + index,
			AwsLocalityMetadataStatus::fresh, 2.0, 10));
		concurrent_rows_b.push_back(diagnostic_row(2000 + index,
			AwsLocalityMetadataStatus::stale, 3.0, 10));
	}
	std::atomic<bool> start_concurrent_projection { false };
	std::atomic<unsigned int> successful_projections { 0 };
	auto project_repeatedly = [&start_concurrent_projection, &successful_projections, &statsdb](
		const std::vector<AwsLocalitySnapshotEntry>& projection) {
		while (!start_concurrent_projection.load()) {
			std::this_thread::yield();
		}
		for (unsigned int iteration = 0; iteration < 10; ++iteration) {
			if (MySQL_HostGroups_Manager::project_aws_locality_stats(&statsdb, projection)) {
				successful_projections.fetch_add(1);
			}
		}
	};
	std::thread projection_a(project_repeatedly, std::cref(concurrent_rows_a));
	std::thread projection_b(project_repeatedly, std::cref(concurrent_rows_b));
	start_concurrent_projection.store(true);
	projection_a.join();
	projection_b.join();
	ok(successful_projections.load() == 20 &&
		statsdb.return_one_int("SELECT count(*) FROM stats_mysql_aws_locality") == 200,
		"concurrent runtime-view refreshes serialize complete replacement transactions");

	GloVars.prometheus_registry = std::make_shared<prometheus::Registry>();
	{
		MySQL_HostGroups_Manager hostgroups;
		MyHGM = &hostgroups;
		counting_provider = std::make_unique<CountingProvider>();
		counting_provider_raw = counting_provider.get();
		ok(install_global_aws_metadata_provider(
			counting_provider.get(), &destroy_counting_provider, nullptr),
			"network-request counter installs through the production registry");

		hostgroups.aws_locality_manager()->configure({disabled_hostgroup(
			101, "first.abcdefghijkl.us-east-1.rds.amazonaws.com", 7)});
		hostgroups.refresh_aws_locality_stats(&statsdb);
		ok(statsdb.return_one_int(
			"SELECT count(*) FROM stats_mysql_aws_locality WHERE hostgroup_id=101 "
			"AND metadata_status='disabled' AND configured_weight=7 "
			"AND effective_weight=7") == 1,
			"public callback projects the MySQL manager's current snapshot");
		ok(counting_provider_raw->requests.load() == 0,
			"query-time refresh issues no metadata-provider request");

		hostgroups.aws_locality_manager()->configure({disabled_hostgroup(
			202, "second.abcdefghijkl.us-east-1.rds.amazonaws.com", 9)});
		hostgroups.refresh_aws_locality_stats(&statsdb);
		ok(statsdb.return_one_int("SELECT count(*) FROM stats_mysql_aws_locality") == 1 &&
			statsdb.return_one_int(
				"SELECT count(*) FROM stats_mysql_aws_locality WHERE hostgroup_id=202") == 1,
			"generation swap replaces the prior projection without mixed rows");

		hostgroups.aws_locality_manager()->configure({});
		hostgroups.refresh_aws_locality_stats(&statsdb);
		ok(statsdb.return_one_int("SELECT count(*) FROM stats_mysql_aws_locality") == 0,
			"no valid locality policy produces zero rows");
		ok(counting_provider_raw->requests.load() == 0,
			"repeated generation queries remain network-free");
		MyHGM = nullptr;
	}
	shutdown_global_aws_metadata_provider();
	GloVars.prometheus_registry.reset();

	statsdb.execute("PRAGMA query_only = ON");
	WriteErrorPtr write_error{nullptr, &std::free};
	char* write_error_raw = nullptr;
	SQLite3_result* write_result = statsdb.execute_statement(
		"INSERT INTO stats_mysql_aws_locality "
		"(hostgroup_id,hostname,port,endpoint_type,configured_weight,effective_weight,"
		"local_region,local_az,backend_region,backend_az,account_match,locality,"
		"active_multiplier,metadata_status,last_success_timestamp,last_attempt_timestamp,"
		"last_error_category) VALUES (1,'x',3306,'unknown',1,1,'','','','',"
		"'unknown','unknown',1.0,'disabled',0,0,'')", &write_error_raw);
	ok(write_error_raw != nullptr,
		"stats listener query-only mode rejects writes to the projection");
	write_error.reset(write_error_raw);
	SQLite3ResultPtr write_result_ptr{write_result};
	statsdb.execute("PRAGMA query_only = OFF");

	proxysql_stop_configured_plugins(manager, error);
	test_globals_cleanup();
	return exit_status();
}
