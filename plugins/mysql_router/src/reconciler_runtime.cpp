#include "mysql_router_reconciler.h"

#include "mysql_router_bootstrap.h"
#include "mysql_router_config.h"
#include "mysql_router_compiler.h"
#include "mysql_router_metadata.h"
#include "mysql_router_plugin.h"
#include "prometheus/counter.h"
#include "prometheus/gauge.h"
#include "sqlite3db.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>

namespace {

std::string quote(std::string_view value) {
	std::string result("'");
	result.reserve(value.size() + 2);
	for (char character : value) {
		if (character == '\'') result.push_back('\'');
		result.push_back(character);
	}
	result.push_back('\'');
	return result;
}

std::unique_ptr<SQLite3_result> query(SQLite3DB& db, const std::string& sql) {
	char* error = nullptr;
	std::unique_ptr<SQLite3_result> result(db.execute_statement(sql.c_str(), &error));
	if (error != nullptr) {
		std::string message(error);
		free(error);
		throw std::runtime_error(message);
	}
	if (!result) throw std::runtime_error("Router local query returned no result");
	return result;
}

uint64_t unsigned_field(const char* value, const char* name) {
	if (value == nullptr || *value == '\0') throw std::runtime_error(std::string(name) + " is NULL");
	char* end = nullptr;
	const unsigned long long parsed = std::strtoull(value, &end, 10);
	if (end == nullptr || *end != '\0') throw std::runtime_error(std::string(name) + " is invalid");
	return static_cast<uint64_t>(parsed);
}

std::string safe_message(std::string_view message) {
	std::string result(message.substr(0, 512));
	for (const std::string secret : {"$A$", "IDENTIFIED BY", "password="}) {
		size_t offset = 0;
		while ((offset = result.find(secret, offset)) != std::string::npos) {
			const size_t end = result.find_first_of(" ,;\n", offset + secret.size());
			result.replace(offset, end == std::string::npos ? std::string::npos : end - offset,
				"(redacted)");
			offset += 10;
		}
	}
	return result;
}

std::string topology_fingerprint(const DesiredTopology& desired,
	const EffectiveTopology& effective) {
	std::ostringstream output;
	output << desired.topology_uuid << '|' << desired.group_name << '|'
		<< static_cast<int>(desired.options.read_only_targets) << '|'
		<< static_cast<int>(desired.options.quorum_traffic) << '|'
		<< desired.options.routing_guideline_unsupported << '|';
	if (desired.options.stats_updates_frequency) output << *desired.options.stats_updates_frequency;
	output << '|';
	for (const auto& instance : desired.instances) {
		output << instance.server_uuid << '@' << instance.classic.host << ':'
			<< instance.classic.port << ':' << static_cast<int>(instance.kind) << ';';
	}
	output << "|w=" << (effective.writer ? *effective.writer : std::string());
	for (const auto& reader : effective.readers) output << "|r=" << reader;
	for (const auto& excluded : effective.excluded) output << "|x=" << excluded;
	return output.str();
}

const char* health_name(HealthState state) {
	switch (state) {
		case HealthState::online: return "online";
		case HealthState::recovering: return "recovering";
		case HealthState::offline: return "offline";
		case HealthState::unreachable: return "unreachable";
	}
	return "unreachable";
}

std::string metadata_version(const MetadataVersion& version) {
	return std::to_string(version.major) + "." + std::to_string(version.minor) + "." +
		std::to_string(version.patch);
}

int result_column(const SQLite3_result& result, std::string_view name) {
	for (size_t index = 0; index < result.column_definition.size(); ++index) {
		if (result.column_definition[index] && result.column_definition[index]->name &&
			name == result.column_definition[index]->name) return static_cast<int>(index);
	}
	throw std::runtime_error("Router snapshot is missing column " + std::string(name));
}

std::string server_identity(uint64_t hostgroup, std::string_view host, uint64_t port) {
	return std::to_string(hostgroup) + "\n" + std::string(host) + "\n" + std::to_string(port);
}

DesiredTopology load_cached_topology(SQLite3DB& db, std::string_view topology_uuid) {
	auto rows = query(db,
		"SELECT topology_uuid,topology_name,group_name,metadata_major,metadata_minor,metadata_patch,"
		"instance_uuid,label,endpoint_host,endpoint_port,instance_kind,attributes,read_only_targets,"
		"quorum_traffic,stats_updates_frequency,routing_guideline_unsupported "
		"FROM mysql_router_topology_cache WHERE topology_uuid=" +
		quote(topology_uuid) + " ORDER BY instance_uuid");
	DesiredTopology topology;
	for (auto* row : rows->rows) {
		if (topology.instances.empty()) {
			topology.topology_uuid = row->fields[0] ? row->fields[0] : "";
			topology.topology_name = row->fields[1] ? row->fields[1] : "";
			topology.group_name = row->fields[2] ? row->fields[2] : "";
			topology.metadata_version = {
				static_cast<int>(unsigned_field(row->fields[3], "metadata_major")),
				static_cast<int>(unsigned_field(row->fields[4], "metadata_minor")),
				static_cast<int>(unsigned_field(row->fields[5], "metadata_patch"))};
			topology.options.read_only_targets = static_cast<ReadOnlyTargets>(
				unsigned_field(row->fields[12], "read_only_targets"));
			topology.options.quorum_traffic = static_cast<QuorumTraffic>(
				unsigned_field(row->fields[13], "quorum_traffic"));
			if (row->fields[14] != nullptr) topology.options.stats_updates_frequency =
				unsigned_field(row->fields[14], "stats_updates_frequency");
			topology.options.routing_guideline_unsupported =
				unsigned_field(row->fields[15], "routing_guideline_unsupported") != 0;
		}
		DesiredInstance instance;
		instance.cluster_uuid = topology.topology_uuid;
		instance.server_uuid = row->fields[6] ? row->fields[6] : "";
		instance.label = row->fields[7] ? row->fields[7] : "";
		instance.classic.host = row->fields[8] ? row->fields[8] : "";
		instance.classic.port = static_cast<uint16_t>(unsigned_field(row->fields[9], "endpoint_port"));
		instance.kind = static_cast<InstanceKind>(unsigned_field(row->fields[10], "instance_kind"));
		instance.attributes = row->fields[11] ? row->fields[11] : "";
		topology.instances.push_back(std::move(instance));
	}
	return topology;
}

void persist_cached_topology(ProxySQL_PluginServices& services,
	const DesiredTopology& topology) {
	SQLite3DB* db = services.get_admindb ? services.get_admindb() : nullptr;
	if (db == nullptr || !db->execute("BEGIN IMMEDIATE")) {
		throw std::runtime_error("cannot begin Router topology-cache transaction");
	}
	bool ok = db->execute("DELETE FROM main.mysql_router_topology_cache") &&
		db->execute("DELETE FROM disk.mysql_router_topology_cache");
	for (const auto& instance : topology.instances) {
		const std::string frequency = topology.options.stats_updates_frequency
			? std::to_string(*topology.options.stats_updates_frequency) : "NULL";
		const std::string values = quote(instance.server_uuid) + "," + quote(topology.topology_uuid) +
			"," + quote(topology.topology_name) + "," + quote(topology.group_name) + "," +
			std::to_string(topology.metadata_version.major) + "," +
			std::to_string(topology.metadata_version.minor) + "," +
			std::to_string(topology.metadata_version.patch) + "," + quote(instance.label) + "," +
			quote(instance.classic.host) + "," + std::to_string(instance.classic.port) + "," +
			std::to_string(static_cast<int>(instance.kind)) + "," + quote(instance.attributes) + "," +
			std::to_string(static_cast<int>(topology.options.read_only_targets)) + "," +
			std::to_string(static_cast<int>(topology.options.quorum_traffic)) + "," + frequency;
		const std::string complete_values = values + "," +
			std::to_string(topology.options.routing_guideline_unsupported ? 1 : 0);
		for (const char* schema : {"main", "disk"}) {
			const std::string sql = "INSERT INTO " + std::string(schema) +
				".mysql_router_topology_cache(instance_uuid,topology_uuid,topology_name,group_name,"
				"metadata_major,metadata_minor,metadata_patch,label,endpoint_host,endpoint_port,"
				"instance_kind,attributes,read_only_targets,quorum_traffic,stats_updates_frequency,"
				"routing_guideline_unsupported) VALUES(" + complete_values + ")";
			ok = ok && db->execute(sql.c_str());
		}
	}
	if (!ok || !db->execute("COMMIT")) {
		db->execute("ROLLBACK");
		throw std::runtime_error("cannot persist complete Router topology cache");
	}
}

bool persist_generation(ProxySQL_PluginServices& services, const char* column,
	uint64_t generation) {
	if (std::string_view(column) != "topology_generation" &&
		std::string_view(column) != "user_generation") return false;
	SQLite3DB* db = services.get_admindb ? services.get_admindb() : nullptr;
	if (db == nullptr || !db->execute("BEGIN IMMEDIATE")) return false;
	const std::string assignment = std::string(column) + "=" + std::to_string(generation);
	const bool ok = db->execute(("UPDATE main.mysql_router_instance SET " + assignment +
		" WHERE singleton_id=1").c_str()) &&
		db->execute(("UPDATE disk.mysql_router_instance SET " + assignment +
		" WHERE singleton_id=1").c_str()) && db->execute("COMMIT");
	if (!ok) db->execute("ROLLBACK");
	return ok;
}

class RuntimeBackend final : public IReconcileBackend {
public:
	explicit RuntimeBackend(ProxySQL_PluginServices& services) : services_(services) {
		if (services_.get_configdb == nullptr) throw std::runtime_error("Router config DB service is unavailable");
		db_ = services_.get_configdb();
		if (db_ == nullptr) throw std::runtime_error("Router config DB is unavailable");
		auto schema = query(*db_,
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mysql_router_instance'");
		if (schema->rows.empty() || unsigned_field(schema->rows[0]->fields[0], "Router schema count") == 0) {
			throw std::out_of_range("Router schema is not materialized");
		}
		auto identity = query(*db_,
			"SELECT topology_uuid,router_id,router_name,router_address,metadata_user,metadata_host,"
			"metadata_port,topology_generation,user_generation FROM mysql_router_instance WHERE singleton_id=1");
		if (identity->rows.empty()) throw std::out_of_range("Router is not bootstrapped");
		if (identity->rows.size() != 1) throw std::runtime_error("duplicate Router identity");
		auto* row = identity->rows[0];
		topology_uuid_ = row->fields[0] ? row->fields[0] : "";
		router_id_ = unsigned_field(row->fields[1], "router_id");
		router_name_ = row->fields[2] ? row->fields[2] : "";
		router_address_ = row->fields[3] ? row->fields[3] : "";
		metadata_user_ = row->fields[4] ? row->fields[4] : "";
		endpoint_.username = metadata_user_;
		endpoint_.host = row->fields[5] ? row->fields[5] : "";
		endpoint_.port = static_cast<uint16_t>(unsigned_field(row->fields[6], "metadata_port"));
		topology_generation_ = unsigned_field(row->fields[7], "topology_generation");
		user_generation_ = unsigned_field(row->fields[8], "user_generation");
		if (topology_uuid_.empty() || metadata_user_.empty() || endpoint_.host.empty()) {
			throw std::runtime_error("persisted Router identity is incomplete");
		}
		std::string error;
		if (!config_store_.load(*db_, error)) throw std::runtime_error(error);
		config_ = config_store_.snapshot();
		listeners_ = {config_.bind_address, config_.rw_port, config_.ro_port,
			config_.rw_split_port, false, false};
		tls_.mode = config_.metadata_ssl_mode;
		current_topology_ = load_cached_topology(*db_, topology_uuid_);
		std::vector<uint8_t> password;
		if (services_.get_secret == nullptr || services_.get_secret("mysql_router",
			("metadata-" + topology_uuid_).c_str(), password) != ProxySQL_PluginSecretResult::ok) {
			throw std::runtime_error("Router metadata credential is unavailable");
		}
		password_ = SecureBytes(std::move(password));
		auto hostgroups = query(*db_,
			"SELECT role,hostgroup_id FROM mysql_router_hostgroups WHERE scope_uuid=" +
			quote(topology_uuid_) + " ORDER BY role");
		MysqlRouterContext& context = mysql_router_context();
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.topology_uuid = topology_uuid_;
		context.status.router_id = router_id_;
		context.status.router_label = router_name_;
		context.status.topology_generation = topology_generation_;
		context.status.user_generation = user_generation_;
		for (auto* hostgroup : hostgroups->rows) {
			const std::string role = hostgroup->fields[0] ? hostgroup->fields[0] : "";
			const int id = static_cast<int>(unsigned_field(hostgroup->fields[1], "hostgroup_id"));
			context.status.managed_hostgroups[role] = id;
			managed_hostgroups_[role] = id;
		}
		if (managed_hostgroups_.size() != mysql_router_hostgroup_roles().size()) {
			throw std::runtime_error("persisted Router hostgroup mapping is incomplete");
		}
		for (const std::string& role : mysql_router_hostgroup_roles()) {
			if (managed_hostgroups_.find(role) == managed_hostgroups_.end()) {
				throw std::runtime_error("persisted Router hostgroup mapping is incomplete");
			}
		}
	}

	uint64_t monotonic_ms() const override {
		return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
	}

	ReconcileTopologySnapshot read_topology() override {
		auto read_metadata = [&](const MetadataEndpoint& candidate) {
			session_ = ConnectorCMetadataSession::connect(candidate, tls_, password_,
				std::max<unsigned>(1, config_.connect_timeout_ms / 1000));
			QueryResult registration = session_->query(
				"SELECT router_id FROM mysql_innodb_cluster_metadata.v2_routers WHERE router_id=?",
				{static_cast<int64_t>(router_id_)});
			ReconcileTopologySnapshot snapshot;
			snapshot.metadata_available = true;
			if (mysql_router_context().metrics.metadata_available) {
				mysql_router_context().metrics.metadata_available->Set(1);
			}
			snapshot.registration_exists = registration.rows.size() == 1;
			if (!snapshot.registration_exists) {
				MysqlRouterContext& context = mysql_router_context();
				std::lock_guard<std::mutex> guard(context.status_mutex);
				context.status.metadata_available = true;
				context.status.registration_exists = false;
				context.status.state = "registration_missing";
				return snapshot;
			}
			snapshot.desired = MetadataV2_2::read_innodb_cluster(
				*session_, topology_uuid_, static_cast<int64_t>(router_id_));
			ExecResult registration_refresh = session_->execute(
				"UPDATE mysql_innodb_cluster_metadata.v2_routers SET product_name='ProxySQL',"
				"version='8.4.0',attributes=JSON_SET(COALESCE(attributes,JSON_OBJECT()),"
				"'$.RWEndpoint',?,'$.ROEndpoint',?,'$.RWSplitEndpoint',?,"
				"'$.MetadataUser',?,'$.ProxySQLTopologyUUID',?) WHERE router_id=?",
				{std::to_string(listeners_.rw_port), std::to_string(listeners_.ro_port),
					std::to_string(listeners_.rw_split_port), metadata_user_, topology_uuid_,
					static_cast<int64_t>(router_id_)});
			if (!registration_refresh.ok) {
				snapshot.warning_kind = "registration";
				snapshot.warning_code = "check_in_failed";
				snapshot.warning_message = registration_refresh.error;
			}
			ObservedHealth health = GrHealthReader::read(*session_);
			snapshot.effective = evaluate_innodb_cluster(snapshot.desired, health);
			snapshot.identity_valid = snapshot.desired.topology_uuid == topology_uuid_;
			snapshot.has_metadata_endpoint = !snapshot.desired.instances.empty();
			snapshot.complete = snapshot.identity_valid && snapshot.has_metadata_endpoint;
			snapshot.fingerprint = topology_fingerprint(snapshot.desired, snapshot.effective);
			if (snapshot.complete) {
				persist_cached_topology(services_, snapshot.desired);
				current_topology_ = snapshot.desired;
				current_effective_ = snapshot.effective;
				update_observability(snapshot.desired, health, snapshot.effective, true);
			}
			{
				MysqlRouterContext& context = mysql_router_context();
				std::lock_guard<std::mutex> guard(context.status_mutex);
				context.status.metadata_available = true;
				context.status.registration_exists = true;
				context.status.unsupported_router_options =
					snapshot.desired.options.routing_guideline_unsupported;
			}
			if (snapshot.desired.options.stats_updates_frequency &&
				*snapshot.desired.options.stats_updates_frequency != 0) {
				const uint64_t now = monotonic_ms();
				const uint64_t frequency = *snapshot.desired.options.stats_updates_frequency;
				const uint64_t interval = frequency > std::numeric_limits<uint64_t>::max() / 1000
					? std::numeric_limits<uint64_t>::max() : frequency * 1000;
				if (last_check_in_ms_ == 0 || now - last_check_in_ms_ >=
					interval) {
					ExecResult checked_in = session_->execute(
						"UPDATE mysql_innodb_cluster_metadata.v2_routers SET last_check_in=NOW() WHERE router_id=?",
						{static_cast<int64_t>(router_id_)});
					if (!checked_in.ok) {
						if (snapshot.warning_code.empty()) {
							snapshot.warning_kind = "metadata";
							snapshot.warning_code = "check_in_failed";
							snapshot.warning_message = checked_in.error;
						}
					} else last_check_in_ms_ = now;
				}
			}
			return snapshot;
		};

		std::exception_ptr metadata_failure;
		std::optional<ReconcileTopologySnapshot> invalid_metadata_snapshot;
		std::set<std::pair<std::string, uint16_t>> attempted;
		auto attempt_metadata = [&](const MetadataEndpoint& candidate,
			ReconcileTopologySnapshot& snapshot) {
			if (!attempted.emplace(candidate.host, candidate.port).second) return false;
			try {
				ReconcileTopologySnapshot candidate_snapshot = read_metadata(candidate);
				if (candidate_snapshot.complete) {
					snapshot = std::move(candidate_snapshot);
					endpoint_ = candidate;
					return true;
				}
				if (!invalid_metadata_snapshot) {
					invalid_metadata_snapshot = std::move(candidate_snapshot);
				}
				return false;
			} catch (...) {
				if (!metadata_failure) metadata_failure = std::current_exception();
				return false;
			}
		};

		ReconcileTopologySnapshot metadata_snapshot;
		if (attempt_metadata(endpoint_, metadata_snapshot)) return metadata_snapshot;
		for (const auto& instance : current_topology_.instances) {
			MetadataEndpoint candidate {metadata_user_, instance.classic.host,
				instance.classic.port};
			if (attempt_metadata(candidate, metadata_snapshot)) return metadata_snapshot;
		}
		if (invalid_metadata_snapshot) {
			ReconcileTopologySnapshot invalid = std::move(*invalid_metadata_snapshot);
			return invalid;
		}

		MysqlRouterContext& failure_context = mysql_router_context();
			{
				std::lock_guard<std::mutex> guard(failure_context.status_mutex);
				failure_context.status.metadata_available = false;
			}
			if (failure_context.metrics.metadata_available) {
				failure_context.metrics.metadata_available->Set(0);
			}
			if (current_topology_.instances.empty()) {
				if (metadata_failure) std::rethrow_exception(metadata_failure);
				throw std::runtime_error("Router metadata endpoints are unavailable");
			}
			for (const auto& instance : current_topology_.instances) {
				try {
					MetadataEndpoint health_endpoint {metadata_user_, instance.classic.host,
						instance.classic.port};
					session_ = ConnectorCMetadataSession::connect(health_endpoint, tls_, password_,
						std::max<unsigned>(1, config_.connect_timeout_ms / 1000));
					ObservedHealth health = GrHealthReader::read(*session_);
					ReconcileTopologySnapshot snapshot;
					snapshot.metadata_available = false;
					if (mysql_router_context().metrics.metadata_available) {
						mysql_router_context().metrics.metadata_available->Set(0);
					}
					snapshot.registration_exists = true;
					snapshot.identity_valid = true;
					snapshot.has_metadata_endpoint = true;
					snapshot.complete = true;
					snapshot.desired = current_topology_;
					snapshot.effective = evaluate_innodb_cluster(current_topology_, health);
					current_effective_ = snapshot.effective;
					snapshot.fingerprint = topology_fingerprint(snapshot.desired, snapshot.effective);
					update_observability(snapshot.desired, health, snapshot.effective, false);
					{
						MysqlRouterContext& context = mysql_router_context();
						std::lock_guard<std::mutex> guard(context.status_mutex);
						context.status.metadata_available = false;
						context.status.registration_exists = true;
					}
					return snapshot;
				} catch (...) {}
			}
			if (metadata_failure) std::rethrow_exception(metadata_failure);
			throw std::runtime_error("Router metadata endpoints are unavailable");
	}

	AccountSnapshot read_users() override {
		if (!session_) throw std::runtime_error("metadata session is unavailable for user refresh");
		return UserSynchronizer::read(*session_, metadata_user_);
	}

	uint64_t publish_topology(const ReconcileTopologySnapshot& snapshot,
		uint64_t generation) override {
		if (!session_) throw std::runtime_error("metadata session is unavailable for topology publication");
		const uint64_t published = publish_mysql_router_topology(
			services_, *session_, snapshot.desired, snapshot.effective, listeners_, generation);
		if (!persist_generation(services_, "topology_generation", published)) {
			throw std::runtime_error("cannot persist the active topology generation");
		}
		MysqlRouterContext& context = mysql_router_context();
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.topology_generation = published;
		context.runtime_topology = pending_runtime_topology_;
		if (context.metrics.topology_generation) context.metrics.topology_generation->Set(published);
		return published;
	}

	uint64_t publish_users(const AccountSnapshot& snapshot, uint64_t generation) override {
		if (!session_ || current_topology_.topology_uuid.empty() || !current_effective_) {
			throw std::runtime_error("metadata topology is unavailable for user publication");
		}
		const uint64_t published = publish_mysql_router_users(services_, *session_,
			current_topology_, *current_effective_, listeners_, snapshot, metadata_user_, generation);
		if (!persist_generation(services_, "user_generation", published)) {
			throw std::runtime_error("cannot persist the active user generation");
		}
		uint64_t collisions = 0;
		uint64_t unresolved = 0;
		uint64_t unsupported = 0;
		bool user_state_observed = false;
		try {
			auto user_state = query(*db_,
				"SELECT SUM(state='collision'),SUM(state='unresolved'),"
				"SUM(state='unresolved' AND last_error='authentication plugin is unsupported') "
				"FROM mysql_router_users");
			if (!user_state->rows.empty()) {
				collisions = user_state->rows[0]->fields[0]
					? unsigned_field(user_state->rows[0]->fields[0], "user collision count") : 0;
				unresolved = user_state->rows[0]->fields[1]
					? unsigned_field(user_state->rows[0]->fields[1], "unresolved user count") : 0;
				unsupported = user_state->rows[0]->fields[2]
					? unsigned_field(user_state->rows[0]->fields[2], "unsupported auth count") : 0;
				user_state_observed = true;
			}
		} catch (...) {
			// Publication is already committed; optional observability must not recast it as failed.
		}
		MysqlRouterContext& context = mysql_router_context();
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.user_generation = published;
		if (context.metrics.user_generation) context.metrics.user_generation->Set(published);
		if (user_state_observed) {
			context.status.user_collisions = collisions;
			context.status.unsupported_auth_plugins = unsupported;
			if (context.metrics.unresolved_users) context.metrics.unresolved_users->Set(unresolved);
		}
		return published;
	}

	bool topology_drifted(const ReconcileTopologySnapshot& snapshot) override {
		std::multiset<std::string> expected;
		auto add = [&](std::string_view role, std::string_view uuid) {
			auto instance = std::find_if(snapshot.desired.instances.begin(), snapshot.desired.instances.end(),
				[&](const DesiredInstance& value) { return value.server_uuid == uuid; });
			if (instance == snapshot.desired.instances.end()) {
				throw std::runtime_error("effective topology references an unknown drift-check instance");
			}
			expected.insert(server_identity(managed_hostgroups_.at(std::string(role)),
				instance->classic.host, instance->classic.port));
		};
		if (snapshot.effective.writer) {
			add("route_writer", *snapshot.effective.writer);
			add("gr_writer", *snapshot.effective.writer);
		}
		for (const std::string& uuid : snapshot.effective.readers) {
			auto instance = std::find_if(snapshot.desired.instances.begin(), snapshot.desired.instances.end(),
				[&](const DesiredInstance& value) { return value.server_uuid == uuid; });
			if (instance == snapshot.desired.instances.end()) {
				throw std::runtime_error("effective topology references an unknown reader");
			}
			add("route_reader", uuid);
			add(instance->kind == InstanceKind::gr_member ? "gr_reader" : "async_reader", uuid);
		}
		for (const std::string& uuid : snapshot.effective.excluded) {
			auto instance = std::find_if(snapshot.desired.instances.begin(), snapshot.desired.instances.end(),
				[&](const DesiredInstance& value) { return value.server_uuid == uuid; });
			if (instance == snapshot.desired.instances.end()) {
				throw std::runtime_error("effective topology references an unknown excluded instance");
			}
			add(instance->kind == InstanceKind::gr_member ? "gr_offline" : "async_offline", uuid);
		}

		std::string ids;
		for (const auto& hostgroup : managed_hostgroups_) {
			if (!ids.empty()) ids.push_back(',');
			ids += std::to_string(hostgroup.second);
		}
		SQLite3DB* admin = services_.get_admindb ? services_.get_admindb() : nullptr;
		if (admin == nullptr) throw std::runtime_error("Admin DB is unavailable for Router drift check");
		auto stored = [&](const char* schema) {
			std::multiset<std::string> rows;
			auto result = query(*admin, "SELECT hostgroup_id,hostname,port FROM " +
				std::string(schema) + ".mysql_servers WHERE hostgroup_id IN (" + ids + ")");
			for (auto* row : result->rows) {
				rows.insert(server_identity(unsigned_field(row->fields[0], "hostgroup_id"),
					row->fields[1] ? row->fields[1] : "", unsigned_field(row->fields[2], "port")));
			}
			return rows;
		};
		if (stored("main") != expected || stored("disk") != expected) return true;
		if (services_.get_mysql_servers_snapshot == nullptr) {
			throw std::runtime_error("live MySQL server snapshot is unavailable for Router drift check");
		}
		std::unique_ptr<SQLite3_result> live(services_.get_mysql_servers_snapshot());
		if (!live) throw std::runtime_error("cannot capture live MySQL servers for Router drift check");
		const int hostgroup_column = result_column(*live, "hostgroup_id");
		const int hostname_column = result_column(*live, "hostname");
		const int port_column = result_column(*live, "port");
		std::multiset<std::string> runtime;
		std::set<int> owned_ids;
		for (const auto& hostgroup : managed_hostgroups_) owned_ids.insert(hostgroup.second);
		for (auto* row : live->rows) {
			const int hostgroup = static_cast<int>(unsigned_field(
				row->fields[hostgroup_column], "hostgroup_id"));
			if (!owned_ids.count(hostgroup)) continue;
			runtime.insert(server_identity(hostgroup,
				row->fields[hostname_column] ? row->fields[hostname_column] : "",
				unsigned_field(row->fields[port_column], "port")));
		}
		return runtime != expected;
	}

	void record_drift_correction() override {
		MysqlRouterContext& context = mysql_router_context();
		if (context.metrics.drift_corrections) context.metrics.drift_corrections->Increment();
	}

	void set_gates(bool ready, std::string_view reason) override {
		if (services_.set_listener_gate == nullptr) throw std::runtime_error("listener gate service is unavailable");
		bool complete = true;
		for (uint16_t port : {listeners_.rw_port, listeners_.ro_port, listeners_.rw_split_port}) {
			const std::string reason_copy(reason);
			const ProxySQL_PluginListenerGate gate {"mysql_router", listeners_.bind_address.c_str(), port,
				ready ? ProxySQL_PluginListenerState::ready : ProxySQL_PluginListenerState::closed,
				reason_copy.c_str()};
			if (!services_.set_listener_gate(gate)) {
				complete = false;
				break;
			}
		}
		if (!complete) {
			for (uint16_t port : {listeners_.rw_port, listeners_.ro_port, listeners_.rw_split_port}) {
				const ProxySQL_PluginListenerGate gate {"mysql_router", listeners_.bind_address.c_str(),
					port, ProxySQL_PluginListenerState::closed, "Router listener-gate update failed"};
				(void)services_.set_listener_gate(gate);
			}
			throw std::runtime_error("cannot update Router listener gate");
		}
		MysqlRouterContext& context = mysql_router_context();
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.gates_ready = ready;
		if (ready) context.status.state = "ready";
		else if (context.status.state != "registration_missing") context.status.state = "degraded";
	}

	void record_transition(std::string_view kind, std::string_view code,
		std::string_view message, bool log_transition) override {
		const std::string safe = safe_message(message);
		if (log_transition && services_.log_message != nullptr) services_.log_message(2, safe.c_str());
		SQLite3DB* stats = services_.get_statsdb ? services_.get_statsdb() : nullptr;
		if (stats != nullptr) {
			const int64_t now = static_cast<int64_t>(std::time(nullptr));
			const std::string identity = "kind=" + quote(kind) + " AND code=" + quote(code) +
				" AND message=" + quote(safe);
			const std::string update = "UPDATE stats_mysql_router_errors SET occurrence_count="
				"occurrence_count+1,last_seen=" + std::to_string(now) + " WHERE " + identity;
			const std::string insert = "INSERT INTO stats_mysql_router_errors"
				"(kind,code,message,occurrence_count,first_seen,last_seen) SELECT " +
				quote(kind) + "," + quote(code) + "," + quote(safe) + ",1," +
				std::to_string(now) + "," + std::to_string(now) +
				" WHERE changes()=0";
			if (stats->execute("BEGIN IMMEDIATE")) {
				if (!stats->execute(update.c_str()) || !stats->execute(insert.c_str()) ||
					!stats->execute("COMMIT")) stats->execute("ROLLBACK");
			}
		}
		MysqlRouterContext& context = mysql_router_context();
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.last_error = safe;
		if (!safe.empty() && context.status.state != "registration_missing") {
			context.status.state = "degraded";
		}
	}

	void clear_transition() override {
		MysqlRouterContext& context = mysql_router_context();
		std::lock_guard<std::mutex> guard(context.status_mutex);
		context.status.last_error.clear();
		if (context.status.gates_ready) context.status.state = "ready";
	}

	void record_refresh(std::string_view kind, bool success, uint64_t from,
		uint64_t to, std::string_view error) override {
		MysqlRouterContext& context = mysql_router_context();
		prometheus::Counter* counter = nullptr;
		if (kind == "topology") counter = success
			? context.metrics.topology_success : context.metrics.topology_failure;
		else if (kind == "users") counter = success
			? context.metrics.user_success : context.metrics.user_failure;
		if (counter) counter->Increment();
		const uint64_t now_seconds = static_cast<uint64_t>(std::time(nullptr));
		{
			std::lock_guard<std::mutex> guard(context.status_mutex);
			if (success && kind == "topology") context.status.topology_last_success = now_seconds;
			if (success && kind == "users") context.status.user_last_success = now_seconds;
			context.status.stale_seconds = context.status.metadata_available ||
				context.status.metadata_last_success == 0 ? 0 :
				now_seconds - context.status.metadata_last_success;
			if (context.metrics.stale_seconds) {
				context.metrics.stale_seconds->Set(context.status.stale_seconds);
			}
		}
		SQLite3DB* stats = services_.get_statsdb ? services_.get_statsdb() : nullptr;
		if (stats == nullptr) return;
		const int64_t now = static_cast<int64_t>(std::time(nullptr));
		const std::string safe = safe_message(error);
		const std::string sql = "INSERT INTO stats_mysql_router_refresh"
			"(refresh_id,started_at,completed_at,kind,result,from_generation,to_generation,error_code,error_message) "
			"SELECT COALESCE(MAX(refresh_id),0)+1," + std::to_string(now) + "," +
			std::to_string(now) + "," + quote(kind) + "," +
			quote(success ? "success" : "failure") + "," + std::to_string(from) + "," +
			std::to_string(to) + "," + quote(success ? "" : "refresh_failed") + "," +
			quote(safe) + " FROM stats_mysql_router_refresh";
		(void)stats->execute(sql.c_str());
	}

	ReconcileSchedule schedule() const override {
		return {config_.refresh_interval_ms, 30000};
	}
	uint64_t initial_topology_generation() const override { return topology_generation_; }
	uint64_t initial_user_generation() const override { return user_generation_; }

private:
	void update_observability(const DesiredTopology& desired, const ObservedHealth& health,
		const EffectiveTopology& effective, bool metadata_available) {
		const uint64_t observed_at = static_cast<uint64_t>(std::time(nullptr));
		std::vector<MysqlRouterRuntimeTopologyRow> rows;
		rows.reserve(desired.instances.size());
		for (const auto& instance : desired.instances) {
			MysqlRouterRuntimeTopologyRow row;
			row.cluster_uuid = desired.topology_uuid;
			row.instance_uuid = instance.server_uuid;
			row.endpoint = instance.classic.host + ":" + std::to_string(instance.classic.port);
			row.instance_kind = instance.kind == InstanceKind::gr_member ? "gr_member" : "read_replica";
			auto observed = health.members.find(instance.server_uuid);
			row.desired_role = instance.kind == InstanceKind::read_replica ||
				(observed != health.members.end() && observed->second.role == DesiredRole::reader)
				? "reader" : "writer";
			row.observed_state = observed == health.members.end()
				? "unreachable" : health_name(observed->second.state);
			if (effective.writer && *effective.writer == instance.server_uuid) row.effective_role = "writer";
			else if (std::find(effective.readers.begin(), effective.readers.end(), instance.server_uuid) !=
				effective.readers.end()) row.effective_role = "reader";
			else row.effective_role = "excluded";
			row.last_observed_at = observed_at;
			rows.push_back(std::move(row));
		}
		const uint64_t writers = effective.writer ? 1 : 0;
		const uint64_t readers = effective.readers.size();
		const uint64_t excluded = effective.excluded.size();
		MysqlRouterContext& context = mysql_router_context();
		std::lock_guard<std::mutex> guard(context.status_mutex);
		const std::string next_writer = effective.writer ? *effective.writer : std::string();
		if (!context.status.writer_uuid.empty() && context.status.writer_uuid != next_writer &&
			context.metrics.writer_changes) context.metrics.writer_changes->Increment();
		context.status.writer_uuid = next_writer;
		context.status.topology_uuid = desired.topology_uuid;
		context.status.metadata_version = metadata_version(desired.metadata_version);
		context.status.metadata_available = metadata_available;
		if (metadata_available) context.status.metadata_last_success = observed_at;
		pending_runtime_topology_ = std::move(rows);
		if (context.metrics.managed_writer_online) context.metrics.managed_writer_online->Set(writers);
		if (context.metrics.managed_reader_online) context.metrics.managed_reader_online->Set(readers);
		if (context.metrics.managed_excluded) context.metrics.managed_excluded->Set(excluded);
	}

	ProxySQL_PluginServices& services_;
	SQLite3DB* db_ {nullptr};
	MysqlRouterConfigStore config_store_;
	MysqlRouterRuntimeConfig config_;
	MetadataEndpoint endpoint_;
	TlsOptions tls_;
	ListenerProfile listeners_;
	SecureBytes password_;
	std::string topology_uuid_;
	std::string router_name_;
	std::string router_address_;
	std::string metadata_user_;
	std::map<std::string, int> managed_hostgroups_;
	uint64_t router_id_ {0};
	uint64_t topology_generation_ {0};
	std::vector<MysqlRouterRuntimeTopologyRow> pending_runtime_topology_;
	uint64_t user_generation_ {0};
	uint64_t last_check_in_ms_ {0};
	DesiredTopology current_topology_;
	std::optional<EffectiveTopology> current_effective_;
	std::unique_ptr<ConnectorCMetadataSession> session_;
};

} // namespace

std::unique_ptr<IReconcileBackend> create_mysql_router_reconcile_backend(
	ProxySQL_PluginServices& services) {
	if (services.get_configdb == nullptr || services.get_configdb() == nullptr) return nullptr;
	try {
		return std::make_unique<RuntimeBackend>(services);
	} catch (const std::out_of_range&) {
		return nullptr;
	}
}
