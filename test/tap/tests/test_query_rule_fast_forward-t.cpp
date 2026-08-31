/**
 * @file test_query_rule_fast_forward-t.cpp
 * @brief Lock the intentionally narrow COM_QUERY fast-forward rule contract.
 */

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <poll.h>
#include <sys/socket.h>

#include "mysql.h"

#include "command_line.h"
#include "json.hpp"
#include "tap.h"

using MysqlPtr = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using nlohmann::json;

namespace {

constexpr int kTargetHostgroup = 61460;
constexpr int kFirstRule = 614600;
constexpr int kLastRule = 614606;
constexpr const char* kComment = "test_query_rule_fast_forward-t";
constexpr const char* kUser = "sbtest1";
constexpr const char* kTable = "query_rule_ff_once";

bool query_and_drain(MYSQL* mysql, const std::string& sql) {
	if (!mysql || mysql_real_query(mysql, sql.data(), sql.size()) != 0) {
		diag("Query failed: %s", mysql ? mysql_error(mysql) : "null MYSQL handle");
		return false;
	}
	int next_result = 0;
	do {
		MYSQL_RES* result = mysql_store_result(mysql);
		if (result) {
			mysql_free_result(result);
		} else if (mysql_field_count(mysql) != 0) {
			diag("mysql_store_result failed: %s", mysql_error(mysql));
			return false;
		}
		next_result = mysql_next_result(mysql);
	} while (next_result == 0);
	return next_result < 0;
}

long long scalar_int(MYSQL* mysql, const std::string& sql, long long fallback = -1) {
	if (!mysql || mysql_query(mysql, sql.c_str()) != 0) {
		diag("Scalar query failed: %s", mysql ? mysql_error(mysql) : "null MYSQL handle");
		return fallback;
	}
	MYSQL_RES* result = mysql_store_result(mysql);
	MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
	long long value = fallback;
	if (row && row[0]) {
		char* end = nullptr;
		const long long parsed = std::strtoll(row[0], &end, 10);
		if (end && *end == '\0') {
			value = parsed;
		}
	}
	if (result) {
		mysql_free_result(result);
	}
	return value;
}

std::string sql_quote(MYSQL* mysql, const std::string& value) {
	std::string escaped(value.size() * 2 + 1, '\0');
	const unsigned long length = mysql_real_escape_string(
		mysql, escaped.data(), value.data(), static_cast<unsigned long>(value.size()));
	escaped.resize(length);
	return "'" + escaped + "'";
}

struct OnlineServer {
	int hostgroup = -1;
	std::string hostname;
	unsigned int port = 0;
};

bool select_online_server(MYSQL* admin, OnlineServer& server) {
	if (mysql_query(admin,
		"SELECT hostgroup_id,hostname,port FROM runtime_mysql_servers "
		"WHERE status='ONLINE' ORDER BY hostgroup_id,hostname,port LIMIT 1") != 0) {
		return false;
	}
	MYSQL_RES* result = mysql_store_result(admin);
	MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
	const bool found = row && row[0] && row[1] && row[2];
	if (found) {
		server.hostgroup = std::atoi(row[0]);
		server.hostname = row[1];
		server.port = static_cast<unsigned int>(std::strtoul(row[2], nullptr, 10));
	}
	if (result) {
		mysql_free_result(result);
	}
	return found;
}

bool processlist_state(MYSQL* admin, unsigned long session_id, int& hostgroup, int& fast_forward) {
	const std::string sql =
		"SELECT hostgroup,extended_info FROM stats_mysql_processlist WHERE SessionID=" +
		std::to_string(session_id);
	if (mysql_query(admin, sql.c_str()) != 0) {
		return false;
	}
	MYSQL_RES* result = mysql_store_result(admin);
	MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
	bool valid = false;
	if (row && row[0] && row[1]) {
		try {
			const json info = json::parse(row[1]);
			hostgroup = std::atoi(row[0]);
			if (info.contains("fast_forward") && info["fast_forward"].is_boolean()) {
				fast_forward = info["fast_forward"].get<bool>() ? 1 : 0;
				valid = true;
			} else if (info.contains("fast_forward") && info["fast_forward"].is_number_integer()) {
				fast_forward = info["fast_forward"].get<int>();
				valid = true;
			}
		} catch (const std::exception& error) {
			diag("Unable to parse processlist state: %s", error.what());
		}
	}
	if (result) {
		mysql_free_result(result);
	}
	return valid;
}

bool wait_for_state(MYSQL* admin, unsigned long session_id, int expected_hostgroup,
	int expected_fast_forward, unsigned int timeout_ms = 3000) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	do {
		int hostgroup = -1;
		int fast_forward = -1;
		if (processlist_state(admin, session_id, hostgroup, fast_forward) &&
			hostgroup == expected_hostgroup && fast_forward == expected_fast_forward) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	} while (std::chrono::steady_clock::now() < deadline);
	return false;
}

bool wait_for_rule_hit(MYSQL* admin, int rule_id, unsigned int timeout_ms = 3000) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	do {
		if (scalar_int(admin,
			"SELECT hits FROM stats_mysql_query_rules WHERE rule_id=" +
			std::to_string(rule_id), 0) > 0) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	} while (std::chrono::steady_clock::now() < deadline);
	return false;
}

bool clear_rules(MYSQL* admin) {
	return query_and_drain(admin,
		"DELETE FROM mysql_query_rules WHERE rule_id BETWEEN " +
		std::to_string(kFirstRule) + " AND " + std::to_string(kLastRule) +
		" AND comment='" + kComment + "'") &&
		query_and_drain(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
}

bool install_rule(MYSQL* admin, const std::string& columns_and_values) {
	return clear_rules(admin) && query_and_drain(admin,
		"INSERT INTO mysql_query_rules(" + columns_and_values) &&
		query_and_drain(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
}

MysqlPtr connect_frontend(const CommandLine& cl, bool compress = false) {
	MysqlPtr client(mysql_init(nullptr), &mysql_close);
	if (client && compress) {
		mysql_options(client.get(), MYSQL_OPT_COMPRESS, nullptr);
	}
	if (!client || !mysql_real_connect(client.get(), cl.host, kUser, kUser,
		"test", cl.port, nullptr, 0)) {
		return MysqlPtr(nullptr, &mysql_close);
	}
	return client;
}

std::vector<unsigned char> com_query_packet(const std::string& query) {
	const size_t payload_size = query.size() + 1;
	std::vector<unsigned char> packet(4 + payload_size);
	packet[0] = payload_size & 0xff;
	packet[1] = (payload_size >> 8) & 0xff;
	packet[2] = (payload_size >> 16) & 0xff;
	packet[3] = 0;
	packet[4] = 0x03;
	memcpy(packet.data() + 5, query.data(), query.size());
	return packet;
}

bool send_all(int fd, const std::vector<unsigned char>& bytes) {
	size_t sent_total = 0;
	while (sent_total < bytes.size()) {
		const ssize_t sent = send(fd, bytes.data() + sent_total,
			bytes.size() - sent_total, MSG_NOSIGNAL);
		if (sent <= 0) {
			return false;
		}
		sent_total += static_cast<size_t>(sent);
	}
	return true;
}

bool recv_exact(int fd, unsigned char* output, size_t size) {
	size_t received_total = 0;
	while (received_total < size) {
		pollfd descriptor { fd, POLLIN | POLLHUP, 0 };
		if (poll(&descriptor, 1, 3000) <= 0) {
			return false;
		}
		const ssize_t received = recv(fd, output + received_total,
			size - received_total, 0);
		if (received <= 0) {
			return false;
		}
		received_total += static_cast<size_t>(received);
	}
	return true;
}

int read_mysql_error(int fd) {
	unsigned char header[4] {};
	if (!recv_exact(fd, header, sizeof(header))) {
		return -1;
	}
	const size_t payload_size = header[0] |
		(static_cast<size_t>(header[1]) << 8) |
		(static_cast<size_t>(header[2]) << 16);
	std::vector<unsigned char> payload(payload_size);
	if (payload_size < 3 || !recv_exact(fd, payload.data(), payload.size()) || payload[0] != 0xff) {
		return -1;
	}
	return payload[1] | (static_cast<int>(payload[2]) << 8);
}

bool wait_for_close(int fd) {
	pollfd descriptor { fd, POLLIN | POLLHUP, 0 };
	if (poll(&descriptor, 1, 3000) <= 0) {
		return false;
	}
	unsigned char byte = 0;
	return recv(fd, &byte, 1, 0) == 0;
}

class Cleanup {
public:
	Cleanup(MYSQL* admin, MYSQL* backend, long long admin_ff, long long runtime_ff,
		long long admin_extended, long long runtime_extended,
		long long admin_packet, long long runtime_packet)
		: admin_(admin), backend_(backend), admin_ff_(admin_ff), runtime_ff_(runtime_ff),
		  admin_extended_(admin_extended), runtime_extended_(runtime_extended),
		  admin_packet_(admin_packet), runtime_packet_(runtime_packet) {}

	~Cleanup() { run(); }

	void own_rules() { rules_ = true; }
	void own_server() { server_ = true; }
	void own_table() { table_ = true; }
	void changed_user() { user_ = true; }
	void changed_variables() { variables_ = true; }

	bool run() {
		if (!active_) {
			return result_;
		}
		active_ = false;
		if (rules_) {
			result_ = clear_rules(admin_) && result_;
		}
		if (server_) {
			result_ = query_and_drain(admin_,
				"DELETE FROM mysql_servers WHERE hostgroup_id=" +
				std::to_string(kTargetHostgroup) + " AND comment='" + kComment + "'") && result_;
			result_ = query_and_drain(admin_, "LOAD MYSQL SERVERS TO RUNTIME") && result_;
		}
		if (table_) {
			result_ = query_and_drain(backend_,
				"DROP TABLE test." + std::string(kTable)) && result_;
		}
		if (user_) {
			result_ = query_and_drain(admin_, "UPDATE mysql_users SET fast_forward=" +
				std::to_string(runtime_ff_) + " WHERE username='" + kUser + "'") && result_;
			result_ = query_and_drain(admin_, "LOAD MYSQL USERS TO RUNTIME") && result_;
			result_ = query_and_drain(admin_, "UPDATE mysql_users SET fast_forward=" +
				std::to_string(admin_ff_) + " WHERE username='" + kUser + "'") && result_;
		}
		if (variables_) {
			result_ = query_and_drain(admin_, "SET mysql-show_processlist_extended=" +
				std::to_string(runtime_extended_)) && result_;
			result_ = query_and_drain(admin_, "SET mysql-max_allowed_packet=" +
				std::to_string(runtime_packet_)) && result_;
			result_ = query_and_drain(admin_, "LOAD MYSQL VARIABLES TO RUNTIME") && result_;
			result_ = query_and_drain(admin_, "SET mysql-show_processlist_extended=" +
				std::to_string(admin_extended_)) && result_;
			result_ = query_and_drain(admin_, "SET mysql-max_allowed_packet=" +
				std::to_string(admin_packet_)) && result_;
		}
		return result_;
	}

private:
	MYSQL* admin_;
	MYSQL* backend_;
	long long admin_ff_;
	long long runtime_ff_;
	long long admin_extended_;
	long long runtime_extended_;
	long long admin_packet_;
	long long runtime_packet_;
	bool rules_ { false };
	bool server_ { false };
	bool table_ { false };
	bool user_ { false };
	bool variables_ { false };
	bool active_ { true };
	bool result_ { true };
};

} // namespace

int main() {
	plan(NO_PLAN);
	CommandLine cl;
	if (cl.getEnv()) {
		ok(false, "the regular MySQL TAP environment is available");
		return exit_status();
	}

	MysqlPtr admin(mysql_init(nullptr), &mysql_close);
	ok(admin && mysql_real_connect(admin.get(), cl.admin_host, cl.admin_username,
		cl.admin_password, nullptr, cl.admin_port, nullptr, 0),
		"the ProxySQL Admin connection is available");
	if (!admin || mysql_ping(admin.get()) != 0) {
		return exit_status();
	}

	OnlineServer server;
	ok(select_online_server(admin.get(), server), "an ONLINE backend is available");
	MysqlPtr backend(mysql_init(nullptr), &mysql_close);
	ok(backend && mysql_real_connect(backend.get(), server.hostname.c_str(), cl.mysql_username,
		cl.mysql_password, "test", server.port, nullptr, 0),
		"the selected backend is directly observable");
	if (!backend || mysql_ping(backend.get()) != 0) {
		return exit_status();
	}

	const long long admin_ff = scalar_int(admin.get(),
		"SELECT fast_forward FROM mysql_users WHERE username='sbtest1'");
	const long long runtime_ff = scalar_int(admin.get(),
		"SELECT fast_forward FROM runtime_mysql_users WHERE username='sbtest1'");
	const long long admin_extended = scalar_int(admin.get(),
		"SELECT variable_value FROM global_variables "
		"WHERE variable_name='mysql-show_processlist_extended'");
	const long long runtime_extended = scalar_int(admin.get(),
		"SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='mysql-show_processlist_extended'");
	const long long admin_packet = scalar_int(admin.get(),
		"SELECT variable_value FROM global_variables "
		"WHERE variable_name='mysql-max_allowed_packet'");
	const long long runtime_packet = scalar_int(admin.get(),
		"SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='mysql-max_allowed_packet'");
	Cleanup cleanup(admin.get(), backend.get(), admin_ff, runtime_ff,
		admin_extended, runtime_extended, admin_packet, runtime_packet);

	const bool collision_free = admin_ff >= 0 && runtime_ff >= 0 &&
		admin_extended >= 0 && runtime_extended >= 0 && admin_packet >= 0 && runtime_packet >= 0 &&
		scalar_int(admin.get(),
			"SELECT COUNT(*) FROM mysql_query_rules WHERE rule_id BETWEEN " +
			std::to_string(kFirstRule) + " AND " + std::to_string(kLastRule)) == 0 &&
		scalar_int(admin.get(),
			"SELECT COUNT(*) FROM runtime_mysql_query_rules WHERE rule_id BETWEEN " +
			std::to_string(kFirstRule) + " AND " + std::to_string(kLastRule)) == 0 &&
		scalar_int(admin.get(), "SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id=61460") == 0 &&
		scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=61460") == 0 &&
		scalar_int(backend.get(), "SELECT COUNT(*) FROM information_schema.tables "
			"WHERE table_schema='test' AND table_name='query_rule_ff_once'") == 0;
	ok(collision_free, "all fixed fixture identifiers are unused before mutation");
	if (!collision_free) {
		return exit_status();
	}

	cleanup.changed_variables();
	const bool variables_ready = query_and_drain(admin.get(), "SET mysql-show_processlist_extended=2") &&
		query_and_drain(admin.get(), "SET mysql-max_allowed_packet=33554432") &&
		query_and_drain(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(variables_ready, "processlist observation and a 32 MiB packet limit are loaded");
	if (!variables_ready) {
		return exit_status();
	}

	cleanup.changed_user();
	const bool user_ready = query_and_drain(admin.get(),
		"UPDATE mysql_users SET fast_forward=0 WHERE username='sbtest1'") &&
		query_and_drain(admin.get(), "LOAD MYSQL USERS TO RUNTIME") &&
		scalar_int(admin.get(),
			"SELECT fast_forward FROM runtime_mysql_users WHERE username='sbtest1'") == 0;
	ok(user_ready, "the fixture user starts outside fast-forward");
	if (!user_ready) {
		return exit_status();
	}

	const bool server_inserted = query_and_drain(admin.get(),
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,gtid_port,status,weight,compression,"
		"max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) "
		"SELECT 61460,hostname,port,gtid_port,'ONLINE',weight,compression,max_connections,"
		"max_replication_lag,use_ssl,max_latency_ms,'test_query_rule_fast_forward-t' "
		"FROM runtime_mysql_servers WHERE hostgroup_id=" + std::to_string(server.hostgroup) +
		" AND hostname=" + sql_quote(admin.get(), server.hostname) +
		" AND port=" + std::to_string(server.port) + " LIMIT 1");
	if (server_inserted) {
		cleanup.own_server();
	}
	const bool server_ready = server_inserted &&
		query_and_drain(admin.get(), "LOAD MYSQL SERVERS TO RUNTIME") &&
		scalar_int(admin.get(),
			"SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id=61460 AND status='ONLINE'") == 1;
	ok(server_ready, "the target hostgroup contains one copied ONLINE backend");

	const bool table_ready = query_and_drain(backend.get(),
		"CREATE TABLE test.query_rule_ff_once(id INT PRIMARY KEY,payload LONGBLOB)");
	if (table_ready) {
		cleanup.own_table();
	}
	ok(table_ready, "the exactly-once backend table is created without replacing data");
	if (!server_ready || !table_ready) {
		return exit_status();
	}

	cleanup.own_rules();
	ok(install_rule(admin.get(),
		"rule_id,active,username,match_pattern,destination_hostgroup,apply,attributes,comment) VALUES"
		"(614600,1,'sbtest1','qrff_text',61460,1,'{\"switch_to_fast_forward\":true}',"
		"'test_query_rule_fast_forward-t')"),
		"the ordinary COM_QUERY switch rule is loaded");
	MysqlPtr text_client = connect_frontend(cl);
	ok(text_client != nullptr, "the ordinary frontend connection is available");
	ok(text_client && query_and_drain(text_client.get(),
		"INSERT /* qrff_text */ INTO test.query_rule_ff_once VALUES(1,'text')"),
		"the triggering COM_QUERY executes");
	ok(text_client && wait_for_state(admin.get(), mysql_thread_id(text_client.get()),
		kTargetHostgroup, 1),
		"COM_QUERY switches permanently to the final rule-chain hostgroup");
	ok(scalar_int(backend.get(),
		"SELECT COUNT(*) FROM test.query_rule_ff_once WHERE id=1") == 1,
		"the triggering COM_QUERY executes exactly once");
	ok(text_client && query_and_drain(text_client.get(), "SELECT 1"),
		"subsequent traffic remains live in fast-forward");
	ok(text_client && scalar_int(admin.get(),
		"SELECT info IS NULL FROM stats_mysql_processlist WHERE SessionID=" +
		std::to_string(mysql_thread_id(text_client.get()))) == 1,
		"ordinary fast-forward handoff does not retain a packet-backed query pointer");
	text_client.reset();

	ok(install_rule(admin.get(),
		"rule_id,active,username,match_pattern,destination_hostgroup,mirror_hostgroup,apply,attributes,comment) VALUES"
		"(614601,1,'sbtest1','qrff_mirror',61460,61460,1,'{\"switch_to_fast_forward\":true}',"
		"'test_query_rule_fast_forward-t')"),
		"the mirror safety rule is loaded");
	MysqlPtr mirror_client = connect_frontend(cl);
	ok(mirror_client && query_and_drain(mirror_client.get(),
		"INSERT IGNORE /* qrff_mirror */ INTO test.query_rule_ff_once VALUES(2,'mirror')"),
		"the source COM_QUERY completes while a mirror session is created");
	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	ok(mirror_client && wait_for_state(admin.get(), mysql_thread_id(mirror_client.get()),
		kTargetHostgroup, 1) && mysql_ping(admin.get()) == 0 &&
		query_and_drain(mirror_client.get(), "SELECT 2"),
		"the source is forwarded and the mirror path does not crash ProxySQL");
	ok(scalar_int(backend.get(),
		"SELECT COUNT(*) FROM test.query_rule_ff_once WHERE id=2") == 1,
		"source and mirror execution preserve the idempotent row");
	mirror_client.reset();

	ok(install_rule(admin.get(),
		"rule_id,active,username,match_digest,destination_hostgroup,apply,attributes,comment) VALUES"
		"(614602,1,'sbtest1','^INSERT INTO test.query_rule_ff_once',61460,1,"
		"'{\"switch_to_fast_forward\":true}','test_query_rule_fast_forward-t')"),
		"the prepared-statement rule is loaded");
	MysqlPtr prepared_client = connect_frontend(cl);
	MYSQL_STMT* statement = prepared_client ? mysql_stmt_init(prepared_client.get()) : nullptr;
	const char* statement_sql = "INSERT INTO test.query_rule_ff_once VALUES(?,'prepared')";
	int prepared_id = 3;
	MYSQL_BIND bind {};
	bind.buffer_type = MYSQL_TYPE_LONG;
	bind.buffer = &prepared_id;
	const bool prepared_ok = statement &&
		mysql_stmt_prepare(statement, statement_sql, std::strlen(statement_sql)) == 0 &&
		mysql_stmt_bind_param(statement, &bind) == 0 && mysql_stmt_execute(statement) == 0;
	ok(prepared_ok, "COM_STMT_PREPARE and COM_STMT_EXECUTE still execute normally");
	int prepared_hostgroup = -1;
	int prepared_ff = -1;
	ok(prepared_client && processlist_state(admin.get(), mysql_thread_id(prepared_client.get()),
		prepared_hostgroup, prepared_ff) && prepared_ff == 0,
		"the action is ignored outside COM_QUERY");
	ok(scalar_int(backend.get(),
		"SELECT COUNT(*) FROM test.query_rule_ff_once WHERE id=3") == 1,
		"the prepared statement executes exactly once");
	if (statement) {
		mysql_stmt_close(statement);
	}
	prepared_client.reset();

	ok(install_rule(admin.get(),
		"rule_id,active,username,match_pattern,destination_hostgroup,apply,attributes,comment) VALUES"
		"(614606,1,'sbtest1','^SELECT \\* FROM `query_rule_ff_once` WHERE 1=0$',61460,1,"
		"'{\"switch_to_fast_forward\":true}','test_query_rule_fast_forward-t')"),
		"the converted COM_FIELD_LIST matching rule is loaded");
	MysqlPtr field_client = connect_frontend(cl);
	ok(field_client != nullptr, "the COM_FIELD_LIST frontend connection is available");
	MYSQL_RES* field_result = field_client ?
		mysql_list_fields(field_client.get(), kTable, "%") : nullptr;
	ok(field_result != nullptr, "COM_FIELD_LIST succeeds through the normal query path");
	if (!field_result && field_client) {
		diag("mysql_list_fields failed: %s", mysql_error(field_client.get()));
	}
	if (field_result) {
		mysql_free_result(field_result);
	}
	ok(wait_for_rule_hit(admin.get(), 614606),
		"the converted COM_FIELD_LIST SQL matched the fast-forward rule");
	int field_hostgroup = -1;
	int field_fast_forward = -1;
	ok(field_client && processlist_state(admin.get(), mysql_thread_id(field_client.get()),
		field_hostgroup, field_fast_forward) && field_fast_forward == 0,
		"COM_FIELD_LIST does not consume the COM_QUERY-only fast-forward action");
	field_client.reset();

	ok(install_rule(admin.get(),
		"rule_id,active,username,match_pattern,destination_hostgroup,apply,attributes,comment) VALUES"
		"(614603,1,'sbtest1','qrff_compressed',61460,1,'{\"switch_to_fast_forward\":true}',"
		"'test_query_rule_fast_forward-t')"),
		"the compressed-client rejection rule is loaded");
	MysqlPtr compressed_client = connect_frontend(cl, true);
	ok(compressed_client && compressed_client->net.compress,
		"the frontend really negotiated protocol compression");
	const int compressed_rc = compressed_client ?
		mysql_query(compressed_client.get(), "DO /* qrff_compressed */ 1") : 0;
	ok(compressed_client && compressed_rc != 0,
		"a compressed COM_QUERY transition is rejected instead of translated");
	ok(compressed_client && mysql_ping(compressed_client.get()) != 0,
		"the rejected compressed frontend is closed");
	compressed_client.reset();

	ok(install_rule(admin.get(),
		"rule_id,active,username,match_pattern,destination_hostgroup,apply,attributes,comment) VALUES"
		"(614604,1,'sbtest1','qrff_large',61460,1,'{\"switch_to_fast_forward\":true}',"
		"'test_query_rule_fast_forward-t')"),
		"the uncompressed large-query rule is loaded");
	MysqlPtr large_client = connect_frontend(cl);
	std::string large_query =
		"INSERT /* qrff_large */ INTO test.query_rule_ff_once VALUES(4,'";
	large_query.append(0x01000000, 'x');
	large_query += "')";
	ok(large_client && query_and_drain(large_client.get(), large_query),
		"an uncompressed COM_QUERY crossing the 16 MiB packet boundary executes");
	ok(large_client && wait_for_state(admin.get(), mysql_thread_id(large_client.get()),
		kTargetHostgroup, 1),
		"the large COM_QUERY enters permanent fast-forward");
	ok(scalar_int(backend.get(),
		"SELECT COUNT(*) FROM test.query_rule_ff_once WHERE id=4") == 1,
		"the reconstructed large COM_QUERY executes exactly once");
	ok(large_client && query_and_drain(large_client.get(), "SELECT 4"),
		"traffic after the large trigger remains live");
	ok(large_client && scalar_int(admin.get(),
		"SELECT info IS NULL FROM stats_mysql_processlist WHERE SessionID=" +
		std::to_string(mysql_thread_id(large_client.get()))) == 1,
		"completed large-query state does not retain a freed query pointer");
	large_client.reset();

	ok(install_rule(admin.get(),
		"rule_id,active,username,match_pattern,destination_hostgroup,apply,attributes,comment) VALUES"
		"(614605,1,'sbtest1','qrff_pipeline',61460,1,'{\"switch_to_fast_forward\":true}',"
		"'test_query_rule_fast_forward-t')"),
		"the pipelined-query rejection rule is loaded");
	MysqlPtr pipeline_client = connect_frontend(cl);
	std::vector<unsigned char> pipelined = com_query_packet(
		"INSERT /* qrff_pipeline */ INTO test.query_rule_ff_once VALUES(5,'pipeline')");
	const std::vector<unsigned char> trailing = com_query_packet(
		"INSERT INTO test.query_rule_ff_once VALUES(6,'trailing')");
	pipelined.insert(pipelined.end(), trailing.begin(), trailing.end());
	const int pipeline_fd = pipeline_client ? mysql_get_socket(pipeline_client.get()) : -1;
	ok(pipeline_fd >= 0 && send_all(pipeline_fd, pipelined),
		"two COM_QUERY packets are sent in one client write");
	const int pipeline_error = pipeline_fd >= 0 ? read_mysql_error(pipeline_fd) : -1;
	ok(pipeline_fd >= 0 && (pipeline_error == 1815 || pipeline_error == -1) &&
		wait_for_close(pipeline_fd),
		"a transition with buffered client packets is rejected and closed");
	ok(mysql_ping(admin.get()) == 0,
		"the rejected pipelined frontend does not crash ProxySQL");
	ok(scalar_int(backend.get(),
		"SELECT COUNT(*) FROM test.query_rule_ff_once WHERE id IN (5,6)") == 0,
		"neither rejected pipelined query reaches the backend");
	pipeline_client.reset();

	ok(cleanup.run(), "all Admin, runtime, and backend fixture state is restored");
	return exit_status();
}
