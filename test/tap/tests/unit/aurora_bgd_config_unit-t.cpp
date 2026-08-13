/**
 * @file aurora_bgd_config_unit-t.cpp
 * @brief Aurora blue/green hostgroup schema and LOAD validation contracts.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "cpp.h"
#include "MySQL_HostGroups_Manager.h"
#include "ProxySQL_Admin_Tables_Definitions.h"

#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

extern MySQL_HostGroups_Manager* MyHGM;

class TestAuroraBGDRuntime {
public:
	static void reload(MySQL_HostGroups_Manager* hgm, SQLite3_result* candidate) {
		hgm->wrlock();
		hgm->save_incoming_mysql_table(candidate, "mysql_aws_aurora_hostgroups");
		hgm->generate_mysql_aws_aurora_hostgroups_table();
		hgm->wrunlock();
	}

	static bool green_hostgroups(
		MySQL_HostGroups_Manager* hgm,
		int writer_hostgroup,
		int& green_writer_hostgroup,
		int& green_reader_hostgroup
	) {
		pthread_mutex_lock(&hgm->AWS_Aurora_Info_mutex);
		auto info_it = hgm->AWS_Aurora_Info_Map.find(writer_hostgroup);
		if (info_it == hgm->AWS_Aurora_Info_Map.end()) {
			pthread_mutex_unlock(&hgm->AWS_Aurora_Info_mutex);
			return false;
		}
		green_writer_hostgroup = info_it->second->green_writer_hostgroup;
		green_reader_hostgroup = info_it->second->green_reader_hostgroup;
		pthread_mutex_unlock(&hgm->AWS_Aurora_Info_mutex);
		return true;
	}
};

static std::string query_string(SQLite3DB* db, const char* query) {
	char* error = nullptr;
	SQLite3_result* result = db->execute_statement(query, &error);
	std::string value;
	if (result && result->rows_count > 0 && result->rows[0]->fields[0]) {
		value = result->rows[0]->fields[0];
	}
	free(error);
	delete result;
	return value;
}

static int query_int(SQLite3DB* db, const char* query) {
	return db->return_one_int(query);
}

static std::string hgm_query_string(const char* query) {
	char* error = nullptr;
	SQLite3_result* result = MyHGM->execute_query(const_cast<char*>(query), &error);
	std::string value;
	if (!error && result && result->rows_count > 0 && result->rows[0]->fields[0]) {
		value = result->rows[0]->fields[0];
	}
	free(error);
	delete result;
	return value;
}

static int hgm_query_int(const char* query) {
	const std::string value = hgm_query_string(query);
	return value.empty() ? 0 : atoi(value.c_str());
}

static SQLite3DB* make_database() {
	SQLite3DB* db = new SQLite3DB();
	db->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	return db;
}

static const char* const AURORA_COLUMNS[] = {
	"writer_hostgroup", "reader_hostgroup", "green_writer_hostgroup", "green_reader_hostgroup",
	"active", "aurora_port", "domain_name", "max_lag_ms", "check_interval_ms",
	"check_timeout_ms", "writer_is_also_reader", "new_reader_weight", "add_lag_ms",
	"min_lag_ms", "lag_num_checks", "autopurge_missing_checks", "comment"
};

static SQLite3_result* make_candidate(bool legacy = false) {
	SQLite3_result* result = new SQLite3_result(legacy ? 15 : 17);
	for (size_t i = 0; i < 17; ++i) {
		if (legacy && (i == 2 || i == 3)) {
			continue;
		}
		result->add_column_definition(SQLITE_TEXT, AURORA_COLUMNS[i]);
	}
	return result;
}

static void add_candidate_row(
	SQLite3_result* result,
	int writer,
	int reader,
	const char* green_writer,
	const char* green_reader,
	bool active,
	const char* comment = "test"
) {
	const std::string writer_value = std::to_string(writer);
	const std::string reader_value = std::to_string(reader);
	const char* fields[] = {
		writer_value.c_str(), reader_value.c_str(), green_writer, green_reader,
		active ? "1" : "0", "3306", ".cluster.example", "600000", "1000", "800",
		"0", "1", "30", "30", "1", "0", comment
	};
	result->add_row(fields);
}

static void add_legacy_candidate_row(SQLite3_result* result, int writer, int reader) {
	const std::string writer_value = std::to_string(writer);
	const std::string reader_value = std::to_string(reader);
	const char* fields[] = {
		writer_value.c_str(), reader_value.c_str(), "1", "3306", ".legacy.example", "600000",
		"1000", "800", "0", "1", "30", "30", "1", "0", "legacy"
	};
	result->add_row(fields);
}

static bool contains_error(const std::vector<std::string>& errors, const std::string& first, const std::string& second = "") {
	for (const std::string& error : errors) {
		if (error.find(first) != std::string::npos &&
			(second.empty() || error.find(second) != std::string::npos)) {
			return true;
		}
	}
	return false;
}

static bool contains_writer(SQLite3_result* result, int writer) {
	for (SQLite3_row* row : result->rows) {
		if (row->fields[0] && atoi(row->fields[0]) == writer) {
			return true;
		}
	}
	return false;
}

static void test_schema_contract() {
	SQLite3DB* db = make_database();
	db->execute(ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS);
	db->execute(ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_AWS_AURORA_HOSTGROUPS);

	const std::string configured_columns =
		"writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,active,"
		"aurora_port,domain_name,max_lag_ms,check_interval_ms,check_timeout_ms,writer_is_also_reader,"
		"new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,autopurge_missing_checks,comment";
	const std::string runtime_columns = configured_columns + ",bgd_status";

	ok(query_string(db, "SELECT GROUP_CONCAT(name, ',') FROM pragma_table_info('mysql_aws_aurora_hostgroups')") == configured_columns,
		"Aurora configured columns follow the BGD contract order");
	ok(query_string(db, "SELECT GROUP_CONCAT(name, ',') FROM pragma_table_info('runtime_mysql_aws_aurora_hostgroups')") == runtime_columns,
		"Aurora runtime columns append bgd_status");
	ok(query_string(db, "SELECT dflt_value FROM pragma_table_info('mysql_aws_aurora_hostgroups') WHERE name='green_writer_hostgroup'") == "NULL",
		"configured green_writer_hostgroup defaults to NULL");
	ok(query_string(db, "SELECT dflt_value FROM pragma_table_info('mysql_aws_aurora_hostgroups') WHERE name='green_reader_hostgroup'") == "NULL",
		"configured green_reader_hostgroup defaults to NULL");
	ok(query_string(db, "SELECT dflt_value FROM pragma_table_info('runtime_mysql_aws_aurora_hostgroups') WHERE name='green_writer_hostgroup'") == "NULL",
		"runtime green_writer_hostgroup defaults to NULL");
	ok(query_string(db, "SELECT dflt_value FROM pragma_table_info('runtime_mysql_aws_aurora_hostgroups') WHERE name='green_reader_hostgroup'") == "NULL",
		"runtime green_reader_hostgroup defaults to NULL");
	ok(query_string(db, "SELECT dflt_value FROM pragma_table_info('runtime_mysql_aws_aurora_hostgroups') WHERE name='bgd_status'") == "'NONE'",
		"runtime bgd_status defaults to NONE");
	ok(query_int(db, "SELECT COUNT(*) FROM pragma_table_info('mysql_aws_aurora_hostgroups') WHERE name='bgd_status'") == 0,
		"bgd_status is absent from configured Aurora rows");
	ok(!db->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,domain_name) VALUES (1,2,-1,3,'.negative.example')"),
		"configured schema rejects a negative green writer hostgroup");
	ok(!db->execute("INSERT INTO runtime_mysql_aws_aurora_hostgroups (writer_hostgroup,reader_hostgroup,green_writer_hostgroup,green_reader_hostgroup,domain_name) VALUES (1,2,3,-1,'.negative.example')"),
		"runtime schema rejects a negative green reader hostgroup");
	delete db;

	SQLite3DB* hgm_db = make_database();
	hgm_db->execute(MYHGM_MYSQL_AWS_AURORA_HOSTGROUPS);
	ok(query_string(hgm_db, "SELECT GROUP_CONCAT(name, ',') FROM pragma_table_info('mysql_aws_aurora_hostgroups')") == runtime_columns,
		"HGM Aurora columns match the runtime contract");
	ok(query_string(hgm_db, "SELECT dflt_value FROM pragma_table_info('mysql_aws_aurora_hostgroups') WHERE name='bgd_status'") == "'NONE'",
		"HGM bgd_status defaults to NONE");
	delete hgm_db;
}

static void test_row_validation() {
	SQLite3_result* candidate = make_candidate();
	add_candidate_row(candidate, 10, 20, nullptr, nullptr, true);
	add_candidate_row(candidate, 30, 40, "31", "41", true);
	add_candidate_row(candidate, 50, 60, "51", nullptr, true);
	add_candidate_row(candidate, 70, 80, "70", "81", true);
	add_candidate_row(candidate, 90, 100, "91", "101", true);
	add_candidate_row(candidate, 110, 120, "111", "90", true);
	add_candidate_row(candidate, 130, 140, nullptr, nullptr, true);

	std::vector<std::string> errors;
	SQLite3_result* filtered = validate_and_filter_aws_aurora_hostgroups(candidate, errors);
	ok(filtered->rows_count == 3, "mixed LOAD publishes only its three valid Aurora rows");
	ok(contains_writer(filtered, 10), "paired NULL green hostgroups are valid");
	ok(contains_writer(filtered, 30), "four distinct configured hostgroups are valid");
	ok(contains_writer(filtered, 130), "an unrelated valid row survives other validation failures");
	ok(contains_error(errors, "writer_hostgroup=50", "green_reader_hostgroup=NULL"),
		"mixed NULL validation identifies the rejected writer and fields");
	ok(contains_error(errors, "writer_hostgroup=70", "conflicting fields"),
		"same-row overlap identifies the rejected writer and fields");
	ok(contains_error(errors, "writer_hostgroup=90", "writer_hostgroup=110"),
		"first active row in a cross-row conflict identifies the other writer");
	ok(contains_error(errors, "writer_hostgroup=110", "writer_hostgroup=90"),
		"second active row in a cross-row conflict identifies the other writer");
	delete filtered;
	delete candidate;
}

static void test_inactive_cross_row_validation() {
	SQLite3_result* candidate = make_candidate();
	add_candidate_row(candidate, 150, 160, nullptr, nullptr, true);
	add_candidate_row(candidate, 170, 180, "171", "150", false);

	std::vector<std::string> errors;
	SQLite3_result* filtered = validate_and_filter_aws_aurora_hostgroups(candidate, errors);
	ok(filtered->rows_count == 1, "an inactive row conflicting with an active row is isolated");
	ok(contains_writer(filtered, 150), "the active owner survives an inactive conflicting row");
	ok(contains_error(errors, "writer_hostgroup=170", "writer_hostgroup=150"),
		"inactive conflict reports the active owner");
	ok(!contains_error(errors, "mysql_aws_aurora_hostgroups writer_hostgroup=150 rejected:"),
		"inactive roles do not invalidate the active owner");
	delete filtered;
	delete candidate;
}

static void test_legacy_projection_normalization() {
	SQLite3_result* candidate = make_candidate(true);
	add_legacy_candidate_row(candidate, 190, 200);

	std::vector<std::string> errors;
	SQLite3_result* filtered = validate_and_filter_aws_aurora_hostgroups(candidate, errors);
	ok(filtered->columns == 17 && filtered->rows_count == 1,
		"legacy Aurora projection is normalized to the configured BGD shape");
	ok(filtered->rows[0]->fields[2] == nullptr && filtered->rows[0]->fields[3] == nullptr,
		"legacy projection normalizes both green hostgroups to SQL NULL");
	ok(errors.empty(), "legacy Aurora projection remains valid");
	delete filtered;
	delete candidate;
}

static void test_invalid_replacement_removes_previous_row() {
	SQLite3_result* initial = make_candidate();
	add_candidate_row(initial, 210, 220, "211", "221", true);
	std::vector<std::string> initial_errors;
	SQLite3_result* initial_filtered = validate_and_filter_aws_aurora_hostgroups(initial, initial_errors);
	ok(initial_filtered->rows_count == 1, "initial valid Aurora row is publishable");

	SQLite3_result* replacement = make_candidate();
	add_candidate_row(replacement, 210, 220, "211", nullptr, true);
	std::vector<std::string> replacement_errors;
	SQLite3_result* replacement_filtered = validate_and_filter_aws_aurora_hostgroups(replacement, replacement_errors);
	ok(replacement_filtered->rows_count == 0,
		"invalid replacement omits a previously published writer from the atomic replacement");
	ok(contains_error(replacement_errors, "writer_hostgroup=210", "must both be NULL"),
		"invalid replacement reports its former writer owner");

	delete replacement_filtered;
	delete replacement;
	delete initial_filtered;
	delete initial;
}

static void test_runtime_ownership_and_status() {
	SQLite3_result* initial = make_candidate();
	add_candidate_row(initial, 300, 310, "301", "311", true);
	add_candidate_row(initial, 320, 330, nullptr, nullptr, true);
	TestAuroraBGDRuntime::reload(MyHGM, initial);

	int green_writer = 0;
	int green_reader = 0;
	ok(TestAuroraBGDRuntime::green_hostgroups(MyHGM, 300, green_writer, green_reader) &&
		green_writer == 301 && green_reader == 311,
		"Aurora runtime info owns configured green hostgroups");
	ok(TestAuroraBGDRuntime::green_hostgroups(MyHGM, 320, green_writer, green_reader) &&
		green_writer == -1 && green_reader == -1,
		"SQL NULL green hostgroups use the -1 runtime sentinel");
	ok(hgm_query_string(
		"SELECT GROUP_CONCAT(bgd_status, ',') FROM "
		"(SELECT bgd_status FROM mysql_aws_aurora_hostgroups ORDER BY writer_hostgroup)"
	) == "NONE,NONE", "new Aurora runtime rows start in NONE");

	SQLite3_result* dump = MyHGM->dump_table_mysql("mysql_aws_aurora_hostgroups");
	ok(dump && dump->columns == 18, "Aurora runtime dump includes configured fields and bgd_status");
	delete dump;

	MyHGM->update_aws_aurora_bgd_status(300, "AVAILABLE");
	ok(hgm_query_string(
		"SELECT bgd_status FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=300"
	) == "AVAILABLE", "Aurora BGD status API publishes an accepted state");
	const char* accepted_statuses[] = {
		"NONE",
		"AVAILABLE",
		"SWITCHOVER_INITIATED",
		"SWITCHOVER_IN_PROGRESS",
		"SWITCHOVER_IN_POST_PROCESSING",
		"SWITCHOVER_COMPLETED"
	};
	bool accepted_all_statuses = true;
	for (const char* status : accepted_statuses) {
		MyHGM->update_aws_aurora_bgd_status(300, status);
		accepted_all_statuses = accepted_all_statuses && hgm_query_string(
			"SELECT bgd_status FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=300"
		) == status;
	}
	ok(accepted_all_statuses, "Aurora BGD status API accepts the complete state vocabulary");
	MyHGM->update_aws_aurora_bgd_status(300, "AVAILABLE");

	SQLite3_result* unrelated_reload = make_candidate();
	add_candidate_row(unrelated_reload, 300, 310, "302", "312", true, "reloaded");
	TestAuroraBGDRuntime::reload(MyHGM, unrelated_reload);
	ok(hgm_query_string(
		"SELECT bgd_status FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=300"
	) == "AVAILABLE", "configuration reload preserves the runtime BGD status");
	ok(TestAuroraBGDRuntime::green_hostgroups(MyHGM, 300, green_writer, green_reader) &&
		green_writer == 302 && green_reader == 312,
		"configuration reload updates runtime green hostgroups");

	MyHGM->update_aws_aurora_bgd_status(300, "NOT_A_BGD_STATUS");
	ok(hgm_query_string(
		"SELECT bgd_status FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=300"
	) == "AVAILABLE", "invalid Aurora BGD status leaves runtime state unchanged");

	SQLite3_result* concurrent_reload = make_candidate();
	add_candidate_row(concurrent_reload, 300, 310, "303", "313", true, "concurrent");
	std::thread reload_thread([concurrent_reload]() {
		TestAuroraBGDRuntime::reload(MyHGM, concurrent_reload);
	});
	std::thread status_thread([]() {
		MyHGM->update_aws_aurora_bgd_status(300, "SWITCHOVER_IN_PROGRESS");
	});
	reload_thread.join();
	status_thread.join();
	ok(hgm_query_string(
		"SELECT bgd_status FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=300"
	) == "SWITCHOVER_IN_PROGRESS", "reload and status publication serialize without losing state");
	ok(TestAuroraBGDRuntime::green_hostgroups(MyHGM, 300, green_writer, green_reader) &&
		green_writer == 303 && green_reader == 313,
		"serialized reload publishes its configured values");

	SQLite3_result* empty_reload = make_candidate();
	TestAuroraBGDRuntime::reload(MyHGM, empty_reload);
	ok(hgm_query_int(
		"SELECT COUNT(*) FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=300"
	) == 0, "removing an Aurora deployment removes its runtime status row");
	ok(!TestAuroraBGDRuntime::green_hostgroups(MyHGM, 300, green_writer, green_reader),
		"removing an Aurora deployment removes its runtime info");
}

int main() {
	plan(44);
	test_init_minimal();

	test_schema_contract();       // 12
	test_row_validation();         // 8
	test_inactive_cross_row_validation(); // 4
	test_legacy_projection_normalization(); // 3
	test_invalid_replacement_removes_previous_row(); // 3

	ok(test_init_hostgroups() == 0, "test_init_hostgroups() succeeds"); // 1
	test_runtime_ownership_and_status(); // 13
	test_cleanup_hostgroups();

	test_cleanup_minimal();
	return exit_status();
}
