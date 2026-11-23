/**
 * @file cluster_resultset_unit-t.cpp
 * @brief Unit tests for the Cluster peer result set checks (ProxySQL_ClusterResultset.h, #6676).
 *
 * The Cluster code reads peer result sets by fixed column index and parses most columns with
 * atoll()/strcmp(); a peer returning fewer columns, or NULL in a parsed column, made ProxySQL read
 * past the row or dereference NULL. Every peer result set is now checked against the definition of
 * its query before it is used.
 *
 * - Each definition is checked against its query and the admin schema of the table it reads: the
 *   column count must match the query, and the columns that must not be NULL must be exactly the
 *   NOT NULL columns of the table. A healthy peer can then never fail the check, and a schema change
 *   that is not reflected in the definitions fails this test.
 * - proxysql_cluster_check_resultset() is run on MYSQL_RES objects built in memory.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "sqlite3db.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "ProxySQL_Cluster.hpp"
#include "ProxySQL_ClusterResultset.h"

#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace {

/** @brief The admin tables the Cluster queries read. */
const char* const TABLE_DEFINITIONS[] = {
	ADMIN_SQLITE_RUNTIME_CHECKSUMS_VALUES,
	STATS_SQLITE_TABLE_MYSQL_GLOBAL,
	ADMIN_SQLITE_RUNTIME_GLOBAL_VARIABLES,
	ADMIN_SQLITE_TABLE_RUNTIME_PROXYSQL_SERVERS,
	ADMIN_SQLITE_RUNTIME_MYSQL_USERS,
	ADMIN_SQLITE_TABLE_MYSQL_LDAP_MAPPING,
	ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_QUERY_RULES,
	ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_QUERY_RULES_FAST_ROUTING,
	ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS,
	ADMIN_SQLITE_TABLE_MYSQL_SERVERS,
	ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_REPLICATION_HOSTGROUPS,
	ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_GROUP_REPLICATION_HOSTGROUPS,
	ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_GALERA_HOSTGROUPS,
	ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_AWS_AURORA_HOSTGROUPS,
	ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_HOSTGROUP_ATTRIBUTES,
	ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS_SSL_PARAMS,
	ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_AWS_RDS_BGD_HOSTGROUPS,
	ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_USERS,
	ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_QUERY_RULES,
	ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_QUERY_RULES_FAST_ROUTING,
	ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_SERVERS,
	ADMIN_SQLITE_TABLE_PGSQL_SERVERS,
	ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_REPLICATION_HOSTGROUPS,
	ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_HOSTGROUP_ATTRIBUTES,
	ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_SERVERS_SSL_PARAMS,
};

/** @brief Every query the Cluster code sends to a peer and reads by column index. */
const char* const CLUSTER_QUERIES[] = {
	CLUSTER_QUERY_GLOBAL_CHECKSUM, CLUSTER_QUERY_CHECKSUMS, CLUSTER_QUERY_METRICS,
	CLUSTER_QUERY_GLOBAL_VARIABLES, CLUSTER_QUERY_PGSQL_VARIABLES, CLUSTER_QUERY_PROXYSQL_SERVERS,
	CLUSTER_QUERY_MYSQL_USERS, CLUSTER_QUERY_MYSQL_LDAP_MAPPING,
	CLUSTER_QUERY_MYSQL_QUERY_RULES, CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING,
	CLUSTER_QUERY_RUNTIME_MYSQL_SERVERS, CLUSTER_QUERY_MYSQL_SERVERS_V2,
	CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS, CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS,
	CLUSTER_QUERY_MYSQL_GALERA, CLUSTER_QUERY_MYSQL_AWS_AURORA, CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES,
	CLUSTER_QUERY_MYSQL_SERVERS_SSL_PARAMS, CLUSTER_QUERY_MYSQL_AWS_RDS_BGD,
	CLUSTER_QUERY_PGSQL_USERS, CLUSTER_QUERY_PGSQL_QUERY_RULES, CLUSTER_QUERY_PGSQL_QUERY_RULES_FAST_ROUTING,
	CLUSTER_QUERY_RUNTIME_PGSQL_SERVERS, CLUSTER_QUERY_PGSQL_SERVERS_V2,
	CLUSTER_QUERY_PGSQL_REPLICATION_HOSTGROUPS, CLUSTER_QUERY_PGSQL_HOSTGROUP_ATTRIBUTES,
	CLUSTER_QUERY_PGSQL_SERVERS_SSL_PARAMS,
};

struct table_column {
	std::string name;
	bool not_null;
};

/** @brief Columns of 'table', in order. An INTEGER PRIMARY KEY column can never hold NULL. */
std::vector<table_column> table_columns(SQLite3DB& db, const std::string& table) {
	std::vector<table_column> cols {};
	char* error = nullptr;
	const std::string q = "PRAGMA table_info(" + table + ")";
	SQLite3_result* res = db.execute_statement(q.c_str(), &error);
	if (error) {
		diag("%s: %s", q.c_str(), error);
		free(error);
	}
	if (res) {
		for (SQLite3_row* row : res->rows) {
			// cid, name, type, notnull, dflt_value, pk
			const bool integer_pk = atoi(row->fields[5]) > 0 && strcasecmp(row->fields[2], "INTEGER") == 0;
			cols.push_back({ row->fields[1], strcmp(row->fields[3], "1") == 0 || integer_pk });
		}
		delete res;
	}
	return cols;
}

/** @brief Column names of the SELECT list of 'query'; "*" stands for every column of the table. */
std::vector<std::string> select_list(const std::string& query) {
	std::vector<std::string> names {};
	const size_t start = query.find("SELECT ");
	const size_t end = query.find(" FROM ");
	if (start == std::string::npos || end == std::string::npos) {
		return names;
	}
	const std::string list = query.substr(start + strlen("SELECT "), end - start - strlen("SELECT "));
	size_t pos = 0;
	while (pos <= list.size()) {
		size_t comma = list.find(',', pos);
		if (comma == std::string::npos) comma = list.size();
		std::string item = list.substr(pos, comma - pos);
		// "expr AS name" and "CASE ... END name": the name is the last word.
		while (!item.empty() && item.back() == ' ') item.pop_back();
		const size_t space = item.rfind(' ');
		names.push_back(space == std::string::npos ? item : item.substr(space + 1));
		pos = comma + 1;
	}
	return names;
}

std::string join(const std::vector<unsigned int>& v) {
	std::string s {};
	for (unsigned int i : v) s += (s.empty() ? "" : ",") + std::to_string(i);
	return s;
}

/** @brief Checks a definition against its query and the schema of its table. */
bool spec_matches_schema(SQLite3DB& db, const ProxySQL_ClusterResultsetSpec& spec, std::string& why) {
	if (spec.table == nullptr) {
		// SELECT GLOBAL_CHECKSUM(): one computed column, never NULL.
		why = "no table";
		return spec.num_fields == 1 && spec.non_null == std::vector<unsigned int> { 0 };
	}
	const std::vector<table_column> cols = table_columns(db, spec.table);
	if (cols.empty()) {
		why = "table not found";
		return false;
	}
	std::vector<std::string> names = select_list(spec.query);
	if (names.size() == 1 && names[0] == "*") {
		names.clear();
		for (const auto& c : cols) names.push_back(c.name);
	}
	if (names.size() != spec.num_fields) {
		why = "the query selects " + std::to_string(names.size()) + " columns, the definition has " +
			std::to_string(spec.num_fields);
		return false;
	}
	std::vector<unsigned int> expected {};
	for (unsigned int i = 0; i < names.size(); i++) {
		const table_column* col = nullptr;
		for (const auto& c : cols) {
			if (strcasecmp(c.name.c_str(), names[i].c_str()) == 0) col = &c;
		}
		if (col == nullptr) {
			why = "column '" + names[i] + "' is not in the table";
			return false;
		}
		if (col->not_null) expected.push_back(i);
	}
	if (expected != spec.non_null) {
		why = "non-NULL columns {" + join(spec.non_null) + "}, NOT NULL in the table {" + join(expected) + "}";
		return false;
	}
	why = std::to_string(spec.num_fields) + " columns, non-NULL {" + join(spec.non_null) + "}";
	return true;
}

/** @brief A buffered MYSQL_RES built in memory, as mysql_store_result() returns it. */
class fake_resultset {
public:
	fake_resultset(const std::vector<std::string>& names, const std::vector<std::vector<const char*>>& rows)
		: names_(names) {
		for (const auto& name : names_) {
			MYSQL_FIELD f {};
			f.name = const_cast<char*>(name.c_str());
			fields_.push_back(f);
		}
		for (const auto& r : rows) {
			std::vector<char*> values {};
			for (const char* v : r) values.push_back(const_cast<char*>(v));
			values_.push_back(values);
		}
		links_.resize(values_.size());
		for (size_t i = 0; i < values_.size(); i++) {
			links_[i].data = values_[i].data();
			links_[i].next = i + 1 < values_.size() ? &links_[i + 1] : nullptr;
		}
		data_.data = links_.empty() ? nullptr : &links_[0];
		data_.rows = links_.size();
		data_.fields = fields_.size();
		res_.field_count = fields_.size();
		res_.fields = fields_.data();
		res_.data = &data_;
		res_.data_cursor = data_.data;
		res_.row_count = links_.size();
	}
	MYSQL_RES* get() { return &res_; }

private:
	std::vector<std::string> names_;
	std::vector<MYSQL_FIELD> fields_;
	std::vector<std::vector<char*>> values_;
	std::vector<MYSQL_ROWS> links_;
	MYSQL_DATA data_ {};
	MYSQL_RES res_ {};
};

const std::vector<std::string> CHECKSUMS_COLUMNS { "name", "version", "epoch", "checksum" };

} // namespace

int main() {
	test_init_minimal();

	const auto& specs = proxysql_cluster_resultset_specs();
	plan(specs.size() + 2 + 16);

	// Definitions against the queries and the admin schemas.
	SQLite3DB db;
	db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	for (const char* def : TABLE_DEFINITIONS) {
		if (!db.execute(def)) diag("Failed to create: %s", def);
	}
	for (const auto& spec : specs) {
		std::string why {};
		const bool matches = spec_matches_schema(db, spec, why);
		ok(matches, "%s: %s", spec.table ? spec.table : spec.query, why.c_str());
	}

	{
		std::vector<std::string> missing {};
		std::set<std::string> queries {};
		for (const char* q : CLUSTER_QUERIES) {
			queries.insert(q);
			if (proxysql_cluster_resultset_spec(q) == nullptr) missing.push_back(q);
		}
		ok(missing.empty(), "every Cluster query has a definition (%zu missing)", missing.size());
		for (const auto& m : missing) diag("No definition: %s", m.c_str());
		ok(queries.size() == specs.size(), "every definition is for a Cluster query (%zu queries, %zu definitions)",
			queries.size(), specs.size());
	}

	// Lookup.
	ok(proxysql_cluster_resultset_spec(CLUSTER_QUERY_CHECKSUMS) != nullptr, "lookup: a Cluster query has a definition");
	ok(proxysql_cluster_resultset_spec("SELECT 1") == nullptr, "lookup: another query has none");
	ok(proxysql_cluster_resultset_spec(nullptr) == nullptr, "lookup: nullptr has none");

	const ProxySQL_ClusterResultsetSpec& checksums = *proxysql_cluster_resultset_spec(CLUSTER_QUERY_CHECKSUMS);
	const ProxySQL_ClusterResultsetSpec& users = *proxysql_cluster_resultset_spec(CLUSTER_QUERY_MYSQL_USERS);

	// Column count.
	{
		std::string err {};
		ok(proxysql_cluster_check_num_fields(checksums, 4, err), "column count: the expected count is accepted");
		err.clear();
		const bool refused = !proxysql_cluster_check_num_fields(checksums, 3, err);
		ok(refused && err == "3 columns, expected 4", "column count: fewer columns are refused ('%s')", err.c_str());
		err.clear();
		ok(!proxysql_cluster_check_num_fields(checksums, 5, err), "column count: more columns are refused");
	}

	// NULL columns.
	{
		const char* full[] = { "u", "p", "0", "0", "s", "0", "1", "0", "1", "1", "10000", "", "" };
		ok(proxysql_cluster_null_column(users, full) == -1, "NULL check: a row without NULL is accepted");
		const char* no_password[] = { "u", nullptr, "0", "0", nullptr, "0", "1", "0", "1", "1", "10000", "", "" };
		ok(proxysql_cluster_null_column(users, no_password) == -1,
			"NULL check: NULL in nullable columns (password, default_schema) is accepted");
		const char* no_hostgroup[] = { "u", "p", "0", nullptr, "s", "0", "1", "0", "1", "1", "10000", "", "" };
		ok(proxysql_cluster_null_column(users, no_hostgroup) == 3,
			"NULL check: NULL in default_hostgroup is reported as column 3");
	}

	// Whole result sets.
	{
		std::string err {};
		fake_resultset rs { CHECKSUMS_COLUMNS, {
			{ "admin_variables", "1", "1700000000", "0x0" },
			{ "mysql_query_rules", "2", "1700000001", "0x1" } } };
		const bool valid = proxysql_cluster_check_resultset(rs.get(), CLUSTER_QUERY_CHECKSUMS, err);
		MYSQL_ROW first = mysql_fetch_row(rs.get());
		ok(valid, "result set: a valid result set is accepted ('%s')", err.c_str());
		ok(first != nullptr && strcmp(first[0], "admin_variables") == 0, "result set: it is rewound to the first row");
	}
	{
		std::string err {};
		fake_resultset rs { CHECKSUMS_COLUMNS, {} };
		ok(proxysql_cluster_check_resultset(rs.get(), CLUSTER_QUERY_CHECKSUMS, err),
			"result set: an empty result set with the right columns is accepted");
	}
	{
		std::string err {};
		fake_resultset rs { { "name" }, { { "mysql_query_rules" } } };
		const bool refused = !proxysql_cluster_check_resultset(rs.get(), CLUSTER_QUERY_CHECKSUMS, err);
		ok(refused && err == "1 columns, expected 4",
			"result set: a single column for a 4-column query is refused ('%s')", err.c_str());
	}
	{
		std::string err {};
		fake_resultset rs { CHECKSUMS_COLUMNS, {
			{ "admin_variables", "1", "1700000000", "0x0" },
			{ "mysql_query_rules", nullptr, "1700000001", "0x1" } } };
		const bool refused = !proxysql_cluster_check_resultset(rs.get(), CLUSTER_QUERY_CHECKSUMS, err);
		ok(refused && err == "NULL in column 1 (version) of row 2",
			"result set: NULL in a NOT NULL column is refused ('%s')", err.c_str());
	}
	{
		std::string err {};
		ok(!proxysql_cluster_check_resultset(nullptr, CLUSTER_QUERY_CHECKSUMS, err), "result set: no result set is refused");
	}
	{
		std::string err {};
		fake_resultset rs { { "1" }, { { "1" } } };
		const bool refused = !proxysql_cluster_check_resultset(rs.get(), "SELECT 1", err);
		ok(refused, "result set: a query without a definition is refused ('%s')", err.c_str());
	}

	return exit_status();
}
