#include "ProxySQL_ClusterResultset.h"

#include <cstring>

#include "proxysql.h"
#include "cpp.h"
#include "ProxySQL_Cluster.hpp"

namespace {

/** @brief Columns 'first' to 'last', both included. */
std::vector<unsigned int> columns(unsigned int first, unsigned int last) {
	std::vector<unsigned int> res {};
	for (unsigned int i = first; i <= last; i++) {
		res.push_back(i);
	}
	return res;
}

} // namespace

const std::vector<ProxySQL_ClusterResultsetSpec>& proxysql_cluster_resultset_specs() {
	// 'non_null' lists the NOT NULL columns of 'table'; unit/cluster_resultset_unit-t checks it.
	static const std::vector<ProxySQL_ClusterResultsetSpec> specs {
		// Monitor
		{ CLUSTER_QUERY_GLOBAL_CHECKSUM, nullptr, 1, { 0 } },
		{ CLUSTER_QUERY_CHECKSUMS, "runtime_checksums_values", 4, columns(0, 3) },
		{ CLUSTER_QUERY_METRICS, "stats_mysql_global", 2, columns(0, 1) },
		// Variables and ProxySQL servers
		{ CLUSTER_QUERY_GLOBAL_VARIABLES, "runtime_global_variables", 2, columns(0, 1) },
		{ CLUSTER_QUERY_PGSQL_VARIABLES, "runtime_global_variables", 2, columns(0, 1) },
		{ CLUSTER_QUERY_PROXYSQL_SERVERS, "runtime_proxysql_servers", 4, columns(0, 3) },
		// MySQL users and query rules
		{ CLUSTER_QUERY_MYSQL_USERS, "runtime_mysql_users", 13, { 0, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12 } },
		{ CLUSTER_QUERY_MYSQL_LDAP_MAPPING, "mysql_ldap_mapping", 4, columns(0, 3) },
		{ CLUSTER_QUERY_MYSQL_QUERY_RULES, "runtime_mysql_query_rules", 34, { 0, 3, 10, 31, 32 } },
		{ CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING, "runtime_mysql_query_rules_fast_routing", 5, columns(0, 4) },
		// MySQL servers
		{ CLUSTER_QUERY_RUNTIME_MYSQL_SERVERS, "runtime_mysql_servers", 12, columns(0, 11) },
		{ CLUSTER_QUERY_MYSQL_SERVERS_V2, "mysql_servers", 12, columns(0, 11) },
		{ CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS, "runtime_mysql_replication_hostgroups", 4, columns(0, 3) },
		{ CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS, "runtime_mysql_group_replication_hostgroups", 9, columns(0, 7) },
		{ CLUSTER_QUERY_MYSQL_GALERA, "runtime_mysql_galera_hostgroups", 9, columns(0, 7) },
		{ CLUSTER_QUERY_MYSQL_AWS_AURORA, "runtime_mysql_aws_aurora_hostgroups", 15, columns(0, 13) },
		{ CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES, "runtime_mysql_hostgroup_attributes", 12, columns(0, 11) },
		{ CLUSTER_QUERY_MYSQL_SERVERS_SSL_PARAMS, "runtime_mysql_servers_ssl_params", 12, columns(0, 11) },
		{ CLUSTER_QUERY_MYSQL_AWS_RDS_BGD, "runtime_mysql_aws_rds_bgd_hostgroups", 11, { 0, 1, 4, 5, 6, 7, 8, 9, 10 } },
		// PostgreSQL users and query rules
		{ CLUSTER_QUERY_PGSQL_USERS, "runtime_pgsql_users", 11, { 0, 2, 3, 4, 5, 6, 7, 8, 9, 10 } },
		{ CLUSTER_QUERY_PGSQL_QUERY_RULES, "runtime_pgsql_query_rules", 33, { 0, 3, 10, 30, 31 } },
		{ CLUSTER_QUERY_PGSQL_QUERY_RULES_FAST_ROUTING, "runtime_pgsql_query_rules_fast_routing", 5, columns(0, 4) },
		// PostgreSQL servers
		{ CLUSTER_QUERY_RUNTIME_PGSQL_SERVERS, "runtime_pgsql_servers", 11, columns(0, 10) },
		{ CLUSTER_QUERY_PGSQL_SERVERS_V2, "pgsql_servers", 11, columns(0, 10) },
		{ CLUSTER_QUERY_PGSQL_REPLICATION_HOSTGROUPS, "runtime_pgsql_replication_hostgroups", 4, columns(0, 3) },
		{ CLUSTER_QUERY_PGSQL_HOSTGROUP_ATTRIBUTES, "runtime_pgsql_hostgroup_attributes", 12, columns(0, 11) },
		{ CLUSTER_QUERY_PGSQL_SERVERS_SSL_PARAMS, "runtime_pgsql_servers_ssl_params", 10, columns(0, 9) },
	};
	return specs;
}

const ProxySQL_ClusterResultsetSpec* proxysql_cluster_resultset_spec(const char* query) {
	if (query == nullptr) {
		return nullptr;
	}
	for (const auto& spec : proxysql_cluster_resultset_specs()) {
		if (strcmp(spec.query, query) == 0) {
			return &spec;
		}
	}
	return nullptr;
}

bool proxysql_cluster_check_num_fields(
	const ProxySQL_ClusterResultsetSpec& spec, unsigned int num_fields, std::string& error
) {
	if (num_fields == spec.num_fields) {
		return true;
	}
	error = std::to_string(num_fields) + " columns, expected " + std::to_string(spec.num_fields);
	return false;
}

int proxysql_cluster_null_column(const ProxySQL_ClusterResultsetSpec& spec, const char* const* row) {
	for (unsigned int col : spec.non_null) {
		if (row[col] == nullptr) {
			return static_cast<int>(col);
		}
	}
	return -1;
}

bool proxysql_cluster_check_resultset(MYSQL_RES* result, const char* query, std::string& error) {
	const ProxySQL_ClusterResultsetSpec* spec = proxysql_cluster_resultset_spec(query);
	if (spec == nullptr) {
		error = "no result set definition for this query";
		return false;
	}
	if (result == nullptr) {
		error = "no result set";
		return false;
	}
	if (!proxysql_cluster_check_num_fields(*spec, mysql_num_fields(result), error)) {
		return false;
	}

	const MYSQL_FIELD* fields = mysql_fetch_fields(result);
	bool valid = true;
	unsigned long long row_num = 0;
	while (MYSQL_ROW row = mysql_fetch_row(result)) {
		row_num++;
		const int col = proxysql_cluster_null_column(*spec, row);
		if (col >= 0) {
			error = "NULL in column " + std::to_string(col);
			if (fields != nullptr && fields[col].name != nullptr) {
				error += std::string(" (") + fields[col].name + ")";
			}
			error += " of row " + std::to_string(row_num);
			valid = false;
			break;
		}
	}
	mysql_data_seek(result, 0);

	return valid;
}
