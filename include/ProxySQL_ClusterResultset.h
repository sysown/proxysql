#ifndef __CLASS_PROXYSQL_CLUSTER_RESULTSET_H
#define __CLASS_PROXYSQL_CLUSTER_RESULTSET_H

/**
 * @file ProxySQL_ClusterResultset.h
 * @brief Shape checks for the result sets returned by Cluster peers.
 *
 * The Cluster code reads each peer result set by fixed column index, and parses most columns with
 * atoll()/strcmp(). A peer that answers with fewer columns, or with NULL in a column the code parses,
 * made ProxySQL read past the row or dereference NULL. Every result set a peer returns is now checked
 * against the definition of its query (exact column count, and the columns that must not be NULL)
 * before any of it is used. A result set that does not match fails the sync, as a failed query does.
 *
 * The columns that must not be NULL are exactly the NOT NULL columns of the table each query reads,
 * so a healthy peer always passes. unit/cluster_resultset_unit-t checks the definitions against the
 * queries and the admin table schemas.
 */

#include <string>
#include <vector>

#include "mysql.h"

/** @brief Monitor: global checksum of the peer. */
#define CLUSTER_QUERY_GLOBAL_CHECKSUM "SELECT GLOBAL_CHECKSUM()"
/** @brief Monitor: per-module checksums of the peer. */
#define CLUSTER_QUERY_CHECKSUMS "SELECT * FROM runtime_checksums_values ORDER BY name"
/** @brief Monitor: status counters of the peer. */
#define CLUSTER_QUERY_METRICS "SELECT * FROM stats_mysql_global ORDER BY Variable_Name"
/** @brief Pull of 'proxysql_servers'. */
#define CLUSTER_QUERY_PROXYSQL_SERVERS "SELECT hostname, port, weight, comment FROM runtime_proxysql_servers ORDER BY hostname, port"
/** @brief Pull of 'mysql_ldap_mapping', with the MySQL users. */
#define CLUSTER_QUERY_MYSQL_LDAP_MAPPING "SELECT priority, frontend_entity, backend_entity, comment FROM mysql_ldap_mapping ORDER BY priority"
/**
 * @brief Pull of admin/mysql/ldap/pgsql variables. The pull appends a WHERE clause selecting the
 *   variables of one module; the result set has the same shape for every module.
 */
#define CLUSTER_QUERY_GLOBAL_VARIABLES "SELECT * FROM runtime_global_variables"

/** @brief Expected shape of the result set of one Cluster query. */
struct ProxySQL_ClusterResultsetSpec {
	/** @brief The query, as sent to the peer. */
	const char* query;
	/** @brief The table the columns come from; used by the unit test to check the definition. */
	const char* table;
	/** @brief Exact number of columns. */
	unsigned int num_fields;
	/** @brief Columns that must not be NULL. */
	std::vector<unsigned int> non_null;
};

/** @brief The definitions of every query whose result set the Cluster code reads. */
const std::vector<ProxySQL_ClusterResultsetSpec>& proxysql_cluster_resultset_specs();

/** @brief The definition for 'query' (compared exactly), or nullptr if there is none. */
const ProxySQL_ClusterResultsetSpec* proxysql_cluster_resultset_spec(const char* query);

/**
 * @brief Checks the column count of a result set.
 * @return True if 'num_fields' matches; otherwise false, with the reason in 'error'.
 */
bool proxysql_cluster_check_num_fields(
	const ProxySQL_ClusterResultsetSpec& spec, unsigned int num_fields, std::string& error);

/**
 * @brief Finds the first column of 'row' that is NULL but must not be.
 * @param row A row with 'spec.num_fields' columns.
 * @return The column index, or -1 if the row is valid.
 */
int proxysql_cluster_null_column(const ProxySQL_ClusterResultsetSpec& spec, const char* const* row);

/**
 * @brief Checks a result set returned by a peer for 'query' against its definition.
 * @details Fails if there is no definition for 'query', if 'result' is nullptr, if the column count
 *   differs, or if a row has NULL in a column that must not be NULL. 'result' must be buffered
 *   (mysql_store_result()); it is rewound to its first row before returning.
 * @return True if the result set can be used; otherwise false, with the reason in 'error'.
 */
bool proxysql_cluster_check_resultset(MYSQL_RES* result, const char* query, std::string& error);

#endif /* __CLASS_PROXYSQL_CLUSTER_RESULTSET_H */
