#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "MySQL_HostGroups_Manager.h"
#include "proxysql.h"
#include "cpp.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"

#include <memory>
#include <pthread.h>
#include <string>
#include "gen_utils.h"

#include "prometheus/counter.h"
#include "prometheus/detail/builder.h"
#include "prometheus/family.h"
#include "prometheus/gauge.h"

#include "prometheus_helpers.h"
#include "proxysql_utils.h"

#define char_malloc (char *)malloc

#include "thread.h"
#include "wqueue.h"

#include "ev.h"

#include <functional>
#include <mutex>
#include <type_traits>

using std::function;

#include "Base_HostGroups_Manager.h"


template Base_HostGroups_Manager<MyHGC>::Base_HostGroups_Manager();
template MyHGC * Base_HostGroups_Manager<MyHGC>::MyHGC_find(unsigned int);
template MyHGC * Base_HostGroups_Manager<MyHGC>::MyHGC_create(unsigned int);
template MyHGC * Base_HostGroups_Manager<MyHGC>::MyHGC_lookup(unsigned int);
#ifdef PROXYSQL31
template HostgroupPoolStats * Base_HostGroups_Manager<MyHGC>::get_hostgroup_pool_stats(unsigned int);
template SQLite3_result * Base_HostGroups_Manager<MyHGC>::SQL3_Hostgroup_Connection_Pool(bool);
#endif
template void Base_HostGroups_Manager<MyHGC>::wrlock();
template void Base_HostGroups_Manager<MyHGC>::wrunlock();

template Base_HostGroups_Manager<PgSQL_HGC>::Base_HostGroups_Manager();
template PgSQL_HGC * Base_HostGroups_Manager<PgSQL_HGC>::MyHGC_find(unsigned int);
template PgSQL_HGC * Base_HostGroups_Manager<PgSQL_HGC>::MyHGC_create(unsigned int);
template PgSQL_HGC * Base_HostGroups_Manager<PgSQL_HGC>::MyHGC_lookup(unsigned int);
#ifdef PROXYSQL31
template HostgroupPoolStats * Base_HostGroups_Manager<PgSQL_HGC>::get_hostgroup_pool_stats(unsigned int);
template SQLite3_result * Base_HostGroups_Manager<PgSQL_HGC>::SQL3_Hostgroup_Connection_Pool(bool);
#endif
template void Base_HostGroups_Manager<PgSQL_HGC>::wrlock();
template void Base_HostGroups_Manager<PgSQL_HGC>::wrunlock();

template SQLite3_result * Base_HostGroups_Manager<MyHGC>::execute_query(char*, char**);
template SQLite3_result * Base_HostGroups_Manager<PgSQL_HGC>::execute_query(char*, char**);


template <typename HGC>
Base_HostGroups_Manager<HGC>::Base_HostGroups_Manager() {
	pthread_mutex_init(&readonly_mutex, NULL);
	pthread_mutex_init(&lock, NULL);
	admindb=NULL;	// initialized only if needed
	mydb=new SQLite3DB();
}


// wrlock() is only required during commit()
template <typename HGC>
void Base_HostGroups_Manager<HGC>::wrlock() {
	pthread_mutex_lock(&lock);
#ifdef DEBUG
	is_locked = true;
#endif
}


template <typename HGC>
void Base_HostGroups_Manager<HGC>::wrunlock() {
#ifdef DEBUG
	is_locked = false;
#endif
	pthread_mutex_unlock(&lock);
}


/**
 * @brief Execute a SQL query and retrieve the resultset.
 *
 * This function executes a SQL query using the provided query string and returns the resultset obtained from the
 * database operation. It also provides an optional error parameter to capture any error messages encountered during
 * query execution.
 *
 * @param query A pointer to a null-terminated string containing the SQL query to be executed.
 * @param error A pointer to a char pointer where any error message encountered during query execution will be stored.
 *              Pass nullptr if error handling is not required.
 * @return A pointer to a SQLite3_result object representing the resultset obtained from the query execution. This
 *         pointer may be nullptr if the query execution fails or returns an empty result.
 */
template <typename HGC>
SQLite3_result * Base_HostGroups_Manager<HGC>::execute_query(char *query, char **error) {
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	wrlock();
	mydb->execute_statement(query, error , &cols , &affected_rows , &resultset);
	wrunlock();
	return resultset;
}

/**
 * @brief Create a new MySQL host group container.
 *
 * This function creates a new instance of the MySQL host group container (`MyHGC`) with
 * the specified host group ID and returns a pointer to it.
 *
 * @param _hid The host group ID for the new container.
 * @return A pointer to the newly created `MyHGC` instance.
 */
template <typename HGC>
HGC * Base_HostGroups_Manager<HGC>::MyHGC_create(unsigned int _hid) {
	HGC *myhgc=new HGC(_hid);
	return myhgc;
}

/**
 * @brief Find a MySQL host group container by host group ID.
 *
 * This function searches for a MySQL host group container with the specified host group ID
 * in the list of host groups. If found, it returns a pointer to the container; otherwise,
 * it returns a null pointer.
 *
 * @param _hid The host group ID to search for.
 * @return A pointer to the found `MyHGC` instance if found; otherwise, a null pointer.
 */
template <typename HGC>
HGC * Base_HostGroups_Manager<HGC>::MyHGC_find(unsigned int _hid) {
	if (MyHostGroups->len < 100) {
		// for few HGs, we use the legacy search
		for (unsigned int i=0; i<MyHostGroups->len; i++) {
			HGC *myhgc=(HGC *)MyHostGroups->index(i);
			if (myhgc->hid==_hid) {
				return myhgc;
			}
		}
	} else {
		// for a large number of HGs, we use the unordered_map
		// this search is slower for a small number of HGs, therefore we use
		// it only for large number of HGs
		typename std::unordered_map<unsigned int, HGC *>::const_iterator it = MyHostGroups_map.find(_hid);
		if (it != MyHostGroups_map.end()) {
			HGC *myhgc = it->second;
			return myhgc;
		}
	}
	return NULL;
}

/**
 * @brief Lookup or create a MySQL host group container by host group ID.
 *
 * This function looks up a MySQL host group container with the specified host group ID. If
 * found, it returns a pointer to the existing container; otherwise, it creates a new container
 * with the specified host group ID, adds it to the list of host groups, and returns a pointer
 * to it.
 *
 * @param _hid The host group ID to lookup or create.
 * @return A pointer to the found or newly created `MyHGC` instance.
 * @note The function assertion fails if a newly created container is not found.
 */
template <typename HGC>
HGC * Base_HostGroups_Manager<HGC>::MyHGC_lookup(unsigned int _hid) {
	HGC *myhgc=NULL;
	myhgc=MyHGC_find(_hid);
	if (myhgc==NULL) {
		myhgc=MyHGC_create(_hid);
	} else {
		return myhgc;
	}
	assert(myhgc);
	MyHostGroups->add(myhgc);
	MyHostGroups_map.emplace(_hid,myhgc);
	return myhgc;
}

#ifdef PROXYSQL31
template <typename HGC>
HostgroupPoolStats * Base_HostGroups_Manager<HGC>::get_hostgroup_pool_stats(unsigned int hid) {
	wrlock();
	HGC *hgc = MyHGC_find(hid);
	wrunlock();
	return hgc ? &hgc->pool_stats : nullptr;
}

template <typename HGC>
SQLite3_result * Base_HostGroups_Manager<HGC>::SQL3_Hostgroup_Connection_Pool(bool reset) {
	auto result = std::make_unique<SQLite3_result>(5);
	result->add_column_definition(SQLITE_TEXT, "hostgroup");
	result->add_column_definition(SQLITE_TEXT, "acquisitions_total");
	result->add_column_definition(SQLITE_TEXT, "waits_total");
	result->add_column_definition(SQLITE_TEXT, "wait_time_us_total");
	result->add_column_definition(SQLITE_TEXT, "waiters");

	wrlock();
	for (unsigned int i = 0; i < MyHostGroups->len; ++i) {
		HGC *hgc = static_cast<HGC *>(MyHostGroups->index(i));
		const HostgroupPoolStatsSnapshot snapshot = reset
			? hgc->pool_stats.reset_window()
			: hgc->pool_stats.window_snapshot();
		const std::string hostgroup = std::to_string(hgc->hid);
		const std::string acquisitions = std::to_string(snapshot.acquisitions_total);
		const std::string waits = std::to_string(snapshot.waits_total);
		const std::string wait_time = std::to_string(snapshot.wait_time_us_total);
		const std::string waiters = std::to_string(snapshot.waiters);
		const char *row[] = {
			hostgroup.c_str(),
			acquisitions.c_str(),
			waits.c_str(),
			wait_time.c_str(),
			waiters.c_str()
		};
		result->add_row(row);
	}
	wrunlock();
	return result.release();
}
#endif

