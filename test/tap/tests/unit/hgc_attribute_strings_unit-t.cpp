/**
 * @file hgc_attribute_strings_unit-t.cpp
 * @brief Worker threads' copy of the hostgroup attribute strings (init_connect,
 *   and aws_iam_region with PROXYSQL40).
 *
 * LOAD ... SERVERS TO RUNTIME frees and replaces these strings in the
 * hostgroup. Workers never read them there: each keeps a copy
 * (Base_Thread::hostgroup_strings), re-copied under the Hostgroup Manager lock
 * when servers_table_version changes. These tests check that:
 * - the copy is taken only when the version changes;
 * - it holds the hostgroups that have a string set, and only those;
 * - a copy stays valid after the hostgroup's string is replaced (no reader
 *   ever points into memory a reload frees; ASan would abort);
 * - clearing a string removes it from the next copy;
 * - both the MySQL and the PostgreSQL Hostgroup Managers provide it.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "MySQL_HostGroups_Manager.h"
#include "PgSQL_HostGroups_Manager.h"
#include "Base_Thread.h"

#include <string>

extern MySQL_HostGroups_Manager *MyHGM;
extern PgSQL_HostGroups_Manager *PgHGM;

namespace {

constexpr unsigned int kHid = 7;
constexpr unsigned int kOtherHid = 8;

/** @brief Base_Thread is all a worker needs for the copy. */
class TestWorker : public Base_Thread {};

MyHGC* mysql_hostgroup(unsigned int hid) {
	MyHGM->wrlock();
	MyHGC* hgc = MyHGM->MyHGC_lookup(hid);
	MyHGM->wrunlock();
	return hgc;
}

/** @brief What LOAD MYSQL SERVERS TO RUNTIME does: replace under the lock, then bump the version. */
void reload_mysql_hostgroup(MyHGC* hgc, const char* init_connect, const char* region) {
	MyHGM->wrlock();
	hgc->set_attribute_init_connect(init_connect);
#ifdef PROXYSQL40
	hgc->set_attribute_aws_iam_region(region);
#else
	(void)region;
#endif // PROXYSQL40
	MyHGM->status.servers_table_version++;
	MyHGM->wrunlock();
}

std::string init_connect_of(const TestWorker& worker, unsigned int hid) {
	const HostgroupStrings* strings = worker.hostgroup_strings_for(hid);
	return strings != nullptr ? strings->init_connect : "<none>";
}

void test_mysql_copy() {
	TestWorker worker;
	MyHGC* hgc = mysql_hostgroup(kHid);
	mysql_hostgroup(kOtherHid); // a hostgroup without strings

	MyHGM->wrlock();
	hgc->set_attribute_init_connect("SET sql_mode=''");
	MyHGM->wrunlock();
	worker.refresh_hostgroup_strings(MyHGM);
	ok(worker.hostgroup_strings_for(kHid) == nullptr,
		"no copy while servers_table_version is unchanged");

	reload_mysql_hostgroup(hgc, "SET sql_mode=''", "us-east-1");
	worker.refresh_hostgroup_strings(MyHGM);
	const HostgroupStrings* copied = worker.hostgroup_strings_for(kHid);
	bool region_ok = true;
#ifdef PROXYSQL40
	region_ok = copied != nullptr && copied->aws_iam_region == "us-east-1";
#endif // PROXYSQL40
	ok(copied != nullptr && copied->init_connect == "SET sql_mode=''" && region_ok &&
		worker.hostgroup_strings_version == MyHGM->servers_table_version_relaxed(),
		"a version change copies the strings and records the version");
	ok(worker.hostgroup_strings_for(kOtherHid) == nullptr && worker.hostgroup_strings.size() == 1,
		"hostgroups without strings are not copied");

	// The reload frees the string the copy was taken from; the copy is unaffected.
	reload_mysql_hostgroup(hgc, "SET autocommit=1", nullptr);
	ok(copied->init_connect == "SET sql_mode=''",
		"the copy stays valid after the hostgroup's string is replaced");
	worker.refresh_hostgroup_strings(MyHGM);
	ok(init_connect_of(worker, kHid) == "SET autocommit=1",
		"the next refresh picks up the replaced string");

	reload_mysql_hostgroup(hgc, nullptr, nullptr);
	worker.refresh_hostgroup_strings(MyHGM);
	ok(worker.hostgroup_strings_for(kHid) == nullptr && worker.hostgroup_strings.empty(),
		"a cleared string is not in the next copy");
}

void test_pgsql_copy() {
	TestWorker worker;
	PgHGM->wrlock();
	PgSQL_HGC* hgc = PgHGM->MyHGC_lookup(kHid);
	hgc->set_attribute_init_connect("SET search_path TO app");
	PgHGM->status.servers_table_version++;
	PgHGM->wrunlock();
	worker.refresh_hostgroup_strings(PgHGM);
	ok(init_connect_of(worker, kHid) == "SET search_path TO app",
		"PgSQL: a version change copies init_connect");

	PgHGM->wrlock();
	hgc->reset_attributes();
	PgHGM->status.servers_table_version++;
	PgHGM->wrunlock();
	worker.refresh_hostgroup_strings(PgHGM);
	ok(worker.hostgroup_strings.empty(), "PgSQL: reset_attributes clears it from the next copy");
}

} // namespace

int main() {
	plan(6 + 2);
	test_init_minimal();
	test_init_hostgroups();

	test_mysql_copy();
	test_pgsql_copy();

	test_cleanup_hostgroups();
	test_cleanup_minimal();
	return exit_status();
}
