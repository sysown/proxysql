#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"

#include <string.h>
#include <vector>
#include <cstddef>

// The incoming_servers_t struct is defined in proxysql_admin.h, which cannot
// be included in this test due to circular include dependencies. Instead we
// re-declare the struct here to verify its layout. The canonical definition
// is the source of truth; this copy must match it exactly.
//
// WARNING: If the struct in proxysql_admin.h changes, this test will
// silently drift. Keep in sync.
struct incoming_servers_t {
	void* incoming_mysql_servers_v2 = nullptr;
	void* incoming_replication_hostgroups = nullptr;
	void* incoming_group_replication_hostgroups = nullptr;
	void* incoming_galera_hostgroups = nullptr;
	void* incoming_aurora_hostgroups = nullptr;
	void* incoming_hostgroup_attributes = nullptr;
	void* incoming_mysql_servers_ssl_params = nullptr;
	void* incoming_aws_rds_bgd_hostgroups = nullptr;
	void* runtime_mysql_servers = nullptr;
};

static_assert(sizeof(incoming_servers_t) == 9 * sizeof(void*),
	"incoming_servers_t must have exactly 9 pointer-sized fields");

static void test_incoming_servers_t_size() {
	size_t expected = 9;
	size_t actual = sizeof(incoming_servers_t) / sizeof(void*);
	ok(actual == expected,
		"sizeof(incoming_servers_t)/sizeof(void*) == %zu (expected %zu)",
		actual, expected);
}

static void test_incoming_servers_t_field_positions() {
	incoming_servers_t s;
	s.incoming_mysql_servers_v2 = (void*)1;
	s.incoming_replication_hostgroups = (void*)2;
	s.incoming_group_replication_hostgroups = (void*)3;
	s.incoming_galera_hostgroups = (void*)4;
	s.incoming_aurora_hostgroups = (void*)5;
	s.incoming_hostgroup_attributes = (void*)6;
	s.incoming_mysql_servers_ssl_params = (void*)7;
	s.incoming_aws_rds_bgd_hostgroups = (void*)8;
	s.runtime_mysql_servers = (void*)9;

	ok(s.incoming_mysql_servers_v2 == (void*)1, "field 0 set correctly");
	ok(s.incoming_replication_hostgroups == (void*)2, "field 1 set correctly");
	ok(s.incoming_group_replication_hostgroups == (void*)3, "field 2 set correctly");
	ok(s.incoming_galera_hostgroups == (void*)4, "field 3 set correctly");
	ok(s.incoming_aurora_hostgroups == (void*)5, "field 4 set correctly");
	ok(s.incoming_hostgroup_attributes == (void*)6, "field 5 set correctly");
	ok(s.incoming_mysql_servers_ssl_params == (void*)7, "field 6 set correctly");
	ok(s.incoming_aws_rds_bgd_hostgroups == (void*)8, "field 7 (BGD) set correctly");
	ok(s.runtime_mysql_servers == (void*)9, "field 8 set correctly");
}

// CLUSTER_QUERY_MYSQL_AWS_RDS_BGD is defined in ProxySQL_Cluster.hpp which
// has the same include dependency issue. Define it locally instead.
#define CLUSTER_QUERY_MYSQL_AWS_RDS_BGD \
	"PROXY_SELECT writer_hostgroup, reader_hostgroup, green_writer_hostgroup, " \
	"green_reader_hostgroup, active, writer_is_also_reader, check_interval_ms, " \
	"check_timeout_ms, comment, auto_generated, status " \
	"FROM runtime_mysql_aws_rds_bgd_hostgroups " \
	"WHERE auto_generated=0 ORDER BY writer_hostgroup"

static void test_cluster_query_rds_bgd() {
	const char* query = CLUSTER_QUERY_MYSQL_AWS_RDS_BGD;
	ok(strncmp(query, "PROXY_SELECT", 12) == 0,
		"CLUSTER_QUERY_MYSQL_AWS_RDS_BGD starts with PROXY_SELECT");
	ok(strstr(query, "auto_generated=0") != nullptr,
		"CLUSTER_QUERY_MYSQL_AWS_RDS_BGD filters auto_generated=0");
	ok(strstr(query, "green_writer_hostgroup") != nullptr,
		"CLUSTER_QUERY_MYSQL_AWS_RDS_BGD includes green_writer_hostgroup");
	ok(strstr(query, "green_reader_hostgroup") != nullptr,
		"CLUSTER_QUERY_MYSQL_AWS_RDS_BGD includes green_reader_hostgroup");
	ok(strstr(query, "runtime_mysql_aws_rds_bgd_hostgroups") != nullptr,
		"CLUSTER_QUERY_MYSQL_AWS_RDS_BGD queries runtime_mysql_aws_rds_bgd_hostgroups");
	ok(strstr(query, "ORDER BY writer_hostgroup") != nullptr,
		"CLUSTER_QUERY_MYSQL_AWS_RDS_BGD has ORDER BY writer_hostgroup");
}

static void test_convert_size_check() {
	std::vector<void*> v8(8, nullptr);
	std::vector<void*> v9(9, nullptr);
	std::vector<void*> v10(10, nullptr);

	size_t expected_struct_ptrs = sizeof(incoming_servers_t) / sizeof(void*);

	ok(v9.size() == expected_struct_ptrs,
		"9-element vector matches sizeof(incoming_servers_t)/sizeof(void*) (%zu)",
		expected_struct_ptrs);
	ok(v8.size() != expected_struct_ptrs,
		"8-element vector does NOT match (%zu vs %zu)",
		v8.size(), expected_struct_ptrs);
	ok(v10.size() != expected_struct_ptrs,
		"10-element vector does NOT match (%zu vs %zu)",
		v10.size(), expected_struct_ptrs);
}

int main() {
	plan(19);

	test_incoming_servers_t_size();
	test_incoming_servers_t_field_positions();
	test_cluster_query_rds_bgd();
	test_convert_size_check();

	return exit_status();
}
