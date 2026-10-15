/**
 * @file hgc_attribute_strings_unit-t.cpp
 * @brief Hostgroup attribute strings replaced by a reload (init_connect, and
 *   aws_iam_region with PROXYSQL40) are read by worker threads while the
 *   Hostgroup Manager replaces them. Readers get a copy under the per-hostgroup
 *   lock.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "MySQL_HostGroups_Manager.h"

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#ifdef PROXYSQL40
// aws_iam_region is a v4.0 (AWS IAM) attribute.
#define AWS_IAM_REGION(h) (h).attribute_aws_iam_region()
#define SET_AWS_IAM_REGION(h, v) (h).set_attribute_aws_iam_region(v)
#else
#define AWS_IAM_REGION(h) std::string()
#define SET_AWS_IAM_REGION(h, v) ((void)(v))
#endif // PROXYSQL40

int main() {
	plan(5);
	test_init_minimal();

	MyHGC hostgroup(7);
	ok(hostgroup.attribute_init_connect().empty() && AWS_IAM_REGION(hostgroup).empty(),
		"unset attributes read as empty strings");

	hostgroup.set_attribute_init_connect("SET sql_mode=''");
	SET_AWS_IAM_REGION(hostgroup, "us-east-1");
#ifdef PROXYSQL40
	const bool region_set = AWS_IAM_REGION(hostgroup) == "us-east-1";
#else
	const bool region_set = true;
#endif // PROXYSQL40
	ok(hostgroup.attribute_init_connect() == "SET sql_mode=''" && region_set,
		"setters replace the attributes and getters return copies");

	SET_AWS_IAM_REGION(hostgroup, nullptr);
	hostgroup.set_attribute_init_connect(nullptr);
	ok(AWS_IAM_REGION(hostgroup).empty() && hostgroup.attribute_init_connect().empty(),
		"a null value clears the attribute");

	// Concurrent readers and a writer replacing the strings, as worker threads
	// opening connections during LOAD MYSQL SERVERS TO RUNTIME. Every value read
	// must be one that was written (under ASan, any use-after-free aborts).
	const std::vector<std::string> regions {"us-east-1", "eu-north-1", "ap-southeast-2"};
	std::atomic<bool> stop {false};
	std::atomic<bool> unexpected {false};
	std::vector<std::thread> readers;
	for (int i = 0; i < 4; ++i) {
		readers.emplace_back([&] {
			while (!stop.load(std::memory_order_relaxed)) {
				const std::string region = AWS_IAM_REGION(hostgroup);
				const std::string init_connect = hostgroup.attribute_init_connect();
				bool known = region.empty();
				for (const auto& candidate : regions) known = known || region == candidate;
				if (!known || (init_connect != "" && init_connect.rfind("SET ", 0) != 0))
					unexpected = true;
			}
		});
	}
	for (int i = 0; i < 20000; ++i) {
		SET_AWS_IAM_REGION(hostgroup, regions[i % regions.size()].c_str());
		hostgroup.set_attribute_init_connect(i % 2 ? "SET autocommit=1" : nullptr);
	}
	stop = true;
	for (auto& reader : readers) reader.join();
	ok(!unexpected, "readers only observe values that were written while the writer replaces them");

	hostgroup.reset_attributes();
	ok(hostgroup.attribute_init_connect().empty() && AWS_IAM_REGION(hostgroup).empty(),
		"reset_attributes clears both strings through the lock");
	return exit_status();
}
