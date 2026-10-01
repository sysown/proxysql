/**
 * @file hgc_attribute_strings_unit-t.cpp
 * @brief Hostgroup attribute strings replaced by a reload (init_connect,
 *   aws_iam_region) are read by worker threads while the Hostgroup Manager
 *   replaces them. Readers get a copy under the per-hostgroup lock.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "MySQL_HostGroups_Manager.h"

#include <atomic>
#include <string>
#include <thread>
#include <vector>

int main() {
	plan(5);
	test_init_minimal();

	MyHGC hostgroup(7);
	ok(hostgroup.attribute_init_connect().empty() && hostgroup.attribute_aws_iam_region().empty(),
		"unset attributes read as empty strings");

	hostgroup.set_attribute_init_connect("SET sql_mode=''");
	hostgroup.set_attribute_aws_iam_region("us-east-1");
	ok(hostgroup.attribute_init_connect() == "SET sql_mode=''" &&
		hostgroup.attribute_aws_iam_region() == "us-east-1",
		"setters replace the attributes and getters return copies");

	hostgroup.set_attribute_aws_iam_region(nullptr);
	ok(hostgroup.attribute_aws_iam_region().empty(), "a null value clears the attribute");

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
				const std::string region = hostgroup.attribute_aws_iam_region();
				const std::string init_connect = hostgroup.attribute_init_connect();
				bool known = region.empty();
				for (const auto& candidate : regions) known = known || region == candidate;
				if (!known || (init_connect != "" && init_connect.rfind("SET ", 0) != 0))
					unexpected = true;
			}
		});
	}
	for (int i = 0; i < 20000; ++i) {
		hostgroup.set_attribute_aws_iam_region(regions[i % regions.size()].c_str());
		hostgroup.set_attribute_init_connect(i % 2 ? "SET autocommit=1" : nullptr);
	}
	stop = true;
	for (auto& reader : readers) reader.join();
	ok(!unexpected, "readers only observe values that were written while the writer replaces them");

	hostgroup.reset_attributes();
	ok(hostgroup.attribute_init_connect().empty() && hostgroup.attribute_aws_iam_region().empty(),
		"reset_attributes clears both strings through the lock");
	return exit_status();
}
