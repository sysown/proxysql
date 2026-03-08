/**
 * @file test_com_register_slave_enables_fast_forward-t.cpp @brief Test
 * COM_REGISTER_SLAVE enables fast forward.  @details Test checks if
 * test_binlog_reader is executed successfully using a user with fast forward
 * flag set to false. test_binlog_reader sends command COM_REGISTER_SLAVE, then
 * ProxySQL enables fast forward. test_binlog_reader then uses libslave to
 * listen binlog events. It listen two times, one after sending a query that do
 * not disable multiplexing and the other after sending a query that disables
 * multiplexing.
 *
 * The repository for test_binlog_reader-t is:
 * https://github.com/ProxySQL/proxysql_binlog_test
 */

#include <string>
#include <cstdlib>
#include "tap.h"

int main(int argc, char** argv) {
	plan(1);
	const char * tdp = getenv("TEST_DEPS");
	const std::string test_binlog_reader = ( tdp == nullptr || *tdp == '\0' ) ? "./test_binlog_reader-t" : std::string(tdp) + "/test_binlog_reader-t";

	const int test_binlog_reader_res = system(test_binlog_reader.c_str());
	ok(
		test_binlog_reader_res == 0,
		"'test_binlog_reader-t' should be correctly executed. Err code was: %d",
		test_binlog_reader_res
	);

	return exit_status();
}
