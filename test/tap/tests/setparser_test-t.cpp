/**
 * @file setparser_test-t.cpp
 * @brief This test is a simple wrapper for calling 'setparser_test' as a tap test.
 */

#include "command_line.h"
#include "tap.h"

#include <stdlib.h>

CommandLine cl;

int main(int argc, char** argv) {

	plan(1);
	std::string test_bin { std::string { cl.workdir } + "setparser_test" };
	int setparser_err = system(test_bin.c_str());

	ok (setparser_err == 0, "Executing 'setparser_test' returned err code: %d", setparser_err);
	return exit_status();
}

