#include <stdlib.h>
#include <cstring>

#include "tap.h"
#include "command_line.h"

CommandLine cl;

int main(int argc, char** argv) {

	char* value = NULL;

	// this test checks the env file loading mechanism implemented in tap/command_line.cpp:CommandLine::getEnv()
	// foldername/.env - enviroment vars for whole folder
	// foldername/foldername.env - enviroment vars for whole folder
	// foldername/testname-t.env - enviroment vars only for testname-t 

	// create
	// echo 'TAP_ENV_VAR1=.env' > .env
	// echo 'TAP_ENV_VAR2=tests.env' > tests.env
	// echo 'TAP_ENV_VAR3=envvars-t.env' > envvars-t.env

	plan(3);

	value = getenv("TAP_ENV_VAR1");
	ok((value != NULL) and (strcmp(value, ".env") == 0), "Env variable 'TAP_ENV_VAR1' from '.env' Expected: '.env' Actual: '%s'", value); // ok_1

	value = getenv("TAP_ENV_VAR2");
	ok((value != NULL) and (strcmp(value, "tests.env") == 0), "Env variable 'TAP_ENV_VAR2' from 'tests.env' Expected: 'tests.env' Actual: '%s'", value); // ok_2

	value = getenv("TAP_ENV_VAR3");
	ok((value != NULL) and (strcmp(value, "envvars-t.env") == 0), "Env variable 'TAP_ENV_VAR3' from 'envvars-t.env' Expected: 'envvars-t.env' Actual: '%s'", value); // ok_3

	return exit_status();
}

