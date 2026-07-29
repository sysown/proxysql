#include "tap.h"
#include "test_globals.h"

#include "MySQL_Thread.h"

static void test_mysql_integer_variables_are_registered() {
	test_globals_init();
	MySQL_Threads_Handler handler;
	char **variables = handler.get_variables_list();

	ok(handler.get_variable_int("aws_blue_green_deployment_auto_discovery") == 1,
		"aws_blue_green_deployment_auto_discovery is registered as an integer variable");
	ok(handler.get_variable_int("session_track_variables") == 0,
		"session_track_variables is registered as an integer variable");

	if (variables) {
		for (char **p = variables; *p != nullptr; ++p) {
			free(*p);
		}
		free(reinterpret_cast<void *>(variables));
	}
	test_globals_cleanup();
}

static void test_mysql_integer_boolean_aliases() {
	test_globals_init();
	MySQL_Threads_Handler handler;
	char **variables = handler.get_variables_list();
	char variable_name[] = "aws_blue_green_deployment_auto_discovery";

	ok(handler.set_variable(variable_name, "true") &&
		handler.get_variable_int(variable_name) == 1,
		"aws_blue_green_deployment_auto_discovery accepts true");
	ok(handler.set_variable(variable_name, "false") &&
		handler.get_variable_int(variable_name) == 0,
		"aws_blue_green_deployment_auto_discovery accepts false");

	if (variables) {
		for (char **p = variables; *p != nullptr; ++p) {
			free(*p);
		}
		free(reinterpret_cast<void *>(variables));
	}
	test_globals_cleanup();
}

int main() {
	plan(4);
	test_mysql_integer_variables_are_registered();
	test_mysql_integer_boolean_aliases();
	return exit_status();
}
