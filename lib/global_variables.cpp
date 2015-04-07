#include "proxysql.h"

// configure the number of threads as number of cores times 2
void pre_variable_mysql_threads(global_variable_entry_t *gve) {
	int rc=sysconf(_SC_NPROCESSORS_ONLN)*2;
	assert(rc>0);
	*(int *)gve->arg_data=rc;
}
