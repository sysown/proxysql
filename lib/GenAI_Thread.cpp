#include "GenAI_Thread.h"
#include "proxysql_debug.h"

// Define the array of variable names for the GenAI module
static const char* genai_thread_variables_names[] = {
	"var1",
	"var2",
	NULL
};

GenAI_Threads_Handler::GenAI_Threads_Handler() {
	shutdown_ = 0;
	num_threads = 0;
	pthread_rwlock_init(&rwlock, NULL);

	// Initialize variables with default values
	variables.var1 = strdup("default_value_1");
	variables.var2 = 100;

	status_variables.threads_initialized = 0;
}

GenAI_Threads_Handler::~GenAI_Threads_Handler() {
	if (variables.var1)
		free(variables.var1);
	pthread_rwlock_destroy(&rwlock);
}

void GenAI_Threads_Handler::init(unsigned int num, size_t stack) {
	proxy_info("Initializing GenAI Threads Handler\n");
	// For now, this is a simple initialization
	// In the future, this may start worker threads
	status_variables.threads_initialized = 1;
	print_version();
}

void GenAI_Threads_Handler::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
}

void GenAI_Threads_Handler::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
}

char* GenAI_Threads_Handler::get_variable(char* name) {
	if (!name)
		return NULL;

	if (!strcmp(name, "var1")) {
		return strdup(variables.var1 ? variables.var1 : "");
	}
	if (!strcmp(name, "var2")) {
		char buf[64];
		sprintf(buf, "%d", variables.var2);
		return strdup(buf);
	}

	return NULL;
}

bool GenAI_Threads_Handler::set_variable(char* name, const char* value) {
	if (!name || !value)
		return false;

	if (!strcmp(name, "var1")) {
		if (variables.var1)
			free(variables.var1);
		variables.var1 = strdup(value);
		return true;
	}
	if (!strcmp(name, "var2")) {
		variables.var2 = atoi(value);
		return true;
	}

	return false;
}

char** GenAI_Threads_Handler::get_variables_list() {
	// Count variables
	int count = 0;
	while (genai_thread_variables_names[count]) {
		count++;
	}

	// Allocate array
	char** list = (char**)malloc(sizeof(char*) * (count + 1));
	if (!list)
		return NULL;

	// Fill array
	for (int i = 0; i < count; i++) {
		list[i] = strdup(genai_thread_variables_names[i]);
	}
	list[count] = NULL;

	return list;
}

void GenAI_Threads_Handler::print_version() {
	fprintf(stderr, "GenAI Threads Handler rev. %s -- %s -- %s\n", GENAI_THREAD_VERSION, __FILE__, __TIMESTAMP__);
}
