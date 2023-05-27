#ifndef __PROXYSQL_COREDUMP_H
#define __PROXYSQL_COREDUMP_H
#include <unordered_set>

#define S1(x) #x
#define S2(x) S1(x)
#define LOCATION() __FILE__ ":" S2(__LINE__)

extern bool coredump_enabled;
extern int coredump_generation_threshold;
extern int coredump_generation_interval_ms;

void init_coredump_struct();
void proxy_coredump_load_filters(std::unordered_set<std::string>&& filters);
void proxy_coredump_get_filters(std::unordered_set<std::string>& filters);
bool proxy_coredump_filter_exists(const std::string& filter);
void proxy_coredump_reset_stats();
void proxy_coredump_generate();

#define generate_coredump() if (unlikely(coredump_enabled)) {\
	if (proxy_coredump_filter_exists(LOCATION())) {\
		proxy_info("Coredump filter location '" LOCATION() "' was hit.\n");\
		proxy_coredump_generate();\
	}\
}

#endif // __PROXYSQL_COREDUMP_H
