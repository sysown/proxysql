#include <string>
#include <unordered_set>

#include "proxysql_coredump.h"
#include "gen_utils.h"
#if (defined(__i386__) || defined(__x86_64__) || defined(__ARM_ARCH_3__) || defined(__mips__)) && defined(__linux)
// currently only support x86-32, x86-64, ARM, and MIPS on Linux
#include "coredumper/coredumper.h"
#endif

bool coredump_enabled = false;
int coredump_generation_threshold = 0;
int coredump_generation_interval_ms = 0;

static int coredump_generated = 0;
static unsigned long long coredump_creation_time = 0;
static pthread_rwlock_t coredump_filters_rwlock;
static std::unordered_set<std::string> coredump_filters;

//std::unordered_set<std::string>& get_coredump_filters() {
//	static std::unordered_set<std::string> coredump_filters{};
//	return coredump_filters;
//}

void init_coredump_struct() {
	pthread_rwlock_init(&coredump_filters_rwlock, nullptr);
	coredump_enabled = false;
	coredump_generation_threshold = 0;
	coredump_generation_interval_ms = 0;
	coredump_generated = 0;
	coredump_creation_time = 0;
}

void proxy_coredump_load_filters(std::unordered_set<std::string>&& filters) {
//	auto& coredump_filters = get_coredump_filters();
	pthread_rwlock_wrlock(&coredump_filters_rwlock);
	coredump_filters.clear();
	coredump_filters = std::move(filters);
	coredump_enabled = !coredump_filters.empty();
	proxy_coredump_reset_stats();
	pthread_rwlock_unlock(&coredump_filters_rwlock);
}

void proxy_coredump_get_filters(std::unordered_set<std::string>& filters) {
//	const auto& coredump_filters = get_coredump_filters();
	pthread_rwlock_rdlock(&coredump_filters_rwlock);
	filters = coredump_filters;
	pthread_rwlock_unlock(&coredump_filters_rwlock);
}

bool proxy_coredump_filter_exists(const std::string& filter) {
	bool result = false;
//	const auto& coredump_filters = get_coredump_filters();
	pthread_rwlock_rdlock(&coredump_filters_rwlock);
	result = (coredump_filters.find(filter) != coredump_filters.end());
	pthread_rwlock_unlock(&coredump_filters_rwlock);
	return result;
}

void proxy_coredump_reset_stats() {
	proxy_info("Reset coredump stats\n");
	coredump_generated = 0;
	coredump_creation_time = 0;
}

void proxy_coredump_generate() {
#if (defined(__i386__) || defined(__x86_64__) || defined(__ARM_ARCH_3__) || defined(__mips__)) && defined(__linux)
	const auto currtime = monotonic_time();;

	if ((coredump_creation_time == 0 || coredump_generation_interval_ms == 0 || 
		(currtime > (coredump_creation_time + (coredump_generation_interval_ms*1000)))) &&
		coredump_generated < coredump_generation_threshold) {
		
		char core_filename[128];
		sprintf(core_filename, "core.%d.%d", getpid(), coredump_generated);
		proxy_info("Generating coredump file '%s'...\n", core_filename);
		WriteCompressedCoreDump(core_filename, SIZE_MAX, COREDUMPER_COMPRESSED, NULL);
		coredump_generated++;
		coredump_creation_time = currtime;
		proxy_info("Coredump file '%s' was generated ['%llu']. Total core files generated '%d'.\n", core_filename, coredump_creation_time, coredump_generated);
	}
#else
	proxy_warning("Coredump generation is not supported on this platform.\n");
#endif
}
