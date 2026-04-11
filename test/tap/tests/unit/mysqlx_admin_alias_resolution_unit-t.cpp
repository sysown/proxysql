#include "tap.h"
#include "test_init.h"

#include <cstring>
#include <string>
#include <vector>

extern const char* resolve_admin_alias_to_canonical(
	const std::vector<std::string>& cmds,
	const char* canonical,
	char *query_no_space, int query_no_space_length
);

namespace {

std::vector<std::string> test_aliases = {
	"LOAD MYSQLX USERS FROM MEMORY",
	"LOAD MYSQLX USERS FROM MEM",
	"LOAD MYSQLX USERS TO RUNTIME",
	"LOAD MYSQLX USERS TO RUN"
};

const char* CANONICAL = "LOAD MYSQLX USERS TO RUNTIME";

const char* resolve(const char* query, const std::vector<std::string>& aliases = test_aliases, const char* canonical = CANONICAL) {
	char buf[256];
	strncpy(buf, query, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';
	int len = strlen(buf);
	return resolve_admin_alias_to_canonical(aliases, canonical, buf, len);
}

}

int main() {
	plan(23);

	test_init_minimal();

	{
		ok(resolve("LOAD MYSQLX USERS FROM MEMORY") != nullptr,
		   "full canonical alias 'FROM MEMORY' resolves");
		ok(resolve("LOAD MYSQLX USERS FROM MEM") != nullptr,
		   "short alias 'FROM MEM' resolves");
		ok(resolve("LOAD MYSQLX USERS TO RUNTIME") != nullptr,
		   "full canonical 'TO RUNTIME' resolves");
		ok(resolve("LOAD MYSQLX USERS TO RUN") != nullptr,
		   "short alias 'TO RUN' resolves");
	}

	{
		ok(resolve("load mysqlx users from memory") != nullptr,
		   "lowercase 'from memory' resolves (case-insensitive)");
		ok(resolve("Load Mysqlx Users To Runtime") != nullptr,
		   "mixed case resolves (case-insensitive)");
		ok(resolve("LOAD MYSQLX USERS TO RUNTIME") == CANONICAL,
		   "resolved pointer equals canonical string");
	}

	{
		ok(resolve("LOAD MYSQLX USERS FROM DISK") == nullptr,
		   "unrelated query 'FROM DISK' returns nullptr");
		ok(resolve("SAVE MYSQLX USERS TO MEMORY") == nullptr,
		   "unrelated query 'SAVE' returns nullptr");
		ok(resolve("LOAD MYSQLX ROUTES TO RUNTIME") == nullptr,
		   "different object type returns nullptr");
		ok(resolve("") == nullptr,
		   "empty query returns nullptr");
		ok(resolve("LOAD") == nullptr,
		   "partial query returns nullptr");
	}

	{
		std::vector<std::string> no_aliases;
		ok(resolve("LOAD MYSQLX USERS TO RUNTIME", no_aliases) == nullptr,
		   "empty alias vector returns nullptr");
	}

	{
		std::vector<std::string> single_alias = { "SAVE MYSQLX USERS TO DISK" };
		const char* disk_canonical = "SAVE MYSQLX USERS TO DISK";
		ok(resolve("SAVE MYSQLX USERS TO DISK", single_alias, disk_canonical) != nullptr,
		   "single-element alias vector matches");
		ok(resolve("SAVE MYSQLX USERS TO MEMORY", single_alias, disk_canonical) == nullptr,
		   "single-element alias vector rejects non-match");
	}

	{
		std::vector<std::string> be_aliases = {
			"LOAD MYSQLX BACKEND ENDPOINTS FROM MEMORY",
			"LOAD MYSQLX BACKEND ENDPOINTS FROM MEM",
			"LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME",
			"LOAD MYSQLX BACKEND ENDPOINTS TO RUN"
		};
		const char* be_canonical = "LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME";
		ok(resolve("LOAD MYSQLX BACKEND ENDPOINTS FROM MEM", be_aliases, be_canonical) != nullptr,
		   "backend endpoints 'FROM MEM' resolves");
		ok(resolve("LOAD MYSQLX BACKEND ENDPOINTS TO RUN", be_aliases, be_canonical) != nullptr,
		   "backend endpoints 'TO RUN' resolves");
	}

	{
		std::vector<std::string> disk_aliases = {
			"SAVE MYSQLX VARIABLES TO DISK"
		};
		const char* disk_canonical = "SAVE MYSQLX VARIABLES TO DISK";
		const char* result = resolve("SAVE MYSQLX VARIABLES TO DISK", disk_aliases, disk_canonical);
		ok(result != nullptr, "disk alias resolves");
		ok(result == disk_canonical, "disk alias returns canonical pointer");
	}

	{
		std::vector<std::string> vars_aliases = {
			"LOAD MYSQLX VARIABLES FROM MEMORY",
			"LOAD MYSQLX VARIABLES FROM MEM",
			"LOAD MYSQLX VARIABLES TO RUNTIME",
			"LOAD MYSQLX VARIABLES TO RUN"
		};
		const char* vars_canonical = "LOAD MYSQLX VARIABLES TO RUNTIME";
		ok(resolve("LOAD MYSQLX VARIABLES FROM MEMORY", vars_aliases, vars_canonical) != nullptr,
		   "variables 'FROM MEMORY' resolves");
		ok(resolve("LOAD MYSQLX VARIABLES TO RUNTIME", vars_aliases, vars_canonical) != nullptr,
		   "variables 'TO RUNTIME' resolves");
		ok(resolve("load mysqlx variables to run", vars_aliases, vars_canonical) != nullptr,
		   "variables lowercase 'to run' resolves");
		ok(resolve("LOAD MYSQLX VARIABLES FROM DISK", vars_aliases, vars_canonical) == nullptr,
		   "variables 'FROM DISK' not in memory aliases returns nullptr");
	}

	test_cleanup_minimal();
	return exit_status();
}
