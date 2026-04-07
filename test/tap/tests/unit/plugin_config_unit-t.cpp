#include "ProxySQL_PluginManager.h"
#include "proxysql_glovars.hpp"
#include "tap.h"

#include <string>

extern ProxySQL_GlobalVariables GloVars;

int main() {
	plan(3);

	GloVars.plugin_modules.clear();
	GloVars.plugin_modules.emplace_back("/tmp/a.so");
	GloVars.plugin_modules.emplace_back("/tmp/b.so");

	ok(GloVars.plugin_modules.size() == static_cast<size_t>(2),
	   "plugin path list stores configured entries");

	ProxySQL_PluginManager mgr;
	std::string err {};
	ok(!mgr.load("/definitely/missing/plugin.so", err),
	   "missing plugin fails with a useful error");
	ok(!err.empty(), "missing plugin failure returns an error string");

	return exit_status();
}
