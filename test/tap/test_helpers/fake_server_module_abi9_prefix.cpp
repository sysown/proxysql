// Deliberately allocate only the frozen ABI-9 ServerModuleHooks prefix.
// This is a DSO fixture: core must never inspect the appended affiliated
// callbacks through the returned pointer.
#include "ProxySQL_ServerDiscovery.h"

#include <cstddef>
#include <new>

namespace {
struct FrozenServerModuleHooks {
	ProxySQL_ServerProtocol protocol;
	void (*runtime_configuration_installed)(void *, ProxySQL_ServerRuntimeSnapshot);
	void *opaque;
};
static_assert(offsetof(ProxySQL_ServerModuleHooks, tables) == sizeof(FrozenServerModuleHooks),
	"frozen ABI-9 prefix must end at tables");

void installed(void *, ProxySQL_ServerRuntimeSnapshot) {}
}

extern "C" ProxySQL_ServerModuleHooks *proxysql_fake_server_module_abi9_prefix_create() {
	auto *prefix = new FrozenServerModuleHooks {ProxySQL_ServerProtocol::mysql, &installed, nullptr};
	return reinterpret_cast<ProxySQL_ServerModuleHooks *>(prefix);
}

extern "C" void proxysql_fake_server_module_abi9_prefix_destroy(ProxySQL_ServerModuleHooks *module) {
	delete reinterpret_cast<FrozenServerModuleHooks *>(module);
}
