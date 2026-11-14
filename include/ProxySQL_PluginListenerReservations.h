#ifndef PROXYSQL_PLUGIN_LISTENER_RESERVATIONS_H
#define PROXYSQL_PLUGIN_LISTENER_RESERVATIONS_H

#ifdef PROXYSQL40

#include <string>
#include <vector>

/**
 * Process-local reservation snapshot for listeners already owned by enabled
 * core modules.
 *
 * Startup seeds this once from the modules that ProxySQL's existing listener
 * conflict check already collected, before their borrowed variable strings are
 * freed.  Plugin-provided candidate interfaces are then validated against that
 * owned snapshot.  The service performs no SQL, DNS, logging, or mutation of
 * core listener configuration.
 *
 * Candidate parsing is intentionally stricter than the permissive core
 * validator used for the reservation strings: candidates must be numeric TCP
 * endpoints (`address:port` or `[ipv6]:port`).  Hostnames and malformed
 * spellings are rejected rather than resolved or silently skipped.
 */
namespace ProxySQL_PluginListenerReservations {

/** Owned copy of one core module's semicolon-separated listener list. */
struct ModuleReservation {
	std::string module_name;
	std::string interfaces;
};

/**
 * Replace the complete reservation snapshot.
 *
 * The call copies every input string and parses the reservation interfaces
 * with the existing core listener parser (including its hostname resolution)
 * while the caller is not holding a data-plane global lock.  A subsequent
 * call replaces the whole snapshot, which is how an internal reload clears
 * stale entries.  Malformed reservation entries keep the existing core
 * validator's permissive "skip invalid entry" behavior.
 */
void replace_reservations(std::vector<ModuleReservation> reservations);

/** Remove every reservation (zero enabled core listeners). */
void clear_reservations();

/**
 * Validate numeric TCP candidate interfaces against the current snapshot.
 *
 * @param owner      Plugin/module name used only for diagnostics; it never
 *                   suppresses a conflict when it matches a reserved module.
 * @param interfaces Semicolon-separated candidate interfaces.  An empty or
 *                   whitespace-only value means zero listeners and succeeds.
 * @param error      Cleared on success; descriptive on failure.
 * @return true when every candidate is well formed and non-overlapping.
 */
bool validate_candidate(const char* owner, const char* interfaces,
	std::string& error);

} // namespace ProxySQL_PluginListenerReservations

#endif /* PROXYSQL40 */
#endif /* PROXYSQL_PLUGIN_LISTENER_RESERVATIONS_H */
