#ifndef PROXYSQL_MANAGED_RUNTIME_H
#define PROXYSQL_MANAGED_RUNTIME_H

#include <cstdint>
#include <string>

struct ManagedRuntimePlan {
 std::string deployment_id;
 std::string configuration_json;
};
struct ManagedPreparedRuntime; // opaque; owned by core
struct ManagedRuntimeResult {
 bool applied{false};
 std::string error_code, message;
};

/**
 * @brief Validate mapped settings and prepare existing runtime operations.
 * @param plan Normalized settings mapped to existing core features.
 * @param out Receives a core-owned prepared object on success.
 * @param error Receives the validation error on failure.
 * @return True on successful preparation. Requires the configuration lock.
 */
bool proxysql_prepare_managed_runtime_locked(
 const ManagedRuntimePlan& plan, ManagedPreparedRuntime** out, std::string& error);
/**
 * @brief Apply prepared inputs through existing configuration operations.
 * @param prepared Core-owned validated runtime inputs.
 * @param desired_revision Desired service-owned revision.
 * @return Existing application outcome. Requires the configuration lock.
 */
ManagedRuntimeResult proxysql_activate_managed_runtime_locked(
 ManagedPreparedRuntime& prepared, uint64_t desired_revision);
/** @brief Release a prepared object; nullptr is allowed. */
void proxysql_destroy_managed_prepared_runtime(ManagedPreparedRuntime*) noexcept;

// These operations perform no network calls or plugin disk transactions.
// Preparation does not introduce an atomic runtime engine or rollback.
#endif // PROXYSQL_MANAGED_RUNTIME_H
