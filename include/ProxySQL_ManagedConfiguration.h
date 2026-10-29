#ifndef PROXYSQL_MANAGED_CONFIGURATION_H
#define PROXYSQL_MANAGED_CONFIGURATION_H

#include <cstdint>
#include <optional>
#include <string>

constexpr uint32_t PROXYSQL_MANAGED_CONFIGURATION_ABI = 1;
enum class ManagedCallKind : uint8_t { query, status, validate, mutate };
enum class ManagedOutcome : uint8_t {
 ok, rejected, conflict, durable_pending, apply_failed, internal_error
};
struct ManagedCaller {
 std::string principal_id, access_key_id;
 uint64_t credential_generation{0};
};
struct ManagedRequest {
 ManagedCallKind kind;
 std::string operation, resource_id, document_json;
 ManagedCaller caller;
 std::optional<uint64_t> expected_revision;
 std::string idempotency_key;
};
struct ManagedResult {
 ManagedOutcome outcome;
 uint64_t desired_revision{0}, applied_revision{0};
 std::string operation_id, error_code, message, document_json;
};
struct ManagedSignatureInput {
 std::string access_key_id, credential_date, region, service;
 std::string amz_date, security_token, string_to_sign, signature_hex;
};
struct ManagedAuthResult {
 bool authenticated{false};
 ManagedCaller caller;
 std::string error_code, message;
};

// Owned by the AWS plugin. All request/result values own their data. The
// service and context remain alive until HTTP handlers have drained. No
// secrets or transport objects cross this interface.
struct ProxySQL_ManagedConfigurationServiceV1 {
 uint32_t abi_version, struct_size;
 void* context;
 ManagedAuthResult (*verify_sigv4)(void*, const ManagedSignatureInput&);
 ManagedResult (*invoke)(void*, const ManagedRequest&);
 // Local installation and startup recovery use the same service-owned
 // persistence/application path as mutations. Called before serving HTTP.
 ManagedResult (*bootstrap)(void*, const std::string& manifest_json);
 ManagedResult (*restore)(void*);
};

/**
 * @brief Validate the required management service before binding or recovery.
 * @param service Borrowed plugin service; never read a truncated tail.
 * @param error Receives an explanation on failure.
 * @return True for a complete service with the supported ABI.
 */
bool proxysql_validate_managed_configuration_service(
 const ProxySQL_ManagedConfigurationServiceV1* service, std::string& error);

#endif // PROXYSQL_MANAGED_CONFIGURATION_H
