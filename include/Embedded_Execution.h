#pragma once
// Internal C++17 interface; this is not a plugin ABI.
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <type_traits>
#include <vector>
namespace embedded {
enum class ErrorKind { syntax, unsupported, policy, invalid_parameter, range, resource, schema_changed, transaction, engine, internal };
struct Error { ErrorKind kind; int native_code; std::string message; std::string sqlstate; };
using Status = std::optional<Error>; // Empty means success.
struct Decimal { std::string exact; };
struct Text { std::string bytes; };
struct Bytes { std::vector<uint8_t> bytes; };
// Temporal values are intentionally unsupported until units and timezone are specified.
using Value = std::variant<std::monostate, int64_t, uint64_t, double, Text, Bytes, Decimal>;
inline size_t value_payload_bytes(const Value& value) {
 return std::visit([](const auto& v) -> size_t {
  using T = std::decay_t<decltype(v)>;
  if constexpr (std::is_same_v<T, std::monostate>) return 0;
  else if constexpr (std::is_same_v<T, Text> || std::is_same_v<T, Bytes>) return v.bytes.size();
  else if constexpr (std::is_same_v<T, Decimal>) return v.exact.size();
  else return 8;
 }, value);
}
enum class TypeKind { unknown, dynamic, signed_integer, unsigned_integer, floating, text, bytes, decimal };
struct Type { TypeKind kind = TypeKind::unknown; int32_t precision = 0; int32_t scale = 0; bool nullable = true; };
struct Column { std::string name; Type type; };
using Row = std::vector<Value>; // Owned by caller, valid until caller changes it.
struct ExecInfo { uint64_t affected_rows = 0; uint64_t last_insert_id = 0; bool has_result = false; };
struct Statement { virtual ~Statement() = default; };
// One adapter instance belongs to one engine connection. It outlives Session.
// Operations are synchronous. Bind must copy values if needed after return.
// Prepare must leave out empty on failure; metadata is returned as owned copies.
// Fetch returns one row with done=false, or an empty row with done=true at EOF.
// Fetch must fail before returning a row exceeding the given payload-byte budget
// (not container/allocator overhead or engine memory).
// No operation implicitly commits, rolls back, retries, or executes to describe.
struct Adapter {
 virtual ~Adapter() = default;
 virtual Status prepare(const std::string&, std::unique_ptr<Statement>& out) = 0;
 virtual Status describe_parameters(Statement&, std::vector<Type>&) = 0;
 virtual Status describe_result(Statement&, std::vector<Column>&) = 0;
 virtual Status bind(Statement&, const std::vector<Value>&) = 0;
 virtual Status execute(Statement&, ExecInfo&) = 0;
 virtual Status fetch(Statement&, Row&, bool& done, size_t budget) = 0;
 virtual Status reset(Statement&) = 0;
 virtual void finalize(std::unique_ptr<Statement>) noexcept = 0;
};
struct EndpointPolicy {
 virtual ~EndpointPolicy() = default;
 virtual Status authorize_prepare(const std::string&) = 0;
 virtual Status authorize_execute(const std::string&, const std::vector<Value>&) = 0;
 virtual Status authorize_fetch(const std::string&) = 0;
};
}
