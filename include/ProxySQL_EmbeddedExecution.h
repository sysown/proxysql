#ifndef PROXYSQL_EMBEDDED_EXECUTION_H
#define PROXYSQL_EMBEDDED_EXECUTION_H

#include <cstddef>
#include <cstdint>

// V1 is a C-shaped C++17 ABI. All views are length-delimited; empty and NULL
// values are distinguished by the value kind, not by a view's data pointer.
constexpr std::uint32_t ProxySQL_Embedded_ABI_V1 = 1;
constexpr int ProxySQL_Embedded_SUCCESS = 0;
constexpr int ProxySQL_Embedded_FAILURE = 1;

struct ProxySQL_Embedded_BytesView {
    const std::uint8_t* data;
    std::size_t size;
};

enum ProxySQL_Embedded_TypeKind : std::uint32_t {
    ProxySQL_Embedded_TYPE_UNKNOWN = 0,
    // Type tag 1 is reserved; NULL is a value, not a metadata type.
    ProxySQL_Embedded_TYPE_INT64 = 2,
    ProxySQL_Embedded_TYPE_UINT64 = 3,
    ProxySQL_Embedded_TYPE_FLOAT64 = 4,
    ProxySQL_Embedded_TYPE_TEXT = 5,
    ProxySQL_Embedded_TYPE_BYTES = 6,
    ProxySQL_Embedded_TYPE_DECIMAL = 7,
    ProxySQL_Embedded_TYPE_BOOLEAN = 8,
    ProxySQL_Embedded_TYPE_DYNAMIC = 9
};

enum ProxySQL_Embedded_ValueKind : std::uint32_t {
    ProxySQL_Embedded_VALUE_NULL = 1,
    ProxySQL_Embedded_VALUE_INT64 = 2,
    ProxySQL_Embedded_VALUE_UINT64 = 3,
    ProxySQL_Embedded_VALUE_FLOAT64 = 4,
    ProxySQL_Embedded_VALUE_TEXT = 5,
    ProxySQL_Embedded_VALUE_BYTES = 6,
    ProxySQL_Embedded_VALUE_DECIMAL = 7,
    ProxySQL_Embedded_VALUE_BOOLEAN = 8
};

struct ProxySQL_Embedded_Type {
    std::uint32_t kind;
    std::int32_t precision;
    std::int32_t scale;
    std::uint8_t nullable;
};

union ProxySQL_Embedded_ValuePayload {
    std::int64_t int64_value;
    std::uint64_t uint64_value;
    double float64_value;
    ProxySQL_Embedded_BytesView bytes;
    std::uint8_t boolean_value;
    std::uint8_t reserved[64];
};

struct ProxySQL_Embedded_Value {
    std::uint32_t kind;
    ProxySQL_Embedded_ValuePayload payload;
};

struct ProxySQL_Embedded_Column {
    ProxySQL_Embedded_BytesView name;
    ProxySQL_Embedded_Type type;
};

enum ProxySQL_Embedded_ErrorKind : std::uint32_t {
    ProxySQL_Embedded_ERROR_UNSPECIFIED = 0,
    ProxySQL_Embedded_ERROR_SYNTAX = 1,
    ProxySQL_Embedded_ERROR_UNSUPPORTED = 2,
    ProxySQL_Embedded_ERROR_POLICY = 3,
    ProxySQL_Embedded_ERROR_INVALID_PARAMETER = 4,
    ProxySQL_Embedded_ERROR_RANGE = 5,
    ProxySQL_Embedded_ERROR_RESOURCE = 6,
    ProxySQL_Embedded_ERROR_SCHEMA_CHANGED = 7,
    ProxySQL_Embedded_ERROR_TRANSACTION = 8,
    ProxySQL_Embedded_ERROR_ENGINE = 9,
    ProxySQL_Embedded_ERROR_INTERNAL = 10
};

struct ProxySQL_Embedded_Error {
    std::uint32_t kind;
    std::int32_t native_code;
    char sqlstate[6];
    ProxySQL_Embedded_BytesView message;
};

// Only advertised capabilities may be requested. Value masks use bit (1 <<
// ProxySQL_Embedded_ValueKind); bit zero is reserved.
constexpr std::uint64_t ProxySQL_Embedded_CAP_READ_ONLY = UINT64_C(1) << 0;
constexpr std::uint64_t ProxySQL_Embedded_CAP_PARAMETER_POSITIONS = UINT64_C(1) << 1;
constexpr std::uint64_t ProxySQL_Embedded_REQUEST_READ_ONLY = UINT64_C(1) << 0;
constexpr std::uint64_t ProxySQL_Embedded_REQUEST_PG_IMPLICIT_CYCLES = UINT64_C(1) << 1;

enum ProxySQL_Embedded_Operation : std::uint32_t {
    ProxySQL_Embedded_OPERATION_PREPARE = 1,
    ProxySQL_Embedded_OPERATION_EXECUTE = 2,
    ProxySQL_Embedded_OPERATION_FETCH = 3,
    ProxySQL_Embedded_OPERATION_RESET = 4,
    ProxySQL_Embedded_OPERATION_CLOSE = 5,
    ProxySQL_Embedded_OPERATION_DISCONNECT = 6,
    ProxySQL_Embedded_OPERATION_LONG_DATA = 7
};

struct ProxySQL_Embedded_ExecInfo {
    std::uint8_t has_result;
    std::uint64_t affected_rows;
    std::uint64_t last_insert_id;
};

struct ProxySQL_Embedded_EngineV1 {
    std::uint32_t abi_version;
    std::uint32_t struct_size;
    void* context;
    std::uint64_t capabilities;
    std::uint64_t value_type_mask;
    int (*prepare)(void*, ProxySQL_Embedded_BytesView, void**, ProxySQL_Embedded_Error*) noexcept;
    int (*describe_parameters)(void*, void*, const ProxySQL_Embedded_Type**,
        std::size_t*, const std::uint32_t**, ProxySQL_Embedded_Error*) noexcept;
    int (*describe_result)(void*, void*, const ProxySQL_Embedded_Column**,
        std::size_t*, ProxySQL_Embedded_Error*) noexcept;
    int (*bind)(void*, void*, const ProxySQL_Embedded_Value*, std::size_t,
        ProxySQL_Embedded_Error*) noexcept;
    int (*execute)(void*, void*, ProxySQL_Embedded_ExecInfo*,
        ProxySQL_Embedded_Error*) noexcept;
    int (*fetch)(void*, void*, const ProxySQL_Embedded_Value**, std::size_t*,
        std::uint8_t*, std::size_t, ProxySQL_Embedded_Error*) noexcept;
    int (*reset)(void*, void*, ProxySQL_Embedded_Error*) noexcept;
    void (*finalize)(void*, void*) noexcept;
    int (*guard_enter)(void*, std::uint32_t, ProxySQL_Embedded_BytesView,
        void**, ProxySQL_Embedded_Error*) noexcept;
    void (*guard_leave)(void*, void*) noexcept;
};

struct ProxySQL_Embedded_PolicyV1 {
    std::uint32_t abi_version;
    std::uint32_t struct_size;
    void* context;
    int (*authorize_prepare)(void*, ProxySQL_Embedded_BytesView,
        ProxySQL_Embedded_Error*) noexcept;
    int (*authorize_execute)(void*, ProxySQL_Embedded_BytesView,
        const ProxySQL_Embedded_Value*, std::size_t, ProxySQL_Embedded_Error*) noexcept;
    int (*authorize_fetch)(void*, ProxySQL_Embedded_BytesView,
        ProxySQL_Embedded_Error*) noexcept;
};

struct ProxySQL_Embedded_RequestV1 {
    std::uint32_t abi_version;
    std::uint32_t struct_size;
    const ProxySQL_Embedded_EngineV1* engine;
    const ProxySQL_Embedded_PolicyV1* policy;
    std::uint64_t flags;
    std::uint16_t (*mysql_status)(void*) noexcept;
    void* status_context;
    // Required for PostgreSQL; returns exactly 'I', 'T' or 'E'.
    std::uint8_t (*pgsql_status)(void*) noexcept;
    void* pgsql_status_context;
};

struct ProxySQL_Embedded_ServiceV1 {
    std::uint32_t abi_version;
    std::uint32_t struct_size;
    int (*register_mysql)(void*, const ProxySQL_Embedded_RequestV1*,
        ProxySQL_Embedded_Error*) noexcept;
    int (*register_pgsql)(void*, const ProxySQL_Embedded_RequestV1*,
        ProxySQL_Embedded_Error*) noexcept;
    int (*unregister_mysql)(void*, ProxySQL_Embedded_Error*) noexcept;
    int (*unregister_pgsql)(void*, ProxySQL_Embedded_Error*) noexcept;
};

#endif
