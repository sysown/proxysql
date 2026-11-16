#pragma once
// Internal typed extended-query controller. The caller must provide an endpoint
// policy that admits ONLY read-only SQL, including at prepare time. This class
// does not inspect or rewrite SQL, own packets, or emit protocol messages.
#include "Embedded_PgSQL_Result.h"
#include "Embedded_Prepared.h"
#include <memory>

namespace embedded {
// Budgets cover controller-owned state and encoded responses, including
// conservative framing/container costs. Adapter, native engine and Session
// metadata allocations occur before this controller can inspect them and are
// outside these budgets; their providers must independently bound them.
struct PgSQLPreparedLimits {
    size_t statements = 128, portals = 128, parameters = 4096, columns = 4096;
    size_t name_per = 1024, sql_per = 1u * 1024u * 1024u, metadata_total = 8u * 1024u * 1024u;
    size_t sql_total = 16u * 1024u * 1024u, bind_total = 16u * 1024u * 1024u;
    size_t result_total = 64u * 1024u * 1024u;
};
struct PgSQLDatum {
    const unsigned char *data = nullptr;
    int32_t length = -1;
    int16_t format = 0;
};
struct PgSQLField {
    bool is_null = false;
    std::vector<unsigned char> payload;
};
using PgSQLFieldRow = std::vector<PgSQLField>;
struct PgSQLDescription {
    std::vector<uint32_t> parameter_oids;
    std::vector<PgSQLColumn> columns;
    std::vector<int16_t> formats;
};
// Row fields own their payloads after transfer from the controller. The caller
// must release each response before requesting another if it needs the same
// total memory bound. Cached result accounting is conservative until portal close.
struct PgSQLExecution {
    std::vector<PgSQLFieldRow> rows;
    bool suspended = false;
    uint64_t row_count = 0;
};
class PgSQLPrepared {
  public:
    PgSQLPrepared(Adapter &, EndpointPolicy &, GuardFactory = {}, PgSQLPreparedLimits = {},
                  QuotaPool * = nullptr);
    ~PgSQLPrepared();
    PgSQLPrepared(const PgSQLPrepared &) = delete;
    PgSQLPrepared &operator=(const PgSQLPrepared &) = delete;
    Status parse(const std::string &, const std::string &, const std::vector<uint32_t> &);
    Status bind(const std::string &, const std::string &, const std::vector<PgSQLDatum> &,
                const std::vector<int16_t> &);
    Status describe_statement(const std::string &, PgSQLDescription &);
    Status describe_portal(const std::string &, PgSQLDescription &);
    Status execute(const std::string &, uint32_t max_rows, PgSQLExecution &);
    Status close_statement(const std::string &);
    Status close_portal(const std::string &);
    // Only implicit, read-only cycles are supported. Explicit transactions
    // require connection-owned portal lifetime management and are refused by caller.
    Status sync();
    // Poison the cycle for an error detected by the transport.
    Status reject(const Error &);
    // Before a simple query, discard implicit-cycle portals and unnamed statement.
    Status simple_query();
    void disconnect() noexcept;
    bool ignoring() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace embedded
