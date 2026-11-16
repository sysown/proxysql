#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "Base_Session.h"
#include "MySQL_Session.h"
#include "Embedded_MySQL_Result.h"
#include "Embedded_Prepared.h"
#include "proxysql_structs.h"

namespace embedded {

struct MySQLPreparedLimits {
    size_t statements = 128;
    size_t sql_per_statement = 1u * 1024u * 1024u;
    size_t sql_total = 16u * 1024u * 1024u;
    size_t longdata_per_statement = 16u * 1024u * 1024u;
    size_t longdata_total = 16u * 1024u * 1024u;
    size_t longdata_parameters = 1024;
    size_t parameters_per_statement = 4096;
    size_t columns_per_statement = 4096;
    size_t metadata_total = 8u * 1024u * 1024u;
    size_t response_bytes = 64u * 1024u * 1024u;
};

using MySQLStatus = std::function<uint16_t()>;

Status register_mysql_prepared(MySQL_Session& session, Adapter& adapter,
                              EndpointPolicy& policy, MySQLStatus status,
                              MySQLPreparedLimits limits = {}, GuardFactory guard_factory = {});

void unregister_mysql_prepared(MySQL_Session& session) noexcept;

// Unregistered sessions are a successful no-op; registered sessions require their owner thread.
Status reset_mysql_prepared(MySQL_Session& session);

bool handle_mysql_prepared(MySQL_Session& session, PtrSize_t& packet);

}  // namespace embedded
