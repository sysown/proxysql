#ifndef SQL_ENGINE_DML_RESULT_H
#define SQL_ENGINE_DML_RESULT_H

#include <cstdint>
#include <string>

namespace sql_engine {

struct DmlResult {
    uint64_t affected_rows = 0;
    uint64_t last_insert_id = 0;
    bool success = false;
    std::string error_message;
};

} // namespace sql_engine

#endif // SQL_ENGINE_DML_RESULT_H
