#ifndef SQL_ENGINE_TOOL_CONFIG_PARSER_H
#define SQL_ENGINE_TOOL_CONFIG_PARSER_H

#include "sql_engine/backend_config.h"
#include "sql_engine/shard_map.h"

#include <string>

namespace sql_engine {

struct ParsedBackend {
    BackendConfig config;
    bool ok = false;
    std::string error;
};

struct ParsedShard {
    TableShardConfig config;
    bool ok = false;
    std::string error;
};

ParsedBackend parse_backend_url(const std::string& url);
ParsedShard parse_shard_spec(const std::string& spec);

} // namespace sql_engine

#endif // SQL_ENGINE_TOOL_CONFIG_PARSER_H
