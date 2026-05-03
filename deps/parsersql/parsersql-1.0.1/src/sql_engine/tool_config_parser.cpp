#include "sql_engine/tool_config_parser.h"

#include <sstream>

namespace sql_engine {

namespace {

void apply_backend_query_param(BackendConfig& config,
                               const std::string& key,
                               const std::string& value) {
    if (key == "name") {
        config.name = value;
    } else if (key == "ssl_mode") {
        config.ssl_mode = value;
    } else if (key == "ssl_ca") {
        config.ssl_ca = value;
    } else if (key == "ssl_cert") {
        config.ssl_cert = value;
    } else if (key == "ssl_key") {
        config.ssl_key = value;
    }
}

void parse_backend_query_params(BackendConfig& config,
                                const std::string& query_part) {
    size_t pos = 0;
    while (pos < query_part.size()) {
        size_t amp = query_part.find('&', pos);
        std::string param = query_part.substr(
            pos, amp == std::string::npos ? std::string::npos : amp - pos);
        size_t eq = param.find('=');
        if (eq != std::string::npos) {
            apply_backend_query_param(config,
                                      param.substr(0, eq),
                                      param.substr(eq + 1));
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
}

} // namespace

ParsedBackend parse_backend_url(const std::string& url) {
    ParsedBackend pb;

    size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        pb.error = "Invalid URL (no scheme): " + url;
        return pb;
    }

    std::string scheme = url.substr(0, scheme_end);
    if (scheme == "mysql") {
        pb.config.dialect = sql_parser::Dialect::MySQL;
    } else if (scheme == "pgsql" || scheme == "postgres" ||
               scheme == "postgresql") {
        pb.config.dialect = sql_parser::Dialect::PostgreSQL;
    } else {
        pb.error = "Unknown scheme: " + scheme;
        return pb;
    }

    std::string rest = url.substr(scheme_end + 3);

    size_t qpos = rest.find('?');
    if (qpos != std::string::npos) {
        parse_backend_query_params(pb.config, rest.substr(qpos + 1));
        rest = rest.substr(0, qpos);
    }

    size_t at_pos = rest.find('@');
    if (at_pos != std::string::npos) {
        std::string userpass = rest.substr(0, at_pos);
        rest = rest.substr(at_pos + 1);
        size_t colon = userpass.find(':');
        if (colon != std::string::npos) {
            pb.config.user = userpass.substr(0, colon);
            pb.config.password = userpass.substr(colon + 1);
        } else {
            pb.config.user = userpass;
        }
    }

    size_t slash = rest.find('/');
    std::string hostport;
    if (slash != std::string::npos) {
        hostport = rest.substr(0, slash);
        pb.config.database = rest.substr(slash + 1);
    } else {
        hostport = rest;
    }

    size_t colon = hostport.find(':');
    if (colon != std::string::npos) {
        pb.config.host = hostport.substr(0, colon);
        try {
            pb.config.port =
                static_cast<uint16_t>(std::stoi(hostport.substr(colon + 1)));
        } catch (...) {
            pb.error = "Invalid port in: " + url;
            return pb;
        }
    } else {
        pb.config.host = hostport;
        pb.config.port =
            (pb.config.dialect == sql_parser::Dialect::MySQL) ? 3306 : 5432;
    }

    if (pb.config.name.empty()) {
        pb.config.name =
            pb.config.host + ":" + std::to_string(pb.config.port);
    }

    pb.ok = true;
    return pb;
}

namespace {

// Split a comma-separated string into trimmed non-empty pieces.
std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

// Parse a single "value=backend" entry. Returns true on success.
bool parse_value_backend(const std::string& entry,
                        std::string& value, std::string& backend) {
    size_t eq = entry.find('=');
    if (eq == std::string::npos) return false;
    value = entry.substr(0, eq);
    backend = entry.substr(eq + 1);
    return !value.empty() && !backend.empty();
}

// Look up a backend name's index in the shards vector. Adds it if absent.
size_t intern_backend(std::vector<ShardInfo>& shards, const std::string& name) {
    for (size_t i = 0; i < shards.size(); ++i) {
        if (shards[i].backend_name == name) return i;
    }
    shards.push_back(ShardInfo{name});
    return shards.size() - 1;
}

} // namespace

// Shard spec syntax (qualifier optional, defaults to HASH for back-compat):
//   table:key:backend1,backend2,...                       (HASH, implicit)
//   table:key:hash:backend1,backend2,...                  (HASH, explicit)
//   table:key:range:upper1=backend1,upper2=backend2,...   (RANGE)
//   table:key:list:val1=backend1,val2=backend2,...        (LIST)
ParsedShard parse_shard_spec(const std::string& spec) {
    ParsedShard ps;

    size_t c1 = spec.find(':');
    if (c1 == std::string::npos) {
        ps.error = "Invalid shard spec (missing table:key:...): " + spec;
        return ps;
    }
    size_t c2 = spec.find(':', c1 + 1);
    if (c2 == std::string::npos) {
        ps.error = "Invalid shard spec (missing key:shards): " + spec;
        return ps;
    }

    ps.config.table_name = spec.substr(0, c1);
    ps.config.shard_key = spec.substr(c1 + 1, c2 - c1 - 1);

    // Look for an optional strategy qualifier in the next colon-separated
    // token: hash | range | list. If absent, default to HASH.
    std::string after_key = spec.substr(c2 + 1);
    size_t c3 = after_key.find(':');
    std::string strategy_token;
    std::string body;
    if (c3 != std::string::npos) {
        std::string candidate = after_key.substr(0, c3);
        if (candidate == "hash" || candidate == "range" || candidate == "list") {
            strategy_token = candidate;
            body = after_key.substr(c3 + 1);
        } else {
            // No strategy qualifier — the colon belongs to the body (rare,
            // since shard names typically don't contain colons, but keep
            // the back-compat path strict).
            body = after_key;
        }
    } else {
        body = after_key;
    }

    if (strategy_token.empty() || strategy_token == "hash") {
        ps.config.strategy = RoutingStrategy::HASH;
        for (auto& shard : split_csv(body)) {
            ps.config.shards.push_back(ShardInfo{shard});
        }
        if (ps.config.shards.empty()) {
            ps.error = "No shards specified in: " + spec;
            return ps;
        }
    } else if (strategy_token == "range") {
        ps.config.strategy = RoutingStrategy::RANGE;
        for (auto& entry : split_csv(body)) {
            std::string upper_str, backend;
            if (!parse_value_backend(entry, upper_str, backend)) {
                ps.error = "Invalid range entry (expected upper=backend): " + entry;
                return ps;
            }
            int64_t upper = 0;
            try {
                upper = std::stoll(upper_str);
            } catch (...) {
                ps.error = "Range upper bound must be integer: " + upper_str;
                return ps;
            }
            size_t shard_idx = intern_backend(ps.config.shards, backend);
            ps.config.ranges.push_back(ShardRange{upper, shard_idx});
        }
        if (ps.config.ranges.empty()) {
            ps.error = "Range strategy requires at least one upper=backend entry: " + spec;
            return ps;
        }
    } else if (strategy_token == "list") {
        ps.config.strategy = RoutingStrategy::LIST;
        for (auto& entry : split_csv(body)) {
            std::string val_str, backend;
            if (!parse_value_backend(entry, val_str, backend)) {
                ps.error = "Invalid list entry (expected value=backend): " + entry;
                return ps;
            }
            ShardListEntry e;
            // Try integer parsing; fall back to string keying.
            char* end = nullptr;
            long long iv = std::strtoll(val_str.c_str(), &end, 10);
            if (end != nullptr && *end == '\0' && !val_str.empty()) {
                e.is_int = true;
                e.int_val = iv;
            } else {
                e.is_int = false;
                e.str_val = val_str;
            }
            e.shard_index = intern_backend(ps.config.shards, backend);
            ps.config.list.push_back(e);
        }
        if (ps.config.list.empty()) {
            ps.error = "List strategy requires at least one value=backend entry: " + spec;
            return ps;
        }
    }

    ps.ok = true;
    return ps;
}

} // namespace sql_engine
