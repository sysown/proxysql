#include "Embedded_Prepared.h"
#include <type_traits>
#include <limits>

namespace embedded {
namespace {
Status error(ErrorKind kind, const char* message) {
    return Error{kind, 0, message, ""};
}
}

Session::Session(Adapter& adapter, EndpointPolicy& policy, size_t max, size_t budget, QuotaPool* quota)
    : adapter_(adapter), policy_(policy), max_statements_(max), result_budget_(budget),
      quota_(quota ? *quota : process_quota_pool()) {}

void Session::Deleter::operator()(Statement* statement) const noexcept {
    if (statement) adapter->finalize(std::unique_ptr<Statement>(statement));
}

Session::~Session() = default;

Status Session::prepare(const std::string& sql, uint64_t& id) {
    id = 0;
    if (entries_.size() >= max_statements_ || next_id_ == 0)
        return error(ErrorKind::resource, "statement limit or IDs exhausted");
    if (sql.find('\0') != std::string::npos)
        return error(ErrorKind::syntax, "embedded NUL in SQL");
    if (auto err = policy_.authorize_prepare(sql)) return err;

    Entry entry(adapter_, quota_);
    ResourceUsage usage{};
    usage[static_cast<size_t>(Resource::native_statements)] = 1;
    usage[static_cast<size_t>(Resource::sql_bytes)] = sql.size();
    if (!entry.lease.resize(usage))
        return Error{ErrorKind::resource, 0, "prepared statement quota exceeded", "54000"};
    entry.sql = sql;
    std::unique_ptr<Statement> native;
    // Adopt even a handle supplied on an error or during an exception.
    struct Adopt {
        std::unique_ptr<Statement>& source;
        Handle& target;
        ~Adopt() { target.reset(source.release()); }
    };
    Status result;
    {
        Adopt adopt{native, entry.handle};
        result = adapter_.prepare(sql, native);
    }
    if (result) return result;
    if (!entry.handle) return error(ErrorKind::internal, "adapter returned no statement");
    if (auto err = adapter_.describe_parameters(*entry.handle, entry.parameters)) return err;
    if (auto err = adapter_.describe_result(*entry.handle, entry.columns)) return err;
    // Include the retained Entry itself as a conservative fixed overhead. Metadata
    // construction above is transient and cannot be preflighted through Adapter.
    size_t bytes = sizeof(Entry);
    const size_t max = std::numeric_limits<size_t>::max();
    auto add = [&](size_t count, size_t size) {
        if (count > (max - bytes) / size) return false;
        bytes += count * size;
        return true;
    };
    bool fits = add(entry.parameters.size(), sizeof(Type)) &&
                add(entry.columns.size(), sizeof(Column));
    for (const auto& column : entry.columns)
        if (fits) fits = add(column.name.size(), 1);
    usage[static_cast<size_t>(Resource::metadata_bytes)] = bytes;
    if (!fits || !entry.lease.resize(usage))
        return Error{ErrorKind::resource, 0, "prepared metadata quota exceeded", "54000"};
    const uint64_t new_id = next_id_;
    entries_.emplace(new_id, std::move(entry));
    ++next_id_;
    id = new_id;
    return {};
}

Status Session::describe(uint64_t id, std::vector<Type>& parameters,
                         std::vector<Column>& columns) const {
    parameters.clear();
    columns.clear();
    auto it = entries_.find(id);
    if (it == entries_.end()) return error(ErrorKind::invalid_parameter, "unknown statement");
    parameters = it->second.parameters;
    columns = it->second.columns;
    return {};
}

Status Session::describe_parameter_positions(uint64_t id, std::vector<uint32_t>& out) {
    out.clear();
    auto it = entries_.find(id);
    if (it == entries_.end()) return error(ErrorKind::invalid_parameter, "unknown statement");
    std::vector<uint32_t> positions;
    if (auto err = adapter_.describe_parameter_positions(*it->second.handle, positions)) return err;
    if (positions.size() != it->second.parameters.size())
        return error(ErrorKind::schema_changed, "native parameter count changed");
    out = std::move(positions);
    return {};
}

Status Session::execute(uint64_t id, const std::vector<Value>& values, ExecInfo& info) {
    info = {};
    auto it = entries_.find(id);
    if (it == entries_.end()) return error(ErrorKind::invalid_parameter, "unknown statement");
    auto& entry = it->second;
    entry.executed = false;
    if (values.size() != entry.parameters.size())
        return error(ErrorKind::invalid_parameter, "parameter count mismatch");
    if (auto err = policy_.authorize_execute(entry.sql, values)) return err;
    if (auto err = adapter_.reset(*entry.handle)) return err;
    if (auto err = adapter_.bind(*entry.handle, values)) return err;
    ExecInfo result;
    if (auto err = adapter_.execute(*entry.handle, result)) return err;
    entry.executed = result.has_result;
    info = result;
    return {};
}

Status Session::fetch(uint64_t id, Row& row, bool& done) {
    row.clear();
    done = false;
    auto it = entries_.find(id);
    if (it == entries_.end()) return error(ErrorKind::invalid_parameter, "unknown statement");
    auto& entry = it->second;
    if (!entry.executed) return error(ErrorKind::invalid_parameter, "no active result");
    entry.executed = false;
    if (auto err = policy_.authorize_fetch(entry.sql)) return err;
    Row result;
    bool finished = false;
    if (auto err = adapter_.fetch(*entry.handle, result, finished, result_budget_)) {
        entry.executed = false;
        return err;
    }
    if ((!finished && (result.empty() || result.size() != entry.columns.size())) ||
        (finished && !result.empty())) {
        return error(ErrorKind::internal, "adapter returned invalid row shape");
    }
    size_t bytes = 0;
    for (const auto& value : result) {
        size_t n = value_payload_bytes(value);
        if (n > result_budget_ - bytes) {
            entry.executed = false;
            return error(ErrorKind::resource, "row budget exceeded");
        }
        bytes += n;
    }
    entry.executed = !finished;
    row = std::move(result);
    done = finished;
    return {};
}

Status Session::reset(uint64_t id) {
    auto it = entries_.find(id);
    if (it == entries_.end()) return error(ErrorKind::invalid_parameter, "unknown statement");
    it->second.executed = false;
    return adapter_.reset(*it->second.handle);
}

Status Session::close(uint64_t id) {
    auto it = entries_.find(id);
    if (it == entries_.end()) return error(ErrorKind::invalid_parameter, "unknown statement");
    entries_.erase(it);
    return {};
}
}
