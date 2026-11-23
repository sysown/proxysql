#pragma once

#include "Embedded_Execution.h"

struct sqlite3;
class ProxySQL_Admin;

namespace embedded {

// Called under the Admin SQL mutex for each native operation.
class AdminSQLitePolicy final : public EndpointPolicy {
public:
    AdminSQLitePolicy(ProxySQL_Admin& admin, sqlite3* db, bool is_admin);
    Status guard(std::unique_ptr<OperationGuard>& out);
    Status authorize_prepare(const std::string&) override { return {}; }
    Status authorize_execute(const std::string& sql, const std::vector<Value>&) override;
    Status authorize_fetch(const std::string&) override { return {}; }
    const Command& command() const { return command_; }
private:
    struct Guard;
    ProxySQL_Admin& admin_;
    sqlite3* db_;
    bool is_admin_;
    Command command_ = Command::unknown;
    Guard* active_ = nullptr;
};

}
