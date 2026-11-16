#pragma once
#include "Embedded_Execution.h"
#include <map>

namespace embedded {
class Session {
public:
    explicit Session(Adapter&, EndpointPolicy&, size_t max_statements = 128,
                     size_t result_budget = 64u * 1024u * 1024u);
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    Status prepare(const std::string&, uint64_t& id);
    Status describe(uint64_t, std::vector<Type>&, std::vector<Column>&) const;
    Status execute(uint64_t, const std::vector<Value>&, ExecInfo&);
    Status fetch(uint64_t, Row&, bool& done);
    Status reset(uint64_t);
    Status close(uint64_t);

private:
    struct Deleter {
        Adapter* adapter;
        void operator()(Statement*) const noexcept;
    };
    using Handle = std::unique_ptr<Statement, Deleter>;
    struct Entry {
        explicit Entry(Adapter& adapter) : handle(nullptr, Deleter{&adapter}) {}
        std::string sql;
        Handle handle;
        std::vector<Type> parameters;
        std::vector<Column> columns;
        bool executed = false;
    };
    Adapter& adapter_;
    EndpointPolicy& policy_;
    size_t max_statements_;
    size_t result_budget_;
    uint64_t next_id_ = 1;
    std::map<uint64_t, Entry> entries_;
};
}
