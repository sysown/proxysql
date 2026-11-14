#ifndef GENAI_PGSQL_READONLY_TRANSACTION_H
#define GENAI_PGSQL_READONLY_TRANSACTION_H

#include <functional>
#include <utility>

namespace genai {
// Own a checked-out connection until rollback has made it safe to reuse.
// Callbacks keep the same cleanup path testable without a database fixture.
class PgSQL_Readonly_Transaction {
public:
    using Command = std::function<bool(const char*)>;
    using Idle = std::function<bool()>;
    using Release = std::function<void(bool)>;

    PgSQL_Readonly_Transaction(Command command, Idle idle, Release release)
        : command_(std::move(command)), idle_(std::move(idle)), release_(std::move(release)) {
        // BEGIN inside an existing transaction only warns: it does not change
        // that transaction's access mode. Refuse such a connection outright.
        if (!idle_()) {
            finished_ = true;
            release_(false);
            return;
        }
        ready_ = command_("BEGIN TRANSACTION READ ONLY");
        if (!ready_) finish();
    }
    ~PgSQL_Readonly_Transaction() { finish(); }
    PgSQL_Readonly_Transaction(const PgSQL_Readonly_Transaction&) = delete;
    PgSQL_Readonly_Transaction& operator=(const PgSQL_Readonly_Transaction&) = delete;

    bool ready() const { return ready_; }
    bool finish() {
        if (!finished_) {
            finished_ = true;
            reusable_ = command_("ROLLBACK") && idle_();
            release_(reusable_);
        }
        return reusable_;
    }

private:
    Command command_;
    Idle idle_;
    Release release_;
    bool ready_ = false;
    bool finished_ = false;
    bool reusable_ = false;
};
} // namespace genai
#endif
