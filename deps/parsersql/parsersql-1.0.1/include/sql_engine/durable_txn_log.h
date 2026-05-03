#ifndef SQL_ENGINE_DURABLE_TXN_LOG_H
#define SQL_ENGINE_DURABLE_TXN_LOG_H

// Durable write-ahead log for distributed transaction decisions.
//
// The single purpose of this file is 2PC recovery. Without it, the
// DistributedTransactionManager has a fatal gap: between phase 1 (all
// participants return PREPARE OK) and phase 2 (dispatch COMMIT to each),
// the coordinator must remember its decision durably. If the coordinator
// crashes in that window, a restart has no idea which transactions were
// in-flight, which ones were supposed to commit, or which ones were
// supposed to roll back. Prepared transactions remain held on every
// backend until a DBA manually resolves them.
//
// The fix is to write an append-only record containing the transaction id,
// the decision (COMMIT or ROLLBACK), and the list of participants, then
// fsync before phase 2 begins. After phase 2 completes successfully, a
// COMPLETE record is written (also fsynced) to mark the transaction as no
// longer in-doubt. On startup, we scan the log; any txn_id with a
// DECISION record but no matching COMPLETE is in-doubt and needs recovery.
//
// Format (line-based, tab-separated, each record ends with '\n'):
//
//     COMMIT\t<txn_id>\t<participant1>,<participant2>,...\n
//     ROLLBACK\t<txn_id>\t<participant1>,<participant2>,...\n
//     COMPLETE\t<txn_id>\n
//
// Limitations of this MVP:
// - Single log file, no rotation. A long-running coordinator will grow
//   the file indefinitely. Compaction is a follow-up.
// - fsync per record. Fine for modest TPS.
// - The log is text, not binary. Easier to debug, slightly larger on disk.
// - Recovery resolution (actually contacting backends to commit/rollback
//   the in-doubt transactions) lives in scan_in_doubt's callers, not here.
//   This class just produces the list of work the caller must do.

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <fcntl.h>
#include <unistd.h>

namespace sql_engine {

class DurableTransactionLog {
public:
    enum class Decision : uint8_t { COMMIT, ROLLBACK };

    struct InDoubtEntry {
        std::string txn_id;
        Decision decision = Decision::COMMIT;
        std::vector<std::string> participants;
    };

    DurableTransactionLog() = default;
    ~DurableTransactionLog() { close(); }

    DurableTransactionLog(const DurableTransactionLog&) = delete;
    DurableTransactionLog& operator=(const DurableTransactionLog&) = delete;

    // Open the log at `path`, creating it if it doesn't exist. Append mode
    // (records go at the end). Must be called before any log_* methods.
    //
    // Returns true on success. On failure the log is not open; callers
    // should decide whether to proceed without durability (dangerous) or
    // fail the commit outright.
    bool open(const std::string& path) {
        std::lock_guard<std::mutex> lk(mu_);
        if (fd_ >= 0) return true;
        path_ = path;
        fd_ = ::open(path.c_str(),
                     O_WRONLY | O_CREAT | O_APPEND,
                     0644);
        return fd_ >= 0;
    }

    // Close the log. Destructor calls this automatically.
    void close() {
        std::lock_guard<std::mutex> lk(mu_);
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    bool is_open() const {
        std::lock_guard<std::mutex> lk(mu_);
        return fd_ >= 0;
    }

    // Record the commit-or-rollback decision for a transaction. Writes
    // synchronously and calls fsync before returning so that a crash after
    // this function returns preserves the record. Must be called BEFORE
    // phase 2 dispatches any XA COMMIT / COMMIT PREPARED / XA ROLLBACK to
    // the participants.
    bool log_decision(const std::string& txn_id,
                      Decision decision,
                      const std::vector<std::string>& participants) {
        std::lock_guard<std::mutex> lk(mu_);
        if (fd_ < 0) return false;
        std::string line;
        line += (decision == Decision::COMMIT) ? "COMMIT\t" : "ROLLBACK\t";
        line += txn_id;
        line += '\t';
        for (size_t i = 0; i < participants.size(); ++i) {
            if (i > 0) line += ',';
            line += participants[i];
        }
        line += '\n';
        return write_and_fsync(line);
    }

    // Record that phase 2 has finished for a transaction (all participants
    // completed the decision). This is the record that removes the
    // transaction from the in-doubt set on recovery.
    bool log_complete(const std::string& txn_id) {
        std::lock_guard<std::mutex> lk(mu_);
        if (fd_ < 0) return false;
        std::string line = "COMPLETE\t" + txn_id + '\n';
        return write_and_fsync(line);
    }

    // Scan an arbitrary log file and return all transactions that have a
    // decision record but no matching completion record. The caller is
    // expected to iterate these and send the appropriate XA COMMIT or XA
    // ROLLBACK to each listed participant.
    //
    // Does not require the log to be open; safe to call at startup before
    // open() if you just want to inspect an existing file.
    static std::vector<InDoubtEntry> scan_in_doubt(const std::string& path) {
        std::vector<InDoubtEntry> in_doubt;
        // Preserve insertion order: track position in `order` and the
        // entry data in `pending`. COMPLETE records remove entries from
        // both.
        std::unordered_map<std::string, size_t> order;
        std::vector<InDoubtEntry> pending;

        FILE* fp = std::fopen(path.c_str(), "r");
        if (!fp) return in_doubt;

        char buf[4096];
        while (std::fgets(buf, sizeof(buf), fp) != nullptr) {
            size_t n = std::strlen(buf);
            while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
                buf[--n] = '\0';
            }
            if (n == 0) continue;

            char* tab1 = std::strchr(buf, '\t');
            if (!tab1) continue;
            *tab1++ = '\0';
            const char* kind = buf;

            if (std::strcmp(kind, "COMPLETE") == 0) {
                auto it = order.find(tab1);
                if (it != order.end()) {
                    // Tombstone this slot -- we'll compact below.
                    pending[it->second].txn_id.clear();
                    order.erase(it);
                }
                continue;
            }

            char* tab2 = std::strchr(tab1, '\t');
            std::string txn_id;
            std::string parts_str;
            if (tab2) {
                *tab2++ = '\0';
                txn_id = tab1;
                parts_str = tab2;
            } else {
                txn_id = tab1;
            }

            InDoubtEntry e;
            e.txn_id = txn_id;
            if (std::strcmp(kind, "COMMIT") == 0) {
                e.decision = Decision::COMMIT;
            } else if (std::strcmp(kind, "ROLLBACK") == 0) {
                e.decision = Decision::ROLLBACK;
            } else {
                continue;
            }
            // Split participants on ','
            const char* p = parts_str.c_str();
            const char* start = p;
            while (*p) {
                if (*p == ',') {
                    if (p > start) e.participants.emplace_back(start, p - start);
                    start = p + 1;
                }
                ++p;
            }
            if (p > start) e.participants.emplace_back(start, p - start);

            auto it = order.find(txn_id);
            if (it != order.end()) {
                // Duplicate decision for the same txn_id -- last writer wins.
                pending[it->second] = std::move(e);
            } else {
                order[txn_id] = pending.size();
                pending.push_back(std::move(e));
            }
        }
        std::fclose(fp);

        // Drop tombstoned entries (those whose txn_id was cleared when
        // a COMPLETE arrived).
        for (auto& e : pending) {
            if (!e.txn_id.empty()) in_doubt.push_back(std::move(e));
        }
        return in_doubt;
    }

    // Convenience wrapper: uses the path the log was opened with.
    std::vector<InDoubtEntry> scan_in_doubt() const {
        return scan_in_doubt(path_);
    }

    // Test-only: truncate the log file. Invalidates any in-doubt recovery
    // scan done afterwards; only use in test setup/teardown.
    bool test_truncate() {
        std::lock_guard<std::mutex> lk(mu_);
        if (fd_ < 0) return false;
        if (::ftruncate(fd_, 0) != 0) return false;
        if (::lseek(fd_, 0, SEEK_SET) == (off_t)-1) return false;
        return true;
    }

    // Rewrite the log in-place so that only the currently in-doubt
    // entries remain. Removes every COMPLETE record and its matching
    // decision record, reducing the file to just the transactions that
    // still need recovery attention.
    //
    // This is the piece that keeps the WAL from growing forever. In a
    // healthy system, compact() is called periodically (e.g. every N
    // successful commits, or after startup recovery runs) and reduces
    // the file to near-zero most of the time -- only genuinely in-doubt
    // transactions persist.
    //
    // Atomicity: writes the compacted contents to a temp file first,
    // then rename(2)s over the live file. rename is POSIX-atomic on the
    // same filesystem, so a crash mid-compact leaves either the old log
    // or the new one, never a half-written one.
    //
    // Thread-safety: takes the internal mutex. Other log operations
    // block until compaction finishes. We briefly close and reopen the
    // underlying fd to point at the new file; any log_decision calls
    // happening during compact() are serialized.
    //
    // Returns true on success. On failure the original log file is
    // left untouched and the caller can try again later.
    bool compact() {
        std::lock_guard<std::mutex> lk(mu_);
        if (path_.empty()) return false;

        // 1. Scan the current file for in-doubt entries.
        auto in_doubt = scan_in_doubt(path_);

        // 2. Write the compacted contents to a temp file next to the
        //    original (so rename stays on the same filesystem and is atomic).
        std::string tmp_path = path_ + ".compact.tmp";
        int tmp_fd = ::open(tmp_path.c_str(),
                            O_WRONLY | O_CREAT | O_TRUNC,
                            0644);
        if (tmp_fd < 0) return false;

        for (const auto& e : in_doubt) {
            std::string line;
            line += (e.decision == Decision::COMMIT) ? "COMMIT\t" : "ROLLBACK\t";
            line += e.txn_id;
            line += '\t';
            for (size_t i = 0; i < e.participants.size(); ++i) {
                if (i > 0) line += ',';
                line += e.participants[i];
            }
            line += '\n';
            if (!write_all(tmp_fd, line)) {
                ::close(tmp_fd);
                ::unlink(tmp_path.c_str());
                return false;
            }
        }

        // 3. fsync the temp file so its contents are durable before we
        //    rename over the live file. Without this, a crash between
        //    the rename and the kernel flushing the temp file could
        //    leave us with a log that's atomically "in place" but not
        //    actually on disk.
        if (::fsync(tmp_fd) != 0) {
            ::close(tmp_fd);
            ::unlink(tmp_path.c_str());
            return false;
        }
        ::close(tmp_fd);

        // 4. Close the current log fd and rename the temp file over the
        //    real one. The rename is atomic on POSIX filesystems.
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
        if (::rename(tmp_path.c_str(), path_.c_str()) != 0) {
            // Rename failed (maybe EXDEV if the temp path ends up on a
            // different filesystem, or ENOSPC). Best effort: reopen the
            // original log so the manager can still log new decisions.
            ::unlink(tmp_path.c_str());
            fd_ = ::open(path_.c_str(),
                         O_WRONLY | O_CREAT | O_APPEND,
                         0644);
            return false;
        }

        // 5. Also fsync the containing directory so the rename itself
        //    is durable. On a crash without this, the filesystem might
        //    replay the old name-to-inode mapping and we'd see stale
        //    state at mount time.
        fsync_parent_dir(path_);

        // 6. Reopen the compacted file in append mode.
        fd_ = ::open(path_.c_str(),
                     O_WRONLY | O_CREAT | O_APPEND,
                     0644);
        return fd_ >= 0;
    }

private:
    mutable std::mutex mu_;
    int fd_ = -1;
    std::string path_;

    // Write `data` to the file and fsync. Caller must hold mu_.
    bool write_and_fsync(const std::string& data) {
        const char* p = data.data();
        size_t remaining = data.size();
        while (remaining > 0) {
            ssize_t w = ::write(fd_, p, remaining);
            if (w < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            p += w;
            remaining -= static_cast<size_t>(w);
        }
        // fsync is what makes this a WAL and not just a log: we need the
        // kernel to push the data to stable storage before we proceed with
        // phase 2.
        if (::fsync(fd_) != 0) return false;
        return true;
    }

    // Write `data` to an arbitrary fd, retrying on EINTR and handling
    // partial writes. Used during compaction.
    static bool write_all(int fd, const std::string& data) {
        const char* p = data.data();
        size_t remaining = data.size();
        while (remaining > 0) {
            ssize_t w = ::write(fd, p, remaining);
            if (w < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            p += w;
            remaining -= static_cast<size_t>(w);
        }
        return true;
    }

    // After an atomic rename, fsync the directory containing the file
    // so the new dirent is durable. Best-effort: directory fsync is
    // required by POSIX but some filesystems don't strictly need it.
    static void fsync_parent_dir(const std::string& path) {
        std::string dir;
        auto slash = path.find_last_of('/');
        if (slash == std::string::npos) {
            dir = ".";
        } else if (slash == 0) {
            dir = "/";
        } else {
            dir = path.substr(0, slash);
        }
        int dfd = ::open(dir.c_str(), O_RDONLY);
        if (dfd < 0) return;
        (void)::fsync(dfd);
        ::close(dfd);
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_DURABLE_TXN_LOG_H
