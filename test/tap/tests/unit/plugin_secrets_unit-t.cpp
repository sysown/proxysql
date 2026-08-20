#include "ProxySQL_PluginSecrets.h"
#include "ProxySQL_PluginSecrets_test.h"
#include "sqlite3db.h"
#include "tap.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

std::string make_temp_dir() {
	char path[] = "/tmp/proxysql_plugin_secrets.XXXXXX";
	char* result = mkdtemp(path);
	return result == nullptr ? "" : result;
}

void remove_temp_dir(const std::string& path) {
	if (path.empty()) return;
	const std::string key = path + "/proxysql-plugin-secrets.key";
	unlink(key.c_str());
	rmdir(path.c_str());
}

std::vector<uint8_t> bytes(const char* value) {
	return std::vector<uint8_t>(value, value + std::strlen(value));
}

std::string as_string(const std::vector<uint8_t>& value) {
	return std::string(value.begin(), value.end());
}

bool select_one_blob(sqlite3* db, const char* sql, std::vector<uint8_t>& value) {
	sqlite3_stmt* stmt = nullptr;
	if ((*proxy_sqlite3_prepare_v2)(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
	const int rc = (*proxy_sqlite3_step)(stmt);
	if (rc == SQLITE_ROW) {
		const auto* data = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
		const int length = sqlite3_column_bytes(stmt, 0);
		if (data != nullptr && length >= 0) value.assign(data, data + length);
	}
	(*proxy_sqlite3_finalize)(stmt);
	return rc == SQLITE_ROW;
}

struct cleanse_record_t {
	const void* address;
	size_t length;
};
std::vector<cleanse_record_t> g_cleanse_records;
void observe_cleanse(void* address, size_t length) {
	g_cleanse_records.push_back({address, length});
}

bool saw_cleanse(const void* address, size_t length) {
	for (const auto& record : g_cleanse_records) {
		if (record.address == address && record.length == length) return true;
	}
	return false;
}

bool saw_cleanse_length(size_t length) {
	for (const auto& record : g_cleanse_records) {
		if (record.length == length) return true;
	}
	return false;
}

int g_open_flags = 0;
void observe_open_flags(int flags) { g_open_flags = flags; }

void create_wrong_length_key(const std::string& datadir) {
	const std::string key_path = datadir + "/proxysql-plugin-secrets.key";
	const int fd = open(key_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
	const char tiny_key[] = "too-short";
	if (fd >= 0) {
		write(fd, tiny_key, sizeof(tiny_key) - 1);
		close(fd);
	}
}

int g_write_eintr_count = 0;
int g_read_eintr_count = 0;
int g_short_write_count = 0;
int g_short_read_count = 0;
ssize_t inject_eintr_and_short_io(bool is_write, int fd, void* buffer, size_t length, int* error) {
	if (is_write && g_write_eintr_count++ == 0) {
		*error = EINTR;
		return -1;
	}
	if (!is_write && g_read_eintr_count++ == 0) {
		*error = EINTR;
		return -1;
	}
	int& short_count = is_write ? g_short_write_count : g_short_read_count;
	if (short_count++ == 0 && length > 1) {
		const size_t short_length = length / 2;
		return is_write ? write(fd, buffer, short_length) : read(fd, buffer, short_length);
	}
	return is_write ? write(fd, buffer, length) : read(fd, buffer, length);
}

int inject_busy_step(sqlite3_stmt*) { return SQLITE_BUSY; }

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(40);

	SQLite3DB db;
	db.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE); // NOSONAR: API requires char*
	const std::string datadir = make_temp_dir();
	ok(!datadir.empty(), "temporary datadir is available");

	ProxySQL_PluginSecrets store(&db, datadir);
	const auto secret = bytes("s3cret");
	ok(store.put("mysql_router", "metadata_password", secret.data(), secret.size()) == ProxySQL_PluginSecretResult::ok,
	   "put encrypts and stores a secret");
	ok(db.execute("INSERT INTO proxysql_plugin_secrets (owner,secret_name,nonce,ciphertext,tag,updated_at) VALUES ('schema_nonce','bad',X'00',X'00',X'00000000000000000000000000000000',1)") == false,
	   "schema rejects non-12-byte nonces");
	ok(db.execute("INSERT INTO proxysql_plugin_secrets (owner,secret_name,nonce,ciphertext,tag,updated_at) VALUES ('schema_tag','bad',X'000000000000000000000000',X'00',X'00',1)") == false,
	   "schema rejects non-16-byte tags");
	ok(db.execute("INSERT INTO proxysql_plugin_secrets (owner,secret_name,nonce,ciphertext,tag) VALUES ('schema_time','bad',X'000000000000000000000000',X'00',X'00000000000000000000000000000000')") == false,
	   "schema requires an update timestamp");

	std::vector<uint8_t> out;
	ok(store.get("mysql_router", "metadata_password", out) == ProxySQL_PluginSecretResult::ok && as_string(out) == "s3cret",
	   "secret round-trips through AES-GCM");
	ok(store.put("mysql_router", "empty_secret", nullptr, 0) == ProxySQL_PluginSecretResult::ok,
	   "empty secret is stored as an authenticated zero-length BLOB");
	out.assign({0x55});
	ok(store.get("mysql_router", "empty_secret", out) == ProxySQL_PluginSecretResult::ok && out.empty(),
	   "empty secret round-trips as an empty plaintext");

	std::vector<uint8_t> ciphertext;
	ok(select_one_blob(db.get_db(), "SELECT ciphertext FROM proxysql_plugin_secrets", ciphertext) &&
	   as_string(ciphertext) != "s3cret",
	   "database ciphertext never contains plaintext");

	struct stat key_stat {};
	const std::string key_path = datadir + "/proxysql-plugin-secrets.key";
	ok(stat(key_path.c_str(), &key_stat) == 0 && (key_stat.st_mode & 0777) == 0600,
	   "new master key is owner-readable only");

	ok(store.get("../bad", "metadata_password", out) == ProxySQL_PluginSecretResult::invalid_argument,
	   "invalid owner is rejected before SQL");
	ok(store.put("mysql_router", "", secret.data(), secret.size()) == ProxySQL_PluginSecretResult::invalid_argument,
	   "invalid secret name is rejected before SQL");
	ok(store.get("-not-an-owner", "metadata_password", out) == ProxySQL_PluginSecretResult::invalid_argument,
	   "owner must begin with an ASCII alphanumeric character or underscore");

	ok(db.execute("UPDATE proxysql_plugin_secrets SET ciphertext = X'00' WHERE owner='mysql_router' AND secret_name='metadata_password'"),
	   "tamper fixture changes ciphertext");
	out.assign({1, 2, 3});
	ok(store.get("mysql_router", "metadata_password", out) == ProxySQL_PluginSecretResult::authentication_failed && out.empty(),
	   "GCM authentication rejects modified ciphertext and clears output");

	const auto atomic_old = bytes("atomic-old");
	const auto atomic_new = bytes("atomic-new");
	ok(store.put("mysql_router", "atomic_failure", atomic_old.data(), atomic_old.size()) == ProxySQL_PluginSecretResult::ok,
	   "atomic-failure fixture stores the previous secret");
	ok(db.execute("CREATE TRIGGER reject_plugin_secret_update BEFORE UPDATE ON proxysql_plugin_secrets "
	              "WHEN NEW.owner='mysql_router' AND NEW.secret_name='atomic_failure' "
	              "BEGIN SELECT RAISE(ABORT, 'injected mutation failure'); END"),
	   "mutation-failure trigger is installed");
	ok(store.put("mysql_router", "atomic_failure", atomic_new.data(), atomic_new.size()) == ProxySQL_PluginSecretResult::storage_error,
	   "failed replacement reports storage error");
	ok(db.execute("DROP TRIGGER reject_plugin_secret_update"),
	   "mutation-failure trigger is removed");
	out.clear();
	ok(store.get("mysql_router", "atomic_failure", out) == ProxySQL_PluginSecretResult::ok && as_string(out) == "atomic-old",
	   "failed replacement leaves the prior encrypted value intact");

	const auto before = bytes("before");
	const auto after = bytes("after");
	ok(store.put("mysql_router", "metadata_password", before.data(), before.size()) == ProxySQL_PluginSecretResult::ok,
	   "replacement fixture restores an encrypted row");
	ok(store.put("mysql_router", "metadata_password", after.data(), after.size()) == ProxySQL_PluginSecretResult::ok,
	   "replacement updates secret atomically");
	out.clear();
	ok(store.get("mysql_router", "metadata_password", out) == ProxySQL_PluginSecretResult::ok && as_string(out) == "after",
	   "atomic replacement leaves only the new plaintext visible");
	ok(store.erase("mysql_router", "metadata_password") == ProxySQL_PluginSecretResult::ok,
	   "erase removes the encrypted secret");
	ok(store.get("mysql_router", "metadata_password", out) == ProxySQL_PluginSecretResult::not_found && out.empty(),
	   "erased secret is unavailable and output is empty");

	{
		proxysql_plugin_secrets_test::scoped_hooks_t hooks({ .cleanse_observer = &observe_cleanse });
		g_cleanse_records.clear();
		ok(store.put("mysql_router", "cleanse_test", secret.data(), secret.size()) == ProxySQL_PluginSecretResult::ok,
		   "cleanse fixture writes secret");
		out.clear();
		ok(store.get("mysql_router", "cleanse_test", out) == ProxySQL_PluginSecretResult::ok,
		   "cleanse fixture decrypts secret");
		ok(saw_cleanse_length(32),
		   "master-key copy is cleansed through the observer");
	}

	const auto staging_secret = bytes("staging-secret-123");
	ok(store.put("mysql_router", "cleanse_failure", staging_secret.data(), staging_secret.size()) == ProxySQL_PluginSecretResult::ok,
	   "failed-decryption cleanse fixture stores a secret");
	ok(db.execute("UPDATE proxysql_plugin_secrets SET tag=X'00000000000000000000000000000000' "
	              "WHERE owner='mysql_router' AND secret_name='cleanse_failure'"),
	   "failed-decryption cleanse fixture tampers with the tag");
	out.assign({0xa1, 0xa2, 0xa3});
	const void* replaced_output_address = out.data();
	{
		proxysql_plugin_secrets_test::scoped_hooks_t hooks({ .cleanse_observer = &observe_cleanse });
		g_cleanse_records.clear();
		ok(store.get("mysql_router", "cleanse_failure", out) == ProxySQL_PluginSecretResult::authentication_failed && out.empty(),
		   "failed decryption does not publish plaintext");
		ok(saw_cleanse(replaced_output_address, 3) &&
		   saw_cleanse_length(staging_secret.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm())),
		   "failed get cleanses both replaced output and unpublished plaintext staging");
	}

	const std::string wrong_length_dir = make_temp_dir();
	create_wrong_length_key(wrong_length_dir);
	ProxySQL_PluginSecrets wrong_length_store(&db, wrong_length_dir);
	ok(wrong_length_store.put("mysql_router", "wrong_key", secret.data(), secret.size()) == ProxySQL_PluginSecretResult::key_error,
	   "existing master key with wrong length is refused");
	remove_temp_dir(wrong_length_dir);

	const std::string symlink_dir = make_temp_dir();
	const std::string symlink_path = symlink_dir + "/proxysql-plugin-secrets.key";
	symlink("/dev/null", symlink_path.c_str());
	ProxySQL_PluginSecrets symlink_store(&db, symlink_dir);
	ok(symlink_store.put("mysql_router", "symlink_key", secret.data(), secret.size()) == ProxySQL_PluginSecretResult::key_error,
	   "symlink master key is refused");
	unlink(symlink_path.c_str());
	remove_temp_dir(symlink_dir);

	const std::string flags_dir = make_temp_dir();
	g_open_flags = 0;
	{
		proxysql_plugin_secrets_test::scoped_hooks_t hooks({ .key_open_observer = &observe_open_flags });
		ProxySQL_PluginSecrets flags_store(&db, flags_dir);
		ok(flags_store.put("mysql_router", "flags_key", secret.data(), secret.size()) == ProxySQL_PluginSecretResult::ok,
		   "first key creation succeeds");
		ok((g_open_flags & O_CREAT) != 0 && (g_open_flags & O_EXCL) != 0 && (g_open_flags & O_NOFOLLOW) != 0,
		   "first key creation uses exclusive no-follow flags");
	}
	remove_temp_dir(flags_dir);

	const std::string io_dir = make_temp_dir();
	g_write_eintr_count = 0;
	g_read_eintr_count = 0;
	g_short_write_count = 0;
	g_short_read_count = 0;
	{
		proxysql_plugin_secrets_test::scoped_hooks_t hooks({ .key_io_hook = &inject_eintr_and_short_io });
		ProxySQL_PluginSecrets io_store(&db, io_dir);
		ok(io_store.put("mysql_router", "io_secret", secret.data(), secret.size()) == ProxySQL_PluginSecretResult::ok,
		   "exclusive key creation survives injected EINTR and short writes");
		out.clear();
		ProxySQL_PluginSecrets io_reader(&db, io_dir);
		ok(io_reader.get("mysql_router", "io_secret", out) == ProxySQL_PluginSecretResult::ok && as_string(out) == "s3cret",
		   "existing key read survives injected EINTR and short reads");
		ok(g_write_eintr_count > 0 && g_read_eintr_count > 0 &&
		   g_short_write_count > 0 && g_short_read_count > 0,
		   "I/O hook observed retries after EINTR and partial key transfers");
	}
	remove_temp_dir(io_dir);

	bool busy_step_reported = false;
	{
		proxysql_plugin_secrets_test::scoped_hooks_t hooks({ .sqlite_step_hook = &inject_busy_step });
		out.assign({0x42});
		busy_step_reported = store.get("mysql_router", "cleanse_test", out) == ProxySQL_PluginSecretResult::storage_error && out.empty();
	}
	out.clear();
	ok(busy_step_reported &&
	   store.get("mysql_router", "cleanse_test", out) == ProxySQL_PluginSecretResult::ok && as_string(out) == "s3cret",
	   "scoped SQLite fault injection reports storage error and cannot outlive its fixture");

	remove_temp_dir(datadir);
	return exit_status();
}
