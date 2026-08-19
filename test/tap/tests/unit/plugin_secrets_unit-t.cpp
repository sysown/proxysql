#include "ProxySQL_PluginSecrets.h"
#include "sqlite3db.h"
#include "tap.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
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

int g_cleanse_calls = 0;
size_t g_cleanse_bytes = 0;
void observe_cleanse(void*, size_t length) {
	++g_cleanse_calls;
	g_cleanse_bytes += length;
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

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(25);

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

	ok(db.execute("UPDATE proxysql_plugin_secrets SET ciphertext = X'00'"),
	   "tamper fixture changes ciphertext");
	out.assign({1, 2, 3});
	ok(store.get("mysql_router", "metadata_password", out) == ProxySQL_PluginSecretResult::authentication_failed && out.empty(),
	   "GCM authentication rejects modified ciphertext and clears output");

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

	ProxySQL_PluginSecrets::set_cleanse_observer(&observe_cleanse);
	g_cleanse_calls = 0;
	g_cleanse_bytes = 0;
	ok(store.put("mysql_router", "cleanse_test", secret.data(), secret.size()) == ProxySQL_PluginSecretResult::ok,
	   "cleanse fixture writes secret");
	out.clear();
	ok(store.get("mysql_router", "cleanse_test", out) == ProxySQL_PluginSecretResult::ok,
	   "cleanse fixture decrypts secret");
	ok(g_cleanse_calls >= 3 && g_cleanse_bytes >= 32,
	   "key copies and plaintext staging are cleansed through the observer");
	ProxySQL_PluginSecrets::set_cleanse_observer(nullptr);

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
	ProxySQL_PluginSecrets::set_key_open_observer(&observe_open_flags);
	ProxySQL_PluginSecrets flags_store(&db, flags_dir);
	ok(flags_store.put("mysql_router", "flags_key", secret.data(), secret.size()) == ProxySQL_PluginSecretResult::ok,
	   "first key creation succeeds");
	ok((g_open_flags & O_CREAT) != 0 && (g_open_flags & O_EXCL) != 0 && (g_open_flags & O_NOFOLLOW) != 0,
	   "first key creation uses exclusive no-follow flags");
	ProxySQL_PluginSecrets::set_key_open_observer(nullptr);
	remove_temp_dir(flags_dir);

	remove_temp_dir(datadir);
	return exit_status();
}
