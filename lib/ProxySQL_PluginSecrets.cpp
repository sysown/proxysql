#ifdef PROXYSQL40

#include "ProxySQL_PluginSecrets.h"

#include "sqlite3db.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace {

constexpr size_t k_master_key_length = 32;
constexpr size_t k_nonce_length = 12;
constexpr size_t k_tag_length = 16;
constexpr const char k_key_filename[] = "proxysql-plugin-secrets.key";
constexpr const char k_aad_context[] = "proxysql-plugin-secret-v1";

std::mutex g_observer_mutex;
ProxySQL_PluginSecrets::cleanse_observer_t g_cleanse_observer = nullptr;
ProxySQL_PluginSecrets::key_open_observer_t g_key_open_observer = nullptr;
ProxySQL_PluginSecrets::key_io_hook_t g_key_io_hook = nullptr;
ProxySQL_PluginSecrets::sqlite_step_hook_t g_sqlite_step_hook = nullptr;

void cleanse(void* ptr, size_t length) {
	if (ptr == nullptr || length == 0) return;
	OPENSSL_cleanse(ptr, length);
	std::lock_guard<std::mutex> lock(g_observer_mutex);
	if (g_cleanse_observer != nullptr) g_cleanse_observer(ptr, length);
}

void cleanse_vector(std::vector<uint8_t>& value) {
	if (!value.empty()) cleanse(value.data(), value.size());
	value.clear();
}

struct key_guard_t {
	uint8_t* key;
	~key_guard_t() { cleanse(key, k_master_key_length); }
};

struct vector_guard_t {
	std::vector<uint8_t>& value;
	~vector_guard_t() { cleanse_vector(value); }
};

struct evp_ctx_guard_t {
	EVP_CIPHER_CTX* ctx { EVP_CIPHER_CTX_new() };
	~evp_ctx_guard_t() { EVP_CIPHER_CTX_free(ctx); }
};

bool valid_component(const char* value) {
	if (value == nullptr || value[0] == '\0') return false;
	const size_t length = std::strlen(value);
	if (length > 128) return false;
	const unsigned char first = static_cast<unsigned char>(value[0]);
	if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ||
	      (first >= '0' && first <= '9') || first == '_')) return false;
	for (size_t i = 1; i < length; ++i) {
		const unsigned char ch = static_cast<unsigned char>(value[i]);
		if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
		      (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-')) return false;
	}
	return true;
}

std::string make_aad(const char* owner, const char* name) {
	std::string aad;
	aad.reserve(std::strlen(owner) + std::strlen(name) + sizeof(k_aad_context) + 2);
	aad.append(owner);
	aad.push_back('\0');
	aad.append(name);
	aad.push_back('\0');
	aad.append(k_aad_context, sizeof(k_aad_context) - 1);
	return aad;
}

bool sqlite_exec(sqlite3* db, const char* sql) {
	char* error = nullptr;
	const int rc = (*proxy_sqlite3_exec)(db, sql, nullptr, nullptr, &error);
	if (error != nullptr) (*proxy_sqlite3_free)(error);
	return rc == SQLITE_OK;
}

bool write_all(int fd, const uint8_t* value, size_t length) {
	while (length != 0) {
		ProxySQL_PluginSecrets::key_io_hook_t hook = nullptr;
		{
			std::lock_guard<std::mutex> lock(g_observer_mutex);
			hook = g_key_io_hook;
		}
		int io_error = 0;
		const ssize_t written = hook != nullptr ?
			hook(true, fd, const_cast<uint8_t*>(value), length, &io_error) : write(fd, value, length);
		if (written < 0 && (hook != nullptr ? io_error : errno) == EINTR) continue;
		if (written <= 0) return false;
		value += written;
		length -= static_cast<size_t>(written);
	}
	return true;
}

bool read_all(int fd, uint8_t* value, size_t length) {
	while (length != 0) {
		ProxySQL_PluginSecrets::key_io_hook_t hook = nullptr;
		{
			std::lock_guard<std::mutex> lock(g_observer_mutex);
			hook = g_key_io_hook;
		}
		int io_error = 0;
		const ssize_t read_count = hook != nullptr ? hook(false, fd, value, length, &io_error) : read(fd, value, length);
		if (read_count < 0 && (hook != nullptr ? io_error : errno) == EINTR) continue;
		if (read_count <= 0) return false;
		value += read_count;
		length -= static_cast<size_t>(read_count);
	}
	return true;
}

int sqlite_step(sqlite3_stmt* stmt) {
	ProxySQL_PluginSecrets::sqlite_step_hook_t hook = nullptr;
	{
		std::lock_guard<std::mutex> lock(g_observer_mutex);
		hook = g_sqlite_step_hook;
	}
	return hook != nullptr ? hook(stmt) : (*proxy_sqlite3_step)(stmt);
}

bool safe_key_stat(const struct stat& st) {
	return S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1 &&
		(st.st_mode & 0777) == 0600 && st.st_size == static_cast<off_t>(k_master_key_length);
}

void observe_key_open(int flags) {
	std::lock_guard<std::mutex> lock(g_observer_mutex);
	if (g_key_open_observer != nullptr) g_key_open_observer(flags);
}

} // namespace

const char* proxysql_plugin_secrets_table_definition() {
	return "CREATE TABLE IF NOT EXISTS proxysql_plugin_secrets ("
		"owner TEXT NOT NULL,"
		"secret_name TEXT NOT NULL,"
		"nonce BLOB NOT NULL CHECK(length(nonce)=12),"
		"ciphertext BLOB NOT NULL,"
		"tag BLOB NOT NULL CHECK(length(tag)=16),"
		"updated_at INTEGER NOT NULL,"
		"PRIMARY KEY(owner, secret_name)"
		")";
}

ProxySQL_PluginSecrets::ProxySQL_PluginSecrets(SQLite3DB* configdb, std::string datadir)
	: configdb_(configdb), datadir_(std::move(datadir)) {}

void ProxySQL_PluginSecrets::set_cleanse_observer(cleanse_observer_t observer) {
	std::lock_guard<std::mutex> lock(g_observer_mutex);
	g_cleanse_observer = observer;
}

void ProxySQL_PluginSecrets::set_key_open_observer(key_open_observer_t observer) {
	std::lock_guard<std::mutex> lock(g_observer_mutex);
	g_key_open_observer = observer;
}

void ProxySQL_PluginSecrets::set_key_io_hook(key_io_hook_t hook) {
	std::lock_guard<std::mutex> lock(g_observer_mutex);
	g_key_io_hook = hook;
}

void ProxySQL_PluginSecrets::set_sqlite_step_hook(sqlite_step_hook_t hook) {
	std::lock_guard<std::mutex> lock(g_observer_mutex);
	g_sqlite_step_hook = hook;
}

bool ProxySQL_PluginSecrets::ensure_schema() const {
	return configdb_ != nullptr && configdb_->get_db() != nullptr &&
		sqlite_exec(configdb_->get_db(), proxysql_plugin_secrets_table_definition());
}

ProxySQL_PluginSecretResult ProxySQL_PluginSecrets::load_master_key(uint8_t key[k_master_key_length]) const {
	if (datadir_.empty()) return ProxySQL_PluginSecretResult::not_available;
	const std::string key_path = datadir_ + "/" + k_key_filename;
	struct stat path_stat {};
	if (lstat(key_path.c_str(), &path_stat) != 0) {
		if (errno != ENOENT) return ProxySQL_PluginSecretResult::key_error;
		const int create_flags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC;
		observe_key_open(create_flags);
		const int fd = open(key_path.c_str(), create_flags, 0600);
		if (fd < 0) {
			// Another writer may have created the key. Re-enter the checked
			// existing-file path rather than ever replacing it.
			if (errno != EEXIST) return ProxySQL_PluginSecretResult::key_error;
		} else {
			const bool random_ok = RAND_bytes(key, k_master_key_length) == 1;
			const bool write_ok = random_ok && write_all(fd, key, k_master_key_length);
			const bool mode_ok = write_ok && fchmod(fd, 0600) == 0;
			const bool sync_ok = mode_ok && fsync(fd) == 0;
			struct stat created_stat {};
			const bool stat_ok = sync_ok && fstat(fd, &created_stat) == 0 && safe_key_stat(created_stat);
			close(fd);
			if (!stat_ok) return ProxySQL_PluginSecretResult::key_error;
			return ProxySQL_PluginSecretResult::ok;
		}
	}

	if (lstat(key_path.c_str(), &path_stat) != 0 || S_ISLNK(path_stat.st_mode) || !safe_key_stat(path_stat)) {
		return ProxySQL_PluginSecretResult::key_error;
	}
	const int fd = open(key_path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) return ProxySQL_PluginSecretResult::key_error;
	struct stat opened_stat {};
	const bool stable = fstat(fd, &opened_stat) == 0 && safe_key_stat(opened_stat) &&
		opened_stat.st_dev == path_stat.st_dev && opened_stat.st_ino == path_stat.st_ino;
	const bool read_ok = stable && read_all(fd, key, k_master_key_length);
	close(fd);
	return read_ok ? ProxySQL_PluginSecretResult::ok : ProxySQL_PluginSecretResult::key_error;
}

ProxySQL_PluginSecretResult ProxySQL_PluginSecrets::put(const char* owner, const char* name,
	const uint8_t* bytes, size_t length) {
	if (!valid_component(owner) || !valid_component(name) || (bytes == nullptr && length != 0)) {
		return ProxySQL_PluginSecretResult::invalid_argument;
	}
	if (!ensure_schema()) return ProxySQL_PluginSecretResult::storage_error;

	std::array<uint8_t, k_master_key_length> key {};
	key_guard_t key_guard { key.data() };
	const auto key_result = load_master_key(key.data());
	if (key_result != ProxySQL_PluginSecretResult::ok) return key_result;

	std::array<uint8_t, k_nonce_length> nonce {};
	std::array<uint8_t, k_tag_length> tag {};
	std::vector<uint8_t> ciphertext(length + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
	vector_guard_t ciphertext_guard { ciphertext };
	const std::string aad = make_aad(owner, name);
	evp_ctx_guard_t ctx_guard;
	int output_length = 0;
	int final_length = 0;
	if (ctx_guard.ctx == nullptr || RAND_bytes(nonce.data(), nonce.size()) != 1 ||
		EVP_EncryptInit_ex(ctx_guard.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
		EVP_CIPHER_CTX_ctrl(ctx_guard.ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1 ||
		EVP_EncryptInit_ex(ctx_guard.ctx, nullptr, nullptr, key.data(), nonce.data()) != 1 ||
		EVP_EncryptUpdate(ctx_guard.ctx, nullptr, &output_length,
			reinterpret_cast<const uint8_t*>(aad.data()), aad.size()) != 1 ||
		EVP_EncryptUpdate(ctx_guard.ctx, ciphertext.data(), &output_length, bytes, length) != 1 ||
		EVP_EncryptFinal_ex(ctx_guard.ctx, ciphertext.data() + output_length, &final_length) != 1 ||
		EVP_CIPHER_CTX_ctrl(ctx_guard.ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1) {
		return ProxySQL_PluginSecretResult::storage_error;
	}
	ciphertext.resize(static_cast<size_t>(output_length + final_length));

	sqlite3* db = configdb_->get_db();
	if (!sqlite_exec(db, "BEGIN IMMEDIATE")) return ProxySQL_PluginSecretResult::storage_error;
	bool committed = false;
	auto rollback = [&]() { if (!committed) sqlite_exec(db, "ROLLBACK"); };
	sqlite3_stmt* stmt = nullptr;
	const char* sql = "INSERT INTO proxysql_plugin_secrets (owner,secret_name,nonce,ciphertext,tag,updated_at) "
		"VALUES (?,?,?,?,?,strftime('%s','now')) "
		"ON CONFLICT(owner,secret_name) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext,tag=excluded.tag,updated_at=excluded.updated_at";
	if ((*proxy_sqlite3_prepare_v2)(db, sql, -1, &stmt, nullptr) != SQLITE_OK) { rollback(); return ProxySQL_PluginSecretResult::storage_error; }
	const bool bound = (*proxy_sqlite3_bind_text)(stmt, 1, owner, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
		(*proxy_sqlite3_bind_text)(stmt, 2, name, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
		(*proxy_sqlite3_bind_blob)(stmt, 3, nonce.data(), nonce.size(), SQLITE_TRANSIENT) == SQLITE_OK &&
		(*proxy_sqlite3_bind_blob)(stmt, 4,
			ciphertext.empty() ? static_cast<const void*>("\0") : static_cast<const void*>(ciphertext.data()),
			ciphertext.size(), SQLITE_TRANSIENT) == SQLITE_OK &&
		(*proxy_sqlite3_bind_blob)(stmt, 5, tag.data(), tag.size(), SQLITE_TRANSIENT) == SQLITE_OK;
	const bool stepped = bound && sqlite_step(stmt) == SQLITE_DONE;
	(*proxy_sqlite3_finalize)(stmt);
	if (!stepped || !sqlite_exec(db, "COMMIT")) { rollback(); return ProxySQL_PluginSecretResult::storage_error; }
	committed = true;
	return ProxySQL_PluginSecretResult::ok;
}

ProxySQL_PluginSecretResult ProxySQL_PluginSecrets::get(const char* owner, const char* name,
	std::vector<uint8_t>& plaintext) {
	cleanse_vector(plaintext);
	if (!valid_component(owner) || !valid_component(name)) return ProxySQL_PluginSecretResult::invalid_argument;
	if (!ensure_schema()) return ProxySQL_PluginSecretResult::storage_error;

	std::array<uint8_t, k_master_key_length> key {};
	key_guard_t key_guard { key.data() };
	const auto key_result = load_master_key(key.data());
	if (key_result != ProxySQL_PluginSecretResult::ok) return key_result;

	sqlite3_stmt* stmt = nullptr;
	const char* sql = "SELECT nonce,ciphertext,tag FROM proxysql_plugin_secrets WHERE owner=? AND secret_name=?";
	if ((*proxy_sqlite3_prepare_v2)(configdb_->get_db(), sql, -1, &stmt, nullptr) != SQLITE_OK) return ProxySQL_PluginSecretResult::storage_error;
	const bool bound = (*proxy_sqlite3_bind_text)(stmt, 1, owner, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
		(*proxy_sqlite3_bind_text)(stmt, 2, name, -1, SQLITE_TRANSIENT) == SQLITE_OK;
	if (!bound) {
		(*proxy_sqlite3_finalize)(stmt);
		return ProxySQL_PluginSecretResult::storage_error;
	}
	const int step_result = sqlite_step(stmt);
	if (step_result != SQLITE_ROW) {
		(*proxy_sqlite3_finalize)(stmt);
		return step_result == SQLITE_DONE ? ProxySQL_PluginSecretResult::not_found : ProxySQL_PluginSecretResult::storage_error;
	}
	const auto* nonce = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
	const int nonce_length = sqlite3_column_bytes(stmt, 0);
	const auto* ciphertext = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 1));
	const int ciphertext_length = sqlite3_column_bytes(stmt, 1);
	const int ciphertext_type = (*proxy_sqlite3_column_type)(stmt, 1);
	const auto* tag = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 2));
	const int tag_length = sqlite3_column_bytes(stmt, 2);
	if (nonce == nullptr || nonce_length != static_cast<int>(k_nonce_length) || ciphertext_type != SQLITE_BLOB || ciphertext_length < 0 ||
		tag == nullptr || tag_length != static_cast<int>(k_tag_length)) {
		(*proxy_sqlite3_finalize)(stmt);
		return ProxySQL_PluginSecretResult::authentication_failed;
	}
	std::vector<uint8_t> staging(static_cast<size_t>(ciphertext_length) + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
	vector_guard_t staging_guard { staging };
	const uint8_t empty_ciphertext = 0;
	const std::string aad = make_aad(owner, name);
	evp_ctx_guard_t ctx_guard;
	int output_length = 0;
	int final_length = 0;
	const bool decrypted = ctx_guard.ctx != nullptr &&
		EVP_DecryptInit_ex(ctx_guard.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
		EVP_CIPHER_CTX_ctrl(ctx_guard.ctx, EVP_CTRL_GCM_SET_IVLEN, k_nonce_length, nullptr) == 1 &&
		EVP_DecryptInit_ex(ctx_guard.ctx, nullptr, nullptr, key.data(), nonce) == 1 &&
		EVP_DecryptUpdate(ctx_guard.ctx, nullptr, &output_length, reinterpret_cast<const uint8_t*>(aad.data()), aad.size()) == 1 &&
		EVP_DecryptUpdate(ctx_guard.ctx, staging.data(), &output_length,
			ciphertext_length == 0 ? &empty_ciphertext : ciphertext, ciphertext_length) == 1 &&
		EVP_CIPHER_CTX_ctrl(ctx_guard.ctx, EVP_CTRL_GCM_SET_TAG, k_tag_length, const_cast<uint8_t*>(tag)) == 1 &&
		EVP_DecryptFinal_ex(ctx_guard.ctx, staging.data() + output_length, &final_length) == 1;
	(*proxy_sqlite3_finalize)(stmt);
	if (!decrypted) return ProxySQL_PluginSecretResult::authentication_failed;
	staging.resize(static_cast<size_t>(output_length + final_length));
	plaintext.swap(staging);
	return ProxySQL_PluginSecretResult::ok;
}

ProxySQL_PluginSecretResult ProxySQL_PluginSecrets::erase(const char* owner, const char* name) {
	if (!valid_component(owner) || !valid_component(name)) return ProxySQL_PluginSecretResult::invalid_argument;
	if (!ensure_schema()) return ProxySQL_PluginSecretResult::storage_error;
	sqlite3* db = configdb_->get_db();
	if (!sqlite_exec(db, "BEGIN IMMEDIATE")) return ProxySQL_PluginSecretResult::storage_error;
	bool committed = false;
	auto rollback = [&]() { if (!committed) sqlite_exec(db, "ROLLBACK"); };
	sqlite3_stmt* stmt = nullptr;
	if ((*proxy_sqlite3_prepare_v2)(db, "DELETE FROM proxysql_plugin_secrets WHERE owner=? AND secret_name=?", -1, &stmt, nullptr) != SQLITE_OK) {
		rollback(); return ProxySQL_PluginSecretResult::storage_error;
	}
	const bool bound = (*proxy_sqlite3_bind_text)(stmt, 1, owner, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
		(*proxy_sqlite3_bind_text)(stmt, 2, name, -1, SQLITE_TRANSIENT) == SQLITE_OK;
	const bool stepped = bound && sqlite_step(stmt) == SQLITE_DONE;
	const int changed = stepped ? (*proxy_sqlite3_changes)(db) : 0;
	(*proxy_sqlite3_finalize)(stmt);
	if (!stepped || !sqlite_exec(db, "COMMIT")) { rollback(); return ProxySQL_PluginSecretResult::storage_error; }
	committed = true;
	return changed == 0 ? ProxySQL_PluginSecretResult::not_found : ProxySQL_PluginSecretResult::ok;
}

#endif /* PROXYSQL40 */
