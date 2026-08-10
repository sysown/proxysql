#include "tap.h"

#include "MySQL_Caching_Sha2_RSA.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <memory>
#ifdef __linux__
#include <chrono>
#include <condition_variable>
#include <mutex>
#endif
#include <string>
#include <thread>
#include <vector>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

class TempDir {
public:
	TempDir() {
		char path_template[] = "/tmp/proxysql-caching-sha2-rsa-XXXXXX"; // NOSONAR: mkdtemp creates this test directory atomically with owner-only permissions.
		char* created = mkdtemp(path_template);
		if (created == nullptr) {
			BAIL_OUT("failed to create an isolated RSA test directory");
		}
		path_ = created;
	}

	~TempDir() {
		if (!path_.empty()) {
			unlink((path_ + "/private.pem").c_str());
			unlink((path_ + "/public.pem").c_str());
			unlink((path_ + "/traditional-private.pem").c_str());
			unlink((path_ + "/malformed-private.pem").c_str());
			unlink((path_ + "/encrypted-private.pem").c_str());
			unlink((path_ + "/encrypted-public.pem").c_str());
			unlink((path_ + "/ec-private.pem").c_str());
			unlink((path_ + "/ec-public.pem").c_str());
			unlink((path_ + "/weak-private.pem").c_str());
			unlink((path_ + "/weak-public.pem").c_str());
			unlink((path_ + "/trailing-private.pem").c_str());
			unlink((path_ + "/trailing-public.pem").c_str());
			unlink((path_ + "/private.pem.lock").c_str());
			rmdir(path_.c_str());
		}
	}
	TempDir(const TempDir&) = delete;
	TempDir& operator=(const TempDir&) = delete;
	TempDir(TempDir&&) = delete;
	TempDir& operator=(TempDir&&) = delete;

	const std::string& path() const { return path_; }

private:
	std::string path_;
};

using EVPKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

#ifdef __linux__
static std::mutex publication_lock_observer_mutex;
static std::condition_variable publication_lock_observer_cv;
static bool publication_lock_observer_enabled = false;
static bool publication_lock_attempted = false;
static bool publication_lock_contended = false;
static bool publication_reload_finished = false;

extern "C" int __real_flock(int fd, int operation);

extern "C" int __wrap_flock(int fd, int operation) {
	bool observe_attempt = false;
	{
		std::lock_guard<std::mutex> lock(publication_lock_observer_mutex);
		observe_attempt = publication_lock_observer_enabled &&
			(operation & LOCK_EX) != 0 && (operation & LOCK_NB) == 0;
	}
	if (!observe_attempt) {
		return __real_flock(fd, operation);
	}

	const int probe_result = __real_flock(fd, operation | LOCK_NB);
	const int probe_errno = errno;
	const bool contended = probe_result < 0 &&
		(probe_errno == EAGAIN || probe_errno == EWOULDBLOCK);
	if (probe_result == 0) {
		(void)__real_flock(fd, LOCK_UN);
	}
	{
		std::lock_guard<std::mutex> lock(publication_lock_observer_mutex);
		publication_lock_attempted = true;
		publication_lock_contended = contended;
	}
	publication_lock_observer_cv.notify_all();
	errno = probe_errno;
	return __real_flock(fd, operation);
}
#endif

static std::string first_line(const std::string& path) {
	BIO* raw_bio = BIO_new_file(path.c_str(), "r");
	if (raw_bio == nullptr) {
		return {};
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
	char line[128] {};
	const int length = BIO_gets(bio.get(), line, sizeof(line));
	return length > 0 ? std::string(line, static_cast<size_t>(length)) : std::string();
}

static bool write_traditional_private_key(
	const std::string& source_path,
	const std::string& destination_path
) {
	BIO* raw_input = BIO_new_file(source_path.c_str(), "r");
	if (raw_input == nullptr) {
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> input(raw_input, &BIO_free);
	EVP_PKEY* raw_key = PEM_read_bio_PrivateKey(input.get(), nullptr, nullptr, nullptr);
	if (raw_key == nullptr) {
		return false;
	}
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, &EVP_PKEY_free);
	BIO* raw_output = BIO_new_file(destination_path.c_str(), "w");
	if (raw_output == nullptr) {
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> output(raw_output, &BIO_free);
	const bool written = PEM_write_bio_PrivateKey_traditional(
		output.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr
	) == 1;
	return written && chmod(destination_path.c_str(), 0600) == 0;
}

static EVPKeyPtr read_private_key(const std::string& path) {
	BIO* raw_bio = BIO_new_file(path.c_str(), "r");
	if (raw_bio == nullptr) {
		return EVPKeyPtr(nullptr, &EVP_PKEY_free);
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
	return EVPKeyPtr(
		PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), &EVP_PKEY_free
	);
}

static EVPKeyPtr generate_rsa_key(int bits) {
	EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	if (raw_context == nullptr) {
		return EVPKeyPtr(nullptr, &EVP_PKEY_free);
	}
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
		raw_context, &EVP_PKEY_CTX_free
	);
	EVP_PKEY* raw_key = nullptr;
	if (EVP_PKEY_keygen_init(context.get()) <= 0 ||
		EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), bits) <= 0 ||
		EVP_PKEY_keygen(context.get(), &raw_key) <= 0) {
		EVP_PKEY_free(raw_key);
		return EVPKeyPtr(nullptr, &EVP_PKEY_free);
	}
	return EVPKeyPtr(raw_key, &EVP_PKEY_free);
}

static EVPKeyPtr generate_ec_key() {
	EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
	if (raw_context == nullptr) {
		return EVPKeyPtr(nullptr, &EVP_PKEY_free);
	}
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
		raw_context, &EVP_PKEY_CTX_free
	);
	EVP_PKEY* raw_key = nullptr;
	if (EVP_PKEY_keygen_init(context.get()) <= 0 ||
		EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
			context.get(), NID_X9_62_prime256v1
		) <= 0 || EVP_PKEY_keygen(context.get(), &raw_key) <= 0) {
		EVP_PKEY_free(raw_key);
		return EVPKeyPtr(nullptr, &EVP_PKEY_free);
	}
	return EVPKeyPtr(raw_key, &EVP_PKEY_free);
}

static bool write_pkcs8_key_pair(
	EVP_PKEY* key,
	const std::string& private_path,
	const std::string& public_path,
	bool encrypted = false
) {
	if (key == nullptr) {
		return false;
	}
	BIO* raw_private = BIO_new_file(private_path.c_str(), "w");
	if (raw_private == nullptr) {
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> private_bio(raw_private, &BIO_free);
	char passphrase[] = "test-passphrase";
	if (PEM_write_bio_PKCS8PrivateKey(
		private_bio.get(), key, encrypted ? EVP_aes_256_cbc() : nullptr,
		encrypted ? passphrase : nullptr,
		encrypted ? static_cast<int>(sizeof(passphrase) - 1) : 0,
		nullptr, nullptr
	) != 1 || chmod(private_path.c_str(), 0600) != 0) {
		return false;
	}
	BIO* raw_public = BIO_new_file(public_path.c_str(), "w");
	if (raw_public == nullptr) {
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> public_bio(raw_public, &BIO_free);
	return PEM_write_bio_PUBKEY(public_bio.get(), key) == 1 &&
		chmod(public_path.c_str(), 0644) == 0; // NOSONAR(cpp:S2612): RSA public keys are intentionally world-readable.
}

static bool write_public_key(EVP_PKEY* key, const std::string& public_path) {
	if (key == nullptr) {
		return false;
	}
	BIO* raw_public = BIO_new_file(public_path.c_str(), "w");
	if (raw_public == nullptr) {
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> public_bio(raw_public, &BIO_free);
	return PEM_write_bio_PUBKEY(public_bio.get(), key) == 1 &&
		chmod(public_path.c_str(), 0644) == 0; // NOSONAR(cpp:S2612): RSA public keys are intentionally world-readable.
}

static bool write_malformed_private_key(const std::string& path) {
	BIO* raw_bio = BIO_new_file(path.c_str(), "w");
	if (raw_bio == nullptr) {
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
	return BIO_puts(bio.get(), "-----BEGIN PRIVATE KEY-----\nnot-a-key\n") > 0 &&
		chmod(path.c_str(), 0600) == 0;
}

static bool append_text(const std::string& path, const char* text) {
	BIO* raw_bio = BIO_new_file(path.c_str(), "a");
	if (raw_bio == nullptr) {
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
	return BIO_puts(bio.get(), text) > 0;
}

static std::vector<unsigned char> encrypt_password_payload(
	const MySQL_Caching_Sha2_RSA_Key_Snapshot& snapshot,
	const std::vector<unsigned char>& cleartext,
	const unsigned char* scramble,
	size_t scramble_length
) {
	std::vector<unsigned char> scrambled = cleartext;
	for (size_t index = 0; index < scrambled.size(); ++index) {
		scrambled[index] ^= scramble[index % scramble_length];
	}

	BIO* raw_bio = BIO_new_mem_buf(
		snapshot.public_key_pem().data(),
		static_cast<int>(snapshot.public_key_pem().size())
	);
	if (raw_bio == nullptr) {
		return {};
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
	EVP_PKEY* raw_key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
	if (raw_key == nullptr) {
		return {};
	}
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, &EVP_PKEY_free);
	EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new(key.get(), nullptr);
	if (raw_context == nullptr) {
		return {};
	}
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
		raw_context, &EVP_PKEY_CTX_free
	);
	if (EVP_PKEY_encrypt_init(context.get()) <= 0 ||
		EVP_PKEY_CTX_set_rsa_padding(context.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
		EVP_PKEY_CTX_set_rsa_oaep_md(context.get(), EVP_sha1()) <= 0 || // NOSONAR(cpp:S4790): test client must match MySQL OAEP SHA-1.
		EVP_PKEY_CTX_set_rsa_mgf1_md(context.get(), EVP_sha1()) <= 0) { // NOSONAR(cpp:S4790): test client must match MySQL MGF1 SHA-1.
		return {};
	}
	size_t ciphertext_length = 0;
	if (EVP_PKEY_encrypt(
		context.get(), nullptr, &ciphertext_length, scrambled.data(), scrambled.size()
	) <= 0) {
		return {};
	}
	std::vector<unsigned char> ciphertext(ciphertext_length);
	if (EVP_PKEY_encrypt(
		context.get(), ciphertext.data(), &ciphertext_length, scrambled.data(), scrambled.size()
	) <= 0) {
		return {};
	}
	ciphertext.resize(ciphertext_length);
	return ciphertext;
}

int main() {
	plan(48);

	MySQL_Caching_Sha2_RSA manager;
	MySQL_Caching_Sha2_RSA_Config config;
	config.auto_generate = false;

	const MySQL_Caching_Sha2_RSA_Reload_Result result = manager.reload(config);

	ok(result.accepted,
		"empty key paths are accepted when automatic generation is disabled");
	ok(manager.acquire() == nullptr,
		"accepted empty key paths leave RSA authentication unavailable");

	TempDir temp_dir;
	ok(!temp_dir.path().empty(), "created an isolated key directory");

	config.auto_generate = true;
	config.datadir = temp_dir.path();
	config.private_key_path = "private.pem";
	config.public_key_path = "public.pem";
	const mode_t previous_umask = umask(0077); // NOSONAR(cpp:S5849): test temporarily restricts generated-file permissions and restores the previous mask.
	const MySQL_Caching_Sha2_RSA_Reload_Result generated = manager.reload(config);
	umask(previous_umask);
	const auto snapshot = manager.acquire();

	ok(generated.accepted && generated.available,
		"missing key pair is generated when automatic generation is enabled");
	ok(snapshot != nullptr, "generated key pair is published as an active snapshot");
	if (snapshot == nullptr) {
		return exit_status();
	}

	ok(snapshot->public_key_pem().find("-----BEGIN PUBLIC KEY-----") == 0,
		"snapshot exposes a canonical PKIX public key");
	ok(snapshot->ciphertext_size() == 256,
		"generated RSA-2048 key accepts a 256-byte ciphertext");

	struct stat private_stat {};
	struct stat public_stat {};
	const int private_stat_rc = stat((temp_dir.path() + "/private.pem").c_str(), &private_stat);
	const int public_stat_rc = stat((temp_dir.path() + "/public.pem").c_str(), &public_stat);
	ok(private_stat_rc == 0 && (private_stat.st_mode & 0777) == 0600,
		"generated private key is stored with mode 0600");
	ok(public_stat_rc == 0 && (public_stat.st_mode & 0777) == 0644,
		"generated public key is stored with mode 0644");
	ok(first_line(temp_dir.path() + "/private.pem") == "-----BEGIN PRIVATE KEY-----\n",
		"generated private key uses unencrypted PKCS#8 PEM format");

	const MySQL_Caching_Sha2_RSA_Reload_Result unchanged = manager.reload(config);
	ok(unchanged.accepted, "an unchanged valid key pair reload is accepted");
	ok(!unchanged.changed, "an unchanged valid key pair reload is a no-op");
	ok(manager.acquire() == snapshot, "an unchanged reload retains the published snapshot");

	unsigned char scramble[20];
	for (size_t index = 0; index < sizeof(scramble); ++index) {
		scramble[index] = static_cast<unsigned char>(index + 1);
	}
	const std::string expected_password = "s3cret-password";
	std::vector<unsigned char> cleartext(expected_password.begin(), expected_password.end());
	cleartext.push_back('\0');
	const std::vector<unsigned char> ciphertext = encrypt_password_payload(
		*snapshot, cleartext, scramble, sizeof(scramble)
	);
	ok(ciphertext.size() == snapshot->ciphertext_size(),
		"test client produced an RSA OAEP/SHA-1 ciphertext");
	std::string decrypted_password;
	ok(manager.decrypt_password(
		snapshot, ciphertext.data(), ciphertext.size(), scramble, sizeof(scramble), decrypted_password
	), "RSA manager decrypts a MySQL caching_sha2_password payload");
	ok(decrypted_password == expected_password,
		"RSA manager reverses the scramble XOR and strips the trailing NUL");
	ok(!manager.decrypt_password(
		snapshot, ciphertext.data(), ciphertext.size() - 1, scramble, sizeof(scramble), decrypted_password
	), "RSA manager rejects ciphertext with the wrong size");

	const std::vector<unsigned char> malformed_cleartext { 'n', 'o', '-', 'n', 'u', 'l' };
	const std::vector<unsigned char> malformed_ciphertext = encrypt_password_payload(
		*snapshot, malformed_cleartext, scramble, sizeof(scramble)
	);
	ok(!malformed_ciphertext.empty(), "test client encrypted malformed plaintext");
	ok(!manager.decrypt_password(
		snapshot, malformed_ciphertext.data(), malformed_ciphertext.size(),
		scramble, sizeof(scramble), decrypted_password
	), "RSA manager rejects decrypted plaintext without one trailing NUL");

	MySQL_Caching_Sha2_RSA_Config invalid_config = config;
	invalid_config.public_key_path.clear();
	const MySQL_Caching_Sha2_RSA_Reload_Result partial_paths = manager.reload(invalid_config);
	ok(!partial_paths.accepted, "reload rejects a configuration with only one key path");
	ok(manager.acquire() == snapshot, "rejected path configuration preserves the active snapshot");

	chmod((temp_dir.path() + "/private.pem").c_str(), 0644); // NOSONAR(cpp:S2612): deliberate insecure-mode negative test.
	const MySQL_Caching_Sha2_RSA_Reload_Result insecure_permissions = manager.reload(config);
	ok(!insecure_permissions.accepted, "reload rejects group-readable private keys");
	ok(manager.acquire() == snapshot, "rejected private-key permissions preserve the active snapshot");
	chmod((temp_dir.path() + "/private.pem").c_str(), 0600);

	const std::string public_link = temp_dir.path() + "/public-link.pem";
	const int symlink_rc = symlink((temp_dir.path() + "/public.pem").c_str(), public_link.c_str());
	MySQL_Caching_Sha2_RSA_Config symlink_config = config;
	symlink_config.public_key_path = "public-link.pem";
	const MySQL_Caching_Sha2_RSA_Reload_Result symlink_result = manager.reload(symlink_config);
	ok(symlink_rc == 0 && !symlink_result.accepted,
		"reload rejects a symbolic link used as a key path");
	ok(manager.acquire() == snapshot,
		"rejected symbolic-link configuration preserves the active snapshot");
	unlink(public_link.c_str());

	TempDir rotated_dir;
	ok(!rotated_dir.path().empty(), "created an isolated rotation directory");
	MySQL_Caching_Sha2_RSA_Config rotated_config = config;
	rotated_config.datadir = rotated_dir.path();
	const MySQL_Caching_Sha2_RSA_Reload_Result rotated = manager.reload(rotated_config);
	const auto rotated_snapshot = manager.acquire();
	ok(rotated.accepted && rotated.changed && rotated.available,
		"reload publishes a newly generated valid key pair");
	ok(rotated_snapshot != nullptr && rotated_snapshot != snapshot,
		"key rotation atomically replaces the acquired snapshot");
	ok(manager.decrypt_password(
		snapshot, ciphertext.data(), ciphertext.size(), scramble, sizeof(scramble), decrypted_password
	) && decrypted_password == expected_password,
		"an acquired old snapshot remains usable after key rotation");

	MySQL_Caching_Sha2_RSA_Config mismatched_config;
	mismatched_config.auto_generate = false;
	mismatched_config.private_key_path = temp_dir.path() + "/private.pem";
	mismatched_config.public_key_path = rotated_dir.path() + "/public.pem";
	const MySQL_Caching_Sha2_RSA_Reload_Result mismatched = manager.reload(mismatched_config);
	ok(!mismatched.accepted, "reload rejects mismatched RSA private and public keys");
	ok(manager.acquire() == rotated_snapshot,
		"rejected mismatched keys preserve the rotated snapshot");

	MySQL_Caching_Sha2_RSA_Config missing_config;
	missing_config.auto_generate = false;
	missing_config.datadir = rotated_dir.path();
	missing_config.private_key_path = "missing-private.pem";
	missing_config.public_key_path = "missing-public.pem";
	const MySQL_Caching_Sha2_RSA_Reload_Result missing = manager.reload(missing_config);
	ok(!missing.accepted, "reload rejects missing configured keys when generation is disabled");
	ok(manager.acquire() == rotated_snapshot,
		"rejected missing keys preserve the rotated snapshot");

	const std::string escaped_parent = temp_dir.path() + "/escaped-parent";
	const int parent_symlink_rc = symlink(rotated_dir.path().c_str(), escaped_parent.c_str());
	MySQL_Caching_Sha2_RSA_Config escaped_config;
	escaped_config.auto_generate = false;
	escaped_config.datadir = temp_dir.path();
	escaped_config.private_key_path = "escaped-parent/private.pem";
	escaped_config.public_key_path = "escaped-parent/public.pem";
	const MySQL_Caching_Sha2_RSA_Reload_Result escaped = manager.reload(escaped_config);
	ok(parent_symlink_rc == 0 && !escaped.accepted,
		"relative key paths cannot escape the datadir through a symlinked parent");
	unlink(escaped_parent.c_str());
	manager.reload(rotated_config);

	const std::string lexical_private =
		"proxysql-rsa-escape-private-" + std::to_string(static_cast<long>(getpid())) + ".pem";
	const std::string lexical_public =
		"proxysql-rsa-escape-public-" + std::to_string(static_cast<long>(getpid())) + ".pem";
	MySQL_Caching_Sha2_RSA_Config lexical_escape_config;
	lexical_escape_config.auto_generate = true;
	lexical_escape_config.datadir = temp_dir.path();
	lexical_escape_config.private_key_path = "../" + lexical_private;
	lexical_escape_config.public_key_path = "../" + lexical_public;
	const MySQL_Caching_Sha2_RSA_Reload_Result lexical_escape = manager.reload(lexical_escape_config);
	const std::string lexical_private_path = "/tmp/" + lexical_private; // NOSONAR(cpp:S5443): negative test asserts traversal cannot create this path.
	const std::string lexical_public_path = "/tmp/" + lexical_public; // NOSONAR(cpp:S5443): negative test asserts traversal cannot create this path.
	ok(!lexical_escape.accepted && access(lexical_private_path.c_str(), F_OK) != 0 &&
		access(lexical_public_path.c_str(), F_OK) != 0,
		"relative parent-directory components cannot generate keys outside the datadir");
	unlink(lexical_private_path.c_str());
	unlink(lexical_public_path.c_str());

	const std::string traditional_path = temp_dir.path() + "/traditional-private.pem";
	const bool traditional_written = write_traditional_private_key(
		temp_dir.path() + "/private.pem", traditional_path
	);
	MySQL_Caching_Sha2_RSA_Config traditional_config;
	traditional_config.auto_generate = false;
	traditional_config.private_key_path = traditional_path;
	traditional_config.public_key_path = temp_dir.path() + "/public.pem";
	const MySQL_Caching_Sha2_RSA_Reload_Result traditional = manager.reload(traditional_config);
	ok(traditional_written && !traditional.accepted,
		"reload rejects a traditional PKCS#1 RSA private-key PEM");

	const std::string malformed_path = temp_dir.path() + "/malformed-private.pem";
	const bool malformed_written = write_malformed_private_key(malformed_path);
	MySQL_Caching_Sha2_RSA_Config malformed_config = traditional_config;
	malformed_config.private_key_path = malformed_path;
	const MySQL_Caching_Sha2_RSA_Reload_Result malformed = manager.reload(malformed_config);
	ok(malformed_written && !malformed.accepted,
		"reload rejects malformed PKCS#8 private-key data");

	EVPKeyPtr encrypted_key = read_private_key(temp_dir.path() + "/private.pem");
	const std::string encrypted_private = temp_dir.path() + "/encrypted-private.pem";
	const std::string encrypted_public = temp_dir.path() + "/encrypted-public.pem";
	const bool encrypted_written = write_pkcs8_key_pair(
		encrypted_key.get(), encrypted_private, encrypted_public, true
	);
	MySQL_Caching_Sha2_RSA_Config encrypted_config;
	encrypted_config.auto_generate = false;
	encrypted_config.private_key_path = encrypted_private;
	encrypted_config.public_key_path = encrypted_public;
	const MySQL_Caching_Sha2_RSA_Reload_Result encrypted = manager.reload(encrypted_config);
	ok(encrypted_written && !encrypted.accepted,
		"reload rejects an encrypted PKCS#8 RSA private key");

	EVPKeyPtr ec_key = generate_ec_key();
	const std::string ec_private = temp_dir.path() + "/ec-private.pem";
	const std::string ec_public = temp_dir.path() + "/ec-public.pem";
	const bool ec_written = write_pkcs8_key_pair(
		ec_key.get(), ec_private, ec_public
	);
	MySQL_Caching_Sha2_RSA_Config ec_config;
	ec_config.auto_generate = false;
	ec_config.private_key_path = ec_private;
	ec_config.public_key_path = ec_public;
	const MySQL_Caching_Sha2_RSA_Reload_Result ec = manager.reload(ec_config);
	ok(ec_written && !ec.accepted,
		"reload rejects a matching non-RSA PKCS#8 key pair");

	const std::string trailing_private = temp_dir.path() + "/trailing-private.pem";
	const std::string trailing_public = temp_dir.path() + "/trailing-public.pem";
	const bool trailing_private_written = write_pkcs8_key_pair(
		encrypted_key.get(), trailing_private, trailing_public
	) && append_text(trailing_private, "unexpected trailing data\n");
	MySQL_Caching_Sha2_RSA_Config trailing_config;
	trailing_config.auto_generate = false;
	trailing_config.private_key_path = trailing_private;
	trailing_config.public_key_path = trailing_public;
	const MySQL_Caching_Sha2_RSA_Reload_Result trailing_private_result = manager.reload(trailing_config);
	ok(trailing_private_written && !trailing_private_result.accepted,
		"reload rejects trailing data after a PKCS#8 private key");

	const bool trailing_public_written = write_pkcs8_key_pair(
		encrypted_key.get(), trailing_private, trailing_public
	) && append_text(trailing_public, "unexpected trailing data\n");
	const MySQL_Caching_Sha2_RSA_Reload_Result trailing_public_result = manager.reload(trailing_config);
	ok(trailing_public_written && !trailing_public_result.accepted,
		"reload rejects trailing data after an SPKI public key");

	EVPKeyPtr weak_key = generate_rsa_key(1024);
	const std::string weak_private = temp_dir.path() + "/weak-private.pem";
	const std::string weak_public = temp_dir.path() + "/weak-public.pem";
	if (weak_key == nullptr) {
		skip(1, "active OpenSSL provider forbids RSA-1024 test-key generation");
	} else {
		const bool weak_written = write_pkcs8_key_pair(
			weak_key.get(), weak_private, weak_public
		);
		MySQL_Caching_Sha2_RSA_Config weak_config;
		weak_config.auto_generate = false;
		weak_config.private_key_path = weak_private;
		weak_config.public_key_path = weak_public;
		const MySQL_Caching_Sha2_RSA_Reload_Result weak = manager.reload(weak_config);
		ok(weak_written && !weak.accepted,
			"reload rejects a matching RSA key pair weaker than 2048 bits");
	}

	TempDir collision_dir;
	MySQL_Caching_Sha2_RSA_Config collision_config;
	collision_config.auto_generate = true;
	collision_config.datadir = collision_dir.path();
	collision_config.private_key_path = "private.pem";
	collision_config.public_key_path = "private.pem.lock";
	const MySQL_Caching_Sha2_RSA_Reload_Result collision = manager.reload(collision_config);
	ok(!collision.accepted &&
		access((collision_dir.path() + "/private.pem").c_str(), F_OK) != 0 &&
		access((collision_dir.path() + "/private.pem.lock").c_str(), F_OK) != 0,
		"generation rejects a public target that collides with the lock namespace without creating files");

	TempDir concurrent_dir;
	MySQL_Caching_Sha2_RSA_Config concurrent_config;
	concurrent_config.auto_generate = true;
	concurrent_config.datadir = concurrent_dir.path();
	concurrent_config.private_key_path = "private.pem";
	concurrent_config.public_key_path = "public.pem";
	MySQL_Caching_Sha2_RSA concurrent_manager_one;
	MySQL_Caching_Sha2_RSA concurrent_manager_two;
	MySQL_Caching_Sha2_RSA_Reload_Result concurrent_result_one;
	MySQL_Caching_Sha2_RSA_Reload_Result concurrent_result_two;
	std::thread first_reload([&concurrent_result_one, &concurrent_manager_one, &concurrent_config]() {
		concurrent_result_one = concurrent_manager_one.reload(concurrent_config);
	});
	std::thread second_reload([&concurrent_result_two, &concurrent_manager_two, &concurrent_config]() {
		concurrent_result_two = concurrent_manager_two.reload(concurrent_config);
	});
	first_reload.join();
	second_reload.join();
	const auto concurrent_snapshot_one = concurrent_manager_one.acquire();
	const auto concurrent_snapshot_two = concurrent_manager_two.acquire();
	ok(!concurrent_dir.path().empty() && concurrent_result_one.accepted &&
		concurrent_result_two.accepted && concurrent_snapshot_one != nullptr &&
		concurrent_snapshot_two != nullptr,
		"concurrent managers both load a safely generated RSA pair");
	ok(concurrent_snapshot_one != nullptr && concurrent_snapshot_two != nullptr &&
		concurrent_snapshot_one->public_key_pem() == concurrent_snapshot_two->public_key_pem(),
		"concurrent generation publishes one consistent key pair");

	TempDir publication_dir;
	const bool publication_directory_created = !publication_dir.path().empty();
	ok(publication_directory_created,
		"created an isolated key-publication directory");
#ifdef __linux__
	const std::string publication_private = publication_directory_created
		? publication_dir.path() + "/private.pem" : std::string();
	const std::string publication_public = publication_directory_created
		? publication_dir.path() + "/public.pem" : std::string();
	const std::string publication_lock = publication_private + ".lock";
	EVPKeyPtr publication_key = generate_rsa_key(2048);
	const int publication_lock_fd = publication_directory_created
		? open(publication_lock.c_str(), O_RDWR | O_CREAT, 0600) : -1;
	const bool publication_prepared = publication_directory_created &&
		publication_lock_fd >= 0 &&
		flock(publication_lock_fd, LOCK_EX) == 0 &&
		write_pkcs8_key_pair(
			publication_key.get(), publication_private, publication_public
		) && unlink(publication_public.c_str()) == 0;
	if (!publication_prepared) {
		if (publication_lock_fd >= 0) {
			(void)flock(publication_lock_fd, LOCK_UN);
			close(publication_lock_fd);
		}
		ok(false, "auto-generating reload waits for a locked partial-pair publisher");
		ok(false, "reload accepts the pair completed by the locked publisher");
	} else {
		MySQL_Caching_Sha2_RSA publication_observer;
		MySQL_Caching_Sha2_RSA_Config publication_config;
		publication_config.auto_generate = true;
		publication_config.private_key_path = publication_private;
		publication_config.public_key_path = publication_public;
		MySQL_Caching_Sha2_RSA_Reload_Result publication_result;
		{
			std::lock_guard<std::mutex> lock(publication_lock_observer_mutex);
			publication_lock_observer_enabled = true;
			publication_lock_attempted = false;
			publication_lock_contended = false;
			publication_reload_finished = false;
		}
		std::thread publication_reload([
			&publication_result,
			&publication_observer,
			&publication_config
		]() {
			publication_result = publication_observer.reload(publication_config);
			{
				std::lock_guard<std::mutex> lock(publication_lock_observer_mutex);
				publication_reload_finished = true;
			}
			publication_lock_observer_cv.notify_all();
		});
		bool observed_contended_attempt = false;
		{
			std::unique_lock<std::mutex> lock(publication_lock_observer_mutex);
			const bool observer_signaled = publication_lock_observer_cv.wait_for(
				lock,
				std::chrono::seconds(5),
				[]() {
					return publication_lock_attempted || publication_reload_finished;
				}
			);
			observed_contended_attempt = observer_signaled && publication_lock_attempted &&
				publication_lock_contended && !publication_reload_finished;
		}
		ok(observed_contended_attempt,
			"auto-generating reload waits for a locked partial-pair publisher");
		const bool publication_completed =
			write_public_key(publication_key.get(), publication_public);
		(void)flock(publication_lock_fd, LOCK_UN);
		close(publication_lock_fd);
		publication_reload.join();
		{
			std::lock_guard<std::mutex> lock(publication_lock_observer_mutex);
			publication_lock_observer_enabled = false;
		}
		ok(publication_completed && publication_result.accepted &&
			publication_observer.acquire() != nullptr,
			"reload accepts the pair completed by the locked publisher");
	}
#else
	skip(2, "deterministic flock interposition is only available on Linux");
#endif

	return exit_status();
}
