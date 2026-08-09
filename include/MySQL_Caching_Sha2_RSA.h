#ifndef PROXYSQL_MYSQL_CACHING_SHA2_RSA_H
#define PROXYSQL_MYSQL_CACHING_SHA2_RSA_H

#include <memory>
#include <mutex>
#include <string>

#include <openssl/types.h>

struct CachingSha2RSAConfig {
	bool auto_generate { true };
	std::string private_key_path;
	std::string public_key_path;
	std::string datadir;
};

class CachingSha2RSAKeySnapshot {
public:
	const std::string& public_key_pem() const { return public_key_pem_; }
	size_t ciphertext_size() const { return ciphertext_size_; }

private:
	friend class MySQL_Caching_Sha2_RSA;
	std::shared_ptr<EVP_PKEY> private_key_;
	std::string public_key_pem_;
	std::string private_key_path_;
	std::string public_key_path_;
	size_t ciphertext_size_ { 0 };
};

struct CachingSha2RSAReloadResult {
	bool accepted { false };
	bool changed { false };
	bool available { false };
	std::string error;
};

class MySQL_Caching_Sha2_RSA {
public:
	CachingSha2RSAReloadResult reload(const CachingSha2RSAConfig& config);
	std::shared_ptr<const CachingSha2RSAKeySnapshot> acquire() const;
	bool decrypt_password(
		const std::shared_ptr<const CachingSha2RSAKeySnapshot>& snapshot,
		const unsigned char* ciphertext,
		size_t ciphertext_length,
		const unsigned char* scramble,
		size_t scramble_length,
		std::string& password,
		std::string* error = nullptr
	) const;

private:
	mutable std::mutex mutex_;
	std::shared_ptr<const CachingSha2RSAKeySnapshot> snapshot_;
};

#endif
