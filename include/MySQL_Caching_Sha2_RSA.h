#ifndef __CLASS_MYSQL_CACHING_SHA2_RSA_H
#define __CLASS_MYSQL_CACHING_SHA2_RSA_H

#include <memory>
#include <pthread.h>
#include <string>

#include <openssl/types.h>

/**
 * @brief Requested caching_sha2_password RSA key configuration.
 * @details Private and public paths are configured together; relative paths resolve beneath @p datadir.
 */
struct MySQL_Caching_Sha2_RSA_Config {
	bool auto_generate { true };
	std::string private_key_path;
	std::string public_key_path;
	std::string datadir;
};

/** @brief Immutable RSA key material retained by authentication exchanges. */
class MySQL_Caching_Sha2_RSA_Key_Snapshot {
public:
	/** @brief Return the canonical SPKI PEM public key supplied to a MySQL client. */
	const std::string& public_key_pem() const { return public_key_pem_; }
	/** @brief Return the exact RSA ciphertext size accepted by this snapshot. */
	size_t ciphertext_size() const { return ciphertext_size_; }

private:
	friend class MySQL_Caching_Sha2_RSA;
	std::shared_ptr<EVP_PKEY> private_key_;
	std::string public_key_pem_;
	std::string private_key_path_;
	std::string public_key_path_;
	size_t ciphertext_size_ { 0 };
};

/** @brief Result of an RSA reload; a rejected reload preserves the active snapshot. */
struct MySQL_Caching_Sha2_RSA_Reload_Result {
	/** @brief The requested configuration passed validation and was accepted. */
	bool accepted { false };
	/** @brief A newly prepared key snapshot replaced the previously active one. */
	bool changed { false };
	/** @brief An active snapshot is available after this reload attempt. */
	bool available { false };
	/** @brief Validation or preparation failure when @c accepted is false. */
	std::string error;
};

/** @brief Atomically publishes immutable RSA snapshots for caching_sha2_password exchanges. */
class MySQL_Caching_Sha2_RSA {
public:
	MySQL_Caching_Sha2_RSA() = default;
	~MySQL_Caching_Sha2_RSA();
	MySQL_Caching_Sha2_RSA(const MySQL_Caching_Sha2_RSA&) = delete;
	MySQL_Caching_Sha2_RSA& operator=(const MySQL_Caching_Sha2_RSA&) = delete;
	MySQL_Caching_Sha2_RSA(MySQL_Caching_Sha2_RSA&&) = delete;
	MySQL_Caching_Sha2_RSA& operator=(MySQL_Caching_Sha2_RSA&&) = delete;

	/** @brief Prepare and atomically publish a valid key pair without replacing a rejected snapshot. */
	MySQL_Caching_Sha2_RSA_Reload_Result reload(const MySQL_Caching_Sha2_RSA_Config& config);
	/** @brief Acquire a snapshot that remains valid even if a later reload publishes another one. */
	std::shared_ptr<const MySQL_Caching_Sha2_RSA_Key_Snapshot> acquire() const;
	/**
	 * @brief Decrypt an exact-size OAEP ciphertext containing one trailing-NUL password.
	 * @details On success, @p password contains cleartext and its caller must cleanse it after use.
	 */
	bool decrypt_password(
		const std::shared_ptr<const MySQL_Caching_Sha2_RSA_Key_Snapshot>& snapshot,
		const unsigned char* ciphertext,
		size_t ciphertext_length,
		const unsigned char* scramble,
		size_t scramble_length,
		std::string& password,
		std::string* error = nullptr
	) const;

private:
	mutable pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;
	std::shared_ptr<const MySQL_Caching_Sha2_RSA_Key_Snapshot> snapshot_;
};

#endif
