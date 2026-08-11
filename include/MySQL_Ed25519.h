#ifndef __CLASS_MYSQL_ED25519_H
#define __CLASS_MYSQL_ED25519_H
#ifdef PROXYSQLED25519

#include <cstddef>

/**
 * MariaDB-variant Ed25519 helpers for frontend client authentication
 * (the client_ed25519 / auth_ed25519 scheme).
 *
 * MariaDB derives the keypair from SHA512(password) where the password has
 * arbitrary length (standard Ed25519 hashes a fixed 32-byte seed), so the
 * derivation MUST use the ref10 implementation vendored in
 * deps/mariadb-client-library (statically linked into libmariadbclient.a via
 * the client_ed25519 plugin). Signature verification is standard Ed25519.
 *
 * Stored-credential format in mysql_users.password:
 *   "$ED$" + 43-char unpadded base64 of the 32-byte public key
 * (prefix case-insensitive, total length exactly 47). This mirrors MariaDB's
 * mysql.user.authentication_string with an explicit marker so it cannot be
 * confused with a cleartext password.
 */

inline constexpr size_t ED25519_NONCE_LEN = 32;
inline constexpr size_t ED25519_SIG_LEN = 64;
inline constexpr size_t ED25519_PUBKEY_LEN = 32;
inline constexpr size_t ED25519_PUBKEY_B64_LEN = 43;
inline constexpr char ED25519_STORED_PREFIX[] = "$ED$";
inline constexpr size_t ED25519_STORED_PREFIX_LEN = sizeof(ED25519_STORED_PREFIX) - 1;
inline constexpr size_t ED25519_STORED_LEN = ED25519_STORED_PREFIX_LEN + ED25519_PUBKEY_B64_LEN;

/** @brief Derive the 32-byte public key from a cleartext password (MariaDB variant). */
void proxysql_ed25519_derive_public_key(const char* password, size_t password_len, unsigned char* out_pubkey);

/** @brief Verify a 64-byte signature over a 32-byte nonce against a 32-byte public key. */
bool proxysql_ed25519_verify_signature(const unsigned char* signature, const unsigned char* nonce, const unsigned char* pubkey);

/** @brief True when 'password' is a stored ed25519 public key ("$ED$" + 43 base64 chars). NULL-safe. */
bool proxysql_ed25519_is_pubkey_format(const char* password);

/** @brief True when 'password' begins with the "$ED$" marker (case-insensitive), regardless of validity. Any such value is reserved for ed25519 credentials and never treated as a cleartext password. NULL-safe. */
bool proxysql_ed25519_has_prefix(const char* password);

/** @brief Decode a "$ED$..." stored credential into a 32-byte public key. False on malformed input. */
bool proxysql_ed25519_decode_pubkey(const char* stored, unsigned char* out_pubkey);

#endif // PROXYSQLED25519
#endif // __CLASS_MYSQL_ED25519_H
