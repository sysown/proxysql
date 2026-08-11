#ifdef PROXYSQLED25519

#include "MySQL_Ed25519.h"

#include <cstring>
#include <strings.h>

#include <openssl/evp.h>

// ref10 entry points compiled into libmariadbclient.a by the STATIC
// client_ed25519 plugin registration (deps/mariadb-client-library).
extern "C" {
int crypto_sign_keypair(unsigned char* pk, unsigned char* pw, unsigned long long pwlen);
int crypto_sign_open(unsigned char* sm, unsigned long long smlen, const unsigned char* pk);
}

void proxysql_ed25519_derive_public_key(const char* password, size_t password_len, unsigned char* out_pubkey) {
	// ref10 takes a non-const pw but never modifies it
	crypto_sign_keypair(out_pubkey, reinterpret_cast<unsigned char*>(const_cast<char*>(password)), password_len); // NOSONAR: the vendored ref10 C API declares pw non-const but only reads it; changing the API would fork the upstream sources
}

bool proxysql_ed25519_verify_signature(const unsigned char* signature, const unsigned char* nonce, const unsigned char* pubkey) {
	// crypto_sign_open() expects a mutable "signed message" R||S||M and
	// clobbers it during verification, so build a local copy.
	unsigned char sm[ED25519_SIG_LEN + ED25519_NONCE_LEN];
	memcpy(sm, signature, ED25519_SIG_LEN);
	memcpy(sm + ED25519_SIG_LEN, nonce, ED25519_NONCE_LEN);
	return crypto_sign_open(sm, sizeof(sm), pubkey) == 0;
}

bool proxysql_ed25519_has_prefix(const char* password) {
	if (password == NULL) return false;
	return strncasecmp(password, ED25519_STORED_PREFIX, ED25519_STORED_PREFIX_LEN) == 0;
}

bool proxysql_ed25519_is_pubkey_format(const char* password) {
	if (proxysql_ed25519_has_prefix(password) == false) return false;
	// bounded scan: only "exactly ED25519_STORED_LEN chars" matters
	return strnlen(password, ED25519_STORED_LEN + 1) == ED25519_STORED_LEN;
}

bool proxysql_ed25519_decode_pubkey(const char* stored, unsigned char* out_pubkey) {
	if (proxysql_ed25519_is_pubkey_format(stored) == false) return false;
	// 43 base64 chars + '=' forms one complete 44-char group. EVP_DecodeBlock
	// emits 33 bytes for it; the 33rd is padding garbage and is discarded.
	unsigned char in[ED25519_PUBKEY_B64_LEN + 1];
	memcpy(in, stored + ED25519_STORED_PREFIX_LEN, ED25519_PUBKEY_B64_LEN);
	in[ED25519_PUBKEY_B64_LEN] = '=';
	unsigned char out[33];
	if (EVP_DecodeBlock(out, in, sizeof(in)) != 33) return false;
	// EVP_DecodeBlock() alone is too lenient: it treats '=' anywhere in the
	// payload as six zero bits and silently accepts non-canonical trailing
	// bits in the final symbol, so a corrupted credential could decode to a
	// DIFFERENT key than the operator intended instead of being rejected.
	// Round-trip check: re-encode the decoded key (44 chars incl. canonical
	// padding + NUL) and require the first 43 characters to match the stored
	// payload exactly.
	unsigned char reencoded[45];
	EVP_EncodeBlock(reencoded, out, ED25519_PUBKEY_LEN);
	if (memcmp(reencoded, in, ED25519_PUBKEY_B64_LEN) != 0) return false;
	memcpy(out_pubkey, out, ED25519_PUBKEY_LEN);
	return true;
}

#endif // PROXYSQLED25519
