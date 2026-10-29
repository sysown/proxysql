/**
 * @file ed25519_unit-t.cpp
 * @brief Known-answer and edge-case tests for the MariaDB-variant Ed25519
 *   helpers in lib/MySQL_Ed25519.cpp.
 *
 * The "secret" vector matches the documented example in the MariaDB KB
 * (CREATE USER ... IDENTIFIED VIA ed25519 USING 'ZIgUREUg5...'), which
 * independently validates that the ref10 sources vendored in deps/ implement
 * the same scheme as the auth_ed25519 server plugin.
 */
#include "tap.h"

#include "MySQL_Ed25519.h"

#include <cstring>
#include <cstdio>
#include <string>

#include <openssl/evp.h>

struct derivation_kat { const char* password; const char* pubkey_b64; };

static const derivation_kat KATS[] = {
	{ "secret",         "ZIgUREUg5PVgQ6LskhXmO+eZLS0nC8be6HPjYWR4YJY" },
	{ "ed25519_pass_1", "5TBW79xTAMbhi8QKQtLLVS0V0b2w9mlKnRG6c+2NxTQ" },
	{ "",               "4LH+dBF+G5W2CKTyId8xR3SyDqZoQjUNUVNxx8aWbG4" },
};

// 64-byte signature of nonce 0x00..0x1f under password "ed25519_pass_1",
// generated with the connector's own ma_crypto_sign() (the scheme is
// deterministic, so this vector is stable).
static const char SIG_HEX[] =
	"004a2ab8c18a320bdde27a5fff54ae43f66b4c21373ba3c1852ce0eb9255d073"
	"f7b6125fb6ee1a236633da90d0e38b3b58c3295b4ab9eb418402cbfa6f879701";

static void unhex(const char* hex, unsigned char* out, size_t outlen) {
	for (size_t i = 0; i < outlen; i++) {
		unsigned int b = 0;
		sscanf(hex + 2 * i, "%2x", &b);
		out[i] = static_cast<unsigned char>(b);
	}
}

static std::string b64_no_pad(const unsigned char* in, size_t len) {
	unsigned char out[64] = { 0 };
	EVP_EncodeBlock(out, in, len);
	std::string s(reinterpret_cast<char*>(out));
	while (!s.empty() && s.back() == '=') s.pop_back();
	return s;
}

int main() {
	plan(
		3 /* derivation KATs */ +
		3 /* decode round-trips */ +
		7 /* is_pubkey_format edge cases */ +
		5 /* has_prefix edge cases */ +
		5 /* decode_pubkey malformed / non-canonical */ +
		1 /* signature KAT */ +
		3 /* tampered signature / nonce / key */
	);

	// 1. derivation known-answer tests
	for (const derivation_kat& kat : KATS) {
		unsigned char pk[ED25519_PUBKEY_LEN];
		proxysql_ed25519_derive_public_key(kat.password, strlen(kat.password), pk); // NOSONAR: KAT table entries are string literals
		std::string encoded = b64_no_pad(pk, sizeof(pk));
		ok(encoded == kat.pubkey_b64,
			"derive_public_key('%s') = '%s' (expected '%s')",
			kat.password, encoded.c_str(), kat.pubkey_b64);
	}

	// 2. decode_pubkey round-trips against derivation
	for (const derivation_kat& kat : KATS) {
		unsigned char derived[ED25519_PUBKEY_LEN];
		unsigned char decoded[ED25519_PUBKEY_LEN];
		proxysql_ed25519_derive_public_key(kat.password, strlen(kat.password), derived); // NOSONAR: KAT table entries are string literals
		std::string stored = std::string(ED25519_STORED_PREFIX) + kat.pubkey_b64;
		bool rc = proxysql_ed25519_decode_pubkey(stored.c_str(), decoded);
		ok(rc && memcmp(derived, decoded, ED25519_PUBKEY_LEN) == 0,
			"decode_pubkey('%s') matches derived key", stored.c_str());
	}

	// 3. is_pubkey_format edge cases
	{
		std::string valid = std::string(ED25519_STORED_PREFIX) + KATS[1].pubkey_b64;
		ok(proxysql_ed25519_is_pubkey_format(valid.c_str()) == true, "valid $ED$ string accepted");
		std::string lower = std::string("$ed$") + KATS[1].pubkey_b64;
		ok(proxysql_ed25519_is_pubkey_format(lower.c_str()) == true, "prefix match is case-insensitive");
		ok(proxysql_ed25519_is_pubkey_format(KATS[1].pubkey_b64) == false, "bare 43-char base64 rejected (prefix mandatory)");
		ok(proxysql_ed25519_is_pubkey_format("$ED$tooshort") == false, "wrong length rejected");
		std::string toolong = valid + "X";
		ok(proxysql_ed25519_is_pubkey_format(toolong.c_str()) == false, "48-char string rejected");
		ok(proxysql_ed25519_is_pubkey_format(NULL) == false, "NULL rejected");
		ok(proxysql_ed25519_is_pubkey_format("*THISLOOKSLIKEASHA1HASHXXXXXXXXXXXXXXXXX") == false, "SHA1-format password rejected");
	}

	// 3b. has_prefix edge cases -- routes on the marker alone, independent of
	// validity, per the fail-closed rule: any "$ED$"-prefixed value (valid
	// or malformed) must be recognized so it is never treated as cleartext.
	{
		std::string valid = std::string(ED25519_STORED_PREFIX) + KATS[1].pubkey_b64;
		ok(proxysql_ed25519_has_prefix(valid.c_str()) == true, "has_prefix: valid 47-char credential accepted");
		ok(proxysql_ed25519_has_prefix("$ED$short") == true, "has_prefix: malformed wrong-length value still recognized");
		ok(proxysql_ed25519_has_prefix("$ed$short") == true, "has_prefix: case-insensitive marker match");
		ok(proxysql_ed25519_has_prefix(KATS[1].pubkey_b64) == false, "has_prefix: bare base64 without marker rejected");
		ok(proxysql_ed25519_has_prefix(NULL) == false, "has_prefix: NULL rejected");
	}

	// 4. decode_pubkey malformed / non-canonical input.
	// EVP_DecodeBlock() alone treats '=' anywhere as six zero bits and ignores
	// non-canonical trailing bits, so decode_pubkey adds a re-encode round-trip;
	// these cases must all be rejected rather than silently decoding to a
	// different key than the operator stored.
	{
		unsigned char pk[ED25519_PUBKEY_LEN];
		// 43 chars but contains characters outside the base64 alphabet
		std::string bad = std::string(ED25519_STORED_PREFIX) + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
		ok(proxysql_ed25519_decode_pubkey(bad.c_str(), pk) == false, "invalid base64 chars rejected");
		ok(proxysql_ed25519_decode_pubkey("not-ed25519-at-all", pk) == false, "non-$ED$ string rejected");

		std::string valid = std::string(ED25519_STORED_PREFIX) + KATS[1].pubkey_b64;
		std::string embedded_eq = valid;
		embedded_eq[ED25519_STORED_PREFIX_LEN + 20] = '=';
		ok(proxysql_ed25519_decode_pubkey(embedded_eq.c_str(), pk) == false,
			"embedded '=' in payload rejected (would decode as zero bits)");
		std::string trailing_eq = valid;
		trailing_eq[trailing_eq.size() - 1] = '=';
		ok(proxysql_ed25519_decode_pubkey(trailing_eq.c_str(), pk) == false,
			"'=' as 43rd payload char rejected");
		// KATS[1] ends in 'Q' (0b010000, canonical: final 2 slack bits zero);
		// 'R' (0b010001) decodes to the same 32 bytes but is non-canonical
		std::string noncanon = valid;
		noncanon[noncanon.size() - 1] = 'R';
		ok(proxysql_ed25519_decode_pubkey(noncanon.c_str(), pk) == false,
			"non-canonical final symbol rejected (trailing bits not zero)");
	}

	// 5. signature known-answer test
	unsigned char sig[ED25519_SIG_LEN];
	unsigned char nonce[ED25519_NONCE_LEN];
	unsigned char pk[ED25519_PUBKEY_LEN];
	unhex(SIG_HEX, sig, sizeof(sig));
	for (size_t i = 0; i < ED25519_NONCE_LEN; i++) nonce[i] = static_cast<unsigned char>(i);
	proxysql_ed25519_derive_public_key("ed25519_pass_1", strlen("ed25519_pass_1"), pk);
	ok(proxysql_ed25519_verify_signature(sig, nonce, pk) == true, "known-answer signature verifies");

	// 6. negative cases
	{
		unsigned char tampered_sig[ED25519_SIG_LEN];
		memcpy(tampered_sig, sig, sizeof(sig));
		tampered_sig[10] ^= 0xff;
		ok(proxysql_ed25519_verify_signature(tampered_sig, nonce, pk) == false, "tampered signature rejected");

		unsigned char wrong_nonce[ED25519_NONCE_LEN];
		memcpy(wrong_nonce, nonce, sizeof(nonce));
		wrong_nonce[0] ^= 0x01;
		ok(proxysql_ed25519_verify_signature(sig, wrong_nonce, pk) == false, "wrong nonce rejected");

		unsigned char wrong_pk[ED25519_PUBKEY_LEN];
		proxysql_ed25519_derive_public_key("some_other_password", strlen("some_other_password"), wrong_pk);
		ok(proxysql_ed25519_verify_signature(sig, nonce, wrong_pk) == false, "wrong public key rejected");
	}

	return exit_status();
}
