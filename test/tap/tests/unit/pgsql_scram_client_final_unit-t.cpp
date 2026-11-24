/**
 * @file pgsql_scram_client_final_unit-t.cpp
 * @brief libscram must reject a SCRAM client-final-message that has no nonce.
 *
 * read_client_final_message() did not check the result of reading the "r="
 * attribute. Without it the nonce stayed NULL, the proof was still read, the
 * message was accepted, and PgSQL_Protocol::scram_handle_client_final() passed
 * the NULL nonce to verify_final_nonce(), which called strlen() on it.
 *
 * The test drives the server side of the exchange directly through libscram,
 * as PgSQL_Protocol does, and never passes a NULL nonce on.
 */

#include "test_globals.h"
#include "test_init.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include "scram.h"
#include "tap.h"

namespace {

// 32 zero bytes, base64: a proof of the right length that never verifies.
const char* const ZERO_PROOF = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const char* const CLIENT_NONCE = "abcdefghijklmnop";

// Runs client-first / server-first on a fresh state, as
// PgSQL_Protocol::scram_handle_client_first() does, and returns the combined
// nonce the server expects in the client-final-message ("" on failure).
// A NULL secret is the unknown-user path (mock authentication).
std::string start_exchange(ScramState* st, const char* secret) {
	std::string client_first = std::string("n,,n=u,r=") + CLIENT_NONCE;
	if (!read_client_first_message(&client_first[0], &st->cbind_flag,
			&st->client_first_message_bare, &st->client_nonce))
		return "";
	const char* server_first = build_server_first_message(st, "u", secret);
	if (server_first == nullptr)
		return "";
	const char* r = strstr(server_first, "r=");
	if (r == nullptr)
		return "";
	r += 2;
	return std::string(r, strcspn(r, ","));
}

struct FinalResult {
	bool parsed;
	bool nonce_null;
	bool nonce_ok;
	bool proof_ok;
};

FinalResult client_final(ScramState* st, const std::string& message) {
	FinalResult res { false, false, false, false };
	std::string buf(message);
	const char* nonce = nullptr;
	char* proof = nullptr;
	res.parsed = read_client_final_message(st, (const uint8_t*)message.c_str(), &buf[0], &nonce, &proof);
	res.nonce_null = (nonce == nullptr);
	if (res.parsed && nonce != nullptr) {
		res.nonce_ok = verify_final_nonce(st, nonce);
		if (res.nonce_ok)
			res.proof_ok = verify_client_proof(st, proof);
	}
	free(proof);
	return res;
}

} // namespace

int main(int, char**) {
	plan(10);

	// Known user (real secret) and unknown user (mock authentication): both
	// reach read_client_final_message() in PgSQL_Protocol.
	for (const char* secret : { "secret", (const char*)nullptr }) {
		const char* who = secret ? "known user" : "unknown user";
		ScramState* st = scram_state_init();
		const std::string nonce = start_exchange(st, secret);
		ok(!nonce.empty(), "%s: client-first-message is accepted and the server nonce is read", who);
		const FinalResult res = client_final(st, std::string("c=biws,p=") + ZERO_PROOF);
		ok(!res.parsed, "%s: client-final-message without r= is rejected", who);
		ok(!res.parsed || !res.nonce_null, "%s: a parsed client-final-message never carries a NULL nonce", who);
		free_scram_state(st);
	}

	{
		ScramState* st = scram_state_init();
		start_exchange(st, "secret");
		const FinalResult res = client_final(st, std::string("c=biws,x=ext,p=") + ZERO_PROOF);
		ok(!res.parsed, "client-final-message with an extension but without r= is rejected");
		free_scram_state(st);
	}

	{
		ScramState* st = scram_state_init();
		const std::string nonce = start_exchange(st, "secret");
		const FinalResult res = client_final(st, "c=biws,r=" + nonce + ",p=" + ZERO_PROOF);
		ok(res.parsed && !res.nonce_null, "well-formed client-final-message is parsed");
		ok(res.nonce_ok, "its nonce matches the exchange");
		ok(!res.proof_ok, "a wrong proof is still refused");
		free_scram_state(st);
	}

	return exit_status();
}
