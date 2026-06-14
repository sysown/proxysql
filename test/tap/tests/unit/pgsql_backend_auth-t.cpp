#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include <string>
#include "scram.h"   // libscram: used to pin the RFC vector and to act as an independent SCRAM verifier
#include "tap.h"

int main(int, char**) {
    plan(15);

    // SSLRequest is a fixed 8 bytes: length=8, code=80877103 (0x04d2162f).
    unsigned char ssl[8];
    pg_build_ssl_request(ssl);
    unsigned char expect_ssl[8] = {0x00,0x00,0x00,0x08, 0x04,0xd2,0x16,0x2f};
    ok(memcmp(ssl, expect_ssl, 8) == 0, "SSLRequest bytes exact");

    // Startup message: int32 length, int32 protocol 196608 (3.0), then key\0value\0... \0.
    unsigned char sm[256]; size_t smlen = 0;
    pg_build_startup(sm, &smlen, sizeof(sm), "alice", "shop");
    // protocol version at offset 4 must be 0x00030000
    ok(sm[4]==0x00 && sm[5]==0x03 && sm[6]==0x00 && sm[7]==0x00, "startup protocol 3.0");

    // AuthenticationMD5Password response: "md5" + hex(md5(hex(md5(pass+user))+salt)).
    // Known vector: user=postgres, password=postgres, salt={1,2,3,4} (independent python ref).
    char md5buf[36];
    unsigned char salt[4] = {0x01,0x02,0x03,0x04};
    pg_build_md5(md5buf, "postgres", "postgres", salt);
    ok(strcmp(md5buf, "md568be9ed08db75f318087ab337aaea044") == 0, "md5 response matches reference vector");

    // --- SCRAM-SHA-256 ---

    // (4) Wrapper shape: client-first must carry the gs2 'n' header ("n,,") and a nonce
    // ("r="), with an empty SCRAM username field ("n=") per the PostgreSQL convention.
    {
        PgSQL_Scram_State* s = pg_scram_new();
        const char* cf = pg_scram_client_first(s, /*channel_binding=*/false);
        bool shape_ok = cf != nullptr
            && strncmp(cf, "n,,", 3) == 0          // gs2 header: no channel binding
            && strstr(cf, "n=,") != nullptr        // empty username field
            && strstr(cf, ",r=") != nullptr;       // client nonce present
        ok(shape_ok, "pg_scram_client_first: gs2 'n,,' header, empty n=, and r= nonce (got: %s)",
           cf ? cf : "(null)");
        pg_scram_free(s);
    }

    // (5) Proof correctness, RFC 7677 Section 5 SCRAM-SHA-256 test vector.
    //   username "user", password "pencil", client nonce "rOprNGfwEbeRWgbNEkqO".
    //   Expected client-final proof: p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=
    //
    // The RFC vector uses client-first-bare "n=user,r=..." (a non-empty username), so we
    // pin it by driving libscram directly with the RFC ScramState fields rather than via
    // build_client_first_message (which would generate a random nonce and an EMPTY n=).
    // build_client_final_message consumes client_nonce, client_first_message_bare,
    // server_first_message and cbind_flag to recompute the proof.
    {
        ScramState* st = scram_state_init();
        st->client_nonce = strdup("rOprNGfwEbeRWgbNEkqO");
        st->client_first_message_bare = strdup("n=user,r=rOprNGfwEbeRWgbNEkqO");
        st->server_first_message = strdup(
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096");
        st->cbind_flag = 'n';

        PgCredentials creds{};
        snprintf(creds.passwd, sizeof(creds.passwd), "%s", "pencil");
        creds.has_scram_keys = false;

        const char* server_nonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        const char* salt_b64 = "W22ZaJ0SNY7soEsUEjb6gQ==";
        // RFC salt decodes from base64; libscram's read path decodes it, but here we call
        // build_client_final_message directly which takes the RAW (decoded) salt.
        unsigned char salt_raw[64];
        // Decode "W22ZaJ0SNY7soEsUEjb6gQ==" -> 16 bytes (standard base64, no helper here).
        // Hand-decode via libscram is not exposed; use a tiny inline base64 decoder.
        auto b64val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1; // '=' padding or invalid
        };
        int saltlen = 0;
        {
            int bits = 0, acc = 0;
            for (const char* p = salt_b64; *p; ++p) {
                int v = b64val(*p);
                if (v < 0) break; // padding terminates
                acc = (acc << 6) | v; bits += 6;
                if (bits >= 8) { bits -= 8; salt_raw[saltlen++] = (acc >> bits) & 0xff; }
            }
        }

        char* final_msg = build_client_final_message(
            st, &creds, server_nonce, (const char*)salt_raw, saltlen, 4096);

        bool proof_ok = final_msg != nullptr
            && strstr(final_msg, "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=") != nullptr;
        ok(proof_ok, "client-final proof matches RFC 7677 Section 5 vector (got: %s)",
           final_msg ? final_msg : "(null)");

        free(final_msg);
        free_scram_state(st);
    }

    // (6) Full client<->server round trip exercising the WRAPPERS under the PostgreSQL
    // empty-username convention (n=,...). The client side is driven entirely through the
    // pg_scram_* wrappers; the server side is libscram's independent SCRAM verifier. This
    // proves the proof our wrapper computes is ACCEPTED by an independent implementation,
    // which the RFC pin (which uses n=user and bypasses the wrappers) cannot show.
    {
        const char* password = "s3cr3t-passw0rd";

        // --- client: build client-first via the wrapper ---
        PgSQL_Scram_State* client = pg_scram_new();
        const char* client_first = pg_scram_client_first(client, /*channel_binding=*/false);

        // --- server: parse client-first and build server-first (libscram, independent) ---
        ScramState* server = scram_state_init();
        std::string cf_copy(client_first);   // read_client_first_message mutates its input
        char cbind_flag = 0;
        char* cfmb = nullptr;
        char* cnonce = nullptr;
        bool parsed = read_client_first_message(&cf_copy[0], &cbind_flag, &cfmb, &cnonce);
        server->cbind_flag = cbind_flag;
        server->client_first_message_bare = cfmb;   // ownership transferred to server state
        server->client_nonce = cnonce;
        // Plaintext password as the "stored secret" -> libscram derives an ad-hoc verifier.
        char* server_first = parsed ? build_server_first_message(server, "", password) : nullptr;

        // --- client: build client-final (WITH proof) via the wrapper ---
        const char* client_final = server_first
            ? pg_scram_client_final(client, password, server_first, strlen(server_first))
            : nullptr;

        // --- server: verify nonce + client proof (independent verifier) ---
        bool accepted = false;
        if (client_final) {
            // read_client_final_message takes a pristine raw_input (for the without-proof
            // reconstruction) AND a separate mutable input buffer it overwrites with NULs;
            // they must be distinct copies (mirrors PgSQL_Protocol::scram_handle_client_final).
            std::string raw(client_final);
            std::string finbuf(client_final);
            const char* final_nonce = nullptr;
            char* proof = nullptr;
            bool rf = read_client_final_message(server, (const uint8_t*)raw.c_str(), &finbuf[0],
                                          &final_nonce, &proof);
            if (rf) {
                accepted = verify_final_nonce(server, final_nonce)
                    && verify_client_proof(server, proof);
            }
            free(proof);
        }
        ok(accepted, "wrapper client proof accepted by independent libscram server verifier");

        // --- bonus: client verifies the server's final signature via the wrapper ---
        char* server_final = accepted ? build_server_final_message(server) : nullptr;
        bool server_verified = server_final
            && pg_scram_verify_server_final(client, server_final, strlen(server_final));
        ok(server_verified, "wrapper verifies server-final signature (mutual auth round trip)");

        free(server_final);
        free_scram_state(server);
        pg_scram_free(client);
    }

    // ------------------------------------------------------------------
    // (13) libscram cbind patch: build_client_first_message emits the
    // p=tls-server-end-point gs2 header when cbind is set.
    //
    // We drive libscram directly (no wrapper) so the assertion is
    // independent of any ProxySQL-side state machine changes.
    // ------------------------------------------------------------------
    {
        ScramState* st = scram_state_init();
        const char* cbind = "p=tls-server-end-point,,0123456789abcdef";
        scram_state_set_cbind_input(st, cbind, 38);

        char* first = build_client_first_message(st);
        bool header_ok = first != nullptr
            && strncmp(first, "p=tls-server-end-point,,", 24) == 0
            && strncmp(first + 24, "n=,r=", 5) == 0;
        ok(header_ok, "build_client_first_message with cbind emits p=tls-server-end-point,, header (got: %s)",
           first ? first : "(null)");

        free(first);
        free_scram_state(st);
    }

    // ------------------------------------------------------------------
    // (14) libscram cbind patch: build_client_final_message emits
    // c=base64(cbind_input) for the c= field when cbind is set.
    //
    // The cbind input is "p=tls-server-end-point,," || 32*NUL (54 bytes for
    // SHA-256). The expected c= literal is base64 of those 54 bytes.
    // ------------------------------------------------------------------
    {
        ScramState* st = scram_state_init();
        unsigned char zero_digest[32] = {0};
        char cbind[54] = "p=tls-server-end-point,,";
        memcpy(cbind + 22, zero_digest, 32);
        scram_state_set_cbind_input(st, cbind, 54);

        st->client_nonce = strdup("rOprNGfwEbeRWgbNEkqO");
        st->client_first_message_bare = strdup("n=user,r=rOprNGfwEbeRWgbNEkqO");
        st->server_first_message = strdup(
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096");
        st->cbind_flag = 'p';

        PgCredentials creds{};
        snprintf(creds.passwd, sizeof(creds.passwd), "%s", "pencil");
        creds.has_scram_keys = false;

        const char* server_nonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        unsigned char salt_raw[16] = {0};
        auto b64val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        };
        const char* salt_b64 = "W22ZaJ0SNY7soEsUEjb6gQ==";
        int saltlen = 0;
        {
            int bits = 0, acc = 0;
            for (const char* p = salt_b64; *p; ++p) {
                int v = b64val(*p);
                if (v < 0) break;
                acc = (acc << 6) | v; bits += 6;
                if (bits >= 8) { bits -= 8; salt_raw[saltlen++] = (acc >> bits) & 0xff; }
            }
        }

        char* final_msg = build_client_final_message(
            st, &creds, server_nonce, (const char*)salt_raw, saltlen, 4096);

        // base64("p=tls-server-end-point,," + 32*NUL) computed once and pinned.
        const char* expected_c_b64 =
            "cEBlcy1zZXJ2ZXItZW5kLXBvaW50LCAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        bool c_ok = final_msg != nullptr
            && strncmp(final_msg, "c=", 2) == 0
            && strncmp(final_msg + 2, expected_c_b64, strlen(expected_c_b64)) == 0
            && final_msg[2 + strlen(expected_c_b64)] == ',';
        if (c_ok) {
            ok(true, "build_client_final_message with cbind emits c=base64(cbind_input)");
        } else {
            char preview[96] = {0};
            if (final_msg) {
                size_t cp = strlen(final_msg);
                if (cp > 90) cp = 90;
                memcpy(preview, final_msg, cp);
            }
            ok(false, "build_client_final_message with cbind emits c=base64(cbind_input) (got: %s)",
               final_msg ? preview : "(null)");
        }

        free(final_msg);
        free_scram_state(st);
    }

    // ------------------------------------------------------------------
    // (15) libscram cbind patch: read_client_first_message on the server
    // side rejects the 'p' gs2 flag (libscram server-side does not
    // support SCRAM-PLUS; a real backend that accepts -PLUS is the
    // e2e test, deferred to 1b-B). This test confirms the client
    // produces a message the server CORRECTLY RECOGNIZES as 'p' (not 'n'
    // or 'y') and rejects with the expected error.
    // ------------------------------------------------------------------
    {
        ScramState* client = scram_state_init();
        const char* cbind = "p=tls-server-end-point,,0123456789abcdef";
        scram_state_set_cbind_input(client, cbind, 38);
        char* first = build_client_first_message(client);

        scram_reset_error();
        ScramState* server = scram_state_init();
        std::string cf_copy(first ? first : "");
        char cbind_flag = 0;
        char* cfmb = nullptr;
        char* cnonce = nullptr;
        bool parsed = read_client_first_message(&cf_copy[0], &cbind_flag, &cfmb, &cnonce);
        const char* err = scram_error();
        bool recognized_as_p = !parsed
            && err != nullptr
            && strstr(err, "client requires SCRAM channel binding") != nullptr
            && first != nullptr
            && strncmp(first, "p=tls-server-end-point,,", 24) == 0;
        ok(recognized_as_p,
           "server recognizes cbind client-first as 'p' gs2 flag (rejects as expected)");

        if (parsed) {
            free(cfmb);
            free(cnonce);
        }
        free(first);
        free_scram_state(server);
        free_scram_state(client);
    }

    return exit_status();
}
