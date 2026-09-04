#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include <string>
#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include "scram.h"   // libscram: used to pin the RFC vector and to act as an independent SCRAM verifier
#include "tap.h"


// Walk a StartupMessage's key\0value\0...\0 body and return the value for `key`,
// or "" when the key is absent. Layout: int32 len, int32 protocol, then pairs.
static std::string startup_param(const unsigned char* sm, size_t smlen, const char* key) {
    size_t off = 8;
    while (off < smlen && sm[off] != 0) {
        const char* k = (const char*)(sm + off);
        off += strlen(k) + 1;
        if (off >= smlen) break;
        const char* v = (const char*)(sm + off);
        off += strlen(v) + 1;
        if (strcmp(k, key) == 0) return std::string(v);
    }
    return std::string();
}


// RFC 7677 Section 3 SCRAM-SHA-256 vector (password "pencil", salt W22ZaJ0SNY7soEsUEjb6gQ==,
// i=4096), written as PostgreSQL stores it in pg_authid.rolpassword -- which is byte for byte
// what pgsql_users.password holds for a verifier-stored user. Using a published vector means
// the harvested-key assertions below have an external expected value rather than agreeing
// with whatever this code happens to compute.
static const char* const RFC7677_VERIFIER =
    "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ=="
    "$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=";

// ClientKey = HMAC(SaltedPassword,"Client Key") and ServerKey = HMAC(SaltedPassword,"Server Key")
// for that same vector. StoredKey = SHA256(ClientKey) is the value encoded in the verifier above.
static const uint8_t RFC7677_CLIENT_KEY[32] = {
    0xa6, 0x0f, 0xc9, 0x23, 0xd6, 0x7e, 0x86, 0x44,
    0xa9, 0x2d, 0x16, 0xb9, 0x6e, 0xda, 0x5e, 0xf4,
    0x65, 0x6b, 0x0c, 0x72, 0x5c, 0x48, 0x43, 0x74,
    0xbe, 0x25, 0x53, 0x55, 0x76, 0x99, 0x6e, 0x8b,
};
static const uint8_t RFC7677_SERVER_KEY[32] = {
    0xc1, 0xf3, 0xcb, 0xc1, 0xc1, 0x3a, 0x9d, 0x35,
    0xa1, 0x4c, 0x09, 0x90, 0xee, 0xd9, 0x76, 0x29,
    0xea, 0x22, 0x58, 0x63, 0xe5, 0x66, 0xa4, 0x31,
    0x4a, 0xb9, 0x9f, 0x3f, 0x00, 0xe5, 0xd9, 0xd5,
};

// Drives the libscram SERVER side of one exchange: consumes a wrapper-produced client-first
// and returns the server-first message built from `stored_secret`. The returned string is
// owned by `srv` (build_server_first_message stores it as server_first_message and
// free_scram_state releases it) -- the caller must NOT free it. read_client_first_message
// mutates its input and hands back buffers the ScramState takes ownership of, so it gets a
// private copy.
static char* server_first_for(ScramState* srv, const char* client_first, const char* stored_secret) {
    std::string copy(client_first);
    char cbind_flag = 0;
    char* cfmb = nullptr;
    char* cnonce = nullptr;
    if (!read_client_first_message(&copy[0], &cbind_flag, &cfmb, &cnonce)) return nullptr;
    srv->cbind_flag = cbind_flag;
    srv->client_first_message_bare = cfmb;   // ownership transferred to srv
    srv->client_nonce = cnonce;
    return build_server_first_message(srv, "", stored_secret);
}

// Server-side verification of a wrapper-produced client-final. Mirrors
// PgSQL_Protocol::scram_handle_client_final: read_client_final_message needs a pristine
// raw_input for the without-proof reconstruction AND a separate mutable buffer it fills
// with NULs, so the two copies must be distinct.
static bool server_accepts(ScramState* srv, const char* client_final) {
    std::string raw(client_final);
    std::string buf(client_final);
    const char* nonce = nullptr;
    char* proof = nullptr;
    bool accepted = false;
    if (read_client_final_message(srv, (const uint8_t*)raw.c_str(), &buf[0], &nonce, &proof))
        accepted = verify_final_nonce(srv, nonce) && verify_client_proof(srv, proof);
    free(proof);
    return accepted;
}

int main(int, char**) {
    plan(29);

    // SSLRequest is a fixed 8 bytes: length=8, code=80877103 (0x04d2162f).
    unsigned char ssl[8];
    pg_build_ssl_request(ssl);
    unsigned char expect_ssl[8] = {0x00,0x00,0x00,0x08, 0x04,0xd2,0x16,0x2f};
    ok(memcmp(ssl, expect_ssl, 8) == 0, "SSLRequest bytes exact");

    // Startup message: int32 length, int32 protocol 196608 (3.0), then key\0value\0... \0.
    unsigned char sm[256]; size_t smlen = 0;
    pg_build_startup(sm, &smlen, sizeof(sm), "alice", "shop", nullptr, nullptr, nullptr);
    // protocol version at offset 4 must be 0x00030000
    ok(sm[4]==0x00 && sm[5]==0x03 && sm[6]==0x00 && sm[7]==0x00, "startup protocol 3.0");

    // The startup message must be able to carry the session settings the libpq path
    // sends as client_encoding=... and options='-c k=v ...'. Without them a client's
    // connection options are silently dropped on the native path. application_name is
    // what identifies the connection in pg_stat_activity and in log_line_prefix '%a'.
    {
        // Nothing optional supplied: none of the three keys may appear.
        ok(startup_param(sm, smlen, "options").empty() &&
           startup_param(sm, smlen, "client_encoding").empty() &&
           startup_param(sm, smlen, "application_name").empty(),
           "startup without options/client_encoding/application_name carries none of them");

        unsigned char sm2[512]; size_t sm2len = 0;
        const char* opts = "-c DateStyle=ISO -c geqo=off";
        bool built = pg_build_startup(sm2, &sm2len, sizeof(sm2), "alice", "shop", "UTF8",
                                      opts, "proxysql");
        ok(built, "startup builds with client_encoding, options and application_name");
        ok(startup_param(sm2, sm2len, "options") == opts,
           "startup carries the options string verbatim (got '%s')",
           startup_param(sm2, sm2len, "options").c_str());
        ok(startup_param(sm2, sm2len, "application_name") == "proxysql",
           "startup carries application_name, so the backend can identify the connection "
           "in pg_stat_activity (got '%s')",
           startup_param(sm2, sm2len, "application_name").c_str());
        ok(startup_param(sm2, sm2len, "client_encoding") == "UTF8" &&
           startup_param(sm2, sm2len, "user") == "alice" &&
           startup_param(sm2, sm2len, "database") == "shop",
           "startup still carries user/database, plus client_encoding");

        // A buffer one byte short of the encoded size must be rejected outright, with no
        // partial write, now that application_name adds to that size.
        unsigned char sm3[512]; size_t sm3len = 123;
        ok(pg_build_startup(sm3, &sm3len, sm2len - 1, "alice", "shop", "UTF8",
                            opts, "proxysql") == false && sm3len == 0,
           "startup refuses a buffer one byte too small and reports 0 bytes written");
    }

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
    // (11) pg_tls_server_end_point: SHA-256 digest of a self-signed
    // SHA-256-signed cert. The expected digest is computed in-test from
    // the same DER, so this is self-validating; the pin is the actual
    // SHA-256 of the test cert's DER. Runs a loopback TLS handshake so
    // SSL_get_peer_certificate actually returns the cert.
    // ------------------------------------------------------------------
    {
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
        EVP_PKEY_generate(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);

        X509* cert = X509_new();
        X509_set_version(cert, X509_VERSION_3);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_getm_notBefore(cert), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char*)"test", -1, -1, 0);
        X509_set_issuer_name(cert, name);
        X509_sign(cert, pkey, EVP_sha256());

        // Expected digest: SHA-256(DER(cert)).
        unsigned char* der = nullptr;
        int der_len = i2d_X509(cert, &der);
        unsigned char expected[32];
        unsigned int expected_len = 0;
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mctx, der, der_len);
        EVP_DigestFinal_ex(mctx, expected, &expected_len);
        EVP_MD_CTX_free(mctx);
        OPENSSL_free(der);

        // Loopback TLS handshake: server presents the cert, client calls
        // pg_tls_server_end_point. Both sides use a memory BIO pair.
        const SSL_METHOD* server_method = TLS_server_method();
        SSL_CTX* sctx = SSL_CTX_new(server_method);
        SSL_CTX_use_certificate(sctx, cert);
        SSL_CTX_use_PrivateKey(sctx, pkey);
        SSL* server_ssl = SSL_new(sctx);
        const SSL_METHOD* client_method = TLS_client_method();
        SSL_CTX* cctx = SSL_CTX_new(client_method);
        SSL* client_ssl = SSL_new(cctx);
        BIO* sbio = BIO_new(BIO_s_mem());
        BIO* cbio = BIO_new(BIO_s_mem());
        // SSL_set_bio consumes one reference per BIO role; the same two BIOs
        // are installed into BOTH SSL objects, so take an extra reference on
        // each before the second SSL_set_bio -- otherwise both SSL_free calls
        // free the same BIOs (double-free, caught by ASAN as SEGV in
        // BUF_MEM_free during teardown).
        BIO_up_ref(sbio);
        BIO_up_ref(cbio);
        SSL_set_bio(server_ssl, sbio, cbio);
        SSL_set_bio(client_ssl, cbio, sbio);
        SSL_set_accept_state(server_ssl);
        SSL_set_connect_state(client_ssl);
        // Drive handshake to completion (non-blocking; loop until both sides done).
        int rc_h = 0;
        for (int i = 0; i < 20; ++i) {
            int r1 = SSL_do_handshake(server_ssl);
            int r2 = SSL_do_handshake(client_ssl);
            if (r1 == 1 && r2 == 1) { rc_h = 1; break; }
        }

        unsigned char out[EVP_MAX_MD_SIZE];
        size_t out_len = 0;
        int rc = pg_tls_server_end_point(client_ssl, out, &out_len);
        bool digest_ok = rc_h == 1
            && rc >= 0
            && out_len == expected_len
            && memcmp(out, expected, expected_len) == 0;
        ok(digest_ok, "pg_tls_server_end_point returns SHA-256 digest for a SHA-256-signed cert (handshake=%d)", rc_h);

        SSL_free(server_ssl);
        SSL_free(client_ssl);
        SSL_CTX_free(sctx);
        SSL_CTX_free(cctx);
        X509_free(cert);
        EVP_PKEY_free(pkey);
    }

    // ------------------------------------------------------------------
    // (12) pg_tls_server_end_point: MD5-signed cert is upgraded to
    // SHA-256 per RFC 5929 §4.1. Loopback handshake as in (11).
    // ------------------------------------------------------------------
    {
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
        EVP_PKEY_generate(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);

        X509* cert = X509_new();
        X509_set_version(cert, X509_VERSION_3);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
        X509_gmtime_adj(X509_getm_notBefore(cert), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char*)"test-md5", -1, -1, 0);
        X509_set_issuer_name(cert, name);
        X509_sign(cert, pkey, EVP_md5());

        unsigned char* der = nullptr;
        int der_len = i2d_X509(cert, &der);
        unsigned char expected[32];
        unsigned int expected_len = 0;
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mctx, EVP_sha256(), nullptr);  // upgrade target
        EVP_DigestUpdate(mctx, der, der_len);
        EVP_DigestFinal_ex(mctx, expected, &expected_len);
        EVP_MD_CTX_free(mctx);
        OPENSSL_free(der);

        const SSL_METHOD* server_method = TLS_server_method();
        SSL_CTX* sctx = SSL_CTX_new(server_method);
        SSL_CTX_use_certificate(sctx, cert);
        SSL_CTX_use_PrivateKey(sctx, pkey);
        SSL* server_ssl = SSL_new(sctx);
        const SSL_METHOD* client_method = TLS_client_method();
        SSL_CTX* cctx = SSL_CTX_new(client_method);
        SSL* client_ssl = SSL_new(cctx);
        BIO* sbio = BIO_new(BIO_s_mem());
        BIO* cbio = BIO_new(BIO_s_mem());
        // SSL_set_bio consumes one reference per BIO role; the same two BIOs
        // are installed into BOTH SSL objects, so take an extra reference on
        // each before the second SSL_set_bio -- otherwise both SSL_free calls
        // free the same BIOs (double-free, caught by ASAN as SEGV in
        // BUF_MEM_free during teardown).
        BIO_up_ref(sbio);
        BIO_up_ref(cbio);
        SSL_set_bio(server_ssl, sbio, cbio);
        SSL_set_bio(client_ssl, cbio, sbio);
        SSL_set_accept_state(server_ssl);
        SSL_set_connect_state(client_ssl);
        int rc_h = 0;
        for (int i = 0; i < 20; ++i) {
            int r1 = SSL_do_handshake(server_ssl);
            int r2 = SSL_do_handshake(client_ssl);
            if (r1 == 1 && r2 == 1) { rc_h = 1; break; }
        }

        unsigned char out[EVP_MAX_MD_SIZE];
        size_t out_len = 0;
        int rc = pg_tls_server_end_point(client_ssl, out, &out_len);
        bool digest_ok = rc_h == 1
            && rc >= 0
            && out_len == expected_len
            && memcmp(out, expected, expected_len) == 0;
        ok(digest_ok, "pg_tls_server_end_point upgrades MD5-signed cert to SHA-256 (RFC 5929 §4.1) (handshake=%d)", rc_h);

        SSL_free(server_ssl);
        SSL_free(client_ssl);
        SSL_CTX_free(sctx);
        SSL_CTX_free(cctx);
        X509_free(cert);
        EVP_PKEY_free(pkey);
    }

    // ------------------------------------------------------------------
    // (13) pg_tls_server_end_point: NULL ssl returns -1.
    // ------------------------------------------------------------------
    {
        unsigned char out[EVP_MAX_MD_SIZE];
        size_t out_len = 0;
        int rc = pg_tls_server_end_point(nullptr, out, &out_len);
        ok(rc == -1, "pg_tls_server_end_point with NULL ssl returns -1");
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
        unsigned char cbind[56];
        memcpy(cbind, "p=tls-server-end-point,,", 24);
        memcpy(cbind + 24, zero_digest, 32);
        scram_state_set_cbind_input(st, (const char*)cbind, 56);

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

        // base64("p=tls-server-end-point,," + 32*NUL) = 76 chars.
        // Pinned; recomputed once with: python3 -c "import base64; print(base64.b64encode(b'p=tls-server-end-point,,' + b'\0'*32).decode())"
        const char* expected_c_b64 =
            "cD10bHMtc2VydmVyLWVuZC1wb2ludCwsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
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

    // ------------------------------------------------------------------
    // (14) pg_scram_build_cbind_input_tls_server_end_point: 32-byte
    // (SHA-256) digest composes to a 56-byte cbind input with the
    // "p=tls-server-end-point,," (24-byte) header pinned at the start.
    // ------------------------------------------------------------------
    {
        unsigned char digest[32];
        for (int i = 0; i < 32; i++) digest[i] = (unsigned char)i;
        unsigned char out[88];
        int len = pg_scram_build_cbind_input_tls_server_end_point(digest, 32, out, sizeof(out));
        bool ok_c14 = (len == 56)
            && memcmp(out, "p=tls-server-end-point,,", 24) == 0
            && memcmp(out + 24, digest, 32) == 0;
        ok(ok_c14, "pg_scram_build_cbind_input_tls_server_end_point composes 24-byte header + 32-byte digest (got len=%d)",
           len);
    }

    // ------------------------------------------------------------------
    // (15) Same for a 64-byte (SHA-512) digest: 88-byte cbind input.
    // ------------------------------------------------------------------
    {
        unsigned char digest[64];
        for (int i = 0; i < 64; i++) digest[i] = (unsigned char)(0xff - i);
        unsigned char out[88];
        int len = pg_scram_build_cbind_input_tls_server_end_point(digest, 64, out, sizeof(out));
        bool ok_c15 = (len == 88)
            && memcmp(out, "p=tls-server-end-point,,", 24) == 0
            && memcmp(out + 24, digest, 64) == 0;
        ok(ok_c15, "pg_scram_build_cbind_input_tls_server_end_point composes 24-byte header + 64-byte digest (got len=%d)",
           len);
    }

    // ==================================================================
    // Credential pass-through on the BACKEND leg.
    //
    // pgsql_users.password may hold a plaintext, an md5 secret, or a SCRAM verifier.
    // The first is the only one the primitives above can hash directly; for the other
    // two the stored value IS already a derived secret and must be reused, never
    // re-derived. Everything below pins that reuse, because getting it subtly wrong
    // produces a handshake that is well-formed and simply always rejected.
    // ------------------------------------------------------------------

    // (22) md5 pass-through against the SAME reference vector pinned in (3).
    // The stored secret is the inner hash: "md5" + hex(md5(password+user)). For
    // user=postgres / password=postgres that inner hash is 3175bce1d3201d16594cebf9d7eb3f9d
    // (md5 of the literal "postgrespostgres", computed independently of this code), so only
    // the outer hash over (inner_hex || salt) is left to do and the response must come out
    // byte-identical to the plaintext-derived one.
    {
        char out[36];
        memset(out, 0xAA, sizeof(out));
        const bool built = pg_build_md5_from_secret(out, "md53175bce1d3201d16594cebf9d7eb3f9d", salt);
        ok(built && strcmp(out, "md568be9ed08db75f318087ab337aaea044") == 0,
           "pg_build_md5_from_secret reproduces the plaintext-derived reference vector (built=%d, got: %s)",
           (int)built, built ? out : "(not built)");
    }

    // (23) Equivalence at a second, unrelated salt, compared against pg_build_md5() itself.
    // (22) alone could pass on a single coincidence; this pins the general property that
    // for any salt the two entry points agree whenever the secret is that user's inner hash.
    {
        unsigned char salt2[4] = {0xde, 0xad, 0xbe, 0xef};
        char from_plain[36];
        char from_secret[36];
        pg_build_md5(from_plain, "postgres", "postgres", salt2);
        const bool built = pg_build_md5_from_secret(from_secret, "md53175bce1d3201d16594cebf9d7eb3f9d", salt2);
        ok(built && strcmp(from_plain, from_secret) == 0,
           "pg_build_md5_from_secret == pg_build_md5 for the same credential at a second salt (plain=%s, secret=%s)",
           from_plain, built ? from_secret : "(not built)");
    }

    // (24) Malformed secrets are refused BEFORE anything is written. A partially built
    // response must never reach the wire, and a secret that is not exactly "md5" + 32
    // lowercase hex is not this user's inner hash -- PostgreSQL stores nothing else.
    {
        static const char* const bad[] = {
            nullptr,
            "",
            "md5",                                    // prefix only
            "md53175bce1d3201d16594cebf9d7eb3f9",     // 31 hex digits: one short
            "md53175bce1d3201d16594cebf9d7eb3f9dd",   // 33 hex digits: one long
            "MD53175bce1d3201d16594cebf9d7eb3f9d",    // prefix in the wrong case
            "md53175BCE1D3201D16594CEBF9D7EB3F9D",    // hex in the wrong case
            "md53175bce1d3201d16594cebf9d7eb3f9z",    // 'z' is not a hex digit
            "3175bce1d3201d16594cebf9d7eb3f9dabc",    // right length, no md5 prefix
            "SCRAM-SHA-256$4096:c2FsdA==$c3Q=:c2s=",  // a verifier, not an md5 secret
            "plaintext-password",
        };
        bool all_rejected = true;
        bool out_untouched = true;
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            char out[36];
            memset(out, 0x5A, sizeof(out));
            if (pg_build_md5_from_secret(out, bad[i], salt)) {
                all_rejected = false;
                diag("  pg_build_md5_from_secret wrongly accepted: %s", bad[i] ? bad[i] : "(null)");
            }
            for (size_t j = 0; j < sizeof(out); j++) {
                if ((unsigned char)out[j] != 0x5A) { out_untouched = false; break; }
            }
        }
        ok(all_rejected && out_untouched,
           "pg_build_md5_from_secret rejects every malformed secret and leaves the output untouched (rejected=%d, untouched=%d)",
           (int)all_rejected, (int)out_untouched);
    }

    // (25) SCRAM verifier pass-through, end to end, in the exact shape production uses.
    //
    // Leg A is the FRONTEND login: the client presents the plaintext, ProxySQL answers from
    // the stored verifier, and the ClientKey the client used is recovered from its proof
    // (PgSQL_Protocol.cpp harvests scram_state->ClientKey at exactly this point). Leg B is
    // the BACKEND login under test: a fresh exchange against the same verifier, driven with
    // NO password at all -- only the harvested ClientKey and the verifier's ServerKey.
    //
    // The verifier is the RFC 7677 Section 3 vector (password "pencil", salt
    // W22ZaJ0SNY7soEsUEjb6gQ==, i=4096) in pg_authid.rolpassword form, so the harvested keys
    // have published expected values and leg A cannot pass by agreeing with itself.
    {
        ScramState* fe = scram_state_init();
        PgSQL_Scram_State* fe_client = pg_scram_new();
        const char* fe_cf = pg_scram_client_first(fe_client, /*channel_binding=*/false);
        char* fe_sf = fe_cf ? server_first_for(fe, fe_cf, RFC7677_VERIFIER) : nullptr;
        const char* fe_final = fe_sf
            ? pg_scram_client_final(fe_client, "pencil", fe_sf, strlen(fe_sf)) : nullptr;
        const bool fe_ok = fe_final && server_accepts(fe, fe_final);

        const bool harvested_ck = fe_ok && memcmp(fe->ClientKey, RFC7677_CLIENT_KEY, 32) == 0;
        const bool verifier_sk  = fe_ok && memcmp(fe->ServerKey, RFC7677_SERVER_KEY, 32) == 0;
        ok(harvested_ck && verifier_sk,
           "frontend SCRAM login against the RFC 7677 verifier yields the published ClientKey and ServerKey (login=%d, ck=%d, sk=%d)",
           (int)fe_ok, (int)harvested_ck, (int)verifier_sk);

        // ---- leg B: the backend handshake, authenticating from the keys alone ----
        ScramState* be = scram_state_init();
        PgSQL_Scram_State* be_client = pg_scram_new();
        const bool keys_set = pg_scram_set_keys(be_client, fe->ClientKey, fe->ServerKey);
        const char* be_cf = pg_scram_client_first(be_client, /*channel_binding=*/false);
        char* be_sf = be_cf ? server_first_for(be, be_cf, RFC7677_VERIFIER) : nullptr;
        // password == nullptr: the whole point. Nothing in this leg knows "pencil".
        const char* be_final = be_sf
            ? pg_scram_client_final(be_client, nullptr, be_sf, strlen(be_sf)) : nullptr;
        const bool be_accepted = be_final && server_accepts(be, be_final);

        // (26) The injected ClientKey produces a proof the server accepts.
        ok(keys_set && be_accepted,
           "backend SCRAM leg authenticates from the injected ClientKey with NO password (keys_set=%d, accepted=%d)",
           (int)keys_set, (int)be_accepted);

        // (27) Mutual authentication still happens: the client verifies the server's
        // signature from the injected ServerKey, not from a SaltedPassword it never computed.
        char* be_server_final = be_accepted ? build_server_final_message(be) : nullptr;
        const bool mutual = be_server_final
            && pg_scram_verify_server_final(be_client, be_server_final, strlen(be_server_final));
        ok(mutual, "backend SCRAM leg verifies the server signature from the injected ServerKey");

        free(be_server_final);
        pg_scram_free(be_client);
        free_scram_state(be);
        pg_scram_free(fe_client);
        free_scram_state(fe);
    }

    // (28) Mutual authentication is not silently skipped. With the correct ClientKey but a
    // corrupted ServerKey the proof is still accepted -- the server has no way to tell --
    // yet the client MUST reject the server's signature. A pass-through that ignored the
    // injected ServerKey, or fell back to a SaltedPassword it never computed, would let a
    // backend impersonation through here.
    {
        uint8_t bad_sk[32];
        memcpy(bad_sk, RFC7677_SERVER_KEY, sizeof(bad_sk));
        bad_sk[0] ^= 0xff;

        ScramState* srv = scram_state_init();
        PgSQL_Scram_State* cli = pg_scram_new();
        const bool keys_set = pg_scram_set_keys(cli, RFC7677_CLIENT_KEY, bad_sk);
        const char* cf = pg_scram_client_first(cli, /*channel_binding=*/false);
        char* sf = cf ? server_first_for(srv, cf, RFC7677_VERIFIER) : nullptr;
        const char* fin = sf ? pg_scram_client_final(cli, nullptr, sf, strlen(sf)) : nullptr;
        const bool proof_accepted = fin && server_accepts(srv, fin);
        char* server_final = proof_accepted ? build_server_final_message(srv) : nullptr;
        const bool verified = server_final
            && pg_scram_verify_server_final(cli, server_final, strlen(server_final));

        ok(keys_set && proof_accepted && !verified,
           "a wrong injected ServerKey still builds an accepted proof but FAILS server-signature verification (keys_set=%d, proof=%d, verified=%d)",
           (int)keys_set, (int)proof_accepted, (int)verified);

        free(server_final);
        pg_scram_free(cli);
        free_scram_state(srv);
    }

    // (29) A half-injection is refused outright. Accepting a ClientKey without a ServerKey
    // would authenticate us to the backend while leaving nothing to check the backend with,
    // which is exactly the silent downgrade (28) guards against -- so it is rejected at the
    // door instead, and the state stays password-driven (proved by client-final still
    // refusing a NULL password afterwards).
    {
        PgSQL_Scram_State* cli = pg_scram_new();
        const bool r_no_sk   = pg_scram_set_keys(cli, RFC7677_CLIENT_KEY, nullptr);
        const bool r_no_ck   = pg_scram_set_keys(cli, nullptr, RFC7677_SERVER_KEY);
        const bool r_no_both = pg_scram_set_keys(cli, nullptr, nullptr);
        const bool r_no_state = pg_scram_set_keys(nullptr, RFC7677_CLIENT_KEY, RFC7677_SERVER_KEY);

        ScramState* srv = scram_state_init();
        const char* cf = pg_scram_client_first(cli, /*channel_binding=*/false);
        char* sf = cf ? server_first_for(srv, cf, RFC7677_VERIFIER) : nullptr;
        const char* fin = sf ? pg_scram_client_final(cli, nullptr, sf, strlen(sf)) : nullptr;

        ok(!r_no_sk && !r_no_ck && !r_no_both && !r_no_state && fin == nullptr,
           "half-injected SCRAM keys are refused and leave the state password-driven (no_sk=%d, no_ck=%d, no_both=%d, no_state=%d, final=%s)",
           (int)r_no_sk, (int)r_no_ck, (int)r_no_both, (int)r_no_state, fin ? "built" : "null");

        free_scram_state(srv);
        pg_scram_free(cli);
    }

    return exit_status();
}
