#include "PgSQL_Backend_Protocol.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <new>
#include <string>
#include <openssl/md5.h>   // project-existing one-shot MD5(); also pulls MD5_DIGEST_LENGTH
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include "scram.h"         // vendored libscram (same include used by PgSQL_Data_Stream.h)

static void put_be32(unsigned char* p, uint32_t v) {
    p[0] = (v >> 24) & 0xff;
    p[1] = (v >> 16) & 0xff;
    p[2] = (v >> 8) & 0xff;
    p[3] = v & 0xff;
}

void pg_build_ssl_request(unsigned char out[8]) {
    put_be32(out, 8);
    put_be32(out + 4, 80877103u);   // 0x04d2162f
}

bool pg_build_startup(unsigned char* out, size_t* out_len, size_t out_cap,
                      const char* user, const char* database,
                      const char* client_encoding, const char* options,
                      const char* application_name) {
    const bool has_enc  = (client_encoding != nullptr && client_encoding[0] != '\0');
    const bool has_opts = (options != nullptr && options[0] != '\0');
    const bool has_app  = (application_name != nullptr && application_name[0] != '\0');

    // Compute the required size first so a bound check can reject before any write,
    // guaranteeing no partial/oversized output is left in the caller buffer. Every
    // parameter costs "key\0" + "value\0"; sizeof() on the key literal already counts
    // its NUL, so renaming a key can never leave a stale hand-counted length behind.
    size_t need = 4 + 4                                             // length + protocol
                + sizeof("user")     + (strlen(user) + 1)
                + sizeof("database") + (strlen(database) + 1)
                + 1;                                                // terminating empty key
    if (has_opts) need += sizeof("options")          + strlen(options) + 1;
    if (has_app)  need += sizeof("application_name") + strlen(application_name) + 1;
    if (has_enc)  need += sizeof("client_encoding")  + strlen(client_encoding) + 1;
    if (need > out_cap) {
        *out_len = 0;
        return false;
    }

    size_t off = 8;                 // reserve length(4) + protocol(4)
    auto add = [&](const char* s) { size_t l = strlen(s) + 1; memcpy(out + off, s, l); off += l; };
    // Emitted in the same order libpq uses, so a packet capture lines up parameter for
    // parameter with one from the libpq path.
    add("user");     add(user);
    add("database"); add(database);
    if (has_opts) { add("options");          add(options); }
    if (has_app)  { add("application_name"); add(application_name); }
    if (has_enc)  { add("client_encoding");  add(client_encoding); }
    out[off++] = 0;                 // terminating empty key

    put_be32(out, (uint32_t)off);   // total length (includes the length field itself)
    put_be32(out + 4, 196608u);     // protocol 3.0 = 0x00030000
    *out_len = off;
    return true;
}

// Lowercase-hex of an MD5 digest over [in, in+inlen). out_hex receives 32 hex
// chars plus a terminating NUL (33 bytes total).
static void md5_hex(const unsigned char* in, size_t inlen, char out_hex[33]) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(in, inlen, digest);
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        out_hex[i * 2]     = hexd[(digest[i] >> 4) & 0xf];
        out_hex[i * 2 + 1] = hexd[digest[i] & 0xf];
    }
    out_hex[MD5_DIGEST_LENGTH * 2] = '\0';
}

// Shared outer step of the AuthenticationMD5Password response:
//   out = "md5" + hex(md5( inner_hex[32] || salt[4] ))
// inner_hex is NOT NUL-terminated; exactly 32 bytes are read.
static void md5_response_from_inner(char out[36], const char* inner_hex,
                                    const unsigned char salt[4]) {
    unsigned char outer_in[MD5_DIGEST_LENGTH * 2 + 4];
    memcpy(outer_in, inner_hex, MD5_DIGEST_LENGTH * 2);
    memcpy(outer_in + MD5_DIGEST_LENGTH * 2, salt, 4);

    char outer_hex[33];
    md5_hex(outer_in, sizeof(outer_in), outer_hex);

    memcpy(out, "md5", 3);
    memcpy(out + 3, outer_hex, 33);   // 32 hex chars + NUL -> out[3..35]
}

void pg_build_md5(char out[36], const char* user, const char* password, const unsigned char salt[4]) {
    // inner = hex(md5(password + user)). Hash the concatenation without an
    // intermediate NUL-terminated copy by passing each part length explicitly.
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, password, strlen(password));
    MD5_Update(&ctx, user, strlen(user));
    MD5_Final(digest, &ctx);

    static const char hexd[] = "0123456789abcdef";
    char inner_hex[MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        inner_hex[i * 2]     = hexd[(digest[i] >> 4) & 0xf];
        inner_hex[i * 2 + 1] = hexd[digest[i] & 0xf];
    }
    md5_response_from_inner(out, inner_hex, salt);
}

bool pg_build_md5_from_secret(char out[36], const char* md5_secret, const unsigned char salt[4]) {
    if (out == nullptr || md5_secret == nullptr || salt == nullptr) return false;
    // "md5" + exactly 32 LOWERCASE hex digits and nothing else -- the only form PostgreSQL
    // stores. Validate in full before writing the first byte: a half-built response on a
    // rejected secret is indistinguishable from a good one at the call site.
    if (strlen(md5_secret) != 3 + (size_t)MD5_DIGEST_LENGTH * 2) return false;
    if (memcmp(md5_secret, "md5", 3) != 0) return false;
    const char* inner_hex = md5_secret + 3;
    for (int i = 0; i < MD5_DIGEST_LENGTH * 2; i++) {
        const char c = inner_hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    // The stored secret IS the inner hash, so only the outer step is left. Hashing it a
    // second time through pg_build_md5() is what made md5-stored users fail on this path.
    md5_response_from_inner(out, inner_hex, salt);
    return true;
}

// --- SCRAM-SHA-256 client exchange (thin wrappers over libscram) ---

// Owns the libscram ScramState plus a cached PgCredentials and the message strings
// libscram hands back as malloc'd C-strings. Holding the latest message of each kind
// keeps the returned pointers valid for the caller (the libscram functions otherwise
// leak the strings to their caller) and lets the destructor free them.
struct PgSQL_Scram_State {
    ScramState* st = nullptr;
    PgCredentials creds{};   // value-initialized -> all fields zeroed, has_scram_keys=false
    char* client_first = nullptr;
    char* client_final = nullptr;
};

PgSQL_Scram_State* pg_scram_new() {
    PgSQL_Scram_State* s = new (std::nothrow) PgSQL_Scram_State();
    if (s == nullptr) return nullptr;
    s->st = scram_state_init();
    if (s->st == nullptr) { delete s; return nullptr; }
    return s;
}

void pg_scram_free(PgSQL_Scram_State* s) {
    if (s == nullptr) return;
    if (s->st) free_scram_state(s->st);   // frees ScramState's owned buffers + the struct
    free(s->client_first);
    free(s->client_final);
    // creds holds password-equivalent material (a plaintext password, or an injected
    // ClientKey/ServerKey pair). Scrub it non-elidably before the memory goes back.
    OPENSSL_cleanse(&s->creds, sizeof(s->creds));
    delete s;
}

const char* pg_scram_client_first(PgSQL_Scram_State* s, bool channel_binding) {
    if (s == nullptr || s->st == nullptr) return nullptr;
    // channel_binding=true selects SCRAM-SHA-256-PLUS. The gs2 header libscram
    // writes is driven by the cbind input the caller installed with
    // pg_scram_set_cbind(), NOT by this flag, so the two must agree: advertising
    // -PLUS while no cbind input is set would emit a plain "n,," header against a
    // -PLUS mechanism name and the server would reject the proof. Refuse that
    // combination rather than produce a mismatched handshake.
    if (channel_binding && s->st->client_cbind_input == nullptr) return nullptr;
    scram_reset_error();
    // libscram emits "n,,n=,r=<nonce>", or "p=tls-server-end-point,,n=,r=<nonce>"
    // when a cbind input is set, and stashes client_nonce / client_first_message_bare
    // into the ScramState for the later proof computation.
    char* msg = build_client_first_message(s->st);
    if (msg == nullptr) return nullptr;
    free(s->client_first);
    s->client_first = msg;
    return s->client_first;
}

const char* pg_scram_client_final(PgSQL_Scram_State* s, const char* password,
                                  const char* server_first, size_t server_first_len) {
    if (s == nullptr || s->st == nullptr || server_first == nullptr) return nullptr;
    // A password is required UNLESS pg_scram_set_keys() injected a ClientKey/ServerKey pair,
    // in which case libscram derives nothing from a password and never reads creds.passwd.
    if (password == nullptr && !s->creds.has_scram_keys) return nullptr;
    scram_reset_error();

    // read_server_first_message() mutates its input (read_attr_value writes NULs and
    // advances), so feed it a private, NUL-terminated, mutable copy.
    std::string sf(server_first, server_first_len);

    char* server_nonce = nullptr;
    char* salt = nullptr;
    int saltlen = 0;
    int iterations = 0;
    if (!read_server_first_message(s->st, &sf[0], &server_nonce, &salt, &saltlen, &iterations)) {
        free(salt);
        return nullptr;
    }

    if (!s->creds.has_scram_keys) {
        // The password is the SCRAM plaintext secret; libscram derives keys ad-hoc.
        snprintf(s->creds.passwd, sizeof(s->creds.passwd), "%s", password);
    }
    // With keys injected, creds already carries ClientKey/ServerKey and passwd stays empty:
    // build_client_final_message() uses the ClientKey directly and skips SASLprep + PBKDF2,
    // so the salt and iteration count the backend just sent are (correctly) unused.

    char* msg = build_client_final_message(s->st, &s->creds, server_nonce, salt, saltlen, iterations);
    // server_nonce / salt point into the parsed buffers: server_nonce into the local
    // `sf` copy (no free), salt is malloc'd by read_server_first_message (must free).
    free(salt);
    if (msg == nullptr) return nullptr;
    free(s->client_final);
    s->client_final = msg;
    return s->client_final;
}

bool pg_scram_verify_server_final(PgSQL_Scram_State* s, const char* server_final, size_t len) {
    if (s == nullptr || s->st == nullptr || server_final == nullptr) return false;
    scram_reset_error();
    // read_server_final_message() mutates its input; use a private NUL-terminated copy.
    std::string sf(server_final, len);
    char ServerSignature[32];   // SCRAM_KEY_LEN
    if (!read_server_final_message(&sf[0], ServerSignature)) return false;
    return verify_server_signature(s->st, &s->creds, ServerSignature);
}

int pg_tls_server_end_point(SSL* ssl, unsigned char* out, size_t* out_len) {
    if (ssl == nullptr || out == nullptr || out_len == nullptr) return -1;
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr) return -1;
    int mdnid = NID_undef, pknid = NID_undef, secbits = 0;
    uint32_t flags = 0;
    if (X509_get_signature_info(cert, &mdnid, &pknid, &secbits, &flags) == 0) {
        X509_free(cert);
        return -1;
    }
    // RFC 5929 §4.1: upgrade MD5 / SHA-1 to SHA-256.
    if (mdnid == NID_md5 || mdnid == NID_sha1) {
        mdnid = NID_sha256;
    }
    const EVP_MD* md = EVP_get_digestbynid(mdnid);
    if (md == nullptr) {
        X509_free(cert);
        return -1;
    }
    unsigned int len = 0;
    if (X509_digest(cert, md, out, &len) == 0 || len == 0) {
        X509_free(cert);
        return -1;
    }
    *out_len = (size_t)len;
    X509_free(cert);
    return (int)len;
}

int pg_scram_build_cbind_input_tls_server_end_point(
    const unsigned char* digest, size_t digest_len,
    unsigned char* out, size_t out_cap) {
    if (digest == nullptr || out == nullptr) return -1;
    // gs2 header per RFC 5802 §6: "p=" cbind-type "," [authzid] ","
    // For tls-server-end-point: "p=tls-server-end-point,," = 24 bytes.
    static const char header[] = "p=tls-server-end-point,,";
    static const size_t header_len = sizeof(header) - 1;  // 24
    size_t total = header_len + digest_len;
    if (out_cap < total) return -1;
    memcpy(out, header, header_len);
    if (digest_len > 0) memcpy(out + header_len, digest, digest_len);
    return (int)total;
}

bool pg_scram_set_keys(PgSQL_Scram_State* s, const uint8_t* client_key, const uint8_t* server_key) {
    if (s == nullptr || s->st == nullptr) return false;
    // Both or neither. A ClientKey on its own still produces a proof the backend accepts,
    // but leaves verify_server_signature() nothing genuine to check against -- the server
    // half of mutual authentication would be dropped without any visible failure. libscram
    // gates both keys on one flag, so a half-filled PgCredentials is not representable
    // there either; refuse the call rather than approximate it.
    if (client_key == nullptr || server_key == nullptr) return false;
    memcpy(s->creds.scram_ClientKey, client_key, sizeof(s->creds.scram_ClientKey));
    memcpy(s->creds.scram_ServerKey, server_key, sizeof(s->creds.scram_ServerKey));
    s->creds.has_scram_keys = true;
    // A verifier is not a password: an empty passwd means nothing downstream can fall back
    // to SASLprep + PBKDF2 over verifier text. Cleansed so an earlier call's cannot linger.
    OPENSSL_cleanse(s->creds.passwd, sizeof(s->creds.passwd));
    return true;
}

void pg_scram_set_cbind(PgSQL_Scram_State* s, const char* cbind_input, int cbind_input_len) {
    if (s == nullptr) return;
    scram_state_set_cbind_input(s->st, cbind_input, cbind_input_len);
}
