#ifndef SCRAM_HMAC_CACHED_H
#define SCRAM_HMAC_CACHED_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Optimized SCRAM-SHA-256 key derivation with cached OpenSSL EVP_MD*.
 * Avoids repeated EVP_MD_fetch() overhead on OpenSSL 3.x.
 * All functions hardcode SHA-256 / 32-byte key length.
 * Returns 0 on success, -1 on failure. */

#define SCRAM_FAST_KEY_LEN 32

int scram_fast_SaltedPassword(const char *password,
							  const char *salt, int saltlen, int iterations,
							  uint8_t *result, const char **errstr);

int scram_fast_H(const uint8_t *input, int len,
				 uint8_t *result, const char **errstr);

int scram_fast_ClientKey(const uint8_t *salted_password,
						 uint8_t *result, const char **errstr);

int scram_fast_ServerKey(const uint8_t *salted_password,
						 uint8_t *result, const char **errstr);

/* Cached HMAC-SHA-256 context for multi-update operations. */
typedef struct scram_fast_hmac_ctx scram_fast_hmac_ctx;

scram_fast_hmac_ctx *scram_fast_hmac_create(void);
int scram_fast_hmac_init(scram_fast_hmac_ctx *ctx, const uint8_t *key, size_t len);
int scram_fast_hmac_update(scram_fast_hmac_ctx *ctx, const uint8_t *data, size_t len);
int scram_fast_hmac_final(scram_fast_hmac_ctx *ctx, uint8_t *dest, size_t len);
void scram_fast_hmac_free(scram_fast_hmac_ctx *ctx);
const char *scram_fast_hmac_error(scram_fast_hmac_ctx *ctx);

/* Invalidate all thread-local SCRAM verifier caches.
 * Incremented on user reload so stale entries are discarded
 * on next lookup. */
void scram_cache_invalidate(void);

#ifdef __cplusplus
}
#endif

#endif
