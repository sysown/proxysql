#include "scram_hmac_cached.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>

/*
 * On OpenSSL 3.x, EVP_sha256() triggers EVP_MD_fetch() on every call,
 * which involves global lock contention and property lookups (~58% of
 * CPU in SCRAM-heavy workloads). Cache the EVP_MD* once and reuse it.
 *
 * On OpenSSL < 3.0, EVP_sha256() is cheap (returns a static object),
 * so the cache has no overhead but also no benefit.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static EVP_MD *cached_sha256_md = NULL;
static pthread_once_t sha256_once = PTHREAD_ONCE_INIT;

static void fetch_sha256(void)
{
	cached_sha256_md = EVP_MD_fetch(NULL, "SHA256", NULL);
}

static EVP_MD *get_sha256_md(void)
{
	pthread_once(&sha256_once, fetch_sha256);
	return cached_sha256_md;
}
#else
static const EVP_MD *get_sha256_md(void)
{
	return EVP_sha256();
}
#endif

/* Error strings */
static const char err_openssl[] = "OpenSSL HMAC failure";
static const char err_oom[] = "out of memory";

/* --- Cached HMAC-SHA-256 context --- */

struct scram_fast_hmac_ctx
{
	HMAC_CTX  *osc;
	const char *errmsg;
};

scram_fast_hmac_ctx *
scram_fast_hmac_create(void)
{
	scram_fast_hmac_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;
	ctx->osc = HMAC_CTX_new();
	if (!ctx->osc)
	{
		free(ctx);
		return NULL;
	}
	return ctx;
}

int
scram_fast_hmac_init(scram_fast_hmac_ctx *ctx, const uint8_t *key, size_t len)
{
	EVP_MD	   *md;

	if (!ctx)
		return -1;
	md = get_sha256_md();
	if (!md)
	{
		ctx->errmsg = err_openssl;
		return -1;
	}
	if (!HMAC_Init_ex(ctx->osc, key, len, md, NULL))
	{
		ctx->errmsg = err_openssl;
		return -1;
	}
	return 0;
}

int
scram_fast_hmac_update(scram_fast_hmac_ctx *ctx, const uint8_t *data, size_t len)
{
	if (!ctx)
		return -1;
	if (!HMAC_Update(ctx->osc, data, len))
	{
		ctx->errmsg = err_openssl;
		return -1;
	}
	return 0;
}

int
scram_fast_hmac_final(scram_fast_hmac_ctx *ctx, uint8_t *dest, size_t len)
{
	unsigned int outlen;

	if (!ctx)
		return -1;
	if (len < SCRAM_FAST_KEY_LEN)
		return -1;
	if (!HMAC_Final(ctx->osc, dest, &outlen))
	{
		ctx->errmsg = err_openssl;
		return -1;
	}
	return 0;
}

void
scram_fast_hmac_free(scram_fast_hmac_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->osc)
		HMAC_CTX_free(ctx->osc);
	free(ctx);
}

const char *
scram_fast_hmac_error(scram_fast_hmac_ctx *ctx)
{
	if (!ctx)
		return err_oom;
	return ctx->errmsg ? ctx->errmsg : err_openssl;
}

/* --- SCRAM key derivation functions --- */

int
scram_fast_SaltedPassword(const char *password,
						  const char *salt, int saltlen, int iterations,
						  uint8_t *result, const char **errstr)
{
	int			password_len = strlen(password);
	uint8_t		one_be[4] = {0, 0, 0, 1};	/* INT(1) big-endian */
	uint8_t		Ui[SCRAM_FAST_KEY_LEN];
	uint8_t		Ui_prev[SCRAM_FAST_KEY_LEN];
	int			i,
				j;
	scram_fast_hmac_ctx *ctx;

	ctx = scram_fast_hmac_create();
	if (!ctx)
	{
		if (errstr) *errstr = err_oom;
		return -1;
	}

	/* First iteration: U1 = HMAC(password, salt || INT(1)) */
	if (scram_fast_hmac_init(ctx, (const uint8_t *) password, password_len) < 0 ||
		scram_fast_hmac_update(ctx, (const uint8_t *) salt, saltlen) < 0 ||
		scram_fast_hmac_update(ctx, one_be, 4) < 0 ||
		scram_fast_hmac_final(ctx, Ui_prev, SCRAM_FAST_KEY_LEN) < 0)
	{
		if (errstr) *errstr = scram_fast_hmac_error(ctx);
		scram_fast_hmac_free(ctx);
		return -1;
	}

	memcpy(result, Ui_prev, SCRAM_FAST_KEY_LEN);

	/* Subsequent iterations */
	for (i = 1; i < iterations; i++)
	{
		if (scram_fast_hmac_init(ctx, (const uint8_t *) password, password_len) < 0 ||
			scram_fast_hmac_update(ctx, Ui_prev, SCRAM_FAST_KEY_LEN) < 0 ||
			scram_fast_hmac_final(ctx, Ui, SCRAM_FAST_KEY_LEN) < 0)
		{
			if (errstr) *errstr = scram_fast_hmac_error(ctx);
			scram_fast_hmac_free(ctx);
			return -1;
		}

		for (j = 0; j < SCRAM_FAST_KEY_LEN; j++)
			result[j] ^= Ui[j];
		memcpy(Ui_prev, Ui, SCRAM_FAST_KEY_LEN);
	}

	scram_fast_hmac_free(ctx);
	return 0;
}

int
scram_fast_H(const uint8_t *input, int len,
			 uint8_t *result, const char **errstr)
{
	EVP_MD	   *md;
	unsigned int outlen;

	md = get_sha256_md();
	if (!md)
	{
		if (errstr) *errstr = err_openssl;
		return -1;
	}
	if (!EVP_Digest(input, len, result, &outlen, md, NULL))
	{
		if (errstr) *errstr = err_openssl;
		return -1;
	}
	return 0;
}

int
scram_fast_ClientKey(const uint8_t *salted_password,
					 uint8_t *result, const char **errstr)
{
	scram_fast_hmac_ctx *ctx;

	ctx = scram_fast_hmac_create();
	if (!ctx)
	{
		if (errstr) *errstr = err_oom;
		return -1;
	}

	if (scram_fast_hmac_init(ctx, salted_password, SCRAM_FAST_KEY_LEN) < 0 ||
		scram_fast_hmac_update(ctx, (const uint8_t *) "Client Key", 10) < 0 ||
		scram_fast_hmac_final(ctx, result, SCRAM_FAST_KEY_LEN) < 0)
	{
		if (errstr) *errstr = scram_fast_hmac_error(ctx);
		scram_fast_hmac_free(ctx);
		return -1;
	}

	scram_fast_hmac_free(ctx);
	return 0;
}

int
scram_fast_ServerKey(const uint8_t *salted_password,
					 uint8_t *result, const char **errstr)
{
	scram_fast_hmac_ctx *ctx;

	ctx = scram_fast_hmac_create();
	if (!ctx)
	{
		if (errstr) *errstr = err_oom;
		return -1;
	}

	if (scram_fast_hmac_init(ctx, salted_password, SCRAM_FAST_KEY_LEN) < 0 ||
		scram_fast_hmac_update(ctx, (const uint8_t *) "Server Key", 10) < 0 ||
		scram_fast_hmac_final(ctx, result, SCRAM_FAST_KEY_LEN) < 0)
	{
		if (errstr) *errstr = scram_fast_hmac_error(ctx);
		scram_fast_hmac_free(ctx);
		return -1;
	}

	scram_fast_hmac_free(ctx);
	return 0;
}
