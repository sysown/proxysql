
/*
 * Required system headers
 */
#include <stdint.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
 
#define int8	int8_t
#define uint8	uint8_t
#define uint16	uint16_t
#define uint32	uint32_t
#define uint64	uint64_t

#define SCRAM_KEY_LEN			 SCRAM_SHA_256_KEY_LEN
#define SCRAM_DEFAULT_ITERATIONS SCRAM_SHA_256_DEFAULT_ITERATIONS
