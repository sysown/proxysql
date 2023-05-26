Unix crypt using SHA-256 and SHA-512
------------------------------------

Author: Ulrich Drepper <drepper@gmail.com>
Version: 0.6 2016-8-31

Only editorial changes since 0.4


Discussion Group:

Josh Bressers, Red Hat
Mark Brown, IBM
David Clissold, IBM
Don Cragun, Sun
Casper Dik, Sun
Ulrich Drepper, Red Hat
Larry Dwyer, HP
Steve Grubb, Red Hat
Ravi A Shankar, IBM
Borislav Simov, HP


Various Unix crypt implementations have been MD5 as an alternative
method to the traditional DES encryption for the one-way conversion
needed.  Both DES and MD5 are deemed insecure for their primary
purpose and by association their use in password encryption is put
into question.  In addition, the produced output for both DES and MD5
has a short length which makes it possible to construct rainbow tables.

Requests for a better solution to the problem have been heard for some
time.  Security departments in companies are trying to phase out all
uses of MD5.  They demand a method which is officially sanctioned.
For US-based users this means tested by the NIST.

This rules out the use of another already implemented method with
limited spread: the use of the Blowfish encryption method.  The choice
comes down to tested encryption (3DES, AES) or hash sums (the SHA
family).

Encryption-based solution do not seem to provide better security (no
proof to the contrary) and the higher CPU requirements can be
compensated for by adding more complexity to a hash sum-based
solution.  This is why the decision has been made by a group of Unix
and Linux vendors to persue this route.

The SHA hash sum functions are well tested.  By choosing the SHA-256
and SHA-512 algorithms the produced output is 32 or 64 bytes
respectively in size.  This fulfills the requirement for a large
output set which makes rainbow tables less useful to impossible, at
least for the next years.

The algorithm used by the MD5-based password hashing is generally
deemed safe as well so there is no big problem with using a similar
algorithm for the SHA-based password hashing solutions.  Parts of the
algorithm have been changed and in one instance what is thought to be
a mistake in the MD5-based implementation has been fixed.

The integration into existing systems is easy if those systems already
support the MD5-based solution.  Ever since the introduction of the
MD5-based method an extended password format is in used:

   $<ID>$<SALT>$<PWD>

If the password is not of this form it is an old-style DES-encrypted
password.  If the password has this form the ID identifies the method
used and this then determines how the rest of the password string is
interpreted.  So far the following ID values are in use:


     ID       |    Method
  -------------------------------
     1        |  MD5 (Linux, BSD)
     2a       |  Blowfish (OpenBSD)
     md5      |  Sun MD5


For the new SHA-256 and SHA-512 methods the following values are
selected:


     ID       |    Method
  -------------------------------
     5        |  SHA-256
     6        |  SHA-512


For the SHA-based methods the SALT string can be a simple string of
which up to 16 characters are used.  The MD5-based implementation used
up to eight characters..  It was decided to allow one extension which
follows an invention Sun implemented in their pluggable crypt
implementation.  If the SALT strings starts with

   rounds=<N>$

where N is an unsigned decimal number the numeric value of N is used
to modify the algorithm used.  As will be explained later, the
SHA-based algorithm contains a loop which can be run an arbitrary
number of times.  The more rounds are performed the higher the CPU
requirements are.  This is a safety mechanism which might help
countering brute-force attacks in the face of increasing computing
power.

The default number of rounds for both algorithms is 5,000.  To ensure
minimal security and stability on the other hand minimum and maximum
values for N are enforced:

   minimum for N = 1,000
   maximum for N = 999,999,999

Any selection of N below the minimum will cause the use of 1,000
rounds and a value of 1 billion and higher will cause 999,999,999
rounds to be used.  In these cases the output string produced by the
crypt function will not have the same salt as the input salt string
since the correct, limited rounds value is used in the output.

The PWD part of the password string is the actual computed password.
The size of this string is fixed:

      SHA-256    43 characters
      SHA-512    86 characters

The output consists of the base64-encoded digest.  The maximum length
of a password string is therefore (excluding final NUL byte in the C
representation):

     SHA-256     80 characters
     SHA-512     123 characters

The input string used for the salt parameter of the crypt function can
potentially be much longer.  But since the salt string is truncated to
at most 16 characters the size of the output string is limited.

The algorithm used for the password hashing follows the one used in
the Linux/BSD MD5 implementation.  The following is a description of
the algorithm where the differences are explicitly pointed out.  Both,
the SHA-256 and the SHA-512 method, use the same algorithm.  The only
difference, which is also a difference to the MD5 version, are all the
cases where an existing digest is used as input for another digest
computation.  In this case the input size (i.e., the digest size)
varies.  For MD5 the digest is 16 bytes, for SHA-256 it is 32 bytes,
and for SHA-512 it is 64 bytes.  The following description will not
mention this difference further.

The algorithm using three primitives for creating a hash digest:

- start a digest.  This sets up the data structures and initial state
  as required for the hash function

- add bytes to a digest.  This can happen multiple times.  Only when
  the required number of bytes for a round of the hash function is
  added will anything happen.  If the required number of bytes is not
  yet reached the bytes will simply be queued up.  For SHA-256 and
  SHA-512 the respective sizes are 64 and 128 bytes.

- finish the context.  This operation causes the currently queued
  bytes to be padded according to the hash function specification and
  the result is processed.  The final digest is computed and made
  available to the use.

When the algorithm talks about adding the salt string this really
means adding the salt string truncated to 16 characters.

When the algorithm talks about adding a string the terminating NUL
byte of the C presentation of the string in NOT added.


Algorithm for crypt using SHA-256/SHA-512:

1.  start digest A

2.  the password string is added to digest A

3.  the salt string is added to digest A.  This is just the salt string
    itself without the enclosing '$', without the magic prefix $5$ and
    $6$ respectively and without the rounds=<N> specification.

    NB: the MD5 algorithm did add the $1$ prefix.  This is not deemed
    necessary since it is a constant string and does not add security
    and /possibly/ allows a plain text attack.  Since the rounds=<N>
    specification should never be added this would also create an
    inconsistency.

4.  start digest B

5.  add the password to digest B

6.  add the salt string to digest B

7.  add the password again to digest B

8.  finish digest B

9.  For each block of 32 or 64 bytes in the password string (excluding
    the terminating NUL in the C representation), add digest B to digest A

10. For the remaining N bytes of the password string add the first
    N bytes of digest B to digest A

11. For each bit of the binary representation of the length of the
    password string up to and including the highest 1-digit, starting
    from to lowest bit position (numeric value 1):

    a) for a 1-digit add digest B to digest A

    b) for a 0-digit add the password string

    NB: this step differs significantly from the MD5 algorithm.  It
    adds more randomness.

12. finish digest A

13. start digest DP

14. for every byte in the password (excluding the terminating NUL byte
    in the C representation of the string)

      add the password to digest DP

15. finish digest DP

16. produce byte sequence P of the same length as the password where

    a) for each block of 32 or 64 bytes of length of the password string
       the entire digest DP is used

    b) for the remaining N (up to  31 or 63) bytes use the first N
       bytes of digest DP

17. start digest DS

18. repeat the following 16+A[0] times, where A[0] represents the first
    byte in digest A interpreted as an 8-bit unsigned value

      add the salt to digest DS

19. finish digest DS

20. produce byte sequence S of the same length as the salt string where

    a) for each block of 32 or 64 bytes of length of the salt string
       the entire digest DS is used

    b) for the remaining N (up to  31 or 63) bytes use the first N
       bytes of digest DS

21. repeat a loop according to the number specified in the rounds=<N>
    specification in the salt (or the default value if none is
    present).  Each round is numbered, starting with 0 and up to N-1.

    The loop uses a digest as input.  In the first round it is the
    digest produced in step 12.  In the latter steps it is the digest
    produced in step 21.h of the previous round.  The following text
    uses the notation "digest A/C" to describe this behavior.


    a) start digest C

    b) for odd round numbers add the byte sequense P to digest C

    c) for even round numbers add digest A/C

    d) for all round numbers not divisible by 3 add the byte sequence S

    e) for all round numbers not divisible by 7 add the byte sequence P

    f) for odd round numbers add digest A/C

    g) for even round numbers add the byte sequence P

    h) finish digest C.

22. Produce the output string.  This is an ASCII string of the maximum
    size specified above, consisting of multiple pieces:

    a) the salt prefix, $5$ or $6$ respectively

    b) the rounds=<N> specification, if one was present in the input
       salt string.  A trailing '$' is added in this case to separate
       the rounds specification from the following text.

    c) the salt string truncated to 16 characters

    d) a '$' character

    e) the base-64 encoded final C digest.  The encoding used is as
       follows:

                 111111111122222222223333333333444444444455555555556666
       0123456789012345678901234567890123456789012345678901234567890123
       ----------------------------------------------------------------
       ./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz

       Each group of three bytes from the digest produces four
       characters as output:

         1. character: the six low bits of the first byte
         2. character: the two high bits of the first byte and the
                       four low bytes from the second byte
	 3. character: the four high bits from the second byte and
                       the two low bits from the third byte
         4. character: the six high bits from the third byte

       The groups of three bytes are as follows (in this sequence).
       These are the indices into the byte array containing the
       digest, starting with index 0.  For the last group there are
       not enough bytes left in the digest and the value zero is used
       in its place.  This group also produces only three or two
       characters as output for SHA-256 and SHA-512 respectively.

       For SHA-256:

         #3   #2   #1   <-- byte number in group

          0 - 10 - 20
         21 -  1 - 11
         12 - 22 -  2
          3 - 13 - 23
         24 -  4 - 14
         15 - 25 -  5
          6 - 16 - 26
         27 -  7 - 17
         18 - 28 -  8
          9 - 19 - 29
          * - 31 - 30


       For SHA-512:

         #3   #2   #1   <-- byte number in group

          0 - 21 - 42
         22 - 43 -  1
         44 -  2 - 23
          3 - 24 - 45
         25 - 46 -  4
         47 -  5 - 26
          6 - 27 - 48
         28 - 49 -  7
         50 -  8 - 29
          9 - 30 - 51
         31 - 52 - 10
         53 - 11 - 32
         12 - 33 - 54
         34 - 55 - 13
         56 - 14 - 35
         15 - 36 - 57
         37 - 58 - 16
         59 - 17 - 38
         18 - 39 - 60
         40 - 61 - 19
         62 - 20 - 41
          * -  * - 63



The following are complete implementation of the crypt variants using
SHA-256 and SHA-512 respectively.  The sources include a self test
which can be enabled by defining the macro TEST.

-------- sha256crypt.c ------------------------------------------------------
/* SHA256-based Unix crypt implementation.
   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.  */

#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>


/* Structure to save state of computation between the single steps.  */
struct sha256_ctx
{
  uint32_t H[8];

  uint32_t total[2];
  uint32_t buflen;
  char buffer[128];	/* NB: always correctly aligned for uint32_t.  */
};


#if __BYTE_ORDER == __LITTLE_ENDIAN
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#else
# define SWAP(n) (n)
#endif


/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (FIPS 180-2:5.1.1)  */
static const unsigned char fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */ };


/* Constants for SHA256 from FIPS 180-2:4.2.2.  */
static const uint32_t K[64] =
  {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };


/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.  */
static void
sha256_process_block (const void *buffer, size_t len, struct sha256_ctx *ctx)
{
  const uint32_t *words = buffer;
  size_t nwords = len / sizeof (uint32_t);
  uint32_t a = ctx->H[0];
  uint32_t b = ctx->H[1];
  uint32_t c = ctx->H[2];
  uint32_t d = ctx->H[3];
  uint32_t e = ctx->H[4];
  uint32_t f = ctx->H[5];
  uint32_t g = ctx->H[6];
  uint32_t h = ctx->H[7];

  /* First increment the byte count.  FIPS 180-2 specifies the possible
     length of the file up to 2^64 bits.  Here we only compute the
     number of bytes.  Do a double word increment.  */
  ctx->total[0] += len;
  if (ctx->total[0] < len)
    ++ctx->total[1];

  /* Process all bytes in the buffer with 64 bytes in each round of
     the loop.  */
  while (nwords > 0)
    {
      uint32_t W[64];
      uint32_t a_save = a;
      uint32_t b_save = b;
      uint32_t c_save = c;
      uint32_t d_save = d;
      uint32_t e_save = e;
      uint32_t f_save = f;
      uint32_t g_save = g;
      uint32_t h_save = h;

      /* Operators defined in FIPS 180-2:4.1.2.  */
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (CYCLIC (x, 2) ^ CYCLIC (x, 13) ^ CYCLIC (x, 22))
#define S1(x) (CYCLIC (x, 6) ^ CYCLIC (x, 11) ^ CYCLIC (x, 25))
#define R0(x) (CYCLIC (x, 7) ^ CYCLIC (x, 18) ^ (x >> 3))
#define R1(x) (CYCLIC (x, 17) ^ CYCLIC (x, 19) ^ (x >> 10))

      /* It is unfortunate that C does not provide an operator for
	 cyclic rotation.  Hope the C compiler is smart enough.  */
#define CYCLIC(w, s) ((w >> s) | (w << (32 - s)))

      /* Compute the message schedule according to FIPS 180-2:6.2.2 step 2.  */
      for (unsigned int t = 0; t < 16; ++t)
	{
	  W[t] = SWAP (*words);
	  ++words;
	}
      for (unsigned int t = 16; t < 64; ++t)
	W[t] = R1 (W[t - 2]) + W[t - 7] + R0 (W[t - 15]) + W[t - 16];

      /* The actual computation according to FIPS 180-2:6.2.2 step 3.  */
      for (unsigned int t = 0; t < 64; ++t)
	{
	  uint32_t T1 = h + S1 (e) + Ch (e, f, g) + K[t] + W[t];
	  uint32_t T2 = S0 (a) + Maj (a, b, c);
	  h = g;
	  g = f;
	  f = e;
	  e = d + T1;
	  d = c;
	  c = b;
	  b = a;
	  a = T1 + T2;
	}

      /* Add the starting values of the context according to FIPS 180-2:6.2.2
	 step 4.  */
      a += a_save;
      b += b_save;
      c += c_save;
      d += d_save;
      e += e_save;
      f += f_save;
      g += g_save;
      h += h_save;

      /* Prepare for the next round.  */
      nwords -= 16;
    }

  /* Put checksum in context given as argument.  */
  ctx->H[0] = a;
  ctx->H[1] = b;
  ctx->H[2] = c;
  ctx->H[3] = d;
  ctx->H[4] = e;
  ctx->H[5] = f;
  ctx->H[6] = g;
  ctx->H[7] = h;
}


/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.2)  */
static void
sha256_init_ctx (struct sha256_ctx *ctx)
{
  ctx->H[0] = 0x6a09e667;
  ctx->H[1] = 0xbb67ae85;
  ctx->H[2] = 0x3c6ef372;
  ctx->H[3] = 0xa54ff53a;
  ctx->H[4] = 0x510e527f;
  ctx->H[5] = 0x9b05688c;
  ctx->H[6] = 0x1f83d9ab;
  ctx->H[7] = 0x5be0cd19;

  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}


/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
static void *
sha256_finish_ctx (struct sha256_ctx *ctx, void *resbuf)
{
  /* Take yet unprocessed bytes into account.  */
  uint32_t bytes = ctx->buflen;
  size_t pad;

  /* Now count remaining bytes.  */
  ctx->total[0] += bytes;
  if (ctx->total[0] < bytes)
    ++ctx->total[1];

  pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
  memcpy (&ctx->buffer[bytes], fillbuf, pad);

  /* Put the 64-bit file length in *bits* at the end of the buffer.  */
  *(uint32_t *) &ctx->buffer[bytes + pad + 4] = SWAP (ctx->total[0] << 3);
  *(uint32_t *) &ctx->buffer[bytes + pad] = SWAP ((ctx->total[1] << 3) |
						  (ctx->total[0] >> 29));

  /* Process last bytes.  */
  sha256_process_block (ctx->buffer, bytes + pad + 8, ctx);

  /* Put result from CTX in first 32 bytes following RESBUF.  */
  for (unsigned int i = 0; i < 8; ++i)
    ((uint32_t *) resbuf)[i] = SWAP (ctx->H[i]);

  return resbuf;
}


static void
sha256_process_bytes (const void *buffer, size_t len, struct sha256_ctx *ctx)
{
  /* When we already have some bits in our internal buffer concatenate
     both inputs first.  */
  if (ctx->buflen != 0)
    {
      size_t left_over = ctx->buflen;
      size_t add = 128 - left_over > len ? len : 128 - left_over;

      memcpy (&ctx->buffer[left_over], buffer, add);
      ctx->buflen += add;

      if (ctx->buflen > 64)
	{
	  sha256_process_block (ctx->buffer, ctx->buflen & ~63, ctx);

	  ctx->buflen &= 63;
	  /* The regions in the following copy operation cannot overlap.  */
	  memcpy (ctx->buffer, &ctx->buffer[(left_over + add) & ~63],
		  ctx->buflen);
	}

      buffer = (const char *) buffer + add;
      len -= add;
    }

  /* Process available complete blocks.  */
  if (len >= 64)
    {
/* To check alignment gcc has an appropriate operator.  Other
   compilers don't.  */
#if __GNUC__ >= 2
# define UNALIGNED_P(p) (((uintptr_t) p) % __alignof__ (uint32_t) != 0)
#else
# define UNALIGNED_P(p) (((uintptr_t) p) % sizeof (uint32_t) != 0)
#endif
      if (UNALIGNED_P (buffer))
	while (len > 64)
	  {
	    sha256_process_block (memcpy (ctx->buffer, buffer, 64), 64, ctx);
	    buffer = (const char *) buffer + 64;
	    len -= 64;
	  }
      else
	{
	  sha256_process_block (buffer, len & ~63, ctx);
	  buffer = (const char *) buffer + (len & ~63);
	  len &= 63;
	}
    }

  /* Move remaining bytes into internal buffer.  */
  if (len > 0)
    {
      size_t left_over = ctx->buflen;

      memcpy (&ctx->buffer[left_over], buffer, len);
      left_over += len;
      if (left_over >= 64)
	{
	  sha256_process_block (ctx->buffer, 64, ctx);
	  left_over -= 64;
	  memcpy (ctx->buffer, &ctx->buffer[64], left_over);
	}
      ctx->buflen = left_over;
    }
}


/* Define our magic string to mark salt for SHA256 "encryption"
   replacement.  */
static const char sha256_salt_prefix[] = "$5$";

/* Prefix for optional rounds specification.  */
static const char sha256_rounds_prefix[] = "rounds=";

/* Maximum salt string length.  */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999

/* Table with characters for base64 transformation.  */
static const char b64t[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";


static char *
sha256_crypt_r (const char *key, const char *salt, char *buffer, int buflen)
{
  unsigned char alt_result[32]
    __attribute__ ((__aligned__ (__alignof__ (uint32_t))));
  unsigned char temp_result[32]
    __attribute__ ((__aligned__ (__alignof__ (uint32_t))));
  struct sha256_ctx ctx;
  struct sha256_ctx alt_ctx;
  size_t salt_len;
  size_t key_len;
  size_t cnt;
  char *cp;
  char *copied_key = NULL;
  char *copied_salt = NULL;
  char *p_bytes;
  char *s_bytes;
  /* Default number of rounds.  */
  size_t rounds = ROUNDS_DEFAULT;
  bool rounds_custom = false;

  /* Find beginning of salt string.  The prefix should normally always
     be present.  Just in case it is not.  */
  if (strncmp (sha256_salt_prefix, salt, sizeof (sha256_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (sha256_salt_prefix) - 1;

  if (strncmp (salt, sha256_rounds_prefix, sizeof (sha256_rounds_prefix) - 1)
      == 0)
    {
      const char *num = salt + sizeof (sha256_rounds_prefix) - 1;
      char *endp;
      unsigned long int srounds = strtoul (num, &endp, 10);
      if (*endp == '$')
	{
	  salt = endp + 1;
	  rounds = MAX (ROUNDS_MIN, MIN (srounds, ROUNDS_MAX));
	  rounds_custom = true;
	}
    }

  salt_len = MIN (strcspn (salt, "$"), SALT_LEN_MAX);
  key_len = strlen (key);

  if ((key - (char *) 0) % __alignof__ (uint32_t) != 0)
    {
      char *tmp = (char *) alloca (key_len + __alignof__ (uint32_t));
      key = copied_key =
	memcpy (tmp + __alignof__ (uint32_t)
		- (tmp - (char *) 0) % __alignof__ (uint32_t),
		key, key_len);
    }

  if ((salt - (char *) 0) % __alignof__ (uint32_t) != 0)
    {
      char *tmp = (char *) alloca (salt_len + __alignof__ (uint32_t));
      salt = copied_salt =
	memcpy (tmp + __alignof__ (uint32_t)
		- (tmp - (char *) 0) % __alignof__ (uint32_t),
		salt, salt_len);
    }

  /* Prepare for the real work.  */
  sha256_init_ctx (&ctx);

  /* Add the key string.  */
  sha256_process_bytes (key, key_len, &ctx);

  /* The last part is the salt string.  This must be at most 16
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  sha256_process_bytes (salt, salt_len, &ctx);


  /* Compute alternate SHA256 sum with input KEY, SALT, and KEY.  The
     final result will be added to the first context.  */
  sha256_init_ctx (&alt_ctx);

  /* Add key.  */
  sha256_process_bytes (key, key_len, &alt_ctx);

  /* Add salt.  */
  sha256_process_bytes (salt, salt_len, &alt_ctx);

  /* Add key again.  */
  sha256_process_bytes (key, key_len, &alt_ctx);

  /* Now get result of this (32 bytes) and add it to the other
     context.  */
  sha256_finish_ctx (&alt_ctx, alt_result);

  /* Add for any character in the key one byte of the alternate sum.  */
  for (cnt = key_len; cnt > 32; cnt -= 32)
    sha256_process_bytes (alt_result, 32, &ctx);
  sha256_process_bytes (alt_result, cnt, &ctx);

  /* Take the binary representation of the length of the key and for every
     1 add the alternate sum, for every 0 the key.  */
  for (cnt = key_len; cnt > 0; cnt >>= 1)
    if ((cnt & 1) != 0)
      sha256_process_bytes (alt_result, 32, &ctx);
    else
      sha256_process_bytes (key, key_len, &ctx);

  /* Create intermediate result.  */
  sha256_finish_ctx (&ctx, alt_result);

  /* Start computation of P byte sequence.  */
  sha256_init_ctx (&alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < key_len; ++cnt)
    sha256_process_bytes (key, key_len, &alt_ctx);

  /* Finish the digest.  */
  sha256_finish_ctx (&alt_ctx, temp_result);

  /* Create byte sequence P.  */
  cp = p_bytes = alloca (key_len);
  for (cnt = key_len; cnt >= 32; cnt -= 32)
    cp = mempcpy (cp, temp_result, 32);
  memcpy (cp, temp_result, cnt);

  /* Start computation of S byte sequence.  */
  sha256_init_ctx (&alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt)
    sha256_process_bytes (salt, salt_len, &alt_ctx);

  /* Finish the digest.  */
  sha256_finish_ctx (&alt_ctx, temp_result);

  /* Create byte sequence S.  */
  cp = s_bytes = alloca (salt_len);
  for (cnt = salt_len; cnt >= 32; cnt -= 32)
    cp = mempcpy (cp, temp_result, 32);
  memcpy (cp, temp_result, cnt);

  /* Repeatedly run the collected hash value through SHA256 to burn
     CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt)
    {
      /* New context.  */
      sha256_init_ctx (&ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
	sha256_process_bytes (p_bytes, key_len, &ctx);
      else
	sha256_process_bytes (alt_result, 32, &ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
	sha256_process_bytes (s_bytes, salt_len, &ctx);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
	sha256_process_bytes (p_bytes, key_len, &ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
	sha256_process_bytes (alt_result, 32, &ctx);
      else
	sha256_process_bytes (p_bytes, key_len, &ctx);

      /* Create intermediate result.  */
      sha256_finish_ctx (&ctx, alt_result);
    }

  /* Now we can construct the result string.  It consists of three
     parts.  */
  cp = stpncpy (buffer, sha256_salt_prefix, MAX (0, buflen));
  buflen -= sizeof (sha256_salt_prefix) - 1;

  if (rounds_custom)
    {
      int n = snprintf (cp, MAX (0, buflen), "%s%zu$",
			sha256_rounds_prefix, rounds);
      cp += n;
      buflen -= n;
    }

  cp = stpncpy (cp, salt, MIN ((size_t) MAX (0, buflen), salt_len));
  buflen -= MIN ((size_t) MAX (0, buflen), salt_len);

  if (buflen > 0)
    {
      *cp++ = '$';
      --buflen;
    }

#define b64_from_24bit(B2, B1, B0, N)					      \
  do {									      \
    unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);			      \
    int n = (N);							      \
    while (n-- > 0 && buflen > 0)					      \
      {									      \
	*cp++ = b64t[w & 0x3f];						      \
	--buflen;							      \
	w >>= 6;							      \
      }									      \
  } while (0)

  b64_from_24bit (alt_result[0], alt_result[10], alt_result[20], 4);
  b64_from_24bit (alt_result[21], alt_result[1], alt_result[11], 4);
  b64_from_24bit (alt_result[12], alt_result[22], alt_result[2], 4);
  b64_from_24bit (alt_result[3], alt_result[13], alt_result[23], 4);
  b64_from_24bit (alt_result[24], alt_result[4], alt_result[14], 4);
  b64_from_24bit (alt_result[15], alt_result[25], alt_result[5], 4);
  b64_from_24bit (alt_result[6], alt_result[16], alt_result[26], 4);
  b64_from_24bit (alt_result[27], alt_result[7], alt_result[17], 4);
  b64_from_24bit (alt_result[18], alt_result[28], alt_result[8], 4);
  b64_from_24bit (alt_result[9], alt_result[19], alt_result[29], 4);
  b64_from_24bit (0, alt_result[31], alt_result[30], 3);
  if (buflen <= 0)
    {
      errno = ERANGE;
      buffer = NULL;
    }
  else
    *cp = '\0';		/* Terminate the string.  */

  /* Clear the buffer for the intermediate result so that people
     attaching to processes or reading core dumps cannot get any
     information.  We do it in this way to clear correct_words[]
     inside the SHA256 implementation as well.  */
  sha256_init_ctx (&ctx);
  sha256_finish_ctx (&ctx, alt_result);
  memset (temp_result, '\0', sizeof (temp_result));
  memset (p_bytes, '\0', key_len);
  memset (s_bytes, '\0', salt_len);
  memset (&ctx, '\0', sizeof (ctx));
  memset (&alt_ctx, '\0', sizeof (alt_ctx));
  if (copied_key != NULL)
    memset (copied_key, '\0', key_len);
  if (copied_salt != NULL)
    memset (copied_salt, '\0', salt_len);

  return buffer;
}


/* This entry point is equivalent to the `crypt' function in Unix
   libcs.  */
char *
sha256_crypt (const char *key, const char *salt)
{
  /* We don't want to have an arbitrary limit in the size of the
     password.  We can compute an upper bound for the size of the
     result in advance and so we can prepare the buffer we pass to
     `sha256_crypt_r'.  */
  static char *buffer;
  static int buflen;
  int needed = (sizeof (sha256_salt_prefix) - 1
		+ sizeof (sha256_rounds_prefix) + 9 + 1
		+ strlen (salt) + 1 + 43 + 1);

  if (buflen < needed)
    {
      char *new_buffer = (char *) realloc (buffer, needed);
      if (new_buffer == NULL)
	return NULL;

      buffer = new_buffer;
      buflen = needed;
    }

  return sha256_crypt_r (key, salt, buffer, buflen);
}


#ifdef TEST
static const struct
{
  const char *input;
  const char result[32];
} tests[] =
  {
    /* Test vectors from FIPS 180-2: appendix B.1.  */
    { "abc",
      "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
      "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad" },
    /* Test vectors from FIPS 180-2: appendix B.2.  */
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
      "\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1" },
    /* Test vectors from the NESSIE project.  */
    { "",
      "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
      "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55" },
    { "a",
      "\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc2\x31\xb3\x9a\x23\xdc\x4d"
      "\xa7\x86\xef\xf8\x14\x7c\x4e\x72\xb9\x80\x77\x85\xaf\xee\x48\xbb" },
    { "message digest",
      "\xf7\x84\x6f\x55\xcf\x23\xe1\x4e\xeb\xea\xb5\xb4\xe1\x55\x0c\xad"
      "\x5b\x50\x9e\x33\x48\xfb\xc4\xef\xa3\xa1\x41\x3d\x39\x3c\xb6\x50" },
    { "abcdefghijklmnopqrstuvwxyz",
      "\x71\xc4\x80\xdf\x93\xd6\xae\x2f\x1e\xfa\xd1\x44\x7c\x66\xc9\x52"
      "\x5e\x31\x62\x18\xcf\x51\xfc\x8d\x9e\xd8\x32\xf2\xda\xf1\x8b\x73" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
      "\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1" },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "\xdb\x4b\xfc\xbd\x4d\xa0\xcd\x85\xa6\x0c\x3c\x37\xd3\xfb\xd8\x80"
      "\x5c\x77\xf1\x5f\xc6\xb1\xfd\xfe\x61\x4e\xe0\xa7\xc8\xfd\xb4\xc0" },
    { "123456789012345678901234567890123456789012345678901234567890"
      "12345678901234567890",
      "\xf3\x71\xbc\x4a\x31\x1f\x2b\x00\x9e\xef\x95\x2d\xd8\x3c\xa8\x0e"
      "\x2b\x60\x02\x6c\x8e\x93\x55\x92\xd0\xf9\xc3\x08\x45\x3c\x81\x3e" }
  };
#define ntests (sizeof (tests) / sizeof (tests[0]))


static const struct
{
  const char *salt;
  const char *input;
  const char *expected;
} tests2[] =
{
  { "$5$saltstring", "Hello world!",
    "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" },
  { "$5$rounds=10000$saltstringsaltstring", "Hello world!",
    "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2."
    "opqey6IcA" },
  { "$5$rounds=5000$toolongsaltstring", "This is just a test",
    "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8"
    "mGRcvxa5" },
  { "$5$rounds=1400$anotherlongsaltstring",
    "a very much longer text to encrypt.  This one even stretches over more"
    "than one line.",
    "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12"
    "oP84Bnq1" },
  { "$5$rounds=77777$short",
    "we have a short salt string but not a short password",
    "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/" },
  { "$5$rounds=123456$asaltof16chars..", "a short string",
    "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/"
    "cZKmF/wJvD" },
  { "$5$rounds=10$roundstoolow", "the minimum number is still observed",
    "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL97"
    "2bIC" },
};
#define ntests2 (sizeof (tests2) / sizeof (tests2[0]))


int
main (void)
{
  struct sha256_ctx ctx;
  char sum[32];
  int result = 0;
  int cnt;

  for (cnt = 0; cnt < (int) ntests; ++cnt)
    {
      sha256_init_ctx (&ctx);
      sha256_process_bytes (tests[cnt].input, strlen (tests[cnt].input), &ctx);
      sha256_finish_ctx (&ctx, sum);
      if (memcmp (tests[cnt].result, sum, 32) != 0)
	{
	  printf ("test %d run %d failed\n", cnt, 1);
	  result = 1;
	}

      sha256_init_ctx (&ctx);
      for (int i = 0; tests[cnt].input[i] != '\0'; ++i)
	sha256_process_bytes (&tests[cnt].input[i], 1, &ctx);
      sha256_finish_ctx (&ctx, sum);
      if (memcmp (tests[cnt].result, sum, 32) != 0)
	{
	  printf ("test %d run %d failed\n", cnt, 2);
	  result = 1;
	}
    }

  /* Test vector from FIPS 180-2: appendix B.3.  */
  char buf[1000];
  memset (buf, 'a', sizeof (buf));
  sha256_init_ctx (&ctx);
  for (int i = 0; i < 1000; ++i)
    sha256_process_bytes (buf, sizeof (buf), &ctx);
  sha256_finish_ctx (&ctx, sum);
  static const char expected[32] =
    "\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67"
    "\xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0";
  if (memcmp (expected, sum, 32) != 0)
    {
      printf ("test %d failed\n", cnt);
      result = 1;
    }

  for (cnt = 0; cnt < ntests2; ++cnt)
    {
      char *cp = sha256_crypt (tests2[cnt].input, tests2[cnt].salt);

      if (strcmp (cp, tests2[cnt].expected) != 0)
	{
	  printf ("test %d: expected \"%s\", got \"%s\"\n",
		  cnt, tests2[cnt].expected, cp);
	  result = 1;
	}
    }

  if (result == 0)
    puts ("all tests OK");

  return result;
}
#endif
-----------------------------------------------------------------------------

-------- sha512crypt.c ------------------------------------------------------
/* SHA512-based Unix crypt implementation.
   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.  */

#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>


/* Structure to save state of computation between the single steps.  */
struct sha512_ctx
{
  uint64_t H[8];

  uint64_t total[2];
  uint64_t buflen;
  char buffer[256];	/* NB: always correctly aligned for uint64_t.  */
};


#if __BYTE_ORDER == __LITTLE_ENDIAN
# define SWAP(n) \
  (((n) << 56)					\
   | (((n) & 0xff00) << 40)			\
   | (((n) & 0xff0000) << 24)			\
   | (((n) & 0xff000000) << 8)			\
   | (((n) >> 8) & 0xff000000)			\
   | (((n) >> 24) & 0xff0000)			\
   | (((n) >> 40) & 0xff00)			\
   | ((n) >> 56))
#else
# define SWAP(n) (n)
#endif


/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (FIPS 180-2:5.1.2)  */
static const unsigned char fillbuf[128] = { 0x80, 0 /* , 0, 0, ...  */ };


/* Constants for SHA512 from FIPS 180-2:4.2.3.  */
static const uint64_t K[80] =
  {
    UINT64_C (0x428a2f98d728ae22), UINT64_C (0x7137449123ef65cd),
    UINT64_C (0xb5c0fbcfec4d3b2f), UINT64_C (0xe9b5dba58189dbbc),
    UINT64_C (0x3956c25bf348b538), UINT64_C (0x59f111f1b605d019),
    UINT64_C (0x923f82a4af194f9b), UINT64_C (0xab1c5ed5da6d8118),
    UINT64_C (0xd807aa98a3030242), UINT64_C (0x12835b0145706fbe),
    UINT64_C (0x243185be4ee4b28c), UINT64_C (0x550c7dc3d5ffb4e2),
    UINT64_C (0x72be5d74f27b896f), UINT64_C (0x80deb1fe3b1696b1),
    UINT64_C (0x9bdc06a725c71235), UINT64_C (0xc19bf174cf692694),
    UINT64_C (0xe49b69c19ef14ad2), UINT64_C (0xefbe4786384f25e3),
    UINT64_C (0x0fc19dc68b8cd5b5), UINT64_C (0x240ca1cc77ac9c65),
    UINT64_C (0x2de92c6f592b0275), UINT64_C (0x4a7484aa6ea6e483),
    UINT64_C (0x5cb0a9dcbd41fbd4), UINT64_C (0x76f988da831153b5),
    UINT64_C (0x983e5152ee66dfab), UINT64_C (0xa831c66d2db43210),
    UINT64_C (0xb00327c898fb213f), UINT64_C (0xbf597fc7beef0ee4),
    UINT64_C (0xc6e00bf33da88fc2), UINT64_C (0xd5a79147930aa725),
    UINT64_C (0x06ca6351e003826f), UINT64_C (0x142929670a0e6e70),
    UINT64_C (0x27b70a8546d22ffc), UINT64_C (0x2e1b21385c26c926),
    UINT64_C (0x4d2c6dfc5ac42aed), UINT64_C (0x53380d139d95b3df),
    UINT64_C (0x650a73548baf63de), UINT64_C (0x766a0abb3c77b2a8),
    UINT64_C (0x81c2c92e47edaee6), UINT64_C (0x92722c851482353b),
    UINT64_C (0xa2bfe8a14cf10364), UINT64_C (0xa81a664bbc423001),
    UINT64_C (0xc24b8b70d0f89791), UINT64_C (0xc76c51a30654be30),
    UINT64_C (0xd192e819d6ef5218), UINT64_C (0xd69906245565a910),
    UINT64_C (0xf40e35855771202a), UINT64_C (0x106aa07032bbd1b8),
    UINT64_C (0x19a4c116b8d2d0c8), UINT64_C (0x1e376c085141ab53),
    UINT64_C (0x2748774cdf8eeb99), UINT64_C (0x34b0bcb5e19b48a8),
    UINT64_C (0x391c0cb3c5c95a63), UINT64_C (0x4ed8aa4ae3418acb),
    UINT64_C (0x5b9cca4f7763e373), UINT64_C (0x682e6ff3d6b2b8a3),
    UINT64_C (0x748f82ee5defb2fc), UINT64_C (0x78a5636f43172f60),
    UINT64_C (0x84c87814a1f0ab72), UINT64_C (0x8cc702081a6439ec),
    UINT64_C (0x90befffa23631e28), UINT64_C (0xa4506cebde82bde9),
    UINT64_C (0xbef9a3f7b2c67915), UINT64_C (0xc67178f2e372532b),
    UINT64_C (0xca273eceea26619c), UINT64_C (0xd186b8c721c0c207),
    UINT64_C (0xeada7dd6cde0eb1e), UINT64_C (0xf57d4f7fee6ed178),
    UINT64_C (0x06f067aa72176fba), UINT64_C (0x0a637dc5a2c898a6),
    UINT64_C (0x113f9804bef90dae), UINT64_C (0x1b710b35131c471b),
    UINT64_C (0x28db77f523047d84), UINT64_C (0x32caab7b40c72493),
    UINT64_C (0x3c9ebe0a15c9bebc), UINT64_C (0x431d67c49c100d4c),
    UINT64_C (0x4cc5d4becb3e42b6), UINT64_C (0x597f299cfc657e2a),
    UINT64_C (0x5fcb6fab3ad6faec), UINT64_C (0x6c44198c4a475817)
  };


/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 128 == 0.  */
static void
sha512_process_block (const void *buffer, size_t len, struct sha512_ctx *ctx)
{
  const uint64_t *words = buffer;
  size_t nwords = len / sizeof (uint64_t);
  uint64_t a = ctx->H[0];
  uint64_t b = ctx->H[1];
  uint64_t c = ctx->H[2];
  uint64_t d = ctx->H[3];
  uint64_t e = ctx->H[4];
  uint64_t f = ctx->H[5];
  uint64_t g = ctx->H[6];
  uint64_t h = ctx->H[7];

  /* First increment the byte count.  FIPS 180-2 specifies the possible
     length of the file up to 2^128 bits.  Here we only compute the
     number of bytes.  Do a double word increment.  */
  ctx->total[0] += len;
  if (ctx->total[0] < len)
    ++ctx->total[1];

  /* Process all bytes in the buffer with 128 bytes in each round of
     the loop.  */
  while (nwords > 0)
    {
      uint64_t W[80];
      uint64_t a_save = a;
      uint64_t b_save = b;
      uint64_t c_save = c;
      uint64_t d_save = d;
      uint64_t e_save = e;
      uint64_t f_save = f;
      uint64_t g_save = g;
      uint64_t h_save = h;

      /* Operators defined in FIPS 180-2:4.1.2.  */
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (CYCLIC (x, 28) ^ CYCLIC (x, 34) ^ CYCLIC (x, 39))
#define S1(x) (CYCLIC (x, 14) ^ CYCLIC (x, 18) ^ CYCLIC (x, 41))
#define R0(x) (CYCLIC (x, 1) ^ CYCLIC (x, 8) ^ (x >> 7))
#define R1(x) (CYCLIC (x, 19) ^ CYCLIC (x, 61) ^ (x >> 6))

      /* It is unfortunate that C does not provide an operator for
	 cyclic rotation.  Hope the C compiler is smart enough.  */
#define CYCLIC(w, s) ((w >> s) | (w << (64 - s)))

      /* Compute the message schedule according to FIPS 180-2:6.3.2 step 2.  */
      for (unsigned int t = 0; t < 16; ++t)
	{
	  W[t] = SWAP (*words);
	  ++words;
	}
      for (unsigned int t = 16; t < 80; ++t)
	W[t] = R1 (W[t - 2]) + W[t - 7] + R0 (W[t - 15]) + W[t - 16];

      /* The actual computation according to FIPS 180-2:6.3.2 step 3.  */
      for (unsigned int t = 0; t < 80; ++t)
	{
	  uint64_t T1 = h + S1 (e) + Ch (e, f, g) + K[t] + W[t];
	  uint64_t T2 = S0 (a) + Maj (a, b, c);
	  h = g;
	  g = f;
	  f = e;
	  e = d + T1;
	  d = c;
	  c = b;
	  b = a;
	  a = T1 + T2;
	}

      /* Add the starting values of the context according to FIPS 180-2:6.3.2
	 step 4.  */
      a += a_save;
      b += b_save;
      c += c_save;
      d += d_save;
      e += e_save;
      f += f_save;
      g += g_save;
      h += h_save;

      /* Prepare for the next round.  */
      nwords -= 16;
    }

  /* Put checksum in context given as argument.  */
  ctx->H[0] = a;
  ctx->H[1] = b;
  ctx->H[2] = c;
  ctx->H[3] = d;
  ctx->H[4] = e;
  ctx->H[5] = f;
  ctx->H[6] = g;
  ctx->H[7] = h;
}


/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.3)  */
static void
sha512_init_ctx (struct sha512_ctx *ctx)
{
  ctx->H[0] = UINT64_C (0x6a09e667f3bcc908);
  ctx->H[1] = UINT64_C (0xbb67ae8584caa73b);
  ctx->H[2] = UINT64_C (0x3c6ef372fe94f82b);
  ctx->H[3] = UINT64_C (0xa54ff53a5f1d36f1);
  ctx->H[4] = UINT64_C (0x510e527fade682d1);
  ctx->H[5] = UINT64_C (0x9b05688c2b3e6c1f);
  ctx->H[6] = UINT64_C (0x1f83d9abfb41bd6b);
  ctx->H[7] = UINT64_C (0x5be0cd19137e2179);

  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}


/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
static void *
sha512_finish_ctx (struct sha512_ctx *ctx, void *resbuf)
{
  /* Take yet unprocessed bytes into account.  */
  uint64_t bytes = ctx->buflen;
  size_t pad;

  /* Now count remaining bytes.  */
  ctx->total[0] += bytes;
  if (ctx->total[0] < bytes)
    ++ctx->total[1];

  pad = bytes >= 112 ? 128 + 112 - bytes : 112 - bytes;
  memcpy (&ctx->buffer[bytes], fillbuf, pad);

  /* Put the 128-bit file length in *bits* at the end of the buffer.  */
  *(uint64_t *) &ctx->buffer[bytes + pad + 8] = SWAP (ctx->total[0] << 3);
  *(uint64_t *) &ctx->buffer[bytes + pad] = SWAP ((ctx->total[1] << 3) |
						  (ctx->total[0] >> 61));

  /* Process last bytes.  */
  sha512_process_block (ctx->buffer, bytes + pad + 16, ctx);

  /* Put result from CTX in first 64 bytes following RESBUF.  */
  for (unsigned int i = 0; i < 8; ++i)
    ((uint64_t *) resbuf)[i] = SWAP (ctx->H[i]);

  return resbuf;
}


static void
sha512_process_bytes (const void *buffer, size_t len, struct sha512_ctx *ctx)
{
  /* When we already have some bits in our internal buffer concatenate
     both inputs first.  */
  if (ctx->buflen != 0)
    {
      size_t left_over = ctx->buflen;
      size_t add = 256 - left_over > len ? len : 256 - left_over;

      memcpy (&ctx->buffer[left_over], buffer, add);
      ctx->buflen += add;

      if (ctx->buflen > 128)
	{
	  sha512_process_block (ctx->buffer, ctx->buflen & ~127, ctx);

	  ctx->buflen &= 127;
	  /* The regions in the following copy operation cannot overlap.  */
	  memcpy (ctx->buffer, &ctx->buffer[(left_over + add) & ~127],
		  ctx->buflen);
	}

      buffer = (const char *) buffer + add;
      len -= add;
    }

  /* Process available complete blocks.  */
  if (len >= 128)
    {
#if !_STRING_ARCH_unaligned
/* To check alignment gcc has an appropriate operator.  Other
   compilers don't.  */
# if __GNUC__ >= 2
#  define UNALIGNED_P(p) (((uintptr_t) p) % __alignof__ (uint64_t) != 0)
# else
#  define UNALIGNED_P(p) (((uintptr_t) p) % sizeof (uint64_t) != 0)
# endif
      if (UNALIGNED_P (buffer))
	while (len > 128)
	  {
	    sha512_process_block (memcpy (ctx->buffer, buffer, 128), 128,
				    ctx);
	    buffer = (const char *) buffer + 128;
	    len -= 128;
	  }
      else
#endif
	{
	  sha512_process_block (buffer, len & ~127, ctx);
	  buffer = (const char *) buffer + (len & ~127);
	  len &= 127;
	}
    }

  /* Move remaining bytes into internal buffer.  */
  if (len > 0)
    {
      size_t left_over = ctx->buflen;

      memcpy (&ctx->buffer[left_over], buffer, len);
      left_over += len;
      if (left_over >= 128)
	{
	  sha512_process_block (ctx->buffer, 128, ctx);
	  left_over -= 128;
	  memcpy (ctx->buffer, &ctx->buffer[128], left_over);
	}
      ctx->buflen = left_over;
    }
}


/* Define our magic string to mark salt for SHA512 "encryption"
   replacement.  */
static const char sha512_salt_prefix[] = "$6$";

/* Prefix for optional rounds specification.  */
static const char sha512_rounds_prefix[] = "rounds=";

/* Maximum salt string length.  */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999

/* Table with characters for base64 transformation.  */
static const char b64t[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";


static char *
sha512_crypt_r (const char *key, const char *salt, char *buffer, int buflen)
{
  unsigned char alt_result[64]
    __attribute__ ((__aligned__ (__alignof__ (uint64_t))));
  unsigned char temp_result[64]
    __attribute__ ((__aligned__ (__alignof__ (uint64_t))));
  struct sha512_ctx ctx;
  struct sha512_ctx alt_ctx;
  size_t salt_len;
  size_t key_len;
  size_t cnt;
  char *cp;
  char *copied_key = NULL;
  char *copied_salt = NULL;
  char *p_bytes;
  char *s_bytes;
  /* Default number of rounds.  */
  size_t rounds = ROUNDS_DEFAULT;
  bool rounds_custom = false;

  /* Find beginning of salt string.  The prefix should normally always
     be present.  Just in case it is not.  */
  if (strncmp (sha512_salt_prefix, salt, sizeof (sha512_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (sha512_salt_prefix) - 1;

  if (strncmp (salt, sha512_rounds_prefix, sizeof (sha512_rounds_prefix) - 1)
      == 0)
    {
      const char *num = salt + sizeof (sha512_rounds_prefix) - 1;
      char *endp;
      unsigned long int srounds = strtoul (num, &endp, 10);
      if (*endp == '$')
	{
	  salt = endp + 1;
	  rounds = MAX (ROUNDS_MIN, MIN (srounds, ROUNDS_MAX));
	  rounds_custom = true;
	}
    }

  salt_len = MIN (strcspn (salt, "$"), SALT_LEN_MAX);
  key_len = strlen (key);

  if ((key - (char *) 0) % __alignof__ (uint64_t) != 0)
    {
      char *tmp = (char *) alloca (key_len + __alignof__ (uint64_t));
      key = copied_key =
	memcpy (tmp + __alignof__ (uint64_t)
		- (tmp - (char *) 0) % __alignof__ (uint64_t),
		key, key_len);
    }

  if ((salt - (char *) 0) % __alignof__ (uint64_t) != 0)
    {
      char *tmp = (char *) alloca (salt_len + __alignof__ (uint64_t));
      salt = copied_salt =
	memcpy (tmp + __alignof__ (uint64_t)
		- (tmp - (char *) 0) % __alignof__ (uint64_t),
		salt, salt_len);
    }

  /* Prepare for the real work.  */
  sha512_init_ctx (&ctx);

  /* Add the key string.  */
  sha512_process_bytes (key, key_len, &ctx);

  /* The last part is the salt string.  This must be at most 16
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  sha512_process_bytes (salt, salt_len, &ctx);


  /* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  The
     final result will be added to the first context.  */
  sha512_init_ctx (&alt_ctx);

  /* Add key.  */
  sha512_process_bytes (key, key_len, &alt_ctx);

  /* Add salt.  */
  sha512_process_bytes (salt, salt_len, &alt_ctx);

  /* Add key again.  */
  sha512_process_bytes (key, key_len, &alt_ctx);

  /* Now get result of this (64 bytes) and add it to the other
     context.  */
  sha512_finish_ctx (&alt_ctx, alt_result);

  /* Add for any character in the key one byte of the alternate sum.  */
  for (cnt = key_len; cnt > 64; cnt -= 64)
    sha512_process_bytes (alt_result, 64, &ctx);
  sha512_process_bytes (alt_result, cnt, &ctx);

  /* Take the binary representation of the length of the key and for every
     1 add the alternate sum, for every 0 the key.  */
  for (cnt = key_len; cnt > 0; cnt >>= 1)
    if ((cnt & 1) != 0)
      sha512_process_bytes (alt_result, 64, &ctx);
    else
      sha512_process_bytes (key, key_len, &ctx);

  /* Create intermediate result.  */
  sha512_finish_ctx (&ctx, alt_result);

  /* Start computation of P byte sequence.  */
  sha512_init_ctx (&alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < key_len; ++cnt)
    sha512_process_bytes (key, key_len, &alt_ctx);

  /* Finish the digest.  */
  sha512_finish_ctx (&alt_ctx, temp_result);

  /* Create byte sequence P.  */
  cp = p_bytes = alloca (key_len);
  for (cnt = key_len; cnt >= 64; cnt -= 64)
    cp = mempcpy (cp, temp_result, 64);
  memcpy (cp, temp_result, cnt);

  /* Start computation of S byte sequence.  */
  sha512_init_ctx (&alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt)
    sha512_process_bytes (salt, salt_len, &alt_ctx);

  /* Finish the digest.  */
  sha512_finish_ctx (&alt_ctx, temp_result);

  /* Create byte sequence S.  */
  cp = s_bytes = alloca (salt_len);
  for (cnt = salt_len; cnt >= 64; cnt -= 64)
    cp = mempcpy (cp, temp_result, 64);
  memcpy (cp, temp_result, cnt);

  /* Repeatedly run the collected hash value through SHA512 to burn
     CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt)
    {
      /* New context.  */
      sha512_init_ctx (&ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
	sha512_process_bytes (p_bytes, key_len, &ctx);
      else
	sha512_process_bytes (alt_result, 64, &ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
	sha512_process_bytes (s_bytes, salt_len, &ctx);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
	sha512_process_bytes (p_bytes, key_len, &ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
	sha512_process_bytes (alt_result, 64, &ctx);
      else
	sha512_process_bytes (p_bytes, key_len, &ctx);

      /* Create intermediate result.  */
      sha512_finish_ctx (&ctx, alt_result);
    }

  /* Now we can construct the result string.  It consists of three
     parts.  */
  cp = __stpncpy (buffer, sha512_salt_prefix, MAX (0, buflen));
  buflen -= sizeof (sha512_salt_prefix) - 1;

  if (rounds_custom)
    {
      int n = snprintf (cp, MAX (0, buflen), "%s%zu$",
			sha512_rounds_prefix, rounds);
      cp += n;
      buflen -= n;
    }

  cp = __stpncpy (cp, salt, MIN ((size_t) MAX (0, buflen), salt_len));
  buflen -= MIN ((size_t) MAX (0, buflen), salt_len);

  if (buflen > 0)
    {
      *cp++ = '$';
      --buflen;
    }

#define b64_from_24bit(B2, B1, B0, N)					      \
  do {									      \
    unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);			      \
    int n = (N);							      \
    while (n-- > 0 && buflen > 0)					      \
      {									      \
	*cp++ = b64t[w & 0x3f];						      \
	--buflen;							      \
	w >>= 6;							      \
      }									      \
  } while (0)

  b64_from_24bit (alt_result[0], alt_result[21], alt_result[42], 4);
  b64_from_24bit (alt_result[22], alt_result[43], alt_result[1], 4);
  b64_from_24bit (alt_result[44], alt_result[2], alt_result[23], 4);
  b64_from_24bit (alt_result[3], alt_result[24], alt_result[45], 4);
  b64_from_24bit (alt_result[25], alt_result[46], alt_result[4], 4);
  b64_from_24bit (alt_result[47], alt_result[5], alt_result[26], 4);
  b64_from_24bit (alt_result[6], alt_result[27], alt_result[48], 4);
  b64_from_24bit (alt_result[28], alt_result[49], alt_result[7], 4);
  b64_from_24bit (alt_result[50], alt_result[8], alt_result[29], 4);
  b64_from_24bit (alt_result[9], alt_result[30], alt_result[51], 4);
  b64_from_24bit (alt_result[31], alt_result[52], alt_result[10], 4);
  b64_from_24bit (alt_result[53], alt_result[11], alt_result[32], 4);
  b64_from_24bit (alt_result[12], alt_result[33], alt_result[54], 4);
  b64_from_24bit (alt_result[34], alt_result[55], alt_result[13], 4);
  b64_from_24bit (alt_result[56], alt_result[14], alt_result[35], 4);
  b64_from_24bit (alt_result[15], alt_result[36], alt_result[57], 4);
  b64_from_24bit (alt_result[37], alt_result[58], alt_result[16], 4);
  b64_from_24bit (alt_result[59], alt_result[17], alt_result[38], 4);
  b64_from_24bit (alt_result[18], alt_result[39], alt_result[60], 4);
  b64_from_24bit (alt_result[40], alt_result[61], alt_result[19], 4);
  b64_from_24bit (alt_result[62], alt_result[20], alt_result[41], 4);
  b64_from_24bit (0, 0, alt_result[63], 2);

  if (buflen <= 0)
    {
      errno = ERANGE;
      buffer = NULL;
    }
  else
    *cp = '\0';		/* Terminate the string.  */

  /* Clear the buffer for the intermediate result so that people
     attaching to processes or reading core dumps cannot get any
     information.  We do it in this way to clear correct_words[]
     inside the SHA512 implementation as well.  */
  sha512_init_ctx (&ctx);
  sha512_finish_ctx (&ctx, alt_result);
  memset (temp_result, '\0', sizeof (temp_result));
  memset (p_bytes, '\0', key_len);
  memset (s_bytes, '\0', salt_len);
  memset (&ctx, '\0', sizeof (ctx));
  memset (&alt_ctx, '\0', sizeof (alt_ctx));
  if (copied_key != NULL)
    memset (copied_key, '\0', key_len);
  if (copied_salt != NULL)
    memset (copied_salt, '\0', salt_len);

  return buffer;
}


/* This entry point is equivalent to the `crypt' function in Unix
   libcs.  */
char *
sha512_crypt (const char *key, const char *salt)
{
  /* We don't want to have an arbitrary limit in the size of the
     password.  We can compute an upper bound for the size of the
     result in advance and so we can prepare the buffer we pass to
     `sha512_crypt_r'.  */
  static char *buffer;
  static int buflen;
  int needed = (sizeof (sha512_salt_prefix) - 1
		+ sizeof (sha512_rounds_prefix) + 9 + 1
		+ strlen (salt) + 1 + 86 + 1);

  if (buflen < needed)
    {
      char *new_buffer = (char *) realloc (buffer, needed);
      if (new_buffer == NULL)
	return NULL;

      buffer = new_buffer;
      buflen = needed;
    }

  return sha512_crypt_r (key, salt, buffer, buflen);
}


#ifdef TEST
static const struct
{
  const char *input;
  const char result[64];
} tests[] =
  {
    /* Test vectors from FIPS 180-2: appendix C.1.  */
    { "abc",
      "\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31"
      "\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a"
      "\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd"
      "\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f" },
    /* Test vectors from FIPS 180-2: appendix C.2.  */
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
      "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f"
      "\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18"
      "\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a"
      "\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09" },
    /* Test vectors from the NESSIE project.  */
    { "",
      "\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07"
      "\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce"
      "\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f"
      "\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e" },
    { "a",
      "\x1f\x40\xfc\x92\xda\x24\x16\x94\x75\x09\x79\xee\x6c\xf5\x82\xf2"
      "\xd5\xd7\xd2\x8e\x18\x33\x5d\xe0\x5a\xbc\x54\xd0\x56\x0e\x0f\x53"
      "\x02\x86\x0c\x65\x2b\xf0\x8d\x56\x02\x52\xaa\x5e\x74\x21\x05\x46"
      "\xf3\x69\xfb\xbb\xce\x8c\x12\xcf\xc7\x95\x7b\x26\x52\xfe\x9a\x75" },
    { "message digest",
      "\x10\x7d\xbf\x38\x9d\x9e\x9f\x71\xa3\xa9\x5f\x6c\x05\x5b\x92\x51"
      "\xbc\x52\x68\xc2\xbe\x16\xd6\xc1\x34\x92\xea\x45\xb0\x19\x9f\x33"
      "\x09\xe1\x64\x55\xab\x1e\x96\x11\x8e\x8a\x90\x5d\x55\x97\xb7\x20"
      "\x38\xdd\xb3\x72\xa8\x98\x26\x04\x6d\xe6\x66\x87\xbb\x42\x0e\x7c" },
    { "abcdefghijklmnopqrstuvwxyz",
      "\x4d\xbf\xf8\x6c\xc2\xca\x1b\xae\x1e\x16\x46\x8a\x05\xcb\x98\x81"
      "\xc9\x7f\x17\x53\xbc\xe3\x61\x90\x34\x89\x8f\xaa\x1a\xab\xe4\x29"
      "\x95\x5a\x1b\xf8\xec\x48\x3d\x74\x21\xfe\x3c\x16\x46\x61\x3a\x59"
      "\xed\x54\x41\xfb\x0f\x32\x13\x89\xf7\x7f\x48\xa8\x79\xc7\xb1\xf1" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "\x20\x4a\x8f\xc6\xdd\xa8\x2f\x0a\x0c\xed\x7b\xeb\x8e\x08\xa4\x16"
      "\x57\xc1\x6e\xf4\x68\xb2\x28\xa8\x27\x9b\xe3\x31\xa7\x03\xc3\x35"
      "\x96\xfd\x15\xc1\x3b\x1b\x07\xf9\xaa\x1d\x3b\xea\x57\x78\x9c\xa0"
      "\x31\xad\x85\xc7\xa7\x1d\xd7\x03\x54\xec\x63\x12\x38\xca\x34\x45" },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "\x1e\x07\xbe\x23\xc2\x6a\x86\xea\x37\xea\x81\x0c\x8e\xc7\x80\x93"
      "\x52\x51\x5a\x97\x0e\x92\x53\xc2\x6f\x53\x6c\xfc\x7a\x99\x96\xc4"
      "\x5c\x83\x70\x58\x3e\x0a\x78\xfa\x4a\x90\x04\x1d\x71\xa4\xce\xab"
      "\x74\x23\xf1\x9c\x71\xb9\xd5\xa3\xe0\x12\x49\xf0\xbe\xbd\x58\x94" },
    { "123456789012345678901234567890123456789012345678901234567890"
      "12345678901234567890",
      "\x72\xec\x1e\xf1\x12\x4a\x45\xb0\x47\xe8\xb7\xc7\x5a\x93\x21\x95"
      "\x13\x5b\xb6\x1d\xe2\x4e\xc0\xd1\x91\x40\x42\x24\x6e\x0a\xec\x3a"
      "\x23\x54\xe0\x93\xd7\x6f\x30\x48\xb4\x56\x76\x43\x46\x90\x0c\xb1"
      "\x30\xd2\xa4\xfd\x5d\xd1\x6a\xbb\x5e\x30\xbc\xb8\x50\xde\xe8\x43" }
  };
#define ntests (sizeof (tests) / sizeof (tests[0]))


static const struct
{
  const char *salt;
  const char *input;
  const char *expected;
} tests2[] =
{
  { "$6$saltstring", "Hello world!",
    "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
    "esI68u4OTLiBFdcbYEdFCoEOfaS35inz1" },
  { "$6$rounds=10000$saltstringsaltstring", "Hello world!",
    "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb"
    "HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v." },
  { "$6$rounds=5000$toolongsaltstring", "This is just a test",
    "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQ"
    "zQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0" },
  { "$6$rounds=1400$anotherlongsaltstring",
    "a very much longer text to encrypt.  This one even stretches over more"
    "than one line.",
    "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP"
    "vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1" },
  { "$6$rounds=77777$short",
    "we have a short salt string but not a short password",
    "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g"
    "ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0" },
  { "$6$rounds=123456$asaltof16chars..", "a short string",
    "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
    "elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1" },
  { "$6$rounds=10$roundstoolow", "the minimum number is still observed",
    "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1x"
    "hLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX." },
};
#define ntests2 (sizeof (tests2) / sizeof (tests2[0]))


int
main (void)
{
  struct sha512_ctx ctx;
  char sum[64];
  int result = 0;
  int cnt;

  for (cnt = 0; cnt < (int) ntests; ++cnt)
    {
      sha512_init_ctx (&ctx);
      sha512_process_bytes (tests[cnt].input, strlen (tests[cnt].input), &ctx);
      sha512_finish_ctx (&ctx, sum);
      if (memcmp (tests[cnt].result, sum, 64) != 0)
	{
	  printf ("test %d run %d failed\n", cnt, 1);
	  result = 1;
	}

      sha512_init_ctx (&ctx);
      for (int i = 0; tests[cnt].input[i] != '\0'; ++i)
	sha512_process_bytes (&tests[cnt].input[i], 1, &ctx);
      sha512_finish_ctx (&ctx, sum);
      if (memcmp (tests[cnt].result, sum, 64) != 0)
	{
	  printf ("test %d run %d failed\n", cnt, 2);
	  result = 1;
	}
    }

  /* Test vector from FIPS 180-2: appendix C.3.  */
  char buf[1000];
  memset (buf, 'a', sizeof (buf));
  sha512_init_ctx (&ctx);
  for (int i = 0; i < 1000; ++i)
    sha512_process_bytes (buf, sizeof (buf), &ctx);
  sha512_finish_ctx (&ctx, sum);
  static const char expected[64] =
    "\xe7\x18\x48\x3d\x0c\xe7\x69\x64\x4e\x2e\x42\xc7\xbc\x15\xb4\x63"
    "\x8e\x1f\x98\xb1\x3b\x20\x44\x28\x56\x32\xa8\x03\xaf\xa9\x73\xeb"
    "\xde\x0f\xf2\x44\x87\x7e\xa6\x0a\x4c\xb0\x43\x2c\xe5\x77\xc3\x1b"
    "\xeb\x00\x9c\x5c\x2c\x49\xaa\x2e\x4e\xad\xb2\x17\xad\x8c\xc0\x9b";
  if (memcmp (expected, sum, 64) != 0)
    {
      printf ("test %d failed\n", cnt);
      result = 1;
    }

  for (cnt = 0; cnt < ntests2; ++cnt)
    {
      char *cp = sha512_crypt (tests2[cnt].input, tests2[cnt].salt);

      if (strcmp (cp, tests2[cnt].expected) != 0)
	{
	  printf ("test %d: expected \"%s\", got \"%s\"\n",
	   	  cnt, tests2[cnt].expected, cp);
	  result = 1;
	}
    }

  if (result == 0)
    puts ("all tests OK");

  return result;
}
#endif
-----------------------------------------------------------------------------
