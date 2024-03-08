/*
Copyright (c) 2003-2022, Troy D. Hanson  https://troydhanson.github.io/uthash/
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* This header provides the HASH_FUNCTION and the HASH_CMP overrides for a case
 * insensitive uthash with key type of string. */

#undef HASH_FUNCTION
#define HASH_FUNCTION(keyptr,keylen,hashv) HASH_JEN_LOWERCASE(keyptr, keylen, hashv)

/* This is a modified version of HASH_JEN provided by uthash.
 * It is the same algorithm except that every char is turned to lower case. */
#define HASH_JEN_LOWERCASE(key,keylen,hashv) \
do {                                                                             \
  unsigned _hj_i,_hj_j,_hj_k;                                                    \
  unsigned const char *_hj_key=(unsigned const char*)(key);                      \
  hashv = 0xfeedbeefu;                                                           \
  _hj_i = _hj_j = 0x9e3779b9u;                                                   \
  _hj_k = (unsigned)(keylen);                                                    \
  while (_hj_k >= 12U) {                                                         \
    _hj_i +=    (tolower(_hj_key[0]) + ( (unsigned)tolower(_hj_key[1]) << 8 )                      \
	+ ( (unsigned)tolower(_hj_key[2]) << 16 )                                         \
	+ ( (unsigned)tolower(_hj_key[3]) << 24 ) );                                      \
    _hj_j +=    (tolower(_hj_key[4]) + ( (unsigned)tolower(_hj_key[5]) << 8 )                      \
	+ ( (unsigned)tolower(_hj_key[6]) << 16 )                                         \
	+ ( (unsigned)tolower(_hj_key[7]) << 24 ) );                                      \
    hashv += (tolower(_hj_key[8]) + ( (unsigned)tolower(_hj_key[9]) << 8 )                         \
	+ ( (unsigned)tolower(_hj_key[10]) << 16 )                                        \
	+ ( (unsigned)tolower(_hj_key[11]) << 24 ) );                                     \
     HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                          \
     _hj_key += 12;                                                              \
     _hj_k -= 12U;                                                               \
  }                                                                              \
  hashv += (unsigned)(keylen);                                                   \
  switch ( _hj_k ) {                                                             \
    case 11: hashv += ( (unsigned)tolower(_hj_key[10]) << 24 ); /* FALLTHROUGH */         \
    case 10: hashv += ( (unsigned)tolower(_hj_key[9]) << 16 );  /* FALLTHROUGH */         \
    case 9:  hashv += ( (unsigned)tolower(_hj_key[8]) << 8 );   /* FALLTHROUGH */         \
    case 8:  _hj_j += ( (unsigned)tolower(_hj_key[7]) << 24 );  /* FALLTHROUGH */         \
    case 7:  _hj_j += ( (unsigned)tolower(_hj_key[6]) << 16 );  /* FALLTHROUGH */         \
    case 6:  _hj_j += ( (unsigned)tolower(_hj_key[5]) << 8 );   /* FALLTHROUGH */         \
    case 5:  _hj_j += tolower(_hj_key[4]);                      /* FALLTHROUGH */         \
    case 4:  _hj_i += ( (unsigned)tolower(_hj_key[3]) << 24 );  /* FALLTHROUGH */         \
    case 3:  _hj_i += ( (unsigned)tolower(_hj_key[2]) << 16 );  /* FALLTHROUGH */         \
    case 2:  _hj_i += ( (unsigned)tolower(_hj_key[1]) << 8 );   /* FALLTHROUGH */         \
    case 1:  _hj_i += tolower(_hj_key[0]);                      /* FALLTHROUGH */         \
    default: ;                                                                   \
  }                                                                              \
  HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                             \
} while (0)

#undef HASH_KEYCMP
#define HASH_KEYCMP(a,b,len) (strcasecmp(a,b))
