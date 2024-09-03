#include "openssl/rand.h"
#include "proxysql.h"
#include "cpp.h"

#ifdef DEBUG
void __dump_pkt(const char *func, unsigned char *_ptr, unsigned int len) {

	if (GloVars.global.gdbg==0) return;
	if (GloVars.global.gdbg_lvl[PROXY_DEBUG_MYSQL_PROTOCOL].verbosity < 8 ) return;
	unsigned int i;
	fprintf(stderr,"DUMP %d bytes FROM %s\n", len, func);
	for(i = 0; i < len; i++) {
		if(isprint(_ptr[i])) fprintf(stderr,"%c", _ptr[i]); else fprintf(stderr,".");
		if (i>0 && (i%16==15 || i==len-1)) {
			unsigned int j;
			if (i%16!=15) {
				j=15-i%16;
				while (j--) fprintf(stderr," ");
			}
			fprintf(stderr," --- ");
			for (j=(i==len-1 ? ((int)(i/16))*16 : i-15 ) ; j<=i; j++) {
				fprintf(stderr,"%02x ", _ptr[j]);
			}
			fprintf(stderr,"\n");
		}
   }
	fprintf(stderr,"\n\n");
	

}
#endif

char *sha1_pass_hex(char *sha1_pass) {
	if (sha1_pass==NULL) return NULL;
	char *buff=(char *)malloc(SHA_DIGEST_LENGTH*2+2);
	buff[0]='*';
	buff[SHA_DIGEST_LENGTH*2+1]='\0';
	int i;
	uint8_t a = 0;
	for (i=0;i<SHA_DIGEST_LENGTH;i++) {
		memcpy(&a,sha1_pass+i,1);
		sprintf(buff+1+2*i, "%02x", a);
	}
	return buff;
}


double proxy_my_rnd(struct rand_struct *rand_st) {
	rand_st->seed1= (rand_st->seed1*3+rand_st->seed2) % rand_st->max_value;
	rand_st->seed2= (rand_st->seed1+rand_st->seed2+33) % rand_st->max_value;
	return (((double) rand_st->seed1) / rand_st->max_value_dbl);
}

void proxy_create_random_string(char *_to, uint length, struct rand_struct *rand_st) {
	unsigned char * to = (unsigned char *)_to;
	int rc = 0;
	uint i;
	rc = RAND_bytes((unsigned char *)to,length);
#ifdef DEBUG
	if (rc==1) {
		// For code coverage (to test the following code and other function)
		// in DEBUG mode we pretend that RAND_bytes() fails 1% of the time
		if(rand()%100==0) {
			rc=0;
		}
	}
#endif // DEBUG
	if (rc!=1) {
		for (i=0; i<length ; i++) {
			*to= (proxy_my_rnd(rand_st) * 94 + 33);
			to++;
		}
	} else {
		for (i=0; i<length ; i++) {
			if (*to > 127) {
				*to -= 128;
			}
			if (*to == 0) {
				*to = 'a';
			}
			to++;
		}
	}
	*to= '\0';
}

int write_encoded_length(unsigned char *p, uint64_t val, uint8_t len, char prefix) {
	if (len==1) {
		*p=(char)val;
		return 1;
	}
	*p=prefix;
	p++;
	memcpy(p,&val,len-1);
	return len;
}

int write_encoded_length_and_string(unsigned char *p, uint64_t val, uint8_t len, char prefix, char *string) {
	int l=write_encoded_length(p,val,len,prefix);
	if (val) {
		memcpy(p+l,string,val);
	}
	return l+val;
}

void proxy_compute_sha1_hash_multi(uint8_t *digest, const char *buf1, int len1, const char *buf2, int len2) {
  PROXY_TRACE();
	const EVP_MD *evp_digest = EVP_get_digestbyname("sha1");
	assert(evp_digest != NULL);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_MD_CTX_init(ctx);
	EVP_DigestInit_ex(ctx, evp_digest, NULL);
	EVP_DigestUpdate(ctx, buf1, len1);
	EVP_DigestUpdate(ctx, buf2, len2);
	unsigned int olen = 0;
	EVP_DigestFinal(ctx, digest, &olen);
	EVP_MD_CTX_free(ctx);
}

void proxy_compute_sha1_hash(uint8_t *digest, const char *buf, int len) {
  PROXY_TRACE();
	const EVP_MD *evp_digest = EVP_get_digestbyname("sha1");
	assert(evp_digest != NULL);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_MD_CTX_init(ctx);
	EVP_DigestInit_ex(ctx, evp_digest, NULL);
	EVP_DigestUpdate(ctx, buf, len);
	unsigned int olen = 0;
	EVP_DigestFinal(ctx, digest, &olen);
	EVP_MD_CTX_free(ctx);
}

void proxy_compute_two_stage_sha1_hash(const char *password, size_t pass_len, uint8_t *hash_stage1, uint8_t *hash_stage2) {
  proxy_compute_sha1_hash(hash_stage1, password, pass_len);
  proxy_compute_sha1_hash(hash_stage2, (const char *) hash_stage1, SHA_DIGEST_LENGTH);
}

void proxy_my_crypt(char *to, const uint8_t *s1, const uint8_t *s2, uint len) {
  const uint8_t *s1_end= s1 + len;
  while (s1 < s1_end)
    *to++= *s1++ ^ *s2++;
}

unsigned char decode_char(char x) {
	if (x >= '0' && x <= '9')
		return (x - 0x30);
	else if (x >= 'A' && x <= 'F')
		return(x - 0x37);
	else if (x >= 'a' && x <= 'f')
		return(x - 0x57);
	else {
		proxy_error("Invalid char");
		return 0;
	}
}

void unhex_pass(uint8_t *out, const char *in) {
	int i=0;
	for (i=0;i<SHA_DIGEST_LENGTH;i++) {
		// this can be simplified a lot, but leaving like this to make it easy to debug
		uint8_t c=0, d=0;
		c=decode_char(in[i*2]);
		c=(c*16) & 0xF0;
		d=decode_char(in[i*2+1]);
		d=d & 0x0F;
		c+=d;
		out[i]=c;
	}
}

void proxy_scramble(char *to, const char *message, const char *password)
{
	uint8_t hash_stage1[SHA_DIGEST_LENGTH];
	uint8_t hash_stage2[SHA_DIGEST_LENGTH];
	proxy_compute_two_stage_sha1_hash(password, strlen(password), hash_stage1, hash_stage2);
	proxy_compute_sha1_hash_multi((uint8_t *) to, message, SCRAMBLE_LENGTH, (const char *) hash_stage2, SHA_DIGEST_LENGTH);
	proxy_my_crypt(to, (const uint8_t *) to, hash_stage1, SCRAMBLE_LENGTH);
	return;
}

bool proxy_scramble_sha1(char *pass_reply,  const char *message, const char *sha1_sha1_pass, char *sha1_pass) {
	bool ret=false;
	uint8_t hash_stage1[SHA_DIGEST_LENGTH];
	uint8_t hash_stage2[SHA_DIGEST_LENGTH];
	uint8_t hash_stage3[SHA_DIGEST_LENGTH];
	uint8_t to[SHA_DIGEST_LENGTH];
	unhex_pass(hash_stage2,sha1_sha1_pass);
	proxy_compute_sha1_hash_multi((uint8_t *) to, message, SCRAMBLE_LENGTH, (const char *) hash_stage2, SHA_DIGEST_LENGTH);
	proxy_my_crypt((char *)hash_stage1,(const uint8_t *) pass_reply, to, SCRAMBLE_LENGTH);
	proxy_compute_sha1_hash(hash_stage3, (const char *) hash_stage1, SHA_DIGEST_LENGTH);
	if (memcmp(hash_stage2,hash_stage3,SHA_DIGEST_LENGTH)==0) {
		memcpy(sha1_pass,hash_stage1,SHA_DIGEST_LENGTH);
		ret=true;
	} else {
		PROXY_TRACE(); // for debugging purpose
	}
	return ret;
}

typedef union _4bytes_t {
	unsigned char data[4];
	uint32_t i;
} _4bytes_t;

unsigned int CPY3(unsigned char *ptr) {
	_4bytes_t buf;
	buf.i=*(uint32_t *)ptr;
	buf.data[3]=0;
	return buf.i;
}

uint64_t CPY8(unsigned char *ptr) {
	uint64_t buf;
	memcpy(&buf,ptr,sizeof(uint64_t));
	return buf;
}

// see http://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
/* arguments to pass:
 * pointer to the field
 * poiter to the variable to store the length
 * returns the bytes length of th field
*/
uint8_t mysql_decode_length(unsigned char *ptr, uint64_t *len) {
	if (*ptr <= 0xfb) { if (len) { *len = CPY1(ptr); };  return 1; }
	if (*ptr == 0xfc) { if (len) { *len = CPY2(ptr+1); }; return 3; }
	if (*ptr == 0xfd) { if (len) { *len = CPY3(ptr+1); };  return 4; }
	if (*ptr == 0xfe) { if (len) { *len = CPY8(ptr+1); };  return 9; }
	return 0; // never reaches here
}

uint8_t mysql_encode_length(uint64_t len, char *hd) {
	if (len < 251) return 1;
	if (len < 65536) { if (hd) { *hd=0xfc; }; return 3; }
	if (len < 16777216) { if (hd) { *hd=0xfd; }; return 4; }
	if (hd) { *hd=0xfe; }
	return 9;	
}

