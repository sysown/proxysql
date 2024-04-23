#ifndef CLASS_MySQL_encode_H
#define CLASS_MySQL_encode_H
#ifdef DEBUG
void __dump_pkt(const char *func, unsigned char *_ptr, unsigned int len);
#endif // DEBUG
char *sha1_pass_hex(char *sha1_pass);
double proxy_my_rnd(struct rand_struct *rand_st);
void proxy_create_random_string(char *_to, uint length, struct rand_struct *rand_st);
int write_encoded_length(unsigned char *p, uint64_t val, uint8_t len, char prefix);
int write_encoded_length_and_string(unsigned char *p, uint64_t val, uint8_t len, char prefix, char *string);
void proxy_compute_sha1_hash_multi(uint8_t *digest, const char *buf1, int len1, const char *buf2, int len2);
void proxy_compute_sha1_hash(uint8_t *digest, const char *buf, int len);
void proxy_compute_two_stage_sha1_hash(const char *password, size_t pass_len, uint8_t *hash_stage1, uint8_t *hash_stage2);
void proxy_my_crypt(char *to, const uint8_t *s1, const uint8_t *s2, uint len);
unsigned char decode_char(char x);
void unhex_pass(uint8_t *out, const char *in);
void proxy_scramble(char *to, const char *message, const char *password);
bool proxy_scramble_sha1(char *pass_reply,  const char *message, const char *sha1_sha1_pass, char *sha1_pass);
unsigned int CPY3(unsigned char *ptr);
uint64_t CPY8(unsigned char *ptr);
uint8_t mysql_encode_length(uint64_t len, char *hd);
#endif // CLASS_MySQL_encode_H
