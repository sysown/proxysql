
//mysql_data_stream_t * mysql_data_stream_init(int, mysql_session_t *);
//void mysql_data_stream_close(mysql_data_stream_t *);

char *user_password(char *, int);

//inline int mysql_pkt_get_size(pkt *);
enum MySQL_response_type mysql_response(pkt *);

typedef struct _rand_struct_t {
  unsigned long seed1,seed2,max_value;
  double max_value_dbl;
} rand_struct_t;


void create_ok_packet(pkt *, unsigned int);
void create_handshake_packet(pkt *, char *);
int check_client_authentication_packet(pkt *, mysql_session_t *);
void create_err_packet(pkt *, unsigned int , uint16_t,char *);
void authenticate_mysql_client_send_OK(mysql_session_t *);
void authenticate_mysql_client_send_ERR(mysql_session_t *, uint16_t , char *);
int mysql_check_alive_and_read_only(const char *, uint16_t);
void proxy_create_random_string(char *, uint , struct rand_struct *);
double proxy_my_rnd(struct rand_struct *);
void proxy_scramble(char *, const char *, const char *);
void proxy_compute_sha1_hash_multi(uint8 *, const char *, int , const char *, int);
void proxy_compute_two_stage_sha1_hash(const char *, size_t, uint8 *, uint8 *);
void proxy_compute_sha1_hash(uint8 *, const char *, int);
void proxy_my_crypt(char *, const uchar *, const uchar *, uint);
int is_transaction_active(pkt *);
int lencint(uint64_t);
uint64_t lencint_unknown(uint64_t);
int writeencint(void *, uint64_t);
int writeencstrnull(void *, const char *);
void myproto_ok_pkt(pkt *, unsigned int , uint64_t , uint64_t, uint16_t, uint16_t);
void myproto_column_count(pkt *, unsigned int , uint64_t);
void myproto_column_def(pkt *, unsigned int , const char *, const char *, const char *, const char *, const char *, uint32_t , uint8_t, uint16_t , uint8_t);
void myproto_eof(pkt *, unsigned int , uint16_t , uint16_t);
void mysql_new_payload_select(pkt *, void *, int);
int parse_change_user_packet(pkt *, mysql_session_t *);
void create_auth_switch_request_packet(pkt *, mysql_session_t *);
int check_auth_switch_response_packet(pkt *, mysql_session_t *);
/*
#ifndef MYSQL_COM_END
#define MYSQL_COM_END COM_END
#define MYSQL_COM_QUIT COM_QUIT
#define MYSQL_COM_INIT_DB COM_INIT_DB
#define MYSQL_COM_QUERY COM_QUERY
#define MYSQL_COM_STATISTICS COM_STATISTICS
#define MYSQL_COM_STMT_PREPARE COM_STMT_PREPARE
#define MYSQL_COM_STMT_EXECUTE COM_STMT_EXECUTE
#define MYSQL_COM_STMT_CLOSE COM_STMT_CLOSE
#define MYSQL_COM_STMT_RESET COM_STMT_RESET
#define MYSQL_COM_STMT_SEND_LONG_DATA COM_STMT_SEND_LONG_DATA
#endif
*/
