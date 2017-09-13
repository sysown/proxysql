#include "proxysql.h"
#include "cpp.h"

extern MySQL_Authentication *GloMyAuth;
extern MySQL_Threads_Handler *GloMTH;

#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Authentication *GloClickHouseAuth;
#endif /* PROXYSQLCLICKHOUSE */

#ifdef max_allowed_packet
#undef max_allowed_packet
#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
typedef uint8_t uint8;
typedef uint8_t uchar;
#endif

//#define RESULTSET_BUFLEN 16300


#ifdef DEBUG
static void __dump_pkt(const char *func, unsigned char *_ptr, unsigned int len) {

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
	uint8_t a;
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

void proxy_create_random_string(char *to, uint length, struct rand_struct *rand_st) {
  uint i;
  for (i=0; i<length ; i++) {
    *to= (char) (proxy_my_rnd(rand_st) * 94 + 33);
    to++;
  }
  *to= '\0';
}

static inline int write_encoded_length(unsigned char *p, uint64_t val, uint8_t len, char prefix) {
	if (len==1) {
		*p=(char)val;
		return 1;
	}
	*p=prefix;
	p++;
	memcpy(p,&val,len-1);
	return len;
}

static inline int write_encoded_length_and_string(unsigned char *p, uint64_t val, uint8_t len, char prefix, char *string) {
	int l=write_encoded_length(p,val,len,prefix);
	if (val) {
		memcpy(p+l,string,val);
	}
	return l+val;
}

void proxy_compute_sha1_hash_multi(uint8 *digest, const char *buf1, int len1, const char *buf2, int len2) {
  PROXY_TRACE();
  
  SHA_CTX sha1_context;
  SHA1_Init(&sha1_context);
  SHA1_Update(&sha1_context, buf1, len1);
  SHA1_Update(&sha1_context, buf2, len2);
  SHA1_Final(digest, &sha1_context);
}

void proxy_compute_sha1_hash(uint8 *digest, const char *buf, int len) {
  PROXY_TRACE();
  
  SHA_CTX sha1_context;
  SHA1_Init(&sha1_context);
  SHA1_Update(&sha1_context, buf, len);
  SHA1_Final(digest, &sha1_context);
}

void proxy_compute_two_stage_sha1_hash(const char *password, size_t pass_len, uint8 *hash_stage1, uint8 *hash_stage2) {
  proxy_compute_sha1_hash(hash_stage1, password, pass_len);
  proxy_compute_sha1_hash(hash_stage2, (const char *) hash_stage1, SHA_DIGEST_LENGTH);
}

void proxy_my_crypt(char *to, const uchar *s1, const uchar *s2, uint len) {
  const uint8 *s1_end= s1 + len;
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
	uint8 hash_stage1[SHA_DIGEST_LENGTH];
	uint8 hash_stage2[SHA_DIGEST_LENGTH];
	proxy_compute_two_stage_sha1_hash(password, strlen(password), hash_stage1, hash_stage2);
	proxy_compute_sha1_hash_multi((uint8 *) to, message, SCRAMBLE_LENGTH, (const char *) hash_stage2, SHA_DIGEST_LENGTH);
	proxy_my_crypt(to, (const uchar *) to, hash_stage1, SCRAMBLE_LENGTH);
	return;
}

bool proxy_scramble_sha1(char *pass_reply,  const char *message, const char *sha1_sha1_pass, char *sha1_pass) {
	bool ret=false;
	uint8 hash_stage1[SHA_DIGEST_LENGTH];
	uint8 hash_stage2[SHA_DIGEST_LENGTH];
	uint8 hash_stage3[SHA_DIGEST_LENGTH];
	uint8 to[SHA_DIGEST_LENGTH];
	unhex_pass(hash_stage2,sha1_sha1_pass);
	proxy_compute_sha1_hash_multi((uint8 *) to, message, SCRAMBLE_LENGTH, (const char *) hash_stage2, SHA_DIGEST_LENGTH);
	proxy_my_crypt((char *)hash_stage1,(const uchar *) pass_reply, to, SCRAMBLE_LENGTH);
	proxy_compute_sha1_hash(hash_stage3, (const char *) hash_stage1, SHA_DIGEST_LENGTH);
	if (memcmp(hash_stage2,hash_stage3,SHA_DIGEST_LENGTH)==0) {
		memcpy(sha1_pass,hash_stage1,SHA_DIGEST_LENGTH);
		ret=true;
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

static uint8_t mysql_encode_length(uint64_t len, char *hd) {
	if (len < 251) return 1;
	if (len < 65536) { if (hd) { *hd=0xfc; }; return 3; }
	if (len < 16777216) { if (hd) { *hd=0xfd; }; return 4; }
	if (hd) { *hd=0xfe; }
	return 9;	
}


enum MySQL_response_type mysql_response(unsigned char *pkt, unsigned int length) {
	unsigned char c=*pkt;
	switch (c) {
		case 0:
     // proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Packet OK_Packet\n");
			return OK_Packet;
		case 0xff:
     // proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Packet ERR_Packet\n");
			return ERR_Packet;
		case 0xfe:
			if (length < 9) {
        //proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Packet EOF_Packet\n");
				return EOF_Packet;
			}
		default:
			//proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Packet UNKNOWN_Packet\n");
			return UNKNOWN_Packet;
	}
}

int pkt_com_query(unsigned char *pkt, unsigned int length) {
	unsigned char buf[length];
	memcpy(buf,pkt+1, length-1);
	buf[length-1]='\0';
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"Query: %s\n", buf);
	return PKT_PARSED;
}

int pkt_ok(unsigned char *pkt, unsigned int length, MySQL_Protocol *mp) {
	if (length < 7) return PKT_ERROR;

	uint64_t affected_rows;
	uint64_t  insert_id;
#ifdef DEBUG
	uint16_t  warns;
#endif /* DEBUG */
	unsigned char msg[length];

	unsigned int p=0;
	int rc;

	pkt++; p++;
	rc=mysql_decode_length(pkt,&affected_rows);
	pkt	+= rc; p+=rc;
	rc=mysql_decode_length(pkt,&insert_id);
	pkt	+= rc; p+=rc;
	mp->prot_status=CPY2(pkt);
	pkt+=sizeof(uint16_t);
	p+=sizeof(uint16_t);
#ifdef DEBUG
	warns=CPY2(pkt);
#endif /* DEBUG */
	pkt+=sizeof(uint16_t);
	p+=sizeof(uint16_t);
	pkt++;
	p++;
	if (length>p) {
		memcpy(msg,pkt,length-p);
		msg[length-p]=0;
	} else {
		msg[0]=0;
	}

	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"OK Packet <affected_rows:%u insert_id:%u status:%u warns:%u msg:%s>\n", (uint32_t)affected_rows, (uint32_t)insert_id, (uint16_t)mp->prot_status, (uint16_t)warns, msg);
	
	return PKT_PARSED;
}



int pkt_end(unsigned char *pkt, unsigned int length, MySQL_Protocol *mp)
{
	if(*pkt != 0xFE || length > 5) return PKT_ERROR;
#ifdef DEBUG
	uint16_t warns = 0;
#endif /* DEBUG */

	if(length > 1) { // 4.1+
		pkt++;
#ifdef DEBUG
		warns    = CPY2(pkt);
#endif /* DEBUG */
		pkt    += 2;
		mp->prot_status  = CPY2(pkt);
	}
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"End Packet <status:%u warns:%u>\n", mp->prot_status, warns);

//	if(status & SERVER_MORE_RESULTS_EXISTS) {
//		proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"End Packet <status:%u warns:%u>\n");
//	}

	return PKT_PARSED;
}



MySQL_Prepared_Stmt_info::MySQL_Prepared_Stmt_info(unsigned char *pkt, unsigned int length) {
	pkt += 5;
	statement_id = CPY4(pkt);
	pkt += sizeof(uint32_t);
	num_columns = CPY2(pkt);
	pkt += sizeof(uint16_t);
	num_params = CPY2(pkt);
	pkt += sizeof(uint16_t);
	pkt++; // reserved_1
	warning_count = CPY2(pkt);
//	fprintf(stderr,"Generating prepared statement with id=%d, cols=%d, params=%d, warns=%d\n", statement_id, num_columns, num_params, warning_count);
	pending_num_columns=num_columns;
	pending_num_params=num_params;
}



void MySQL_Protocol::init(MySQL_Data_Stream **__myds, MySQL_Connection_userinfo *__userinfo, MySQL_Session *__sess) {
	myds=__myds;
	userinfo=__userinfo;
	sess=__sess;
	current_PreStmt=NULL;
}

int MySQL_Protocol::parse_mysql_pkt(PtrSize_t *PS_entry, MySQL_Data_Stream *__myds) {
	unsigned char *pkt=(unsigned char *)PS_entry->ptr;	
	enum mysql_data_stream_status *DSS=&(*myds)->DSS;

	mysql_hdr hdr;
	unsigned char cmd;
	unsigned char *payload;
	int from=(*myds)->myds_type;	// if the packet is from client or server
	enum MySQL_response_type c;

	payload=pkt+sizeof(mysql_hdr);
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"MySQL Packet length=%d, senquence_id=%d, addr=%p\n", hdr.pkt_length, hdr.pkt_id, payload);

	switch (*DSS) {

		// client is not connected yet
		case STATE_NOT_CONNECTED:
			if (from==MYDS_FRONTEND) { // at this stage we expect a packet from the server, not from client
				return PKT_ERROR;
			}
			break;

		// client has sent the handshake
		case STATE_CLIENT_HANDSHAKE:
			if (from==MYDS_FRONTEND) { // at this stage we expect a packet from the server, not from client
				return PKT_ERROR;
			}
			c=mysql_response(payload, hdr.pkt_length);
			switch (c) {
				case OK_Packet:
					if (pkt_ok(payload, hdr.pkt_length, this)==PKT_PARSED) {
						*DSS=STATE_SLEEP;
						return PKT_PARSED;
					}
					break;
				default:
					return PKT_ERROR; // from the server we expect either an OK or an ERR. Everything else is wrong
			}
			break;

		// connection is idle. Client should be send a command
		case STATE_SLEEP:
//			if (!from_client) {
//				return PKT_ERROR;
//			}
			cmd=*payload;
			switch (cmd) {
				case MYSQL_COM_QUERY:
					if (pkt_com_query(payload, hdr.pkt_length)==PKT_PARSED) {
						//*states=STATE_CLIENT_COM_QUERY;
						return PKT_PARSED;
					}
					break;
			}
			//break;

		default:
		// TO BE REMOVED: begin
			if (from==MYDS_FRONTEND) { // at this stage we expect a packet from the server, not from client
				return PKT_ERROR;
			}
			c=mysql_response(payload, hdr.pkt_length);
			switch (c) {
				case OK_Packet:
					if (pkt_ok(payload, hdr.pkt_length, this)==PKT_PARSED) {
						*DSS=STATE_SLEEP;
						return PKT_PARSED;
					}
					break;
				case EOF_Packet:
					pkt_end(payload, hdr.pkt_length, this);
					break;
				default:
					return PKT_ERROR; // from the server we expect either an OK or an ERR. Everything else is wrong
			}
			
		// TO BE REMOVED: end
			break;
	}
	
	return PKT_ERROR;
}



static unsigned char protocol_version=10;
static uint16_t server_status=SERVER_STATUS_AUTOCOMMIT;

bool MySQL_Protocol::generate_statistics_response(bool send, void **ptr, unsigned int *len) {
// FIXME : this function generates a not useful string. It is a placeholder for now

	char buf1[1000];
	unsigned long long t1=monotonic_time();
	sprintf(buf1,"Uptime: %llu Threads: %d  Questions: %llu  Slow queries: %llu", (t1-GloVars.global.start_time)/1000/1000, MyHGM->status.client_connections , GloMTH->get_total_queries() , GloMTH->get_slow_queries() );
	unsigned char statslen=strlen(buf1);
	mysql_hdr myhdr;
	myhdr.pkt_id=1;
	myhdr.pkt_length=statslen;

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);
	memcpy(_ptr+l,buf1,statslen);

	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

bool MySQL_Protocol::generate_pkt_EOF(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t warnings, uint16_t status) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=5;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);
	_ptr[l]=0xfe; l++;
	memcpy(_ptr+l, &warnings, sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l, &status, sizeof(uint16_t));
	
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		switch ((*myds)->DSS) {
			case STATE_COLUMN_DEFINITION:
				(*myds)->DSS=STATE_EOF1;
				break;
			case STATE_ROW:
				(*myds)->DSS=STATE_EOF2;
				break;
			default:
				//assert(0);
				break;
		}
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

bool MySQL_Protocol::generate_pkt_ERR(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t error_code, char *sql_state, char *sql_message) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	mysql_hdr myhdr;
	uint32_t sql_message_len=( sql_message ? strlen(sql_message) : 0 );
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=1+sizeof(uint16_t)+1+5+sql_message_len;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);
	_ptr[l]=0xff; l++;
	memcpy(_ptr+l, &error_code, sizeof(uint16_t)); l+=sizeof(uint16_t);
	_ptr[l]='#'; l++;
	memcpy(_ptr+l, sql_state, 5); l+=5;
	if (sql_message) memcpy(_ptr+l, sql_message, sql_message_len);
	
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		switch ((*myds)->DSS) {
			case STATE_CLIENT_HANDSHAKE:
			case STATE_QUERY_SENT_DS:
			case STATE_QUERY_SENT_NET:
				(*myds)->DSS=STATE_ERR;
				break;
			case STATE_OK:
				break;
			case STATE_SLEEP:
				if ((*myds)->sess->session_fast_forward==true) { // see issue #733
					break;
				}
			default:
				assert(0);
		}
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

bool MySQL_Protocol::generate_pkt_OK(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, unsigned int affected_rows, uint64_t last_insert_id, uint16_t status, uint16_t warnings, char *msg) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	char affected_rows_prefix;
	uint8_t affected_rows_len=mysql_encode_length(affected_rows, &affected_rows_prefix);
	char last_insert_id_prefix;
	uint8_t last_insert_id_len=mysql_encode_length(last_insert_id, &last_insert_id_prefix);
	uint32_t msg_len=( msg ? strlen(msg) : 0 );
	char msg_prefix;
	uint8_t msg_len_len=mysql_encode_length(msg_len, &msg_prefix);

	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=1+affected_rows_len+last_insert_id_len+sizeof(uint16_t)+sizeof(uint16_t)+msg_len;
	if (msg_len) myhdr.pkt_length+=msg_len_len;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);
	_ptr[l]=0x00; l++;
	l+=write_encoded_length(_ptr+l, affected_rows, affected_rows_len, affected_rows_prefix);
	l+=write_encoded_length(_ptr+l, last_insert_id, last_insert_id_len, last_insert_id_prefix);
	memcpy(_ptr+l, &status, sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l, &warnings, sizeof(uint16_t)); l+=sizeof(uint16_t);
	if (msg) {
		l+=write_encoded_length(_ptr+l, msg_len, msg_len_len, msg_prefix);
		memcpy(_ptr+l, msg, msg_len);
	}
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		switch ((*myds)->DSS) {
			case STATE_CLIENT_HANDSHAKE:
			case STATE_QUERY_SENT_DS:
			case STATE_QUERY_SENT_NET:
				(*myds)->DSS=STATE_OK;
				break;
			case STATE_OK:
				break;
			default:
				assert(0);
		}
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

bool MySQL_Protocol::generate_pkt_column_count(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint64_t count) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}

	char count_prefix=0;
	uint8_t count_len=mysql_encode_length(count, &count_prefix);

	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=count_len;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);

	l+=write_encoded_length(_ptr+l, count, count_len, count_prefix);

	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

bool MySQL_Protocol::generate_pkt_field(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, char *schema, char *table, char *org_table, char *name, char *org_name, uint16_t charset, uint32_t column_length, uint8_t type, uint16_t flags, uint8_t decimals, bool field_list, uint64_t defvalue_length, char *defvalue) {

	if ((*myds)->sess->mirror==true) {
		return true;
	}
	char *def=(char *)"def";
	uint32_t def_strlen=strlen(def);
	char def_prefix;
	uint8_t def_len=mysql_encode_length(def_strlen, &def_prefix);

	uint32_t schema_strlen=strlen(schema);
	char schema_prefix;
	uint8_t schema_len=mysql_encode_length(schema_strlen, &schema_prefix);

	uint32_t table_strlen=strlen(table);
	char table_prefix;
	uint8_t table_len=mysql_encode_length(table_strlen, &table_prefix);

	uint32_t org_table_strlen=strlen(org_table);
	char org_table_prefix;
	uint8_t org_table_len=mysql_encode_length(org_table_strlen, &org_table_prefix);

	uint32_t name_strlen=strlen(name);
	char name_prefix;
	uint8_t name_len=mysql_encode_length(name_strlen, &name_prefix);

	uint32_t org_name_strlen=strlen(org_name);
	char org_name_prefix;
	uint8_t org_name_len=mysql_encode_length(org_name_strlen, &org_name_prefix);


	char defvalue_length_prefix;
	uint8_t defvalue_length_len=mysql_encode_length(defvalue_length, &defvalue_length_prefix);

	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length = def_len + def_strlen
		+ schema_len + schema_strlen
		+ table_len + table_strlen
		+ org_table_len + org_table_strlen
		+ name_len + name_strlen
		+ org_name_len + org_name_strlen
		+ 1  // filler
		+ sizeof(uint16_t) // charset
		+ sizeof(uint32_t) // column_length
		+ sizeof(uint8_t)  // type
		+ sizeof(uint16_t) // flags
		+ sizeof(uint8_t)  // decimals
		+ 2; // filler
	if (field_list) {
		myhdr.pkt_length += defvalue_length_len + strlen(defvalue);
	} //else myhdr.pkt_length++;

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);

	l+=write_encoded_length_and_string(_ptr+l, def_strlen, def_len, def_prefix, def);
	l+=write_encoded_length_and_string(_ptr+l, schema_strlen, schema_len, schema_prefix, schema);
	l+=write_encoded_length_and_string(_ptr+l, table_strlen, table_len, table_prefix, table);
	l+=write_encoded_length_and_string(_ptr+l, org_table_strlen, org_table_len, org_table_prefix, org_table);
	l+=write_encoded_length_and_string(_ptr+l, name_strlen, name_len, name_prefix, name);
	l+=write_encoded_length_and_string(_ptr+l, org_name_strlen, org_name_len, org_name_prefix, org_name);
	_ptr[l]=0x0c; l++;
	memcpy(_ptr+l,&charset,sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l,&column_length,sizeof(uint32_t)); l+=sizeof(uint32_t);
	_ptr[l]=type; l++;
	memcpy(_ptr+l,&flags,sizeof(uint16_t)); l+=sizeof(uint16_t);
	_ptr[l]=decimals; l++;
	_ptr[l]=0x00; l++;
	_ptr[l]=0x00; l++;
	if (field_list) {
		l+=write_encoded_length_and_string(_ptr+l, strlen(defvalue), defvalue_length_len, defvalue_length_prefix, defvalue);
	} 
	//else _ptr[l]=0x00;
	//else fprintf(stderr,"current deflen=%d, defstrlen=%d, namelen=%d, namestrlen=%d, l=%d\n", def_len, def_strlen, name_len, name_strlen, l);
	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}


// FIXME FIXME function not completed yet!
// see https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html
bool MySQL_Protocol::generate_STMT_PREPARE_RESPONSE(uint8_t sequence_id, MySQL_STMT_Global_info *stmt_info, uint32_t _stmt_id) {
	uint8_t sid=sequence_id;
	uint16_t i;
	char *okpack=(char *)malloc(16); // first packet
	mysql_hdr hdr;
	hdr.pkt_id=sid;
	hdr.pkt_length=12;
	memcpy(okpack,&hdr,sizeof(mysql_hdr)); // copy header
	okpack[4]=0;
	okpack[13]=0;
	okpack[15]=0;
	if (_stmt_id) {
		memcpy(okpack+5,&_stmt_id,sizeof(uint32_t));
	} else {
		memcpy(okpack+5,&stmt_info->statement_id,sizeof(uint32_t));
	}
	memcpy(okpack+9,&stmt_info->num_columns,sizeof(uint16_t));
	memcpy(okpack+11,&stmt_info->num_params,sizeof(uint16_t));
	memcpy(okpack+14,&stmt_info->warning_count,sizeof(uint16_t));
	(*myds)->PSarrayOUT->add((void *)okpack,16);
	sid++;
	if (stmt_info->num_params) {
		for (i=0; i<stmt_info->num_params; i++) {
			generate_pkt_field(true,NULL,NULL,sid,
				(char *)"", (char *)"", (char *)"", (char *)"?", (char *)"",
				63,0,253,128,0,false,0,NULL); // NOTE: charset is 63 = binary !
			sid++;
		}
		generate_pkt_EOF(true,NULL,NULL,sid,0,SERVER_STATUS_AUTOCOMMIT); // FIXME : for now we pass a very broken flag
		sid++;
	}
	if (stmt_info->num_columns) {
		for (i=0; i<stmt_info->num_columns; i++) {
			MYSQL_FIELD *fd=stmt_info->fields[i];
			generate_pkt_field(true,NULL,NULL,sid,
				fd->db,
				fd->table, fd->org_table,
				fd->name, fd->org_name,
				fd->charsetnr, 0, fd->type, fd->flags, fd->decimals, false,0,NULL);
			sid++;
		}
		generate_pkt_EOF(true,NULL,NULL,sid,0,SERVER_STATUS_AUTOCOMMIT); // FIXME : for now we pass a very broken flag
		sid++;
	}
	return true;
}

bool MySQL_Protocol::generate_pkt_row(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, int colnums, unsigned long *fieldslen, char **fieldstxt) {
	int col=0;
	int rowlen=0;
	for (col=0; col<colnums; col++) {
		rowlen+=( fieldstxt[col] ? fieldslen[col]+mysql_encode_length(fieldslen[col],NULL) : 1 );
	}
	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=rowlen;

	unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
	unsigned char *_ptr=(unsigned char *)l_alloc(size);
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	int l=sizeof(mysql_hdr);
	for (col=0; col<colnums; col++) {
		if (fieldstxt[col]) {
			char length_prefix;
			uint8_t length_len=mysql_encode_length(fieldslen[col], &length_prefix);
			l+=write_encoded_length_and_string(_ptr+l,fieldslen[col],length_len, length_prefix, fieldstxt[col]);
		} else {
			_ptr[l]=0xfb;
			l++;
		}
	}
	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

uint8_t MySQL_Protocol::generate_pkt_row3(MySQL_ResultSet *myrs, unsigned int *len, uint8_t sequence_id, int colnums, unsigned long *fieldslen, char **fieldstxt) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	int col=0;
	unsigned int rowlen=0;
	uint8_t pkt_sid=sequence_id;
	for (col=0; col<colnums; col++) {
		rowlen+=( fieldstxt[col] ? fieldslen[col]+mysql_encode_length(fieldslen[col],NULL) : 1 );
	}
	PtrSize_t pkt;
	pkt.size=rowlen+sizeof(mysql_hdr);
	if ( pkt.size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
		// there is space in the buffer, add the data to it
		pkt.ptr = myrs->buffer + myrs->buffer_used;
		myrs->buffer_used += pkt.size;
	} else {
		// there is no space in the buffer, we flush the buffer and recreate it
		myrs->buffer_to_PSarrayOut();
		// now we can check again if there is space in the buffer
		if ( pkt.size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
			// there is space in the NEW buffer, add the data to it
			pkt.ptr = myrs->buffer + myrs->buffer_used;
			myrs->buffer_used += pkt.size;
		} else {
			// a new buffer is not enough to store the new row
			pkt.ptr=l_alloc(pkt.size);
		}
	}
	int l=sizeof(mysql_hdr);
	for (col=0; col<colnums; col++) {
		if (fieldstxt[col]) {
			char length_prefix;
			uint8_t length_len=mysql_encode_length(fieldslen[col], &length_prefix);
			l+=write_encoded_length_and_string((unsigned char *)pkt.ptr+l,fieldslen[col],length_len, length_prefix, fieldstxt[col]);
		} else {
			char *_ptr=(char *)pkt.ptr;
			_ptr[l]=0xfb;
			l++;
		}
	}
	if (pkt.size < (0xFFFFFF+sizeof(mysql_hdr))) {
		mysql_hdr myhdr;
		myhdr.pkt_id=pkt_sid;
		myhdr.pkt_length=rowlen;
		memcpy(pkt.ptr, &myhdr, sizeof(mysql_hdr));
		if (pkt.ptr >= myrs->buffer && pkt.ptr < myrs->buffer+RESULTSET_BUFLEN) {
			// we are writing within the buffer, do not add to PSarrayOUT
		} else {
			// we are writing outside the buffer, add to PSarrayOUT
			myrs->PSarrayOUT->add(pkt.ptr,pkt.size);
		}
	} else {
		unsigned int left=pkt.size;
		unsigned int copied=0;
		while (left>=(0xFFFFFF+sizeof(mysql_hdr))) {
			PtrSize_t pkt2;
			pkt2.size=0xFFFFFF+sizeof(mysql_hdr);
			pkt2.ptr=l_alloc(pkt2.size);
			memcpy((char *)pkt2.ptr+sizeof(mysql_hdr), (char *)pkt.ptr+sizeof(mysql_hdr)+copied, 0xFFFFFF);
			mysql_hdr myhdr;
			myhdr.pkt_id=pkt_sid;
			pkt_sid++;
			myhdr.pkt_length=0xFFFFFF;
			memcpy(pkt2.ptr, &myhdr, sizeof(mysql_hdr));
			// we are writing a large packet (over 16MB), we assume we are always outside the buffer
			myrs->PSarrayOUT->add(pkt2.ptr,pkt2.size);
			copied+=0xFFFFFF;
			left-=0xFFFFFF;
		}
		PtrSize_t pkt2;
		pkt2.size=left;
		pkt2.ptr=l_alloc(pkt2.size);
		memcpy((char *)pkt2.ptr+sizeof(mysql_hdr), (char *)pkt.ptr+sizeof(mysql_hdr)+copied, left-sizeof(mysql_hdr));
		mysql_hdr myhdr;
		myhdr.pkt_id=pkt_sid;
		myhdr.pkt_length=left-sizeof(mysql_hdr);
		memcpy(pkt2.ptr, &myhdr, sizeof(mysql_hdr));
		// we are writing a large packet (over 16MB), we assume we are always outside the buffer
		myrs->PSarrayOUT->add(pkt2.ptr,pkt2.size);
	}
	if (len) { *len=pkt.size+(pkt_sid-sequence_id)*sizeof(mysql_hdr); }
	if (pkt.size >= (0xFFFFFF+sizeof(mysql_hdr))) {
		l_free(pkt.size,pkt.ptr);
	}
	return pkt_sid;
}

bool MySQL_Protocol::generate_pkt_auth_switch_request(bool send, void **ptr, unsigned int *len) {
  proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating auth switch request pkt\n");
  mysql_hdr myhdr;
  myhdr.pkt_id=1;
  myhdr.pkt_length=1 // fe
		+ (strlen("mysql_native_password")+1)
		+ 20 // scramble
		+ 1; // 00
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)malloc(size);
	memset(_ptr,0,size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l;
  l=sizeof(mysql_hdr);
  _ptr[l]=0xfe; l++; //0xfe

  memcpy(_ptr+l,"mysql_native_password",strlen("mysql_native_password"));
	l+=strlen("mysql_native_password");
	_ptr[l]=0x00; l++;
  memcpy(_ptr+l, (*myds)->myconn->scramble_buff+0, 20); l+=20;
  _ptr[l]=0x00; //l+=1; //0x00
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		(*myds)->DSS=STATE_SERVER_HANDSHAKE;
		(*myds)->sess->status=CONNECTING_CLIENT;
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

//bool MySQL_Protocol::generate_pkt_initial_handshake(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len) {
bool MySQL_Protocol::generate_pkt_initial_handshake(bool send, void **ptr, unsigned int *len, uint32_t *_thread_id) {
  proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating handshake pkt\n");
  mysql_hdr myhdr;
  myhdr.pkt_id=0;
  myhdr.pkt_length=sizeof(protocol_version)
    + (strlen(mysql_thread___server_version)+1)
    + sizeof(uint32_t)  // thread_id
    + 8  // scramble1
    + 1  // 0x00
    //+ sizeof(glovars.server_capabilities)
    //+ sizeof(glovars.server_language)
    //+ sizeof(glovars.server_status)
    + sizeof(mysql_thread___server_capabilities)
    + sizeof(mysql_thread___default_charset)
    + sizeof(server_status)
    + 3 // unknown stuff
    + 10 // filler
    + 12 // scramble2
    + 1  // 0x00
    + (strlen("mysql_native_password")+1);

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)malloc(size);
	memset(_ptr,0,size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l;
  l=sizeof(mysql_hdr);
  uint32_t thread_id=__sync_fetch_and_add(&glovars.thread_id,1);
	if (thread_id==0) {
		thread_id=__sync_fetch_and_add(&glovars.thread_id,1); // again!
	}
	*_thread_id=thread_id;

  rand_struct rand_st;
  //randominit(&rand_st,rand(),rand());
  rand_st.max_value= 0x3FFFFFFFL;
  rand_st.max_value_dbl=0x3FFFFFFFL;
  rand_st.seed1=rand()%rand_st.max_value;
  rand_st.seed2=rand()%rand_st.max_value;

  memcpy(_ptr+l, &protocol_version, sizeof(protocol_version)); l+=sizeof(protocol_version);
  memcpy(_ptr+l, mysql_thread___server_version, strlen(mysql_thread___server_version)); l+=strlen(mysql_thread___server_version)+1;
  memcpy(_ptr+l, &thread_id, sizeof(uint32_t)); l+=sizeof(uint32_t);
//#ifdef MARIADB_BASE_VERSION
//  proxy_create_random_string(myds->myconn->myconn.scramble_buff+0,8,(struct my_rnd_struct *)&rand_st);
//#else
  proxy_create_random_string((*myds)->myconn->scramble_buff+0,8,(struct rand_struct *)&rand_st);
//#endif

  int i;
  for (i=0;i<8;i++) {
    if ((*myds)->myconn->scramble_buff[i]==0) {
      (*myds)->myconn->scramble_buff[i]='a';
    }
  }

  memcpy(_ptr+l, (*myds)->myconn->scramble_buff+0, 8); l+=8;
  _ptr[l]=0x00; l+=1; //0x00
	if (mysql_thread___have_compress) {
		mysql_thread___server_capabilities |= CLIENT_COMPRESS; // FIXME: shouldn't be here
	}
	(*myds)->myconn->options.server_capabilities=mysql_thread___server_capabilities;
  memcpy(_ptr+l,&mysql_thread___server_capabilities, sizeof(mysql_thread___server_capabilities)); l+=sizeof(mysql_thread___server_capabilities);
  memcpy(_ptr+l,&mysql_thread___default_charset, sizeof(mysql_thread___default_charset)); l+=sizeof(mysql_thread___default_charset);
  memcpy(_ptr+l,&server_status, sizeof(server_status)); l+=sizeof(server_status);
  memcpy(_ptr+l,"\x0f\x80\x15",3); l+=3;
  for (i=0;i<10; i++) { _ptr[l]=0x00; l++; } //filler
  //create_random_string(mypkt->data+l,12,(struct my_rnd_struct *)&rand_st); l+=12;
//#ifdef MARIADB_BASE_VERSION
//  proxy_create_random_string(myds->myconn->myconn.scramble_buff+8,12,(struct my_rnd_struct *)&rand_st);
//#else
  proxy_create_random_string((*myds)->myconn->scramble_buff+8,12,(struct rand_struct *)&rand_st);
//#endif
  //create_random_string(scramble_buf+8,12,&rand_st);

  for (i=8;i<20;i++) {
    if ((*myds)->myconn->scramble_buff[i]==0) {
      (*myds)->myconn->scramble_buff[i]='a';
    }
  }

  memcpy(_ptr+l, (*myds)->myconn->scramble_buff+8, 12); l+=12;
  l+=1; //0x00
  memcpy(_ptr+l,"mysql_native_password",strlen("mysql_native_password"));

	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		(*myds)->DSS=STATE_SERVER_HANDSHAKE;
		(*myds)->sess->status=CONNECTING_CLIENT;
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

bool MySQL_Protocol::process_pkt_OK(unsigned char *pkt, unsigned int len) {

  if (len < 11) return false;

  mysql_hdr hdr;
  memcpy(&hdr,pkt,sizeof(mysql_hdr));
  pkt     += sizeof(mysql_hdr);

	if (*pkt) return false;
	if (len!=hdr.pkt_length+sizeof(mysql_hdr)) return false;

	uint64_t affected_rows;
	uint64_t  insert_id;
#ifdef DEBUG
	uint16_t  warns;
#endif /* DEBUG */
	unsigned char msg[len];

	unsigned int p=0;
	int rc;

	pkt++; p++;
	rc=mysql_decode_length(pkt,&affected_rows);
	pkt += rc; p+=rc;
	rc=mysql_decode_length(pkt,&insert_id);
	pkt += rc; p+=rc;
	prot_status=CPY2(pkt);
	pkt+=sizeof(uint16_t);
	p+=sizeof(uint16_t);
#ifdef DEBUG
	warns=CPY2(pkt);
#endif /* DEBUG */
	pkt+=sizeof(uint16_t);
	p+=sizeof(uint16_t);
	pkt++;
	p++;
	if (len>p) {
		memcpy(msg,pkt,len-p);
		msg[len-p]=0;
	} else {
		msg[0]=0;
	}

	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"OK Packet <affected_rows:%u insert_id:%u status:%u warns:%u msg:%s>\n", (uint32_t)affected_rows, (uint32_t)insert_id, (uint16_t)prot_status, (uint16_t)warns, msg);
	
	return true;
}

bool MySQL_Protocol::process_pkt_EOF(unsigned char *pkt, unsigned int len) {
	int ret;
	mysql_hdr hdr;
	unsigned char *payload;
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	payload=pkt+sizeof(mysql_hdr);
	ret=pkt_end(payload, hdr.pkt_length, this);
	return ( ret==PKT_PARSED ? true : false );
}

bool MySQL_Protocol::process_pkt_COM_QUERY(unsigned char *pkt, unsigned int len) {
	bool ret=false;

	unsigned int _len=len-sizeof(mysql_hdr)-1;
	unsigned char *query=(unsigned char *)l_alloc(_len+1);
	memcpy(query,pkt+1+sizeof(mysql_hdr),_len);
	query[_len]=0x00;

	//printf("%s\n",query);

	l_free(_len+1,query);

	ret=true;
	return ret;
}


bool MySQL_Protocol::process_pkt_auth_swich_response(unsigned char *pkt, unsigned int len) {
	bool ret=false;
	char *password=NULL;

	if (len!=sizeof(mysql_hdr)+20) {
		return ret;
	}
	mysql_hdr hdr;
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	int default_hostgroup=-1;
	bool transaction_persistent;
	bool _ret_use_ssl=false;
	unsigned char pass[128];
	memset(pass,0,128);
	pkt+=sizeof(mysql_hdr);
	memcpy(pass, pkt, 20);
	char reply[SHA_DIGEST_LENGTH+1];
	reply[SHA_DIGEST_LENGTH]='\0';
	void *sha1_pass=NULL;
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
#ifdef PROXYSQLCLICKHOUSE
		password=GloClickHouseAuth->lookup((char *)userinfo->username, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, NULL, NULL, &transaction_persistent, NULL, NULL, &sha1_pass);
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		password=GloMyAuth->lookup((char *)userinfo->username, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, NULL, NULL, &transaction_persistent, NULL, NULL, &sha1_pass);
	}
	// FIXME: add support for default schema and fast forward , issues #255 and #256
	if (password==NULL) {
		ret=false;
	} else {
			if (password[0]!='*') { // clear text password
				proxy_scramble(reply, (*myds)->myconn->scramble_buff, password);
				if (memcmp(reply, pass, SHA_DIGEST_LENGTH)==0) {
					ret=true;
				}
			} else {
				ret=proxy_scramble_sha1((char *)pass,(*myds)->myconn->scramble_buff,password+1, reply);
				if (ret) {
					if (sha1_pass==NULL) {
						// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
						GloMyAuth->set_SHA1((char *)userinfo->username, USERNAME_FRONTEND,reply);
					}
					if (userinfo->sha1_pass) free(userinfo->sha1_pass);
					userinfo->sha1_pass=sha1_pass_hex(reply);
				}
			}
	}
	if (sha1_pass) {
		free(sha1_pass);
		sha1_pass=NULL;
	}
	return ret;
}


bool MySQL_Protocol::process_pkt_COM_CHANGE_USER(unsigned char *pkt, unsigned int len) {
	// FIXME: very buggy function, it doesn't perform any real check
	bool ret=false;
  int cur=sizeof(mysql_hdr);
	unsigned char *user=NULL;
	char *password=NULL;
	char *db=NULL;
	mysql_hdr hdr;
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	int default_hostgroup=-1;
	bool transaction_persistent;
	bool _ret_use_ssl=false;
	cur++;
	user=pkt+cur;
	cur+=strlen((const char *)user);
	cur++;
	unsigned char pass_len=pkt[cur];
	cur++;
	unsigned char pass[128];
	memset(pass,0,128);
	//pkt+=sizeof(mysql_hdr);
	memcpy(pass, pkt+cur, pass_len);
	char reply[SHA_DIGEST_LENGTH+1];
	reply[SHA_DIGEST_LENGTH]='\0';
	cur+=pass_len;
	db=(char *)pkt+cur;
	void *sha1_pass=NULL;
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
#ifdef PROXYSQLCLICKHOUSE
		password=GloClickHouseAuth->lookup((char *)user, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, NULL, NULL, &transaction_persistent, NULL, NULL, &sha1_pass);
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		password=GloMyAuth->lookup((char *)user, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, NULL, NULL, &transaction_persistent, NULL, NULL, &sha1_pass);
	}
	// FIXME: add support for default schema and fast forward, see issue #255 and #256
	(*myds)->sess->default_hostgroup=default_hostgroup;
	(*myds)->sess->transaction_persistent=transaction_persistent;
	if (password==NULL) {
		ret=false;
	} else {
		if (pass_len==0 && strlen(password)==0) {
			ret=true;
		} else {
			if (password[0]!='*') { // clear text password
				proxy_scramble(reply, (*myds)->myconn->scramble_buff, password);
				if (memcmp(reply, pass, SHA_DIGEST_LENGTH)==0) {
					ret=true;
				}
			} else {
				if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE) {
					ret=proxy_scramble_sha1((char *)pass,(*myds)->myconn->scramble_buff,password+1, reply);
					if (ret) {
						if (sha1_pass==NULL) {
							// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
							GloMyAuth->set_SHA1((char *)user, USERNAME_FRONTEND,reply);
						}
						if (userinfo->sha1_pass) free(userinfo->sha1_pass);
						userinfo->sha1_pass=sha1_pass_hex(reply);
					}
				}
			}
		}
		if (_ret_use_ssl==true) {
			// if we reached here, use_ssl is false , but _ret_use_ssl is true
			// it means that a client is required to use SSL , but it is not
			ret=false;
		}
	}
	if (userinfo->username) free(userinfo->username);
	if (userinfo->password) free(userinfo->password);
	if (ret==true) {
		(*myds)->DSS=STATE_CLIENT_HANDSHAKE;

		userinfo->username=strdup((const char *)user);
		userinfo->password=strdup((const char *)password);
		if (db) userinfo->set_schemaname(db,strlen(db));
	} else {
		// we always duplicate username and password, or crashes happen
		userinfo->username=strdup((const char *)user);
		/*if (pass_len) */ userinfo->password=strdup((const char *)"");
	}
	if (password) {
		free(password);
		password=NULL;
	}
	if (sha1_pass) {
		free(sha1_pass);
		sha1_pass=NULL;
	}

	return ret;
}

bool MySQL_Protocol::process_pkt_handshake_response(unsigned char *pkt, unsigned int len) {
	bool ret=false;
	uint8_t charset;
	uint32_t  capabilities;
	uint32_t  max_pkt;
	uint32_t  pass_len;
	unsigned char *user=NULL;
	char *db=NULL;
	unsigned char pass[128];
	char *password=NULL;
	bool use_ssl=false;
	bool _ret_use_ssl=false;

	memset(pass,0,128);
	void *sha1_pass=NULL;
#ifdef DEBUG
	unsigned char *_ptr=pkt;
#endif
	mysql_hdr hdr;
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	//Copy4B(&hdr,pkt);
	pkt     += sizeof(mysql_hdr);
	capabilities     = CPY4(pkt);
	pkt     += sizeof(uint32_t);
	max_pkt  = CPY4(pkt);
	pkt     += sizeof(uint32_t);
	charset  = *(uint8_t *)pkt;
	// see bug #810
	if (charset==0) {
		charset=mysql_thread___default_charset;
	}
	pkt     += 24;
	if (len==sizeof(mysql_hdr)+32) {
		(*myds)->encrypted=true;
		use_ssl=true;
	} else {
	user     = pkt;
	pkt     += strlen((char *)user) + 1;

	pass_len = (capabilities & CLIENT_SECURE_CONNECTION ? *pkt++ : strlen((char *)pkt));
	memcpy(pass, pkt, pass_len);
	pass[pass_len] = 0;

	pkt += pass_len;
	db = (capabilities & CLIENT_CONNECT_WITH_DB ? (char *)pkt : NULL);

	char reply[SHA_DIGEST_LENGTH+1];
	reply[SHA_DIGEST_LENGTH]='\0';
	int default_hostgroup=-1;
	char *default_schema=NULL;
	bool schema_locked;
	bool transaction_persistent;
	bool fast_forward;
	int max_connections;
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
#ifdef PROXYSQLCLICKHOUSE
		password=GloClickHouseAuth->lookup((char *)user, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, &default_schema, &schema_locked, &transaction_persistent, &fast_forward, &max_connections, &sha1_pass);
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		password=GloMyAuth->lookup((char *)user, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, &default_schema, &schema_locked, &transaction_persistent, &fast_forward, &max_connections, &sha1_pass);
	}
	//assert(default_hostgroup>=0);
	(*myds)->sess->default_hostgroup=default_hostgroup;
	(*myds)->sess->default_schema=default_schema; // just the pointer is passed
	(*myds)->sess->schema_locked=schema_locked;
	(*myds)->sess->transaction_persistent=transaction_persistent;
	(*myds)->sess->session_fast_forward=fast_forward;
	(*myds)->sess->user_max_connections=max_connections;
	if (password==NULL) {
		// this is a workaround for bug #603
		if (
			((*myds)->sess->session_type == PROXYSQL_SESSION_ADMIN)
		|| 
			((*myds)->sess->session_type == PROXYSQL_SESSION_STATS) 
		) {
			if (strcmp((const char *)user,mysql_thread___monitor_username)==0) {
				proxy_scramble(reply, (*myds)->myconn->scramble_buff, mysql_thread___monitor_password);
				if (memcmp(reply, pass, SHA_DIGEST_LENGTH)==0) {
					(*myds)->sess->default_hostgroup=STATS_HOSTGROUP;
					(*myds)->sess->default_schema=strdup((char *)"main"); // just the pointer is passed
					(*myds)->sess->schema_locked=false;
					(*myds)->sess->transaction_persistent=false;
					(*myds)->sess->session_fast_forward=false;
					(*myds)->sess->user_max_connections=0;
					password=l_strdup(mysql_thread___monitor_password);
				ret=true;
				}
			} else {
				ret=false;
			}
		} else {
			ret=false;
		}
	} else {
		if (pass_len==0 && strlen(password)==0) {
			ret=true;
		} else {
			if (password[0]!='*') { // clear text password
				proxy_scramble(reply, (*myds)->myconn->scramble_buff, password);
				if (memcmp(reply, pass, SHA_DIGEST_LENGTH)==0) {
					ret=true;
				}
			} else {
				if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE) {
					ret=proxy_scramble_sha1((char *)pass,(*myds)->myconn->scramble_buff,password+1, reply);
					if (ret) {
						if (sha1_pass==NULL) {
							// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
							GloMyAuth->set_SHA1((char *)user, USERNAME_FRONTEND,reply);
						}
						if (userinfo->sha1_pass) free(userinfo->sha1_pass);
						userinfo->sha1_pass=sha1_pass_hex(reply);
					}
					}
				}
			}
		}
		if (_ret_use_ssl==true) {
			// if we reached here, use_ssl is false , but _ret_use_ssl is true
			// it means that a client is required to use SSL , but it is not
			ret=false;
		}
	}
  proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"Handshake (%s auth) <user:\"%s\" pass:\"%s\" scramble:\"%s\" db:\"%s\" max_pkt:%u>, capabilities:%u char:%u, use_ssl:%s\n",
            (capabilities & CLIENT_SECURE_CONNECTION ? "new" : "old"), user, password, pass, db, max_pkt, capabilities, charset, ((*myds)->encrypted ? "yes" : "no"));
	assert(sess);
	assert(sess->client_myds);
	MySQL_Connection *myconn=sess->client_myds->myconn;
	assert(myconn);
	myconn->set_charset(charset);
	// enable compression
	if (capabilities & CLIENT_COMPRESS) {
		if (myconn->options.server_capabilities & CLIENT_COMPRESS) {
			myconn->options.compression_min_length=50;
			//myconn->set_status_compression(true);  // don't enable this here. It needs to be enabled after the OK is sent
		}
	}
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,len); }
#endif

	if (use_ssl) {
		ret=true;
		goto __exit_process_pkt_handshake_response;
	}

	if (ret==true) {

		(*myds)->myconn->options.max_allowed_pkt=max_pkt;
		(*myds)->DSS=STATE_CLIENT_HANDSHAKE;

		userinfo->username=strdup((const char *)user);
		userinfo->password=strdup((const char *)password);
		if (db) userinfo->set_schemaname(db,strlen(db));
	} else {
		// we always duplicate username and password, or crashes happen
		userinfo->username=strdup((const char *)user);
		if (pass_len) userinfo->password=strdup((const char *)"");
	}

__exit_process_pkt_handshake_response:
	if (password) {
		free(password);
		password=NULL;
	}
	if (sha1_pass) {
		free(sha1_pass);
		sha1_pass=NULL;
	}

	return ret;
}

void * MySQL_Protocol::Query_String_to_packet(uint8_t sid, std::string *s, unsigned int *l) {
	mysql_hdr hdr;
	hdr.pkt_id=sid;
	hdr.pkt_length=1+s->length();
	*l=hdr.pkt_length+sizeof(mysql_hdr);
	void *pkt=malloc(*l);
	memcpy(pkt,&hdr,sizeof(mysql_hdr));
	uint8_t c=_MYSQL_COM_QUERY;
	memcpy((char *)pkt+4,&c,1);
	memcpy((char *)pkt+5,s->c_str(),s->length());
	return pkt;
}



// get_binds_from_pkt() process an STMT_EXECUTE packet, and extract binds value
// and optionally metadata
// if stmt_meta is NULL, it means it is the first time that the client run
// STMT_EXECUTE and therefore stmt_meta needs to be build
//
// returns stmt_meta, or a new one
// See https://dev.mysql.com/doc/internals/en/com-stmt-execute.html for reference
stmt_execute_metadata_t * MySQL_Protocol::get_binds_from_pkt(void *ptr, unsigned int size, MySQL_STMT_Global_info *stmt_info, stmt_execute_metadata_t **stmt_meta) {
	stmt_execute_metadata_t *ret=NULL; //return NULL in case of failure
	if (size<14) {
		// some error!
		return ret;
	}
	uint16_t num_params=stmt_info->num_params;
	if (num_params==2) {
		PROXY_TRACE();
	}
	char *p=(char *)ptr+5;
	if (*stmt_meta) { // this PS was executed at least once, and we already have metadata
		ret=*stmt_meta;
	} else { // this is the first time that this PS is executed
		ret= new stmt_execute_metadata_t();
	}
	if (*stmt_meta==NULL) {
		memcpy(&ret->stmt_id,p,4); // stmt-id
	}
	p+=4; // stmt-id
	memcpy(&ret->flags,p,1); p+=1; // flags
	p+=4; // iteration-count
	ret->num_params=num_params;
	// we keep a pointer to the packet
	// this is extremely important because:
  // * binds[X].buffer does NOT point to a new allocated buffer
  // * binds[X].buffer points to offset inside the original packet
	// FIXME: there is still no free for pkt, so that will be a memory leak that needs to be fixed
	ret->pkt=ptr;
	uint8_t new_params_bound_flag;
	if (num_params) {
		uint16_t i;
		size_t null_bitmap_length=(num_params+7)/8;
		if (size < (14+1+null_bitmap_length)) {
			// some data missing?
			delete ret;
			return NULL;
		}
		memcpy(&new_params_bound_flag,p+null_bitmap_length,1);
		uint8_t *null_bitmap=NULL;
		null_bitmap=(uint8_t *)malloc(null_bitmap_length);
		memcpy(null_bitmap,p,null_bitmap_length);
		p+=null_bitmap_length;
		p+=1; // new_params_bound_flag

		MYSQL_BIND *binds=NULL;
		my_bool *is_nulls=NULL;
		unsigned long *lengths=NULL;
		// now we create bind structures only if needed
		if (*stmt_meta==NULL) {
			binds=(MYSQL_BIND *)malloc(sizeof(MYSQL_BIND)*num_params);
			memset(binds,0,sizeof(MYSQL_BIND)*num_params);
			ret->binds=binds;
			is_nulls=(my_bool *)malloc(sizeof(my_bool)*num_params);
			ret->is_nulls=is_nulls;
			lengths=(unsigned long *)malloc(sizeof(unsigned long)*num_params);
			ret->lengths=lengths;
		} else { // if STMT_EXECUTE was already executed once
			binds=ret->binds;
			is_nulls=ret->is_nulls;
			lengths=ret->lengths;
		}

		// process packet and set NULLs
		for (i=0;i<num_params;i++) {
			uint8_t null_byte=null_bitmap[i/8];
			uint8_t idx=i%8;
			my_bool is_null = (null_byte & ( 1 << idx )) >> idx;
			is_nulls[i]=is_null;
			binds[i].is_null=&is_nulls[i];
		}
		free(null_bitmap); // we are done with it

		if (new_params_bound_flag) {
			// the client is rebinding the parameters
			// the client is sending again the type of each parameter
			for (i=0;i<num_params;i++) {
				// set buffer_type and is_unsigned
				uint16_t buffer_type=0;
				memcpy(&buffer_type,p,2);
				binds[i].is_unsigned=0;
				if (buffer_type >= 32768) { // is_unsigned bit
					buffer_type-=32768;
					binds[i].is_unsigned=1;
				}
				binds[i].buffer_type=(enum enum_field_types)buffer_type;
				p+=2;

				// set length, defaults to 0
				// for parameters with not fixed length, that will be assigned later
				lengths[i]=0;
				binds[i].length=&lengths[i];
			}
		}
		for (i=0;i<num_params;i++) {
			if (is_nulls[i]==true) {
				// the parameter is NULL, no need to read any data from the packet
				continue;
			}
			enum enum_field_types buffer_type=binds[i].buffer_type;
			switch (buffer_type) {
				case MYSQL_TYPE_TINY:
					binds[i].buffer=p;
					p+=1;
					break;
				case MYSQL_TYPE_SHORT:
				case MYSQL_TYPE_YEAR:
					binds[i].buffer=p;
					p+=2;
					break;
				case MYSQL_TYPE_FLOAT:
				case MYSQL_TYPE_LONG:
				case MYSQL_TYPE_INT24:
					binds[i].buffer=p;
					p+=4;
					break;
				case MYSQL_TYPE_DOUBLE:
				case MYSQL_TYPE_LONGLONG:
					binds[i].buffer=p;
					p+=8;
					break;
				case MYSQL_TYPE_TIME:
					{
						binds[i].buffer=malloc(sizeof(MYSQL_TIME)); // NOTE: remember to free() this
						uint8_t l;
						memcpy(&l,p,1);
						p++;
						MYSQL_TIME ts;
						memset(&ts,0,sizeof(MYSQL_TIME));
						memcpy(&ts.neg,p,1);
						memcpy(&ts.day,p+1,4);
						memcpy(&ts.hour,p+5,1);
						memcpy(&ts.minute,p+6,1);
						memcpy(&ts.second,p+7,1);
						if (l>8) {
							memcpy(&ts.second_part,p+8,4);
						}
						p+=l;
						memcpy(binds[i].buffer,&ts,sizeof(MYSQL_TIME));
					}
					break;
				case MYSQL_TYPE_DATE:
				case MYSQL_TYPE_TIMESTAMP:
				case MYSQL_TYPE_DATETIME:
					{
						binds[i].buffer=malloc(sizeof(MYSQL_TIME)); // NOTE: remember to free() this
						uint8_t l;
						memcpy(&l,p,1);
						p++;
						MYSQL_TIME ts;
						memset(&ts,0,sizeof(MYSQL_TIME));
						memcpy(&ts.year,p,2);
						memcpy(&ts.month,p+2,1);
						memcpy(&ts.day,p+3,1);
						if (l>4) {
							memcpy(&ts.hour,p+4,1);
							memcpy(&ts.minute,p+5,1);
							memcpy(&ts.second,p+6,1);
						}
						if (l>7) {
							memcpy(&ts.second_part,p+7,4);
						}
						p+=l;
						memcpy(binds[i].buffer,&ts,sizeof(MYSQL_TIME));
					}
					break;
				case MYSQL_TYPE_TINY_BLOB:
				case MYSQL_TYPE_MEDIUM_BLOB:
				case MYSQL_TYPE_LONG_BLOB:
				case MYSQL_TYPE_BLOB:
				case MYSQL_TYPE_VARCHAR:
				case MYSQL_TYPE_VAR_STRING:
				case MYSQL_TYPE_STRING:
				case MYSQL_TYPE_DECIMAL:
				case MYSQL_TYPE_NEWDECIMAL:
					{
						uint8_t l=0;
						uint64_t len;
						l=mysql_decode_length((unsigned char *)p, &len);
						if (l>1) {
							PROXY_TRACE();
						}
						p+=l;
						binds[i].buffer=p;
						p+=len;
						lengths[i]=len;
					}
					break;
				default:
					assert(0);
					break;
			}
		}
	}
/*
#ifdef DEBUG
	// debug
	fprintf(stderr,"STMT_EXEC: %d\n",ret->stmt_id);
	if (num_params==2) {
		PROXY_TRACE();
	}
	for (int i=0;i<num_params;i++) {
		fprintf(stderr,"  Param %d, is_null=%d, type=%d\n", i, *(ret->binds[i].is_null), ret->binds[i].buffer_type);
	}
#endif
*/
	if (ret)
		ret->size=size;
	return ret;
}

MySQL_ResultSet::MySQL_ResultSet(MySQL_Protocol *_myprot, MYSQL_RES *_res, MYSQL *_my, MYSQL_STMT *_stmt) {
	transfer_started=false;
	resultset_completed=false;
	myprot=_myprot;
	mysql=_my;
	buffer=NULL;
	if (_stmt==NULL) { // we allocate this buffer only for not prepared statements
		buffer=(unsigned char *)malloc(RESULTSET_BUFLEN);
	}
	buffer_used=0;
	myds=NULL;
	sid=0;
	PSarrayOUT = NULL;
	if (myprot) { // if myprot = NULL , this is a mirror
		myds=myprot->get_myds();
		sid=myds->pkt_sid+1;
		PSarrayOUT = new PtrSizeArray(8);
	}
	result=_res;
	resultset_size=0;
	num_rows=0;
	num_fields=mysql_field_count(mysql);
	PtrSize_t pkt;
	// immediately generate the first set of packets
	// columns count
	if (myprot==NULL) {
		return; // this is a mirror
	}
	myprot->generate_pkt_column_count(false,&pkt.ptr,&pkt.size,sid,num_fields);
	sid++;
	PSarrayOUT->add(pkt.ptr,pkt.size);
	resultset_size+=pkt.size;
	// columns description
	for (unsigned int i=0; i<num_fields; i++) {
		MYSQL_FIELD *field=mysql_fetch_field(result);
		myprot->generate_pkt_field(false,&pkt.ptr,&pkt.size,sid,field->db,field->table,field->org_table,field->name,field->org_name,field->charsetnr,field->length,field->type,field->flags,field->decimals,false,0,NULL);
		PSarrayOUT->add(pkt.ptr,pkt.size);
		resultset_size+=pkt.size;
		sid++;
	}
	// first EOF
	unsigned int nTrx=myds->sess->NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
	if (myds->sess->autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
	myprot->generate_pkt_EOF(false,&pkt.ptr,&pkt.size,sid,0,mysql->server_status|setStatus);
	sid++;
	PSarrayOUT->add(pkt.ptr,pkt.size);
	resultset_size+=pkt.size;
	if (_stmt) { // binary protocol , we also assume we have ALL the resultset
		unsigned long long total_size=0;
		MYSQL_ROWS *r=_stmt->result.data;
		if (r) {
		total_size+=r->length;
		if (r->length > 0xFFFFFF) {
			total_size+=(r->length / 0xFFFFFF) * sizeof(mysql_hdr);
		}
		total_size+=sizeof(mysql_hdr);
		while(r->next) {
			r=r->next;
			total_size+=r->length;
			if (r->length > 0xFFFFFF) {
				total_size+=(r->length / 0xFFFFFF) * sizeof(mysql_hdr);
			}
			total_size+=sizeof(mysql_hdr);
		}
		PtrSize_t pkt;
		pkt.size=total_size;
		pkt.ptr=malloc(pkt.size);
		total_size=0;
		r=_stmt->result.data;
		add_row2(r,(unsigned char *)pkt.ptr);
		total_size+=r->length;
		if (r->length > 0xFFFFFF) {
			total_size+=(r->length / 0xFFFFFF) * sizeof(mysql_hdr);
		}
		total_size+=sizeof(mysql_hdr);
		while(r->next) {
			r=r->next;
			add_row2(r,(unsigned char *)pkt.ptr+total_size);
			total_size+=r->length;
			if (r->length > 0xFFFFFF) {
				total_size+=(r->length / 0xFFFFFF) * sizeof(mysql_hdr);
			}
			total_size+=sizeof(mysql_hdr);
		}
		PSarrayOUT->add(pkt.ptr,pkt.size);
		resultset_size+=pkt.size;
		}
		add_eof();
	}
}

MySQL_ResultSet::~MySQL_ResultSet() {
	PtrSize_t pkt;
	if (PSarrayOUT) {
		while (PSarrayOUT->len) {
			PSarrayOUT->remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
		delete PSarrayOUT;
	}
	if (buffer) {
		free(buffer);
		buffer=NULL;
	}
	if (myds) myds->pkt_sid=sid-1;
}

unsigned int MySQL_ResultSet::add_row(MYSQL_ROW row) {
	unsigned long *lengths=mysql_fetch_lengths(result);
	unsigned int pkt_length=0;
	if (myprot) {
		sid=myprot->generate_pkt_row3(this, &pkt_length, sid, num_fields, lengths, row);
	} else {
		unsigned int col=0;
		for (col=0; col<num_fields; col++) {
			pkt_length+=( row[col] ? lengths[col]+mysql_encode_length(lengths[col],NULL) : 1 );
		}
	}
	sid++;
	resultset_size+=pkt_length;
	num_rows++;
	return pkt_length;
}

// add_row2 is perhaps a faster implementation of add_row()
// still experimentatl
// so far, used only for prepared statements
// it assumes that the MYSQL_ROW is an format ready to be sent to the client
unsigned int MySQL_ResultSet::add_row2(MYSQL_ROWS *row, unsigned char *offset) {
	unsigned long length=row->length;

	uint8_t pkt_sid=sid;
	if (length < (0xFFFFFF+sizeof(mysql_hdr))) {
		mysql_hdr myhdr;
		myhdr.pkt_length=length;
		myhdr.pkt_id=pkt_sid;
		memcpy(offset, &myhdr, sizeof(mysql_hdr));
		memcpy(offset+sizeof(mysql_hdr), row->data, row->length);
		pkt_sid++;
	} else {
		unsigned int left=length;
		unsigned int copied=0;
		while (left>=0xFFFFFF) {
			mysql_hdr myhdr;
			myhdr.pkt_length=0xFFFFFF;
			myhdr.pkt_id=pkt_sid;
			pkt_sid++;
			memcpy(offset, &myhdr, sizeof(mysql_hdr));
			offset+=sizeof(mysql_hdr);
			memcpy(offset, row->data+copied, myhdr.pkt_length);
			offset+=0xFFFFFF;
			// we are writing a large packet (over 16MB), we assume we are always outside the buffer
			copied+=0xFFFFFF;
			left-=0xFFFFFF;
		}
		mysql_hdr myhdr;
		myhdr.pkt_length=left;
		myhdr.pkt_id=pkt_sid;
		pkt_sid++;
		memcpy(offset, &myhdr, sizeof(mysql_hdr));
		offset+=sizeof(mysql_hdr);
		memcpy(offset, row->data+copied, myhdr.pkt_length);
		// we are writing a large packet (over 16MB), we assume we are always outside the buffer
	}
	sid=pkt_sid;
	return length;
}

void MySQL_ResultSet::add_eof() {
	PtrSize_t pkt;
	if (myprot) {
		buffer_to_PSarrayOut();
		unsigned int nTrx=myds->sess->NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (myds->sess->autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		myprot->generate_pkt_EOF(false,&pkt.ptr,&pkt.size,sid,0,mysql->server_status|setStatus);
		PSarrayOUT->add(pkt.ptr,pkt.size);
		sid++;
		resultset_size+=pkt.size;
	}
	resultset_completed=true;
}

void MySQL_ResultSet::add_err(MySQL_Data_Stream *_myds) {
	PtrSize_t pkt;
	if (myprot) {
		MYSQL *_mysql=_myds->myconn->mysql;
		buffer_to_PSarrayOut();
		char sqlstate[10];
		sprintf(sqlstate,"%s",mysql_sqlstate(_mysql));
		if (_myds && _myds->killed_at) { // see case #750
			myprot->generate_pkt_ERR(false,&pkt.ptr,&pkt.size,sid,1907,sqlstate,(char *)"Query execution was interrupted, query_timeout exceeded");
		} else {
			myprot->generate_pkt_ERR(false,&pkt.ptr,&pkt.size,sid,mysql_errno(_mysql),sqlstate,mysql_error(_mysql));
		}
		PSarrayOUT->add(pkt.ptr,pkt.size);
		sid++;
		resultset_size+=pkt.size;
	}
	resultset_completed=true;
}

bool MySQL_ResultSet::get_resultset(PtrSizeArray *PSarrayFinal) {
	transfer_started=true;
	if (myprot) {
		PSarrayFinal->copy_add(PSarrayOUT,0,PSarrayOUT->len);
		while (PSarrayOUT->len)
			PSarrayOUT->remove_index(PSarrayOUT->len-1,NULL);
	}
	return resultset_completed;
}

void MySQL_ResultSet::buffer_to_PSarrayOut() {
	if (buffer_used==0)
		return;	// exit immediately if the buffer is empty
	if (buffer_used < RESULTSET_BUFLEN/2) {
		buffer=(unsigned char *)realloc(buffer,buffer_used);
	}
	PSarrayOUT->add(buffer,buffer_used);
	buffer=(unsigned char *)malloc(RESULTSET_BUFLEN);
	buffer_used=0;
}

unsigned long long MySQL_ResultSet::current_size() {
	unsigned long long intsize=0;
	intsize+=sizeof(MySQL_ResultSet);
	intsize+=RESULTSET_BUFLEN; // size of buffer
	if (PSarrayOUT==NULL)	// see bug #699
		return intsize;
	intsize+=sizeof(PtrSizeArray);
	intsize+=(PSarrayOUT->size*sizeof(PtrSize_t *));
	unsigned int i;
	for (i=0; i<PSarrayOUT->len; i++) {
		PtrSize_t *pkt=PSarrayOUT->index(i);
		if (pkt->size>RESULTSET_BUFLEN) {
			intsize+=pkt->size;
		} else {
			intsize+=RESULTSET_BUFLEN;
		}
	}
	return intsize;
}
