#include "proxysql.h"
#include "cpp.h"

extern MySQL_Authentication *GloMyAuth;

#ifdef max_allowed_packet
#undef max_allowed_packet
#endif

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
  
/*
  GChecksum *sha1_context=g_checksum_new(G_CHECKSUM_SHA1);
  g_checksum_update(sha1_context, (const unsigned char *)buf1, len1);
  g_checksum_update(sha1_context, (const unsigned char *)buf2, len2);
  size_t s=SHA_DIGEST_LENGTH;
  g_checksum_get_digest(sha1_context,digest,&s);
  g_checksum_free(sha1_context);
*/
}


void proxy_compute_sha1_hash(uint8 *digest, const char *buf, int len) {
  PROXY_TRACE();
  
  SHA_CTX sha1_context;
  SHA1_Init(&sha1_context);
  SHA1_Update(&sha1_context, buf, len);
  SHA1_Final(digest, &sha1_context);

/*  
  GChecksum *sha1_context=g_checksum_new(G_CHECKSUM_SHA1);
  g_checksum_update(sha1_context, (const unsigned char *)buf, len);
  size_t s=SHA_DIGEST_LENGTH;
  g_checksum_get_digest(sha1_context,digest,&s);
  g_checksum_free(sha1_context);
*/
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




void proxy_scramble(char *to, const char *message, const char *password)
{
  uint8 hash_stage1[SHA_DIGEST_LENGTH];
  uint8 hash_stage2[SHA_DIGEST_LENGTH];

  /* Two stage SHA1 hash of the password. */
  proxy_compute_two_stage_sha1_hash(password, strlen(password), hash_stage1,
                              hash_stage2);

  /* create crypt string as sha1(message, hash_stage2) */;
  proxy_compute_sha1_hash_multi((uint8 *) to, message, SCRAMBLE_LENGTH,
                          (const char *) hash_stage2, SHA_DIGEST_LENGTH);
  proxy_my_crypt(to, (const uchar *) to, hash_stage1, SCRAMBLE_LENGTH);
}










typedef union _4bytes_t {
	unsigned char data[4];
	uint32_t i;
} _4bytes_t;

unsigned int CPY3(unsigned char *ptr) {
	_4bytes_t buf;
//	memcpy(buf.data, pkt, 3);	
	buf.i=*(uint32_t *)ptr;
	buf.data[3]=0;
//	unsigned char _cpy3buf[4];
//	_cpy3buf[3]=0;
//	unsigned int ret=*(unsigned int *)_cpy3buf;
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
/*
//int parse_mysql_pkt(unsigned char *pkt, enum session_states *states, int from_client) {
int parse_mysql_pkt(unsigned char *pkt, MySQL_Data_Stream *myds, int from_client) {
	mysql_hdr hdr;
	unsigned char cmd;
	unsigned char *payload;
	enum MySQL_response_type c;
	payload=pkt+sizeof(mysql_hdr);
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"MySQL Packet length=%d, senquence_id=%d, addr=%p\n", hdr.pkt_length, hdr.pkt_id, payload);

	enum mysql_data_stream_status *DSS=&myds->DSS;
	switch (*DSS) {

		// client is not connected yet
		case STATE_NOT_CONNECTED:
			if (from_client) { // at this stage we expect a packet from the server, not from client
				return PKT_ERROR;
			}
			if (pkt_handshake_server(payload, hdr.pkt_length)==PKT_PARSED) {
				*DSS=STATE_SERVER_HANDSHAKE;
				return PKT_PARSED;
			}
			break;

		// server has sent the handshake
		case STATE_SERVER_HANDSHAKE:
			if (!from_client) {
				return PKT_ERROR;
			}
			if (pkt_handshake_client(payload, hdr.pkt_length)==PKT_PARSED) {
				*DSS=STATE_CLIENT_HANDSHAKE;
				return PKT_PARSED;
			}
			break;

		// client has sent the handshake
		case STATE_CLIENT_HANDSHAKE:
			if (from_client) { // at this stage we expect a packet from the server, not from client
				return PKT_ERROR;
			}
			c=mysql_response(payload, hdr.pkt_length);
			switch (c) {
				case OK_Packet:
					if (pkt_ok(payload, hdr.pkt_length)==PKT_PARSED) {
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
						// *states=STATE_CLIENT_COM_QUERY;
						return PKT_PARSED;
					}
					break;
			}
			//break;



			
		default:
		// TO BE REMOVED: begin
			if (from_client) { // at this stage we expect a packet from the server, not from client
				return PKT_ERROR;
			}
			c=mysql_response(payload, hdr.pkt_length);
			switch (c) {
				case OK_Packet:
					if (pkt_ok(payload, hdr.pkt_length)==PKT_PARSED) {
						*DSS=STATE_SLEEP;
						return PKT_PARSED;
					}
					break;
				case EOF_Packet:
					pkt_end(payload, hdr.pkt_length);
					break;
				default:
					return PKT_ERROR; // from the server we expect either an OK or an ERR. Everything else is wrong
			}
			
		// TO BE REMOVED: end
			break;
	}
	
	return PKT_ERROR;
}
*/



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
   //uint64_t  status;  // FIXME: uint16_t
   uint16_t  warns;  // FIXME: uint16_t
   unsigned char msg[length];

	unsigned int p=0;
	int rc;

   //field_count = (u_int)*pkt++;
	pkt++; p++;
	rc=mysql_decode_length(pkt,&affected_rows);
	pkt	+= rc; p+=rc;
	rc=mysql_decode_length(pkt,&insert_id);
	pkt	+= rc; p+=rc;
	mp->prot_status=CPY2(pkt);
	pkt+=sizeof(uint16_t);
	p+=sizeof(uint16_t);
	warns=CPY2(pkt);
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

	uint16_t warns = 0;
	//uint16_t status = 0;

	if(length > 1) { // 4.1+
		pkt++;
		warns    = CPY2(pkt);
		pkt    += 2;
		mp->prot_status  = CPY2(pkt);

/*
      if((tag->state == STATE_TXT_ROW || tag->state == STATE_BIN_ROW) &&
         status & SERVER_MORE_RESULTS_EXISTS &&
         tag->event != EVENT_END_MULTI_RESULT)
            return PKT_WRONG_TYPE;
   }
*/
	}
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"End Packet <status:%u warns:%u>\n", mp->prot_status, warns);

//	if(status & SERVER_MORE_RESULTS_EXISTS) {
//		proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"End Packet <status:%u warns:%u>\n");
//	}

	return PKT_PARSED;
}


int pkt_handshake_server(unsigned char *pkt, unsigned int length, MySQL_Protocol *mp) {
	//return PKT_PARSED;
	if (*pkt != 0x0A || length < 29) return PKT_ERROR;

	uint8_t protocol;
	uint16_t capabilities;
	uint8_t charset;
	//uint16_t status;
	uint32_t thread_id;

	unsigned char * version;
	unsigned char * salt1;
	unsigned char * salt2;

	protocol = *(uint8_t *)pkt;
	pkt      += sizeof(uint8_t);
	version   = pkt;
	pkt      += strlen((char *)version) + 1;
	thread_id = CPY4(pkt);
	pkt      += sizeof(uint32_t);
	salt1     = pkt;
	pkt      += strlen((char *)salt1) + 1;
	capabilities = CPY2(pkt);
	pkt    += sizeof(uint16_t);
	charset = *(uint8_t *)pkt;
	pkt    += sizeof(uint8_t);
	mp->prot_status  = CPY2(pkt);
	pkt    += 15; // 2 for status, 13 for zero-byte padding
	salt2   = pkt;

	// FIXME: the next two lines are here just to prevent this: warning: variable ‘salt2’ set but not used [-Wunused-but-set-variable]
	// salt2 needs to be handled
	salt2++;
	salt2 = pkt;
	

   proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"Handshake <proto:%u ver:\"%s\" thd:%d cap:%d char:%d status:%d>\n", protocol, version, thread_id, capabilities, charset, mp->prot_status);
//   if(op.verbose) unmask_caps(caps);

   return PKT_PARSED;

}


void MySQL_Protocol::init(MySQL_Data_Stream **__myds, MySQL_Connection_userinfo *__userinfo, MySQL_Session *__sess) {
	myds=__myds;
	userinfo=__userinfo;
	sess=__sess;
}

int MySQL_Protocol::pkt_handshake_client(unsigned char *pkt, unsigned int length) {
	int ret=PKT_ERROR;
	uint8_t charset;
   uint32_t  capabilities;
   uint32_t  max_pkt;
   uint32_t  pass_len;
   unsigned char *user;
   unsigned char *db;
   unsigned char pass[128];
	bool _ret_use_ssl=false; 	
	int default_hostgroup=-1;
	bool transaction_persistent;

      capabilities     = CPY4(pkt);
      pkt     += sizeof(uint32_t);
      max_pkt  = CPY4(pkt);
      pkt     += sizeof(uint32_t);
      charset  = *(uint8_t *)pkt;
      pkt     += 24;
      user     = pkt;
      pkt     += strlen((char *)user) + 1;

      pass_len = (capabilities & CLIENT_SECURE_CONNECTION ? *pkt++ : strlen((char *)pkt));
      memcpy(pass, pkt, pass_len);
      pass[pass_len] = 0;

      pkt += pass_len;
      db = (capabilities & CLIENT_CONNECT_WITH_DB ? pkt : 0);

	char reply[SHA_DIGEST_LENGTH+1];
	reply[SHA_DIGEST_LENGTH]='\0';
	char *password=GloMyAuth->lookup((char *)user, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, &transaction_persistent);
	if (password==NULL) {
		ret=PKT_ERROR;
	} else {
		if (pass_len==0 && strlen(password)==0) {
			ret=PKT_PARSED;
		} else {
			proxy_scramble(reply, (*myds)->myconn->scramble_buff, password);
			if (memcmp(reply, pass, SHA_DIGEST_LENGTH)==0) {
				ret=PKT_PARSED;
			}
		}
	}
  proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"Handshake (%s auth) <user:\"%s\" pass:\"%s\" scramble:\"%s\" db:\"%s\" max_pkt:%u>, capabilities:%u char:%u\n",
            (capabilities & CLIENT_SECURE_CONNECTION ? "new" : "old"), user, password, pass, db, max_pkt, capabilities, charset);

	
   return ret;
}


//int parse_mysql_pkt(unsigned char *pkt, enum session_states *states, int from_client) {
int MySQL_Protocol::parse_mysql_pkt(PtrSize_t *PS_entry, MySQL_Data_Stream *__myds) {
	unsigned char *pkt=(unsigned char *)PS_entry->ptr;	
//	unsigned int size=PS_entry->size;
	//myds=__myds;
	enum mysql_data_stream_status *DSS=&(*myds)->DSS;

	mysql_hdr hdr;
	unsigned char cmd;
	unsigned char *payload;
	int from=(*myds)->myds_type;	// if the packet is from client or server
	enum MySQL_response_type c;

	payload=pkt+sizeof(mysql_hdr);
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	//Copy4B(&hdr,pkt);
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"MySQL Packet length=%d, senquence_id=%d, addr=%p\n", hdr.pkt_length, hdr.pkt_id, payload);

	switch (*DSS) {

		// client is not connected yet
		case STATE_NOT_CONNECTED:
			if (from==MYDS_FRONTEND) { // at this stage we expect a packet from the server, not from client
				return PKT_ERROR;
			}
			if (pkt_handshake_server(payload, hdr.pkt_length, this)==PKT_PARSED) {
				*DSS=STATE_SERVER_HANDSHAKE;
				return PKT_PARSED;
			}
			break;

		// server has sent the handshake
		case STATE_SERVER_HANDSHAKE:
			if (from==MYDS_BACKEND) {
				return PKT_ERROR;
			}
			if (pkt_handshake_client(payload, hdr.pkt_length)==PKT_PARSED) {
				*DSS=STATE_CLIENT_HANDSHAKE;
				return PKT_PARSED;
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
//static uint16_t server_capabilities=CLIENT_FOUND_ROWS | CLIENT_PROTOCOL_41 | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB | CLIENT_SSL;
static uint8_t server_language=33;
static uint16_t server_status=1;
//static char *mysql_server_version = (char *)"5.1.30";

/*
//void MySQL_Protocol::generate_server_handshake(MySQL_Data_Stream *myds) {
void MySQL_Protocol::generate_server_handshake() {
	(*myds)->DSS=STATE_SERVER_HANDSHAKE;
  //proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
  proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating handshake pkt\n");
  mysql_hdr myhdr;
  myhdr.pkt_id=0;
  //myhdr.pkt_length=sizeof(glovars.protocol_version)
  myhdr.pkt_length=sizeof(protocol_version)
  //  + (strlen(glovars.mysql_server_version)+1)
    + (strlen(mysql_server_version)+1)
    + sizeof(uint32_t)  // thread_id
    + 8  // scramble1
    + 1  // 0x00
    //+ sizeof(glovars.server_capabilities)
    //+ sizeof(glovars.server_language)
    //+ sizeof(glovars.server_status)
    + sizeof(server_capabilities)
    + sizeof(server_language)
    + sizeof(server_status)
    + 3 // unknown stuff
    + 10 // filler
    + 12 // scramble2
    + 1  // 0x00
    + (strlen("mysql_native_password")+1);

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  //mypkt->data=g_slice_alloc0(mypkt->length);
  //mypkt->data=l_alloc0(thrLD->sfp, mypkt->length);
  unsigned char *ptr=(unsigned char *)l_alloc(size);
  memcpy(ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(ptr, &myhdr);
  int l;
  l=sizeof(mysql_hdr);
  //srand(pthread_self());
  //uint32_t thread_id=rand()%100000;
  //uint32_t thread_id=__sync_fetch_and_add(&glovars.thread_id,1);
  uint32_t thread_id=pthread_self();

  rand_struct rand_st;
  //randominit(&rand_st,rand(),rand());
  rand_st.max_value= 0x3FFFFFFFL;
  rand_st.max_value_dbl=0x3FFFFFFFL;
  rand_st.seed1=rand()%rand_st.max_value;
  rand_st.seed2=rand()%rand_st.max_value;

  memcpy(ptr+l, &protocol_version, sizeof(protocol_version)); l+=sizeof(protocol_version);
  memcpy(ptr+l, mysql_server_version, strlen(mysql_server_version)); l+=strlen(mysql_server_version)+1;
  memcpy(ptr+l, &thread_id, sizeof(uint32_t)); l+=sizeof(uint32_t);
#ifdef MARIADB_BASE_VERSION
  proxy_create_random_string((*myds)->myconn->myconn.scramble_buff+0,8,(struct my_rnd_struct *)&rand_st);
#else
  proxy_create_random_string((*myds)->myconn->myconn.scramble_buff+0,8,(struct rand_struct *)&rand_st);
#endif

  int i;
  for (i=0;i<8;i++) {
    if ((*myds)->myconn->myconn.scramble_buff[i]==0) {
      (*myds)->myconn->myconn.scramble_buff[i]='a';
    }
  }

  memcpy(ptr+l, (*myds)->myconn->myconn.scramble_buff+0, 8); l+=8;
  l+=1; //0x00
  memcpy(ptr+l,&server_capabilities, sizeof(server_capabilities)); l+=sizeof(server_capabilities);
  memcpy(ptr+l,&server_language, sizeof(server_language)); l+=sizeof(server_language);
  memcpy(ptr+l,&server_status, sizeof(server_status)); l+=sizeof(server_status);
  memcpy(ptr+l,"\x0f\x80\x15",3); l+=3;
  l+=10; //filler
  //create_random_string(mypkt->data+l,12,(struct my_rnd_struct *)&rand_st); l+=12;
#ifdef MARIADB_BASE_VERSION
  proxy_create_random_string((*myds)->myconn->myconn.scramble_buff+8,12,(struct my_rnd_struct *)&rand_st);
#else
  proxy_create_random_string((*myds)->myconn->myconn.scramble_buff+8,12,(struct rand_struct *)&rand_st);
#endif
  //create_random_string(scramble_buf+8,12,&rand_st);

  for (i=8;i<20;i++) {
    if ((*myds)->myconn->myconn.scramble_buff[i]==0) {
      (*myds)->myconn->myconn.scramble_buff[i]='a';
    }
  }

  memcpy(ptr+l, (*myds)->myconn->myconn.scramble_buff+8, 12); l+=12;
  l+=1; //0x00
  memcpy(ptr+l,"mysql_native_password",strlen("mysql_native_password"));
	(*myds)->PSarrayOUT->add((void *)ptr,size);
}
*/


//bool MySQL_Protocol::generate_statistics_response(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len) {
bool MySQL_Protocol::generate_statistics_response(bool send, void **ptr, unsigned int *len) {
// FIXME : this function generates a not useful string. It is a placeholder for now

	const char *stats=(char *)"Uptime: 1000  Threads: 1  Questions: 34221015  Slow queries: 0  Opens: 757  Flush tables: 1  Open tables: 185  Queries per second avg: 22.289";

	unsigned char statslen=strlen(stats);
	mysql_hdr myhdr;
	myhdr.pkt_id=1;
	//myhdr.pkt_length=statslen+1;
	myhdr.pkt_length=statslen;
	

	
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
  int l=sizeof(mysql_hdr);
	//_ptr[l++]=statslen;
	memcpy(_ptr+l,stats,statslen);	

	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

//bool MySQL_Protocol::generate_pkt_EOF(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t warnings, uint16_t status) {
bool MySQL_Protocol::generate_pkt_EOF(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t warnings, uint16_t status) {
	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=5;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
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

//bool MySQL_Protocol::generate_pkt_ERR(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t error_code, char *sql_state, char *sql_message) {
bool MySQL_Protocol::generate_pkt_ERR(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t error_code, char *sql_state, char *sql_message) {
	mysql_hdr myhdr;
	uint32_t sql_message_len=( sql_message ? strlen(sql_message) : 0 );
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=1+sizeof(uint16_t)+1+5+sql_message_len;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
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
			case STATE_QUERY_SENT:
				(*myds)->DSS=STATE_ERR;
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


//bool MySQL_Protocol::generate_pkt_OK(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len, uint8_t sequence_id, unsigned int affected_rows, unsigned int last_insert_id, uint16_t status, uint16_t warnings, char *msg) {
bool MySQL_Protocol::generate_pkt_OK(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, unsigned int affected_rows, unsigned int last_insert_id, uint16_t status, uint16_t warnings, char *msg) {

	char affected_rows_prefix;
	uint8_t affected_rows_len=mysql_encode_length(affected_rows, &affected_rows_prefix);
	char last_insert_id_prefix;
	uint8_t last_insert_id_len=mysql_encode_length(last_insert_id, &last_insert_id_prefix);
	uint32_t msg_len=( msg ? strlen(msg) : 0 );

	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=1+affected_rows_len+last_insert_id_len+sizeof(uint16_t)+sizeof(uint16_t)+msg_len;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
  int l=sizeof(mysql_hdr);
	_ptr[l]=0x00; l++;
/*
	if (affected_rows_len > 1) {
		_ptr[l]=affected_rows_prefix; l++;
	}
	memcpy(_ptr+l, &affected_rows, affected_rows_len); l+=( affected_rows_len > 1 ? affected_rows_len - 1 : 1 ); 
	if (last_insert_id_len > 1) {
		_ptr[l]=last_insert_id_prefix; l++;
	}
	memcpy(_ptr+l, &last_insert_id, last_insert_id_len); l+=( last_insert_id_len > 1 ? last_insert_id_len -1 : 1 );
*/
	l+=write_encoded_length(_ptr+l, affected_rows, affected_rows_len, affected_rows_prefix);
	l+=write_encoded_length(_ptr+l, last_insert_id, last_insert_id_len, last_insert_id_prefix);
	memcpy(_ptr+l, &status, sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l, &warnings, sizeof(uint16_t)); l+=sizeof(uint16_t);
	if (msg) memcpy(_ptr+l, msg, msg_len);
	
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		switch ((*myds)->DSS) {
			case STATE_CLIENT_HANDSHAKE:
			case STATE_QUERY_SENT:
				(*myds)->DSS=STATE_OK;
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

//bool MySQL_Protocol::generate_COM_QUIT(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len) {
bool MySQL_Protocol::generate_COM_QUIT(bool send, void **ptr, unsigned int *len) {
	mysql_hdr myhdr;
	myhdr.pkt_id=0;
	myhdr.pkt_length=1;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
  int l=sizeof(mysql_hdr);
	_ptr[l]=0x01; l++;
	
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
	return true;
}

//bool MySQL_Protocol::generate_COM_INIT_DB(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len, char *schema) {
bool MySQL_Protocol::generate_COM_INIT_DB(bool send, void **ptr, unsigned int *len, char *schema) {
	uint32_t schema_len=strlen(schema);
	mysql_hdr myhdr;
	myhdr.pkt_id=0;
	myhdr.pkt_length=1+schema_len;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
  int l=sizeof(mysql_hdr);
	_ptr[l]=0x02; l++;
	memcpy(_ptr+l, schema, schema_len);
	
	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

//bool MySQL_Protocol::generate_COM_PING(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len) {
bool MySQL_Protocol::generate_COM_PING(bool send, void **ptr, unsigned int *len) {
	mysql_hdr myhdr;
	myhdr.pkt_id=0;
	myhdr.pkt_length=1;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
  int l=sizeof(mysql_hdr);
	_ptr[l]=0x0e; l++;
	
	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

//bool MySQL_Protocol::generate_COM_RESET_CONNECTION(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len) {
bool MySQL_Protocol::generate_COM_RESET_CONNECTION(bool send, void **ptr, unsigned int *len) {
	mysql_hdr myhdr;
	myhdr.pkt_id=0;
	myhdr.pkt_length=1;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
  int l=sizeof(mysql_hdr);
	_ptr[l]=0x1f; l++;
	
	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

//bool MySQL_Protocol::generate_pkt_column_count(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint64_t count) {
bool MySQL_Protocol::generate_pkt_column_count(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint64_t count) {

	char count_prefix=0;
	uint8_t count_len=mysql_encode_length(count, &count_prefix);

	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=count_len;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
  int l=sizeof(mysql_hdr);


/*
	if (count_len > 1) {
		_ptr[l]=count_prefix; l++;
	}
	memcpy(_ptr+l, &count, count_len); l+=( count_len > 1 ? count_len -1 : 1 );
*/

	l+=write_encoded_length(_ptr+l, count, count_len, count_prefix);

	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}


//bool MySQL_Protocol::generate_pkt_field(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len, uint8_t sequence_id, char *schema, char *table, char *org_table, char *name, char *org_name, uint16_t charset, uint32_t column_length, uint8_t type, uint16_t flags, uint8_t decimals, bool field_list, uint64_t defvalue_length, char *defvalue) {
bool MySQL_Protocol::generate_pkt_field(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, char *schema, char *table, char *org_table, char *name, char *org_name, uint16_t charset, uint32_t column_length, uint8_t type, uint16_t flags, uint8_t decimals, bool field_list, uint64_t defvalue_length, char *defvalue) {

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


bool MySQL_Protocol::generate_pkt_row(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, int colnums, int *fieldslen, char **fieldstxt) {
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

//bool MySQL_Protocol::generate_pkt_handshake_response(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len) {
bool MySQL_Protocol::generate_pkt_handshake_response(bool send, void **ptr, unsigned int *len) {
  proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating response handshake pkt\n");
  mysql_hdr myhdr;
  myhdr.pkt_id=1;


	uint32_t capabilities = CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG | CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS | CLIENT_PS_MULTI_RESULTS ;
	uint32_t max_allowed_packet=1*1024*1024;
	uint8_t charset=21;
	uint8_t _tmp;
/*
  pkt     += sizeof(mysql_hdr);
  capabilities     = CPY4(pkt);
  pkt     += sizeof(uint32_t);
  max_pkt  = CPY4(pkt);
  pkt     += sizeof(uint32_t);
  charset  = *(uint8_t *)pkt;
  pkt     += 24;
  user     = pkt;
  pkt     += strlen((char *)user) + 1;

  pass_len = (capabilities & CLIENT_SECURE_CONNECTION ? *pkt++ : strlen((char *)pkt));
  memcpy(pass, pkt, pass_len);
  pass[pass_len] = 0;

  pkt += pass_len;
  db = (capabilities & CLIENT_CONNECT_WITH_DB ? pkt : 0);
*/
	
	myhdr.pkt_length= 0
		+ sizeof(uint32_t) // capabilities
		+ sizeof(uint32_t) // max_allowed_packet
		+ sizeof(uint8_t)	 // charset
		+ 23							 // padding
		+ strlen(userinfo->username)+1 // user
		+ ( strlen(userinfo->password) ? 21 : 1 )
		+ strlen(userinfo->schemaname) + 1
		+ strlen((char *)"mysql_native_password") + 1;

	//MYSQL &myc=(*myds)->myconn->myconn;

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
  int l=sizeof(mysql_hdr);
	memcpy(_ptr+l,&capabilities,sizeof(uint32_t)); l+=sizeof(uint32_t);
	memcpy(_ptr+l,&max_allowed_packet,sizeof(uint32_t)); l+=sizeof(uint32_t);
	_ptr[l]=charset; l++;
	memset(_ptr+l,0,23); l+=23;
	_tmp=strlen(userinfo->username);
	//_ptr[l]=_tmp; l++;
	if (_tmp) {
		memcpy(_ptr+l,userinfo->username,_tmp); l+=_tmp;
	}
	_ptr[l++]=0;
	if (strlen(userinfo->password)) {
		_ptr[l++]=20;
		char reply[SHA_DIGEST_LENGTH+1];
  	reply[SHA_DIGEST_LENGTH]='\0';
    proxy_scramble(reply, (*myds)->myconn->scramble_buff, userinfo->password);
		memcpy(_ptr+l,reply,20); l+=20;
	} else {
		_ptr[l++]=0;
	}
	_tmp=strlen(userinfo->schemaname);
	memcpy(_ptr+l,userinfo->schemaname,_tmp+1);
	l+=_tmp+1;
	memcpy(_ptr+l,(char *)"mysql_native_password",strlen((char *)"mysql_native_password")+1);

	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif

	return true;
}

//bool MySQL_Protocol::generate_pkt_initial_handshake(MySQL_Data_Stream *myds, bool send, void **ptr, unsigned int *len) {
bool MySQL_Protocol::generate_pkt_initial_handshake(bool send, void **ptr, unsigned int *len) {
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
    + sizeof(server_language)
    + sizeof(server_status)
    + 3 // unknown stuff
    + 10 // filler
    + 12 // scramble2
    + 1  // 0x00
    + (strlen("mysql_native_password")+1);

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  //mypkt->data=g_slice_alloc0(mypkt->length);
  //mypkt->data=l_alloc0(thrLD->sfp, mypkt->length);
  unsigned char *_ptr=(unsigned char *)l_alloc0(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  //Copy4B(_ptr, &myhdr);
  int l;
  l=sizeof(mysql_hdr);
  //srand(pthread_self());
  //uint32_t thread_id=rand()%100000;
  uint32_t thread_id=__sync_fetch_and_add(&glovars.thread_id,1);
  //uint32_t thread_id=pthread_self();

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
  memcpy(_ptr+l,&mysql_thread___server_capabilities, sizeof(mysql_thread___server_capabilities)); l+=sizeof(mysql_thread___server_capabilities);
  memcpy(_ptr+l,&server_language, sizeof(server_language)); l+=sizeof(server_language);
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


//bool MySQL_Protocol::process_pkt_OK(MySQL_Data_Stream *myds, unsigned char *pkt, unsigned int len) {
bool MySQL_Protocol::process_pkt_OK(unsigned char *pkt, unsigned int len) {

  if (len < 11) return false;

  mysql_hdr hdr;
  memcpy(&hdr,pkt,sizeof(mysql_hdr));
  pkt     += sizeof(mysql_hdr);

	if (*pkt) return false;
	if (len!=hdr.pkt_length+sizeof(mysql_hdr)) return false;

	//MYSQL &myc=(*myds)->myconn->myconn;

	uint64_t affected_rows;
	uint64_t  insert_id;
	//uint16_t  status;
	uint16_t  warns;
	unsigned char msg[len];

	unsigned int p=0;
	int rc;

   //field_count = (u_int)*pkt++;
	pkt++; p++;
	rc=mysql_decode_length(pkt,&affected_rows);
	pkt += rc; p+=rc;
	rc=mysql_decode_length(pkt,&insert_id);
	pkt += rc; p+=rc;
	prot_status=CPY2(pkt);
	pkt+=sizeof(uint16_t);
	p+=sizeof(uint16_t);
	warns=CPY2(pkt);
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

//bool MySQL_Protocol::process_pkt_COM_QUERY(MySQL_Data_Stream *myds, unsigned char *pkt, unsigned int len) {
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

//bool MySQL_Protocol::process_pkt_initial_handshake(MySQL_Data_Stream *myds, unsigned char *pkt, unsigned int len) {
bool MySQL_Protocol::process_pkt_initial_handshake(unsigned char *pkt, unsigned int len) {
	//return PKT_PARSED;
	bool ret=false;
	mysql_hdr hdr;
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	//Copy4B(&hdr,pkt);
	pkt     += sizeof(mysql_hdr);
	//MYSQL &myc=(*myds)->myconn->myconn;

	if (*pkt != 0x0A || len < 33) goto exit_process_pkt_initial_handshake;

	uint8_t protocol;
	uint16_t capabilities;
	uint8_t charset;
	//uint16_t status;
	uint32_t thread_id;

	unsigned char * version;
	unsigned char * salt1;
	unsigned char * salt2;

	protocol = *(uint8_t *)pkt;
	pkt      += sizeof(uint8_t);
	version   = pkt;
	pkt      += strlen((char *)version) + 1;
	thread_id = CPY4(pkt);
	pkt      += sizeof(uint32_t);
	salt1     = pkt;
	pkt      += strlen((char *)salt1) + 1;
	capabilities = CPY2(pkt);
	pkt    += sizeof(uint16_t);
	charset = *(uint8_t *)pkt;
	pkt    += sizeof(uint8_t);
	prot_status  = CPY2(pkt);
	pkt    += 15; // 2 for status, 13 for zero-byte padding
	salt2   = pkt;

	// FIXME: the next two lines are here just to prevent this: warning: variable ‘salt2’ set but not used [-Wunused-but-set-variable]
	// salt2 needs to be handled
	salt2++;
	salt2 = pkt;
	

   proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"Handshake <proto:%u ver:\"%s\" thd:%d cap:%d char:%d status:%d>\n", protocol, version, thread_id, capabilities, charset, prot_status);
//   if(op.verbose) unmask_caps(caps);



	(*myds)->myconn->options.server_capabilities=capabilities;
	//myc.charset=(const charset_info_st *)l_alloc(sizeof(struct charset_info_st));
	//myc.charset=(const charset_info_st *)malloc(sizeof(struct charset_info_st));
	//const_cast<charset_info_st *>(myc.charset)->nr=charset;
	//myc.thread_id=thread_id;
	//myc.server_version=l_strdup((const char *)version);
	(*myds)->myconn->options.server_version=strdup((const char *)version);
	(*myds)->myconn->options.protocol_version=protocol;
	(*myds)->myconn->options.charset=charset;
	
	memcpy((*myds)->myconn->scramble_buff,(const char *)salt1,strlen((char *)salt1));
	memcpy((*myds)->myconn->scramble_buff+strlen((char *)salt1),(const char *)salt2,strlen((char *)salt2));	

	ret=true;

exit_process_pkt_initial_handshake:
   return ret;

}

//bool MySQL_Protocol::process_pkt_handshake_response(MySQL_Data_Stream *myds, unsigned char *pkt, unsigned int len) {
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
	bool transaction_persistent;
	password=GloMyAuth->lookup((char *)user, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, &transaction_persistent);
	//assert(default_hostgroup>=0);
	(*myds)->sess->default_hostgroup=default_hostgroup;
	(*myds)->sess->transaction_persistent=transaction_persistent;
	if (password==NULL) {
		ret=false;
	} else {
		if (pass_len==0 && strlen(password)==0) {
			ret=true;
		} else {
			proxy_scramble(reply, (*myds)->myconn->scramble_buff, password);
			if (memcmp(reply, pass, SHA_DIGEST_LENGTH)==0) {
				ret=true;
			}
		}
		if (_ret_use_ssl==true) {
			// if we reached here, use_ssl is false , but _ret_use_ssl is true
			// it means that a client is required to use SSL , but it is not
			ret=false;
		}
	}
	}
  proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"Handshake (%s auth) <user:\"%s\" pass:\"%s\" scramble:\"%s\" db:\"%s\" max_pkt:%u>, capabilities:%u char:%u, use_ssl:%s\n",
            (capabilities & CLIENT_SECURE_CONNECTION ? "new" : "old"), user, password, pass, db, max_pkt, capabilities, charset, ((*myds)->encrypted ? "yes" : "no"));

#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,len); }
#endif

	if (use_ssl) return true;

	if (ret==true) {
		//MYSQL &myc=(*myds)->myconn->myconn;
		//myc.user=strdup((const char *)user);
		//if (password) myc.passwd=strdup(password);
		//if (db) myc.db=strdup((const char *)db);
/*
		myc.user=l_strdup((const char *)user);
		if (password) myc.passwd=l_strdup(password);
		if (db) myc.db=l_strdup((const char *)db);
*/
		//myc.server_capabilities=capabilities;
		//myc.charset=(const charset_info_st *)malloc(sizeof(struct charset_info_st));
//		myc.charset=(const charset_info_st *)l_alloc(sizeof(struct charset_info_st));
		//onst_cast<charset_info_st *>(myc.charset)->nr=charset;
		//myds->myconn->myconn


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
	//if (password) free(password);
	if (password) l_free_string(password);

	//l_free(len,pkt);
	return ret;
}

//uint16_t get_status(unsigned char *pkt, unsigned int len) {
//}
