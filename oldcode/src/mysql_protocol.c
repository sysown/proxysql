#include "proxysql.h"



void send_auth_pkt(mysql_session_t *sess) {
	pkt *hs;
	hs=mypkt_alloc();
	create_handshake_packet(hs,sess->scramble_buf);
	MY_SESS_ADD_PKT_OUT_CLIENT(hs);
}


char *user_password(char *username, int admin) {
	char *ret=NULL; char *pass=NULL;
	if (admin==1) {
		if (strncmp(username,glovars.proxy_admin_user,strlen(glovars.proxy_admin_user))==0) {
			pass=strdup(glovars.proxy_admin_password);
			return pass;
		} else {
			return NULL;
		}
	}
	if (admin==2) {
		if (strncmp(username,glovars.proxy_monitor_user,strlen(glovars.proxy_monitor_user))==0) {
			pass=strdup(glovars.proxy_monitor_password);
			return pass;
		} else {
			return NULL;
		}
	}
	pthread_rwlock_rdlock(&glovars.rwlock_usernames);
	ret=g_hash_table_lookup(glovars.usernames,username);
	if (ret) {
		pass=strdup(ret);
	}
	pthread_rwlock_unlock(&glovars.rwlock_usernames);
	return pass;
}



//inline int mysql_pkt_get_size (pkt *p) {
//	return p->length-sizeof(mysql_hdr);
//}



uint16_t status_flags(pkt *p) {
	int offset;
	enum MySQL_response_type c;
	c=mysql_response(p);
	unsigned long v;
	uint16_t status;
	status=0;
	offset=1+sizeof(mysql_hdr);
	v=0;
	if (c==OK_Packet) {
		// affected rows
		//memcpy(&v,p->data+offset,sizeof(unsigned long));
		MEM_COPY_FWD(&v,p->data+offset,sizeof(unsigned long));
		offset+=lencint(lencint_unknown(v));
		// last insert id
		//memcpy(&v,p->data+offset,sizeof(unsigned long));
		MEM_COPY_FWD(&v,p->data+offset,sizeof(unsigned long));
		offset+=lencint(lencint_unknown(v));
		//offset+=lencint(v);
		//memcpy(&status,p->data+offset,sizeof(uint16_t));	
		MEM_COPY_FWD(&status,p->data+offset,sizeof(uint16_t));
	};
	if (c==EOF_Packet) {
		// warning counts
		offset+=2;
		//memcpy(&status,p->data+offset,sizeof(uint16_t));
		MEM_COPY_FWD(&status,p->data+offset,sizeof(uint16_t));
	}
	//fprintf(stderr,"Status = %d\n", status);
	if (status < 3) {
		PROXY_TRACE();
	}
	return status;
}

int is_transaction_active(pkt *p) {
	uint16_t status=0;
	status=status_flags(p);
	if ((status & SERVER_STATUS_IN_TRANS)==SERVER_STATUS_IN_TRANS) { return 1; }
	return 0;	
}

enum MySQL_response_type mysql_response(pkt *p) {
	unsigned char c=*((char *)p->data+sizeof(mysql_hdr));
	switch (c) {
		case 0:
			proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Packet OK_Packet\n");
			return OK_Packet;
		case 0xff:
			proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Packet ERR_Packet\n");
			return ERR_Packet;
		case 0xfe:
			if ((p->length-sizeof(mysql_hdr)) < 9) {
				proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Packet EOF_Packet\n");
				return EOF_Packet;
			}
		default:
			proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Packet UNKNOWN_Packet\n");
			return UNKNOWN_Packet;
	}
}


int parse_change_user_packet(pkt *mypkt, mysql_session_t *sess) {
	// FIXME: very buggy function, it doesn't perform any real check
	int ret=-1;
	int cur=sizeof(mysql_hdr);
	cur+=1;
	g_free(sess->mysql_username);
	char *ptr=mypkt->data+cur;
	sess->mysql_username=g_strdup(ptr);
	cur+=strlen(sess->mysql_username);
	cur+=2;
	//memcpy(sess->scramble_buf,mypkt->data+cur,20);
	cur+=20;
	g_free(sess->mysql_schema_cur);
	ptr=mypkt->data+cur;
	sess->mysql_schema_cur=g_strdup(ptr);
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "CHANGE USER: Username %s , schema %s\n" , sess->mysql_username, sess->mysql_schema_cur);
	ret=0;
	return ret;
}

void create_auth_switch_request_packet(pkt *mypkt, mysql_session_t *sess) {
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 7, "Generating auth switch request pkt\n");
	mysql_hdr myhdr;
	myhdr.pkt_id=1;
	myhdr.pkt_length=1 // fe
		+ (strlen("mysql_native_password")+1)
		+ 20 // scramble
		+ 1; // 00
	mypkt->length=myhdr.pkt_length+sizeof(mysql_hdr);
	mypkt->data=l_alloc0(mypkt->length);
	memcpy(mypkt->data, &myhdr, sizeof(mysql_hdr));
	int cur=sizeof(mysql_hdr);
	memcpy(mypkt->data+cur,"\xfe",1);
	cur++;
	memcpy(mypkt->data+cur,"mysql_native_password",strlen("mysql_native_password"));
	cur+=strlen("mysql_native_password");
	memcpy(mypkt->data+cur,"\x00",1);
	cur++;
	memcpy(mypkt->data+cur, sess->scramble_buf, 20);
	cur+=20;
	memcpy(mypkt->data+cur,"\x00",1);
}


int check_auth_switch_response_packet(pkt *mypkt, mysql_session_t *sess) {
	int ret=-1;
	sess->waiting_change_user_response=0;
	if (mypkt->length!=sizeof(mysql_hdr)+20) {
		return ret;
	}
	mysql_hdr myhdr;
	memcpy(&myhdr, mypkt->data, sizeof(mysql_hdr));
	if (myhdr.pkt_length!=20) {
		return ret;
	}
	free(sess->mysql_password);
	sess->mysql_password=user_password(sess->mysql_username, sess->admin);
	if (sess->mysql_password==NULL)	 {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 4, "Username %s does not exist\n" , sess->mysql_username);
		return ret;
	}
	unsigned char *scramble_reply=NULL;
	scramble_reply=mypkt->data+sizeof(mysql_hdr);
	char reply[SHA_DIGEST_LENGTH+1];
	reply[SHA_DIGEST_LENGTH]='\0';
	if (scramble_reply) {
		proxy_scramble(reply, sess->scramble_buf, sess->mysql_password);
		if (memcmp(reply,scramble_reply,SHA_DIGEST_LENGTH)==0) {
			ret=0;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 6, "Password match!\n");
		}
	} else {
		if (strcmp(sess->mysql_password,"")==0) {
			ret=0;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 4, "Empty password match!\n");
		}
	}
	return ret;
}

int check_client_authentication_packet(pkt *mypkt, mysql_session_t *sess) {
	// WARNING : for now it only checks the password
	int ret=-1;
	uint32_t capabilities;
	int cur=sizeof(mysql_hdr);
	memcpy(&capabilities,mypkt->data+cur,sizeof(uint32_t));
	cur+=32;
	char *username=mypkt->data+cur;
	sess->mysql_username=g_strdup(username);
	unsigned char *scramble_reply=NULL;
	cur+=strlen(username);
	cur++;
	unsigned char c=*((unsigned char *)mypkt->data+cur);
	cur++;
	if (c) {
		scramble_reply=mypkt->data+cur;
		cur+=c;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 4,"Username = %s\n" , username);
	sess->mysql_password=user_password(username, sess->admin);
	if (sess->mysql_password==NULL)	 {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 4, "Username %s does not exist\n" , username);
		return ret;
	}
	//proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 4, "Password in hash table = %s\n" , sess->mysql_password);
	char reply[SHA_DIGEST_LENGTH+1];
	reply[SHA_DIGEST_LENGTH]='\0';
	if (scramble_reply) {
		proxy_scramble(reply, sess->scramble_buf, sess->mysql_password);
		if (memcmp(reply,scramble_reply,SHA_DIGEST_LENGTH)==0) {
			ret=0;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 6, "Password match!\n");
		}
	} else {
		if (strcmp(sess->mysql_password,"")==0) {
			ret=0;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 4, "Empty password match!\n");
		}
	}
	if (!ret) {
		if(cur!=mypkt->length) { // we aren't at the end of the packet
			if (( capabilities & CLIENT_CONNECT_WITH_DB ) == CLIENT_CONNECT_WITH_DB) {
				sess->mysql_schema_cur=g_strdup(mypkt->data+cur);
				cur+=strlen(sess->mysql_schema_cur);
			}
//			if ((cur==(mypkt->length-1)) || (strlen(sess->mysql_schema_cur)==0) ) {
//				free(sess->mysql_schema_cur);
//				sess->mysql_schema_cur=NULL;
//			}
		}
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 6, "Username = %s, schema = %s pkt_length = %d\n" , username, sess->mysql_schema_cur, mypkt->length);
	}
	return ret;
}


void create_handshake_packet(pkt *mypkt, char *scramble_buf) {
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating handshake pkt\n");
	mysql_hdr myhdr;
	myhdr.pkt_id=0;
	myhdr.pkt_length=sizeof(glovars.protocol_version)
		+ (strlen(glovars.mysql_server_version)+1)
		+ sizeof(uint32_t)  // thread_id
		+ 8  // scramble1
		+ 1  // 0x00
		+ sizeof(glovars.server_capabilities)
		+ sizeof(glovars.server_language)
		+ sizeof(glovars.server_status)
		+ 3 // unknown stuff
		+ 10 // filler
		+ 12 // scramble2
		+ 1  // 0x00
		+ (strlen("mysql_native_password")+1);

	mypkt->length=myhdr.pkt_length+sizeof(mysql_hdr);
	//mypkt->data=g_slice_alloc0(mypkt->length);
	//mypkt->data=l_alloc0(thrLD->sfp, mypkt->length);
	mypkt->data=l_alloc0(mypkt->length);
	memcpy(mypkt->data, &myhdr, sizeof(mysql_hdr));
	int l;
	l=sizeof(mysql_hdr);
	//srand(pthread_self());
	//uint32_t thread_id=rand()%100000;
	//uint32_t thread_id=__sync_fetch_and_add(&glovars.thread_id,1);
	uint32_t thread_id=pthread_self();

	rand_struct_t rand_st;
	//randominit(&rand_st,rand(),rand());
	rand_st.max_value= 0x3FFFFFFFL;
	rand_st.max_value_dbl=0x3FFFFFFFL;
	rand_st.seed1=rand()%rand_st.max_value;
	rand_st.seed2=rand()%rand_st.max_value;

	memcpy(mypkt->data+l, &glovars.protocol_version, sizeof(glovars.protocol_version)); l+=sizeof(glovars.protocol_version);
	memcpy(mypkt->data+l, glovars.mysql_server_version, strlen(glovars.mysql_server_version)); l+=strlen(glovars.mysql_server_version)+1;
	memcpy(mypkt->data+l, &thread_id, sizeof(uint32_t)); l+=sizeof(uint32_t);
#ifdef MARIADB_BASE_VERSION
	proxy_create_random_string(scramble_buf+0,8,(struct my_rnd_struct *)&rand_st);
#else
	proxy_create_random_string(scramble_buf+0,8,(struct rand_struct *)&rand_st);
#endif
	
	int i;
	for (i=0;i<8;i++) {
		if (scramble_buf[i]==0) {
			scramble_buf[i]='a';
		}
	}
	
	memcpy(mypkt->data+l, scramble_buf+0, 8); l+=8;
	l+=1; //0x00
	memcpy(mypkt->data+l,&glovars.server_capabilities, sizeof(glovars.server_capabilities)); l+=sizeof(glovars.server_capabilities);
	memcpy(mypkt->data+l,&glovars.server_language, sizeof(glovars.server_language)); l+=sizeof(glovars.server_language);
	memcpy(mypkt->data+l,&glovars.server_status, sizeof(glovars.server_status)); l+=sizeof(glovars.server_status);
	memcpy(mypkt->data+l,"\x0f\x80\x15",3); l+=3;
	l+=10; //filler
	//create_random_string(mypkt->data+l,12,(struct my_rnd_struct *)&rand_st); l+=12;
#ifdef MARIADB_BASE_VERSION
	proxy_create_random_string(scramble_buf+8,12,(struct my_rnd_struct *)&rand_st);
#else
	proxy_create_random_string(scramble_buf+8,12,(struct rand_struct *)&rand_st);
#endif
	//create_random_string(scramble_buf+8,12,&rand_st);

	for (i=8;i<20;i++) {
		if (scramble_buf[i]==0) {
			scramble_buf[i]='a';
		}
	}

	memcpy(mypkt->data+l, scramble_buf+8, 12); l+=12;
	l+=1; //0x00
	memcpy(mypkt->data+l,"mysql_native_password",strlen("mysql_native_password"));
}



void create_ok_packet(pkt *mypkt, unsigned int id) {
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating OK pkt . id %d\n", id);
	mysql_hdr myhdr;
	myhdr.pkt_id=id;
	myhdr.pkt_length=7;
	mypkt->length=myhdr.pkt_length+sizeof(mysql_hdr);
	//mypkt->data=g_slice_alloc(mypkt->length);
	//mypkt->data=l_alloc(thrLD->sfp, mypkt->length);
	mypkt->data=l_alloc(mypkt->length);
	memcpy(mypkt->data, &myhdr, sizeof(mysql_hdr));
	memcpy(mypkt->data+sizeof(mysql_hdr),"\x00\x00\x00\x02\x00\x00\x00",7);
}

void create_err_packet(pkt *mypkt, unsigned int id, uint16_t errcode, char *errstr) {
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating ERR pkt . id %d, errcode %d , errstr %s\n", id, errcode, errstr);
	mysql_hdr myhdr;
	myhdr.pkt_id=id;
	myhdr.pkt_length=3+strlen(errstr);
	mypkt->length=myhdr.pkt_length+sizeof(mysql_hdr);
	//mypkt->data=g_slice_alloc(mypkt->length);
	//mypkt->data=l_alloc(thrLD->sfp, mypkt->length);
	mypkt->data=l_alloc(mypkt->length);
	memcpy(mypkt->data, &myhdr, sizeof(mysql_hdr));
	memcpy(mypkt->data+sizeof(mysql_hdr),"\xff",1);
	memcpy(mypkt->data+sizeof(mysql_hdr)+1,&errcode,sizeof(uint16_t));
	memcpy(mypkt->data+sizeof(mysql_hdr)+3,errstr,strlen(errstr));
}

void authenticate_mysql_client_send_OK(mysql_session_t *sess) {
	// prepare an ok packet
	pkt *hs;
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	hs=mypkt_alloc();
	create_ok_packet(hs,2);
	// send it to the client
	write_one_pkt_to_net(sess->client_myds,hs);
}

void authenticate_mysql_client_send_ERR(mysql_session_t *sess, uint16_t errcode, char *errstr) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Sending auth ERR. sess %p , errcode %d , errmsg %s\n", sess, errcode, errstr);
	pkt *hs;
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	hs=mypkt_alloc();
//	create_err_packet(hs, 2, 1045, "#28000Access denied for user");
	create_err_packet(hs, 2, errcode, errstr);
	write_one_pkt_to_net(sess->client_myds,hs);
}

int mysql_check_alive_and_read_only(const char *hostname, uint16_t port) {
	MYSQL *conn=mysql_init(NULL);
	if (conn==NULL) {
		exit(EXIT_FAILURE);
	}
	if (mysql_real_connect(conn, hostname, glovars.mysql_usage_user, glovars.mysql_usage_password, NULL, port, NULL, 0) == NULL) {
		proxy_error("[ERROR]: server %s:%d not alive when trying to connect using %s/%s : %s\n", hostname, port, glovars.mysql_usage_user, glovars.mysql_usage_password, mysql_error(conn));
		mysql_close(conn);
		return -1;
	}
	if (mysql_query(conn,"SHOW GLOBAL VARIABLES LIKE 'read_only'")) {
		mysql_close(conn);
		return -1;
	}
	MYSQL_RES *result = mysql_store_result(conn);
	if (result == NULL) {
		mysql_close(conn);
		return -1;
	}
	int num_rows = mysql_num_rows(result);
	if (num_rows != 1) {
		mysql_close(conn);
		return -1;
	}
	int num_fields = mysql_num_fields(result);
	if (num_fields != 2) {
		mysql_close(conn);
		return -1;
	}
	MYSQL_ROW row;
	row = mysql_fetch_row(result);
	if (row == NULL) {
		mysql_close(conn);
		return -1;
	}
	char *read_only;
	read_only=strdup(row[1]);
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 1, "server %s read_only %s\n" , hostname, read_only);
	int r=1;
	if ((strcmp(read_only,"0") == 0) || (strcmp(read_only,"OFF") == 0)) {
		r=0;
	}
	free(read_only);
	mysql_free_result(result);
	mysql_close(conn);
	return r;
}



void proxy_create_random_string(char *to, uint length, struct rand_struct *rand_st) {
	int i;
	for (i=0; i<length ; i++) {
		*to= (char) (proxy_my_rnd(rand_st) * 94 + 33);
		to++;
	}
	*to= '\0';
}

double proxy_my_rnd(struct rand_struct *rand_st) {
	rand_st->seed1= (rand_st->seed1*3+rand_st->seed2) % rand_st->max_value;
	rand_st->seed2= (rand_st->seed1+rand_st->seed2+33) % rand_st->max_value;
	return (((double) rand_st->seed1) / rand_st->max_value_dbl);
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

void proxy_compute_sha1_hash_multi(uint8 *digest, const char *buf1, int len1, const char *buf2, int len2) {
	PROXY_TRACE();
	/*
	SHA_CTX sha1_context;
	SHA1_Init(&sha1_context);
	SHA1_Update(&sha1_context, buf1, len1);
	SHA1_Update(&sha1_context, buf2, len2);
	SHA1_Final(digest, &sha1_context);
	*/
	GChecksum *sha1_context=g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(sha1_context, (const unsigned char *)buf1, len1);
	g_checksum_update(sha1_context, (const unsigned char *)buf2, len2);
	size_t s=SHA_DIGEST_LENGTH;
	g_checksum_get_digest(sha1_context,digest,&s);
	g_checksum_free(sha1_context);
}


void proxy_compute_two_stage_sha1_hash(const char *password, size_t pass_len, uint8 *hash_stage1, uint8 *hash_stage2) {
  proxy_compute_sha1_hash(hash_stage1, password, pass_len);
  proxy_compute_sha1_hash(hash_stage2, (const char *) hash_stage1, SHA_DIGEST_LENGTH);
}

void proxy_compute_sha1_hash(uint8 *digest, const char *buf, int len) {
	PROXY_TRACE();
	/*
	SHA_CTX sha1_context;
	SHA1_Init(&sha1_context);
	SHA1_Update(&sha1_context, buf, len);
	SHA1_Final(digest, &sha1_context);
	*/
	GChecksum *sha1_context=g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(sha1_context, (const unsigned char *)buf, len);
	size_t s=SHA_DIGEST_LENGTH;
	g_checksum_get_digest(sha1_context,digest,&s);
	g_checksum_free(sha1_context);
	
}


void proxy_my_crypt(char *to, const uchar *s1, const uchar *s2, uint len) {
  const uint8 *s1_end= s1 + len;
  while (s1 < s1_end)
    *to++= *s1++ ^ *s2++;
}

int lencint(uint64_t v) {
	if (v<251) {
		return 1;
	}
	if (v>=251 && v<65536) {
		return 3;
	}
	if (v>=65536 && v<16777216) {
		return 4;
	}
	if (v>=16777216) {
		return 9;
	}
	return 9;
}

uint64_t lencint_unknown(uint64_t v) {
	char c8=v;
	if (c8<251) {return c8;}
	uint32_t c32=0;
	//memcpy(&c32,&v,3);
	MEM_COPY_FWD(&c32,&v,3);
	if (c32 >= 251 && c32<65536) { return c32; }
	c32=v;
	if (c32 >= 65536 && c32<16777216) { return c32; }
	return v;
}

int writeencint(void *ptr, uint64_t v) {
	int l=lencint(v);
	if (l==1) {
		//memcpy(ptr,&v,1);
		MEM_COPY_FWD(ptr,&v,1);
	}
	if (l==3) {
		//memcpy(ptr, "\xfc", 1);
		//memcpy(ptr+1, &v, 2);
		MEM_COPY_FWD(ptr, "\xfc", 1);
		MEM_COPY_FWD(ptr+1, &v, 2);
	}
	if (l==4) {
		//memcpy(ptr, "\xfd", 1);
		//memcpy(ptr+1, &v, 3);
		MEM_COPY_FWD(ptr, "\xfd", 1);
		MEM_COPY_FWD(ptr+1, &v, 3);
	}
	if (l==9) {
		//memcpy(ptr, "\xfe", 1);
		//memcpy(ptr+1, &v, 8);
		MEM_COPY_FWD(ptr, "\xfe", 1);
		MEM_COPY_FWD(ptr+1, &v, 8);
	}
	return l;
}

//int writeencstrnull(void *ptr, const char *s) {
int writeencstrnull(void *ptr, const char *s) {
	if (s==NULL) {
		// NULL
		//memcpy(ptr, "\xfb", 1);
		MEM_COPY_FWD(ptr, "\xfb", 1);
		return 1;
	}
	int l=strlen(s);
	int el=lencint(l);
	if (el==1) {
		//memcpy(ptr,&l,1);
		MEM_COPY_FWD(ptr,&l,1);
	}
	if (el==3) {
		//memcpy(ptr, "\xfc", 1);
		//memcpy(ptr+1, &l, el-1);
		MEM_COPY_FWD(ptr, "\xfc", 1);
		MEM_COPY_FWD(ptr+1, &l, el-1);
	}
	if (el==4) {
		//memcpy(ptr, "\xfd", 1);
		MEM_COPY_FWD(ptr, "\xfd", 1);
	}
	if (el==9) {
		//memcpy(ptr, "\xfe", 1);
		//memcpy(ptr+1, &l, el-1);
		MEM_COPY_FWD(ptr, "\xfe", 1);
		MEM_COPY_FWD(ptr+1, &l, el-1);
	}
	//memcpy(ptr+el,s,l);
	MEM_COPY_FWD(ptr+el,(char *)s,l);
	return l+el;
}



void myproto_ok_pkt(pkt *mypkt, unsigned int id, uint64_t affected_rows, uint64_t last_insert_id, uint16_t status, uint16_t warnings) {
	int i=0;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating OK pkt . id %d, affected_rows %d , last_insert_id %d , status %d , warning %d\n", id, affected_rows, last_insert_id, status, warnings);
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	mysql_hdr myhdr;
	myhdr.pkt_id=id;
	myhdr.pkt_length=1;
	myhdr.pkt_length+=lencint(affected_rows);
	myhdr.pkt_length+=lencint(last_insert_id);
	myhdr.pkt_length+=sizeof(uint16_t);
	myhdr.pkt_length+=sizeof(uint16_t);
	mypkt->length=myhdr.pkt_length+sizeof(mysql_hdr);
	//mypkt->data=g_slice_alloc(mypkt->length);
	//mypkt->data=l_alloc(thrLD->sfp, mypkt->length);
	mypkt->data=l_alloc(mypkt->length);
	memcpy(mypkt->data, &myhdr, sizeof(mysql_hdr));
	i=sizeof(mysql_hdr);
	memcpy(mypkt->data+i, "\x00", 1); // OK header
	i+=1;
	writeencint(mypkt->data+i, affected_rows);
	i+=lencint(affected_rows);
	writeencint(mypkt->data+i, last_insert_id);
	i+=lencint(last_insert_id);
	memcpy(mypkt->data+i, &status, sizeof(uint16_t));
	i+=sizeof(uint16_t);
	memcpy(mypkt->data+i, &warnings, sizeof(uint16_t));
}

void myproto_column_count(pkt *mypkt, unsigned int id, uint64_t cnt) {
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	mysql_hdr myhdr;
	myhdr.pkt_id=id;
	myhdr.pkt_length=0;
	myhdr.pkt_length+=lencint(cnt);
	mypkt->length=myhdr.pkt_length+sizeof(mysql_hdr);
	//mypkt->data=g_slice_alloc(mypkt->length);
	//mypkt->data=l_alloc(thrLD->sfp, mypkt->length);
	mypkt->data=l_alloc(mypkt->length);
	memcpy(mypkt->data, &myhdr, sizeof(mysql_hdr));
	writeencint(mypkt->data+sizeof(mysql_hdr), cnt);
}

void myproto_column_def(pkt *mypkt, unsigned int id, const char *schema, const char *table, const char *org_table, const char *name, const char *org_name, uint32_t column_length, uint8_t column_type, uint16_t flags, uint8_t decimals) {
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	int i;
	int length_schema=strlen(schema);
	int length_table=strlen(table);
	int length_org_table=strlen(org_table);
	int length_name=strlen(name);
	int length_org_name=strlen(org_name);
	mysql_hdr myhdr;
	myhdr.pkt_id=id;
	myhdr.pkt_length=4;
	myhdr.pkt_length+=lencint(length_schema)+length_schema;
	myhdr.pkt_length+=lencint(length_table)+length_table;
	myhdr.pkt_length+=lencint(length_org_table)+length_org_table;
	myhdr.pkt_length+=lencint(length_name)+length_name;
	myhdr.pkt_length+=lencint(length_org_name)+length_org_name;
	myhdr.pkt_length+=1+2;
	myhdr.pkt_length+=sizeof(uint32_t); //column_length
	myhdr.pkt_length+=sizeof(uint8_t); //column_type
	myhdr.pkt_length+=sizeof(uint16_t); //flags
	myhdr.pkt_length+=sizeof(uint8_t); //decimals
	myhdr.pkt_length+=2; //filler
	mypkt->length=myhdr.pkt_length+sizeof(mysql_hdr);
	//mypkt->data=g_slice_alloc(mypkt->length);
	//mypkt->data=l_alloc(thrLD->sfp,mypkt->length);
	mypkt->data=l_alloc(mypkt->length);
	memcpy(mypkt->data, &myhdr, sizeof(mysql_hdr)); i=sizeof(mysql_hdr);
	memcpy(mypkt->data+i,"\x03\x64\x65\x66",4); i+=4;
	i+=writeencstrnull(mypkt->data+i,schema);
	i+=writeencstrnull(mypkt->data+i,table);
	i+=writeencstrnull(mypkt->data+i,org_table);
	i+=writeencstrnull(mypkt->data+i,name);
	i+=writeencstrnull(mypkt->data+i,org_name);
	memcpy(mypkt->data+i,"\x0c\x21\x00",3); i+=3;
	memcpy(mypkt->data+i, &column_length, sizeof(uint32_t)); i+=sizeof(uint32_t);
	memcpy(mypkt->data+i, &column_type, sizeof(uint8_t)); i+=sizeof(uint8_t);
	memcpy(mypkt->data+i, &flags, sizeof(uint16_t)); i+=sizeof(uint16_t);
	memcpy(mypkt->data+i, &decimals, sizeof(uint8_t)); i+=sizeof(uint8_t);
	memcpy(mypkt->data+i,"\x00\x00",2);
}


void myproto_eof(pkt *mypkt, unsigned int id, uint16_t warning_count, uint16_t status_flags) {
	int i;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating EOF pkt . id %d, warning %d , status %d\n", id, warning_count, status_flags);
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	mysql_hdr myhdr;
	myhdr.pkt_id=id;
	myhdr.pkt_length=5;
	mypkt->length=myhdr.pkt_length+sizeof(mysql_hdr);
	//mypkt->data=g_slice_alloc(mypkt->length);
	//mypkt->data=l_alloc(thrLD->sfp,mypkt->length);
	mypkt->data=l_alloc(mypkt->length);
	memcpy(mypkt->data, &myhdr, sizeof(mysql_hdr)); i=sizeof(mysql_hdr);
	memcpy(mypkt->data+i,"\xfe",1); i+=1;
	memcpy(mypkt->data+i,&warning_count,sizeof(uint16_t)); i+=2;
	memcpy(mypkt->data+i,&status_flags,sizeof(uint16_t));
}

void mysql_new_payload_select(pkt *mypkt, void *payload, int len) {
	proxy_debug(PROXY_DEBUG_QUERY_CACHE, 7, "Creating new pkt with SELECT %s\n", (char *)payload);
	int i;
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	mysql_hdr myhdr;
	unsigned char c=MYSQL_COM_QUERY;
	//g_slice_free1(mypkt->length, mypkt->data);
	//l_free(thrLD->sfp,mypkt->length, mypkt->data);
	l_free(mypkt->length, mypkt->data);
	if (len==-1) { len=strlen(payload); }
	myhdr.pkt_id=0;
	myhdr.pkt_length=len+1;
	mypkt->length=myhdr.pkt_length+sizeof(mysql_hdr);
	//mypkt->data=g_slice_alloc(mypkt->length);
	//mypkt->data=l_alloc(thrLD->sfp,mypkt->length);
	mypkt->data=l_alloc(mypkt->length);
	memcpy(mypkt->data, &myhdr, sizeof(mysql_hdr)); i=sizeof(mysql_hdr);
	memcpy(mypkt->data+i,&c,1); i+=1;
	memcpy(mypkt->data+i,payload,len);	
}	
