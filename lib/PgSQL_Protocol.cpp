//#include <openssl/rand.h>
#include "proxysql.h"
#include "cpp.h"
/*
#include "re2/re2.h"
#include "re2/regexp.h"
#include "MySQL_PreparedStatement.h"


#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_Variables.h"
#include <sstream>
*/
#include "PgSQL_Authentication.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Protocol.h"
extern "C" {
#include "usual/time.h"
}
//#include "usual/time.c"

extern PgSQL_Authentication* GloPgAuth;

/*
 * PgSQL type OIDs for result sets
 */
#define BYTEAOID 17
#define INT8OID 20
#define INT4OID 23
#define TEXTOID 25
#define NUMERICOID 1700


void PG_pkt::make_space(unsigned int len) {
	if ((size + len) <= capacity) {
		return;
	} else {
		capacity = l_near_pow_2(size + len);
		ptr = (char *)realloc(ptr, capacity);
	}
}

void PG_pkt::put_char(char val) {
	make_space(sizeof(char));
	ptr[size++] = val;
}

void PG_pkt::put_uint16(uint16_t val) {
	make_space(4);
	ptr[size++] = (val >> 8) & 255;
	ptr[size++] = val & 255;
}

void PG_pkt::put_uint32(uint32_t val) {
	make_space(4);
	ptr[size++] = (val >> 24) & 255;
	ptr[size++] = (val >> 16) & 255;
	ptr[size++] = (val >> 8) & 255;
	ptr[size++] = val & 255;
}

void PG_pkt::put_uint64(uint64_t val) {
	put_uint32(val >> 32);
	put_uint32((uint32_t)val);
}

void PG_pkt::put_bytes(const void *data, int len) {
	make_space(len);
	memcpy(ptr + size, data, len);
	size += len;
}

void PG_pkt::put_string(const char *str) {
	int len = strlen(str);
	put_bytes(str, len + 1);
}


void PG_pkt::start_packet(int type) {
	assert(type < 256);
	put_char(type);
	put_uint32(0); // this is a space reserved for the packet length
}

void PG_pkt::finish_packet() {
	uint8_t* pos = NULL;
	unsigned len = 0;

	if (multiple_pkt_mode == false) {
		pos = (uint8_t*)ptr + 1; // the first byte after the packet type
		len = size - 1; // the length of the packet minus the packet type byte
	} else {

		if (pkt_offset.empty() == false) {
			const unsigned int offset = pkt_offset.back();
			pos = (uint8_t*)ptr + offset + 1;
			len = (size - offset) - 1;
		}
	}

	*pos++ = (len >> 24) & 255;
	*pos++ = (len >> 16) & 255;
	*pos++ = (len >> 8) & 255;
	*pos++ = len & 255;
}

void PG_pkt::write_generic(int type, const char *pktdesc, ...) {
	va_list ap;
	const char *adesc = pktdesc;

	if (multiple_pkt_mode)
		pkt_offset.push_back(size);

	start_packet(type);
	va_start(ap, pktdesc);
	while (*adesc) {
		switch (*adesc) {
			case 'c': // char/byte
				put_char(va_arg(ap, int));
				break;
			case 'h': // uint16
				put_uint16(va_arg(ap, int));
				break;
			case 'i': // uint32
				put_uint32(va_arg(ap, int));
				break;
			case 'q': // uint64
				put_uint64(va_arg(ap, uint64_t));
				break;
			case 's': // Cstring
				put_string(va_arg(ap, char *));
				break;
			case 'b': // bytes
				{
					uint8_t *bin = va_arg(ap, uint8_t *);
					int len = va_arg(ap, int);
					put_bytes(bin, len);
				}
				break;
			default:
				assert(0);
				break;
		}
		adesc++;
	}
	va_end(ap);

	finish_packet();
}

void PG_pkt::write_RowDescription(const char *tupdesc, ...) {
	va_list ap;
	int ncol = strlen(tupdesc);

	start_packet('T');

	put_uint16(ncol);

	va_start(ap, tupdesc);
	for (int i = 0; i < ncol; i++) {
		char * name = va_arg(ap, char *);

		/* Fields: name, reloid, colnr, oid, typsize, typmod, fmt */
		put_string(name);
		put_uint32(0);
		put_uint16(0);
		const char c = tupdesc[i];
		switch (c) {
			case 's':
				put_uint32(TEXTOID);
				put_uint16(-1);
				break;
			case 'b':
				put_uint32(BYTEAOID);
				put_uint16(-1);
				break;
			case 'i':
				put_uint32(INT4OID);
				put_uint16(4);
				break;
			case 'q':
				put_uint32(INT8OID);
				put_uint16(8);
				break;
			case 'N':
				put_uint32(NUMERICOID);
				put_uint16(-1);
				break;
			case 'T':
				put_uint32(TEXTOID);
				put_uint16(-1);
				break;
			default:
				assert(0);
				break;
		}
		put_uint32(-1);
		put_uint16(0);
	}
	va_end(ap);

	/* set correct length */
	finish_packet();
}


void SQLite3_to_Postgres(PtrSizeArray *psa, SQLite3_result *result, char *error, int affected_rows, const char *query_type) {
	assert(psa != NULL);
	const char *fs = strchr(query_type, ' ');
	int qtlen = strlen(query_type);
	if (fs != NULL) {
		qtlen = (fs - query_type) + 1;
	}
	char buf[qtlen];
	memcpy(buf,query_type, qtlen-1);
	buf[qtlen-1] = 0;
	{
		char *s = buf;
		while (*s) {
			*s = toupper((unsigned char) *s);
			s++;
		}
	}
	if (result) {
		int ncol = result->columns;
		PG_pkt pkt(64);
		pkt.start_packet('T');
		pkt.put_uint16(ncol);
		for (int i=0; i < ncol ; i++) {
			char *name = result->column_definition[i]->name;
			pkt.put_string(name);
			pkt.put_uint32(0);
			pkt.put_uint16(0);
			pkt.put_uint32(TEXTOID); // we add all columns as TEXT
			pkt.put_uint16(-1);
			pkt.put_uint32(-1);
			pkt.put_uint16(0);
		}
		pkt.finish_packet();
		pkt.to_PtrSizeArray(psa);
		for (int r=0; r<result->rows_count; r++) {
			//PG_pkt pkt(128);
			pkt.start_packet('D');
			pkt.put_uint16(ncol);
			for (int i=0; i < ncol; i++) {
				const char *val = result->rows[r]->fields[i];
				if (val != NULL) {
					int len = result->rows[r]->sizes[i];
					pkt.put_uint32(len);
					pkt.put_bytes(val, len);
				} else {
					pkt.put_uint32(-1); // NULL
				}
			}
			pkt.finish_packet();
			pkt.to_PtrSizeArray(psa);
		}

		if (strcmp(buf,"SELECT") == 0) {
			char tmpbuf[128];
			sprintf(tmpbuf,"%s %d", buf, result->rows_count);
			pkt.write_generic('C', "s", tmpbuf);
		} else {
			pkt.write_CommandComplete(buf);
		}
		pkt.to_PtrSizeArray(psa);
		pkt.write_ReadyForQuery();
		pkt.to_PtrSizeArray(psa);
	} else { // no resultset
		PG_pkt pkt(64);
		if (error) {
			// there was an error
			pkt.write_generic('E', "cscscsc",
				'S', "ERROR",
				'C', "28000",
				'M', error, 0);
/*
			if (strcmp(error,(char *)"database is locked")==0) {
				pkt.write_generic('E',
				myprot->generate_pkt_ERR(true,NULL,NULL,sid,1205,(char *)"HY000",error);
			} else {
				myprot->generate_pkt_ERR(true,NULL,NULL,sid,1045,(char *)"28000",error);
			}
*/
			// see https://www.pgsql.org/docs/current/protocol-message-formats.html
		} else {
			char tmpbuf[128];
			if (strcmp(buf,"INSERT") == 0) {
				sprintf(tmpbuf,"%s 0 %d", buf, affected_rows);
				pkt.write_generic('C', "s", tmpbuf);
			} else if (strcmp(buf,"UPDATE") == 0 || strcmp(buf,"DELETE") == 0) {
				sprintf(tmpbuf,"%s %d", buf, affected_rows);
				pkt.write_generic('C', "s", tmpbuf);
			} else {
				pkt.write_CommandComplete(buf);
			}
		}
		pkt.to_PtrSizeArray(psa);
		pkt.write_ReadyForQuery();
		pkt.to_PtrSizeArray(psa);
	}
}
void PG_pkt::write_DataRow(const char *tupdesc, ...) {
	int ncol = strlen(tupdesc);
	va_list ap;

	start_packet('D');
	put_uint16(ncol);

	va_start(ap, tupdesc);
	for (int i = 0; i < ncol; i++) {
		char tmp[128];
		char *tmp2 = NULL;
		const char *val = NULL;

		if (tupdesc[i] == 'i') {
			snprintf(tmp, sizeof(tmp), "%d", va_arg(ap, int));
			val = tmp;
		} else if (tupdesc[i] == 'q' || tupdesc[i] == 'N') {
			snprintf(tmp, sizeof(tmp), "%" PRIu64, va_arg(ap, uint64_t));
			val = tmp;
		} else if (tupdesc[i] == 's') {
			val = va_arg(ap, char *);
		} else if (tupdesc[i] == 'b') {
			int blen = va_arg(ap, int);
			if (blen >= 0) {
				uint8_t *bval = va_arg(ap, uint8_t *);
				size_t required = 2 + blen * 2 + 1;
				tmp2 = (char *)malloc(required);
				strcpy(tmp2, "\\x");
				for (int j = 0; j < blen; j++)
					sprintf(tmp2 + (2 + j * 2), "%02x", bval[j]);
				val = tmp2;
			} else {
				(void) va_arg(ap, uint8_t *);
				val = NULL;
			}
		} else if (tupdesc[i] == 'T') {
			usec_t time = va_arg(ap, usec_t);
			val = format_time_s(time, tmp, sizeof(tmp));
		} else {
			fprintf(stderr, "bad tupdesc: %s", tupdesc);
			assert(0);
		}

		if (val) {
			int len = strlen(val);
			put_uint32(len);
			put_bytes(val, len);
			if (tmp2 != NULL) {
				free(tmp2);
				tmp2 = NULL;
			}
		} else {
			/* NULL */
			put_uint32(-1);
		}
	}
	va_end(ap);

	/* set correct length */
	finish_packet();
}

PtrSize_t * PG_pkt::get_PtrSize(unsigned c) {
	PtrSize_t * pkt = (PtrSize_t *)malloc(sizeof(PtrSize_t));
	pkt->ptr = ptr;
	pkt->size = size;
	capacity = l_near_pow_2(c);
	size = 0;
	ptr = (char *)malloc(capacity);
	return pkt;
}

void PG_pkt::to_PtrSizeArray(PtrSizeArray *psa, unsigned c) {
	psa->add(ptr, size);
	size = 0;
	if (c != 0) {
		capacity = l_near_pow_2(c);
		ptr = (char *)malloc(capacity);
	} else {
		capacity = 0;
		ptr = NULL;
	}
}

bool PgSQL_Protocol::generate_pkt_initial_handshake(bool send, void** _ptr, unsigned int* len, uint32_t* thread_id, bool deprecate_eof_active) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating handshake pkt\n");

	PG_pkt pgpkt{};

	const int type = 'R';

	switch ((AUTHENTICATION_METHOD)pgsql_thread___authentication_method) {

	case AUTHENTICATION_METHOD::NO_PASSWORD:
		pgpkt.write_generic(type, "i", PG_PKT_AUTH_OK);
		break;
	case AUTHENTICATION_METHOD::CLEAR_TEXT_PASSWORD:
		pgpkt.write_generic(type, "i", PG_PKT_AUTH_PLAIN);
		break;
	case AUTHENTICATION_METHOD::MD5_PASSWORD:
		pgpkt.write_generic(type, "i", PG_PKT_AUTH_MD5);
		break;
	case AUTHENTICATION_METHOD::SASL_SCRAM_SHA_256:
		pgpkt.write_generic(type, "iss", PG_PKT_AUTH_SASL, "SCRAM-SHA-256", "");
		break;
	case AUTHENTICATION_METHOD::SASL_SCRAM_SHA_256_PLUS:
		pgpkt.write_generic(type, "iss", PG_PKT_AUTH_SASL, "SCRAM-SHA-256-PLUS", "");
		break;
	default:
		assert(0);
	}

	(*myds)->auth_method = (AUTHENTICATION_METHOD)pgsql_thread___authentication_method;
	(*myds)->auth_next_pkt_type = 'p';

	if (send == true) {
		auto buff = pgpkt.detach();
		(*myds)->PSarrayOUT->add((void*)buff.first, buff.second);
		(*myds)->DSS = STATE_SERVER_HANDSHAKE;
		(*myds)->sess->status = CONNECTING_CLIENT;
	}
	//if (len) { *len = size; }
	//if (_ptr) { *_ptr = (void*)ptr; }

	return true;
}

static inline bool get_uint32be(unsigned char* pkt, uint32_t* dst_p)
{
	int read_pos = 0;
	unsigned a, b, c, d;

	a = pkt[read_pos++];
	b = pkt[read_pos++];
	c = pkt[read_pos++];
	d = pkt[read_pos++];
	*dst_p = (a << 24) | (b << 16) | (c << 8) | d;
	return true;
}


static inline bool get_uint16be(unsigned char* pkt, uint16_t* dst_p)
{
	int read_pos = 0;
	unsigned a, b;

	a = pkt[read_pos++];
	b = pkt[read_pos++];
	*dst_p = (a << 8) | b;
	return true;
}

bool PgSQL_Protocol::get_header(unsigned char* pkt, unsigned int pkt_len, pgsql_hdr* hdr) {
	unsigned int type;
	uint32_t len;
	unsigned int got;
	unsigned int avail;
	uint16_t len16;
	uint8_t type8;
	uint32_t code;
	const uint8_t* ptr;

	unsigned int read_pos = 0;

	if (pkt_len < NEW_HEADER_LEN) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Packet received is less than %d bytes\n", NEW_HEADER_LEN);
		return false;
	}

	// below check is not needed 
	//if (read_pos + 1 > pkt_len) {
	//	return false;
	//}
	//

	type8 = pkt[read_pos++];
	type = type8;

	if (type != 0) {
		/*
		 * Regular (v3) packet, starts with type byte and
		 * 4-byte length.
		 */

		if (read_pos + 4 > pkt_len)
			return false;

		 /* wire length does not include type byte */
		if (!get_uint32be(pkt + read_pos, &len))
			return false;
		read_pos+=4;
		len++;
		got = NEW_HEADER_LEN;
	}
	else {
		/*
		 * Startup/special (formerly v2) packet, formally
		 * starts with 4-byte length.  We assume the first
		 * byte is zero because in current use they shouldn't
		 * be that long to have more than zero in the MSB.
		 */

		 // below check is not needed 
		 //if (read_pos + 1 > pkt_len) {
		 //	return false;
		 //}
		 //

		 /* second byte should also be zero */
		type8 = pkt[read_pos++];

		if (type8 != 0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Unknown special packet\n");
			return false;
		}

		/* don't tolerate partial pkt */
		if ((pkt_len - read_pos) < OLD_HEADER_LEN - 2) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Special packet is less than %d bytes\n", OLD_HEADER_LEN);
			return false;
		}

		if (read_pos + 2 > pkt_len)
			return false;

		if (!get_uint16be(pkt + read_pos, &len16))
			return false;

		read_pos += 2;
		len = len16;

		/* 4-byte code follows */
		if (!get_uint32be(pkt + read_pos, &code))
			return false;

		read_pos += 4;

		if (code == PG_PKT_CANCEL) {
			type = PG_PKT_CANCEL;
		}
		else if (code == PG_PKT_SSLREQ) {
			type = PG_PKT_SSLREQ;
		}
		else if (code == PG_PKT_GSSENCREQ) {
			type = PG_PKT_GSSENCREQ;
		}
		else if ((code >> 16) == 3 && (code & 0xFFFF) < 2) {
			type = PG_PKT_STARTUP;
		}
		else if (code == PG_PKT_STARTUP_V2) {
			type = PG_PKT_STARTUP_V2;
		}
		else {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "unknown special pkt: len=%u code=%u\n", len, code);
			return false;
		}
		got = OLD_HEADER_LEN;
	}

	/* don't believe nonsense */
	if (len < got || len > 2147483647)
		return false;

	/* store pkt info */
	hdr->type = type;
	hdr->len = len;

	/* fill pkt with only data for this packet */
	if (len > pkt_len - read_pos) {
		avail = pkt_len - read_pos;
	}
	else {
		avail = len;
	}

	hdr->data.ptr = pkt + read_pos;
	hdr->data.size = avail;
	read_pos += avail;

	if (read_pos > pkt_len)
		return false;

	return true;
}

unsigned int get_string(const char* data, unsigned int len, const char** dst_p)
{
	const char* res = data;
	const char* nul = (const char*)memchr(res, 0, len);
	if (!nul)
		return 0;
	*dst_p = res;
	return (nul + 1 - data);
}

void PgSQL_Protocol::load_conn_parameters(pgsql_hdr* pkt, bool startup)
{
	const char* key, * val;
	unsigned int read_pos = 0;

	while (1) {

		int pos = get_string(((const char*)pkt->data.ptr) + read_pos, pkt->data.size - read_pos, &key);
		if (pos == 0) return;

		read_pos += pos;

		pos = get_string(((const char*)pkt->data.ptr) + read_pos, pkt->data.size - read_pos, &val);
		if (pos == 0) return;

		read_pos += pos;

		//slog_debug(server, "S: param: %s = %s", key, val);
		(*myds)->myconn->conn_params.set_value(key, val);
	}
}

bool PgSQL_Protocol::process_startup_packet(unsigned char* pkt, unsigned int len) {

	pgsql_hdr hdr{};
	if (!get_header(pkt, len, &hdr)) {
		return false;
	}

	//PG_PKT_STARTUP_V2 not supported

	if (hdr.type != PG_PKT_STARTUP) {
		return false;
	}

	load_conn_parameters(&hdr, true);

	const unsigned char* user = (unsigned char*)(*myds)->myconn->conn_params.get_value(PG_USER);

	if (!user || *user == '\0') {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p. no username supplied.\n", (*myds), (*myds)->sess);
		generate_error_packet(false, "no username supplied", NULL, true);
		return false;
	}

	(*myds)->DSS = STATE_SERVER_HANDSHAKE;

	return true;
}

EXECUTION_STATE PgSQL_Protocol::process_handshake_response_packet(unsigned char* pkt, unsigned int len) {
#ifdef DEBUG
	//if (dump_pkt) { __dump_pkt(__func__, pkt, len); }
#endif

	char* user = NULL;
	char* pass = NULL;

	char* password = NULL;
	char* default_schema = NULL;
	char* db = NULL;
	char* attributes = NULL;
	void* sha1_pass = NULL;
	int max_connections;
	int default_hostgroup = -1;
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	bool using_password = false;
	bool schema_locked;
	bool transaction_persistent = true;
	bool fast_forward = false;
	bool _ret_use_ssl = false;
	EXECUTION_STATE ret = EXECUTION_STATE::FAILED;

	pgsql_hdr hdr{};
	if (!get_header(pkt, len, &hdr)) {
		return EXECUTION_STATE::FAILED;
	}

	assert((hdr.data.size - 1) > 0);

	if (hdr.type != (*myds)->auth_next_pkt_type) {
		return EXECUTION_STATE::FAILED;
	}

	user = (char*)(*myds)->myconn->conn_params.get_value(PG_USER);

	if (!user || *user == '\0') {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Client password pkt before startup packet.\n", (*myds), (*myds)->sess, user);
		generate_error_packet(false, "client password pkt before startup packet", NULL, true);
		goto __exit_process_pkt_handshake_response;
	}

	password = GloPgAuth->lookup((char*)user, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, &default_schema, &schema_locked, &transaction_persistent, &fast_forward, &max_connections, &sha1_pass, &attributes);

	if (password) {
#ifdef DEBUG
		char* tmp_pass = strdup(password);
		int lpass = strlen(tmp_pass);
		for (int i = 2; i < lpass - 1; i++) {
			tmp_pass[i] = '*';
		}
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password='%s'\n", (*myds), (*myds)->sess, user, tmp_pass);
		free(tmp_pass);
#endif // debug
		(*myds)->sess->default_hostgroup = default_hostgroup;
		(*myds)->sess->default_schema = default_schema; // just the pointer is passed
		(*myds)->sess->user_attributes = attributes; // just the pointer is passed
		(*myds)->sess->schema_locked = schema_locked;
		(*myds)->sess->transaction_persistent = transaction_persistent;
		(*myds)->sess->session_fast_forward = false; // default
		if ((*myds)->sess->session_type == PROXYSQL_SESSION_POSTGRESQL) {
			(*myds)->sess->session_fast_forward = fast_forward;
		}
		(*myds)->sess->user_max_connections = max_connections;
	} else {

		if (
			((*myds)->sess->session_type == PROXYSQL_SESSION_ADMIN)
			||
			((*myds)->sess->session_type == PROXYSQL_SESSION_STATS)
			||
			((*myds)->sess->session_type == PROXYSQL_SESSION_SQLITE)
			) {
			if (strcmp((const char*)user, mysql_thread___monitor_username) == 0) {
				if (strcmp(password, mysql_thread___monitor_password) == 0) {
					(*myds)->sess->default_hostgroup = STATS_HOSTGROUP;
					(*myds)->sess->default_schema = strdup((char*)"main"); // just the pointer is passed
					(*myds)->sess->schema_locked = false;
					(*myds)->sess->transaction_persistent = false;
					(*myds)->sess->session_fast_forward = false;
					(*myds)->sess->user_max_connections = 0;
					password = l_strdup(mysql_thread___monitor_password);
					ret = EXECUTION_STATE::SUCCESSFUL;
				}
			}
		}
	}

	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' , auth_method=%d\n", (*myds), (*myds)->sess, user, (int)(*myds)->auth_method);
	switch ((*myds)->auth_method) {
	case AUTHENTICATION_METHOD::CLEAR_TEXT_PASSWORD:
		{
			uint32_t pass_len = hdr.data.size;
			pass = (char*)malloc(pass_len + 1);
			memcpy(pass, hdr.data.ptr, pass_len);
			pass[pass_len] = 0;

			using_password = (pass_len > 0);

			if (pass_len) {
				if (pass[pass_len - 1] == 0) {
					pass_len--; // remove the extra 0 if present
				}
			}

			if (!pass || *pass == '\0') {
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Empty password returned by client.\n", (*myds), (*myds)->sess, user);
				generate_error_packet(false, "empty password returned by client", NULL, true);
				break;
			}

			if (strcmp(password, pass) == 0) {
				ret = EXECUTION_STATE::SUCCESSFUL;
			}
		}
			break;
	case AUTHENTICATION_METHOD::SASL_SCRAM_SHA_256:
		{
			const char* mech;
			uint32_t length;
			const unsigned char* data;
			int read_pos = 0;

			using_password = true;

			PgUser stored_user_info{ '\0' };
			strncpy(stored_user_info.name, user, MAX_USERNAME);
			strncpy(stored_user_info.passwd, password, MAX_PASSWORD);

			if (!(*myds)->scram_state.server_nonce) {
				/* process as SASLInitialResponse */
				int pos = get_string((const char*)hdr.data.ptr, hdr.data.size, &mech);

				if (pos == 0) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. SASL mechanism not found.\n", (*myds), (*myds)->sess, user);
					break;
				}
				
				read_pos=pos;

				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Selected SASL mechanism: %s.\n", (*myds), (*myds)->sess, user, mech);
				if (strcmp(mech, "SCRAM-SHA-256") != 0) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Client selected an invalid SASL authentication mechanism: %s.\n", (*myds), (*myds)->sess, user, mech);
					generate_error_packet(false, "client selected an invalid SASL authentication mechanism", NULL, true);
					break;
				}

				if (get_uint32be(((unsigned char*)hdr.data.ptr) + read_pos, &length) == false) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Malformed packet.\n", (*myds), (*myds)->sess, user);
					break;
				}

				read_pos+=4;

				if ((hdr.data.size - read_pos) < length) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Malformed packet.\n", (*myds), (*myds)->sess, user);
					break;
				}

				// check mem boundry

				if (!scram_handle_client_first(&(*myds)->scram_state, &stored_user_info, ((const unsigned char*)hdr.data.ptr) + read_pos, length)) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. SASL authentication failed\n", (*myds), (*myds)->sess, user);
					generate_error_packet(false, "SASL authentication failed", NULL, true);
					break;
				}

				ret = EXECUTION_STATE::PENDING;
			} else {
				/* process as SASLResponse */
				//length = mbuf_avail_for_read(&pkt->data);
				//if (!mbuf_get_bytes(&pkt->data, length, &data))
				//	return false;

				data = (const unsigned char*)hdr.data.ptr;
				length = hdr.data.size;

				if (scram_handle_client_final(&(*myds)->scram_state, &stored_user_info, data, length)) {
					/* save SCRAM keys for user */
					if (!(*myds)->scram_state.adhoc) {
						memcpy(stored_user_info.scram_ClientKey,
							(*myds)->scram_state.ClientKey,
							sizeof((*myds)->scram_state.ClientKey));
						memcpy(stored_user_info.scram_ServerKey,
							(*myds)->scram_state.ServerKey,
							sizeof((*myds)->scram_state.ServerKey));
						stored_user_info.has_scram_keys = true;
					}

					free_scram_state(&(*myds)->scram_state);
					//if (!finish_client_login(client))
					//	return false;
					//welcome_client();
					ret = EXECUTION_STATE::SUCCESSFUL;
				}
				else {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. SASL authentication failed.\n", (*myds), (*myds)->sess, user);
					//generate_error_packet(false, "SASL authentication failed", NULL, true);
				}
			}
		}
		break;
	default:
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . goto __exit_process_pkt_handshake_response . Unknown auth method\n", (*myds), (*myds)->sess, user);
			break;
	}
	
	if (ret == EXECUTION_STATE::FAILED)
		goto __exit_process_pkt_handshake_response;
	
	// set the default session charset
	//(*myds)->sess->default_charset = charset;
	
	/*if (pass_len == 0 && strlen(password) == 0) {
		ret = true;
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password=''\n", (*myds), (*myds)->sess, user);
	}*/




	assert(sess);
	assert(sess->client_myds);
	//assert(sess->client_myds->myconn);
	/*myconn->set_charset(charset, CONNECT_START);
	{
		std::stringstream ss;
		ss << charset;

		mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_RESULTS, ss.str().c_str());
		mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_CLIENT, ss.str().c_str());
		mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_CONNECTION, ss.str().c_str());
		mysql_variables.client_set_value(sess, SQL_COLLATION_CONNECTION, ss.str().c_str());
	}
*/


	if (ret == EXECUTION_STATE::SUCCESSFUL) {

		(*myds)->DSS = STATE_CLIENT_HANDSHAKE;

		if (userinfo->username) free(userinfo->username);
		if (userinfo->password) free(userinfo->password);

		userinfo->username = strdup((const char*)user);
		userinfo->password = strdup((const char*)password);

		const char* db = (*myds)->myconn->conn_params.get_value(PG_DATABASE);

		if (db)
			userinfo->set_schemaname((char*)db, strlen(db));
		else
			userinfo->set_schemaname(userinfo->username, strlen(userinfo->username));

		const char* charset = (*myds)->myconn->conn_params.get_value(PG_CLIENT_ENCODING);

		//if (charset)
		//	(*myds)->sess->default_charset = charset;
	}
	else {
		// we always duplicate username and password, or crashes happen
		if (!userinfo->username) // if set already, ignore
			userinfo->username = strdup((const char*)user);
		if (using_password)
			userinfo->password = strdup((const char*)"");
	}
	userinfo->set(NULL, NULL, NULL, NULL); // just to call compute_hash()

__exit_process_pkt_handshake_response:
	free(pass);
	if (password) {
		free(password);
		password = NULL;
	}
	if (sha1_pass) {
		free(sha1_pass);
		sha1_pass = NULL;
	}

	if (ret == EXECUTION_STATE::SUCCESSFUL) {
		//ret = verify_user_attributes(__LINE__, __func__, user);
	}
	return ret;
}

void PgSQL_Protocol::welcome_client() {
	PG_pkt pgpkt(128);

	pgpkt.set_multi_pkt_mode(true);
	pgpkt.write_AuthenticationOk();
	pgpkt.write_ParameterStatus("server_encoding", "UTF-8");
	pgpkt.write_ParameterStatus("is_superuser", "on"); // only for admin

	const char* client_encoding = (*myds)->myconn->conn_params.get_value(PG_CLIENT_ENCODING);
	if (client_encoding)
		pgpkt.write_ParameterStatus("client_encoding", client_encoding);

	const char* application_name = (*myds)->myconn->conn_params.get_value(PG_APPLICATION_NAME);
	if (application_name)
		pgpkt.write_ParameterStatus("application_name", application_name);

	if (pgsql_thread___server_version)
		pgpkt.write_ParameterStatus("server_version", pgsql_thread___server_version);

	pgpkt.write_ReadyForQuery();
	pgpkt.set_multi_pkt_mode(false);

	auto buff = pgpkt.detach();
	(*myds)->PSarrayOUT->add((void*)buff.first, buff.second);
	//(*myds)->DSS = STATE_CLIENT_AUTH_OK;
	//(*myds)->sess->status = WAITING_CLIENT_DATA;
}

void PgSQL_Protocol::generate_error_packet(bool send_ready, const char* msg, const char* code, bool fatal) {
	PG_pkt pgpkt{};

	if (send_ready)
		pgpkt.set_multi_pkt_mode(true);

	pgpkt.write_generic('E', "cscscscsc", 
		'S', fatal ? "FATAL" : "ERROR",
		'V', fatal ? "FATAL" : "ERROR",
		'C', code ? code : "08P01", 'M', msg, 0);

	if (send_ready) {
		pgpkt.write_ReadyForQuery();
		pgpkt.set_multi_pkt_mode(false);
	}

	auto buff = pgpkt.detach();
	(*myds)->PSarrayOUT->add((void*)buff.first, buff.second);
	switch ((*myds)->DSS) {
	case STATE_SERVER_HANDSHAKE:
	case STATE_CLIENT_HANDSHAKE:
	case STATE_QUERY_SENT_DS:
	case STATE_QUERY_SENT_NET:
	case STATE_ERR:
		(*myds)->DSS = STATE_ERR;
		break;
	case STATE_OK:
		break;
	case STATE_SLEEP:
		if ((*myds)->sess->session_fast_forward == true) { // see issue #733
			break;
		}
	default:
		// LCOV_EXCL_START
		assert(0);
		// LCOV_EXCL_STOP
	}
}

bool PgSQL_Protocol::scram_handle_client_first(ScramState* scram_state, PgUser* user, const unsigned char* data, uint32_t datalen)
{
	char* ibuf;
	char* input;

	scram_reset_error();

	ibuf = (char*)malloc(datalen + 1);
	if (ibuf == NULL)
		return false;
	memcpy(ibuf, data, datalen);
	ibuf[datalen] = '\0';

	input = ibuf;
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. SCRAM client-first-message = \"%s\"\n", (*myds), (*myds)->sess, user->name, input);
	if (!read_client_first_message(input,
		&scram_state->cbind_flag,
		&scram_state->client_first_message_bare,
		&scram_state->client_nonce))
		goto failed;

	if (!user->mock_auth) {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. stored secret = \"%s\"\n", (*myds), (*myds)->sess, user->name, user->passwd);
		switch (get_password_type(user->passwd)) {
		case PASSWORD_TYPE_MD5:
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. SCRAM authentication failed: user has MD5 secret\n", (*myds), (*myds)->sess, user->name);
			goto failed;
		case PASSWORD_TYPE_PLAINTEXT:
		case PASSWORD_TYPE_SCRAM_SHA_256:
			break;
		}
	}

	if (!build_server_first_message(scram_state, user->name, user->mock_auth ? NULL : user->passwd))
		goto failed;

	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. SCRAM server-first-message = \"%s\"\n", (*myds), (*myds)->sess, user->name, scram_state->server_first_message);
	{
		PG_pkt pgpkt{};
		pgpkt.write_AuthenticationRequest(PG_PKT_AUTH_SASL_CONT, (const uint8_t*)scram_state->server_first_message, strlen(scram_state->server_first_message));
		auto buff = pgpkt.detach();
		(*myds)->PSarrayOUT->add((void*)buff.first, buff.second);
	}

	free(ibuf);
	return true;
failed:
	free(ibuf);
	return false;
}

bool PgSQL_Protocol::scram_handle_client_final(ScramState* scram_state, PgUser* user, const unsigned char* data, uint32_t datalen)
{
	char* ibuf;
	char* input;
	const char* client_final_nonce = NULL;
	char* proof = NULL;
	char* server_final_message;
	int res;

	scram_reset_error();

	ibuf = (char*)malloc(datalen + 1);
	if (ibuf == NULL)
		return false;
	memcpy(ibuf, data, datalen);
	ibuf[datalen] = '\0';

	input = ibuf;
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. SCRAM client-final-message = \"%s\"\n", (*myds), (*myds)->sess, user->name, input);
	if (!read_client_final_message(scram_state, data, input,
		&client_final_nonce,
		&proof))
		goto failed;

	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. SCRAM client-final-message-without-proof = \"%s\"\n", (*myds), 
		(*myds)->sess, user->name, scram_state->client_final_message_without_proof);

	if (!verify_final_nonce(scram_state, client_final_nonce)) {
		proxy_error("Invalid SCRAM response (nonce does not match)\n");
		goto failed;
	}

	if (!verify_client_proof(scram_state, proof)) {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s. Password authentication failed\n", (*myds),
			(*myds)->sess, user->name);
		goto failed;
	}

	server_final_message = build_server_final_message(scram_state);
	if (!server_final_message)
		goto failed;
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s. SCRAM server-final-message = \"%s\"\n", (*myds),
		(*myds)->sess, user->name, server_final_message);

	{
		PG_pkt pgpkt{};
		pgpkt.write_AuthenticationRequest(PG_PKT_AUTH_SASL_FIN, (const uint8_t*)server_final_message, strlen(server_final_message));
		auto buff = pgpkt.detach();
		(*myds)->PSarrayOUT->add((void*)buff.first, buff.second);
	}

	free(server_final_message);
	free(proof);
	free(ibuf);
	return res;
failed:
	free(proof);
	free(ibuf);
	return false;
}
