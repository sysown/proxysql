
#include <openssl/rand.h>
#include "proxysql.h"
#include "cpp.h"
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
	if (ownership == false)  return;

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
			// see https://www.postgresql.org/docs/current/protocol-message-formats.html
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

bool PgSQL_Protocol::generate_pkt_initial_handshake(bool send, void** _ptr, unsigned int* len, uint32_t* _thread_id, bool deprecate_eof_active) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating handshake pkt\n");

	PG_pkt pgpkt{};

	const int type = 'R';

	uint32_t thread_id = __sync_fetch_and_add(&glovars.thread_id, 1);
	if (thread_id == 0) {
		thread_id = __sync_fetch_and_add(&glovars.thread_id, 1); // again!
	}
	*_thread_id = thread_id;

	switch ((AUTHENTICATION_METHOD)pgsql_thread___authentication_method) {

	case AUTHENTICATION_METHOD::NO_PASSWORD:
		pgpkt.write_generic(type, "i", PG_PKT_AUTH_OK);
		break;
	case AUTHENTICATION_METHOD::CLEAR_TEXT_PASSWORD:
		pgpkt.write_generic(type, "i", PG_PKT_AUTH_PLAIN);
		break;
	case AUTHENTICATION_METHOD::MD5_PASSWORD:
		memset((*myds)->tmp_login_salt, 0, sizeof((*myds)->tmp_login_salt));
		if (RAND_bytes((*myds)->tmp_login_salt, sizeof((*myds)->tmp_login_salt)) != 1) {
			// Fallback method: using a basic pseudo-random generator
			srand((unsigned int)time(NULL));  
			for (int i = 0; i < sizeof((*myds)->tmp_login_salt); i++) {
				(*myds)->tmp_login_salt[i] = rand() % 256;  
			}
		}
		pgpkt.write_generic(type, "ib", PG_PKT_AUTH_MD5, (*myds)->tmp_login_salt, sizeof((*myds)->tmp_login_salt));
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

/*
 * @brief Reads and converts a big endian 32-bit unsigned integer from the provided packet buffer into the destination pointer.
 *
 * This function is used to extract the big endian 32-bit unsigned integer value at the specified position in a given
 * packet buffer, and stores it in the destination pointer passed as an argument.
 *
 * @param[in] pkt A pointer to the start of the input packet buffer from which to read the 32-bit integer.
 *
 * @param[out] dst_p A pointer where the extracted big endian 32-bit unsigned integer value will be stored.
 */
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


/**
 * @brief Extracts a 16-bit unsigned integer from a packet and stores it in the provided destination pointer.
 *
 * This function reads two bytes from the packet `pkt` starting from the beginning, interprets them as a big-endian unsigned 16-bit integer,
 * and stores the result into the memory location pointed to by `dst_p`. It consistently returns true to indicate successful execution.
 *
 * @param pkt Pointer to the packet data (array of unsigned chars) from which the 16-bit integer will be extracted.
 *             The caller must ensure this pointer is valid and points to at least two bytes of data.
 * @param dst_p Pointer to a uint16_t variable where the extracted integer will be stored. The caller must ensure that
 *             this pointer is valid and points to a uint16_t variable.
 *
 * @return Always returns true to indicate success.
 *
 * @note This function uses big-endian byte order (network byte order) for interpreting the packet data.
 *       It is assumed that the packet buffer `pkt` contains at least two bytes (the size of a uint16_t).
 *       The function uses post-increment to move the reading position after extracting each byte.
 */
static inline bool get_uint16be(unsigned char* pkt, uint16_t* dst_p)
{
	int read_pos = 0; ///< Current read position in the buffer.
	unsigned a, b;

	// Read the two bytes from the buffer
	a = pkt[read_pos++]; ///< First byte read from the buffer.
	b = pkt[read_pos++]; ///< Second byte read from the buffer.
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
	//const uint8_t* ptr;

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

bool PgSQL_Protocol::process_startup_packet(unsigned char* pkt, unsigned int len, bool& ssl_request) {
	
	ssl_request = false;
	pgsql_hdr hdr{};
	if (!get_header(pkt, len, &hdr)) {
		return false;
	}

	if (hdr.type == PG_PKT_SSLREQ) {
		const bool have_ssl = pgsql_thread___have_ssl;
		char* ssl_supported = (char*)malloc(1);
		*ssl_supported = have_ssl ? 'S' : 'N';
		(*myds)->PSarrayOUT->add((void*)ssl_supported, 1);
		(*myds)->sess->writeout();
		(*myds)->encrypted = have_ssl;
		ssl_request = true;
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 8, "Session=%p , DS=%p. SSL_REQUEST:'%c'\n", (*myds)->sess, (*myds), *ssl_supported);
		return true;
	}

	//PG_PKT_STARTUP_V2 not supported
	if (hdr.type != PG_PKT_STARTUP) {
		return false;
	}

	load_conn_parameters(&hdr, true);

	const unsigned char* user = (unsigned char*)(*myds)->myconn->conn_params.get_value(PG_USER);

	if (!user || *user == '\0') {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p. no username supplied.\n", (*myds), (*myds)->sess);
		generate_error_packet(true, false, "no username supplied", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION, true);
		return false;
	}

	(*myds)->DSS = STATE_SERVER_HANDSHAKE;

	return true;
}

char* extract_password(const pgsql_hdr* hdr, uint32_t* len) {
	char* pass = NULL;
	uint32_t pass_len = hdr->data.size;

	if (pass_len == 0) 
		return NULL;

	pass = (char*)malloc(pass_len + 1);
	memcpy(pass, hdr->data.ptr, pass_len);
	pass[pass_len] = 0;

	if (pass_len) {
		if (pass[pass_len - 1] == 0) {
			pass_len--; // remove the extra 0 if present
		}
	}

	if (len) *len = pass_len;
	return pass;
}

EXECUTION_STATE PgSQL_Protocol::process_handshake_response_packet(unsigned char* pkt, unsigned int len) {
#ifdef DEBUG
	//if (dump_pkt) { __dump_pkt(__func__, pkt, len); }
#endif

	char* user = NULL;
	char* pass = NULL;

	char* password = NULL;
	//char* db = NULL;
	char* attributes = NULL;
	void* sha1_pass = NULL;
	int max_connections;
	int default_hostgroup = -1;
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	bool using_password = false;
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
		generate_error_packet(true, false, "client password pkt before startup packet", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION, true);
		goto __exit_process_pkt_handshake_response;
	}

	password = GloPgAuth->lookup((char*)user, USERNAME_FRONTEND, &_ret_use_ssl, &default_hostgroup, &transaction_persistent, &fast_forward, &max_connections, &sha1_pass, &attributes);

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
		//(*myds)->sess->default_schema = default_schema; // just the pointer is passed
		(*myds)->sess->user_attributes = attributes; // just the pointer is passed
		//(*myds)->sess->schema_locked = schema_locked;
		(*myds)->sess->transaction_persistent = transaction_persistent;
		(*myds)->sess->session_fast_forward = false; // default
		if ((*myds)->sess->session_type == PROXYSQL_SESSION_PGSQL) {
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
				(*myds)->sess->default_hostgroup = STATS_HOSTGROUP;
				(*myds)->sess->default_schema = strdup((char*)"main"); // just the pointer is passed
				(*myds)->sess->schema_locked = false;
				(*myds)->sess->transaction_persistent = false;
				(*myds)->sess->session_fast_forward = false;
				(*myds)->sess->user_max_connections = 0;
				password = l_strdup(mysql_thread___monitor_password);
			}
		}
	}

	if (password) {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' , auth_method=%s\n", (*myds), (*myds)->sess, user, AUTHENTICATION_METHOD_STR[(int)(*myds)->auth_method]);
		switch ((*myds)->auth_method) {
		case AUTHENTICATION_METHOD::MD5_PASSWORD:
		{
			uint32_t pass_len = 0;
			pass = extract_password(&hdr, &pass_len);
			using_password = (pass_len > 0);

			if (pass_len) {
				if (pass[pass_len - 1] == 0) {
					pass_len--; // remove the extra 0 if present
				}
			}

			if (!pass || *pass == '\0') {
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Empty password returned by client.\n", (*myds), (*myds)->sess, user);
				generate_error_packet(true, false, "empty password returned by client", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION, true);
				break;
			}

			unsigned char md5_digest[MD5_DIGEST_LENGTH];
			char md5_string[MD5_DIGEST_LENGTH * 2 + sizeof((*myds)->tmp_login_salt)];
			MD5_CTX md5_context;
			// needs to be precalculated and stored in DB
			MD5_Init(&md5_context);
			MD5_Update(&md5_context, password, strlen(password));
			MD5_Update(&md5_context, user, strlen(user));
			MD5_Final(md5_digest, &md5_context);
			for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
				sprintf(&md5_string[i * 2], "%02x", (unsigned int)md5_digest[i]);
			}
			//
			memcpy(md5_string+(MD5_DIGEST_LENGTH*2), (*myds)->tmp_login_salt, sizeof((*myds)->tmp_login_salt));
			MD5_Init(&md5_context);
			MD5_Update(&md5_context, md5_string, (MD5_DIGEST_LENGTH*2)+sizeof((*myds)->tmp_login_salt));
			MD5_Final(md5_digest, &md5_context);
			memcpy(md5_string, "md5", 3);
			for (int i = 0, j = 3;  i < MD5_DIGEST_LENGTH; i++, j+=2) {
				sprintf(&md5_string[j], "%02x", (unsigned int)md5_digest[i]);
			}

			if (strlen(md5_string) == pass_len && strcmp(md5_string, pass) == 0) {
				ret = EXECUTION_STATE::SUCCESSFUL;
			}
		}
		break;
		case AUTHENTICATION_METHOD::CLEAR_TEXT_PASSWORD:
		{
			uint32_t pass_len = 0;
			pass = extract_password(&hdr, &pass_len);
			using_password = (pass_len > 0);

			if (!pass || *pass == '\0') {
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Empty password returned by client.\n", (*myds), (*myds)->sess, user);
				generate_error_packet(true, false, "empty password returned by client", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION, true);
				break;
			}

			if (strlen(password) == pass_len && strcmp(password, pass) == 0) {
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

			if ((*myds)->scram_state == NULL) {
				(*myds)->scram_state = scram_state_init();
			}

			PgCredentials stored_user_info{ '\0' };
			strncpy(stored_user_info.name, user, MAX_USERNAME);
			strncpy(stored_user_info.passwd, password, MAX_PASSWORD);

			if (!(*myds)->scram_state->server_nonce) {
				/* process as SASLInitialResponse */
				int pos = get_string((const char*)hdr.data.ptr, hdr.data.size, &mech);

				if (pos == 0) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. SASL mechanism not found.\n", (*myds), (*myds)->sess, user);
					break;
				}

				read_pos = pos;

				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Selected SASL mechanism: %s.\n", (*myds), (*myds)->sess, user, mech);
				if (strcmp(mech, "SCRAM-SHA-256") != 0) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Client selected an invalid SASL authentication mechanism: %s.\n", (*myds), (*myds)->sess, user, mech);
					generate_error_packet(true, false, "client selected an invalid SASL authentication mechanism", 
						PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION, true);
					break;
				}

				if (get_uint32be(((unsigned char*)hdr.data.ptr) + read_pos, &length) == false) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Malformed packet.\n", (*myds), (*myds)->sess, user);
					break;
				}

				read_pos += 4;

				if ((hdr.data.size - read_pos) < length) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. Malformed packet.\n", (*myds), (*myds)->sess, user);
					break;
				}

				// check mem boundry

				if (!scram_handle_client_first((*myds)->scram_state, &stored_user_info, ((const unsigned char*)hdr.data.ptr) + read_pos, length)) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. SASL authentication failed\n", (*myds), (*myds)->sess, user);
					generate_error_packet(true, false, "SASL authentication failed", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION, true);
					break;
				}

				ret = EXECUTION_STATE::PENDING;
			}
			else {
				/* process as SASLResponse */
				//length = mbuf_avail_for_read(&pkt->data);
				//if (!mbuf_get_bytes(&pkt->data, length, &data))
				//	return false;

				data = (const unsigned char*)hdr.data.ptr;
				length = hdr.data.size;

				if (scram_handle_client_final((*myds)->scram_state, &stored_user_info, data, length)) {
					/* save SCRAM keys for user */
					if (!(*myds)->scram_state->adhoc) {
						memcpy(stored_user_info.scram_ClientKey,
							(*myds)->scram_state->ClientKey,
							sizeof((*myds)->scram_state->ClientKey));
						memcpy(stored_user_info.scram_ServerKey,
							(*myds)->scram_state->ServerKey,
							sizeof((*myds)->scram_state->ServerKey));
						stored_user_info.has_scram_keys = true;
					}

					free_scram_state((*myds)->scram_state);
					(*myds)->scram_state = NULL;
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
			//generate_error_packet(true, false, "authentication method not supported", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION, true);
			break;
		}
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s'. User not found in the database.\n", (*myds), (*myds)->sess, user);
		generate_error_packet(true, false, "User not found", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION, true);
	}
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
		userinfo->set_dbname(db ? db : userinfo->username);

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
	
	if (sess->session_type == PROXYSQL_SESSION_ADMIN)
		pgpkt.write_ParameterStatus("is_superuser", "on"); // only for admin

	const char* application_name = (*myds)->myconn->conn_params.get_value(PG_APPLICATION_NAME);
	if (application_name)
		pgpkt.write_ParameterStatus("application_name", application_name);

	const char* client_encoding = (*myds)->myconn->conn_params.get_value(PG_CLIENT_ENCODING);
	if (client_encoding)
		pgpkt.write_ParameterStatus("client_encoding", client_encoding);
	// if client does not provide client_encoding, PostgreSQL uses the default client encoding. 
	// We need to save the default client encoding to send it to the client in case client doesn't provide one.
	else if (pgsql_thread___default_client_encoding) 
		pgpkt.write_ParameterStatus("client_encoding", pgsql_thread___default_client_encoding);

	if (pgsql_thread___server_version)
		pgpkt.write_ParameterStatus("server_version", pgsql_thread___server_version);

	pgpkt.write_ParameterStatus("server_encoding", "UTF8");

	pgpkt.write_ReadyForQuery();
	pgpkt.set_multi_pkt_mode(false);

	auto buff = pgpkt.detach();
	(*myds)->PSarrayOUT->add((void*)buff.first, buff.second);
	//(*myds)->DSS = STATE_CLIENT_AUTH_OK;
	//(*myds)->sess->status = WAITING_CLIENT_DATA;
}

void PgSQL_Protocol::generate_error_packet(bool send, bool ready, const char* msg, PGSQL_ERROR_CODES code, bool fatal, bool track, PtrSize_t* _ptr) {
	// to avoid memory leak
	assert(send == true || _ptr);

	if (send) {
		// in case of fatal error we dont generate ready packets
		ready = !fatal;
	}

	PG_pkt pgpkt{};

	if (ready)
		pgpkt.set_multi_pkt_mode(true);

	pgpkt.write_generic('E', "cscscscsc", 
		'S', fatal ? "FATAL" : "ERROR",
		'V', fatal ? "FATAL" : "ERROR",
		'C', PgSQL_Error_Helper::get_error_code(code), 'M', msg, 0);

	if (ready == true) {
		pgpkt.write_ReadyForQuery();
		pgpkt.set_multi_pkt_mode(false);
	}

	
	auto buff = pgpkt.detach();
	if (send) {
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

	if (_ptr) {
		_ptr->ptr = buff.first;
		_ptr->size = buff.second;
	}

	if (track) {
		if (*myds && (*myds)->sess && (*myds)->sess->thread) {
			(*myds)->sess->thread->status_variables.stvar[st_var_generated_pkt_err]++;
		}
	}
}

bool PgSQL_Protocol::scram_handle_client_first(ScramState* scram_state, PgCredentials* user, const unsigned char* data, uint32_t datalen)
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

bool PgSQL_Protocol::scram_handle_client_final(ScramState* scram_state, PgCredentials* user, const unsigned char* data, uint32_t datalen)
{
	char* ibuf;
	char* input;
	const char* client_final_nonce = NULL;
	char* proof = NULL;
	char* server_final_message;

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
	return true;
failed:
	free(proof);
	free(ibuf);
	return false;
}

char* extract_tag_from_query(const char* query) {

	constexpr size_t crete_table_len = sizeof("CREATE TABLE AS") - 1;

	size_t qtlen = strlen(query);
	if ((qtlen > crete_table_len) && strncasecmp(query, "CREATE TABLE AS", crete_table_len) == 0) {
		return strdup("SELECT");
	}
	else {
		const char* fs = strchr(query, ' ');

		if (fs != NULL) {
			qtlen = (fs - query) + 1;
		}
		char buf[qtlen];
		memcpy(buf, query, qtlen - 1);
		buf[qtlen - 1] = 0;
		{
			char* s = buf;
			while (*s) {
				*s = toupper((unsigned char)*s);
				s++;
			}
		}

		return strdup(buf);
	}
}


bool PgSQL_Protocol::generate_ok_packet(bool send, bool ready, const char* msg, int rows, const char* query, char trx_state, PtrSize_t* _ptr) {
	// to avoid memory leak
	assert(send == true || _ptr);

	PG_pkt pgpkt{};

	if (ready == true) {
		pgpkt.set_multi_pkt_mode(true);
	}

	char* tag = extract_tag_from_query(query);
	assert(tag);

	char tmpbuf[128];
	if (strcmp(tag, "INSERT") == 0) {
		sprintf(tmpbuf, "%s 0 %d", tag, rows);
		pgpkt.write_CommandComplete(tmpbuf);
	} else if (strcmp(tag, "UPDATE") == 0 ||
		strcmp(tag, "DELETE") == 0 ||
		strcmp(tag, "MERGE") == 0 ||
		strcmp(tag, "MOVE") == 0 ||
		strcmp(tag, "FETCH") == 0 ||
		strcmp(tag, "COPY") == 0 ||
		strcmp(tag, "SELECT") == 0 ||
		strcmp(tag, "COPY") == 0 ) {
		sprintf(tmpbuf, "%s %d", tag, rows);
		pgpkt.write_CommandComplete(tmpbuf);
	} else {
		pgpkt.write_CommandComplete(tag);
	}
	
	if (ready == true) {
		pgpkt.write_ReadyForQuery(trx_state);
		pgpkt.set_multi_pkt_mode(false);
	}

	auto buff = pgpkt.detach();
	if (send == true) {
		(*myds)->PSarrayOUT->add((void*)buff.first, buff.second);
	} else {
		_ptr->ptr = buff.first;
		_ptr->size = buff.second;
	}
	free(tag);
	return true;
}

//bool PgSQL_Protocol::generate_row_description(bool send, PgSQL_Query_Result* rs, const PG_Fields& fields, unsigned int size) {
//	if ((*myds)->sess->mirror == true) {
//		return true;
//	}
//
//	unsigned char* _ptr = NULL;
//
//	if (rs) {
//		if (size <= (PGSQL_RESULTSET_BUFLEN - rs->buffer_used)) {
//			// there is space in the buffer, add the data to it
//			_ptr = rs->buffer + rs->buffer_used;
//			rs->buffer_used += size;
//		} else {
//			// there is no space in the buffer, we flush the buffer and recreate it
//			rs->buffer_to_PSarrayOut();
//			// now we can check again if there is space in the buffer
//			if (size <= (PGSQL_RESULTSET_BUFLEN - rs->buffer_used)) {
//				// there is space in the NEW buffer, add the data to it
//				_ptr = rs->buffer + rs->buffer_used;
//				rs->buffer_used += size;
//			} else {
//				// a new buffer is not enough to store the new row
//				_ptr = (unsigned char*)l_alloc(size);
//			}
//		}
//	} else {
//		_ptr = (unsigned char*)l_alloc(size);
//	}
//
//	PG_pkt pgpkt(_ptr, 0);
//
//	pgpkt.put_char('T');
//	pgpkt.put_uint32(size );
//	pgpkt.put_uint16(fields.size());
//
//	for (unsigned int i = 0; i < fields.size(); i++) {
//		pgpkt.put_string(fields[i].name);
//		pgpkt.put_uint32(fields[i].tbl_oid);
//		pgpkt.put_uint16(fields[i].col_idx);
//		pgpkt.put_uint32(fields[i].type_oid);
//		pgpkt.put_uint16(fields[i].col_len);
//		pgpkt.put_uint32(fields[i].type_mod);
//		pgpkt.put_uint16(fields[i].fmt);
//	}
//
//	if (send == true) { (*myds)->PSarrayOUT->add((void*)_ptr, size); }
//	
////#ifdef DEBUG
////	if (dump_pkt) { __dump_pkt(__func__, _ptr, size); }
////#endif
//	if (rs) {
//		if (_ptr >= rs->buffer && _ptr < rs->buffer + PGSQL_RESULTSET_BUFLEN) {
//			// we are writing within the buffer, do not add to PSarrayOUT
//		} else {
//			// we are writing outside the buffer, add to PSarrayOUT
//			rs->PSarrayOUT.add(_ptr, size);
//		}
//	}
//	return true;
//}


unsigned int PgSQL_Protocol::copy_row_description_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result) {
	assert(pg_query_result);
	assert(result);
	
	unsigned int fields_cnt = PQnfields(result);
	unsigned int size = 1 + 4 + 2;
	for (unsigned int i = 0; i < fields_cnt; i++) {
		size += strlen(PQfname(result, i)) + 1 + 18; // null terminator, name, reloid, colnr, oid, typsize, typmod, fmt
	}

	bool alloced_new_buffer = false;
	unsigned char* _ptr = pg_query_result->buffer_reserve_space(size);

	// buffer is not enough to store the new row description. Remember we have already pushed data to PSarrayOUT
	if (_ptr == NULL) {
		_ptr = (unsigned char*)l_alloc(size);
		alloced_new_buffer = true;
	}

	PG_pkt pgpkt(_ptr, size);

	pgpkt.put_char('T');
	pgpkt.put_uint32(size - 1);
	pgpkt.put_uint16(fields_cnt);

	for (unsigned int i = 0; i < fields_cnt; i++) {
		pgpkt.put_string(PQfname(result, i));
		pgpkt.put_uint32(PQftable(result, i));
		pgpkt.put_uint16(PQftablecol(result, i));
		pgpkt.put_uint32(PQftype(result, i));
		pgpkt.put_uint16(PQfsize(result, i));
		pgpkt.put_uint32(PQfmod(result, i));
		pgpkt.put_uint16(PQfformat(result, i));
	}

	if (send == true) { 
		// not supported
		//(*myds)->PSarrayOUT->add((void*)_ptr, size); 
	}

//#ifdef DEBUG
//	if (dump_pkt) { __dump_pkt(__func__, _ptr, size); }
//#endif

	pg_query_result->resultset_size = size;

	if (alloced_new_buffer) {
		// we created new buffer
		//pg_query_result->buffer_to_PSarrayOut();
		pg_query_result->PSarrayOUT.add(_ptr, size);
	}
	
	pg_query_result->num_fields = fields_cnt;
	pg_query_result->pkt_count++;
	return size;
}

unsigned int PgSQL_Protocol::copy_row_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result) {
	assert(pg_query_result);
	assert(result);
	assert(pg_query_result->num_fields);

	const unsigned int numRows = PQntuples(result);
	unsigned int total_size = 0;
	for (unsigned int i = 0; i < numRows; i++) {
		unsigned int size = 1 + 4 + 2; // 'D', length, field count
		for (unsigned int j = 0; j < pg_query_result->num_fields; j++) {
			size += PQgetlength(result, i, j) + 4; // length, value
		}
		total_size += size;

		bool alloced_new_buffer = false;
		unsigned char* _ptr = pg_query_result->buffer_reserve_space(size);

		// buffer is not enough to store the new row. Remember we have already pushed data to PSarrayOUT
		if (_ptr == NULL) {
			_ptr = (unsigned char*)l_alloc(size);
			alloced_new_buffer = true;
		}

		PG_pkt pgpkt(_ptr, size);

		pgpkt.put_char('D');
		pgpkt.put_uint32(size - 1);
		pgpkt.put_uint16(pg_query_result->num_fields);
		int column_value_len = 0;
		for (unsigned int j = 0; j < pg_query_result->num_fields; j++) {
			column_value_len = PQgetlength(result, i, j);
			if (column_value_len == 0 && PQgetisnull(result, i, j) == 1) {
				column_value_len = -1; /*0xFFFFFFFF*/
			}
			pgpkt.put_uint32(column_value_len);
			if (column_value_len > 0) {
				pgpkt.put_bytes(PQgetvalue(result, i, j), column_value_len);
			}
		}

		if (send == true) { 
			// not supported
			//(*myds)->PSarrayOUT->add((void*)_ptr, size); 
		}

		pg_query_result->resultset_size += size;

		if (alloced_new_buffer) {
			// we created new buffer
			//pg_query_result->buffer_to_PSarrayOut();
			pg_query_result->PSarrayOUT.add(_ptr, size);
		}

		pg_query_result->pkt_count++;
	}

	pg_query_result->num_rows += numRows;

	return total_size;
}

unsigned int PgSQL_Protocol::copy_command_completion_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result, 
	bool extract_affected_rows) {
	assert(pg_query_result);
	assert(result);

	const char* tag = PQcmdStatus((PGresult*)result);
	if (!tag) assert(0); // for testing it should not be null

	const unsigned int size = strlen(tag) + 1 + 1 + 4; // tag length, null byte, 'C', length, tag
	bool alloced_new_buffer = false;
	
	unsigned char* _ptr = pg_query_result->buffer_reserve_space(size);
	
	// buffer is not enough to store the new row. Remember we have already pushed data to PSarrayOUT
	if (_ptr == NULL) {
		_ptr = (unsigned char*)l_alloc(size);
		alloced_new_buffer = true;
	}

	PG_pkt pgpkt(_ptr, size);

	pgpkt.put_char('C');
	pgpkt.put_uint32(size - 1);
	pgpkt.put_string(tag);

	if (send == true) { 
		// not supported
		//(*myds)->PSarrayOUT->add((void*)_ptr, size); 
	}

	pg_query_result->resultset_size += size;

	if (alloced_new_buffer) {
		// we created new buffer
		//pg_query_result->buffer_to_PSarrayOut();
		pg_query_result->PSarrayOUT.add(_ptr, size);
	}
	pg_query_result->pkt_count++;

    // To prevent rows sent from being considered as affected rows,
    // we avoid extracting affected rows for SELECT queries.
	if (extract_affected_rows) {
		const char* extracted_affect_rows = PQcmdTuples(const_cast<PGresult*>(result));
		if (*extracted_affect_rows)
			pg_query_result->affected_rows = strtoull(extracted_affect_rows, NULL, 10);
	}
	return size;
}

unsigned int PgSQL_Protocol::copy_error_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result) {
	assert(pg_query_result);
	assert(result);

	const char* severity = PQresultErrorField(result, PG_DIAG_SEVERITY);
	const char* text = PQresultErrorField(result, PG_DIAG_SEVERITY_NONLOCALIZED);
	const char* sqlstate = PQresultErrorField(result, PG_DIAG_SQLSTATE);
	const char* primary = PQresultErrorField(result, PG_DIAG_MESSAGE_PRIMARY);
	const char* detail = PQresultErrorField(result, PG_DIAG_MESSAGE_DETAIL);
	const char* hint = PQresultErrorField(result, PG_DIAG_MESSAGE_HINT);
	const char* position = PQresultErrorField(result, PG_DIAG_STATEMENT_POSITION);
	const char* internal_position = PQresultErrorField(result, PG_DIAG_INTERNAL_POSITION);
	const char* internal_query = PQresultErrorField(result, PG_DIAG_INTERNAL_QUERY);
	const char* context = PQresultErrorField(result, PG_DIAG_CONTEXT);
	const char* schema_name = PQresultErrorField(result, PG_DIAG_SCHEMA_NAME);
	const char* table_name = PQresultErrorField(result, PG_DIAG_TABLE_NAME);
	const char* column_name = PQresultErrorField(result, PG_DIAG_COLUMN_NAME);
	const char* datatype_name = PQresultErrorField(result, PG_DIAG_DATATYPE_NAME);
	const char* constraint_name = PQresultErrorField(result, PG_DIAG_CONSTRAINT_NAME);
	const char* source_file = PQresultErrorField(result, PG_DIAG_SOURCE_FILE);
	const char* source_line = PQresultErrorField(result, PG_DIAG_SOURCE_LINE);
	const char* source_function = PQresultErrorField(result, PG_DIAG_SOURCE_FUNCTION);

	unsigned int size = 1 + 4 + 1; // 'E', length, null byte

	if (severity) size += strlen(severity) + 1 + 1;
	if (text) size += strlen(text) + 1 + 1;
	if (sqlstate) size += strlen(sqlstate) + 1 + 1;
	if (primary) size += strlen(primary) + 1 + 1;
	if (detail) size += strlen(detail) + 1 + 1;
	if (hint) size += strlen(hint) + 1 + 1;
	if (position) size += strlen(position) + 1 + 1;
	if (internal_position) size += strlen(internal_position) + 1 + 1;
	if (internal_query) size += strlen(internal_query) + 1 + 1;
	if (context) size += strlen(context) + 1 + 1;
	if (schema_name) size += strlen(schema_name) + 1 + 1;
	if (table_name) size += strlen(table_name) + 1 + 1;
	if (column_name) size += strlen(column_name) + 1 + 1;
	if (datatype_name) size += strlen(datatype_name) + 1 + 1;
	if (constraint_name) size += strlen(constraint_name) + 1 + 1;
	if (source_file) size += strlen(source_file) + 1 + 1;
	if (source_line) size += strlen(source_line) + 1 + 1;
	if (source_function) size += strlen(source_function) + 1 + 1;

	bool alloced_new_buffer = false;
	unsigned char* _ptr = pg_query_result->buffer_reserve_space(size);
	
	// buffer is not enough to store the new row. Remember we have already pushed data to PSarrayOUT
	if (_ptr == NULL) {
		_ptr = (unsigned char*)l_alloc(size);
		alloced_new_buffer = true;
	}

	PG_pkt pgpkt(_ptr, size);

	pgpkt.put_char('E');
	pgpkt.put_uint32(size - 1); 
	if (severity) {
		pgpkt.put_char('S');
		pgpkt.put_string(severity);
	}
	if (text) {
		pgpkt.put_char('V');
		pgpkt.put_string(text);
	}
	if (sqlstate) {
		pgpkt.put_char('C');
		pgpkt.put_string(sqlstate);
	}
	if (primary) {
		pgpkt.put_char('M');
		pgpkt.put_string(primary);
	}
	if (detail) {
		pgpkt.put_char('D');
		pgpkt.put_string(detail);
	}
	if (hint) {
		pgpkt.put_char('H');
		pgpkt.put_string(hint);
	}
	if (position) {
		pgpkt.put_char('P');
		pgpkt.put_string(position);
	}
	if (internal_position) {
		pgpkt.put_char('p');
		pgpkt.put_string(internal_position);
	}
	if (internal_query) {
		pgpkt.put_char('q');
		pgpkt.put_string(internal_query);
	}
	if (context) {
		pgpkt.put_char('W');
		pgpkt.put_string(context);
	}
	if (schema_name) {
		pgpkt.put_char('s');
		pgpkt.put_string(schema_name);
	}
	if (table_name) {
		pgpkt.put_char('t');
		pgpkt.put_string(table_name);
	}
	if (column_name) {
		pgpkt.put_char('c');
		pgpkt.put_string(column_name);
	}
	if (datatype_name) {
		pgpkt.put_char('d');
		pgpkt.put_string(datatype_name);
	}
	if (constraint_name) {
		pgpkt.put_char('n');
		pgpkt.put_string(constraint_name);
	}
	if (source_file) {
		pgpkt.put_char('F');
		pgpkt.put_string(source_file);
	}
	if (source_line) {
		pgpkt.put_char('L');
		pgpkt.put_string(source_line);
	}
	if (source_function) {
		pgpkt.put_char('R');
		pgpkt.put_string(source_function);
	}
	pgpkt.put_char('\0');

	if (send == true) {
		// not supported
		//(*myds)->PSarrayOUT->add((void*)_ptr, size); 
	}
	
	pg_query_result->resultset_size += size;

	if (alloced_new_buffer) {
		// we created new buffer
		//pg_query_result->buffer_to_PSarrayOut();
		pg_query_result->PSarrayOUT.add(_ptr, size);
	}
	pg_query_result->pkt_count++;
	return size;
}

unsigned int PgSQL_Protocol::copy_empty_query_response_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PGresult* result) {
	assert(pg_query_result);
	// we are currently not using result. It is just for future use

	const unsigned int size = 1 + 4; // I, length
	bool alloced_new_buffer = false;

	unsigned char* _ptr = pg_query_result->buffer_reserve_space(size);

	// buffer is not enough to store the new row. Remember we have already pushed data to PSarrayOUT
	if (_ptr == NULL) {
		_ptr = (unsigned char*)l_alloc(size);
		alloced_new_buffer = true;
	}

	PG_pkt pgpkt(_ptr, size);

	pgpkt.put_char('I');
	pgpkt.put_uint32(size - 1);

	if (send == true) {
		// not supported
		//(*myds)->PSarrayOUT->add((void*)_ptr, size); 
	}

	pg_query_result->resultset_size += size;

	if (alloced_new_buffer) {
		// we created new buffer
		//pg_query_result->buffer_to_PSarrayOut();
		pg_query_result->PSarrayOUT.add(_ptr, size);
	}
	pg_query_result->pkt_count++;
	return size;
}

unsigned int PgSQL_Protocol::copy_ready_status_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, PGTransactionStatusType txn_status) {
	assert(pg_query_result);

	char txn_state = 'I';
	if (txn_status == PQTRANS_INTRANS)
		txn_state = 'T';
	else if (txn_status == PQTRANS_INERROR)
		txn_state = 'E';

	const unsigned int size = 1 + 4 + 1; // Z, length, I/T/E
	bool alloced_new_buffer = false;

	unsigned char* _ptr = pg_query_result->buffer_reserve_space(size);

	// buffer is not enough to store the new row. Remember we have already pushed data to PSarrayOUT
	if (_ptr == NULL) {
		_ptr = (unsigned char*)l_alloc(size);
		alloced_new_buffer = true;
	}

	PG_pkt pgpkt(_ptr, size);

	pgpkt.put_char('Z');
	pgpkt.put_uint32(size - 1);
	pgpkt.put_char(txn_state);

	if (send == true) {
		// not supported
		//(*myds)->PSarrayOUT->add((void*)_ptr, size); 
	}

	pg_query_result->resultset_size += size;

	if (alloced_new_buffer) {
		// we created new buffer
		//pg_query_result->buffer_to_PSarrayOut();
		pg_query_result->PSarrayOUT.add(_ptr, size);
	}
	pg_query_result->pkt_count++;
	return size;
}

unsigned int PgSQL_Protocol::copy_buffer_to_PgSQL_Query_Result(bool send, PgSQL_Query_Result* pg_query_result, const PSresult* result) {
	assert(pg_query_result);
	assert(result && result->len && result->data);

	bool alloced_new_buffer = false;

	const unsigned int size = result->len;
	unsigned char* _ptr = pg_query_result->buffer_reserve_space(size);

	// buffer is not enough to store the new row. Remember we have already pushed data to PSarrayOUT
	if (_ptr == NULL) {
		_ptr = (unsigned char*)l_alloc(size);
		alloced_new_buffer = true;
	}

	memcpy(_ptr, result->data, size);

	if (send == true) {
		// not supported
		//(*myds)->PSarrayOUT->add((void*)_ptr, size); 
	}

	pg_query_result->resultset_size += size;

	if (alloced_new_buffer) {
		// we created new buffer
		//pg_query_result->buffer_to_PSarrayOut();
		pg_query_result->PSarrayOUT.add(_ptr, size);
	}
	pg_query_result->pkt_count++;

	// assuming single-row result
	if (result->id == 'D')
		pg_query_result->num_rows += 1;

	return size;
}

PgSQL_Query_Result::PgSQL_Query_Result() {
	buffer = NULL;
	transfer_started = false;
	buffer_used = 0;
	resultset_size = 0;
	num_fields = 0;
	num_rows = 0;
	pkt_count = 0;
	affected_rows = -1;
	result_packet_type = PGSQL_QUERY_RESULT_NO_DATA;
}

PgSQL_Query_Result::~PgSQL_Query_Result() {
	PtrSize_t pkt;
	while (PSarrayOUT.len) {
		PSarrayOUT.remove_index_fast(0, &pkt);
		l_free(pkt.size, pkt.ptr);
	}

	if (buffer) {
		free(buffer);
		buffer = NULL;
	}
}

void PgSQL_Query_Result::buffer_init() {
	if (buffer == NULL) {
		buffer = (unsigned char*)malloc(PGSQL_RESULTSET_BUFLEN);
	}
	buffer_used = 0;
}

void PgSQL_Query_Result::init(PgSQL_Protocol* _proto, PgSQL_Data_Stream* _myds, PgSQL_Connection* _conn) {
	PROXY_TRACE2();
	transfer_started = false;
	proto = _proto;
	conn = _conn;
	myds = _myds;
	buffer_init();
	reset();

	if (proto == NULL) {
		return; // this is a mirror
	}
}

unsigned int PgSQL_Query_Result::add_row_description(const PGresult* result) {
	const unsigned int res = proto->copy_row_description_to_PgSQL_Query_Result(false, this, result);
	result_packet_type |= PGSQL_QUERY_RESULT_TUPLE;
	return res;
}

unsigned int PgSQL_Query_Result::add_row(const PGresult* result) {

	return proto->copy_row_to_PgSQL_Query_Result(false,this, result);
}

unsigned int PgSQL_Query_Result::add_row(const PSresult* result) {

	const unsigned int res = proto->copy_buffer_to_PgSQL_Query_Result(false, this, result);
	result_packet_type |= PGSQL_QUERY_RESULT_TUPLE; // temporary
	return res;
}

unsigned int PgSQL_Query_Result::add_error(const PGresult* result) {
	unsigned int size = 0;

	if (result) {
		size = proto->copy_error_to_PgSQL_Query_Result(false, this, result);
		PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::proxysql, conn->parent->myhgc->hid, conn->parent->address, conn->parent->port, 1907);
	}
	else {
		PtrSize_t pkt;
		if (myds && myds->killed_at) { // see case #750
			if (myds->kill_type == 0) {
				proto->generate_error_packet(false, false, (char*)"Query execution was interrupted, query_timeout exceeded",
					PGSQL_ERROR_CODES::ERRCODE_QUERY_CANCELED, false, false, &pkt);
				PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::proxysql, conn->parent->myhgc->hid, conn->parent->address, conn->parent->port, 1907);
			} else {
				proto->generate_error_packet(false, false, (char*)"Query execution was interrupted",
					PGSQL_ERROR_CODES::ERRCODE_QUERY_CANCELED, false, false, &pkt);
				PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::proxysql, conn->parent->myhgc->hid, conn->parent->address, conn->parent->port, 1317);
			}
		} else if (conn->is_error_present()) {
			proto->generate_error_packet(false, false, conn->get_error_message().c_str(), conn->get_error_code(), false, false, &pkt);
			PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::proxysql, conn->parent->myhgc->hid, conn->parent->address, conn->parent->port, 1907);
		} else {
			assert(0); // should never reach here
		}

		PSarrayOUT.add(pkt.ptr, pkt.size);
		resultset_size += pkt.size;
		size = pkt.size;
	}

	result_packet_type |= PGSQL_QUERY_RESULT_ERROR;
	return size;
}

unsigned int PgSQL_Query_Result::add_empty_query_response(const PGresult* result) {
	const unsigned int bytes = proto->copy_empty_query_response_to_PgSQL_Query_Result(false, this, result);
	result_packet_type |= PGSQL_QUERY_RESULT_EMPTY;
	return bytes;
}

unsigned int PgSQL_Query_Result::add_ready_status(PGTransactionStatusType txn_status) {
	const unsigned int bytes = proto->copy_ready_status_to_PgSQL_Query_Result(false, this, txn_status);
	buffer_to_PSarrayOut();
	result_packet_type |= PGSQL_QUERY_RESULT_READY;
	return bytes;
}

bool PgSQL_Query_Result::get_resultset(PtrSizeArray* PSarrayFinal) {
	transfer_started = true;
	// Ready packet confirms that the result is complete
	const bool result_complete = (result_packet_type & PGSQL_QUERY_RESULT_READY);
	if (result_complete == true) {
		assert(buffer_used == 0); // we still have data in the buffer
	} else {
		buffer_to_PSarrayOut();
	}

	if (proto) {
		PSarrayFinal->copy_add(&PSarrayOUT, 0, PSarrayOUT.len);
		while (PSarrayOUT.len)
			PSarrayOUT.remove_index(PSarrayOUT.len - 1, NULL);
	}
	if (result_complete) 
		reset(); // reset only if result is complete
	return result_complete;
}

void PgSQL_Query_Result::buffer_to_PSarrayOut() {
	if (buffer_used == 0)
		return;	// exit immediately if the buffer is empty
	if (buffer_used < PGSQL_RESULTSET_BUFLEN / 2) {
		buffer = (unsigned char*)realloc(buffer, buffer_used);
	}
	PSarrayOUT.add(buffer, buffer_used);
	buffer = (unsigned char*)malloc(PGSQL_RESULTSET_BUFLEN);
	buffer_used = 0;
}

unsigned long long PgSQL_Query_Result::current_size() {
	unsigned long long intsize = 0;
	intsize += sizeof(PgSQL_Query_Result);
	intsize += PGSQL_RESULTSET_BUFLEN; // size of buffer
	if (PSarrayOUT.len == 0)	// see bug #699
		return intsize;
	intsize += sizeof(PtrSizeArray);
	intsize += (PSarrayOUT.size * sizeof(PtrSize_t*));
	unsigned int i;
	for (i = 0; i < PSarrayOUT.len; i++) {
		PtrSize_t* pkt = PSarrayOUT.index(i);
		if (pkt->size > PGSQL_RESULTSET_BUFLEN) {
			intsize += pkt->size;
		}
		else {
			intsize += PGSQL_RESULTSET_BUFLEN;
		}
	}
	return intsize;
}

unsigned int PgSQL_Query_Result::add_command_completion(const PGresult* result, bool extract_affected_rows) {
	const unsigned int bytes = proto->copy_command_completion_to_PgSQL_Query_Result(false, this, result, extract_affected_rows);
	result_packet_type |= PGSQL_QUERY_RESULT_COMMAND;
	/*if (affected_rows) {
		myds->sess->CurrentQuery.have_affected_rows = true; // if affected rows is set, last_insert_id is set too
		myds->sess->CurrentQuery.affected_rows = affected_rows;
		myds->sess->CurrentQuery.last_insert_id = 0; // not supported
	}*/
	return bytes;
}

unsigned char* PgSQL_Query_Result::buffer_reserve_space(unsigned int size) {
	unsigned char* ret_buffer = NULL;
	if (size <= buffer_available_capacity()) {
		// there is space in the buffer, add the data to it
		ret_buffer = buffer + buffer_used;
		buffer_used += size;
	}
	else {
		// there is no space in the buffer, we flush the buffer and recreate it
		buffer_to_PSarrayOut();
		// now we can check again if there is space in the buffer
		if (size <= buffer_available_capacity()) {
			// there is space in the NEW buffer, add the data to it
			ret_buffer = buffer + buffer_used;
			buffer_used += size;
		}
	}
	return ret_buffer;
}

void PgSQL_Query_Result::reset() {
	resultset_size = 0;
	num_fields = 0;
	num_rows = 0;
	pkt_count = 0;
	affected_rows = -1;
	result_packet_type = PGSQL_QUERY_RESULT_NO_DATA;
}
