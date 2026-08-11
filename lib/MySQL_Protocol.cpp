#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "openssl/rand.h"
#include "proxysql.h"
#include "cpp.h"
#include "re2/re2.h"
#include "re2/regexp.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_Passthrough_Auth_Cache.h"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_Variables.h"
#ifdef PROXYSQL31
#include "MySQL_Caching_Sha2_RSA.h"
#include <openssl/crypto.h>
#endif

#include <sstream>
#include <zstd.h>

//#include <ma_global.h>

extern MySQL_Authentication *GloMyAuth;
extern MySQL_Passthrough_Auth_Cache *GloMyPTAuthCache;
extern MySQL_LDAP_Authentication *GloMyLdapAuth;
extern MySQL_Threads_Handler *GloMTH;

#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Authentication *GloClickHouseAuth;
#endif /* PROXYSQLCLICKHOUSE */

#ifdef max_allowed_packet
#undef max_allowed_packet
#endif

#ifndef CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA 0x00200000
#endif

#include "proxysql_find_charset.h"

mf_unique_ptr<const char> get_masked_pass(const char* pass) {
	return mf_unique_ptr<const char>(
		static_cast<const char*>(strdup(pass == nullptr ? "(null)" : "(redacted)"))
	);
}

namespace {

void cleanse_and_free_password(char*& password) {
	if (password != nullptr) {
		OPENSSL_cleanse(password, strlen(password));
		free(password);
		password = nullptr;
	}
}

void cleanse_and_free_auth_response(unsigned char*& response, size_t response_size) {
	if (response != nullptr) {
		OPENSSL_cleanse(response, response_size);
		char* allocation = reinterpret_cast<char*>(response);
		response = nullptr;
		cleanse_and_free_password(allocation);
	}
}

class ScopedStringCleanser {
	std::string& value_;

	public:
	explicit ScopedStringCleanser(std::string& value) : value_(value) {}
	~ScopedStringCleanser() {
		if (!value_.empty()) {
			OPENSSL_cleanse(value_.data(), value_.size());
		}
	}
	ScopedStringCleanser(const ScopedStringCleanser&) = delete;
	ScopedStringCleanser& operator=(const ScopedStringCleanser&) = delete;
	ScopedStringCleanser(ScopedStringCleanser&&) = delete;
	ScopedStringCleanser& operator=(ScopedStringCleanser&&) = delete;
};

} // namespace

extern "C" char * sha256_crypt_r (const char *key, const char *salt, char *buffer, int buflen);

static const char *plugins[3] = {
	"mysql_native_password",
	"mysql_clear_password",
	"caching_sha2_password",
};

#ifdef PROXYSQL31
enum class frontend_auth_context : uint8_t {
	INITIAL_HANDSHAKE,
	COM_CHANGE_USER,
	PASSTHROUGH
};

struct frontend_certificate_policy_result {
	bool allowed { true };
	bool has_spiffe_id { false };
};

static bool evaluate_require_x509(
	MySQL_Data_Stream* myds,
	const json& attrs,
	const char* username,
	frontend_auth_context context,
	int calling_line,
	const char* calling_func
) {
	const auto require_x509 = attrs.find("require_x509");
	if (require_x509 == attrs.end()) return true;
	if (!require_x509->is_boolean()) {
		proxy_error("%d:%s(): Invalid require_x509 type for user %s\n", calling_line, calling_func, username);
		return false;
	}
	if (!require_x509->get<bool>()) return true;

	const bool allowed = myds
		&& myds->encrypted
		&& myds->ssl
		&& myds->client_cert_present
		&& myds->client_cert_verify_result == X509_V_OK;
	if (!allowed) {
		proxy_error("%d:%s(): Frontend X509 authentication error for user %s: context=%u cert_present=%s verify_result=%ld\n",
			calling_line, calling_func, username, static_cast<unsigned>(context),
			(myds && myds->client_cert_present) ? "yes" : "no",
			myds ? myds->client_cert_verify_result : X509_V_ERR_UNSPECIFIED);
	}
	return allowed;
}

static bool spiffe_identity_matches(MySQL_Data_Stream* myds, const std::string& expected) {
	if (!myds || !myds->x509_subject_alt_name) return false;
	if (expected.rfind("!", 0) == 0 && expected.size() > 1) {
		const string pattern { expected.substr(1) };
		re2::RE2::Options opts { re2::RE2::Quiet };
		re2::RE2 subject_alt_regex(pattern, opts);
		return re2::RE2::FullMatch(myds->x509_subject_alt_name.get(), subject_alt_regex);
	}
	return expected.rfind("spiffe://", 0) == 0
		&& expected == myds->x509_subject_alt_name.get();
}

static bool evaluate_spiffe_identity(
	MySQL_Data_Stream* myds,
	const json::const_iterator& spiffe_id,
	const char* username,
	frontend_auth_context context,
	int calling_line,
	const char* calling_func
) {
	if (context == frontend_auth_context::COM_CHANGE_USER) {
		proxy_error("%d:%s(): COM_CHANGE_USER target %s has a SPIFFE identity\n",
			calling_line, calling_func, username);
		return false;
	}
	if (!spiffe_id->is_string()) {
		proxy_error("%d:%s(): Invalid spiffe_id type for user %s\n", calling_line, calling_func, username);
		return false;
	}

	const std::string expected = spiffe_id->get<std::string>();
	const bool allowed = spiffe_identity_matches(myds, expected);
	if (!allowed) {
		proxy_error("%d:%s(): SPIFFE Authentication error for user %s . spiffed_id expected : %s , received: %s\n",
			calling_line, calling_func, username, expected.c_str(),
			(myds && myds->x509_subject_alt_name) ? myds->x509_subject_alt_name.get() : "none");
	}
	return allowed;
}

static frontend_certificate_policy_result evaluate_frontend_certificate_policy(
	MySQL_Data_Stream* myds,
	const json& attrs,
	const unsigned char* user,
	frontend_auth_context context,
	int calling_line,
	const char* calling_func
) {
	frontend_certificate_policy_result result;
	const char* username = user ? reinterpret_cast<const char*>(user) : "unknown";
	if (!attrs.is_object()) {
		proxy_error("%d:%s(): Invalid user attributes for user %s\n", calling_line, calling_func, username);
		result.allowed = false;
		return result;
	}
	const auto spiffe_id = attrs.find("spiffe_id");
	result.has_spiffe_id = spiffe_id != attrs.end();
	result.allowed = evaluate_require_x509(
		myds, attrs, username, context, calling_line, calling_func);
	if (!result.allowed) return result;
	if (spiffe_id == attrs.end()) return result;
	result.allowed = evaluate_spiffe_identity(
		myds, spiffe_id, username, context, calling_line, calling_func);
	return result;
}

static frontend_certificate_policy_result evaluate_frontend_certificate_policy(
	MySQL_Data_Stream* myds,
	const char* attributes,
	const unsigned char* user,
	frontend_auth_context context,
	int calling_line,
	const char* calling_func
) {
	frontend_certificate_policy_result result;
	if (!attributes || !*attributes) return result;

	try {
		const json attrs = json::parse(attributes);
		return evaluate_frontend_certificate_policy(myds, attrs, user, context, calling_line, calling_func);
	} catch (const nlohmann::json::exception& e) {
		proxy_error("%d:%s(): Invalid user attributes for user %s: %s\n", calling_line, calling_func,
			user ? reinterpret_cast<const char*>(user) : "unknown", e.what());
		result.allowed = false;
		return result;
	}
}
#endif

#include "MySQL_encode.h"

char* get_password(account_details_t& ad, PASSWORD_TYPE::E passtype) {
	char* ret = nullptr;

	if (ad.clear_text_password[passtype] == NULL) {
		if (passtype == PASSWORD_TYPE::PRIMARY) {
			if (ad.password) {
				ret = strdup(ad.password);
			}
		} else if (ad.attributes) {
			const nlohmann::json attrs = nlohmann::json::parse(ad.attributes, nullptr, false);
			string addl_pass { get_nested_elem_val(attrs, { "additional_password" }, string {}) };
			ScopedStringCleanser addl_pass_cleanser(addl_pass);
			string uh_addl_pass { unhex(addl_pass) };
			ScopedStringCleanser uh_addl_pass_cleanser(uh_addl_pass);
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 3,
				"Additional password info length:%zu, value:`(redacted)`\n",
				uh_addl_pass.length());
			ret = reinterpret_cast<char*>(strdup(uh_addl_pass.c_str()));
		}
	} else {
		// best password we have; if we were able to derive the clear text password, we provide that
		ret = strdup(ad.clear_text_password[passtype]);

		// Only count one attempt using the cache per connection
		if (passtype == PASSWORD_TYPE::PRIMARY) {
			__sync_add_and_fetch(&MyHGM->status.client_connections_sha2cached, 1);
		}
	}

	return ret;
}

#ifdef DEBUG
void debug_spiffe_id(const unsigned char *user, const char *attributes, int __line, const char *__func) {
	if (attributes!=NULL && strlen(attributes)) {
		proxy_info("%d:%s(): Attributes for user %s are present; values redacted\n",
			__line, __func, user);
	}
}
#endif


void MySQL_Protocol::init(MySQL_Data_Stream **__myds, MySQL_Connection_userinfo *__userinfo, MySQL_Session *__sess) {
	myds=__myds;
	userinfo=__userinfo;
	sess=__sess;
	current_PreStmt=NULL;
#ifdef PROXYSQL31
	caching_sha2_rsa_snapshot_.reset();
	frontend_auth_error_ = MySQLFrontendAuthError::NONE;
#endif
}

static unsigned char protocol_version=10;
static uint16_t server_status=SERVER_STATUS_AUTOCOMMIT;

bool MySQL_Protocol::generate_statistics_response(bool send, void **ptr, unsigned int *len) {
// FIXME : this function generates a not useful string. It is a placeholder for now

	char buf1[1000];
	unsigned long long t1=monotonic_time();
	sprintf(buf1,"Uptime: %llu Threads: %d  Questions: %llu  Slow queries: %llu", (t1-GloVars.global.start_time)/1000/1000, MyHGM->status.client_connections , GloMTH->get_status_variable(st_var_queries,p_th_counter::questions) , GloMTH->get_status_variable(st_var_queries_slow,p_th_counter::slow_queries) );
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

bool MySQL_Protocol::generate_pkt_EOF(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t warnings, uint16_t status, MySQL_ResultSet *myrs) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=5;
	unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
	unsigned char *_ptr = NULL;
	if (myrs == NULL) {
		_ptr = (unsigned char *)l_alloc(size);
	} else {
		_ptr = myrs->buffer + myrs->buffer_used;
		myrs->buffer_used += size;
	}
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	int l=sizeof(mysql_hdr);
	_ptr[l]=0xfe; l++;
	int16_t internal_status = status;
	if (sess) {
		switch (sess->session_type) {
			case PROXYSQL_SESSION_SQLITE:
			case PROXYSQL_SESSION_ADMIN:
			case PROXYSQL_SESSION_STATS:
				internal_status |= SERVER_STATUS_NO_BACKSLASH_ESCAPES;
				break;
			default:
				break;
		}
	}
	if (*myds && (*myds)->myconn) {
		if ((*myds)->myconn->options.no_backslash_escapes) {
			internal_status |= SERVER_STATUS_NO_BACKSLASH_ESCAPES;
		}
		(*myds)->pkt_sid=sequence_id;
	}
	memcpy(_ptr+l, &warnings, sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l, &internal_status, sizeof(uint16_t));
	
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
	if (*myds) {
		(*myds)->pkt_sid=sequence_id;
	}
	return true;
}

bool MySQL_Protocol::generate_pkt_ERR(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t error_code, const char *sql_state, const char *sql_message, bool track) {
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
			case STATE_ERR:
				(*myds)->DSS=STATE_ERR;
				break;
			case STATE_OK:
				break;
			case STATE_SLEEP:
				if ((*myds)->sess->session_fast_forward) { // see issue #733
					break;
				}
			default:
				// LCOV_EXCL_START
				assert(0);
				// LCOV_EXCL_STOP
		}
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	if (track)
		if (*myds)
			if ((*myds)->sess)
				if ((*myds)->sess->thread)
					(*myds)->sess->thread->status_variables.stvar[st_var_generated_pkt_err]++;
	if (*myds) {
		(*myds)->pkt_sid=sequence_id;
	}
	return true;
}

bool MySQL_Protocol::generate_one_byte_pkt(unsigned char b) {
#ifdef PROXYSQL31
	return generate_auth_more_data(&b, 1);
#else
	assert((*myds) != NULL);
	uint8_t sequence_id;
	sequence_id = (*myds)->pkt_sid;
	sequence_id++;
	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=2;
	unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
	unsigned char *_ptr=(unsigned char *)l_alloc(size);
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	int l=sizeof(mysql_hdr);
	_ptr[l]=1;
	l++;
	_ptr[l]=b;
	(*myds)->PSarrayOUT->add((void *)_ptr,size);
	(*myds)->pkt_sid=sequence_id;
	return true;
#endif
}

#ifdef PROXYSQL31
bool MySQL_Protocol::generate_auth_more_data(const unsigned char *data, size_t data_len) {
	assert((*myds) != NULL);
	assert(data != NULL || data_len == 0);
	assert(data_len <= 0xFFFFFFU - 1);

	uint8_t sequence_id = (*myds)->pkt_sid + 1;
	mysql_hdr myhdr;
	myhdr.pkt_id = sequence_id;
	myhdr.pkt_length = static_cast<uint32_t>(data_len + 1);

	const unsigned int size = myhdr.pkt_length + sizeof(mysql_hdr);
	unsigned char *_ptr = static_cast<unsigned char *>(l_alloc(size));
	if (_ptr == nullptr) {
		return false;
	}
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	_ptr[sizeof(mysql_hdr)] = 0x01;
	if (data_len != 0) {
		memcpy(_ptr + sizeof(mysql_hdr) + 1, data, data_len);
	}

	(*myds)->PSarrayOUT->add(static_cast<void *>(_ptr), size);
	(*myds)->pkt_sid = sequence_id;
	return true;
}

MySQLFrontendAuthError MySQL_Protocol::consume_frontend_auth_error() {
	const MySQLFrontendAuthError error = frontend_auth_error_;
	frontend_auth_error_ = MySQLFrontendAuthError::NONE;
	return error;
}
#endif

bool MySQL_Protocol::generate_pkt_OK(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, unsigned int affected_rows, uint64_t last_insert_id, uint16_t status, uint16_t warnings, char *msg, bool eof_identifier) {
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

	bool client_session_track=false;
	//char gtid_buf[128];
	char gtid_prefix;
	uint8_t gtid_len=0;
	uint8_t gtid_len_len=0;

	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=1+affected_rows_len+last_insert_id_len+sizeof(uint16_t)+sizeof(uint16_t)+msg_len;
	if (msg_len) myhdr.pkt_length+=msg_len_len;

	if (*myds && (*myds)->myconn) {
		if ((*myds)->myconn->options.client_flag & CLIENT_SESSION_TRACKING) {
			if (mysql_thread___client_session_track_gtid) {
				if (sess) {
					if (sess->gtid_hid >= 0) {
						if (msg_len == 0) {
							myhdr.pkt_length++;
						}
						client_session_track=true;
						gtid_len = strlen(sess->gtid_buf);
						gtid_len_len = mysql_encode_length(gtid_len, &gtid_prefix);
						myhdr.pkt_length += gtid_len_len;
						myhdr.pkt_length += gtid_len;
						myhdr.pkt_length += 4; // headers related to GTID
					}
				}
			}
		}
	}


	unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
	unsigned char *_ptr=(unsigned char *)l_alloc(size);
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	int l=sizeof(mysql_hdr);

	/*
	 * Use 0xFE packet header if eof_identifier is true.
	 * OK packet with 0xFE replaces EOF packet for clients
	 * supporting CLIENT_DEPRECATE_EOF flag
	 */
	if (eof_identifier)
		_ptr[l]=0xFE;
	else
		_ptr[l]=0x00;

	l++;
	l+=write_encoded_length(_ptr+l, affected_rows, affected_rows_len, affected_rows_prefix);
	l+=write_encoded_length(_ptr+l, last_insert_id, last_insert_id_len, last_insert_id_prefix);
	int16_t internal_status = status;
	if (sess) {
		switch (sess->session_type) {
			case PROXYSQL_SESSION_SQLITE:
			case PROXYSQL_SESSION_ADMIN:
			case PROXYSQL_SESSION_STATS:
				internal_status |= SERVER_STATUS_NO_BACKSLASH_ESCAPES;
				break;
			default:
				break;
		}
		if (sess->session_type == PROXYSQL_SESSION_MYSQL) {
			sess->CurrentQuery.have_affected_rows = true; // if affected rows is set, last_insert_id is set too
			sess->CurrentQuery.affected_rows = affected_rows;
			sess->CurrentQuery.last_insert_id = last_insert_id;
		}
	}
	if (*myds && (*myds)->myconn) {
		if ((*myds)->myconn->options.no_backslash_escapes) {
			internal_status |= SERVER_STATUS_NO_BACKSLASH_ESCAPES;
		}
	}
	if (gtid_len == 0) {
		// Remove 'SERVER_SESSION_STATE_CHANGED', since we don't track this info unless GTID related
		internal_status &= ~SERVER_SESSION_STATE_CHANGED;
	}
	memcpy(_ptr+l, &internal_status, sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l, &warnings, sizeof(uint16_t)); l+=sizeof(uint16_t);
	if (msg && strlen(msg)) {
		l+=write_encoded_length(_ptr+l, msg_len, msg_len_len, msg_prefix);
		memcpy(_ptr+l, msg, msg_len);
	}
	l+=msg_len;
	if (client_session_track == true) {
		if (msg_len == 0) {
			_ptr[l]=0x00; l++;
		}
		if (gtid_len) {
			unsigned char gtid_prefix_h1 = gtid_len+2;
			unsigned char state_change_prefix = gtid_prefix_h1+2;
			_ptr[l] = state_change_prefix; l++;
			_ptr[l]=0x03; l++; // SESSION_TRACK_GTIDS
			_ptr[l] = gtid_prefix_h1; l++;
			_ptr[l]=0x00; l++;
			// l+=write_encoded_length(_ptr+l, gtid_len, gtid_len_len, gtid_prefix); // overcomplicated
			_ptr[l] = gtid_len; l++;
			memcpy(_ptr+l, sess->gtid_buf, gtid_len);
		}
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
			case STATE_ROW:
				if (eof_identifier)
					(*myds)->DSS=STATE_EOF2;
				else
					// LCOV_EXCL_START
					assert(0);
					// LCOV_EXCL_STOP
				break;
			default:
				// LCOV_EXCL_START
				assert(0);
				// LCOV_EXCL_STOP
		}
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	if (*myds) {
		(*myds)->pkt_sid=sequence_id;
	}
	return true;
}

bool MySQL_Protocol::generate_pkt_column_count(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint64_t count, MySQL_ResultSet *myrs) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}

	char count_prefix=0;
	uint8_t count_len=mysql_encode_length(count, &count_prefix);

	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=count_len;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
//  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  unsigned char *_ptr = NULL;
	if (myrs) {
		if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
			// there is space in the buffer, add the data to it
			_ptr = myrs->buffer + myrs->buffer_used;
			myrs->buffer_used += size;
		} else {
			// there is no space in the buffer, we flush the buffer and recreate it
			myrs->buffer_to_PSarrayOut();
			// now we can check again if there is space in the buffer
			if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
				// there is space in the NEW buffer, add the data to it
				_ptr = myrs->buffer + myrs->buffer_used;
				myrs->buffer_used += size;
			} else {
				// a new buffer is not enough to store the new row
				_ptr=(unsigned char *)l_alloc(size);
			}
		}
	} else {
		_ptr=(unsigned char *)l_alloc(size);
	}
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);

	l+=write_encoded_length(_ptr+l, count, count_len, count_prefix);

	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	if (myrs) {
		if (_ptr >= myrs->buffer && _ptr < myrs->buffer+RESULTSET_BUFLEN) {
			// we are writing within the buffer, do not add to PSarrayOUT
		} else {
			// we are writing outside the buffer, add to PSarrayOUT
			myrs->PSarrayOUT.add(_ptr,size);
		}
	}
	return true;
}


// this is an optimized version of generate_pkt_field() that uses MYSQL_FIELD
// in order to avoid recomputing the length of the various fields
// it also cannot handle field_list
bool MySQL_Protocol::generate_pkt_field2(void **ptr, unsigned int *len, uint8_t sequence_id, MYSQL_FIELD *field, MySQL_ResultSet *myrs) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	//char *def=(char *)"def";
	//uint32_t def_strlen = field->catalog_length;
	char def_prefix;
	uint8_t def_len=mysql_encode_length(field->catalog_length, &def_prefix);

	//uint32_t schema_strlen=strlen(schema);
	char schema_prefix;
	uint8_t schema_len=mysql_encode_length(field->db_length, &schema_prefix);

	//uint32_t table_strlen=strlen(table);
	char table_prefix;
	uint8_t table_len=mysql_encode_length(field->table_length, &table_prefix);

	//uint32_t org_table_strlen=strlen(org_table);
	char org_table_prefix;
	uint8_t org_table_len=mysql_encode_length(field->org_table_length, &org_table_prefix);

	//uint32_t name_strlen=strlen(name);
	char name_prefix;
	uint8_t name_len=mysql_encode_length(field->name_length, &name_prefix);

	//uint32_t org_name_strlen=strlen(org_name);
	char org_name_prefix;
	uint8_t org_name_len=mysql_encode_length(field->org_name_length, &org_name_prefix);

/*
	char defvalue_length_prefix;
	uint8_t defvalue_length_len=0;
	if (field_list) {
		defvalue_length_len=mysql_encode_length(field->def_length, &defvalue_length_prefix);
	}
*/
	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length = def_len + field->catalog_length
		+ schema_len + field->db_length
		+ table_len + field->table_length
		+ org_table_len + field->org_table_length
		+ name_len + field->name_length
		+ org_name_len + field->org_name_length
		+ 1  // filler
		+ sizeof(uint16_t) // charset
		+ sizeof(uint32_t) // column_length
		+ sizeof(uint8_t)  // type
		+ sizeof(uint16_t) // flags
		+ sizeof(uint8_t)  // decimals
		+ 2; // filler
/*
	if (field_list) {
		myhdr.pkt_length += defvalue_length_len + strlen(defvalue);
	}
*/
	unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
	unsigned char *_ptr = NULL;
/* myrs always passed
	if (myrs) {
*/
		if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
			// there is space in the buffer, add the data to it
			_ptr = myrs->buffer + myrs->buffer_used;
			myrs->buffer_used += size;
		} else {
			// there is no space in the buffer, we flush the buffer and recreate it
			myrs->buffer_to_PSarrayOut();
			// now we can check again if there is space in the buffer
			if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
				// there is space in the NEW buffer, add the data to it
				_ptr = myrs->buffer + myrs->buffer_used;
				myrs->buffer_used += size;
			} else {
				// a new buffer is not enough to store the new row
				_ptr=(unsigned char *)l_alloc(size);
			}
		}
/* myrs always passed
	} else {
		_ptr=(unsigned char *)l_alloc(size);
	}
*/
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	int l=sizeof(mysql_hdr);

	l+=write_encoded_length_and_string(_ptr+l, field->catalog_length, def_len, def_prefix, field->catalog);
	l+=write_encoded_length_and_string(_ptr+l, field->db_length, schema_len, schema_prefix, field->db);
	l+=write_encoded_length_and_string(_ptr+l, field->table_length, table_len, table_prefix, field->table);
	l+=write_encoded_length_and_string(_ptr+l, field->org_table_length, org_table_len, org_table_prefix, field->org_table);
	l+=write_encoded_length_and_string(_ptr+l, field->name_length, name_len, name_prefix, field->name);
	l+=write_encoded_length_and_string(_ptr+l, field->org_name_length, org_name_len, org_name_prefix, field->org_name);
	_ptr[l]=0x0c; l++;
	memcpy(_ptr+l,&field->charsetnr,sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l,&field->length,sizeof(uint32_t)); l+=sizeof(uint32_t);
	_ptr[l]=field->type; l++;
	memcpy(_ptr+l,&field->flags,sizeof(uint16_t)); l+=sizeof(uint16_t);
	_ptr[l]=field->decimals; l++;
	_ptr[l]=0x00; l++;
	_ptr[l]=0x00; l++;
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
/* myrs always passed
	if (myrs) {
*/
		if (_ptr >= myrs->buffer && _ptr < myrs->buffer+RESULTSET_BUFLEN) {
			// we are writing within the buffer, do not add to PSarrayOUT
		} else {
			// we are writing outside the buffer, add to PSarrayOUT
			myrs->PSarrayOUT.add(_ptr,size);
		}
/* myrs always passed
	}
*/
	return true;
}

bool MySQL_Protocol::generate_pkt_field(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, char *schema, char *table, char *org_table, char *name, char *org_name, uint16_t charset, uint32_t column_length, uint8_t type, uint16_t flags, uint8_t decimals, bool field_list, uint64_t defvalue_length, char *defvalue, MySQL_ResultSet *myrs) {

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
  unsigned char *_ptr = NULL;
	if (myrs) {
		if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
			// there is space in the buffer, add the data to it
			_ptr = myrs->buffer + myrs->buffer_used;
			myrs->buffer_used += size;
		} else {
			// there is no space in the buffer, we flush the buffer and recreate it
			myrs->buffer_to_PSarrayOut();
			// now we can check again if there is space in the buffer
			if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
				// there is space in the NEW buffer, add the data to it
				_ptr = myrs->buffer + myrs->buffer_used;
				myrs->buffer_used += size;
			} else {
				// a new buffer is not enough to store the new row
				_ptr=(unsigned char *)l_alloc(size);
			}
		}
	} else {
		_ptr=(unsigned char *)l_alloc(size);
	}
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
	if (myrs) {
		if (_ptr >= myrs->buffer && _ptr < myrs->buffer+RESULTSET_BUFLEN) {
			// we are writing within the buffer, do not add to PSarrayOUT
		} else {
			// we are writing outside the buffer, add to PSarrayOUT
			myrs->PSarrayOUT.add(_ptr,size);
		}
	}
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
	pthread_rwlock_rdlock(&stmt_info->rwlock_);
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
	int setStatus = SERVER_STATUS_AUTOCOMMIT;
	if (myds) {
		setStatus = 0;
		unsigned int Trx_id = (*myds)->sess->FindOneActiveTransaction();
		setStatus = (Trx_id >= 0 ? SERVER_STATUS_IN_TRANS : 0 );
		if ((*myds)->sess->autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
	}
	bool deprecate_eof_active = false;
	if (*myds && (*myds)->myconn) {
		if ((*myds)->myconn->options.client_flag & CLIENT_DEPRECATE_EOF) {
			deprecate_eof_active = true;
		}
	}
	if (stmt_info->num_params) {
		for (i=0; i<stmt_info->num_params; i++) {
			generate_pkt_field(true,NULL,NULL,sid,
				(char *)"", (char *)"", (char *)"", (char *)"?", (char *)"",
				63,0,253,128,0,false,0,NULL); // NOTE: charset is 63 = binary !
			sid++;
		}
		if (!deprecate_eof_active) {
			generate_pkt_EOF(true,NULL,NULL,sid,0,setStatus);
			sid++;
		}
	}
	if (stmt_info->num_columns) {
		for (i=0; i<stmt_info->num_columns; i++) {
			MYSQL_FIELD *fd=stmt_info->fields[i];
			generate_pkt_field(true,NULL,NULL,sid,
				fd->db,
				fd->table, fd->org_table,
				fd->name, fd->org_name,
				fd->charsetnr, fd->length, fd->type, fd->flags, fd->decimals, false,0,NULL);
			sid++;
		}
		if (!deprecate_eof_active) {
			generate_pkt_EOF(true,NULL,NULL,sid,0,setStatus);
			sid++;
		}
	}
	pthread_rwlock_unlock(&stmt_info->rwlock_);
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

uint8_t MySQL_Protocol::generate_pkt_row3(MySQL_ResultSet *myrs, unsigned int *len, uint8_t sequence_id, int colnums, unsigned long *fieldslen, char **fieldstxt, unsigned long rl) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	int col=0;
	unsigned long rowlen=0;
	uint8_t pkt_sid=sequence_id;
	if (rl == 0) {
		// if rl == 0 , we are using text protocol (legacy) therefore we need to compute the size of the row
		for (col=0; col<colnums; col++) {
			rowlen+=( fieldstxt[col] ? fieldslen[col]+mysql_encode_length(fieldslen[col],NULL) : 1 );
		}
	} else {
		// we already know the size of the row
		rowlen=rl;
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
	if (rl == 0) {
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
	} else {
		memcpy((unsigned char *)pkt.ptr+l, fieldstxt, rl);
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
			myrs->PSarrayOUT.add(pkt.ptr,pkt.size);
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
			myrs->PSarrayOUT.add(pkt2.ptr,pkt2.size);
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
		myrs->PSarrayOUT.add(pkt2.ptr,pkt2.size);
	}
	if (len) { *len=pkt.size+(pkt_sid-sequence_id)*sizeof(mysql_hdr); }
	if (pkt.size >= (0xFFFFFF+sizeof(mysql_hdr))) {
		l_free(pkt.size,pkt.ptr);
	}
	return pkt_sid;
}

bool MySQL_Protocol::generate_pkt_auth_switch_request(bool send, void **ptr, unsigned int *len) {
  proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating auth switch request pkt\n");
	const char *plugins_names[3] = { "mysql_native_password", "mysql_clear_password", "caching_sha2_password" };
	size_t plugins_lens[3];
	for (int i=0; i<3; i++)
		plugins_lens[i] = strlen(plugins_names[i]);
  mysql_hdr myhdr;
  myhdr.pkt_id=2;
	if ((*myds)->encrypted) {
		myhdr.pkt_id++;
	}

	// Check if a 'COM_CHANGE_USER' Auth Switch is being performed in session
	if ((*myds)->sess->change_user_auth_switch) {
		myhdr.pkt_id=1;
	}

	switch((*myds)->switching_auth_type) {
		case AUTH_MYSQL_NATIVE_PASSWORD:
			myhdr.pkt_length=1 // fe
				+ (plugins_lens[0]+1)
				+ 20 // scramble
				+ 1; // 00
			break;
		case AUTH_MYSQL_CLEAR_PASSWORD:
			myhdr.pkt_length=1 // fe
				+ (plugins_lens[1]+1)
				+ 1; // 00
			break;
		case AUTH_MYSQL_CACHING_SHA2_PASSWORD:
			myhdr.pkt_length=1 // fe
				+ (plugins_lens[2]+1)
				+ 20 // scramble
				+ 1; // 00
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			// LCOV_EXCL_STOP
			break;
	}

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)malloc(size);
	memset(_ptr,0,size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l;
  l=sizeof(mysql_hdr);
  _ptr[l]=0xfe; l++; //0xfe

	switch((*myds)->switching_auth_type) {
		case AUTH_MYSQL_NATIVE_PASSWORD:
			memcpy(_ptr+l,plugins_names[0],plugins_lens[0]);
			l+=plugins_lens[0];
			_ptr[l]=0x00; l++;
			memcpy(_ptr+l, (*myds)->myconn->scramble_buff+0, 20); l+=20;
			break;
		case AUTH_MYSQL_CLEAR_PASSWORD:
			memcpy(_ptr+l,plugins_names[1],plugins_lens[1]);
			l+=plugins_lens[1];
			_ptr[l]=0x00; l++;
			break;
		case AUTH_MYSQL_CACHING_SHA2_PASSWORD:
			memcpy(_ptr+l,plugins_names[2],plugins_lens[2]);
			l+=plugins_lens[2];
			_ptr[l]=0x00; l++;
			memcpy(_ptr+l, (*myds)->myconn->scramble_buff+0, 20); l+=20;
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			// LCOV_EXCL_STOP
			break;
	}
  _ptr[l]=0x00; //l+=1; //0x00
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		(*myds)->DSS=STATE_SERVER_HANDSHAKE;
		(*myds)->sess->status=CONNECTING_CLIENT;
	}
	(*myds)->switching_auth_sent = (*myds)->switching_auth_type;

	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

bool MySQL_Protocol::generate_pkt_initial_handshake(bool send, void **ptr, unsigned int *len, uint32_t *_thread_id, bool deprecate_eof_active) {
	int use_plugin_id = mysql_thread___default_authentication_plugin_int;
  proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating handshake pkt\n");
	assert(use_plugin_id == 0 || use_plugin_id == 2 ); // mysql_native_password or caching_sha2_password
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
    + sizeof(mysql_thread___server_capabilities)/2
    + sizeof(uint8_t) // charset in handshake is 1 byte
    + sizeof(server_status)
    + 3 // unknown stuff
    + 10 // filler
    + 12 // scramble2
    + 1  // 0x00
//    + (strlen("mysql_native_password")+1);
    + (strlen(plugins[use_plugin_id])+1);
	sent_auth_plugin_id = (enum proxysql_auth_plugins)use_plugin_id;

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

//  for (i=0;i<8;i++) {
//    if ((*myds)->myconn->scramble_buff[i]==0) {
//      (*myds)->myconn->scramble_buff[i]='a';
//    }
//  }

	memcpy(_ptr+l, (*myds)->myconn->scramble_buff+0, 8); l+=8;
	_ptr[l]=0x00; l+=1; //0x00
	if (mysql_thread___have_compress) {
		mysql_thread___server_capabilities |= CLIENT_COMPRESS;
		mysql_thread___server_capabilities |= CLIENT_ZSTD_COMPRESSION_ALGORITHM;
	} else {
		mysql_thread___server_capabilities &= ~CLIENT_COMPRESS;
		mysql_thread___server_capabilities &= ~CLIENT_ZSTD_COMPRESSION_ALGORITHM;
	}
	if (mysql_thread___have_ssl==true || mysql_thread___default_authentication_plugin_int==2) {
		// we enable SSL for client connections for either of these 2 conditions:
		// - have_ssl is enabled
		// - default_authentication_plugin=caching_sha2_password
		mysql_thread___server_capabilities |= CLIENT_SSL;
	} else {
		mysql_thread___server_capabilities &= ~CLIENT_SSL;
	}
	mysql_thread___server_capabilities |= CLIENT_LONG_FLAG;
	mysql_thread___server_capabilities |= CLIENT_MYSQL | CLIENT_PLUGIN_AUTH | CLIENT_RESERVED;

	// Advertise CLIENT_DEPRECATE_EOF in the server greeting when either:
	// 1) mysql_thread___enable_client_deprecate_eof is explicitly enabled, OR
	// 2) session_track_variables is ENFORCED (backends must support CLIENT_DEPRECATE_EOF
	//    to properly handle session tracking capabilities in this mode).
	// This is coordinated with the corresponding logic in PPHR_2() to ensure consistent
	// CLIENT_DEPRECATE_EOF handling between server greeting and client capabilities negotiation.
	if (deprecate_eof_active
		&& (mysql_thread___enable_client_deprecate_eof
			|| mysql_thread___session_track_variables == session_track_variables::ENFORCED)) {
		mysql_thread___server_capabilities |= CLIENT_DEPRECATE_EOF;
	} else {
		mysql_thread___server_capabilities &= ~CLIENT_DEPRECATE_EOF;
	}

	uint32_t server_capabilities = mysql_thread___server_capabilities;
	(*myds)->myconn->options.server_capabilities=server_capabilities;
  memcpy(_ptr+l,&server_capabilities, sizeof(server_capabilities)/2); l+=sizeof(server_capabilities)/2;
  const MARIADB_CHARSET_INFO *ci = NULL;
  ci = proxysql_find_charset_collate(mysql_thread___default_variables[SQL_COLLATION_CONNECTION]);
  if (!ci) {
		// LCOV_EXCL_START
	  proxy_error("Cannot find character set for name [%s]. Configuration error. Check [%s] global variable.\n",
			  mysql_thread___default_variables[SQL_CHARACTER_SET], mysql_tracked_variables[SQL_CHARACTER_SET].internal_variable_name);
	  assert(0);
		// LCOV_EXCL_STOP
  }
  uint8_t uint8_charset = ci->nr & 255;
  memcpy(_ptr+l,&uint8_charset, sizeof(uint8_charset)); l+=sizeof(uint8_charset);
  memcpy(_ptr+l,&server_status, sizeof(server_status)); l+=sizeof(server_status);
	// Upper-word ('capability_flags_2') capabilities advertised in the greeting.
	// These match what real MySQL servers advertise (see issue #4023) and were
	// accidentally dropped during the zstd refactor in 8c6a6444d; this local
	// restores the baseline. 'extended_capabilities' is intentionally a local:
	// it must NOT leak into '(*myds)->myconn->options.server_capabilities' nor
	// into the low-word memcpy above, which record per-connection state rather
	// than the full greeting. Per-session/per-toggle upper-word bits (e.g.
	// CLIENT_DEPRECATE_EOF when 'deprecate_eof_active', CLIENT_ZSTD_COMPRESSION
	// when 'have_compress') are folded in from 'server_capabilities' so the
	// greeting stays in sync with their runtime state.
	uint32_t extended_capabilities =
		CLIENT_MULTI_RESULTS | CLIENT_MULTI_STATEMENTS | CLIENT_PS_MULTI_RESULTS |
		CLIENT_PLUGIN_AUTH | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA |
		CLIENT_SESSION_TRACKING | CLIENT_REMEMBER_OPTIONS;
	extended_capabilities |= server_capabilities & 0xFFFF0000u;
	uint16_t upper_word = static_cast<uint16_t>(extended_capabilities >> 16);
	memcpy(_ptr+l, static_cast<void*>(&upper_word), sizeof(upper_word)); l += sizeof(upper_word);
	// Copy the 'auth_plugin_data_len'. Hardcoded due to 'CLIENT_PLUGIN_AUTH' always enabled and reported
	// as 'mysql_native_password'.
	uint8_t auth_plugin_data_len = 21;
	memcpy(_ptr+l, &auth_plugin_data_len, sizeof(auth_plugin_data_len)); l += sizeof(auth_plugin_data_len);

  for (i=0;i<10; i++) { _ptr[l]=0x00; l++; } //filler
  //create_random_string(mypkt->data+l,12,(struct my_rnd_struct *)&rand_st); l+=12;
//#ifdef MARIADB_BASE_VERSION
//  proxy_create_random_string(myds->myconn->myconn.scramble_buff+8,12,(struct my_rnd_struct *)&rand_st);
//#else
  proxy_create_random_string((*myds)->myconn->scramble_buff+8,12,(struct rand_struct *)&rand_st);
//#endif
  //create_random_string(scramble_buf+8,12,&rand_st);

//  for (i=8;i<20;i++) {
//    if ((*myds)->myconn->scramble_buff[i]==0) {
//      (*myds)->myconn->scramble_buff[i]='a';
//    }
//  }

  memcpy(_ptr+l, (*myds)->myconn->scramble_buff+8, 12); l+=12;
  l+=1; //0x00
  //memcpy(_ptr+l,"mysql_native_password",strlen("mysql_native_password"));
  memcpy(_ptr+l,plugins[use_plugin_id],strlen(plugins[use_plugin_id]));

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

#ifdef PROXYSQLCLICKHOUSE
void ch_account_to_my(account_details_t& account, ch_account_details_t& ch_account) {
    account.username = ch_account.username;
    account.password = ch_account.password;
    account.sha1_pass = ch_account.sha1_pass;
    account.use_ssl = ch_account.use_ssl;
    account.default_hostgroup = ch_account.default_hostgroup;
    account.default_schema = ch_account.default_schema;
    account.schema_locked = ch_account.schema_locked;
    account.transaction_persistent = ch_account.transaction_persistent;
    account.fast_forward = ch_account.fast_forward;
    account.max_connections = ch_account.max_connections;
    account.num_connections_used = ch_account.num_connections_used;

    // Fields that are not present in `ch_account_details_t`
    account.num_connections_used_addl_pass = 0;   // Assuming no additional password used
    account.clear_text_password[0] = nullptr;     // No clear text passwords by default
    account.clear_text_password[1] = nullptr;
    account.frontend_ = ch_account.frontend_;   // Copy frontend flag
    account.backend_ = ch_account.backend_;     // Copy backend flag
    account.active_ = ch_account.active_;       // Copy active flag
    account.attributes = nullptr;                 // No attributes by default
    account.comment = nullptr;                    // No comment by default
}
#endif /* PROXYSQLCLICKHOUSE */

/**
 * @brief Can 'need' bytes be read from the client's authentication response?
 * @details The response buffer is heap-allocated from a CLIENT-CONTROLLED length
 *   as 'malloc(pass_len + 1)', with a terminating NUL written at [pass_len], so
 *   exactly 'pass_len + 1' bytes are readable. Nothing in the packet parsing
 *   enforces a minimum: a client may send a 1-byte response and get a 2-byte
 *   allocation. The fixed-width comparisons below read SHA_DIGEST_LENGTH (20) or
 *   SHA256_DIGEST_LENGTH (32) bytes, so without this check they read past the end
 *   of the allocation, before authentication has succeeded.
 *
 *   Do NOT tighten this to 'pass_len == need'. 'pass_len' is not the amount of
 *   valid data in the buffer: the packet parser strips a trailing NUL from the
 *   client's response ("remove the extra 0 if present"), so a legitimate 20-byte
 *   native response whose last byte is 0x00 -- about 1 in 256 -- arrives with
 *   pass_len == 19 while all 20 bytes are present. An equality gate therefore
 *   rejects real logins intermittently; measured at 20 spurious denials across
 *   ~6520 connections in test_auth_methods-t. Comparing against the allocation
 *   size ('pass_len + 1') admits that case and still bounds the read.
 */
static inline bool auth_response_has(int64_t pass_len, size_t need) {
	return pass_len >= 0 && static_cast<uint64_t>(pass_len) + 1 >= need;
}

bool MySQL_Protocol::process_pkt_auth_swich_response(unsigned char *pkt, unsigned int len) {
	bool ret=false;
	char *password=NULL;

#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,pkt,len); }
#endif

	if (len!=sizeof(mysql_hdr)+20) {
		return ret;
	}
	mysql_hdr hdr;
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	unsigned char pass[128];
	memset(pass,0,128);
	pkt+=sizeof(mysql_hdr);
	memcpy(pass, pkt, 20);

	MyProt_tmp_auth_vars vars1;
	account_details_t account_details {};
	dup_account_details_t dup_details {};
	dup_details.sha1_pass = true;

	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
#ifdef PROXYSQLCLICKHOUSE
		ch_dup_account_details_t ch_dup_details {};
		ch_dup_details.sha1_pass = true;

		ch_account_details_t ch_account {
			GloClickHouseAuth->lookup((char*)userinfo->username, USERNAME_FRONTEND, ch_dup_details)
		};

		ch_account_to_my(account_details, ch_account);
		password = ch_account.password;
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		account_details = GloMyAuth->lookup((char*)userinfo->username, cred_scope_for_session(session_type), dup_details);
		password = account_details.password;
	}
	// FIXME: add support for default schema and fast forward , issues #255 and #256
	// FIXME: not sure if we should also handle user_attributes *here* . For now we pass NULL (no change)
	if (password==NULL) {
		ret=false;
	} else {
			char reply[SHA_DIGEST_LENGTH+1];
			reply[SHA_DIGEST_LENGTH]='\0';

			if (password[0]!='*') { // clear text password
				proxy_scramble(reply, (*myds)->myconn->scramble_buff, password);
				// No bounds check needed here: 'len' is validated to be exactly
				// sizeof(mysql_hdr)+20 above, and 'pass' is a zeroed 128-byte stack
				// buffer holding those 20 bytes. Unlike the PPHR_* paths, nothing
				// here is sized from a client-declared length.
				if (memcmp(reply, pass, SHA_DIGEST_LENGTH)==0) {
					ret=true;
				}
			} else {
				ret=proxy_scramble_sha1((char *)pass,(*myds)->myconn->scramble_buff,password+1, reply);
				if (ret) {
					if (account_details.sha1_pass==NULL) {
						// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
						GloMyAuth->set_SHA1((char *)userinfo->username, cred_scope_for_session(session_type),reply);
					}
					if (userinfo->sha1_pass) free(userinfo->sha1_pass);
					userinfo->sha1_pass=sha1_pass_hex(reply);
				}
			}
	}
	free_account_details(account_details);

	return ret;
}

bool MySQL_Protocol::verify_user_pass(
	enum proxysql_session_type session_type,
	const char* password,
	const char* user,
	const char* pass,
	int pass_len,
	const char* sha1_pass,
	const char* auth_plugin
) {
	bool ret = false;

	char reply[SHA_DIGEST_LENGTH+1];
	reply[SHA_DIGEST_LENGTH]='\0';
	auth_plugin_id = AUTH_UNKNOWN_PLUGIN; // default

	if (strncmp((char *)auth_plugin,plugins[0],strlen(plugins[0]))==0) { // mysql_native_password
		auth_plugin_id = AUTH_MYSQL_NATIVE_PASSWORD;
	} else if (strncmp((char *)auth_plugin,plugins[1],strlen(plugins[1]))==0) { // mysql_clear_password
		auth_plugin_id = AUTH_MYSQL_CLEAR_PASSWORD;
	} else if (strncmp((char *)auth_plugin,plugins[2],strlen(plugins[2]))==0) { // caching_sha2_password
		//auth_plugin_id = 2; // FIXME: this is temporary, because yet not supported
		auth_plugin_id = AUTH_MYSQL_CACHING_SHA2_PASSWORD; // FIXME: this is temporary, because yet not supported . It must become 3
	}

	if (password[0]!='*') { // clear text password
		if (auth_plugin_id == 0) { // mysql_native_password
			proxy_scramble(reply, (*myds)->myconn->scramble_buff, password);
			if (auth_response_has(pass_len, SHA_DIGEST_LENGTH) &&
				memcmp(reply, pass, SHA_DIGEST_LENGTH)==0) {
				ret=true;
			}
		} else if (auth_plugin_id == 1) { // mysql_clear_password
			if (strncmp(password,(char *)pass,strlen(password))==0) {
				ret=true;
			}
		} else if (auth_plugin_id == 2) { // caching_sha2_password
			// ## FIXME: Current limitation
			// For now, if a 'COM_CHANGE_USER' is received with a hashed 'password' for
			// 'caching_sha2_password', we fail to authenticate. This is part of the broader limitation of
			// 'Auth Switch' support for 'caching_sha2_password' (See
			// https://proxysql.com/documentation/authentication-methods/#limitations).
			//
			// ## Future Fix
			// The right approach is to perform an 'Auth Switch Request' or to accept the hash if the clear
			// text password is already known and the hash can be verified. This processing is now performed
			// in 'process_pkt_COM_CHANGE_USER', state at which it should be determine if we can accept the
			// hash, or if we should prepare the state machine for a 'Auth Switch Request'. Progress for this
			// is tracked in https://github.com/sysown/proxysql/issues/4618.
			ret = false;
		} else {
			ret = false;
		}
	} else {
		if (auth_plugin_id == 0) {
			// proxy_scramble_sha1() feeds 'pass' to proxy_my_crypt() for
			// SCRAMBLE_LENGTH (20) bytes, so it needs the same bound as the
			// cleartext branch above. This is the COMMON path -- stored passwords are
			// normally hashed ('*'-prefixed).
			if ((session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE) &&
				auth_response_has(pass_len, SCRAMBLE_LENGTH)) {
				ret=proxy_scramble_sha1((char *)pass,(*myds)->myconn->scramble_buff,password+1, reply);
				if (ret) {
					if (sha1_pass==NULL) {
						GloMyAuth->set_SHA1(user, cred_scope_for_session(session_type),reply);
					}
					if (userinfo->sha1_pass) free(userinfo->sha1_pass);
					userinfo->sha1_pass=sha1_pass_hex(reply);
				}
			}
		} else {
			if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE || session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) {
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , session_type=%d\n", (*myds), (*myds)->sess, user, session_type);
				unsigned char md1_buf[SHA_DIGEST_LENGTH];
				unsigned char md2_buf[SHA_DIGEST_LENGTH];
				SHA1((const unsigned char *)pass,pass_len,md1_buf);
				SHA1(md1_buf,SHA_DIGEST_LENGTH,md2_buf);
				char *double_hashed_password = sha1_pass_hex((char *)md2_buf); // note that sha1_pass_hex() returns a new buffer

				if (strcasecmp(double_hashed_password,password)==0) {
					ret = true;
					if (sha1_pass==NULL) {
						GloMyAuth->set_SHA1(user, cred_scope_for_session(session_type),md1_buf);
					}
					if (userinfo->sha1_pass)
						free(userinfo->sha1_pass);
					userinfo->sha1_pass=sha1_pass_hex((char *)md1_buf);
				} else {
					ret = false;
				}
				free(double_hashed_password);
			}
		}
	}

	return ret;
}

bool MySQL_Protocol::process_pkt_COM_CHANGE_USER(unsigned char *pkt, unsigned int len) {
	bool ret=false;
	int cur=sizeof(mysql_hdr);
	unsigned char *user=NULL;
	char *db=NULL;
	unsigned char *pass=NULL;
	const unsigned char *packet_end = pkt + len;
	mysql_hdr hdr;

	if (len <= sizeof(mysql_hdr)) {
		return false;
	}

	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	cur++;
	// Validate each field before consuming it to avoid malformed-packet reads and writes.
	const unsigned char *user_ptr = pkt + cur;
	const size_t user_remaining = packet_end - user_ptr;
	const size_t user_len = strnlen(reinterpret_cast<const char*>(user_ptr), user_remaining);
	if (user_len == user_remaining) {
		return false;
	}
	user=const_cast<unsigned char*>(user_ptr);
	cur+=user_len + 1;
	if (pkt + cur >= packet_end) {
		return false;
	}
	unsigned char pass_len=pkt[cur];
	cur++;
	const unsigned char *pass_ptr = pkt + cur;
	if (static_cast<size_t>(packet_end - pass_ptr) < pass_len) {
		return false;
	}
	pass=(unsigned char *)malloc(pass_len+1);
	if (pass==NULL) {
		return false;
	}
	memcpy(pass, pass_ptr, pass_len);
	pass[pass_len]=0;
	cur+=pass_len;
	if (pkt + cur >= packet_end) {
		cleanse_and_free_auth_response(pass, pass_len + 1);
		return false;
	}
	const char *db_ptr = reinterpret_cast<const char*>(pkt + cur);
	const size_t db_remaining = packet_end - (pkt + cur);
	const size_t db_len = strnlen(db_ptr, db_remaining);
	if (db_len == db_remaining) {
		cleanse_and_free_auth_response(pass, pass_len + 1);
		return false;
	}
	db=const_cast<char*>(db_ptr);
	// Move to field after 'database'
	cur += db_len + 1;
	// Skip field 'character-set' (size 2)
	if (static_cast<size_t>(packet_end - (pkt + cur)) < sizeof(uint16_t)) {
		cleanse_and_free_auth_response(pass, pass_len + 1);
		return false;
	}
	cur += 2;
	// Check and get 'Client Auth Plugin' if capability is supported
	char* client_auth_plugin = nullptr;
	int capabilities = (*myds)->sess->client_myds->myconn->options.client_flag;
	if (capabilities & CLIENT_PLUGIN_AUTH && pkt + cur < packet_end) {
		const char *auth_plugin_ptr = reinterpret_cast<const char*>(pkt + cur);
		const size_t auth_plugin_len = strnlen(auth_plugin_ptr, packet_end - (pkt + cur));
		if (auth_plugin_len == static_cast<size_t>(packet_end - (pkt + cur))) {
			cleanse_and_free_auth_response(pass, pass_len + 1);
			return false;
		}
		client_auth_plugin = const_cast<char*>(auth_plugin_ptr);
	}
	// Default to 'mysql_native_password' in case 'auth_plugin' is not found.
	if (client_auth_plugin == nullptr) {
		client_auth_plugin = const_cast<char*>("mysql_native_password");
	}
	if (pass_len) {
		if (pass[pass_len-1] == 0) {
			pass_len--; // remove the extra 0 if present
		}
	}

#ifdef PROXYSQL31
	if ((*myds)->frontend_authenticated_via_spiffe) {
		proxy_error(
			"Client %s:%d cannot run COM_CHANGE_USER after SPIFFE authentication\n",
			(*myds)->addr.addr, (*myds)->addr.port);
		cleanse_and_free_auth_response(pass, pass_len + 1);
		return false;
	}
#endif

	account_details_t account_details {};
	dup_account_details_t dup_details { false, true, true };
	enum proxysql_session_type session_type = (*myds)->sess->session_type;

	if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
#ifdef PROXYSQLCLICKHOUSE
		ch_dup_account_details_t ch_dup_details { false, true };
		ch_dup_details.sha1_pass = true;

		ch_account_details_t ch_account_details {
			GloClickHouseAuth->lookup((char*)user, USERNAME_FRONTEND, ch_dup_details)
		};

		ch_account_to_my(account_details, ch_account_details);
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		account_details = GloMyAuth->lookup((char *)user, cred_scope_for_session(session_type), dup_details);
	}

	/**
	 * @brief Reject COM_CHANGE_USER for pass-through-eligible users (spec §5.4).
	 *
	 * Phase 1 explicitly does not support pass-through for COM_CHANGE_USER:
	 * the protocol-level state machine in PPHR_passthrough_init assumes a
	 * fresh client handshake and would corrupt a session that already has
	 * a bound backend connection. Rather than try to drive the probe
	 * mid-session, the spec says to reject and let the client fall back
	 * to opening a new connection (which goes through the normal
	 * PPHR_verify_password / pass-through path).
	 *
	 * This check MUST run BEFORE the unconditional session-state mutations
	 * below (sess->default_hostgroup, sess->transaction_persistent,
	 * sess->user_attributes get overwritten from @c account_details for
	 * EVERY CHANGE_USER, success or not). If we deferred this check to
	 * after those mutations, a rejected CHANGE_USER would leave the
	 * already-authenticated session with the pass-through target row's
	 * routing/attrs grafted on top of the previous user's state -- the
	 * rejected attempt would have observable side-effects. Doing the
	 * check here, before the lookup result touches the session, gives a
	 * clean failure with the session state untouched.
	 *
	 * Two cases need explicit rejection here when mysql-passthrough_auth_enabled
	 * is on:
	 *
	 *   - Empty-password row (password != NULL, strlen == 0): without this
	 *     guard the existing
	 *         if (pass_len==0 && strlen(password)==0) { ret = true; }
	 *     branch below grants passwordless CHANGE_USER access to an
	 *     admin-provisioned pass-through row -- silently violating the
	 *     §3.2 behavior change.
	 *
	 *   - Unknown user (password == NULL): already falls through to
	 *     ret=false a few lines down (the legacy behavior), so it does NOT
	 *     need a new guard. We could mirror the explicit form for clarity
	 *     but it would be a no-op.
	 *
	 * The rejection here is silent (ret=false, generic auth failure) and
	 * leaks no information about whether the user exists or whether
	 * pass-through is enabled.
	 */
	/*
	 * Compute the row's stored password ONCE before the rejection gate.
	 *
	 * get_password() bumps MyHGM->status.client_connections_sha2cached
	 * when @c clear_text_password[PRIMARY] is the value being returned
	 * (see the in-source comment "Only count one attempt using the cache
	 * per connection"). An earlier version of this commit called
	 * get_password() once for the rejection check and a second time for
	 * the legacy block below, double-bumping that counter on every
	 * non-rejected CHANGE_USER. Compute once and share.
	 */
	char* password = get_password(account_details, PASSWORD_TYPE::PRIMARY);

#ifdef PROXYSQL31
	const auto target_policy = evaluate_frontend_certificate_policy(
		*myds,
		account_details.attributes,
		user,
		frontend_auth_context::COM_CHANGE_USER,
		__LINE__, __func__);
	if (!target_policy.allowed || target_policy.has_spiffe_id) {
		cleanse_and_free_auth_response(pass, pass_len + 1);
		cleanse_and_free_password(password);
		free_account_details(account_details);
		return false;
	}
#endif

	if (mysql_thread___passthrough_auth_enabled
		&& mysql_thread___passthrough_auth_empty_password
		&& password != NULL
		&& password[0] == '\0'
	#ifdef PROXYSQL31
		&& !target_policy.has_spiffe_id
	#endif
		&& (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE)) {
		// Rationale for the pre-mutation ordering and the two eligible
		// cases is documented on the doxygen block above this gate.
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
			"COM_CHANGE_USER to pass-through-eligible user '%s' rejected "
			"(Phase 1 does not support pass-through via CHANGE_USER, spec §5.4)\n",
			user ? (const char*)user : "(null)");
		ret = false;
		cleanse_and_free_auth_response(pass, pass_len + 1);
		if (userinfo->username) free(userinfo->username);
		userinfo->clear_password();
		userinfo->username = strdup((const char *)user);
		userinfo->password = strdup((const char *)"");
		cleanse_and_free_password(password);
		free_account_details(account_details);
		userinfo->set(NULL, NULL, NULL, NULL);
		return ret;
	}

	// FIXME: add support for default schema and fast forward, see issue #255 and #256
	(*myds)->sess->default_hostgroup=account_details.default_hostgroup;
	(*myds)->sess->transaction_persistent=account_details.transaction_persistent;
	// Could be reached several times before auth completion; allocating attributes should be reset
	if ((*myds)->sess->user_attributes) {
		free((*myds)->sess->user_attributes);
		(*myds)->sess->user_attributes = nullptr;
	}
	(*myds)->sess->user_attributes=account_details.attributes;
	account_details.attributes = nullptr;

	if (password==NULL) {
		ret=false;
	} else {
		if (pass_len==0 && strlen(password)==0) {
			ret=true;
		} else {
			// If pass not sent within 'COM_CHANGE_USER' packet, an 'Auth Switch Request'
			// is required. We default to 'mysql_native_password'. See #3504 for more context.
			if (pass_len == 0) {
				// mysql_native_password
				(*myds)->switching_auth_type = AUTH_MYSQL_NATIVE_PASSWORD;
				// started 'Auth Switch Request' for 'CHANGE_USER' in MySQL_Session.
				(*myds)->sess->change_user_auth_switch = true;

				generate_pkt_auth_switch_request(true, NULL, NULL);
				(*myds)->myconn->userinfo->set((char *)user, NULL, db, NULL);
				ret = false;
			} else {
				// If pass is sent with 'COM_CHANGE_USER', we proceed trying to use
				// it to authenticate the user. See #3504 for more context.
				ret = verify_user_pass(
					session_type, password, reinterpret_cast<char*>(user), reinterpret_cast<char*>(pass),
					pass_len, static_cast<char*>(account_details.sha1_pass), client_auth_plugin
				);
			}
		}
	}
	cleanse_and_free_auth_response(pass, pass_len + 1);
	if (userinfo->username) free(userinfo->username);
	userinfo->clear_password();
	if (ret==true) {
		(*myds)->DSS=STATE_CLIENT_HANDSHAKE;

		userinfo->username=strdup((const char *)user);
		userinfo->password=strdup((const char *)password);
		if (db) userinfo->set_schemaname(db,strlen(db));
	} else {
		// we always duplicate username and password, or crashes happen
		userinfo->username=strdup((const char *)user);
		userinfo->password=strdup((const char *)"");
	}
	cleanse_and_free_password(password);
	free_account_details(account_details);
	userinfo->set(NULL,NULL,NULL,NULL); // just to call compute_hash()
	if (ret) {
		// we need to process charset if present in CHANGE_USER
		uint16_t charset=0;
		int bytes_processed = (db-(char *)pkt);
		bytes_processed += strlen(db) + 1;
		int bytes_left = len - bytes_processed;
		if (bytes_left > 2) {
			char *p = db;
			p += strlen(db);
			p++; // null byte
			memcpy(&charset, p, sizeof(charset));
		}
		// see bug #810
		if (charset==0) {
			const MARIADB_CHARSET_INFO *ci = NULL;
			ci = proxysql_find_charset_name(mysql_thread___default_variables[SQL_CHARACTER_SET]);
			if (!ci) {
				// LCOV_EXCL_START
				proxy_error("Cannot find charset [%s]\n", mysql_thread___default_variables[SQL_CHARACTER_SET]);
				assert(0);
				// LCOV_EXCL_STOP
			}
			charset=ci->nr;
		}
		// reject connections from unknown charsets
		const MARIADB_CHARSET_INFO * c = proxysql_find_charset_nr(charset);
		if (!c) {
			proxy_error("Client %s:%d is trying to use unknown charset %u. Disconnecting\n", (*myds)->addr.addr, (*myds)->addr.port, charset);
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . Client %s:%d is trying to use unknown charset %u. Disconnecting\n", (*myds), (*myds)->sess, user, (*myds)->addr.addr, (*myds)->addr.port, charset);
			ret = false;
			return ret;
		}
		// set the default charset for this session
		(*myds)->sess->default_charset = charset;
		if ((*myds)->sess->user_attributes) {
#ifndef PROXYSQL31
			if (user_attributes_has_spiffe(__LINE__, __func__, user)) {
				// if SPIFFE was used, CHANGE_USER is not allowed.
				// This because when SPIFFE is used, the password it is not relevant,
				// as it could be a simple "none" , or "123456", or "password"
				// The whole idea of using SPIFFE is that this is responsible for
				// authentication, and not the password.
				// Therefore CHANGE_USER is not allowed
				proxy_error("Client %s:%d is trying to run CHANGE_USER , but this is disabled because it previously used SPIFFE ID. Disconnecting\n", (*myds)->addr.addr, (*myds)->addr.port);
				ret = false;
				return ret;
			}
#endif

			char* user_attributes = (*myds)->sess->user_attributes;
			if (strlen(user_attributes)) {
				nlohmann::json j_user_attributes = nlohmann::json::parse(user_attributes);
				auto default_transaction_isolation = j_user_attributes.find("default-transaction_isolation");

				if (default_transaction_isolation != j_user_attributes.end()) {
					std::string def_trx_isolation_val =
						j_user_attributes["default-transaction_isolation"].get<std::string>();
					mysql_variables.client_set_value((*myds)->sess, SQL_ISOLATION_LEVEL, def_trx_isolation_val.c_str());
				}
			}
		}
		assert(sess);
		assert(sess->client_myds);
		MySQL_Connection *myconn=sess->client_myds->myconn;
		assert(myconn);

		myconn->set_charset(charset, CONNECT_START);

		std::stringstream ss;
		ss << charset;

		/* We are processing handshake from client. Client sends us a character set it will use in communication.
		 * we store this character set in the client's variables to use later in multiplexing with different backends
		 */
		mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_RESULTS, ss.str().c_str());
		mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_CLIENT, ss.str().c_str());
		mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_CONNECTION, ss.str().c_str());
		mysql_variables.client_set_value(sess, SQL_COLLATION_CONNECTION, ss.str().c_str());
	}
#ifdef PROXYSQL31
	if (ret) {
		(*myds)->frontend_authenticated_via_spiffe = false;
	}
#endif
	return ret;
}

// this function was inline in process_pkt_handshake_response() , split for readibility
int MySQL_Protocol::PPHR_1(unsigned char *pkt, unsigned int len, bool& ret, MyProt_tmp_auth_vars& vars1) { // process_pkt_handshake_response inner 1
#ifdef PROXYSQL31
	if ((*myds)->switching_auth_stage == 6) {
		(*myds)->auth_in_progress = 0;
		ret = false;
		vars1.user = reinterpret_cast<unsigned char *>((*myds)->myconn->userinfo->username);

		const auto key_snapshot = caching_sha2_rsa_snapshot_;
		caching_sha2_rsa_snapshot_.reset();
		const size_t ciphertext_length =
			len >= sizeof(mysql_hdr) ? len - sizeof(mysql_hdr) : 0;
		if (key_snapshot == nullptr ||
			ciphertext_length != key_snapshot->ciphertext_size() ||
			GloMTH == nullptr || GloMTH->caching_sha2_rsa() == nullptr) {
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
				"Session=%p , DS=%p , user='%s' . Invalid caching_sha2_password RSA response\n",
				(*myds)->sess, (*myds), vars1.user);
			return 1;
		}

		std::string plaintext_password;
		ScopedStringCleanser plaintext_password_cleanser(plaintext_password);
		if (!GloMTH->caching_sha2_rsa()->decrypt_password(
				key_snapshot,
				pkt,
				ciphertext_length,
				reinterpret_cast<const unsigned char *>((*myds)->myconn->scramble_buff),
				SCRAMBLE_LENGTH,
				plaintext_password)) {
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
				"Session=%p , DS=%p , user='%s' . Invalid caching_sha2_password RSA response\n",
				(*myds)->sess, (*myds), vars1.user);
			return 1;
		}

		const size_t plaintext_password_length = plaintext_password.size();
		unsigned char* plaintext_password_copy = static_cast<unsigned char *>(
			malloc(plaintext_password_length + 1)
		);
		if (plaintext_password_copy == nullptr) {
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
				"Session=%p , DS=%p , user='%s' . Cannot allocate caching_sha2_password RSA response\n",
				(*myds)->sess, (*myds), vars1.user);
			return 1;
		}
		if (plaintext_password_length != 0) {
			memcpy(plaintext_password_copy, plaintext_password.data(), plaintext_password_length);
		}
		plaintext_password_copy[plaintext_password_length] = '\0';
		vars1.pass_len = plaintext_password_length;
		vars1.pass = plaintext_password_copy;
		vars1.pass_is_sensitive = true;
		vars1.db = (*myds)->myconn->userinfo->schemaname;
		vars1.charset = (*myds)->tmp_charset;
		vars1.capabilities = (*myds)->myconn->options.client_flag;
		auth_plugin_id = (*myds)->switching_auth_type;
		(*myds)->switching_auth_stage = 5;
		frontend_auth_error_ = MySQLFrontendAuthError::NONE;
		return 2;
	}
#endif
	if ((*myds)->switching_auth_stage == 1) {
		// this was set in PPHR_4auth0() or PPHR_4auth1()
		(*myds)->switching_auth_stage=2;
	}
	if ((*myds)->switching_auth_stage == 4) {
		// this was set in PPHR_sha2full()
		(*myds)->switching_auth_stage=5;
	}
	(*myds)->auth_in_progress = 0;
	if (len==5) {
		ret = false;
		vars1.user = (unsigned char *)(*myds)->myconn->userinfo->username;
		if ((*myds)->switching_auth_stage == 5 && *pkt == 2) {
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
				"Session=%p , DS=%p , user='%s' . Client requested the caching_sha2_password RSA public key\n",
				(*myds)->sess, (*myds), vars1.user);
#ifdef PROXYSQL31
			caching_sha2_rsa_snapshot_ =
				GloMTH != nullptr && GloMTH->caching_sha2_rsa() != nullptr ?
				GloMTH->caching_sha2_rsa()->acquire() : nullptr;
			if (caching_sha2_rsa_snapshot_ != nullptr) {
				const std::string& public_key = caching_sha2_rsa_snapshot_->public_key_pem();
				if (!generate_auth_more_data(
						reinterpret_cast<const unsigned char *>(public_key.data()), public_key.size())) {
					caching_sha2_rsa_snapshot_.reset();
					frontend_auth_error_ = MySQLFrontendAuthError::NONE;
					proxy_error(
						"User '%s'@'%s' requested the caching_sha2_password RSA public key, but ProxySQL could not allocate the response packet.\n",
						vars1.user, (*myds)->addr.addr
					);
					return 1;
				}
				(*myds)->switching_auth_stage = 6;
				(*myds)->auth_in_progress = 1;
				frontend_auth_error_ = MySQLFrontendAuthError::NONE;
				return 1;
			}
			frontend_auth_error_ = MySQLFrontendAuthError::CACHING_SHA2_RSA_UNAVAILABLE;
			proxy_error(
				"User '%s'@'%s' requested the caching_sha2_password RSA public key, but no valid RSA key pair is available.\n",
				vars1.user, (*myds)->addr.addr
			);
#else
			proxy_error(
				"User '%s'@'%s' requested the caching_sha2_password RSA public key, which ProxySQL does not"
				" serve. Connect using TLS instead.\n",
				vars1.user, (*myds)->addr.addr
			);
#endif
			(*myds)->auth_in_progress = 0;
			return 1;
		}
		const bool tls_caching_sha2_empty_password =
			(*myds)->switching_auth_stage == 5 &&
			(*myds)->switching_auth_type == AUTH_MYSQL_CACHING_SHA2_PASSWORD &&
			(*myds)->encrypted && *pkt == '\0';
		if (!tls_caching_sha2_empty_password) {
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . Client is disconnecting\n", (*myds), (*myds)->sess, vars1.user);
			proxy_error("User '%s'@'%s' is disconnecting during switch auth\n", vars1.user, (*myds)->addr.addr);
			(*myds)->auth_in_progress = 0;
			return 1;
		}
	}
	auth_plugin_id = (*myds)->switching_auth_type;
	const size_t payload_length = len >= sizeof(mysql_hdr) ? len - sizeof(mysql_hdr) : 0;
	if (auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD &&
		(*myds)->switching_auth_stage == 5 && !(*myds)->encrypted) {
		ret = false;
		vars1.user = (unsigned char *)(*myds)->myconn->userinfo->username;
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
			"Session=%p , DS=%p , user='%s' . Rejected cleartext caching_sha2_password response without TLS\n",
			(*myds)->sess, (*myds), vars1.user);
		return 1;
	}
	if (auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD) {
		vars1.pass_len = payload_length;
	} else {
		const unsigned char* terminator = static_cast<const unsigned char *>(
			std::memchr(pkt, '\0', payload_length)
		);
		if (terminator == nullptr || terminator != pkt + payload_length - 1) {
			ret = false;
			vars1.user = (unsigned char *)(*myds)->myconn->userinfo->username;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
				"Session=%p , DS=%p , user='%s' . Rejected malformed NUL-terminated authentication response\n",
				(*myds)->sess, (*myds), vars1.user);
			return 1;
		}
		vars1.pass_len = payload_length - 1;
	}
	vars1.pass = (unsigned char *)malloc(vars1.pass_len+1);
	memcpy(vars1.pass, pkt, vars1.pass_len);
	vars1.pass[vars1.pass_len] = 0;
#ifdef PROXYSQL31
	vars1.pass_is_sensitive = auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD &&
		(*myds)->switching_auth_stage == 5;
#endif
	vars1.user = (unsigned char *)(*myds)->myconn->userinfo->username;
	vars1.db = (*myds)->myconn->userinfo->schemaname;
	//(*myds)->switching_auth_stage=2;
	vars1.charset=(*myds)->tmp_charset;
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,2,"Session=%p , DS=%p . Encrypted: %d , switching_auth: %d, auth_plugin_id: %d\n", (*myds)->sess, (*myds), (*myds)->encrypted, (*myds)->switching_auth_stage, auth_plugin_id);
	vars1.capabilities = (*myds)->myconn->options.client_flag;
	return 2;
}

// this function was inline in process_pkt_handshake_response() , split for readibility
bool MySQL_Protocol::PPHR_2(unsigned char *pkt, unsigned int len, bool& ret, MyProt_tmp_auth_vars& vars1) { // process_pkt_handshake_response inner 2

	// HandshakeResponse41 requires a 32-byte fixed header before any variable-length fields.
	const unsigned int handshake_response_header_len = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t) + 23;
	if (len < sizeof(mysql_hdr) + handshake_response_header_len) return false;

	unsigned char* packet_end = vars1._ptr + len;

	vars1.capabilities = CPY4(pkt);
	// see bug #2916. If CLIENT_MULTI_STATEMENTS is set by the client
	// we enforce setting CLIENT_MULTI_RESULTS, this is the proper and expected
	// behavior (refer to 'https://dev.mysql.com/doc/c-api/8.0/en/c-api-multiple-queries.html').
	// Don't enforcing this would cause a mismatch between client and backend
	// connections flags.
	if (vars1.capabilities & CLIENT_MULTI_STATEMENTS) {
		vars1.capabilities |= CLIENT_MULTI_RESULTS;
	}
	// CLIENT_DEPRECATE_EOF is disabled in client capabilities unless either:
	// 1) mysql_thread___enable_client_deprecate_eof is explicitly set, OR
	// 2) session_track_variables is ENFORCED (which requires CLIENT_DEPRECATE_EOF support
	//    since backends must support both CLIENT_DEPRECATE_EOF and CLIENT_SESSION_TRACKING).
	// This flag is stored in 'client_flag' field from 'MySQL_Connection::options' and is
	// used in subsequent connection checks throughout the session lifecycle.
	// This step, combined with the corresponding logic in 'generate_pkt_initial_handshake',
	// ensures consistent CLIENT_DEPRECATE_EOF handling across client and backend connections.
	if (!mysql_thread___enable_client_deprecate_eof
		&& mysql_thread___session_track_variables != session_track_variables::ENFORCED) {
		vars1.capabilities &= ~CLIENT_DEPRECATE_EOF;
	}
	(*myds)->myconn->options.client_flag = vars1.capabilities;
	pkt += sizeof(uint32_t);
	vars1.max_pkt = CPY4(pkt);
	(*myds)->myconn->options.max_allowed_pkt = vars1.max_pkt;
	pkt += sizeof(uint32_t);
	vars1.charset = *(uint8_t *)pkt;
	if ( (*myds)->encrypted == false ) { // client wants to use SSL
		if (len == sizeof(mysql_hdr)+32) {
			(*myds)->encrypted = true;
			vars1.use_ssl = true;
			ret = false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . goto __exit_process_pkt_handshake_response\n", (*myds), (*myds)->sess, vars1.user);
			return false;
		}
	}
	// see bug #810
	if (vars1.charset==0) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_name(mysql_thread___default_variables[SQL_CHARACTER_SET]);
		if (!ci) {
			// LCOV_EXCL_START
			proxy_error("Cannot find charset [%s]\n", mysql_thread___default_variables[SQL_CHARACTER_SET]);
			assert(0);
			// LCOV_EXCL_STOP
		}
		vars1.charset=ci->nr;
	}
	(*myds)->tmp_charset = vars1.charset;
	pkt += 24;
//	if (len==sizeof(mysql_hdr)+32) {
//		(*myds)->encrypted=true;
//		use_ssl=true;
//	} else {
	unsigned char* user_end = (unsigned char*)memchr(pkt, 0, packet_end - pkt);
	if (user_end == NULL) {
		ret = false;
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p . malformed username in handshake response\n", (*myds), (*myds)->sess);
		return false;
	}
	vars1.user = pkt;
	pkt = user_end + 1;

	if (vars1.capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
		if (packet_end <= pkt) {
			ret = false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . missing auth response length in handshake response\n", (*myds), (*myds)->sess, vars1.user);
			return false;
		}
		uint64_t passlen64;
		int pass_len_enc=mysql_decode_length_ll(pkt,&passlen64);
		if (pass_len_enc <= 0 || static_cast<size_t>(packet_end - pkt) < static_cast<size_t>(pass_len_enc)) {
			ret = false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . malformed auth response length in handshake response\n", (*myds), (*myds)->sess, vars1.user);
			return false;
		}
		vars1.pass_len = passlen64;
		pkt	+= pass_len_enc;
		if (vars1.pass_len > (len - (pkt - vars1._ptr))) {
			ret = false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . goto __exit_process_pkt_handshake_response\n", (*myds), (*myds)->sess, vars1.user);
			return false;
		}
	} else {
		if (vars1.capabilities & CLIENT_SECURE_CONNECTION) {
			if (packet_end <= pkt) {
				ret = false;
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . missing auth response length in handshake response\n", (*myds), (*myds)->sess, vars1.user);
				return false;
			}
			vars1.pass_len = *pkt++;
		} else {
			unsigned char* pass_end = (unsigned char*)memchr(pkt, 0, packet_end - pkt);
			if (pass_end == NULL) {
				ret = false;
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . malformed auth response in handshake response\n", (*myds), (*myds)->sess, vars1.user);
				return false;
			}
			vars1.pass_len = pass_end - pkt;
		}
		if (vars1.pass_len > (len - (pkt - vars1._ptr))) {
			ret = false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . goto __exit_process_pkt_handshake_response\n", (*myds), (*myds)->sess, vars1.user);
			return false;
		}
	}
	vars1.pass = (unsigned char *)malloc(vars1.pass_len+1);
	memcpy(vars1.pass, pkt, vars1.pass_len);
	vars1.pass[vars1.pass_len] = 0;

	pkt += vars1.pass_len;
	if (vars1.capabilities & CLIENT_CONNECT_WITH_DB) {
		unsigned char* db_end = (unsigned char*)memchr(pkt, 0, packet_end - pkt);
		if (db_end == NULL) {
			ret = false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . malformed default schema in handshake response\n", (*myds), (*myds)->sess, vars1.user);
			return false;
		}
		vars1.db_tmp = strndup((const char *)pkt, db_end - pkt);
		if (vars1.db_tmp) {
			vars1.db = vars1.db_tmp;
		}
		pkt = db_end + 1;
		if (vars1.db) {
			// TODO: Not ideal, but the flow is currently complex. Resource management should be simplified in
			// a future rework, so we can 'centralize' the update to the session state with auth results.
			userinfo->set_schemaname(vars1.db, strlen(vars1.db));
		}
	} else {
		vars1.db = NULL;
	}
	if (vars1.pass_len) {
		if (vars1.pass[vars1.pass_len-1] == 0) {
			vars1.pass_len--; // remove the extra 0 if present
		}
	}
	unsigned char *extra_pkt = pkt;
	if (packet_end > extra_pkt) {
		if (vars1.capabilities & CLIENT_PLUGIN_AUTH) {
			if (extra_pkt >= packet_end) {
				ret = false;
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . malformed auth plugin offset in handshake response\n", (*myds), (*myds)->sess, vars1.user);
				return false;
			}
			const size_t extra_len = packet_end - extra_pkt;
			const size_t auth_plugin_len = strnlen(reinterpret_cast<const char*>(extra_pkt), extra_len);
			if (auth_plugin_len == extra_len) {
				ret = false;
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . malformed auth plugin in handshake response\n", (*myds), (*myds)->sess, vars1.user);
				return false;
			}
			vars1.auth_plugin = extra_pkt;
			extra_pkt += auth_plugin_len + 1;
		}
		const unsigned char* packet_end = vars1._ptr + len;
		const bool has_zstd_level = vars1.capabilities & CLIENT_ZSTD_COMPRESSION_ALGORITHM;
		const unsigned char* connect_attrs_end = packet_end - (has_zstd_level ? 1 : 0);
		if ((vars1.capabilities & CLIENT_CONNECT_ATTRS) && extra_pkt < connect_attrs_end) {
			uint64_t attrs_len = 0;
			const int attrs_len_enc = mysql_decode_length_ll(extra_pkt, &attrs_len);
			if (
				attrs_len_enc <= 0
				||
				static_cast<uint64_t>(connect_attrs_end - extra_pkt) < static_cast<uint64_t>(attrs_len_enc) + attrs_len
			) {
				ret = false;
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . malformed connect attrs in handshake response\n", (*myds), (*myds)->sess, vars1.user);
				return false;
			}
			extra_pkt += attrs_len_enc + attrs_len;
		}
		if (has_zstd_level) {
			if (packet_end <= extra_pkt) {
				ret = false;
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . missing zstd compression level in handshake response\n", (*myds), (*myds)->sess, vars1.user);
				return false;
			}
			vars1.use_zstd_compression = true;
			vars1.zstd_compression_level = *extra_pkt;
		}
	}
	return true;
}

void MySQL_Protocol::PPHR_3(MyProt_tmp_auth_vars& vars1) { // detect plugin id
	if (vars1.auth_plugin == NULL) {
		vars1.auth_plugin = (unsigned char *)"mysql_native_password"; // default
		auth_plugin_id = AUTH_MYSQL_NATIVE_PASSWORD;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' , auth_plugin_id=%d\n", (*myds), (*myds)->sess, vars1.user, auth_plugin_id);

	if (auth_plugin_id == AUTH_UNKNOWN_PLUGIN) {
		if (strncmp((char *)vars1.auth_plugin,plugins[0],strlen(plugins[0]))==0) { // mysql_native_password
			auth_plugin_id = AUTH_MYSQL_NATIVE_PASSWORD;
		} else if (strncmp((char *)vars1.auth_plugin,plugins[1],strlen(plugins[1]))==0) { // mysql_clear_password
			auth_plugin_id = AUTH_MYSQL_CLEAR_PASSWORD;
		} else if (strncmp((char *)vars1.auth_plugin,plugins[2],strlen(plugins[2]))==0) { // caching_sha2_password
			if (sent_auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD) {
				// if we send mysql_native_password as default authentication plugin we do not support
				// clients using caching_sha2_password , thus we define "unknown plugin" and force the
				// client to switch to mysql_native_password
				auth_plugin_id = AUTH_UNKNOWN_PLUGIN;
			} else if (sent_auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD) {
				auth_plugin_id = AUTH_MYSQL_CACHING_SHA2_PASSWORD;
			} else {
				assert(0);
			}
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' , auth_plugin_id=%d\n", (*myds), (*myds)->sess, vars1.user, auth_plugin_id);
}

bool MySQL_Protocol::PPHR_4auth0(unsigned char *pkt, unsigned int len, bool& ret, MyProt_tmp_auth_vars& vars1) {
	if ((*myds)->switching_auth_stage == 0) {
		(*myds)->switching_auth_stage = 1;
		(*myds)->auth_in_progress = 1;
		// check if user exists
		bool user_exists = true;
		if (GloMyLdapAuth) { // we check if user exists only if GloMyLdapAuth is enabled
#ifdef PROXYSQLCLICKHOUSE
			enum proxysql_session_type session_type = (*myds)->sess->session_type;
			if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
				//user_exists = GloClickHouseAuth->exists((char *)user);
				// for clickhouse, we currently do not support clear text or LDAP
				user_exists = true;
			} else {
#endif /* PROXYSQLCLICKHOUSE */
				user_exists = GloMyAuth->exists((char *)vars1.user);
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user_exists=%d , user='%s'\n", (*myds), (*myds)->sess, user_exists, vars1.user);
#ifdef PROXYSQLCLICKHOUSE
			}
#endif /* PROXYSQLCLICKHOUSE */
		}
		if (user_exists) {
			(*myds)->switching_auth_type = AUTH_MYSQL_NATIVE_PASSWORD; // mysql_native_password
		} else {
			(*myds)->switching_auth_type = AUTH_MYSQL_CLEAR_PASSWORD; // mysql_clear_password
		}
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user_exists=%d , user='%s' , setting switching_auth_type=%d\n", (*myds), (*myds)->sess, user_exists, vars1.user, (*myds)->switching_auth_type);
		generate_pkt_auth_switch_request(true, NULL, NULL);
		(*myds)->myconn->userinfo->set((char *)vars1.user, NULL, vars1.db, NULL);
		ret = false;
		return false;
	}
	return true;
}


bool MySQL_Protocol::PPHR_4auth1(unsigned char *pkt, unsigned int len, bool& ret, MyProt_tmp_auth_vars& vars1) {
	if (GloMyLdapAuth) {
		if ((*myds)->switching_auth_stage == 0) {
			bool user_exists = true;
#ifdef PROXYSQLCLICKHOUSE
			enum proxysql_session_type session_type = (*myds)->sess->session_type;
			if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
				//user_exists = GloClickHouseAuth->exists((char *)user);
				// for clickhouse, we currently do not support clear text or LDAP
				user_exists = true;
			} else {
#endif /* PROXYSQLCLICKHOUSE */
				user_exists = GloMyAuth->exists((char *)vars1.user);
#ifdef PROXYSQLCLICKHOUSE
			}
#endif /* PROXYSQLCLICKHOUSE */
			if (user_exists == false) {
				(*myds)->switching_auth_type = AUTH_MYSQL_CLEAR_PASSWORD; // mysql_clear_password
				(*myds)->switching_auth_stage = 1;
				(*myds)->auth_in_progress = 1;
				generate_pkt_auth_switch_request(true, NULL, NULL);
				(*myds)->myconn->userinfo->set((char *)vars1.user, NULL, vars1.db, NULL);
				ret = false;
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . goto __exit_process_pkt_handshake_response. User does not exist\n", (*myds), (*myds)->sess, vars1.user);
				return false;
			}
		}
	}
	return true;
}

void MySQL_Protocol::PPHR_5passwordTrue(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	char * reply,
	account_details_t& attr1
) {
#ifdef DEBUG
	proxy_debug(
		PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password='%s'\n",
		(*myds), (*myds)->sess, vars1.user, mf_unique_ptr<const char>(get_masked_pass(vars1.password)).get()
	);
#endif // debug
	// Could be reached several times before auth completion; allocating attributes should be reset
	(*myds)->sess->default_hostgroup = attr1.default_hostgroup;
	// Protect against multiple calls; only replace on property change
	if ((*myds)->sess->default_schema && ((*myds)->sess->default_schema != attr1.default_schema)) {
		free((*myds)->sess->default_schema);
		(*myds)->sess->default_schema = nullptr;
	}
	// TODO: Not ideal, but the flow is currently too complex. Simplifying resource management so
	// we can reduce extra alloctions should be part of the next rework.
	(*myds)->sess->default_schema = attr1.default_schema ? strdup(attr1.default_schema) : nullptr;
	// Protect against multiple calls; only replace on property change
	if ((*myds)->sess->user_attributes && (*myds)->sess->user_attributes != attr1.attributes) {
		free((*myds)->sess->user_attributes);
		(*myds)->sess->user_attributes = nullptr;
	}
	// TODO: Not ideal, but the flow is currently too complex. Simplifying resource management so
	// we can reduce extra alloctions should be part of the next rework.
	(*myds)->sess->user_attributes = attr1.attributes ? strdup(attr1.attributes) : nullptr;
#ifdef DEBUG
	debug_spiffe_id(vars1.user,attr1.attributes, __LINE__, __func__);
#endif
	(*myds)->sess->schema_locked = attr1.schema_locked;
	(*myds)->sess->transaction_persistent = attr1.transaction_persistent;
	(*myds)->sess->session_fast_forward=SESSION_FORWARD_TYPE_NONE; // default
	if ((*myds)->sess->session_type == PROXYSQL_SESSION_MYSQL) {
		(*myds)->sess->session_fast_forward = attr1.fast_forward ? SESSION_FORWARD_TYPE_PERMANENT : SESSION_FORWARD_TYPE_NONE;
	}
	(*myds)->sess->user_max_connections = attr1.max_connections;
}


// Defined below, next to PPHR_6auth2, the other caller.
static bool caching_sha2_fast_auth_verify(
	const char* cleartext_password,
	const char* scramble,
	const unsigned char* client_response,
	int64_t client_response_len
);

/**
 * @brief Authenticate the 'mysql-monitor_*' credential.
 * @details This is the only code path that authenticates
 *   'mysql-monitor_username' / 'mysql-monitor_password'. That credential is not
 *   stored in 'GloMyAuth', so @ref MySQL_Protocol::PPHR_verify_password reaches
 *   here through its 'vars1.password == NULL' branch, for ADMIN / STATS / SQLITE
 *   sessions only.
 *
 *   It used to be hardcoded to the 'mysql_native_password' scramble: a SHA1
 *   'proxy_scramble' compared over SHA_DIGEST_LENGTH (20) bytes. Under
 *   'caching_sha2_password' the client's fast-auth response is a 32-byte
 *   SHA256-derived value, so that comparison could never succeed and the
 *   credential was rejected outright -- breaking Kubernetes liveness/readiness
 *   probes and metrics exporters connecting to the Admin interface (issue #5363).
 *   Note it returned false without ever sending 'perform full authentication',
 *   which is why TLS was not a workaround either.
 *
 *   The password is held in cleartext (as documented for 'mysql-monitor_password'),
 *   so every supported plugin can be verified directly and no full-auth round trip
 *   is ever required here.
 */
void MySQL_Protocol::PPHR_5passwordFalse_0(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	char * reply,
	account_details_t& attr1) {
	if (strcmp((const char *)vars1.user,mysql_thread___monitor_username)!=0) {
		ret=false;
		return;
	}

	bool verified = false;

	switch (auth_plugin_id) {
		case AUTH_MYSQL_NATIVE_PASSWORD:
			proxy_scramble(reply, (*myds)->myconn->scramble_buff, mysql_thread___monitor_password);
			// NOTE: do NOT gate this on 'vars1.pass_len == SHA_DIGEST_LENGTH'.
			// 'pass_len' is not the amount of valid data in 'vars1.pass': PPHR_2
			// strips a trailing NUL byte from the client's response
			// ("remove the extra 0 if present"), so a legitimate 20-byte native
			// response whose last byte is 0x00 -- about 1 in 256 -- arrives with
			// pass_len == 19 while all 20 bytes are present in the buffer.
			verified =
				auth_response_has(vars1.pass_len, SHA_DIGEST_LENGTH) &&
				(memcmp(reply, vars1.pass, SHA_DIGEST_LENGTH) == 0);
			break;

		case AUTH_MYSQL_CACHING_SHA2_PASSWORD:
			if ((*myds)->switching_auth_stage == 5) {
				// A full-auth round trip was driven by another path (e.g. pass-through
				// auth), so 'vars1.pass' already holds the cleartext.
				verified =
					(vars1.pass != NULL) &&
					(strcmp(mysql_thread___monitor_password, (const char *)vars1.pass) == 0);
			} else {
				verified = caching_sha2_fast_auth_verify(
					mysql_thread___monitor_password, (*myds)->myconn->scramble_buff,
					vars1.pass, vars1.pass_len
				);
			}
			break;

		case AUTH_MYSQL_CLEAR_PASSWORD:
			verified =
				(vars1.pass != NULL) &&
				(strcmp(mysql_thread___monitor_password, (const char *)vars1.pass) == 0);
			break;

		default:
			// A client can request an arbitrary plugin; this is not a programming
			// error, so do not assert. Reject and say why.
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
				"Session=%p , DS=%p , user='%s' . Unsupported auth_plugin_id=%d for the monitor credential\n",
				(*myds), (*myds)->sess, vars1.user, auth_plugin_id);
			break;
	}

	if (verified == false) {
		ret=false;
		return;
	}

	(*myds)->sess->default_hostgroup=STATS_HOSTGROUP;
	(*myds)->sess->default_schema=strdup((char *)"main"); // just the pointer is passed
	(*myds)->sess->schema_locked=false;
	(*myds)->sess->transaction_persistent=false;
	(*myds)->sess->session_fast_forward=SESSION_FORWARD_TYPE_NONE;
	(*myds)->sess->user_max_connections=0;
	vars1.password=l_strdup(mysql_thread___monitor_password);
	ret=true;

	// caching_sha2_password requires an explicit 'fast_auth_success' marker before
	// the OK packet; mirrors what the PPHR_6auth2 call site does in
	// PPHR_verify_password. Without it the client rejects the subsequent OK.
	if (
		auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD
		&&
		(*myds)->switching_auth_stage == 0
	) {
		const unsigned char fast_auth_success = '\3';
		if (!generate_one_byte_pkt(fast_auth_success)) {
			ret = false;
		}
	}
}

void MySQL_Protocol::PPHR_5passwordFalse_auth2(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	char * reply,
	account_details_t& attr1
) {
	if (GloMyLdapAuth) {
#ifdef DEBUG
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
			"Session=%p , DS=%p , username='%s' , password='(redacted)'\n",
			(*myds), (*myds)->sess, vars1.user);
#endif // debug
		char *backend_username = NULL;
		(*myds)->sess->use_ldap_auth = true;
		vars1.password = GloMyLdapAuth->lookup((char *) vars1.user, (char *) vars1.pass, USERNAME_FRONTEND, 
			&attr1.use_ssl, &attr1.default_hostgroup, &attr1.default_schema, &attr1.schema_locked,
			&attr1.transaction_persistent, &attr1.fast_forward, &attr1.max_connections, &attr1.sha1_pass, &attr1.attributes, &backend_username);
		if (vars1.password) {
#ifdef DEBUG
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
				"Session=%p , DS=%p , username='%s' , password='(redacted)'\n",
				(*myds), (*myds)->sess, backend_username);
#endif // debug
			(*myds)->sess->default_hostgroup=attr1.default_hostgroup;
			(*myds)->sess->default_schema=attr1.default_schema; // just the pointer is passed
			(*myds)->sess->user_attributes = attr1.attributes; // just the pointer is passed, LDAP returns empty string
#ifdef DEBUG
			debug_spiffe_id(vars1.user,attr1.attributes, __LINE__, __func__);
#endif
			(*myds)->sess->schema_locked=attr1.schema_locked;
			(*myds)->sess->transaction_persistent=attr1.transaction_persistent;
			(*myds)->sess->session_fast_forward=attr1.fast_forward ? SESSION_FORWARD_TYPE_PERMANENT : SESSION_FORWARD_TYPE_NONE;
			(*myds)->sess->user_max_connections=attr1.max_connections;
			if (strcmp(vars1.password, (char *) vars1.pass) == 0) {
				if (backend_username) {
					account_details_t acct {
						GloMyAuth->lookup(backend_username, USERNAME_BACKEND, { true, true, true })
					};

					if (acct.password) {
						(*myds)->sess->default_hostgroup=attr1.default_hostgroup;
						// Free the previously set 'default_schema' by 'GloMyLdapAuth'
						if ((*myds)->sess->default_schema) {
							free((*myds)->sess->default_schema);
						}
						(*myds)->sess->default_schema=attr1.default_schema; // just the pointer is passed
						// Free the previously set 'user_attributes' by 'GloMyLdapAuth'
						if ((*myds)->sess->user_attributes) {
							free((*myds)->sess->user_attributes);
						}
						(*myds)->sess->user_attributes = attr1.attributes; // just the pointer is passed
#ifdef DEBUG
						proxy_info("Attributes for user %s are present; values redacted\n",
							acct.username);
#endif
						(*myds)->sess->schema_locked=attr1.schema_locked;
						(*myds)->sess->transaction_persistent=attr1.transaction_persistent;
						(*myds)->sess->session_fast_forward=attr1.fast_forward ? SESSION_FORWARD_TYPE_PERMANENT : SESSION_FORWARD_TYPE_NONE;
						(*myds)->sess->user_max_connections=attr1.max_connections;
						char *tmp_user=strdup((const char *)acct.username);
						userinfo->set(backend_username, NULL, NULL, NULL);
						// 'MySQL_Connection_userinfo::set' duplicates the supplied information, 'free' is required.
						free(backend_username);
						if (attr1.sha1_pass==NULL) {
							// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
							// TODO: CHECK these usages of 'reply'
							// USERNAME_FRONTEND, not the session scope: this is the LDAP
							// path, which only ever backs frontend users -- an ADMIN/STATS
							// session never reaches it.
							GloMyAuth->set_SHA1((char *)userinfo->username, USERNAME_FRONTEND,reply);
						}
						if (userinfo->sha1_pass) free(userinfo->sha1_pass);
						userinfo->sha1_pass=sha1_pass_hex(reply);
						userinfo->fe_username=strdup((const char *)tmp_user);
						free(tmp_user);
						ret=true;
					} else {
						proxy_error("Unable to load credentials for backend user %s , associated to LDAP user %s\n", backend_username, acct.username);
					}

					free_account_details(acct);
				} else {
					proxy_error("Unable to find backend user associated to LDAP user '%s'\n", vars1.user);
					ret=false;
				}
			}
		}
	}
}

/**
 * @brief Verify a 'caching_sha2_password' fast-auth response.
 * @details The client sends
 *     XOR( SHA256(pw), SHA256( SHA256(SHA256(pw)) || scramble ) )
 *   which the server recomputes from a password it can derive. This is the
 *   cache-hit path of the plugin; it requires no extra round trip and is the
 *   only completion possible when ProxySQL holds the cleartext.
 *
 *   Extracted so there is exactly one implementation of the algorithm: it is
 *   used both by @ref MySQL_Protocol::PPHR_6auth2 for credentials found in
 *   'GloMyAuth' and by @ref MySQL_Protocol::PPHR_5passwordFalse_0 for the
 *   'mysql-monitor_*' credential, which is not stored there.
 *
 * @param cleartext_password The password ProxySQL holds, NUL-terminated.
 * @param scramble The 20-byte connection scramble.
 * @param client_response The response bytes sent by the client.
 * @param client_response_len The client-declared response length, i.e. the
 *   'pass_len' the buffer was allocated from. See @ref auth_response_has: the
 *   allocation is 'client_response_len + 1' bytes, and this function reads a
 *   fixed SHA256_DIGEST_LENGTH (32), so a short response would otherwise be read
 *   past its end before authentication.
 * @return true when the response matches.
 */
static bool caching_sha2_fast_auth_verify(
	const char* cleartext_password,
	const char* scramble,
	const unsigned char* client_response,
	int64_t client_response_len
) {
	// Bounds the 32-byte compare below against the allocation, NOT against an
	// exact length. 'client_response_len' is not the amount of valid data: PPHR_2
	// strips a trailing NUL byte ("remove the extra 0 if present"), so a
	// legitimate 32-byte caching_sha2 response ending in 0x00 -- about 1 in 256 --
	// reports 31 while all 32 bytes are present. An equality gate rejects real
	// logins intermittently; measured at 20 spurious denials across ~6520
	// connections in test_auth_methods-t.
	if (auth_response_has(client_response_len, SHA256_DIGEST_LENGTH) == false) {
		return false;
	}
	if (cleartext_password == NULL || client_response == NULL) {
		return false;
	}

	unsigned char a[SHA256_DIGEST_LENGTH];
	unsigned char b[SHA256_DIGEST_LENGTH];
	unsigned char c[SHA256_DIGEST_LENGTH+20];
	unsigned char d[SHA256_DIGEST_LENGTH];
	unsigned char e[SHA256_DIGEST_LENGTH];
	SHA256((const unsigned char *)cleartext_password, strlen(cleartext_password), a);
	SHA256(a, SHA256_DIGEST_LENGTH, b);
	memcpy(c,b,SHA256_DIGEST_LENGTH);
	memcpy(c+SHA256_DIGEST_LENGTH, scramble, 20);
	SHA256(c, SHA256_DIGEST_LENGTH+20, d);
	for (int i=0; i<SHA256_DIGEST_LENGTH; i++) {
		e[i] = a[i] ^ d[i];
	}

	return memcmp(e, client_response, SHA256_DIGEST_LENGTH) == 0;
}

void MySQL_Protocol::PPHR_6auth2(
	bool& ret,
	MyProt_tmp_auth_vars& vars1
	) {
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE || session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) {
		if (
			caching_sha2_fast_auth_verify(
				vars1.password, (*myds)->myconn->scramble_buff, vars1.pass, vars1.pass_len
			)
		) {
			ret = true;
		}
	}
}

void MySQL_Protocol::PPHR_7auth1(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	char * reply,
	account_details_t& attr1
) {
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	// As in verify_user_pass(): proxy_scramble_sha1() reads SCRAMBLE_LENGTH (20)
	// bytes from 'vars1.pass', which is sized from the client-declared length.
	if ((session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE || session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) &&
		auth_response_has(vars1.pass_len, SCRAMBLE_LENGTH)) {
		ret=proxy_scramble_sha1((char *)vars1.pass,(*myds)->myconn->scramble_buff,vars1.password+1, reply);
		if (ret) {
			if (attr1.sha1_pass==NULL) {
				// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
				GloMyAuth->set_SHA1((char *)vars1.user, cred_scope_for_session(session_type),reply);
			}
			if (userinfo->sha1_pass)
				free(userinfo->sha1_pass);
			userinfo->sha1_pass=sha1_pass_hex(reply);
		}
	}
}


void MySQL_Protocol::PPHR_7auth2(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	char * reply,
	account_details_t& attr1
) {
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE || session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , session_type=%d\n", (*myds), (*myds)->sess, vars1.user, session_type);
/*
		uint8_t hash_stage1[SHA_DIGEST_LENGTH];
		uint8_t hash_stage2[SHA_DIGEST_LENGTH];
		SHA_CTX sha1_context;
		SHA1_Init(&sha1_context);
		SHA1_Update(&sha1_context, vars1.pass, vars1.pass_len);
		SHA1_Final(hash_stage1, &sha1_context);
		SHA1_Init(&sha1_context);
		SHA1_Update(&sha1_context,hash_stage1,SHA_DIGEST_LENGTH);
		SHA1_Final(hash_stage2, &sha1_context);
		char *double_hashed_password = sha1_pass_hex((char *)hash_stage2); // note that sha1_pass_hex() returns a new buffer
*/
		unsigned char md1_buf[SHA_DIGEST_LENGTH];
		unsigned char md2_buf[SHA_DIGEST_LENGTH];
		SHA1(vars1.pass, vars1.pass_len, md1_buf);
		SHA1(md1_buf,SHA_DIGEST_LENGTH,md2_buf);
		char *double_hashed_password = sha1_pass_hex((char *)md2_buf); // note that sha1_pass_hex() returns a new buffer

		if (strcasecmp(double_hashed_password,vars1.password)==0) {
			ret = true;
			if (attr1.sha1_pass==NULL) {
				// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
				GloMyAuth->set_SHA1((char *)vars1.user, cred_scope_for_session(session_type),md1_buf);
			}
			if (userinfo->sha1_pass)
				free(userinfo->sha1_pass);
			userinfo->sha1_pass=sha1_pass_hex((char *)md1_buf);
		} else {
			ret = false;
		}
		free(double_hashed_password);
	}
}

bool MySQL_Protocol::PPHR_verify_sha2(
	MyProt_tmp_auth_vars& vars1,
	enum proxysql_auth_plugins passformat,
	PASSWORD_TYPE::E passtype
) {
	bool ret = false;

	if ((*myds)->switching_auth_stage == 5) {
		if (passformat == AUTH_MYSQL_NATIVE_PASSWORD) {
			unsigned char md1_buf[SHA_DIGEST_LENGTH];
			unsigned char md2_buf[SHA_DIGEST_LENGTH];
			SHA1(vars1.pass, vars1.pass_len, md1_buf);
			SHA1(md1_buf,SHA_DIGEST_LENGTH,md2_buf);
			char *double_hashed_password = sha1_pass_hex((char *)md2_buf); // note that sha1_pass_hex() returns a new buffer
			if (strcasecmp(double_hashed_password,vars1.password)==0) {
				ret = true;
			}
			free(double_hashed_password);
		} else if (passformat == AUTH_MYSQL_CACHING_SHA2_PASSWORD) {
			assert(strlen(vars1.password) == 70);
			string sp = string(vars1.password);
			// MySQL stores rounds as 3-char zero-padded uppercase hex of (rounds/1000).
			// See sql/auth/sha2_password.cc::Caching_sha2_password::digest_round_separator():
			//   sprintf(rounds_str, "%03X", m_stored_digest_rounds)
			// Parsing as base-10 silently truncates at the first hex digit (A-F),
			// breaking auth for any backend with caching_sha2_password_digest_rounds >= 10000.
			long rounds = stol(sp.substr(3,3), nullptr, 16);
			string salt = sp.substr(7,20);
			string sha256hash = sp.substr(27,43);
			char buf[100];
			salt = "$5$rounds=" + to_string(rounds*1000) + "$" + salt;
			sha256_crypt_r((const char*)vars1.pass, salt.c_str(), buf, sizeof(buf));
			string sbuf = string(buf);
			std::size_t found = sbuf.find_last_of("$");
			assert(found != string::npos);
			sbuf = sbuf.substr(found+1);
			if (strcmp(sbuf.c_str(),vars1.password+27)==0) {
				ret = true;
			}
		} else {
			// Programatic error; invalid param
			assert(0);
		}
	}

	return ret;
}

void MySQL_Protocol::PPHR_sha2full(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	enum proxysql_auth_plugins passformat,
	PASSWORD_TYPE::E passtype
) {
	if ((*myds)->switching_auth_stage == 0) {
		const unsigned char perform_full_authentication = '\4';
		if (!generate_one_byte_pkt(perform_full_authentication)) {
			ret = false;
			return;
		}
		(*myds)->pkt_sid++; // increment pkt_sid by one
		// Required to be set; later used in 'PPHR_1' for setting current 'auth_plugin_id'. E.g:
		//  - mysql-default_authentication_plugin: 'caching_sha2_password'
		//  - Requested authentication: 'caching_sha2_password'
		//  - Stored password: 'mysql_native_password'
		// A full auth is required; and the switching auth type will be used later in 'PPHR_1'.
		(*myds)->switching_auth_type = auth_plugin_id;
		(*myds)->switching_auth_stage = 4;
		(*myds)->auth_in_progress = 1;
	} else if ((*myds)->switching_auth_stage == 5) {
		if (passformat == AUTH_MYSQL_NATIVE_PASSWORD) {
			unsigned char md1_buf[SHA_DIGEST_LENGTH];
			unsigned char md2_buf[SHA_DIGEST_LENGTH];
			SHA1(vars1.pass, vars1.pass_len, md1_buf);
			SHA1(md1_buf,SHA_DIGEST_LENGTH,md2_buf);
			char *double_hashed_password = sha1_pass_hex((char *)md2_buf); // note that sha1_pass_hex() returns a new buffer
			if (strcasecmp(double_hashed_password,vars1.password)==0) {
				ret = true;
			}
			free(double_hashed_password);
		} else if (passformat == AUTH_MYSQL_CACHING_SHA2_PASSWORD) {
			assert(strlen(vars1.password) == 70);
			string sp = string(vars1.password);
			// MySQL stores rounds as 3-char zero-padded uppercase hex of (rounds/1000) — see
			// PPHR_verify_sha2() above for the upstream format reference. Must parse base-16.
			long rounds = stol(sp.substr(3,3), nullptr, 16);
			string salt = sp.substr(7,20);
			string sha256hash = sp.substr(27,43);
			//char * sha256_crypt_r (const char *key, const char *salt, char *buffer, int buflen);
			char buf[100];
			salt = "$5$rounds=" + to_string(rounds*1000) + "$" + salt;
			sha256_crypt_r((const char*)vars1.pass, salt.c_str(), buf, sizeof(buf));
			string sbuf = string(buf);
			std::size_t found = sbuf.find_last_of("$");
			assert(found != string::npos);
			sbuf = sbuf.substr(found+1);
			if (strcmp(sbuf.c_str(),vars1.password+27)==0) {
				ret = true;
			}
		} else {
			assert(0);
		}
		if (ret == true) {
			enum proxysql_session_type session_type = (*myds)->sess->session_type;
			if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE || session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) {
				// currently proxysql doesn't know the clear text password for that specific user, let's set it!
				GloMyAuth->set_clear_text_password((char *)vars1.user, USERNAME_FRONTEND, (const char *)vars1.pass, passtype);
				// Update 'vars1' password with 'clear text' one, so session can be later updated with it
				cleanse_and_free_password(vars1.password);
				vars1.password = strdup(reinterpret_cast<const char*>(vars1.pass));
			}
		}
	} else {
		assert(0);
	}
}

bool MySQL_Protocol::PPHR_passthrough_init(MyProt_tmp_auth_vars& vars1) {
	// Stage 0: first call — client just sent the HandshakeResponse with a
	// scrambled password. Reply with AuthMoreData{0x04} so the client
	// follows up with its cleartext (under TLS or RSA-encrypted per the
	// caching_sha2_password protocol).
	if ((*myds)->switching_auth_stage == 0) {
		const unsigned char perform_full_authentication = '\4';
		if (!generate_one_byte_pkt(perform_full_authentication)) {
			return false;
		}
		(*myds)->pkt_sid++;
		(*myds)->switching_auth_type = AUTH_MYSQL_CACHING_SHA2_PASSWORD;
		(*myds)->switching_auth_stage = 4;
		(*myds)->auth_in_progress = 1;
		return true;
	}

	// Stage 5: client has replied with the cleartext password (now in
	// vars1.pass). Treat it as "potentially right" and put it directly on
	// userinfo->password -- the same field the normal backend connect path
	// uses as the auth password in mysql_real_connect_start (see
	// MySQL_Connection::connect_start). The non-blocking pass-through
	// handler then acquires a pooled backend connection that authenticates
	// with this credential; the backend's OK/ERR is the verdict, replacing
	// the old one-shot synchronous probe.
	//
	// We previously stashed the cleartext on a dedicated
	// client_myds->passthrough_cleartext field; that field is gone now that
	// the credential rides userinfo->password like any other auth.
	if ((*myds)->switching_auth_stage == 5) {
		// Stash the captured cleartext on client_myds->passthrough_cleartext.
		// It MUST live on a dedicated field, NOT userinfo->password: the
		// do_auth epilogue in process_pkt_handshake_response overwrites
		// userinfo->password with "" when auth is still in progress
		// (the `else` branch with `if (vars1.pass_len)`), which would clobber
		// the borrowed cleartext before the session handler runs. The
		// dedicated field is left untouched by that epilogue. The session
		// handler copies this cleartext onto the backend connection's
		// userinfo->password at probe-acquire time (after the epilogue has
		// run), so it becomes the auth password for mysql_real_connect_start.
		if ((*myds)->passthrough_cleartext) {
			cleanse_and_free_password((*myds)->passthrough_cleartext);
		}
		if (vars1.pass && vars1.pass_len > 0) {
			(*myds)->passthrough_cleartext =
				strdup(reinterpret_cast<const char*>(vars1.pass));
		}
		// else: client sent an empty cleartext. Leave passthrough_cleartext
		// NULL and let handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT
		// fail the auth with a generic ERR. An empty password can never
		// authenticate against a real backend account.
		(*myds)->auth_in_progress = 1;
		(*myds)->sess->set_status(AUTHENTICATING_BACKEND_FOR_CLIENT);
		return true;
	}

	// Any other stage is a protocol bug; assert in debug builds.
	assert(0);
	return false;
}

void MySQL_Protocol::PPHR_SetConnAttrs(MyProt_tmp_auth_vars& vars1, account_details_t& attr1) {
	MySQL_Connection *myconn = NULL;
	myconn=sess->client_myds->myconn;
	assert(myconn);
	myconn->set_charset(vars1.charset, CONNECT_START);

	std::stringstream ss;
	ss << vars1.charset;

	/* We are processing handshake from client. Client sends us a character set it will use in communication.
	 * we store this character set in the client's variables to use later in multiplexing with different backends
	 */
	mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_RESULTS, ss.str().c_str());
	mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_CLIENT, ss.str().c_str());
	mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_CONNECTION, ss.str().c_str());
	mysql_variables.client_set_value(sess, SQL_COLLATION_CONNECTION, ss.str().c_str());

	// Honor an explicit zstd negotiation from the client before falling back to legacy zlib compression.
	const bool use_zstd_compression =
		vars1.use_zstd_compression
		&&
		(vars1.capabilities & CLIENT_ZSTD_COMPRESSION_ALGORITHM)
		&&
		(myconn->options.server_capabilities & CLIENT_ZSTD_COMPRESSION_ALGORITHM);
	const bool use_zlib_compression =
		!use_zstd_compression
		&&
		(vars1.capabilities & CLIENT_COMPRESS)
		&&
		(myconn->options.server_capabilities & CLIENT_COMPRESS);
	const uint8_t zstd_compression_level =
		(vars1.zstd_compression_level > 0 && vars1.zstd_compression_level <= ZSTD_maxCLevel())
			? vars1.zstd_compression_level
			: static_cast<uint8_t>(mysql_thread___zstd_compression_level);

	myconn->options.compression_zstd = false;
	myconn->options.zstd_compression_level = 0;

	if (use_zlib_compression || use_zstd_compression) {
		myconn->options.compression_min_length=50;
		myconn->options.compression_zstd = use_zstd_compression;
		myconn->options.zstd_compression_level = use_zstd_compression ? zstd_compression_level : 0;
		//myconn->set_status_compression(true);  // don't enable this here. It needs to be enabled after the OK is sent
	}
	if (attr1.use_ssl==true) {
		(*myds)->sess->use_ssl = true;
	}
}

// PPHR_proc_auth_stage :: bool -> MySQL_Protocol::MySQL_Data_Stream -> auth_plugin_id -> OSC
// PPHR_cont_auth :: bool -> MySQL_Protocol::MySQL_Data_Stream -> auth_plugin_id -> OSC
// MySQL_Protocol::verify_password :: vars1 -> account_details_t -> bool
// Template idea for auth in stages; not used at the moment
/*
void MySQL_Protocol::PPHR_next_auth_stage(MyProt_tmp_auth_vars& vars1, PASSWORD_TYPE::E passtype) {
	if (
		auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD
		&&
		strlen(vars1.password) == 70
		&&
		strncasecmp(vars1.password, "$A$0", 4) == 0
	) {
		if ((*myds)->switching_auth_stage == 0) {
			const unsigned char perform_full_authentication = '\4';
			generate_one_byte_pkt(perform_full_authentication);
			(*myds)->switching_auth_type = auth_plugin_id;
			(*myds)->switching_auth_stage = 4;
			(*myds)->auth_in_progress = 1;
		} else if ((*myds)->switching_auth_stage == 5) {
			enum proxysql_session_type session_type = (*myds)->sess->session_type;
			if (
				session_type == PROXYSQL_SESSION_MYSQL ||
				session_type == PROXYSQL_SESSION_SQLITE ||
				session_type == PROXYSQL_SESSION_ADMIN ||
				session_type == PROXYSQL_SESSION_STATS
			) {
				// Clear text password currently unknown for that specific user; let's set it!
				GloMyAuth->set_clear_text_password(
					(char *)vars1.user, USERNAME_FRONTEND, (const char *)vars1.pass, passtype
				);
				// Update 'vars1' password with 'clear text' one, so session can be later updated with it
				if (vars1.password) { free(vars1.password); }
				vars1.password = strdup(reinterpret_cast<const char*>(vars1.pass));
			}
		}
	} else if (vars1.password[0] != '*') {
		if (auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD && (*myds)->switching_auth_stage == 0) {
		}
	} else {
	}
}
*/

//
// Update global state if pass verified:
// - If auth finished:
//     + Save password: sha1 || clear_text_password
// - If not (caching_sha2_password):
//     + Continue auth; trigger contitue of full auth
bool MySQL_Protocol::PPHR_verify_password(MyProt_tmp_auth_vars& vars1, account_details_t& account_details) {
	bool ret = false;
	char reply[SHA_DIGEST_LENGTH + 1] = { 0 };

	// Pass-through cache lookup and dispatch (spec §3.1, §8.2). Two
	// eligibility cases share the same lookup-and-dispatch logic:
	//
	//   - empty_pw_case:    mysql_users row exists with password=''
	//                       (admin opt-in via passthrough_auth_empty_password)
	//   - unknown_user_case: user not in mysql_users at all
	//                       (gated by passthrough_auth_unknown_users; routing
	//                        and schema synthesized from globals each connect)
	//
	// On cache hit, replace vars1.password with the learned cleartext so
	// the existing verification path below runs as if mysql_users had
	// stored a cleartext password. On miss (and TLS gate satisfied),
	// dispatch to PPHR_passthrough_init which drives the
	// caching_sha2_password full-auth exchange and ultimately schedules a
	// backend probe via AUTHENTICATING_BACKEND_FOR_CLIENT.
	{
	#ifdef PROXYSQL31
		const bool raw_empty_pw_case =
			mysql_thread___passthrough_auth_empty_password
			&& vars1.password != NULL
			&& vars1.password[0] == '\0';

		frontend_certificate_policy_result row_policy {};
		if (raw_empty_pw_case) {
			row_policy = evaluate_frontend_certificate_policy(
				*myds, account_details.attributes, vars1.user,
				frontend_auth_context::PASSTHROUGH, __LINE__, __func__);
		}

		const bool empty_pw_case = raw_empty_pw_case && !row_policy.has_spiffe_id;

		if (mysql_thread___passthrough_auth_enabled
			&& empty_pw_case
			&& !row_policy.allowed) {
			return false;
		}
	#else
		const bool empty_pw_case =
			mysql_thread___passthrough_auth_empty_password
			&& vars1.password != NULL
			&& strlen(vars1.password) == 0;
	#endif
		// Unknown-user pass-through has no mysql_users row and therefore no
		// per-user require_x509 attribute. Its transport gate remains
		// mysql-passthrough_auth_require_tls.
		const bool unknown_user_case =
			mysql_thread___passthrough_auth_unknown_users
			&& vars1.password == NULL;

		/**
		 * @brief Hard-reject when the row state is pass-through eligible but
		 * the client plugin cannot drive pass-through.
		 *
		 * When @c mysql-passthrough_auth_enabled is on, an empty stored
		 * password in @c mysql_users semantically means "learn this via the
		 * caching_sha2_password full-auth exchange" -- it is NO LONGER a
		 * marker for passwordless login (spec §3.2). However the rest of
		 * PPHR_verify_password retains the legacy
		 *   if (pass_len == 0 && strlen(password) == 0) ret = true;
		 * branch a few dozen lines below, which would otherwise grant
		 * passwordless login to e.g. a mysql_native_password client sending
		 * an empty password against the same row -- silently bypassing the
		 * documented behavior change of §3.2.
		 *
		 * Block that fallthrough explicitly here: if pass-through is enabled
		 * AND the row signals eligibility (empty password) AND the client
		 * isn't using caching_sha2_password (the only plugin we can actually
		 * probe for cleartext), set ret=false and exit before any other
		 * branch can accept the connection. Same disposition as a
		 * legitimately failed pass-through: generic auth failure, no
		 * information leak about whether the user exists.
		 *
		 * This applies only to @c empty_pw_case (admin-provisioned opt-in
		 * row). The @c unknown_user_case already cannot reach the
		 * passwordless-OK branch because @c vars1.password==NULL takes a
		 * different code path that already fails.
		 */
		if (mysql_thread___passthrough_auth_enabled
			&& empty_pw_case
			&& auth_plugin_id != AUTH_MYSQL_CACHING_SHA2_PASSWORD
			&& (*myds)->sess->session_type == PROXYSQL_SESSION_MYSQL) {
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
				"pass-through eligible row but client plugin is not "
				"caching_sha2_password (id=%d), rejecting auth for user='%s'\n",
				auth_plugin_id,
				vars1.user ? (const char*)vars1.user : "(null)");
			ret = false;
			return ret;
		}

		if (mysql_thread___passthrough_auth_enabled
			&& auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD
			&& (*myds)->sess->session_type == PROXYSQL_SESSION_MYSQL
			&& GloMyPTAuthCache != NULL
			&& vars1.user != NULL
			&& (empty_pw_case || unknown_user_case)) {

			/**
			 * @brief Username allowlist gate (spec §7.1).
			 *
			 * When @c mysql-passthrough_auth_username_pattern is set,
			 * only usernames that FullMatch the regex may drive a probe.
			 * Defaults to "" which allows every username (back-compat),
			 * but the spec lists this as the primary mitigation against
			 * unknown-user enumeration: an admin enabling
			 * @c passthrough_auth_unknown_users=true SHOULD set a pattern
			 * to constrain which usernames may even reach the probe path.
			 *
			 * Failure mode: not in allowlist -> generic auth failure with
			 * no further information leak. The pattern check happens
			 * BEFORE cache lookup so a denied username never even gets a
			 * cache-hit response (preventing trivial enumeration via
			 * timing of "user was in cache" vs "user wasn't").
			 *
			 * Applies to BOTH empty_pw_case and unknown_user_case --
			 * operators may want to constrain which admin-provisioned
			 * empty-password rows can pass-through too.
			 */
			const char *pattern_raw =
				mysql_thread___passthrough_auth_username_pattern;
			if (pattern_raw != NULL && pattern_raw[0] != '\0') {
				const bool allowed =
					GloMyPTAuthCache->username_allowed(
						std::string((const char*)vars1.user),
						std::string(pattern_raw));
				if (!allowed) {
					proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
						"pass-through auth refused: user='%s' does not match "
						"mysql-passthrough_auth_username_pattern\n",
						(const char*)vars1.user);
					ret = false;
					return ret;
				}
			}

			// Unknown-user case: synthesize routing/schema defaults from
			// globals (spec §3.5) directly onto the session, since there's
			// no mysql_users row to drive PPHR_5passwordTrue.
			if (unknown_user_case) {
				(*myds)->sess->default_hostgroup = mysql_thread___passthrough_default_hg;
				if ((*myds)->sess->default_schema == NULL) {
					const char *ds =
						(mysql_thread___passthrough_default_schema
							&& mysql_thread___passthrough_default_schema[0] != '\0')
							? mysql_thread___passthrough_default_schema
							: mysql_thread___default_schema;
					if (ds != NULL && ds[0] != '\0') {
						(*myds)->sess->default_schema = strdup(ds);
					}
				}
				(*myds)->sess->schema_locked = false;
				(*myds)->sess->transaction_persistent = true;
				(*myds)->sess->session_fast_forward = SESSION_FORWARD_TYPE_NONE;
				(*myds)->sess->user_max_connections = 0;
			}

			std::string cleartext;
			const uint32_t ttl_s =
				mysql_thread___passthrough_auth_cache_ttl_s > 0
					? static_cast<uint32_t>(mysql_thread___passthrough_auth_cache_ttl_s)
					: 0;
			if (GloMyPTAuthCache->lookup(
					std::string((const char*)vars1.user), cleartext, ttl_s)) {
				GloMyPTAuthCache->bump_cache_hits();
				/*
				 * Mark the session: the credential being used to verify
				 * this client connection came from the pass-through
				 * cache, so the backend-rejection eviction hook in
				 * handler_again___status_CONNECTING_SERVER is permitted
				 * to invalidate the entry on a future ER_ACCESS_DENIED.
				 */
				if ((*myds) && (*myds)->sess) {
					(*myds)->sess->passthrough_credential = true;
				}
				if (vars1.password) {
					OPENSSL_cleanse(vars1.password, strlen(vars1.password));
					free(vars1.password);
				}
				vars1.password = strdup(cleartext.c_str());
				if (!cleartext.empty()) {
					OPENSSL_cleanse(cleartext.data(), cleartext.size());
				}
				/**
				 * @brief Mirror the synthesized session defaults into
				 * @c account_details for the unknown-user cache-hit path.
				 *
				 * After this `if (cache hit)` branch returns, execution
				 * falls through to the rest of PPHR_verify_password which
				 * (for a non-NULL @c vars1.password) calls
				 * @ref PPHR_5passwordTrue. That helper UNCONDITIONALLY
				 * copies every routing/schema/connection field from
				 * @c account_details onto the session:
				 *
				 *   sess->default_hostgroup      <- attr1.default_hostgroup
				 *   sess->default_schema         <- attr1.default_schema
				 *   sess->schema_locked          <- attr1.schema_locked
				 *   sess->transaction_persistent <- attr1.transaction_persistent
				 *   sess->session_fast_forward   <- attr1.fast_forward ? ...
				 *   sess->user_max_connections   <- attr1.max_connections
				 *
				 * For unknown users, @c GloMyAuth->lookup returns a value-
				 * initialized @c account_details_t (all scalars zero, all
				 * pointers null). Without explicitly populating these
				 * fields with the synthesized defaults from globals
				 * (which were applied to the session above), the call to
				 * PPHR_5passwordTrue silently CLOBBERS them with zeros --
				 * the session ends up with default_hostgroup=0 (back to
				 * HG 0, not @c mysql-passthrough_default_hg),
				 * default_schema=NULL, transaction_persistent=false, etc.
				 * Worse, any non-zero scalar in the value-init struct
				 * could surface as a stale @c fast_forward bit and bypass
				 * query rules.
				 *
				 * Spec §3.5 says "Routing/defaults for unknown users are
				 * re-derived from globals each connect" -- this block is
				 * what makes that hold across the PPHR_5passwordTrue
				 * fallthrough.
				 *
				 * Discovered by the auth-correctness, security, and
				 * integration subagents during the PR #5810 deep review.
				 */
				if (unknown_user_case) {
					account_details.default_hostgroup =
						mysql_thread___passthrough_default_hg;
					if (account_details.default_schema) {
						free(account_details.default_schema);
						account_details.default_schema = NULL;
					}
					const char *ds =
						(mysql_thread___passthrough_default_schema
							&& mysql_thread___passthrough_default_schema[0] != '\0')
							? mysql_thread___passthrough_default_schema
							: mysql_thread___default_schema;
					if (ds != NULL && ds[0] != '\0') {
						account_details.default_schema = strdup(ds);
					}
					account_details.schema_locked = false;
					account_details.transaction_persistent = true;
					account_details.fast_forward = false;
					account_details.max_connections = 0;
					/*
					 * NOTE: account_details.use_ssl is intentionally NOT
					 * touched here. It controls the row-driven "this user
					 * requires SSL frontend connection" semantic; for an
					 * unknown user we have no row-level intent. The
					 * default-constructed value (false) is what we want,
					 * but explicitly assigning it would be a dead store --
					 * PPHR_5passwordTrue reads attr1.use_ssl only via
					 * PPHR_SetConnAttrs later, and the value-init already
					 * gives the right default.
					 */
				}
			} else if (mysql_thread___passthrough_auth_require_tls && !(*myds)->encrypted) {
				// Spec §7.1/§7.4: refuse to ask the client for cleartext
				// over a non-TLS connection. Fall through to the normal
				// rejection path.
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
					"pass-through auth refused: client connection is not TLS and "
					"mysql-passthrough_auth_require_tls=true (user='%s')\n",
					vars1.user ? (const char*)vars1.user : "(null)");
			} else {
				/**
				 * @brief Push routing/schema defaults onto the session
				 *        BEFORE driving the AuthMoreData{0x04} round-trip.
				 *
				 * The cache-miss + empty-pw row case never reaches the
				 * PPHR_5passwordTrue call site further down in this
				 * function (control returns from PPHR_passthrough_init
				 * for the round-trip, then the second pass through
				 * PPHR_verify_password lands at this same else-branch
				 * and returns again from stage 5). That means the
				 * session never gets its default_hostgroup populated
				 * from the mysql_users row -- it stays at the
				 * MySQL_Session::reset() sentinel (-1).
				 *
				 * @ref MySQL_Session::handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT
				 * reads @c default_hostgroup to route the probe; with
				 * the unset sentinel, @c MyHGM->MyHGC_lookup gets the
				 * value cast to @c UINT32_MAX (4294967295), no hostgroup
				 * exists for that id, and the handler calls
				 * @c fail_session("no hostgroup") which generates an
				 * ERR packet. The generate_pkt_ERR path then trips its
				 * @c assert(0) on an unexpected DSS state, crashing
				 * ProxySQL with a SIGABRT signal-6 backtrace.
				 *
				 * The cache-hit path doesn't hit this because after the
				 * lookup hit, control falls through to PPHR_5passwordTrue
				 * which unconditionally pushes account_details onto the
				 * session. The unknown_user case has its own dedicated
				 * population block above (line ~2660) that synthesizes
				 * defaults from @c mysql-passthrough_default_hg /
				 * @c mysql-passthrough_default_schema globals.
				 *
				 * Calling PPHR_5passwordTrue here mirrors what the
				 * cache-hit fallthrough would do. The helper is
				 * idempotent (only field-sets, no side effects) and
				 * the call is gated on @c !unknown_user_case because
				 * unknown_user_case's @c account_details is a
				 * value-initialized struct (all zeros) and would
				 * silently clobber the synthesized session defaults.
				 *
				 * This bug was latent until TLS was enabled on the
				 * frontend leg: the only way to exercise the
				 * cache-miss + empty-pw path end-to-end is to make
				 * caching_sha2 full-auth complete, which requires
				 * TLS on the client. The non-TLS test fixtures
				 * failed earlier in the protocol (errno 2061,
				 * "Couldn't read RSA public key from server") and
				 * never reached the probe handler.
				 */
				if (!unknown_user_case) {
					PPHR_5passwordTrue(ret, vars1, reply, account_details);
				}
				// Cache miss → drive the caching_sha2_password full-auth
				// exchange so the client emits its cleartext, which we will
				// then probe against the backend.
				if (!PPHR_passthrough_init(vars1)) {
					return false;
				}
				return ret; // not done yet; protocol state machine continues
			}
		}
	}

	if (vars1.password == NULL) {
		// this is a workaround for bug #603
		if (
			((*myds)->sess->session_type == PROXYSQL_SESSION_ADMIN)
			||
			((*myds)->sess->session_type == PROXYSQL_SESSION_STATS)
			||
			((*myds)->sess->session_type == PROXYSQL_SESSION_SQLITE)
		) {
			PPHR_5passwordFalse_0(ret, vars1, reply, account_details);
		} else {
			// assume failure
			ret=false;
			// try LDAP
			if (auth_plugin_id == AUTH_MYSQL_CLEAR_PASSWORD) {
				PPHR_5passwordFalse_auth2(ret, vars1, reply, account_details);
			}
		}
	} else {
		// update 'MySQL_Session' info using 'account_details'; transfers ownership of:
		//  - 'ad::default_schema', 'ad::attributes'
		PPHR_5passwordTrue(ret, vars1, reply, account_details);

		if (vars1.pass_len==0 && strlen(vars1.password)==0) {
			ret=true;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password=''\n", (*myds), (*myds)->sess, vars1.user);
		}
		// For empty passwords client expects either 'OK' or 'ERR'
		else if (vars1.pass_len == 0 && strlen(vars1.password) != 0) {
			ret=false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password=''\n", (*myds), (*myds)->sess, vars1.user);
		}
		else {
#ifdef DEBUG
			proxy_debug(
				PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password='%s' , auth_plugin_id=%d\n",
				(*myds), (*myds)->sess, vars1.user, get_masked_pass(vars1.password).get(), auth_plugin_id
			);
#endif // debug
			if (
				auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD
				&&
				strlen(vars1.password) == 70
				&&
				strncasecmp(vars1.password,"$A$0",4)==0
			) {
				// We have a hashed caching_sha2_password
				PPHR_sha2full(ret, vars1, AUTH_MYSQL_CACHING_SHA2_PASSWORD, vars1.passtype);
			} else if (vars1.password[0]!='*') { // clear text password
				if (auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD) { // mysql_native_password
					proxy_scramble(reply, (*myds)->myconn->scramble_buff, vars1.password);
					if (vars1.pass_len != 0 &&
						auth_response_has(vars1.pass_len, SHA_DIGEST_LENGTH) &&
						memcmp(reply, vars1.pass, SHA_DIGEST_LENGTH)==0) {
						ret=true;
					}
				} else if (auth_plugin_id == AUTH_MYSQL_CLEAR_PASSWORD)  { // mysql_clear_password
					if (strcmp(vars1.password, (char *) vars1.pass) == 0) {
						ret = true;
					}
				} else if (auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD) { // caching_sha2_password
					// Checking 'switching_auth_stage' is required case due to a potential concurrent update
					// of pass in 'GloMyAuth'. When the pass found is clear-text it's assumed that full-auth
					// is never required and that we are in the first auth stage, because of this, the pass
					// received by the client is assumed to be hashed (first auth data received). Yet, during
					// during a 'full-auth' the pass stored in 'GloMyAuth' could have been updated either by
					// user action or by another concurrent connection that called 'set_clear_text_pass' on
					// completion. In this case, we would have received a 'clear-text' pass form 'GloMyAuth'
					// but we since we would be in the final auth stage, the pass sent by client should also
					// be 'clear-text' (encrypt-pass).
					if ((*myds)->switching_auth_stage == 5) {
						if (strcmp(vars1.password, reinterpret_cast<char*>(vars1.pass)) == 0) {
							ret = true;
						}
					} else {
						PPHR_6auth2(ret, vars1);
						if (ret == true) {
							if ((*myds)->switching_auth_stage == 0) {
								const unsigned char fast_auth_success = '\3';
								ret = generate_one_byte_pkt(fast_auth_success);
							}
						}
					}
				} else {
					assert(0);
				}
			} else { // password hashed with SHA1 , mysql_native_password format
				if (auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD) { // mysql_native_password
					PPHR_7auth1(ret, vars1, reply, account_details);
				} else if (auth_plugin_id == AUTH_MYSQL_CLEAR_PASSWORD) { // mysql_clear_password
					PPHR_7auth2(ret, vars1, reply, account_details);
				} else if (auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD) { // caching_sha2_password
					PPHR_sha2full(ret, vars1, AUTH_MYSQL_NATIVE_PASSWORD, vars1.passtype);
				} else {
					assert(0);
				}
			}
		}
	}

	return ret;
}

/**
 * @brief Process handshake response from the client, and it needs to be called until
 *   the authentication is completed (successfully or failed)
 *
 * @return:
 *      true: the authentication completed
 *      false: the authentication failed, or more data is needed
 */
bool MySQL_Protocol::process_pkt_handshake_response(unsigned char *pkt, unsigned int len) {
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,pkt,len); }
#endif
	bool ret = false;
	auth_plugin_id = AUTH_UNKNOWN_PLUGIN;

	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	MyProt_tmp_auth_vars vars1;
	account_details_t account_details {};
	dup_account_details_t dup_details { true, true, true };

	vars1._ptr = pkt;
	mysql_hdr hdr;
	bool bool_rc = false;
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	//Copy4B(&hdr,pkt);
	pkt     += sizeof(mysql_hdr);

	// NOTE: 'mysqlsh' sends a 'COM_INIT_DB' as soon as the connection is openned
	// before ProxySQL has sent 'Server Greeting' messsage. Because this packet is
	// unexpected, we simple return 'false' and exit.
	if (hdr.pkt_id == 0 && *pkt == 2) {
		ret = false;
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . Client is disconnecting\n", (*myds), (*myds)->sess, vars1.user);
		goto __exit_process_pkt_handshake_response;
	}

	if ((*myds)->myconn->userinfo->username) { // authentication already started.
		int rc = PPHR_1(pkt, len, ret, vars1);
		if (rc == 1)
			goto __exit_process_pkt_handshake_response;
		if (rc == 2)
			goto __do_auth;
		assert(0);
	}

	bool_rc = PPHR_2(pkt, len, ret, vars1);
	if (bool_rc == false)
		goto __exit_process_pkt_handshake_response;


	PPHR_3(vars1); // detect plugin id
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' , auth_plugin_id=%d\n", (*myds), (*myds)->sess, vars1.user, auth_plugin_id);


	if (sent_auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD) {
		switch (auth_plugin_id) {
			case AUTH_UNKNOWN_PLUGIN:
				bool_rc = PPHR_4auth0(pkt, len, ret, vars1);
				if (bool_rc == false) {
					goto __exit_process_pkt_handshake_response;
				} else {
				}
				break;
			case AUTH_MYSQL_NATIVE_PASSWORD:
				bool_rc = PPHR_4auth1(pkt, len, ret, vars1);
				if (bool_rc == false) {
					goto __exit_process_pkt_handshake_response;
				} else {
				}
				break;
			case AUTH_MYSQL_CLEAR_PASSWORD:
				break;
			case AUTH_MYSQL_CACHING_SHA2_PASSWORD:
				// this should never happen.
				// in PPHR_3 we set auth_plugin_id = AUTH_UNKNOWN_PLUGIN
				// if sent_auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD
				assert(0);
				break;
			default:
				assert(0);
				break;
		}
	} else if (sent_auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD) {
		switch (auth_plugin_id) {
			case AUTH_UNKNOWN_PLUGIN:
			case AUTH_MYSQL_NATIVE_PASSWORD:
				// for now we always switch to mysql_native_password
				// FIXME: verify if it is correct to call this here.
				// maybe it should only be called for AUTH_UNKNOWN_PLUGIN and not for AUTH_MYSQL_NATIVE_PASSWORD
				bool_rc = PPHR_4auth0(pkt, len, ret, vars1);
				if (bool_rc == false) {
					goto __exit_process_pkt_handshake_response;
				} else {
				}
				break;
			case AUTH_MYSQL_CLEAR_PASSWORD:
				break;
			case AUTH_MYSQL_CACHING_SHA2_PASSWORD:
				if ((*myds)->auth_in_progress != 0) {
					assert(0);
				}
				if ((*myds)->switching_auth_stage != 0) {
					assert(0);
				}
				break;
			default:
				break;
		}
	} else {
		assert(0);
	}

__do_auth:
	{
		// reject connections from unknown charsets
		const MARIADB_CHARSET_INFO * c = proxysql_find_charset_nr(vars1.charset);
		if (!c) {
			proxy_error("Client %s:%d is trying to use unknown charset %u. Disconnecting\n", (*myds)->addr.addr, (*myds)->addr.port, vars1.charset);
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . Client %s:%d is trying to use unknown charset %u. Disconnecting\n", (*myds), (*myds)->sess, vars1.user, (*myds)->addr.addr, (*myds)->addr.port, vars1.charset);
			ret = false;
			goto __exit_do_auth;
		}
		// set the default session charset
		(*myds)->sess->default_charset = vars1.charset;
	}
	if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
#ifdef PROXYSQLCLICKHOUSE
		ch_dup_account_details_t ch_dup_details { true, true };

		ch_account_details_t ch_account {
			GloClickHouseAuth->lookup((char*)vars1.user, USERNAME_FRONTEND, ch_dup_details)
		};

		ch_account_to_my(account_details, ch_account);
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		account_details = GloMyAuth->lookup((char*)vars1.user, cred_scope_for_session(session_type), dup_details);
	}

	vars1.password = get_password(account_details, PASSWORD_TYPE::PRIMARY);
	vars1.passtype = PASSWORD_TYPE::PRIMARY;
	// the async state machine needs to change; we are creating overhead in auth for old-passwords
	ret = PPHR_verify_password(vars1, account_details);

	// full_auth have been performed an taken place, we 'may' already have clear_text of addl_pass
	if (!ret && (*myds)->auth_in_progress == 0) {
		proxy_debug(
			PROXY_DEBUG_MYSQL_AUTH, 5,
			"Attempting to use additional user password   ret='%d', switching_auht_stage='%d'\n",
			ret, (*myds)->switching_auth_stage
		);
		char* addl_pass = get_password(account_details, PASSWORD_TYPE::ADDITIONAL);

		if (addl_pass) {
			if (strlen(addl_pass) > 0) {
				cleanse_and_free_password(vars1.password);
				vars1.password = addl_pass;
				vars1.passtype = PASSWORD_TYPE::ADDITIONAL;
				ret = PPHR_verify_password(vars1, account_details);
			} else {
				cleanse_and_free_password(addl_pass);
			}
		}
	}

	if (
		ret &&
		(*myds)->auth_in_progress == 0 &&
		(*myds)->sess->session_type == PROXYSQL_SESSION_MYSQL &&
		(*myds)->sess->connections_handler == false &&
		(*myds)->sess->mirror == false
	) {
		__sync_add_and_fetch(
			vars1.passtype == PASSWORD_TYPE::PRIMARY ?
				&MyHGM->status.client_connections_prim_pass : &MyHGM->status.client_connections_addl_pass,
			1
		);
	}

__exit_do_auth:

	assert(sess);
	assert(sess->client_myds);

	// set connection attributes (charsets, compression, encryption)
	PPHR_SetConnAttrs(vars1, account_details);

#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,vars1._ptr,len); }
#endif

	if (vars1.use_ssl) {
		ret=true;
		goto __exit_process_pkt_handshake_response;
	}

	// Could be reached several times before auth completion; allocating attributes should be reset
	if (ret==true) {

		(*myds)->DSS=STATE_CLIENT_HANDSHAKE;

		if (!userinfo->username) // if set already, ignore
			userinfo->username=strdup((const char *)vars1.user);
		userinfo->clear_password();
		userinfo->password=strdup((const char *)vars1.password);
		if (vars1.db) userinfo->set_schemaname(vars1.db,strlen(vars1.db));
		userinfo->passtype = vars1.passtype;
	} else {
		// we always duplicate username and password, or crashes happen
		if (!userinfo->username) // if set already, ignore
			userinfo->username=strdup((const char *)vars1.user);
		if (vars1.pass_len) {
			userinfo->clear_password();
			userinfo->password=strdup((const char *)"");
		};
		userinfo->passtype = vars1.passtype;
	}
	userinfo->set(NULL,NULL,NULL,NULL); // just to call compute_hash()

__exit_process_pkt_handshake_response:

#ifdef DEBUG
	{
		const auto get_debug_pass = [] (const char* pass, size_t len = 0) -> string {
			if (!pass) { return "(null)"; }
			(void)len;
			return "(redacted)";
		};

#ifdef PROXYSQL31
		const string tmp_pass = vars1.pass_is_sensitive ?
			"(redacted RSA plaintext)" : get_debug_pass(vars1.password);
		const string tmp_cpass = vars1.pass_is_sensitive ?
			"(redacted RSA plaintext)" :
			get_debug_pass(reinterpret_cast<const char*>(vars1.pass), vars1.pass_len);
#else
		const string tmp_pass { get_debug_pass(vars1.password) };
		const string tmp_cpass { get_debug_pass(reinterpret_cast<const char*>(vars1.pass), vars1.pass_len) };
#endif

		proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 1,
			"Handshake in progress   session_id=%u user=\"%s\" password=\"%s\" client_pass=\"%s\" scramble=\"%s\""
				" db=\"%s\" auth_method=\"%s\" max_pkt=%u capabilities=%u charset=%u use_ssl=%d auth_in_progress=%d\n",
			(*myds)->sess->thread_session_id, vars1.user, tmp_pass.c_str(), tmp_cpass.c_str(),
			hex((*myds)->myconn->scramble_buff).c_str(), vars1.db, vars1.auth_plugin,
			(*myds)->myconn->options.max_allowed_pkt, vars1.capabilities, vars1.charset, (*myds)->encrypted,
			(*myds)->auth_in_progress
		);
	}
#endif

#ifdef PROXYSQL31
	if (vars1.pass_is_sensitive && vars1.pass != nullptr) {
		OPENSSL_cleanse(vars1.pass, vars1.pass_len + 1);
	}
#endif
	free(vars1.pass);
	cleanse_and_free_password(vars1.password);
	if (vars1.db_tmp) {
		free(vars1.db_tmp);
		vars1.db_tmp=NULL;
	}
	if (ret == true) {
		ret = verify_user_attributes(__LINE__, __func__, vars1.user);
	}
	free_account_details(account_details);
	return ret;
}

bool MySQL_Protocol::verify_user_attributes(int calling_line, const char *calling_func, const unsigned char *user) {
#ifdef PROXYSQL31
	const char* attributes = (*myds)->sess->user_attributes;
	if (!attributes || !*attributes) {
		const auto policy = evaluate_frontend_certificate_policy(
			*myds, attributes, user, frontend_auth_context::INITIAL_HANDSHAKE, calling_line, calling_func);
		if (!policy.allowed) return false;
		(*myds)->frontend_authenticated_via_spiffe = policy.has_spiffe_id;
		return true;
	}
	try {
		const json attrs = json::parse(attributes);
		const auto policy = evaluate_frontend_certificate_policy(
			*myds, attrs, user, frontend_auth_context::INITIAL_HANDSHAKE, calling_line, calling_func);
		if (!policy.allowed) return false;
		(*myds)->frontend_authenticated_via_spiffe = policy.has_spiffe_id;
		const auto default_transaction_isolation = attrs.find("default-transaction_isolation");
		if (default_transaction_isolation != attrs.end() && default_transaction_isolation->is_string()) {
			const std::string value = default_transaction_isolation->get<std::string>();
			mysql_variables.client_set_value((*myds)->sess, SQL_ISOLATION_LEVEL, value.c_str());
		}
	} catch (const nlohmann::json::exception& e) {
		proxy_error("%d:%s(): Invalid user attributes for user %s: %s\n", calling_line, calling_func,
			user ? reinterpret_cast<const char*>(user) : "unknown", e.what());
		return false;
	}
	return true;
#else
	bool ret = true;
	if ((*myds)->sess->user_attributes) {
		char *a = (*myds)->sess->user_attributes; // no copy, just pointer
		if (strlen(a)) {
			try {
				json j = nlohmann::json::parse(a);
				auto spiffe_id = j.find("spiffe_id");
				if (spiffe_id != j.end()) {
					ret = false;
					if (!spiffe_id->is_string()) {
						proxy_error("%d:%s(): Invalid spiffe_id type for user %s\n", calling_line, calling_func, user);
						return false;
					}
					std::string spiffe_val = spiffe_id->get<std::string>();
					if ((*myds)->x509_subject_alt_name) {
						if (spiffe_val.rfind("!", 0) == 0 && spiffe_val.size() > 1) {
							string str_spiffe_regex { spiffe_val.substr(1) };
							re2::RE2::Options opts = re2::RE2::Options(RE2::Quiet);
							re2::RE2 subject_alt_regex(str_spiffe_regex, opts);

							ret = re2::RE2::FullMatch((*myds)->x509_subject_alt_name.get(), subject_alt_regex);
						} else if (strncmp(spiffe_val.c_str(), "spiffe://", strlen("spiffe://"))==0) {
							if (strcmp(spiffe_val.c_str(), (*myds)->x509_subject_alt_name.get())==0) {
								ret = true;
							}
						}
					}
					if (ret == false) {
						proxy_error("%d:%s(): SPIFFE Authentication error for user %s . spiffed_id expected : %s , received: %s\n", calling_line, calling_func, user, spiffe_val.c_str(), ((*myds)->x509_subject_alt_name ? (*myds)->x509_subject_alt_name.get() : "none"));
					}
				}
				auto default_transaction_isolation = j.find("default-transaction_isolation");
				if (default_transaction_isolation != j.end() && default_transaction_isolation->is_string()) {
					std::string default_transaction_isolation_value = default_transaction_isolation->get<std::string>();
					mysql_variables.client_set_value((*myds)->sess, SQL_ISOLATION_LEVEL, default_transaction_isolation_value.c_str());
				}
			} catch (const nlohmann::json::exception& e) {
				proxy_error("%d:%s(): Invalid user attributes for user %s: %s\n", calling_line, calling_func, user, e.what());
				return false;
			}
		}
	}
	return ret;
#endif
}

#ifndef PROXYSQL31
bool MySQL_Protocol::user_attributes_has_spiffe(int calling_line, const char *calling_func, const unsigned char *user) {
	bool ret = false;
	if ((*myds)->sess->user_attributes) {
		char *a = (*myds)->sess->user_attributes; // no copy, just pointer
		if (strlen(a)) {
			try {
				json j = nlohmann::json::parse(a);
				if (!j.is_object()) return false;
				auto spiffe_id = j.find("spiffe_id");
				if (spiffe_id != j.end()) {
					ret = true;
				}
			} catch (const nlohmann::json::exception& e) {
				proxy_error("%d:%s(): Invalid user attributes for user %s: %s\n", calling_line, calling_func, user, e.what());
				return false;
			}
		}
	}
	return ret;
}
#endif

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
stmt_execute_metadata_t * MySQL_Protocol::get_binds_from_pkt(
	PtrSize_t& pkt, MySQL_STMT_Global_info *stmt_info, stmt_execute_metadata_t **stmt_meta
) {
	stmt_execute_metadata_t *ret=NULL; //return NULL in case of failure
	if (pkt.size < 14) {
		// some error!
		return ret;
	}
	uint16_t num_params=stmt_info->num_params;
	if (num_params==2) {
		PROXY_TRACE();
	}
	char *p=(char *)pkt.ptr+5;
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
	ret->pkt=pkt.ptr;
	uint8_t new_params_bound_flag;
	if (num_params) {
		uint16_t i;
		size_t null_bitmap_length=(num_params+7)/8;
		if (pkt.size < (14+1+null_bitmap_length)) {
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
			uint8_t tmp_is_null = (null_byte & ( 1 << idx )) >> idx;
			my_bool is_null = tmp_is_null;
			if (new_params_bound_flag == 0) {
				// NOTE: Just impose 'is_null' to be '1' using the values from
				// previous bindings when we know values for these **haven't
				// changed**, this is, when 'new_params_bound_flag' is '0'.
				// Otherwise we will assume a value to be 'NULL' when the
				// binding type could have actually been changed from the
				// previous 'MYSQL_TYPE_NULL'. For more context see #3603.
				if (binds[i].buffer_type == MYSQL_TYPE_NULL)
					is_null = 1;
			}
			is_nulls[i]=is_null;
			binds[i].is_null=&is_nulls[i];
			// set length, defaults to 0
			// for parameters with not fixed length, that will be assigned later
			// we moved this initialization here due to #3585
			binds[i].is_unsigned=0;
			lengths[i]=0;
			binds[i].length=&lengths[i];
			// NOTE: We nullify buffers here to reflect that memory wasn't
			// initalized. See #3546.
			binds[i].buffer = NULL;
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
				// NOTE: This is required because further check for nullity rely on
				// 'is_nulls' instead of 'buffer_type'. See #3603.
				if (binds[i].buffer_type == MYSQL_TYPE_NULL) {
					is_nulls[i]= 1;
				}

				p+=2;

			}
		}

		for (i=0;i<num_params;i++) {
			if (p > static_cast<char*>(pkt.ptr) + pkt.size) {
				// Required to prevent double-free in dtor
				if (ret->pkt) { ret->pkt = NULL; }
				// Only free when metadata not obtained from cache (i.e. first execute)
				if (!*stmt_meta) { delete ret; }

				return NULL;
			}
			unsigned long *_l = 0;
			my_bool * _is_null;
			void *_data = (*myds)->sess->SLDH->get(ret->stmt_id, i, &_l, &_is_null);
			if (_data) {
				// Data was sent via STMT_SEND_LONG_DATA so no data in the packet.
				binds[i].length = _l;
				binds[i].buffer = _data;
				binds[i].is_null = _is_null;
				continue;
			} else if (is_nulls[i]==true) {
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
						if (l) {
							memcpy(&ts.neg,p,1);
							memcpy(&ts.day,p+1,4);
							memcpy(&ts.hour,p+5,1);
							memcpy(&ts.minute,p+6,1);
							memcpy(&ts.second,p+7,1);
						}
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
						if (l) {
							memcpy(&ts.year,p,2);
							memcpy(&ts.month,p+2,1);
							memcpy(&ts.day,p+3,1);
						}
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
				case MYSQL_TYPE_DECIMAL:
				case MYSQL_TYPE_VARCHAR:
				case MYSQL_TYPE_BIT:
				case MYSQL_TYPE_JSON:
				case MYSQL_TYPE_NEWDECIMAL:
				case MYSQL_TYPE_ENUM:
				case MYSQL_TYPE_SET:
				case MYSQL_TYPE_TINY_BLOB:
				case MYSQL_TYPE_MEDIUM_BLOB:
				case MYSQL_TYPE_LONG_BLOB:
				case MYSQL_TYPE_BLOB:
				case MYSQL_TYPE_VAR_STRING:
				case MYSQL_TYPE_STRING:
				case MYSQL_TYPE_GEOMETRY:
					{
						uint8_t l=0;
						uint32_t len { 0 };
						l=mysql_decode_length((unsigned char *)p, &len);
						if (l>1) {
							PROXY_TRACE();
						}

						if (p + l > static_cast<char*>(pkt.ptr) + pkt.size || len > pkt.size) {
							// Required to prevent double-free in dtor
							if (ret->pkt) { ret->pkt = NULL; }
							// Only free when metadata not obtained from cache (i.e. first execute)
							if (!*stmt_meta) { delete ret; }

							return NULL;
						}

						p+=l;
						binds[i].buffer=p;
						p+=len;
						lengths[i]=len;
					}
					break;
				default:
					// LCOV_EXCL_START
					proxy_error("Unsupported field type %d in zero-based parameters[%d] "
							"of query %s from user %s with default schema %s\n",
							buffer_type, i, stmt_info->query, stmt_info->username, stmt_info->schemaname);
					assert(0);
					break;
					// LCOV_EXCL_STOP
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
		ret->size=pkt.size;

	return ret;
}

bool MySQL_Protocol::generate_COM_QUERY_from_COM_FIELD_LIST(PtrSize_t *pkt) {
	unsigned int o_pkt_size = pkt->size;
	char *pkt_ptr = (char *)pkt->ptr;

	pkt_ptr+=5;
	// some sanity check
	void *a = NULL;
	a = memchr((void *)pkt_ptr, 0, o_pkt_size-5);
	if (a==NULL) return false; // we failed to parse
	char *tablename = strdup(pkt_ptr);
	unsigned int wild_len = o_pkt_size - 5 - strlen(tablename) - 1;
	char *wild = NULL;
	if (wild_len > 0) {
		pkt_ptr+=strlen(tablename);
		pkt_ptr++;
		wild=strndup(pkt_ptr,wild_len);
	}
	char *q = NULL;
	if ((*myds)->com_field_wild) {
		free((*myds)->com_field_wild);
		(*myds)->com_field_wild=NULL;
	}
	if (wild) {
		(*myds)->com_field_wild=strdup(wild);
	}

	char *qt = (char *)"SELECT * FROM `%s` WHERE 1=0";
	q = (char *)malloc(strlen(qt)+strlen(tablename));
	sprintf(q,qt,tablename);
	l_free(pkt->size, pkt->ptr);
	pkt->size = strlen(q)+5;
	mysql_hdr Hdr;
	Hdr.pkt_id=1;
	Hdr.pkt_length = pkt->size - 4;
	pkt->ptr=malloc(pkt->size);
	memcpy(pkt->ptr,&Hdr,sizeof(mysql_hdr));
    memset((char *)pkt->ptr+4,3,1); // COM_QUERY
    memcpy((char *)pkt->ptr+5,q,pkt->size-5);

	if (wild) free(wild);
	free(tablename);
	free(q);
	return true;
}

my_bool proxy_mysql_stmt_close(MYSQL_STMT* stmt) {
	// Clean internal structures for 'stmt->mysql->stmts'.
	if (stmt->mysql) {
		stmt->mysql->stmts =
			list_delete(stmt->mysql->stmts, &stmt->list);
	}
	// Nullify 'mysql' field to avoid sending a blocking command to the server.
	stmt->mysql = NULL;
	// Perform the regular close operation.
	return mysql_stmt_close(stmt);
}
