#include "openssl/rand.h"
#include "proxysql.h"
#include "cpp.h"
#include "re2/re2.h"
#include "re2/regexp.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_Variables.h"

#include <sstream>

//#include <ma_global.h>

extern MySQL_Authentication *GloMyAuth;
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


extern "C" char * sha256_crypt_r (const char *key, const char *salt, char *buffer, int buflen);


uint8_t mysql_encode_length(uint64_t len, char *hd);


MySQL_ResultSet::MySQL_ResultSet() {
	buffer = NULL;
	//reset_pid = true;
}

void MySQL_ResultSet::buffer_init(MySQL_Protocol* myproto) {
	if (buffer==NULL) {
		buffer=(unsigned char *)malloc(RESULTSET_BUFLEN);
	}

	buffer_used=0;
	myprot = myproto;
}

void MySQL_ResultSet::init(MySQL_Protocol *_myprot, MYSQL_RES *_res, MYSQL *_my, MYSQL_STMT *_stmt) {
	PROXY_TRACE2();
	transfer_started=false;
	resultset_completed=false;
	myprot=_myprot;
	mysql=_my;
	stmt=_stmt;
	if (buffer==NULL) {
	//if (_stmt==NULL) { // we allocate this buffer only for not prepared statements
	// removing the previous assumption. We allocate this buffer also for prepared statements
		buffer=(unsigned char *)malloc(RESULTSET_BUFLEN);
	//}
	}
	buffer_used=0;
	myds=NULL;
	if (myprot) { // if myprot = NULL , this is a mirror
		myds=myprot->get_myds();
	}
	//if (reset_pid==true) {
	sid=0;
	//PSarrayOUT = NULL;
	if (myprot) { // if myprot = NULL , this is a mirror
		sid=myds->pkt_sid+1;
		//PSarrayOUT = new PtrSizeArray(8);
	}
	//}
	//reset_pid=true;
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
	MySQL_Data_Stream * c_myds = *(myprot->myds);
	if (c_myds->com_field_list==false) {
		myprot->generate_pkt_column_count(false,&pkt.ptr,&pkt.size,sid,num_fields,this);
		sid++;
		resultset_size+=pkt.size;
	}
	// columns description
	for (unsigned int i=0; i<num_fields; i++) {
		MYSQL_FIELD *field=mysql_fetch_field(result);
		if (c_myds->com_field_list==false) {
			// we are replacing generate_pkt_field() with a more efficient version
			//myprot->generate_pkt_field(false,&pkt.ptr,&pkt.size,sid,field->db,field->table,field->org_table,field->name,field->org_name,field->charsetnr,field->length,field->type,field->flags,field->decimals,false,0,NULL,this);
			myprot->generate_pkt_field2(&pkt.ptr,&pkt.size,sid,field,this);
			resultset_size+=pkt.size;
			sid++;
		} else {
			if (c_myds->com_field_wild==NULL || mywildcmp(c_myds->com_field_wild,field->name)) {
				myprot->generate_pkt_field(false,&pkt.ptr,&pkt.size,sid,field->db,field->table,field->org_table,field->name,field->org_name,field->charsetnr,field->length,field->type,field->flags,field->decimals,true,4,(char *)"null",this);
				resultset_size+=pkt.size;
				sid++;
			}
		}
	}

	deprecate_eof_active = c_myds->myconn && (c_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF);

	// first EOF
	unsigned int nTrx=myds->sess->NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
	if (myds->sess->autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
	setStatus |= ( mysql->server_status & ~SERVER_STATUS_AUTOCOMMIT ); // get flags from server_status but ignore autocommit
	setStatus = setStatus & ~SERVER_STATUS_CURSOR_EXISTS; // Do not send cursor #1128
//	if (_stmt) { // binary protocol , we also assume we have ALL the resultset
//		myprot->generate_pkt_EOF(false,&pkt.ptr,&pkt.size,sid,0,mysql->server_status|setStatus);
//		sid++;
//		PSarrayOUT.add(pkt.ptr,pkt.size);
//		resultset_size+=pkt.size;
	//} else {
		if (RESULTSET_BUFLEN <= (buffer_used + 9)) {
			buffer_to_PSarrayOut();
		}
	if (!deprecate_eof_active && myds->com_field_list==false) {
		// up to 2.2.0 we used to add an EOF here.
		// due to bug #3547 we move the logic into add_eof() that can now handle also prepared statements
		PROXY_TRACE2();
		// if the backend server has CLIENT_DEPRECATE_EOF enabled, and the client does not support
		// CLIENT_DEPRECATE_EOF, warning_count will be excluded from the intermediate EOF packet
		add_eof((mysql->server_capabilities & CLIENT_DEPRECATE_EOF));
	}
}


// due to bug #3547 , in case of an error we remove the EOF
// and replace it with an ERR
// note that EOF is added on a packet on its own, instead of using a buffer,
// so that can be removed using remove_last_eof()
void MySQL_ResultSet::remove_last_eof() {
	PROXY_TRACE2();
	PtrSize_t pkt;
	if (PSarrayOUT.len) {
		unsigned int l = PSarrayOUT.len-1;
		PtrSize_t * pktp = PSarrayOUT.index(l);
		if (pktp->size == 9) {
			PROXY_TRACE2();
			PSarrayOUT.remove_index(l,&pkt);
			l_free(pkt.size, pkt.ptr);
			sid--;
		}
	}
}

void MySQL_ResultSet::init_with_stmt(MySQL_Connection *myconn) {
	PROXY_TRACE2();
	assert(stmt);
	MYSQL_STMT *_stmt = stmt;
	MySQL_Data_Stream * c_myds = *(myprot->myds);
		buffer_to_PSarrayOut();
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
#define MAXBUFFSTMT 12*1024*1024  // hardcoded to LESS *very important* than 16MB
			if (total_size < MAXBUFFSTMT) {
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
				PSarrayOUT.add(pkt.ptr,pkt.size);
				if (resultset_size/0xFFFFFFF != ((resultset_size+pkt.size)/0xFFFFFFF)) {
					// generate a heartbeat every 256MB
					unsigned long long curtime=monotonic_time();
					c_myds->sess->thread->atomic_curtime=curtime;
				}
				resultset_size+=pkt.size;
			} else { // this code fixes a bug: resultset larger than 4GB would cause a crash
				unsigned long long tmp_pkt_size = 0;
				r=_stmt->result.data;
				MYSQL_ROWS * r2 = NULL;
				while (r) {
					if (r->length >= MAXBUFFSTMT) {
						// we have a large row
						// we will send just that
						tmp_pkt_size = r->length;
						if (r->length > 0xFFFFFF) {
							tmp_pkt_size+=(r->length / 0xFFFFFF) * sizeof(mysql_hdr);
						}
						tmp_pkt_size += sizeof(mysql_hdr);
						PtrSize_t pkt;
						pkt.size=tmp_pkt_size;
						pkt.ptr=malloc(pkt.size);
						add_row2(r,(unsigned char *)pkt.ptr);
						PSarrayOUT.add(pkt.ptr,pkt.size);
						if (resultset_size/0xFFFFFFF != ((resultset_size+pkt.size)/0xFFFFFFF)) {
							// generate a heartbeat every 256MB
							unsigned long long curtime=monotonic_time();
							c_myds->sess->thread->atomic_curtime=curtime;
						}
						resultset_size+=pkt.size;
						r=r->next; // next row
					} else { // we have small row
						r2 = r;
						tmp_pkt_size = 0;
						unsigned int a = 0;
						while (r && (tmp_pkt_size + r->length) < MAXBUFFSTMT) {
							a++;
							tmp_pkt_size += r->length;
							tmp_pkt_size += sizeof(mysql_hdr);
							//if (r->next) {
								r = r->next;
							//}
						}
						r = r2; // we reset it back to the beginning
						if (tmp_pkt_size) { // this should always be true
							unsigned long long tmp2 = 0;
							PtrSize_t pkt;
							pkt.size=tmp_pkt_size;
							pkt.ptr=malloc(pkt.size);
							while (tmp2 < tmp_pkt_size) {
								add_row2(r,(unsigned char *)pkt.ptr+tmp2);
								tmp2 += r->length;
								tmp2 += sizeof(mysql_hdr);
								r = r->next;
							}
							PSarrayOUT.add(pkt.ptr,pkt.size);
							if (resultset_size/0xFFFFFFF != ((resultset_size+pkt.size)/0xFFFFFFF)) {
								// generate a heartbeat every 256MB
								unsigned long long curtime=monotonic_time();
								c_myds->sess->thread->atomic_curtime=curtime;
							}
							resultset_size+=pkt.size;
						}
					}
				}
			}
		}
		// up to 2.2.0 we were always adding an EOF
		// due to bug #3547 , in case of an error we remove the EOF
		// and replace it with an ERR
		// note that EOF is added on a packet on its own, instead of using a buffer,
		// so that can be removed
		//
		// NOTE: After 2.4.5 previous behavior is modified in favor of the following:
		//
		// When CLIENT_DEPRECATE_EOF two EOF packets are two be expected in the response:
		//   1. After the columns definitions (This is added directly by 'MySQL_ResultSet::init').
		//   2. After the rows values, this can either be and EOF packet or a ERR packet in case of error.
		//
		// First EOF packet isn't optional, and it's just the second the one that is optionaly either an EOF
		// or an ERR packet. The following code adds either the final EOF or ERR packet. This is equally valid
		// for when CLIENT_DEPRECATE_EOF is enabled or not. If CLIENT_DEPRECATE_EOF is:
		//   * DISABLED: The behavior is as described before.
		//   * ENABLED: Code is identical for this case. The initial EOF packet is conditionally added by
		//     'MySQL_ResultSet::init', thus, this packet should not be present if not needed at this point.
		//     In case of error an ERR packet needs to be added, otherwise `add_eof` handles the generation of
		//     the equivalent OK packet replacing the final EOF packet.
		int myerr = mysql_stmt_errno(_stmt);
		if (myerr) {
			PROXY_TRACE2();
			add_err(myconn->myds);
		} else {
			PROXY_TRACE2();
			add_eof();
		}
}

MySQL_ResultSet::~MySQL_ResultSet() {
	PtrSize_t pkt;
	//if (PSarrayOUT) {
		while (PSarrayOUT.len) {
			PSarrayOUT.remove_index_fast(0,&pkt);
			l_free(pkt.size, pkt.ptr);
		}
		//delete PSarrayOUT;
	//}
	if (buffer) {
		free(buffer);
		buffer=NULL;
	}
	//if (myds) myds->pkt_sid=sid-1;
}

// this function is used for binary protocol
// maybe later on can be adapted for text protocol too
unsigned int MySQL_ResultSet::add_row(MYSQL_ROWS *rows) {
	unsigned int pkt_length=0;
	MYSQL_ROW row = rows->data;
	unsigned long row_length = rows->length;
	// we call generate_pkt_row3 passing row_length
	sid=myprot->generate_pkt_row3(this, &pkt_length, sid, 0, NULL, row, row_length);
	sid++;
	resultset_size+=pkt_length;
	num_rows++;
	return pkt_length;
}


// this function is used for text protocol
unsigned int MySQL_ResultSet::add_row(MYSQL_ROW row) {
	unsigned long *lengths=mysql_fetch_lengths(result);
	unsigned int pkt_length=0;
	if (myprot) {
		// we call generate_pkt_row3 without passing row_length
		sid=myprot->generate_pkt_row3(this, &pkt_length, sid, num_fields, lengths, row, 0);
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
	num_rows++;
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
			char *o = (char *) row->data;
			o += copied;
			memcpy(offset, o, myhdr.pkt_length);
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
		char *o = (char *) row->data;
		o += copied;
		memcpy(offset, o, myhdr.pkt_length);
		// we are writing a large packet (over 16MB), we assume we are always outside the buffer
	}
	sid=pkt_sid;
	return length;
}

void MySQL_ResultSet::add_eof(bool suppress_warning_count) {
	if (myprot) {
		unsigned int nTrx=myds->sess->NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (myds->sess->autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		setStatus |= ( mysql->server_status & ~SERVER_STATUS_AUTOCOMMIT ); // get flags from server_status but ignore autocommit
		setStatus = setStatus & ~SERVER_STATUS_CURSOR_EXISTS; // Do not send cursor #1128
		//myprot->generate_pkt_EOF(false,&pkt.ptr,&pkt.size,sid,0,mysql->server_status|setStatus);
		//PSarrayOUT->add(pkt.ptr,pkt.size);
		//sid++;
		//resultset_size+=pkt.size;
		
		// Note: warnings count will only be sent to the client if mysql-query_digests is enabled
		const MySQL_Backend* _mybe = myds->sess->mybe;
		const MySQL_Data_Stream* _server_myds = (_mybe && _mybe->server_myds) ? _mybe->server_myds : nullptr;
		const MySQL_Connection* _myconn = (_server_myds && _server_myds->myds_type == MYDS_BACKEND && _server_myds->myconn) ?
			_server_myds->myconn : nullptr;
		const unsigned int warning_count = (_myconn && suppress_warning_count == false) ? _myconn->warning_count : 0;
		if (deprecate_eof_active) {
			PtrSize_t pkt;
			buffer_to_PSarrayOut();
			myprot->generate_pkt_OK(false, &pkt.ptr, &pkt.size, sid, 0, 0, setStatus, warning_count, NULL, true);
			PSarrayOUT.add(pkt.ptr, pkt.size);
			resultset_size += pkt.size;
		}
		else {
			// due to bug #3547 , in case of an error we remove the EOF
			// and replace it with an ERR
			// note that EOF is added on a packet on its own, instead of using a buffer,
			// so that can be removed using remove_last_eof()
			buffer_to_PSarrayOut();
			myprot->generate_pkt_EOF(false, NULL, NULL, sid, warning_count, setStatus, this);
			resultset_size += 9;
			buffer_to_PSarrayOut();
		}
		sid++;
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
			if (_myds->kill_type == 0) {
				myprot->generate_pkt_ERR(false,&pkt.ptr,&pkt.size,sid,1907,sqlstate,(char *)"Query execution was interrupted, query_timeout exceeded");
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, _myds->myconn->parent->myhgc->hid, _myds->myconn->parent->address, _myds->myconn->parent->port, 1907);
			} else {
				myprot->generate_pkt_ERR(false,&pkt.ptr,&pkt.size,sid,1317,sqlstate,(char *)"Query execution was interrupted");
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, _myds->myconn->parent->myhgc->hid, _myds->myconn->parent->address, _myds->myconn->parent->port, 1317);
			}
		} else {
			int myerr = 0;
			// the error code is returned from:
			// - mysql_stmt_errno() if using a prepared statement
			// - mysql_errno() if not using a prepared statement
			if (stmt) {
				myerr = mysql_stmt_errno(stmt);
				myprot->generate_pkt_ERR(false,&pkt.ptr,&pkt.size,sid,myerr,sqlstate,mysql_stmt_error(stmt));
			} else {
				myerr = mysql_errno(_mysql);
				myprot->generate_pkt_ERR(false,&pkt.ptr,&pkt.size,sid,myerr,sqlstate,mysql_error(_mysql));
			}
			// TODO: Check this is a mysql error
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, _myds->myconn->parent->myhgc->hid, _myds->myconn->parent->address, _myds->myconn->parent->port, myerr);
		}
		PSarrayOUT.add(pkt.ptr,pkt.size);
		sid++;
		resultset_size+=pkt.size;
	}
	resultset_completed=true;
}

/*
bool MySQL_ResultSet::get_COM_FIELD_LIST_response(PtrSizeArray *PSarrayFinal) {
	transfer_started=true;
	if (myprot) {
	}
	return resultset_completed;
}
*/

bool MySQL_ResultSet::get_resultset(PtrSizeArray *PSarrayFinal) {
	transfer_started=true;
	if (myprot) {
		PSarrayFinal->copy_add(&PSarrayOUT,0,PSarrayOUT.len);
		while (PSarrayOUT.len)
			PSarrayOUT.remove_index(PSarrayOUT.len-1,NULL);
	}
	return resultset_completed;
}

void MySQL_ResultSet::buffer_to_PSarrayOut(bool _last) {
	if (buffer_used==0)
		return;	// exit immediately if the buffer is empty
	if (buffer_used < RESULTSET_BUFLEN/2) {
		if (_last == false) {
			buffer=(unsigned char *)realloc(buffer,buffer_used);
		}
	}
	PSarrayOUT.add(buffer,buffer_used);
	if (_last) {
		buffer = NULL;
	} else {
		buffer=(unsigned char *)malloc(RESULTSET_BUFLEN);
	}
	buffer_used=0;
}

unsigned long long MySQL_ResultSet::current_size() {
	unsigned long long intsize=0;
	intsize+=sizeof(MySQL_ResultSet);
	intsize+=RESULTSET_BUFLEN; // size of buffer
	if (PSarrayOUT.len==0)	// see bug #699
		return intsize;
	intsize+=sizeof(PtrSizeArray);
	intsize+=(PSarrayOUT.size*sizeof(PtrSize_t *));
	unsigned int i;
	for (i=0; i<PSarrayOUT.len; i++) {
		PtrSize_t *pkt=PSarrayOUT.index(i);
		if (pkt->size>RESULTSET_BUFLEN) {
			intsize+=pkt->size;
		} else {
			intsize+=RESULTSET_BUFLEN;
		}
	}
	return intsize;
}

/*
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
*/
