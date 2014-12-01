#include "proxysql.h"

typedef union _4bytes_t {
	unsigned char data[4];
	uint32_t i;
} _4bytes_t;

unsigned int CPY3(unsigned char *pkt) {
	_4bytes_t buf;
	memcpy(buf.data, pkt, 3);	
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
	if (*ptr <= 0xfb) { *len = *ptr; return 1; }
	if (*ptr == 0xfc) { *len = CPY2(ptr+1); return 3; }
	if (*ptr == 0xfd) { *len = CPY3(ptr+1);  return 4; }
	if (*ptr == 0xfe) { *len = CPY8(ptr+1);  return 9; }
	return 0; // never reaches here
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


int parse_mysql_pkt(unsigned char *pkt, enum session_states *states, int from_client) {
	mysql_hdr hdr;
	unsigned char cmd;
	unsigned char *payload;
	enum MySQL_response_type c;
	payload=pkt+sizeof(mysql_hdr);
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	proxy_debug(PROXY_DEBUG_NET,1,"MySQL Packet length=%d, senquence_id=%d, addr=%p\n", hdr.pkt_length, hdr.pkt_id, payload);

	switch (*states) {

		// client is not connected yet
		case STATE_NOT_CONNECTED:
			if (from_client) { // at this stage we expect a packet from the server, not from client
				return PKT_ERROR;
			}
			if (pkt_handshake_server(payload, hdr.pkt_length)==PKT_PARSED) {
				*states=STATE_SERVER_HANDSHAKE;
				return PKT_PARSED;
			}
			break;

		// server has sent the handshake
		case STATE_SERVER_HANDSHAKE:
			if (!from_client) {
				return PKT_ERROR;
			}
			if (pkt_handshake_client(payload, hdr.pkt_length)==PKT_PARSED) {
				*states=STATE_CLIENT_HANDSHAKE;
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
						*states=STATE_SLEEP;
						return PKT_PARSED;
					}
					break;
				default:
					return PKT_ERROR; // from the server we expect either an OK or an ERR. Everything else is wrong
			}
			break;

		// connection is idle. Client should be send a command
		case STATE_SLEEP:
			if (!from_client) {
				return PKT_ERROR;
			}
			cmd=*payload;
			switch (cmd) {
				case MYSQL_COM_QUERY:
					if (pkt_com_query(payload, hdr.pkt_length)==PKT_PARSED) {
						//*states=STATE_CLIENT_COM_QUERY;
						return PKT_PARSED;
					}
					break;
			}
			break;



			
		default:
		// TO BE REMOVED: begin
			if (from_client) { // at this stage we expect a packet from the server, not from client
				return PKT_ERROR;
			}
			c=mysql_response(payload, hdr.pkt_length);
			switch (c) {
				case OK_Packet:
					if (pkt_ok(payload, hdr.pkt_length)==PKT_PARSED) {
						*states=STATE_SLEEP;
						return PKT_PARSED;
					}
					break;
				default:
					return PKT_ERROR; // from the server we expect either an OK or an ERR. Everything else is wrong
			}
			
		// TO BE REMOVED: end
			break;
	}
	
	return PKT_ERROR;
}

int pkt_com_query(unsigned char *pkt, unsigned int length) {
	unsigned char buf[length];
	memcpy(buf,pkt+1, length-1);
	buf[length-1]='\0';
	proxy_debug(PROXY_DEBUG_NET,1,"Query: %s\n", buf);
	return PKT_PARSED;
}

int pkt_ok(unsigned char *pkt, unsigned int length) {
	if (length < 7) return PKT_ERROR;

   uint64_t affected_rows;
   uint64_t  insert_id;
   uint64_t  status;
   uint64_t  warns;
   unsigned char msg[length];

	int p=0;
	int rc;

   //field_count = (u_int)*pkt++;
	pkt++; p++;
	rc=mysql_decode_length(pkt,&affected_rows);
	pkt	+= rc; p+=rc;
	rc=mysql_decode_length(pkt,&insert_id);
	pkt	+= rc; p+=rc;
	status=CPY2(pkt);
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

	proxy_debug(PROXY_DEBUG_NET,1,"OK Packet <affected_rows:%u insert_id:%u status:%u warns:%u msg:%s>\n", (uint32_t)affected_rows, (uint32_t)insert_id, (uint16_t)status, (uint16_t)warns, msg);
	
	return PKT_PARSED;
}

int pkt_handshake_server(unsigned char *pkt, unsigned int length) {
	//return PKT_PARSED;
	if (*pkt != 0x0A || length < 29) return PKT_ERROR;

	uint8_t protocol;
	uint16_t capabilities;
	uint8_t charset;
	uint16_t status;
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
	status  = CPY2(pkt);
	pkt    += 15; // 2 for status, 13 for zero-byte padding
	salt2   = pkt;

   proxy_debug(PROXY_DEBUG_NET,1,"Handshake <proto:%u ver:\"%s\" thd:%d cap:%d char:%d status:%d>\n", protocol, version, thread_id, capabilities, charset, status);
//   if(op.verbose) unmask_caps(caps);

   return PKT_PARSED;

}


int pkt_handshake_client(unsigned char *pkt, unsigned int length) {
	//return PKT_PARSED;
	uint8_t charset;
   uint32_t  capabilities;
   uint32_t  max_pkt;
   uint32_t  pass_len;
   unsigned char *user;
   unsigned char *db;
   unsigned char pass[128];

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

   proxy_debug(PROXY_DEBUG_NET,1,"Handshake (%s auth) <user:\"%s\" db:\"%s\" max_pkt:%u>, capabilities:%u char:%u\n",
            (capabilities & CLIENT_SECURE_CONNECTION ? "new" : "old"), user, db, max_pkt, capabilities, charset);

   return PKT_PARSED;
}

