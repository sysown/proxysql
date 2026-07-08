#include "PgSQL_Backend_Protocol.h"
#include <cstdlib>
#include <cstring>
#include <string>

static inline uint32_t be32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

void PgSQL_Backend_Msg_Framer::feed(const unsigned char* data, size_t n) {
    if (failed) return;                                  // already in error state; ignore further bytes
    if (n > SIZE_MAX - len) { failed = true; return; }   // would overflow len+n
    if (len + n > cap) {
        size_t need = len + n;
        size_t ncap = cap ? cap : 4096;
        while (ncap < need) {
            if (ncap > SIZE_MAX / 2) { ncap = need; break; }  // avoid doubling overflow
            ncap *= 2;
        }
        unsigned char* nb = (unsigned char*)realloc(buf, ncap);
        if (!nb) { failed = true; return; }              // old buf still owned/freed by dtor; don't touch it
        buf = nb;
        cap = ncap;
    }
    memcpy(buf + len, data, n);
    len += n;
}

PgSQL_Frame_Result PgSQL_Backend_Msg_Framer::next(PgSQL_Backend_Msg& out) {
    if (failed) return FRAME_ERROR;                     // sticky error from feed()
    if (len - pos < 5) return FRAME_NEED_MORE;          // need type + length
    uint32_t msglen = be32(buf + pos + 1);
    if (msglen < 4 || msglen > PGSQL_MAX_BACKEND_MSG_LEN) return FRAME_ERROR;  // length includes its own 4 bytes; cap guards against DoS
    size_t total = 1 + msglen;                          // type byte + length-prefixed body
    if (len - pos < total) return FRAME_NEED_MORE;
    out.type = (char)buf[pos];
    out.payload = buf + pos + 5;
    out.payload_len = msglen - 4;
    pos += total;
    if (pos == len) { pos = 0; len = 0; }               // fully drained -> cheap reset
    return FRAME_OK;
}

void PgSQL_Backend_Msg_Framer::reset() { pos = 0; len = 0; failed = false; }

static void pg_native_append_be32(std::string& out, uint32_t v) {
	out.push_back((char)((v >> 24) & 0xff));
	out.push_back((char)((v >> 16) & 0xff));
	out.push_back((char)((v >> 8) & 0xff));
	out.push_back((char)(v & 0xff));
}

static void pg_native_append_be16(std::string& out, uint16_t v) {
	out.push_back((char)((v >> 8) & 0xff));
	out.push_back((char)(v & 0xff));
}

// Overwrites 4 bytes at out[pos..pos+3] with the big-endian encoding of v.
// Used to backpatch the length field once the message body has been appended.
static void pg_native_patch_be32(std::string& out, size_t pos, uint32_t v) {
	out[pos] = (char)((v >> 24) & 0xff);
	out[pos + 1] = (char)((v >> 16) & 0xff);
	out[pos + 2] = (char)((v >> 8) & 0xff);
	out[pos + 3] = (char)(v & 0xff);
}

void pg_native_build_copyfail(std::string& out, const char* reason) {
	const size_t rlen = strlen(reason) + 1;        // include NUL terminator
	out.push_back('f');
	pg_native_append_be32(out, (uint32_t)(4 + rlen));
	out.append(reason, rlen);
}

void pg_build_parse(std::string& out, const char* stmt_name, const char* query,
                    const uint32_t* param_oids, uint16_t n_oids) {
	out.push_back('P');
	size_t len_pos = out.size();
	pg_native_append_be32(out, 0);                 // placeholder, patched below
	out.append(stmt_name, strlen(stmt_name) + 1);  // dest_stmt_name\0
	out.append(query, strlen(query) + 1);          // query\0
	pg_native_append_be16(out, n_oids);
	for (uint16_t i = 0; i < n_oids; i++) {
		pg_native_append_be32(out, param_oids[i]);
	}
	pg_native_patch_be32(out, len_pos, (uint32_t)(out.size() - len_pos));
}

void pg_build_bind(std::string& out, const char* portal, const char* stmt_name,
                   const uint16_t* param_formats, uint16_t n_param_formats,
                   const char* const* param_values, const int32_t* param_lengths, uint16_t n_params,
                   const uint16_t* result_formats, uint16_t n_result_formats) {
	out.push_back('B');
	size_t len_pos = out.size();
	pg_native_append_be32(out, 0);                 // placeholder, patched below
	out.append(portal, strlen(portal) + 1);        // portal\0
	out.append(stmt_name, strlen(stmt_name) + 1);  // stmt_name\0
	pg_native_append_be16(out, n_param_formats);
	for (uint16_t i = 0; i < n_param_formats; i++) {
		pg_native_append_be16(out, param_formats[i]);
	}
	pg_native_append_be16(out, n_params);
	for (uint16_t i = 0; i < n_params; i++) {
		if (param_values[i] == nullptr) {
			pg_native_append_be32(out, (uint32_t)-1);  // SQL NULL: length -1, no bytes follow
		} else {
			int32_t vlen = param_lengths[i];
			pg_native_append_be32(out, (uint32_t)vlen);
			out.append(param_values[i], (size_t)vlen);
		}
	}
	pg_native_append_be16(out, n_result_formats);
	for (uint16_t i = 0; i < n_result_formats; i++) {
		pg_native_append_be16(out, result_formats[i]);
	}
	pg_native_patch_be32(out, len_pos, (uint32_t)(out.size() - len_pos));
}

void pg_build_describe(std::string& out, char kind, const char* name) {
	out.push_back('D');
	size_t len_pos = out.size();
	pg_native_append_be32(out, 0);                 // placeholder, patched below
	out.push_back(kind);
	out.append(name, strlen(name) + 1);            // name\0
	pg_native_patch_be32(out, len_pos, (uint32_t)(out.size() - len_pos));
}

void pg_build_execute(std::string& out, const char* portal, uint32_t max_rows) {
	out.push_back('E');
	size_t len_pos = out.size();
	pg_native_append_be32(out, 0);                 // placeholder, patched below
	out.append(portal, strlen(portal) + 1);        // portal\0
	pg_native_append_be32(out, max_rows);
	pg_native_patch_be32(out, len_pos, (uint32_t)(out.size() - len_pos));
}

void pg_build_close(std::string& out, char kind, const char* name) {
	out.push_back('C');
	size_t len_pos = out.size();
	pg_native_append_be32(out, 0);                 // placeholder, patched below
	out.push_back(kind);
	out.append(name, strlen(name) + 1);            // name\0
	pg_native_patch_be32(out, len_pos, (uint32_t)(out.size() - len_pos));
}

void pg_build_flush(std::string& out) {
	out.push_back('H');
	pg_native_append_be32(out, 4);
}

void pg_build_sync(std::string& out) {
	out.push_back('S');
	pg_native_append_be32(out, 4);
}

// Build the fixed 16-byte CancelRequest packet used by native-mode query
// cancellation. Unlike normal frontend messages there is NO leading type byte:
// the packet is a startup-style message identified solely by its request code.
// Layout (all big-endian): int32 length(16) | int32 code(80877102) |
// int32 backend pid | int32 secret key. The server sends no reply; it acts on
// the request and closes the connection.
void pg_build_cancel_request(unsigned char out[16], int32_t pid, int32_t secret) {
	const uint32_t len = 16;
	const uint32_t code = 80877102u; // 1234<<16 | 5678 — the CancelRequest code
	out[0]  = (unsigned char)((len  >> 24) & 0xff);
	out[1]  = (unsigned char)((len  >> 16) & 0xff);
	out[2]  = (unsigned char)((len  >>  8) & 0xff);
	out[3]  = (unsigned char)( len         & 0xff);
	out[4]  = (unsigned char)((code >> 24) & 0xff);
	out[5]  = (unsigned char)((code >> 16) & 0xff);
	out[6]  = (unsigned char)((code >>  8) & 0xff);
	out[7]  = (unsigned char)( code        & 0xff);
	out[8]  = (unsigned char)(((uint32_t)pid    >> 24) & 0xff);
	out[9]  = (unsigned char)(((uint32_t)pid    >> 16) & 0xff);
	out[10] = (unsigned char)(((uint32_t)pid    >>  8) & 0xff);
	out[11] = (unsigned char)(( (uint32_t)pid          ) & 0xff);
	out[12] = (unsigned char)(((uint32_t)secret >> 24) & 0xff);
	out[13] = (unsigned char)(((uint32_t)secret >> 16) & 0xff);
	out[14] = (unsigned char)(((uint32_t)secret >>  8) & 0xff);
	out[15] = (unsigned char)(( (uint32_t)secret       ) & 0xff);
}
