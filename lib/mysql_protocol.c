

// see http://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
/* arguments to pass:
 * pointer to the field
 * poiter to the variable to store the length
 * returns the bytes length of th field
*/
uint8_t mysql_decode_length(char *ptr, uin64_t *len) {
	if (*ptr <= 0xfb) { *len = *ptr; return 1; }
	if (*ptr == 0xfc) { *len = G2(ptr+1); return 3; }
	if (*pkt == 0xfd) { *len = G3(pkt+1);  return 4; }
	if (*pkt == 0xfe) { *len = G8(pkt+1);  return 9; }
	return 0; // never reaches here
}
