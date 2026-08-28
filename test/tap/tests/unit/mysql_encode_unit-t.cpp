#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "MySQL_encode.h"

#include <cstring>
#include <cstdlib>

// ============================================================
// mysql_encode_length() — MySQL length-encoded integer
// ============================================================

static void test_encode_length_1byte() {
    char hd[16];
    // Values < 251 use 1 byte; hd is NOT written for 1-byte values
    uint8_t len = mysql_encode_length(0, hd);
    ok(len == 1, "encode_length: 0 uses 1 byte");

    len = mysql_encode_length(250, hd);
    ok(len == 1, "encode_length: 250 uses 1 byte");

    // Also works with NULL hd pointer
    len = mysql_encode_length(100, NULL);
    ok(len == 1, "encode_length: 100 uses 1 byte (NULL hd)");
}

static void test_encode_length_3byte() {
    char hd[16];
    // Values 251-65535 use 3 bytes (0xFC prefix)
    uint8_t len = mysql_encode_length(251, hd);
    ok(len == 3, "encode_length: 251 uses 3 bytes");
    ok((unsigned char)hd[0] == 0xFC, "encode_length: 251 has 0xFC prefix");

    len = mysql_encode_length(65535, hd);
    ok(len == 3, "encode_length: 65535 uses 3 bytes");
}

static void test_encode_length_4byte() {
    char hd[16];
    // Values 65536-16777215 use 4 bytes (0xFD prefix)
    uint8_t len = mysql_encode_length(65536, hd);
    ok(len == 4, "encode_length: 65536 uses 4 bytes");
    ok((unsigned char)hd[0] == 0xFD, "encode_length: 65536 has 0xFD prefix");
}

static void test_encode_length_9byte() {
    char hd[16];
    // Values > 16777215 use 9 bytes (0xFE prefix)
    uint8_t len = mysql_encode_length(16777216, hd);
    ok(len == 9, "encode_length: 16777216 uses 9 bytes");
    ok((unsigned char)hd[0] == 0xFE, "encode_length: 16777216 has 0xFE prefix");
}

// ============================================================
// CPY3() / CPY8() — byte reading utilities
// ============================================================

static void test_cpy3() {
    unsigned char data[] = {0x01, 0x02, 0x03, 0xFF};
    unsigned int result = CPY3(data);
    // CPY3 reads 3 bytes little-endian and masks MSB to 0
    ok((result & 0xFF000000) == 0, "CPY3: MSB is zeroed");
    ok((result & 0x00FFFFFF) != 0, "CPY3: lower 3 bytes are non-zero");
}

static void test_cpy8() {
    unsigned char data[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint64_t result = CPY8(data);
    ok(result == 1, "CPY8: reads 8 bytes little-endian (value 1)");

    unsigned char data2[] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    result = CPY8(data2);
    ok(result == 65535, "CPY8: reads 65535 correctly");
}

// ============================================================
// proxy_my_crypt() — XOR cipher
// ============================================================

static void test_proxy_my_crypt_xor() {
    uint8_t s1[] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t s2[] = {0x11, 0x22, 0x33, 0x44};
    char to[4];
    proxy_my_crypt(to, s1, s2, 4);
    ok((unsigned char)to[0] == (0xAA ^ 0x11), "proxy_my_crypt: byte 0 XOR correct");
    ok((unsigned char)to[1] == (0xBB ^ 0x22), "proxy_my_crypt: byte 1 XOR correct");
    ok((unsigned char)to[2] == (0xCC ^ 0x33), "proxy_my_crypt: byte 2 XOR correct");
    ok((unsigned char)to[3] == (0xDD ^ 0x44), "proxy_my_crypt: byte 3 XOR correct");
}

static void test_proxy_my_crypt_self_inverse() {
    // XOR is self-inverse: crypt(crypt(data, key), key) == data
    uint8_t original[] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t key[] = {0x42, 0x42, 0x42, 0x42};
    char encrypted[4], decrypted[4];
    proxy_my_crypt(encrypted, original, key, 4);
    proxy_my_crypt(decrypted, (uint8_t *)encrypted, key, 4);
    ok(memcmp(decrypted, original, 4) == 0, "proxy_my_crypt: XOR is self-inverse");
}

// ============================================================
// write_encoded_length() — MySQL protocol length field encoder
// ============================================================

static void test_write_encoded_length() {
    unsigned char buf[16];
    memset(buf, 0, sizeof(buf));

    // 1-byte encoding
    int written = write_encoded_length(buf, 100, 1, 0);
    ok(written == 1, "write_encoded_length: 1-byte returns 1");
    ok(buf[0] == 100, "write_encoded_length: 1-byte value correct");

    // 3-byte encoding (0xFC prefix)
    memset(buf, 0, sizeof(buf));
    written = write_encoded_length(buf, 300, 3, 0xFC);
    ok(written == 3, "write_encoded_length: 3-byte returns 3");
    ok(buf[0] == 0xFC, "write_encoded_length: 3-byte has FC prefix");
}

int main() {
    plan(23);
    test_init_minimal();

    test_encode_length_1byte();    // 3
    test_encode_length_3byte();    // 3
    test_encode_length_4byte();    // 2
    test_encode_length_9byte();    // 2
    test_cpy3();                   // 2
    test_cpy8();                   // 2
    test_proxy_my_crypt_xor();     // 4
    test_proxy_my_crypt_self_inverse(); // 1
    test_write_encoded_length();   // 4

    test_cleanup_minimal();
    return exit_status();
}
