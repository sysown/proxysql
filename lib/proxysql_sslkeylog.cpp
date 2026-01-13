/**
 * @file proxysql_sslkeylog.cpp
 * @brief Implementation of SSL/TLS key logging for ProxySQL
 *
 * This module implements the NSS Key Log Format for writing TLS secrets
 * to a file, enabling decryption of SSL/TLS traffic by tools like Wireshark.
 *
 * NSS Key Log Format Reference:
 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
 *
 * Each line in the keylog file has the format:
 *   <Label> <ClientRandom> <Secret>\n
 *
 * Common labels:
 *   - CLIENT_RANDOM (TLS 1.2 and earlier)
 *   - CLIENT_HANDSHAKE_TRAFFIC_SECRET (TLS 1.3)
 *   - SERVER_HANDSHAKE_TRAFFIC_SECRET (TLS 1.3)
 *   - CLIENT_TRAFFIC_SECRET_0/1/2... (TLS 1.3)
 *   - SERVER_TRAFFIC_SECRET_0/1/2... (TLS 1.3)
 *
 * SECURITY WARNING: This file contains cryptographic secrets that can decrypt
 * all TLS traffic. Access must be restricted. Only enable for debugging.
 */

#include "proxysql_sslkeylog.h"

// NSS Key Log Format reference:
// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format

#define KEYLOG_LABEL_MAXLEN (sizeof("CLIENT_HANDSHAKE_TRAFFIC_SECRET") - 1)

#define CLIENT_RANDOM_SIZE  32

/*
 * The master secret in TLS 1.2 and before is always 48 bytes. In TLS 1.3, the
 * secret size depends on the cipher suite's hash function which is 32 bytes
 * for SHA-256 and 48 bytes for SHA-384.
 */
#define SECRET_MAXLEN       48

/**
 * @brief Read-write lock protecting concurrent access to the keylog file
 *
 * Multiple threads can read simultaneously, but writes (open/close) are exclusive.
 * This ensures that keylog writes during TLS handshakes don't race with file rotation.
 */
static pthread_rwlock_t keylog_file_rwlock;

/**
 * @brief File pointer to the currently open SSL keylog file
 *
 * NULL if keylog is disabled or file failed to open.
 * Protected by keylog_file_rwlock.
 */
static FILE *keylog_file_fp = NULL;

/**
 * @brief Open a file in append mode with line buffering
 *
 * Helper function that opens a file with mode "a+" and sets line buffering.
 * Line buffering is used because keylog entries are written one line at a time.
 *
 * @param file Path to the file to open
 * @return FILE pointer on success, NULL on failure
 *
 * @note Line buffer size is 4096 bytes
 * @note File is closed on failure to set buffer
 */
FILE* proxysql_open_file(const char* file) {
    FILE *file_tmp = fopen(file, "a+");
    if (file_tmp) {
        if (setvbuf(file_tmp, NULL, _IOLBF, 4096)) {
            fclose(file_tmp);
            file_tmp = NULL;
            goto __exit;
        }
    }
__exit:
    return file_tmp;
}

/**
 * @brief Initialize the SSL keylog subsystem
 *
 * Initializes the rwlock that protects concurrent access to the keylog file.
 * Must be called once at ProxySQL startup before any other keylog functions.
 *
 * Thread-safety: Safe (should only be called during single-threaded initialization)
 */
void proxysql_keylog_init() {
    pthread_rwlock_init(&keylog_file_rwlock, nullptr);
    keylog_file_fp = NULL;
}

/**
 * @brief Open and initialize the SSL keylog file
 *
 * Opens the specified file in append mode with line buffering.
 * If a keylog file is already open, it is closed first (file rotation).
 *
 * This function is called when:
 * - ProxySQL starts with ssl_keylog_file variable set
 * - The ssl_keylog_file variable is updated at runtime
 * - PROXYSQL FLUSH LOGS is executed
 *
 * @param keylog_file Path to the keylog file (must not be NULL)
 * @return true if the file was opened successfully, false on failure
 *
 * Thread-safety: Safe (uses write lock)
 */
bool proxysql_keylog_open(const char* keylog_file)
{
    assert(keylog_file);
    FILE* keylog_file_tmp = proxysql_open_file(keylog_file);
    if (!keylog_file_tmp) return false;
    pthread_rwlock_wrlock(&keylog_file_rwlock);
    proxysql_keylog_close(false);  // Close existing file if open
    keylog_file_fp = keylog_file_tmp;
    pthread_rwlock_unlock(&keylog_file_rwlock);
    return true;
}

/**
 * @brief Close the SSL keylog file
 *
 * Closes the currently open keylog file (if any) and sets the
 * file pointer to NULL.
 *
 * @param lock If true, acquires rwlock before closing (default: true)
 *             Set to false only if already holding the lock (internal use)
 *
 * Thread-safety: Safe when lock=true, unsafe when lock=false (internal only)
 */
void proxysql_keylog_close(bool lock)
{
    if (lock)
        pthread_rwlock_wrlock(&keylog_file_rwlock);
    if(keylog_file_fp) {
        fclose(keylog_file_fp);
        keylog_file_fp = NULL;
    }
    if (lock)
        pthread_rwlock_unlock(&keylog_file_rwlock);
}

/**
 * @brief OpenSSL callback for writing TLS secrets to the keylog file
 *
 * This callback is invoked by OpenSSL during TLS handshake to write
 * secrets (master secret, traffic secrets) to the keylog file.
 *
 * The callback is registered via SSL_CTX_set_keylog_callback() and is
 * called automatically by OpenSSL for each new TLS connection.
 *
 * Line format (NSS Key Log Format):
 *   <Label> <ClientRandom> <Secret>
 *
 * Examples:
 *   CLIENT_RANDOM a1b2c3... 48_byte_master_secret
 *   CLIENT_HANDSHAKE_TRAFFIC_SECRET a1b2c3... 32_byte_secret
 *
 * @param ssl The SSL connection (unused, present for callback signature)
 * @param line The keylog line generated by OpenSSL (without newline)
 *
 * Thread-safety: Safe (uses read lock)
 *
 * @note Double-checked locking pattern: first check without lock, then verify with lock
 * @note Maximum line length is 254 bytes (256 buffer - 2 for newline and null terminator)
 * @note Lines are automatically newline-terminated if not already present
 */
void proxysql_keylog_write_line_callback(const SSL *ssl, const char *line)
{
    (void)ssl; // to fix warning

    // Double-checked locking: first check without lock for performance
    // The check is repeated after acquiring the lock for correctness
    if (!keylog_file_fp) return;

    /* The line is written to a 256-byte buffer. The maximum line length
     * from OpenSSL is validated to not exceed 254 bytes to allow for a
     * newline and null terminator.
     */
    size_t linelen;
    char buf[256];

    pthread_rwlock_rdlock(&keylog_file_rwlock);
    if(!keylog_file_fp || !line) {
        goto __exit;
    }

    linelen = strlen(line);
    if(linelen == 0 || linelen > sizeof(buf) - 2) {
        /* Empty line or too big to fit in a LF and NUL. */
        goto __exit;
    }

    memcpy(buf, line, linelen);
    if(line[linelen - 1] != '\n') {
        buf[linelen++] = '\n';
    }
    buf[linelen] = '\0';

    /* The read lock allows multiple threads to write to the file concurrently. */
    fputs(buf, keylog_file_fp);

__exit:
    pthread_rwlock_unlock(&keylog_file_rwlock);
}

/**
 * @brief Attach the keylog callback to an SSL context
 *
 * Registers proxysql_keylog_write_line_callback() as the keylog
 * callback for the given SSL context. The callback is invoked by
 * OpenSSL whenever TLS secrets are generated during handshake.
 *
 * The callback is only attached if no callback is already registered
 * to avoid overwriting user-defined callbacks (idempotent).
 *
 * @param ssl_ctx The SSL context to attach the callback to
 *
 * Thread-safety: Safe (idempotent - checks before attaching)
 *
 * @note This uses SSL_CTX_set_keylog_callback() (OpenSSL 1.1.1+)
 * @see proxysql_keylog_write_line_callback
 */
void proxysql_keylog_attach_callback(SSL_CTX* ssl_ctx) {
    if (ssl_ctx && (SSL_CTX_get_keylog_callback(ssl_ctx) == (SSL_CTX_keylog_cb_func)NULL)) {
	    SSL_CTX_set_keylog_callback(ssl_ctx, proxysql_keylog_write_line_callback);
    }
}
