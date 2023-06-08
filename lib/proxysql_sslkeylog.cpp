#include "proxysql_sslkeylog.h"

// http://udn.realityripple.com/docs/Mozilla/Projects/NSS/Key_Log_Format

#define KEYLOG_LABEL_MAXLEN (sizeof("CLIENT_HANDSHAKE_TRAFFIC_SECRET") - 1)

#define CLIENT_RANDOM_SIZE  32

/*
 * The master secret in TLS 1.2 and before is always 48 bytes. In TLS 1.3, the
 * secret size depends on the cipher suite's hash function which is 32 bytes
 * for SHA-256 and 48 bytes for SHA-384.
 */
#define SECRET_MAXLEN       48

static pthread_rwlock_t keylog_file_rwlock;

/* The fp for the open SSLKEYLOGFILE, or NULL if not open */
static FILE *keylog_file_fp = NULL;

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

void proxysql_keylog_init() {
    pthread_rwlock_init(&keylog_file_rwlock, nullptr);
    keylog_file_fp = NULL;
}

bool proxysql_keylog_open(const char* keylog_file)
{
    assert(keylog_file);
    FILE* keylog_file_tmp = proxysql_open_file(keylog_file);
    if (!keylog_file_tmp) return false;
    pthread_rwlock_wrlock(&keylog_file_rwlock);
    proxysql_keylog_close(false);
    keylog_file_fp = keylog_file_tmp;
    pthread_rwlock_unlock(&keylog_file_rwlock);
    return true;
}

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

void proxysql_keylog_write_line_callback(const SSL *ssl, const char *line)
{
    (void)ssl; // to fix warning

    // checking keylog_file_fp without acquiring a lock is safe, as it is checked again after acquring lock
    if (!keylog_file_fp) return;

    /* The current maximum valid keylog line length LF and NUL is 195. */
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

    /* as we are using rwlock, using fputs as it's thread-safe*/
    fputs(buf, keylog_file_fp);

__exit:
    pthread_rwlock_unlock(&keylog_file_rwlock);
}

void proxysql_keylog_attach_callback(SSL_CTX* ssl_ctx) {
    if (ssl_ctx && (SSL_CTX_get_keylog_callback(ssl_ctx) == (SSL_CTX_keylog_cb_func)NULL)) {
	    SSL_CTX_set_keylog_callback(ssl_ctx, proxysql_keylog_write_line_callback);
    }
}
