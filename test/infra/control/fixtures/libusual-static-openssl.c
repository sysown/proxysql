#include <openssl/ssl.h>
#include <usual/tls/tls.h>

int main(void) {
    SSL_CTX *openssl = SSL_CTX_new(TLS_client_method());
    struct tls *usual = tls_client();
    if (openssl == NULL || usual == NULL) return 1;
    tls_free(usual);
    SSL_CTX_free(openssl);
    return 0;
}
