#include <ma_global.h>
#include <ma_sys.h>
#include <ma_common.h>
#include <ma_pvio.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *ma_tls_init(MYSQL *mysql);
static void require(int ok, const char *message)
{
  if (!ok) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}
static void set_error(MYSQL *mysql, unsigned int n, const char *state,
                      const char *format, ...)
{
  (void)mysql; (void)n; (void)state; (void)format;
}
static SSL *connect_tls_options(const char *ca, const char *capath, const char *crlpath)
{
  MYSQL *mysql= mysql_init(NULL);
  MARIADB_PVIO pvio= { 0 };
  SSL *ssl;
  require(mysql != NULL, "mysql_init");
  mysql_ssl_set(mysql, NULL, NULL, ca, capath, NULL);
  if (crlpath != NULL)
    require(mysql_options(mysql, MYSQL_OPT_SSL_CRLPATH, crlpath) == 0, "set CRL path");
  pvio.mysql= mysql;
  pvio.set_error= set_error;
  mysql->net.pvio= &pvio;
  ssl= ma_tls_init(mysql);
  mysql->net.pvio= NULL;
  mysql_close(mysql);
  return ssl;
}
static SSL *connect_tls(const char *ca, const char *capath)
{
  return connect_tls_options(ca, capath, NULL);
}
static void close_tls(SSL *ssl)
{
  if (ssl != NULL) {
    /* Match ma_tls_close: ma_tls_init retains a creator context reference. */
    SSL_CTX_free(SSL_get_SSL_CTX(ssl));
    SSL_free(ssl);
  }
}
static int trusts(SSL *ssl, const char *certificate)
{
  FILE *file= fopen(certificate, "r");
  X509 *cert;
  X509_STORE_CTX *verify= X509_STORE_CTX_new();
  int trusted;
  require(file != NULL && verify != NULL, "verification fixture allocation");
  cert= PEM_read_X509(file, NULL, NULL, NULL);
  fclose(file);
  require(cert != NULL && ssl != NULL, "certificate and SSL context required");
  require(X509_STORE_CTX_init(verify,
      SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl)), cert, NULL) == 1, "verify init");
  trusted= X509_verify_cert(verify);
  X509_STORE_CTX_free(verify);
  X509_free(cert);
  return trusted == 1;
}
static void copy_file(const char *source, const char *destination)
{
  FILE *in= fopen(source, "rb"), *out= fopen(destination, "wb");
  char buffer[4096];
  size_t size;
  require(in != NULL && out != NULL, "open CA replacement fixture");
  while ((size= fread(buffer, 1, sizeof(buffer), in)) != 0)
    require(fwrite(buffer, 1, size, out) == size, "write CA replacement");
  require(!ferror(in), "read CA replacement");
  fclose(in);
  require(fclose(out) == 0, "close CA replacement");
}
int main(int argc, char **argv)
{
  SSL *first, *second;
  const char *mode, *one, *two, *corrupt, *mutable, *capath;
  require(argc == 7, "mode CA1 CA2 CORRUPT MUTABLE CAPATH required");
  mode= argv[1]; one= argv[2]; two= argv[3]; corrupt= argv[4];
  mutable= argv[5]; capath= argv[6];
  require(mysql_thread_init() == 0, "thread init");
  if (strcmp(mode, "hit") == 0) {
    first= connect_tls(one, NULL);
    second= connect_tls(one, NULL);
    require(first != NULL && second != NULL, "unchanged CA loads");
    require(SSL_CTX_get_cert_store(SSL_get_SSL_CTX(first)) ==
            SSL_CTX_get_cert_store(SSL_get_SSL_CTX(second)), "unchanged CA not cached");
    close_tls(first);
    first= NULL;
    mysql_thread_end();
    require(trusts(second, one) && !trusts(second, two), "live store invalidated by cache cleanup");
  } else if (strcmp(mode, "crl") == 0) {
    first= connect_tls(one, NULL);
    second= connect_tls_options(one, NULL, capath);
    require(first != NULL && second != NULL, "CA with CRL options loads");
    require(SSL_CTX_get_cert_store(SSL_get_SSL_CTX(first)) !=
            SSL_CTX_get_cert_store(SSL_get_SSL_CTX(second)), "CRL options reused cached store");
    require(trusts(first, one), "CRL flags contaminated cached connection");
  } else if (strcmp(mode, "isolation") == 0 || strcmp(mode, "capath") == 0) {
    first= connect_tls(one, strcmp(mode, "capath") == 0 ? capath : NULL);
    require(first != NULL && trusts(first, one), "first CA load");
    second= connect_tls(two, NULL);
    require(second != NULL && trusts(second, two), "second CA load");
    require(!trusts(second, one), "second connection inherited unrelated CA");
    require(!trusts(first, two), "existing connection trust mutated by another connection");
  } else if (strcmp(mode, "rotation") == 0) {
    copy_file(one, mutable);
    first= connect_tls(mutable, NULL);
    require(first != NULL && trusts(first, one), "original CA load");
    copy_file(two, mutable);
    second= connect_tls(mutable, NULL);
    require(second != NULL && trusts(second, two), "replacement CA load");
    require(!trusts(second, one), "removed CA still trusted after replacement");
    require(trusts(first, one) && !trusts(first, two), "live connection store mutated on rotation");
  } else if (strcmp(mode, "retry") == 0 || strcmp(mode, "new-retry") == 0) {
    copy_file(one, mutable);
    first= connect_tls(strcmp(mode, "retry") == 0 ? mutable : one, NULL);
    require(first != NULL, "initial CA load");
    copy_file(corrupt, mutable);
    require(connect_tls(mutable, NULL) == NULL, "invalid CA accepted on first load");
    require(connect_tls(mutable, NULL) == NULL, "invalid CA accepted on retry");
    copy_file(two, mutable);
    second= connect_tls(mutable, NULL);
    require(second != NULL && trusts(second, two) && !trusts(second, one), "recovery retained stale trust");
  } else {
    require(strcmp(mode, "lifecycle") == 0, "known test mode");
    first= connect_tls(one, NULL);
    require(first != NULL, "initial lifecycle CA load");
    close_tls(first);
    first= NULL;
    mysql_thread_end();
    mysql_thread_end();
    require(mysql_thread_init() == 0, "thread reinit");
    second= connect_tls(two, NULL);
    require(second != NULL && trusts(second, two) && !trusts(second, one), "thread reuse retained stale trust");
  }
  close_tls(first);
  close_tls(second);
  mysql_thread_end();
  printf("MariaDB CA cache %s passed\n", mode);
  return 0;
}
