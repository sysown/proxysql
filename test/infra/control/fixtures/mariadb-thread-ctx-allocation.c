#include <ma_global.h>
#include <ma_sys.h>
#include <ma_common.h>
#include <ma_pvio.h>
#include <openssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>

static unsigned int ssl_ctx_new_calls;

static void fixture_set_error(MYSQL *mysql, unsigned int error_nr,
                              const char *sqlstate, const char *format, ...)
{
  (void)mysql;
  (void)error_nr;
  (void)sqlstate;
  (void)format;
}

void *ma_tls_init(MYSQL *mysql);
SSL_CTX *__real_SSL_CTX_new(const SSL_METHOD *method);

SSL_CTX *__wrap_SSL_CTX_new(const SSL_METHOD *method)
{
  ++ssl_ctx_new_calls;
  if (ssl_ctx_new_calls == 2)
    return NULL;
  return __real_SSL_CTX_new(method);
}

int main(int argc, char **argv)
{
  MYSQL *mysql;
  MARIADB_PVIO pvio= { 0 };
  void *ssl;

  if (argc != 2) {
    fprintf(stderr, "usage: mariadb-thread-ctx-allocation CA_FILE\n");
    return EXIT_FAILURE;
  }

  mysql= mysql_init(NULL);
  if (mysql == NULL) {
    fprintf(stderr, "mysql_init failed\n");
    return EXIT_FAILURE;
  }
  mysql_ssl_set(mysql, NULL, NULL, argv[1], NULL, NULL);
  pvio.mysql= mysql;
  pvio.set_error= fixture_set_error;
  mysql->net.pvio= &pvio;

  ssl= ma_tls_init(mysql);
  if (ssl != NULL) {
    fprintf(stderr, "ma_tls_init accepted a failed thread SSL_CTX allocation\n");
    SSL_free((SSL *)ssl);
    mysql->net.pvio= NULL;
    mysql_close(mysql);
    return EXIT_FAILURE;
  }
  if (ssl_ctx_new_calls != 2) {
    fprintf(stderr, "expected two SSL_CTX_new calls, observed %u\n",
            ssl_ctx_new_calls);
    mysql->net.pvio= NULL;
    mysql_close(mysql);
    return EXIT_FAILURE;
  }

  mysql->net.pvio= NULL;
  mysql_close(mysql);
  printf("MariaDB thread SSL_CTX allocation failure test passed\n");
  return EXIT_SUCCESS;
}
