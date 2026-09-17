#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include "proxysql_default_ca.h"

#define ARRAY_SIZE(values) (sizeof(values) / sizeof((values)[0]))

static void fail(const char *message)
{
  fprintf(stderr, "ERROR: %s\n", message);
  exit(EXIT_FAILURE);
}

static void require(int condition, const char *message)
{
  if (!condition)
    fail(message);
}

static SSL_CTX *new_context(void)
{
  SSL_CTX *context= SSL_CTX_new(TLS_client_method());
  if (context == NULL)
    fail("could not create SSL_CTX");
  return context;
}

static X509 *read_certificate(const char *path)
{
  FILE *file= fopen(path, "rb");
  X509 *certificate;

  if (file == NULL)
    fail("could not open fixture certificate");
  certificate= PEM_read_X509(file, NULL, NULL, NULL);
  if (fclose(file) != 0)
    fail("could not close fixture certificate");
  if (certificate == NULL)
    fail("could not parse fixture certificate");
  return certificate;
}

static int store_trusts_certificate(SSL_CTX *context, const char *path)
{
  X509_STORE *store= SSL_CTX_get_cert_store(context);
  X509 *expected= read_certificate(path);
  X509_STORE_CTX *verify_context= X509_STORE_CTX_new();
  int trusted;

  require(verify_context != NULL &&
          X509_STORE_CTX_init(verify_context, store, expected, NULL) == 1,
          "could not initialize fixture verification");
  trusted= X509_verify_cert(verify_context);
  X509_STORE_CTX_free(verify_context);
  X509_free(expected);
  return trusted == 1;
}

static void clear_environment(void)
{
  if (unsetenv("SSL_CERT_FILE") != 0 || unsetenv("SSL_CERT_DIR") != 0)
    fail("could not clear OpenSSL environment overrides");
}

static void test_candidate_literals(void)
{
  static const char *const expected_files[]= {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",
    "/var/lib/ca-certificates/ca-bundle.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
    "/etc/ssl/cert.pem",
    "/private/etc/ssl/cert.pem",
    NULL
  };
  size_t index;

  for (index= 0; index < ARRAY_SIZE(expected_files); index++) {
    require((expected_files[index] == NULL &&
             proxysql_default_ca_files[index] == NULL) ||
            (expected_files[index] != NULL &&
             proxysql_default_ca_files[index] != NULL &&
             strcmp(expected_files[index],
                    proxysql_default_ca_files[index]) == 0),
            "fixed OS CA bundle candidate order changed");
  }
}

static void test_valid_bundle(const char *valid_ca, const char *missing)
{
  const char *const candidates[]= { missing, valid_ca, NULL };
  SSL_CTX *context= new_context();

  clear_environment();
  require(proxysql_ssl_load_verify_locations(context, NULL, NULL,
                                             candidates) == 1,
          "valid fixed CA bundle did not load");
  require(store_trusts_certificate(context, valid_ca),
          "valid fixed CA bundle certificate is absent from the store");
  SSL_CTX_free(context);
}

static void test_corrupt_first_bundle_stops(const char *corrupt,
                                            const char *valid_second)
{
  const char *const candidates[]= { corrupt, valid_second, NULL };
  SSL_CTX *context= new_context();

  clear_environment();
  ERR_clear_error();
  require(proxysql_ssl_load_verify_locations(context, NULL, NULL,
                                             candidates) == 0,
          "corrupt first eligible bundle was bypassed");
  require(ERR_peek_error() != 0,
          "first eligible bundle failure did not preserve OpenSSL errors");
  require(!store_trusts_certificate(context, valid_second),
          "second candidate mutated the store after first load failure");
  ERR_clear_error();
  SSL_CTX_free(context);
}

static void test_symlinked_bundle(const char *symlink_bundle,
                                  const char *valid_target)
{
  const char *const candidates[]= { symlink_bundle, NULL };
  SSL_CTX *context= new_context();

  clear_environment();
  require(proxysql_ssl_load_verify_locations(context, NULL, NULL,
                                             candidates) == 1,
          "symlinked system CA bundle target did not load");
  require(store_trusts_certificate(context, valid_target),
          "symlinked CA bundle certificate is absent from the store");
  SSL_CTX_free(context);
}

static void test_unsafe_bundle_is_skipped(const char *unsafe_ca,
                                          const char *unsafe_certificate,
                                          const char *safe_ca,
                                          const char *safe_certificate)
{
  const char *const candidates[]= { unsafe_ca, safe_ca, NULL };
  struct stat status;
  SSL_CTX *context= new_context();

  require(stat(unsafe_ca, &status) == 0 &&
          (status.st_mode & (S_IWGRP | S_IWOTH)) != 0,
          "unsafe fixture is not group/world writable");
  clear_environment();
  require(proxysql_ssl_load_verify_locations(context, NULL, NULL,
                                             candidates) == 1,
          "safe bundle after unsafe candidate did not load");
  require(!store_trusts_certificate(context, unsafe_certificate),
          "group/world-writable CA bundle was implicitly trusted");
  require(store_trusts_certificate(context, safe_certificate),
          "safe CA bundle after unsafe candidate is absent");
  SSL_CTX_free(context);
}

static void test_empty_environment_value(const char *environment_name,
                                         const char *candidate_ca)
{
  const char *const candidates[]= { candidate_ca, NULL };
  SSL_CTX *expected_context= new_context();
  SSL_CTX *actual_context= new_context();
  int expected_result;
  int actual_result;

  clear_environment();
  if (setenv(environment_name, "", 1) != 0)
    fail("could not set empty OpenSSL environment override");
  ERR_clear_error();
  expected_result= SSL_CTX_set_default_verify_paths(expected_context);
  ERR_clear_error();
  actual_result= proxysql_ssl_load_verify_locations(actual_context, NULL, NULL,
                                                    candidates);
  require(actual_result == expected_result,
          "empty environment override did not preserve default-path result");
  require(!store_trusts_certificate(actual_context, candidate_ca),
          "empty environment override was replaced by a fixed candidate");
  ERR_clear_error();
  SSL_CTX_free(actual_context);
  SSL_CTX_free(expected_context);
  clear_environment();
}

static void test_no_candidate_fallback(const char *missing,
                                       const char *unrelated_ca)
{
  const char *const candidates[]= { missing, NULL };
  SSL_CTX *expected_context= new_context();
  SSL_CTX *actual_context= new_context();
  int expected_result;
  int actual_result;

  clear_environment();
  ERR_clear_error();
  expected_result= SSL_CTX_set_default_verify_paths(expected_context);
  ERR_clear_error();
  actual_result= proxysql_ssl_load_verify_locations(actual_context, NULL, NULL,
                                                    candidates);
  require(actual_result == expected_result,
          "no-candidate fallback changed compiled-default behavior");
  require(!store_trusts_certificate(actual_context, unrelated_ca),
          "missing fixed candidates loaded an unrelated fixture CA");
  ERR_clear_error();
  SSL_CTX_free(actual_context);
  SSL_CTX_free(expected_context);
}

static void test_explicit_connector_priority(const char *explicit_ca,
                                             const char *candidate_ca,
                                             const char *explicit_ca_path)
{
  const char *const candidates[]= { candidate_ca, NULL };
  SSL_CTX *file_context= new_context();
  SSL_CTX *path_context= new_context();

  clear_environment();
  if (setenv("SSL_CERT_FILE", "", 1) != 0)
    fail("could not set explicit-priority environment fixture");
  require(proxysql_ssl_load_verify_locations(file_context, explicit_ca, NULL,
                                             candidates) == 1,
          "explicit connector CA file did not load");
  require(store_trusts_certificate(file_context, explicit_ca),
          "explicit connector CA file is absent from the store");
  require(!store_trusts_certificate(file_context, candidate_ca),
          "implicit candidate overrode explicit connector CA file");

  require(proxysql_ssl_load_verify_locations(path_context, NULL,
                                             explicit_ca_path,
                                             candidates) == 1,
          "explicit connector CA path did not load");
  require(store_trusts_certificate(path_context, explicit_ca),
          "explicit connector CA path does not trust its fixture CA");
  require(!store_trusts_certificate(path_context, candidate_ca),
          "implicit candidate overrode explicit connector CA path");
  SSL_CTX_free(path_context);
  SSL_CTX_free(file_context);
  clear_environment();
}

int main(int argc, char **argv)
{
  if (argc != 8)
    fail("usage: trust-store VALID1 VALID2 CORRUPT UNSAFE SYMLINK MISSING CAPATH");

  test_candidate_literals();
  test_valid_bundle(argv[1], argv[6]);
  test_corrupt_first_bundle_stops(argv[3], argv[2]);
  test_symlinked_bundle(argv[5], argv[1]);
  test_unsafe_bundle_is_skipped(argv[4], argv[4], argv[2], argv[2]);
  test_empty_environment_value("SSL_CERT_FILE", argv[1]);
  test_empty_environment_value("SSL_CERT_DIR", argv[1]);
  test_no_candidate_fallback(argv[6], argv[1]);
  test_explicit_connector_priority(argv[1], argv[2], argv[7]);

  printf("MariaDB default trust-store resolver tests passed\n");
  return EXIT_SUCCESS;
}
