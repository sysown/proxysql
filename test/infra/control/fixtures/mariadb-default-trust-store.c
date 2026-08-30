#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "proxysql_default_ca.h"

#define ARRAY_SIZE(values) (sizeof(values) / sizeof((values)[0]))
#define MAX_CALLS 16
#define PATH_BUFFER_SIZE 4096

struct fake_loader {
  char calls[MAX_CALLS][PATH_BUFFER_SIZE];
  size_t call_count;
  const char *success_path;
  int fallback_result;
  int fallback_calls;
  int mark_result;
  int mark_calls;
  int pop_to_mark_calls;
  int clear_last_mark_calls;
  int clear_error_calls;
};

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

static void join_path(char *destination, size_t size,
                      const char *directory, const char *name)
{
  int length= snprintf(destination, size, "%s/%s", directory, name);
  if (length < 0 || (size_t)length >= size)
    fail("fixture path is too long");
}

static void make_directory(const char *path)
{
  if (mkdir(path, 0700) != 0)
    fail("could not create fixture directory");
}

static void make_file(const char *path)
{
  FILE *file= fopen(path, "wb");
  if (!file)
    fail("could not create fixture file");
  if (fputs("fixture\n", file) == EOF || fclose(file) != 0)
    fail("could not write fixture file");
}

static int fake_load(void *context, const char *ca_file, const char *ca_path)
{
  struct fake_loader *loader= (struct fake_loader *)context;
  const char *selected= ca_file ? ca_file : ca_path;

  require(selected != NULL, "loader received no CA file or directory");
  require(loader->call_count < MAX_CALLS, "too many loader calls");
  if (snprintf(loader->calls[loader->call_count], PATH_BUFFER_SIZE, "%s", selected)
      >= PATH_BUFFER_SIZE)
    fail("recorded loader path is too long");
  loader->call_count++;
  return loader->success_path && strcmp(selected, loader->success_path) == 0;
}

static int fake_fallback(void *context)
{
  struct fake_loader *loader= (struct fake_loader *)context;
  loader->fallback_calls++;
  return loader->fallback_result;
}

static void fake_clear_error(void *context)
{
  struct fake_loader *loader= (struct fake_loader *)context;
  loader->clear_error_calls++;
}

static int fake_set_error_mark(void *context)
{
  struct fake_loader *loader= (struct fake_loader *)context;
  loader->mark_calls++;
  return loader->mark_result;
}

static int fake_pop_error_to_mark(void *context)
{
  struct fake_loader *loader= (struct fake_loader *)context;
  loader->pop_to_mark_calls++;
  return 1;
}

static int fake_clear_last_error_mark(void *context)
{
  struct fake_loader *loader= (struct fake_loader *)context;
  loader->clear_last_mark_calls++;
  return 1;
}

static struct proxysql_ssl_verify_ops fake_ops(struct fake_loader *loader)
{
  struct proxysql_ssl_verify_ops ops;
  ops.context= loader;
  ops.load_verify_locations= fake_load;
  ops.set_default_verify_paths= fake_fallback;
  ops.set_error_mark= fake_set_error_mark;
  ops.pop_error_to_mark= fake_pop_error_to_mark;
  ops.clear_last_error_mark= fake_clear_last_error_mark;
  ops.clear_error= fake_clear_error;
  return ops;
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
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/ca-certificates/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    NULL
  };
  static const char *const expected_directories[]= {
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/etc/pki/ca-trust/extracted/openssl",
    "/var/lib/ca-certificates/openssl",
    "/usr/local/share/certs",
    "/private/etc/ssl/certs",
    "/opt/homebrew/etc/openssl@3/certs",
    "/usr/local/etc/openssl@3/certs",
    NULL
  };
  size_t index;

  for (index= 0; index < ARRAY_SIZE(expected_files); index++) {
    require((expected_files[index] == NULL && proxysql_default_ca_files[index] == NULL) ||
            (expected_files[index] != NULL && proxysql_default_ca_files[index] != NULL &&
             strcmp(expected_files[index], proxysql_default_ca_files[index]) == 0),
            "platform CA file candidate order changed");
  }
  for (index= 0; index < ARRAY_SIZE(expected_directories); index++) {
    require((expected_directories[index] == NULL &&
             proxysql_default_ca_directories[index] == NULL) ||
            (expected_directories[index] != NULL &&
             proxysql_default_ca_directories[index] != NULL &&
             strcmp(expected_directories[index],
                    proxysql_default_ca_directories[index]) == 0),
            "platform CA directory candidate order changed");
  }
}

static void test_explicit_connector_priority(const char *fixture_root)
{
  char platform_file[PATH_BUFFER_SIZE];
  const char *files[2];
  const char *directories[]= { NULL };
  struct fake_loader loader= { 0 };
  struct proxysql_ssl_verify_ops ops= fake_ops(&loader);
  const char *explicit_ca= "/operator/connector-ca.pem";

  join_path(platform_file, sizeof(platform_file), fixture_root, "platform.pem");
  make_file(platform_file);
  files[0]= platform_file;
  files[1]= NULL;
  loader.success_path= explicit_ca;

  clear_environment();
  require(proxysql_ssl_load_verify_locations(explicit_ca, NULL, files,
                                             directories, &ops) == 1,
          "explicit connector CA did not succeed");
  require(loader.call_count == 1 &&
          strcmp(loader.calls[0], explicit_ca) == 0,
          "explicit connector CA was not the only load attempt");
  require(loader.fallback_calls == 0,
          "explicit connector CA reached compiled defaults");

  memset(&loader, 0, sizeof(loader));
  ops= fake_ops(&loader);
  require(proxysql_ssl_load_verify_locations(explicit_ca, NULL, files,
                                             directories, &ops) == 0,
          "explicit connector CA failure was hidden");
  require(loader.call_count == 1 && loader.fallback_calls == 0 &&
          loader.clear_error_calls == 0,
          "explicit connector CA failure tried another trust source");

  memset(&loader, 0, sizeof(loader));
  ops= fake_ops(&loader);
  loader.success_path= "/operator/hash-dir";
  require(proxysql_ssl_load_verify_locations(NULL, loader.success_path, files,
                                             directories, &ops) == 1,
          "explicit connector CA directory did not succeed");
  require(loader.call_count == 1 &&
          strcmp(loader.calls[0], loader.success_path) == 0 &&
          loader.fallback_calls == 0,
          "explicit connector CA directory was not the only load attempt");
}

static void test_environment_priority(const char *fixture_root)
{
  char platform_file[PATH_BUFFER_SIZE];
  const char *files[2];
  const char *directories[]= { NULL };
  struct fake_loader loader= { 0 };
  struct proxysql_ssl_verify_ops ops= fake_ops(&loader);

  join_path(platform_file, sizeof(platform_file), fixture_root, "env-platform.pem");
  make_file(platform_file);
  files[0]= platform_file;
  files[1]= NULL;

  clear_environment();
  if (setenv("SSL_CERT_FILE", "/operator/environment-ca.pem", 1) != 0)
    fail("could not set SSL_CERT_FILE");
  loader.fallback_result= 1;
  require(proxysql_ssl_load_verify_locations(NULL, NULL, files,
                                             directories, &ops) == 1,
          "SSL_CERT_FILE default-path call did not preserve success");
  require(loader.call_count == 0 && loader.fallback_calls == 1,
          "SSL_CERT_FILE was replaced by a platform candidate");

  memset(&loader, 0, sizeof(loader));
  ops= fake_ops(&loader);
  require(proxysql_ssl_load_verify_locations(NULL, NULL, files,
                                             directories, &ops) == 0,
          "SSL_CERT_FILE default-path failure was hidden");
  require(loader.call_count == 0 && loader.fallback_calls == 1,
          "SSL_CERT_FILE failure tried a platform candidate");

  clear_environment();
  if (setenv("SSL_CERT_DIR", "/operator/environment-hash-dir", 1) != 0)
    fail("could not set SSL_CERT_DIR");
  memset(&loader, 0, sizeof(loader));
  ops= fake_ops(&loader);
  loader.fallback_result= 1;
  require(proxysql_ssl_load_verify_locations(NULL, NULL, files,
                                             directories, &ops) == 1,
          "SSL_CERT_DIR default-path call did not preserve success");
  require(loader.call_count == 0 && loader.fallback_calls == 1,
          "SSL_CERT_DIR was replaced by a platform candidate");
  clear_environment();
}

static void test_platform_file_resolution(const char *fixture_root)
{
  char missing[PATH_BUFFER_SIZE];
  char rejected[PATH_BUFFER_SIZE];
  char selected[PATH_BUFFER_SIZE];
  char hash_directory[PATH_BUFFER_SIZE];
  char hash_file[PATH_BUFFER_SIZE];
  const char *files[4];
  const char *directories[2];
  struct fake_loader loader= { 0 };
  struct proxysql_ssl_verify_ops ops= fake_ops(&loader);

  join_path(missing, sizeof(missing), fixture_root, "missing.pem");
  join_path(rejected, sizeof(rejected), fixture_root, "rejected.pem");
  join_path(selected, sizeof(selected), fixture_root, "selected.pem");
  join_path(hash_directory, sizeof(hash_directory), fixture_root, "unused-hashes");
  join_path(hash_file, sizeof(hash_file), hash_directory, "0123abcd.0");
  make_file(rejected);
  make_file(selected);
  make_directory(hash_directory);
  make_file(hash_file);
  files[0]= missing;
  files[1]= rejected;
  files[2]= selected;
  files[3]= NULL;
  directories[0]= hash_directory;
  directories[1]= NULL;
  loader.success_path= selected;

  clear_environment();
  require(proxysql_ssl_load_verify_locations(NULL, NULL, files,
                                             directories, &ops) == 1,
          "readable platform CA file was not selected");
  require(loader.call_count == 2 &&
          strcmp(loader.calls[0], rejected) == 0 &&
          strcmp(loader.calls[1], selected) == 0,
          "platform CA files were not attempted in order");
  require(loader.clear_error_calls == 1,
          "failed platform CA load left an error for the next candidate");
  require(loader.fallback_calls == 0,
          "successful platform CA file reached compiled defaults");

  memset(&loader, 0, sizeof(loader));
  ops= fake_ops(&loader);
  loader.success_path= selected;
  loader.mark_result= 1;
  require(proxysql_ssl_load_verify_locations(NULL, NULL, files,
                                             directories, &ops) == 1,
          "marked platform CA resolution did not succeed");
  require(loader.mark_calls == 2 && loader.pop_to_mark_calls == 1 &&
          loader.clear_last_mark_calls == 1 &&
          loader.clear_error_calls == 0,
          "platform probing did not preserve the pre-existing error queue");
}

static void test_hashed_directory_resolution(const char *fixture_root)
{
  char empty_directory[PATH_BUFFER_SIZE];
  char invalid_hash_directory[PATH_BUFFER_SIZE];
  char invalid_hash_entry[PATH_BUFFER_SIZE];
  char hash_directory[PATH_BUFFER_SIZE];
  char non_hash_file[PATH_BUFFER_SIZE];
  char hash_file[PATH_BUFFER_SIZE];
  const char *files[]= { NULL };
  const char *directories[4];
  struct fake_loader loader= { 0 };
  struct proxysql_ssl_verify_ops ops= fake_ops(&loader);

  join_path(empty_directory, sizeof(empty_directory), fixture_root, "empty-dir");
  join_path(invalid_hash_directory, sizeof(invalid_hash_directory), fixture_root,
            "invalid-hash-dir");
  join_path(invalid_hash_entry, sizeof(invalid_hash_entry), invalid_hash_directory,
            "cafebabe.0");
  join_path(hash_directory, sizeof(hash_directory), fixture_root, "hash-dir");
  join_path(non_hash_file, sizeof(non_hash_file), hash_directory, "certificate.pem");
  join_path(hash_file, sizeof(hash_file), hash_directory, "deadbeef.12");
  make_directory(empty_directory);
  make_directory(invalid_hash_directory);
  make_directory(invalid_hash_entry);
  make_directory(hash_directory);
  make_file(non_hash_file);
  make_file(hash_file);
  directories[0]= empty_directory;
  directories[1]= invalid_hash_directory;
  directories[2]= hash_directory;
  directories[3]= NULL;
  loader.success_path= hash_directory;

  clear_environment();
  require(proxysql_ssl_load_verify_locations(NULL, NULL, files,
                                             directories, &ops) == 1,
          "usable hashed CA directory was not selected");
  require(loader.call_count == 1 &&
          strcmp(loader.calls[0], hash_directory) == 0,
          "empty or non-hashed directory was passed to OpenSSL");
  require(loader.fallback_calls == 0,
          "successful hashed CA directory reached compiled defaults");
}

static void test_safe_fallback(const char *fixture_root)
{
  char missing_file[PATH_BUFFER_SIZE];
  char empty_directory[PATH_BUFFER_SIZE];
  const char *files[2];
  const char *directories[2];
  struct fake_loader loader= { 0 };
  struct proxysql_ssl_verify_ops ops= fake_ops(&loader);

  join_path(missing_file, sizeof(missing_file), fixture_root, "fallback-missing.pem");
  join_path(empty_directory, sizeof(empty_directory), fixture_root, "fallback-empty");
  make_directory(empty_directory);
  files[0]= missing_file;
  files[1]= NULL;
  directories[0]= empty_directory;
  directories[1]= NULL;

  clear_environment();
  loader.fallback_result= 1;
  require(proxysql_ssl_load_verify_locations(NULL, NULL, files,
                                             directories, &ops) == 1,
          "compiled-default success was not preserved");
  require(loader.call_count == 0 && loader.fallback_calls == 1,
          "absent platform paths did not use exactly one compiled fallback");

  memset(&loader, 0, sizeof(loader));
  ops= fake_ops(&loader);
  require(proxysql_ssl_load_verify_locations(NULL, NULL, files,
                                             directories, &ops) == 0,
          "compiled-default failure was hidden");
  require(loader.call_count == 0 && loader.fallback_calls == 1,
          "compiled-default failure caused another load attempt");
}

int main(int argc, char **argv)
{
  const char *fixture_root;

  if (argc != 2)
    fail("usage: mariadb-default-trust-store FIXTURE_ROOT");
  fixture_root= argv[1];

  test_candidate_literals();
  test_explicit_connector_priority(fixture_root);
  test_environment_priority(fixture_root);
  test_platform_file_resolution(fixture_root);
  test_hashed_directory_resolution(fixture_root);
  test_safe_fallback(fixture_root);

  clear_environment();
  printf("MariaDB default trust-store resolver tests passed\n");
  return EXIT_SUCCESS;
}
