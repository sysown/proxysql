//#include <iostream>
//#include <thread>
#include "proxysql.h"

//#include <sys/types.h>
//#include <sys/stat.h>

#include "cpp.h"

//#include "ProxySQL_Statistics.hpp"
//#include "MySQL_PreparedStatement.h"
//#include "ProxySQL_Cluster.hpp"
//#include "MySQL_Logger.hpp"
//#include "SQLite3_Server.h"
//#include "query_processor.h"
//#include "MySQL_Authentication.hpp"
//#include "MySQL_LDAP_Authentication.hpp"
//#include "proxysql_restapi.h"
//#include "Web_Interface.hpp"



#include <openssl/x509v3.h>

static long
get_file_size (const char *filename) {
	FILE *fp;
	fp = fopen (filename, "rb");
	if (fp) {
		long size;
		if ((0 != fseek (fp, 0, SEEK_END)) || (-1 == (size = ftell (fp))))
			size = 0;
		fclose (fp);
		return size;
	} else
		return 0;
}

static char * load_file (const char *filename) {
	FILE *fp;
	char *buffer;
	long size;
	size = get_file_size (filename);
	if (0 == size)
		return NULL;
	fp = fopen (filename, "rb");
	if (! fp)
		return NULL;
	buffer = (char *)malloc (size + 1);
	if (! buffer) {
		fclose (fp);
		return NULL;
	}
	buffer[size] = '\0';
	if (size != (long)fread (buffer, 1, size, fp)) {
		free (buffer);
		buffer = NULL;
	}
	fclose (fp);
	return buffer;
}

// absolute path of ssl files
static char *ssl_key_fp = NULL;
static char *ssl_cert_fp = NULL;
static char *ssl_ca_fp = NULL;

struct dh_st {
	int pad;
	int version;
	BIGNUM *p;
	BIGNUM *g;
	long length;
	BIGNUM *pub_key;
	BIGNUM *priv_key;
	int flags;
	BN_MONT_CTX *method_mont_p;
	BIGNUM *q;
	BIGNUM *j;
	unsigned char *seed;
	int seedlen;
	BIGNUM *counter;
	int references;
	CRYPTO_EX_DATA ex_data;
	const DH_METHOD *meth;
	ENGINE *engine;
	CRYPTO_RWLOCK *lock;
};

int callback_ssl_verify_peer(int ok, X509_STORE_CTX* ctx) {
	// for now only return 1
	return 1;
}

X509 * generate_x509(EVP_PKEY *pkey, const unsigned char *cn, uint32_t serial, int days, X509 *ca_x509, EVP_PKEY *ca_pkey) {
	int rc;
	X509 * x = NULL;
	X509_NAME * name= NULL;
	X509_EXTENSION* ext = NULL;
	X509V3_CTX v3_ctx;
	if ((x = X509_new()) == NULL) {
		proxy_error("Unable to run X509_new()\n");
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}
	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * days);
	rc = X509_set_pubkey(x, pkey);
	if (rc==0){
		proxy_error("Unable to set pubkey: %s\n", ERR_error_string(ERR_get_error(),NULL));
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}
	name = X509_get_subject_name(x);

	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0);

	if (ca_x509) {
		rc = X509_set_issuer_name(x, X509_get_subject_name(ca_x509));
	} else {
		rc = X509_set_issuer_name(x, name);
	}
	if (rc==0) {
		proxy_error("Unable to set issuer: %s\n", ERR_error_string(ERR_get_error(),NULL));
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}

	// set the context
	X509V3_set_ctx(&v3_ctx, ca_x509 ? ca_x509 : x, x, NULL, NULL, 0);

	ext = X509V3_EXT_conf_nid(
		NULL, &v3_ctx, NID_basic_constraints, ca_x509 ? "critical, CA:FALSE" : "critical, CA:TRUE");
	if (ext) {
		X509_add_ext(x, ext, -1);
		X509_EXTENSION_free(ext);
	} else {
		proxy_error("Unable to set certificate extensions: %s\n", ERR_error_string(ERR_get_error(),NULL));
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}

	if (ca_pkey) {
		rc = X509_sign(x, ca_pkey, EVP_sha256());
	} else {
		rc = X509_sign(x, pkey, EVP_sha256());
	}
	if (rc==0) {
		proxy_error("Unable to X509 sign: %s\n", ERR_error_string(ERR_get_error(),NULL));
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}
	return x;
}

void write_x509(const char *filen, X509 *x) {
	BIO * x509file = NULL;
	x509file = BIO_new_file(filen, "w" );
	if (!x509file ) {
		proxy_error("Error on BIO_new_file\n");
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}
	if (!PEM_write_bio_X509( x509file, x)) {
		proxy_error("Error on PEM_write_bio_X509 for %s\n", filen);
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}
	BIO_free_all( x509file );
}

void write_rsa_key(const char *filen, RSA *rsa) {
	BIO* pOut = BIO_new_file(filen, "w");
	if (!pOut) {
		proxy_error("Error on BIO_new_file\n");
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}
	if (!PEM_write_bio_RSAPrivateKey( pOut, rsa, NULL, NULL, 0, NULL, NULL)) {
		proxy_error("Error on PEM_write_bio_RSAPrivateKey for %s\n", filen);
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}
	BIO_free_all( pOut );
}


EVP_PKEY * proxy_key_read(const char *filen, bool bootstrap, std::string& msg) {
	EVP_PKEY * pkey = NULL;

	BIO * pIn = BIO_new_file(filen,"r");
	if (!pIn) {
		proxy_error("Error on BIO_new_file() while reading %s\n", filen);
		if (bootstrap == true) {
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		} else {
			msg = "Error on BIO_new_file() while reading " + std::string(filen);
			return pkey;
		}
	}
	pkey = PEM_read_bio_PrivateKey( pIn , NULL, NULL,  NULL);
	if (pkey == NULL) {
		proxy_error("Error on PEM_read_bio_PrivateKey for %s\n", filen);
		if (bootstrap == true) {
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		} else {
			msg = "Error on PEM_read_bio_PrivateKey() for " + std::string(filen);
			BIO_free(pIn);
			return pkey;
		}
	}
	BIO_free(pIn);
	return pkey;
}

X509 * proxy_read_x509(const char *filen, bool bootstrap, std::string& msg) {
	X509 * x = NULL;
	BIO * x509file = NULL;
	x509file = BIO_new_file(filen, "r" );
	if (!x509file ) {
		proxy_error("Error on BIO_new_file() while reading %s\n", filen);
		if (bootstrap == true) {
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		} else {
			msg = "Error on BIO_new_file() while reading " + std::string(filen);
			return x;
		}
	}
	x = PEM_read_bio_X509( x509file, NULL, NULL, NULL);
	if (x == NULL) {
		proxy_error("Error on PEM_read_bio_X509 for %s\n", filen);
		if (bootstrap == true) {
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		} else {
			msg = "Error on PEM_read_bio_X509() for " + std::string(filen);
			BIO_free_all(x509file);
			return x;
		}
	}
	BIO_free_all( x509file );
	return x;
}

// return 0 un success
int ssl_mkit(X509 **x509ca, X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days, bool bootstrap, std::string& msg) {
	X509 *x1;
	X509 *x2;
	EVP_PKEY *pk;
	RSA *rsa;

	// relative path to datadir of ssl files
	const char * ssl_key_rp = (const char *)"proxysql-key.pem";
	const char * ssl_cert_rp = (const char *)"proxysql-cert.pem";
	const char * ssl_ca_rp = (const char *)"proxysql-ca.pem";

	// how many files exists ?
	int nfiles = 0;
	bool ssl_key_exists = true;
	bool ssl_cert_exists = true;
	bool ssl_ca_exists = true;

	// check if files exists
	if (bootstrap == true) {
		ssl_key_fp = (char *)malloc(strlen(GloVars.datadir)+strlen(ssl_key_rp)+8);
		sprintf(ssl_key_fp,"%s/%s",GloVars.datadir,ssl_key_rp);
	}
	if (access(ssl_key_fp, R_OK)) {
		ssl_key_exists = false;
	}

	if (bootstrap == true) {
		ssl_cert_fp = (char *)malloc(strlen(GloVars.datadir)+strlen(ssl_cert_rp)+8);
		sprintf(ssl_cert_fp,"%s/%s",GloVars.datadir,ssl_cert_rp);
	}
	if (access(ssl_cert_fp, R_OK)) {
		ssl_cert_exists = false;
	}

	if (bootstrap == true) {
		ssl_ca_fp = (char *)malloc(strlen(GloVars.datadir)+strlen(ssl_ca_rp)+8);
		sprintf(ssl_ca_fp,"%s/%s",GloVars.datadir,ssl_ca_rp);
	}
	if (access(ssl_ca_fp, R_OK)) {
		ssl_ca_exists = false;
	}

	nfiles += (ssl_key_exists ? 1 : 0);
	nfiles += (ssl_cert_exists ? 1 : 0);
	nfiles += (ssl_ca_exists ? 1 : 0);

	if (
		(bootstrap == true && (nfiles != 0 && nfiles != 3))
		||
		(bootstrap == false && (nfiles != 3))
	) {
		if (bootstrap == true) {
			proxy_error("Only some SSL files are present. Either all files are present, or none. Exiting.\n");
		} else {
			proxy_error("Aborting PROXYSQL RELOAD TLS because not all SSL files are present\n");
		}
		proxy_error("%s : %s\n" , ssl_key_rp, (ssl_key_exists ? (char *)"YES" : (char *)"NO"));
		proxy_error("%s : %s\n" , ssl_cert_rp, (ssl_cert_exists ? (char *)"YES" : (char *)"NO"));
		proxy_error("%s : %s\n" , ssl_ca_rp, (ssl_ca_exists ? (char *)"YES" : (char *)"NO"));

		if (bootstrap == true) {
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		} else {
			msg = "RELOAD TLS failed: " + std::to_string(nfiles) + " TLS files are present. Expected: 3";
			return 1;
		}
	}

	if (bootstrap == true && nfiles == 0) {
		proxy_info("No SSL keys/certificates found in datadir (%s). Generating new keys/certificates.\n", GloVars.datadir);
		if ((pkeyp == NULL) || (*pkeyp == NULL)) {
			if ((pk = EVP_PKEY_new()) == NULL) {
				proxy_error("Unable to run EVP_PKEY_new()\n");
				exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
			}
		} else
			pk = *pkeyp;

		rsa = RSA_new();

		if (!rsa) {
			proxy_error("Unable to run RSA_new()\n");
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		}
		BIGNUM *e= BN_new();
		if (!e) {
			proxy_error("Unable to run BN_new()\n");
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		}
		if (!BN_set_word(e, RSA_F4) || !RSA_generate_key_ex(rsa, bits, e, NULL)) {
			RSA_free(rsa);
			BN_free(e);
			proxy_error("Unable to run BN_new()\n");
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		}
		BN_free(e);


		write_rsa_key(ssl_key_fp, rsa);

		if (!EVP_PKEY_assign_RSA(pk, rsa)) {
			proxy_error("Unable to run EVP_PKEY_assign_RSA()\n");
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		}
		time_t t = time(NULL);
		x1 = generate_x509(pk, (const unsigned char *)"ProxySQL_Auto_Generated_CA_Certificate", t, 3650, NULL, NULL);
		write_x509(ssl_ca_fp, x1);
		x2 = generate_x509(pk, (const unsigned char *)"ProxySQL_Auto_Generated_Server_Certificate", t, 3650, x1, pk);
		write_x509(ssl_cert_fp, x2);

		rsa = NULL;
	} else {
		proxy_info("SSL keys/certificates found in datadir (%s): loading them.\n", GloVars.datadir);
		if (bootstrap == true) {
			// during bootstrap we just call the reads
			// if the read fails during bootstrap, proxysql immediately exists
			pk = proxy_key_read(ssl_key_fp, bootstrap, msg);
			x1 = proxy_read_x509(ssl_ca_fp, bootstrap, msg);
			x2 = proxy_read_x509(ssl_cert_fp, bootstrap, msg);
		} else {
			pk = proxy_key_read(ssl_key_fp, bootstrap, msg);
			if (pk) {
				x1 = proxy_read_x509(ssl_ca_fp, bootstrap, msg);
				if (x1) {
					x2 = proxy_read_x509(ssl_cert_fp, bootstrap, msg);
				}
			}
			// note that this is only relevant during PROXYSQL RELOAD TLS
			if (pk == NULL || x1 == NULL || x2 == NULL) {
				return 1;
			}
		}
	}
	*x509ca = x1;
	*x509p = x2;
	*pkeyp = pk;

	if (bootstrap == true) {
		if (SSL_CTX_set_dh_auto(GloVars.global.ssl_ctx, 1) == 0) {
			proxy_error("Error in SSL while initializing DH: %s . Shutting down.\n",ERR_error_string(ERR_get_error(), NULL));
			exit(EXIT_SUCCESS); // EXIT_SUCCESS to avoid a restart loop
		}
	} else {
		SSL_METHOD *ssl_method;
		ssl_method = (SSL_METHOD *)TLS_server_method();
		GloVars.global.tmp_ssl_ctx = SSL_CTX_new(ssl_method);

		if (SSL_CTX_set_dh_auto(GloVars.global.ssl_ctx, 1) == 0) {
			proxy_error("Error in SSL while initializing DH: %s . Shutting down.\n",ERR_error_string(ERR_get_error(), NULL));
			proxy_error("Aborting PROXYSQL RELOAD TLS. Error in SSL while initializing DH: %s\n",ERR_error_string(ERR_get_error(), NULL));
			msg = "RELOAD TLS failed: Error initializing DH. ";
			msg += ERR_error_string(ERR_get_error(), NULL);
			return 1;
		}
	}

	return 0;
}

int ProxySQL_create_or_load_TLS(bool bootstrap, std::string& msg) {
	BIO *bio_err;
	X509 *x509 = NULL;
	X509 *x509ca = NULL;
	EVP_PKEY *pkey = NULL;

	int ret = 0;

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	if (bootstrap == true) {
		// this is legacy code, when keys are loaded only during bootstrap
		if (ssl_mkit(&x509ca, &x509, &pkey, 2048, 0, 730, true, msg) != 0) {
			proxy_error("Unable to initialize SSL. Shutting down...\n");
			exit(EXIT_SUCCESS); // we exit gracefully to not be restarted
		}

		if ( SSL_CTX_use_certificate(GloVars.global.ssl_ctx, x509) <= 0 ) {
			ERR_print_errors_fp(stderr);
			proxy_error("Unable to use SSL certificate. Shutting down...\n");
			exit(EXIT_SUCCESS); // we exit gracefully to not be restarted
		}
		if ( SSL_CTX_add_extra_chain_cert(GloVars.global.ssl_ctx, x509ca) <= 0 ) {
			ERR_print_errors_fp(stderr);
			proxy_error("Unable to use SSL CA chain. Shutting down...\n");
			exit(EXIT_SUCCESS); // we exit gracefully to not be restarted
		}
		if ( SSL_CTX_use_PrivateKey(GloVars.global.ssl_ctx, pkey) <= 0 ) {
			ERR_print_errors_fp(stderr);
			proxy_error("Unable to use SSL key. Shutting down...\n");
			exit(EXIT_SUCCESS); // we exit gracefully to not be restarted
		}
		if ( !SSL_CTX_check_private_key(GloVars.global.ssl_ctx) ) {
			proxy_error("Private key does not match the public certificate\n");
			exit(EXIT_SUCCESS); // we exit gracefully to not be restarted
		}
		GloVars.global.ssl_key_pem_mem = load_file(ssl_key_fp);
        GloVars.global.ssl_cert_pem_mem = load_file(ssl_cert_fp);

		// We set the locations for the certificates to be used for
		// verifications purposes.
		if (!SSL_CTX_load_verify_locations(GloVars.global.ssl_ctx, ssl_ca_fp, ssl_ca_fp)) {
			proxy_error("Unable to load CA certificates location for verification. Shutting down\n");
			exit(EXIT_SUCCESS); // we exit gracefully to not be restarted
		}
	} else {
		// here we use global.tmp_ssl_ctx instead of global.ssl_ctx
		// because we will try to swap at the end
		if (ssl_mkit(&x509ca, &x509, &pkey, 2048, 0, 730, false, msg) == 0) { // 0 on success
			if (SSL_CTX_use_certificate(GloVars.global.tmp_ssl_ctx, x509) == 1) { // 1 on success
				if (SSL_CTX_add_extra_chain_cert(GloVars.global.tmp_ssl_ctx, x509ca) == 1) { // 1 on success
					if (SSL_CTX_use_PrivateKey(GloVars.global.tmp_ssl_ctx, pkey) == 1) { // 1 on success
						if (SSL_CTX_check_private_key(GloVars.global.tmp_ssl_ctx) == 1) { // 1 on success
							if (SSL_CTX_load_verify_locations(GloVars.global.tmp_ssl_ctx, ssl_ca_fp, ssl_ca_fp) == 1) { // 1 on success

							// take the mutex
							std::lock_guard<std::mutex> lock(GloVars.global.ssl_mutex);
							// note: we don't free the current SSL context, perhaps used by some connections
							// swap the SSL context
							GloVars.global.ssl_ctx = GloVars.global.tmp_ssl_ctx;
							GloVars.global.tmp_ssl_ctx = NULL;
							free(GloVars.global.ssl_key_pem_mem);
							free(GloVars.global.ssl_cert_pem_mem);
							GloVars.global.ssl_key_pem_mem = load_file(ssl_key_fp);
        					GloVars.global.ssl_cert_pem_mem = load_file(ssl_cert_fp);

							} else {
								proxy_error("Failed to load location of CA certificates for verification\n");
								msg = "Unable to load CA certificates location for verification";
								ret = 1;
							}
						} else {
							proxy_error("Private key does not match the public certificate\n");
							msg = "Private key does not match the public certificate";
							ret = 1;
						}
					} else {
						ERR_print_errors_fp(stderr);
						proxy_error("Unable to use SSL key\n");
						msg = "Unable to use SSL key";
						ret = 1;
					}
				} else {
					ERR_print_errors_fp(stderr);
					proxy_error("Unable to use SSL CA chain\n");
					msg = "Unable to use SSL CA chain";
					ret = 1;
				}
			} else {
				ERR_print_errors_fp(stderr);
				proxy_error("Unable to use SSL certificate\n");
				msg = "Unable to use SSL certificate";
				ret = 1;
			}
		} else {
			proxy_error("Unable to initialize SSL\n");
			if (msg.length() == 0) {
				msg = "Unable to initialize SSL";
			}
			ret = 1;
		}
	}
	if (ret == 0) {
		SSL_CTX_set_verify(GloVars.global.ssl_ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, callback_ssl_verify_peer);
	}
	X509_free(x509);
	EVP_PKEY_free(pkey);


	BIO_free(bio_err);
	return ret;
}

