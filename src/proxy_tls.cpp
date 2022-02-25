#include "proxysql.h"
#include "cpp.h"

#include <openssl/x509v3.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>

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

inline char * load_file(const std::string& filename) {
	return load_file(filename.c_str());
}


// absolute path of ssl files
static std::string ssl_key_fp;
static std::string ssl_cert_fp;
static std::string ssl_ca_fp;

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

void write_x509(const std::string& filename, X509 *x) {
	BIO * x509file = NULL;
	x509file = BIO_new_file(filename.c_str(), "w" );
	if (!x509file ) {
		proxy_error("Error on BIO_new_file\n");
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}
	if (!PEM_write_bio_X509( x509file, x)) {
		proxy_error("Error on PEM_write_bio_X509 for %s\n", filename.c_str());
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}
	BIO_free_all( x509file );
}

void write_rsa_key(const std::string& filename, EVP_PKEY* pkey) {
	BIO* pOut = BIO_new_file(filename.c_str(), "w");
	if (!pOut) {
		proxy_error("Error on BIO_new_file\n");
		exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
	}
	if (!PEM_write_bio_PrivateKey(pOut, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
		proxy_error("Error during PEM_write_bio_PrivateKey for %s\n", filename.c_str());
		exit(EXIT_SUCCESS);
	}

	BIO_free_all( pOut );
}


EVP_PKEY * proxy_key_read(const std::string& filename, bool bootstrap, std::string& msg) {
	EVP_PKEY * pkey = NULL;

	BIO * pIn = BIO_new_file(filename.c_str(),"r");
	if (!pIn) {
		proxy_error("Error on BIO_new_file() while reading %s\n", filename.c_str());
		if (bootstrap == true) {
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		} else {
			msg = "Error on BIO_new_file() while reading " + filename;
			return pkey;
		}
	}
	pkey = PEM_read_bio_PrivateKey( pIn , NULL, NULL,  NULL);

	if (pkey == NULL) {
		proxy_error("Error on PEM_read_bio_PrivateKey for %s\n", filename.c_str());
		if (bootstrap == true) {
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		} else {
			msg = "Error on PEM_read_bio_PrivateKey() for " + filename;
			BIO_free(pIn);
			return pkey;
		}
	}
	BIO_free(pIn);
	return pkey;
}

X509 * proxy_read_x509(const std::string& filename, bool bootstrap, std::string& msg) {
	X509 * x = NULL;
	BIO * x509file = NULL;
	x509file = BIO_new_file(filename.c_str(), "r" );
	if (!x509file ) {
		proxy_error("Error on BIO_new_file() while reading %s\n", filename.c_str());
		if (bootstrap == true) {
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		} else {
			msg = "Error on BIO_new_file() while reading " + filename;
			return x;
		}
	}
	x = PEM_read_bio_X509( x509file, NULL, NULL, NULL);
	if (x == NULL) {
		proxy_error("Error on PEM_read_bio_X509 for %s\n", filename.c_str());
		if (bootstrap == true) {
			exit(EXIT_SUCCESS); // we exit gracefully to avoid being restarted
		} else {
			msg = "Error on PEM_read_bio_X509() for " + filename;
			BIO_free_all(x509file);
			return x;
		}
	}
	BIO_free_all( x509file );
	return x;
}

// return 0 un success
int ssl_mkit(X509 **x509ca, X509 **x509p, EVP_PKEY **pkeyp, unsigned int bits, int serial, int days, bool bootstrap, std::string& msg) {
	X509 *x1 = nullptr;
	X509 *x2 = nullptr;
	EVP_PKEY *pk = nullptr;

	assert(x509ca && x509p && pkeyp); // No null pointer paramters allowed.	These are dereferenced later

	// relative path to datadir of ssl files
	const char * ssl_key_rp = "proxysql-key.pem";
	const char * ssl_cert_rp = "proxysql-cert.pem";
	const char * ssl_ca_rp = "proxysql-ca.pem";

	uint16_t ssl_file_count = 0;

	// Until proven
	bool ssl_key_present = false;
	bool ssl_cert_present = false;
	bool ssl_ca_present = false;
	// Construct filepaths
	if (bootstrap == true) {
		ssl_key_fp = std::string(GloVars.datadir) + ssl_key_rp;
		ssl_cert_fp = std::string(GloVars.datadir) + ssl_cert_rp;
		ssl_ca_fp = std::string(GloVars.datadir) + ssl_ca_rp;
	}
	// check if files are present
	if (access(ssl_key_fp.c_str(), R_OK) == 0) {
		ssl_key_present = true;
		ssl_file_count++;
	}
	if (access(ssl_cert_fp.c_str(), R_OK) == 0) {
		ssl_cert_present = true;
		ssl_file_count++;
	}
	if (access(ssl_ca_fp.c_str(), R_OK) == 0) {
		ssl_ca_present = true;
		ssl_file_count++;
	}

	if (
		(bootstrap == true && (ssl_file_count != 0 && ssl_file_count != 3))
		||
		(bootstrap == false && (ssl_file_count != 3))
	) {
		if (bootstrap == true) {
			proxy_error("Only some SSL files are present. Either all files are present, or none. Exiting.\n");
		} else {
			proxy_error("Aborting PROXYSQL RELOAD TLS because not all SSL files are present\n");
		}
		proxy_error("%s : %s\n" , ssl_key_rp, (ssl_key_present ? (char *)"YES" : (char *)"NO"));
		proxy_error("%s : %s\n" , ssl_cert_rp, (ssl_cert_present ? (char *)"YES" : (char *)"NO"));
		proxy_error("%s : %s\n" , ssl_ca_rp, (ssl_ca_present ? (char *)"YES" : (char *)"NO"));

		if (bootstrap == true) {
			exit(EXIT_SUCCESS); 
		} else {
			msg = "RELOAD TLS failed: " + std::to_string(ssl_file_count) + " TLS files are present. Expected: 3";
			return 1;
		}
	}

	if (bootstrap == true && ssl_file_count == 0) {
		proxy_info("No SSL keys/certificates found in datadir (%s). Generating new keys/certificates.\n", GloVars.datadir);

		if (*pkeyp != nullptr) {
			EVP_PKEY_free(*pkeyp);
			*pkeyp = nullptr;
		}
		/* @note: Based off of OpenSSL3.0 manual implementation details here: https://www.openssl.org/docs/man3.0/man7/EVP_PKEY-RSA.html */
		OSSL_PARAM params[3];
		unsigned int primes = 2;
		EVP_PKEY_CTX* pk_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);

		if (!pk_ctx) {
			proxy_error("Could not initialize RSA PKEY Context:  EVP_PKEY_CTX_new_from_name() for 'RSA'\n");
			exit(EXIT_SUCCESS);
		}

		int rc = EVP_PKEY_keygen_init(pk_ctx);

		if (rc != 1) {
			proxy_error("Could not initialize RSA Keygen: EVP_PKEY_keygen_init()\n");
			exit(EXIT_SUCCESS);
		}

		params[0] = OSSL_PARAM_construct_uint("bits", &bits);
		params[1] = OSSL_PARAM_construct_uint("primes", &primes);
		params[2] = OSSL_PARAM_construct_end();
		rc = EVP_PKEY_CTX_set_params(pk_ctx, params);

		if (rc != 1) {
			proxy_error("Could not set Keygen Parameters: EVP_PKEY_CTX_set_params()\n");
			exit(EXIT_SUCCESS);
		}

		rc = EVP_PKEY_generate(pk_ctx, &pk);

		if (rc != 1) {
			proxy_error("Could not generate key: EVP_PKEY_generate()\n");
			exit(EXIT_SUCCESS);
		}
		EVP_PKEY_CTX_free(pk_ctx);

		write_rsa_key(ssl_key_fp, pk);

		time_t t = time(NULL);
		x1 = generate_x509(pk, (const unsigned char *)"ProxySQL_Auto_Generated_CA_Certificate", t, 3650, NULL, NULL);
		write_x509(ssl_ca_fp, x1);
		x2 = generate_x509(pk, (const unsigned char *)"ProxySQL_Auto_Generated_Server_Certificate", t, 3650, x1, pk);
		write_x509(ssl_cert_fp, x2);
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
		if (!SSL_CTX_load_verify_locations(GloVars.global.ssl_ctx, ssl_ca_fp.c_str(), ssl_ca_fp.c_str())) {
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
							if (SSL_CTX_load_verify_locations(GloVars.global.tmp_ssl_ctx, ssl_ca_fp.c_str(), ssl_ca_fp.c_str()) == 1) { // 1 on success

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

