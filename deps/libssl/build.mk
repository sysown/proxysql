# These settings are shared by source compilation and artifact identity.
OPENSSL_CONFIGURE_FLAGS := no-shared no-tests -fPIC
export OPENSSL_CONFIGURE_FLAGS

OPENSSL_BUILD_STAMP := libssl/openssl/.proxysql-build-complete

$(OPENSSL_BUILD_STAMP): libssl/openssl-$(OPENSSL_VERSION).tar.gz \
		libssl/openssl-$(OPENSSL_VERSION).tar.gz.sha256 \
		libssl/verify-source.bash libssl/build.mk
	cd libssl && ./verify-source.bash
	rm -rf libssl/openssl-$(OPENSSL_VERSION)
	cd libssl && tar --no-same-owner -zxf openssl-$(OPENSSL_VERSION).tar.gz
	cd libssl/openssl && CC=$(CC) CXX=$(CXX) ./config $(OPENSSL_CONFIGURE_FLAGS)
	cd libssl/openssl && CC=$(CC) CXX=$(CXX) $(MAKE)
	test -f $(LIB_SSL_PATH)
	test -f $(LIB_CRYPTO_PATH)
	touch $@

.PHONY: dependency-source-openssl
dependency-source-openssl: $(OPENSSL_BUILD_STAMP)
