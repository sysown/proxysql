# v4.0 owns its own source/build directory. The old connector still builds
# through the tracked mariadb_client symlink and its original patch stack.
MARIADB_V40_TREE := $(MARIADB_VENDOR_DIR)/$(MARIADB_V40_SOURCE)
MARIADB_V40_TARBALL := $(MARIADB_V40_TREE).tar.gz
MARIADB_V40_PATCH_DIR := $(MARIADB_VENDOR_DIR)/patches-$(MARIADB_V40_VERSION)
MARIADB_V40_BUILD_RULE := $(MARIADB_VENDOR_DIR)/build-3.4.mk
MARIADB_V40_FLAGS_FILE := $(MARIADB_VENDOR_DIR)/.connector-$(MARIADB_V40_VERSION)-flags

MARIADB_V40_PATCHES :=
ifneq ($(UNAME_S),Darwin)
ifneq ($(filter 1,$(PROXYDEBUG) $(USEVALGRIND)),)
MARIADB_V40_PATCHES += ma_context.h.patch
endif
endif
MARIADB_V40_PATCHES += mariadb_stmt.c.patch mariadb_lib.c.patch \
	mariadb_lib.c.collation.patch mariadb_lib.c.ipv6_fix.patch \
	mariadb_async.c.patch ma_password.c.patch mysql.h.patch tls_server_name.patch \
	ma_priv.h.patch ma_alloc.c.patch ma_charset.c.patch unittest_basic-t.c.patch \
	unittest_charset.c.patch ed25519_visibility.patch \
	mariadb_dyncol.c-multiplication-overflow.patch \
	ma_array.c-multiplication-overflow.patch zutil.c-multiplication-overflow.patch \
	cr_new_stmt_metadata_removal.patch ps_buffer_stmt_read_all_rows.patch \
	mariadb_stmt_store_result_err.patch empty_split_compress_packet.patch \
	sslkeylogfile.patch client_deprecate_eof.patch mariadb_com.h.patch x509cache.patch \
	mariadb_rpl.patch mariadb_rpl_rows.patch mariadb_lib.c.metadata_column_check.patch \
	async_auth_reply_cleanup.patch

MARIADB_V40_CMAKE := -Wno-dev -DCMAKE_BUILD_TYPE=RelWithDebInfo \
	-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_COMPILE_WARNING_AS_ERROR=OFF \
	-DCMAKE_POSITION_INDEPENDENT_CODE=ON -DDEFAULT_CHARSET=latin1 \
	-DDEFAULT_SSL_VERIFY_SERVER_CERT=OFF -DWITH_SSL=OPENSSL \
	-DOPENSSL_ROOT_DIR=$(SSL_PATH) -DOPENSSL_INCLUDE_DIR=$(SSL_IDIR) \
	-DOPENSSL_SSL_LIBRARY=$(LIB_SSL_PATH) -DOPENSSL_CRYPTO_LIBRARY=$(LIB_CRYPTO_PATH) \
	-DCLIENT_PLUGIN_CLIENT_ED25519=STATIC -DCLIENT_PLUGIN_CACHING_SHA2_PASSWORD=STATIC \
	-DCLIENT_PLUGIN_SHA256_PASSWORD=STATIC -DCLIENT_PLUGIN_MYSQL_CLEAR_PASSWORD=STATIC
ifeq ($(UNAME_S),Darwin)
MARIADB_V40_CMAKE += -DICONV_LIBRARIES=$$(brew --prefix libiconv)/lib/libiconv.dylib \
	-DICONV_INCLUDE_DIR=$$(brew --prefix libiconv)/include
endif
ifeq ($(WITHASAN),1)
MARIADB_V40_CMAKE += -DWITH_ASAN=ON -DCMAKE_C_FLAGS="$(CFLAGS) -fno-omit-frame-pointer"
endif
ifeq ($(WITHTSAN),1)
MARIADB_V40_CMAKE += -DCMAKE_C_FLAGS="$(CFLAGS) -fsanitize=thread -fno-omit-frame-pointer" \
	-DCMAKE_CXX_FLAGS="$(CXXFLAGS) -fsanitize=thread -fno-omit-frame-pointer"
endif

MARIADB_V40_BUILD_FLAGS := $(UNAME_S) $(CC) $(CXX) $(CFLAGS) $(CXXFLAGS) $(LDFLAGS) \
	$(MARIADB_V40_CMAKE) $(MARIADB_V40_PATCHES)
export MARIADB_V40_BUILD_FLAGS

.PHONY: force-mariadb-v40-flags
force-mariadb-v40-flags:

$(MARIADB_V40_FLAGS_FILE): force-mariadb-v40-flags
	@printf '%s\n' "$$MARIADB_V40_BUILD_FLAGS" | cmp -s - "$@" || \
		printf '%s\n' "$$MARIADB_V40_BUILD_FLAGS" > "$@"

$(MARIADB_V40_TREE)/libmariadb/libmariadbclient.a: $(OPENSSL_BUILD_STAMP) \
		$(MARIADB_V40_TARBALL) $(MARIADB_V40_TARBALL).sha256 $(MARIADB_V40_FLAGS_FILE) \
		$(MARIADB_V40_BUILD_RULE) $(addprefix $(MARIADB_V40_PATCH_DIR)/,$(MARIADB_V40_PATCHES))
	cd $(MARIADB_VENDOR_DIR) && \
		if command -v sha256sum >/dev/null 2>&1; then \
			sha256sum -c $(notdir $(MARIADB_V40_TARBALL)).sha256; \
		else shasum -a 256 -c $(notdir $(MARIADB_V40_TARBALL)).sha256; fi
	rm -rf $(MARIADB_V40_TREE)
	tar --no-same-owner -xzf $(MARIADB_V40_TARBALL) -C $(MARIADB_VENDOR_DIR)
	@set -e; for name in $(MARIADB_V40_PATCHES); do \
		echo "Applying Connector/C $(MARIADB_V40_VERSION) patch $$name"; \
		patch -f -F0 -p0 -d $(MARIADB_V40_TREE) < $(MARIADB_V40_PATCH_DIR)/$$name; \
	done
	cd $(MARIADB_V40_TREE) && CC="$(CC)" CXX="$(CXX)" cmake . $(MARIADB_V40_CMAKE)
	$(MAKE) -C $(MARIADB_V40_TREE) mariadbclient
	test -f "$@"
