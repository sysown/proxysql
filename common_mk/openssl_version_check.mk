REQUIRED_OPENSSL_VERSION := 3.0.0

$(info OPENSSL_PACKAGE: $(OPENSSL_PACKAGE))

check_openssl_version:
ifeq ($(UNAME_S),Darwin)
	@if [ -n "$(CUSTOM_OPENSSL_PATH)" ]; then \
		header_path="$(CUSTOM_OPENSSL_PATH)/include/openssl/opensslv.h"; \
		if [ ! -f "$$header_path" ]; then \
			echo "OpenSSL header file not found at $$header_path"; \
			exit 1; \
		fi; \
		version_number=$$(grep "# *define OPENSSL_VERSION_STR" $$header_path | sed -E 's/.*"([^"]+)".*/\1/'); \
		if [ -z "$$version_number" ]; then \
			echo "Failed to extract OPENSSL_VERSION_STR from $$header_path"; \
			exit 1; \
		fi; \
		major=$$(echo $$version_number | cut -d'.' -f1); \
		minor=$$(echo $$version_number | cut -d'.' -f2); \
		patch=$$(echo $$version_number | cut -d'.' -f3); \
		if [ $$major -gt 3 ] || { [ $$major -eq 3 ] && { [ $$minor -gt 0 ] || { [ $$minor -eq 0 ] && [ $$patch -ge 0 ]; }; }; }; then \
			: ; \
		else \
			echo "OpenSSL version must be >= $(REQUIRED_OPENSSL_VERSION). Detected: $$major.$$minor.$$patch"; \
			exit 1; \
		fi; \
	else \
		openssl_version=$$(pkg-config --modversion $(OPENSSL_PACKAGE) 2>/dev/null); \
		if [ -z "$$openssl_version" ]; then \
			echo "OpenSSL not found via pkg-config."; \
			exit 1; \
		fi; \
		major=$$(echo $$openssl_version | cut -d'.' -f1); \
		minor=$$(echo $$openssl_version | cut -d'.' -f2); \
		patch=$$(echo $$openssl_version | cut -d'.' -f3); \
		if [ $$major -gt 3 ] || { [ $$major -eq 3 ] && { [ $$minor -gt 0 ] || { [ $$minor -eq 0 ] && [ $$patch -ge 0 ]; }; }; }; then \
			: ; \
		else \
			echo "OpenSSL version must be >= $(REQUIRED_OPENSSL_VERSION). Detected: $$openssl_version"; \
			exit 1; \
		fi; \
	fi
else
	@echo "Checking OpenSSL version..."
	@if [ -n "$(CUSTOM_OPENSSL_PATH)" ]; then \
		echo "Using custom OpenSSL path: $(CUSTOM_OPENSSL_PATH)"; \
		header_path="$(CUSTOM_OPENSSL_PATH)/include/openssl/opensslv.h"; \
		if [ ! -f "$$header_path" ]; then \
			echo "OpenSSL header file not found at $$header_path"; \
			exit 1; \
		fi; \
		version_number=$$(grep "# *define OPENSSL_VERSION_STR" $$header_path | sed -E 's/.*"([^"]+)".*/\1/'); \
		if [ -z "$$version_number" ]; then \
			echo "Failed to extract OPENSSL_VERSION_STR from $$header_path"; \
			exit 1; \
		fi; \
		major=$$(echo $$version_number | cut -d'.' -f1); \
		minor=$$(echo $$version_number | cut -d'.' -f2); \
		patch=$$(echo $$version_number | cut -d'.' -f3); \
		echo "Detected OpenSSL version from header: $$major.$$minor.$$patch"; \
		required_major=3; \
		required_minor=0; \
		required_patch=0; \
		if [ $$major -gt $$required_major ] || { [ $$major -eq $$required_major ] && { [ $$minor -gt $$required_minor ] || { [ $$minor -eq $$required_minor ] && [ $$patch -ge $$required_patch ]; }; }; }; then \
			echo "OpenSSL version is valid."; \
		else \
			echo "OpenSSL version must be >= $(REQUIRED_OPENSSL_VERSION). Detected: $$major.$$minor.$$patch"; \
			exit 1; \
		fi; \
	else \
		echo "Using pkg-config to detect OpenSSL"; \
		openssl_version=$$(pkg-config --modversion $(OPENSSL_PACKAGE) 2>/dev/null); \
		if [ -z "$$openssl_version" ]; then \
			echo "OpenSSL not found via pkg-config."; \
			exit 1; \
		fi; \
		echo "Detected OpenSSL version from pkg-config: $$openssl_version"; \
		if [ "$$(printf '%s\n' "$(REQUIRED_OPENSSL_VERSION)" "$$openssl_version" | sort -V | head -n1)" != "$(REQUIRED_OPENSSL_VERSION)" ]; then \
			echo "OpenSSL version must be >= $(REQUIRED_OPENSSL_VERSION). Detected: $$openssl_version"; \
			exit 1; \
		fi; \
	fi
endif