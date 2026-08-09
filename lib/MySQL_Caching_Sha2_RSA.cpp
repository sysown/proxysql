#include "MySQL_Caching_Sha2_RSA.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace {

constexpr int MINIMUM_RSA_KEY_BITS = 2048;
constexpr size_t MAXIMUM_PEM_FILE_SIZE = 1024 * 1024;

class ScopedFd {
public:
	explicit ScopedFd(int fd = -1) : fd_(fd) {}
	~ScopedFd() { if (fd_ >= 0) close(fd_); }
	ScopedFd(const ScopedFd&) = delete;
	ScopedFd& operator=(const ScopedFd&) = delete;
	ScopedFd(ScopedFd&& other) noexcept : fd_(other.release()) {}
	ScopedFd& operator=(ScopedFd&& other) noexcept {
		if (this != &other) {
			if (fd_ >= 0) close(fd_);
			fd_ = other.release();
		}
		return *this;
	}
	int get() const { return fd_; }
	int release() { const int fd = fd_; fd_ = -1; return fd; }

private:
	int fd_;
};

class ScopedStringCleanser {
public:
	explicit ScopedStringCleanser(std::string& value) : value_(value) {}
	~ScopedStringCleanser() {
		if (!value_.empty()) {
			OPENSSL_cleanse(value_.data(), value_.size());
		}
	}
	ScopedStringCleanser(const ScopedStringCleanser&) = delete;
	ScopedStringCleanser& operator=(const ScopedStringCleanser&) = delete;

private:
	std::string& value_;
};

class ScopedBufferCleanser {
public:
	ScopedBufferCleanser(std::vector<unsigned char>& value, size_t allocation_size)
		: value_(value), allocation_size_(allocation_size) {}
	~ScopedBufferCleanser() {
		if (allocation_size_ > 0) {
			OPENSSL_cleanse(value_.data(), allocation_size_);
		}
	}
	ScopedBufferCleanser(const ScopedBufferCleanser&) = delete;
	ScopedBufferCleanser& operator=(const ScopedBufferCleanser&) = delete;

private:
	std::vector<unsigned char>& value_;
	size_t allocation_size_;
};

std::string errno_message(const std::string& operation, const std::string& path) {
	return operation + " '" + path + "': " + std::strerror(errno);
}

std::string parent_directory(const std::string& path) {
	const std::string::size_type slash = path.rfind('/');
	if (slash == std::string::npos) {
		return ".";
	}
	if (slash == 0) {
		return "/";
	}
	return path.substr(0, slash);
}

struct ResolvedKeyPath {
	std::string display_path;
	std::string leaf;
	ScopedFd parent_fd;
};

int directory_open_flags(bool reject_symlink) {
	int flags = O_RDONLY;
#ifdef O_DIRECTORY
	flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
	flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
	if (reject_symlink) {
		flags |= O_NOFOLLOW;
	}
#endif
	return flags;
}

bool valid_relative_component(const std::string& component) {
	return !component.empty() && component != "." && component != "..";
}

bool resolve_key_path(
	const std::string& path,
	const std::string& datadir,
	ResolvedKeyPath& resolved,
	std::string& error
) {
	if (path.empty()) {
		error = "RSA key path is empty";
		return false;
	}

	if (path.front() == '/') {
		resolved.display_path = path;
		resolved.leaf = path.substr(path.rfind('/') + 1);
		if (resolved.leaf.empty()) {
			error = "RSA key path '" + path + "' does not name a file";
			return false;
		}
		const std::string directory = parent_directory(path);
		resolved.parent_fd = ScopedFd(open(directory.c_str(), directory_open_flags(false)));
		if (resolved.parent_fd.get() < 0) {
			error = errno_message("cannot open key directory", directory);
			return false;
		}
		return true;
	}

	if (datadir.empty()) {
		error = "relative RSA key path '" + path + "' requires a data directory";
		return false;
	}
	resolved.display_path = datadir.back() == '/' ? datadir + path : datadir + "/" + path;
	ScopedFd current(open(datadir.c_str(), directory_open_flags(false)));
	if (current.get() < 0) {
		error = errno_message("cannot open ProxySQL data directory", datadir);
		return false;
	}

	size_t offset = 0;
	while (offset < path.size()) {
		const size_t slash = path.find('/', offset);
		const bool final_component = slash == std::string::npos;
		const std::string component = path.substr(
			offset, final_component ? std::string::npos : slash - offset
		);
		if (!valid_relative_component(component)) {
			error = "relative RSA key path '" + path +
				"' contains an empty, current-directory, or parent-directory component";
			return false;
		}
		if (final_component) {
			resolved.leaf = component;
			resolved.parent_fd = std::move(current);
			return true;
		}

		const int child_fd = openat(
			current.get(), component.c_str(), directory_open_flags(true)
		);
		if (child_fd < 0) {
			error = errno_message(
				"cannot securely open relative key-directory component", component
			);
			return false;
		}
		current = ScopedFd(child_fd);
		offset = slash + 1;
	}

	error = "RSA key path '" + path + "' does not name a file";
	return false;
}

bool fsync_parent_directory(const ResolvedKeyPath& path, std::string& error) {
	if (fsync(path.parent_fd.get()) != 0) {
		error = errno_message("cannot sync key directory for", path.display_path);
		return false;
	}
	return true;
}

bool path_exists(const ResolvedKeyPath& path, bool& exists, std::string& error) {
	struct stat st {};
	if (fstatat(path.parent_fd.get(), path.leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
		exists = true;
		return true;
	}
	if (errno == ENOENT) {
		exists = false;
		return true;
	}
	error = errno_message("cannot inspect key file", path.display_path);
	return false;
}

bool validate_open_file(int fd, const std::string& path, bool private_key, std::string& error) {
	struct stat st {};
	if (fstat(fd, &st) != 0) {
		error = errno_message("cannot inspect opened key file", path);
		return false;
	}
	if (!S_ISREG(st.st_mode)) {
		error = "key file '" + path + "' is not a regular file";
		return false;
	}
	if (private_key && (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
		error = "private key file '" + path + "' must not grant group or other permissions";
		return false;
	}
	return true;
}

bool validate_key_path(const ResolvedKeyPath& path, std::string& error) {
	struct stat st {};
	if (fstatat(path.parent_fd.get(), path.leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
		error = errno_message("cannot inspect key file", path.display_path);
		return false;
	}
	if (!S_ISREG(st.st_mode)) {
		error = "key file '" + path.display_path + "' is not a regular file";
		return false;
	}
	return true;
}

int open_key_file(const ResolvedKeyPath& path) {
	int flags = O_RDONLY;
#ifdef O_CLOEXEC
	flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
	flags |= O_NONBLOCK;
#endif
	return openat(path.parent_fd.get(), path.leaf.c_str(), flags);
}

int reject_password_callback(char*, int, int, void*) {
	return 0;
}

bool read_key_file_content(
	int fd,
	const std::string& path,
	std::string& content,
	std::string& error
) {
	char buffer[4096];
	for (;;) {
		const ssize_t count = read(fd, buffer, sizeof(buffer));
		if (count == 0) {
			return true;
		}
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count < 0) {
			error = errno_message("cannot read RSA key file", path);
			return false;
		}
		if (content.size() + static_cast<size_t>(count) > MAXIMUM_PEM_FILE_SIZE) {
			error = "RSA key file '" + path + "' exceeds the 1 MiB safety limit";
			return false;
		}
		content.append(buffer, static_cast<size_t>(count));
	}
}

bool is_pem_whitespace(char value) {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n' ||
		value == '\f' || value == '\v';
}

bool has_single_pem_envelope(
	const std::string& content,
	const std::string& begin_marker,
	const std::string& end_marker
) {
	size_t begin = 0;
	while (begin < content.size() && is_pem_whitespace(content[begin])) {
		++begin;
	}
	if (content.compare(begin, begin_marker.size(), begin_marker) != 0 ||
		content.find(begin_marker, begin + begin_marker.size()) != std::string::npos) {
		return false;
	}
	const size_t end = content.find(end_marker, begin + begin_marker.size());
	if (end == std::string::npos ||
		content.find(end_marker, end + end_marker.size()) != std::string::npos) {
		return false;
	}
	for (size_t index = end + end_marker.size(); index < content.size(); ++index) {
		if (!is_pem_whitespace(content[index])) {
			return false;
		}
	}
	return true;
}

bool public_pem(EVP_PKEY* key, std::string& pem, std::string& error) {
	BIO* raw_bio = BIO_new(BIO_s_mem());
	if (raw_bio == nullptr) {
		error = "cannot allocate public-key serialization buffer";
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
	if (PEM_write_bio_PUBKEY(bio.get(), key) != 1) {
		error = "cannot serialize RSA public key";
		return false;
	}
	BUF_MEM* memory = nullptr;
	BIO_get_mem_ptr(bio.get(), &memory);
	if (memory == nullptr || memory->data == nullptr || memory->length == 0) {
		error = "serialized RSA public key is empty";
		return false;
	}
	pem.assign(memory->data, memory->length);
	return true;
}

bool private_pem(EVP_PKEY* key, std::string& pem, std::string& error) {
	BIO* raw_bio = BIO_new(BIO_s_mem());
	if (raw_bio == nullptr) {
		error = "cannot allocate private-key serialization buffer";
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
	if (PEM_write_bio_PKCS8PrivateKey(
		bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr
	) != 1) {
		error = "cannot serialize RSA private key";
		return false;
	}
	BUF_MEM* memory = nullptr;
	BIO_get_mem_ptr(bio.get(), &memory);
	if (memory == nullptr || memory->data == nullptr || memory->length == 0) {
		error = "serialized RSA private key is empty";
		return false;
	}
	pem.assign(memory->data, memory->length);
	return true;
}

bool validate_rsa_key(
	EVP_PKEY* key,
	const std::string& path,
	bool private_key,
	std::string& error
) {
	if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
		error = "key file '" + path + "' does not contain an RSA key";
		return false;
	}
	if (EVP_PKEY_bits(key) < MINIMUM_RSA_KEY_BITS) {
		error = "RSA key file '" + path + "' is weaker than 2048 bits";
		return false;
	}
	EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new(key, nullptr);
	if (raw_context == nullptr) {
		error = "cannot allocate validation context for RSA key file '" + path + "'";
		return false;
	}
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
		raw_context, &EVP_PKEY_CTX_free
	);
	const bool valid = private_key ?
		EVP_PKEY_private_check(context.get()) > 0 &&
			EVP_PKEY_pairwise_check(context.get()) > 0 :
		EVP_PKEY_public_check(context.get()) > 0;
	if (!valid) {
		error = "RSA key file '" + path + "' failed structural validation";
		return false;
	}
	return true;
}

bool load_private_key(
	const ResolvedKeyPath& path,
	std::shared_ptr<EVP_PKEY>& key,
	std::string& error
) {
	if (!validate_key_path(path, error)) {
		return false;
	}
	ScopedFd fd(open_key_file(path));
	if (fd.get() < 0) {
		error = errno_message("cannot open private key", path.display_path);
		return false;
	}
	if (!validate_open_file(fd.get(), path.display_path, true, error)) {
		return false;
	}
	std::string content;
	ScopedStringCleanser content_cleanser(content);
	if (!read_key_file_content(fd.get(), path.display_path, content, error) ||
		!has_single_pem_envelope(
			content, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"
		)) {
		if (error.empty()) {
			error = "private key '" + path.display_path +
				"' must contain exactly one unencrypted PKCS#8 PEM object";
		}
		return false;
	}
	BIO* raw_bio = BIO_new_mem_buf(content.data(), static_cast<int>(content.size()));
	if (raw_bio == nullptr) {
		error = "cannot allocate reader for private key '" + path.display_path + "'";
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
	PKCS8_PRIV_KEY_INFO* raw_key_info = PEM_read_bio_PKCS8_PRIV_KEY_INFO(
		bio.get(), nullptr, reject_password_callback, nullptr
	);
	if (raw_key_info == nullptr) {
		error = "private key '" + path.display_path +
			"' is malformed, encrypted, or not unencrypted PKCS#8 PEM";
		return false;
	}
	std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> key_info(
		raw_key_info, &PKCS8_PRIV_KEY_INFO_free
	);
	EVP_PKEY* raw_key = EVP_PKCS82PKEY(key_info.get());
	if (raw_key == nullptr) {
		error = "cannot decode PKCS#8 private key '" + path.display_path + "'";
		return false;
	}
	key = std::shared_ptr<EVP_PKEY>(raw_key, &EVP_PKEY_free);
	return validate_rsa_key(key.get(), path.display_path, true, error);
}

bool load_public_key(
	const ResolvedKeyPath& path,
	std::shared_ptr<EVP_PKEY>& key,
	std::string& error
) {
	if (!validate_key_path(path, error)) {
		return false;
	}
	ScopedFd fd(open_key_file(path));
	if (fd.get() < 0) {
		error = errno_message("cannot open public key", path.display_path);
		return false;
	}
	if (!validate_open_file(fd.get(), path.display_path, false, error)) {
		return false;
	}
	std::string content;
	if (!read_key_file_content(fd.get(), path.display_path, content, error) ||
		!has_single_pem_envelope(
			content, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"
		)) {
		if (error.empty()) {
			error = "public key '" + path.display_path +
				"' must contain exactly one SPKI PEM object";
		}
		return false;
	}
	BIO* raw_bio = BIO_new_mem_buf(content.data(), static_cast<int>(content.size()));
	if (raw_bio == nullptr) {
		error = "cannot allocate reader for public key '" + path.display_path + "'";
		return false;
	}
	std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
	EVP_PKEY* raw_key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
	if (raw_key == nullptr) {
		error = "public key '" + path.display_path + "' is malformed or not PKIX PEM";
		return false;
	}
	key = std::shared_ptr<EVP_PKEY>(raw_key, &EVP_PKEY_free);
	return validate_rsa_key(key.get(), path.display_path, false, error);
}

struct LoadedKeyPair {
	std::shared_ptr<EVP_PKEY> private_key;
	std::string public_key_pem;
	std::string private_key_path;
	std::string public_key_path;
	size_t ciphertext_size { 0 };
};

bool load_key_pair(
	const ResolvedKeyPath& private_path,
	const ResolvedKeyPath& public_path,
	LoadedKeyPair& loaded,
	std::string& error
) {
	std::shared_ptr<EVP_PKEY> private_key;
	std::shared_ptr<EVP_PKEY> public_key;
	if (!load_private_key(private_path, private_key, error) ||
		!load_public_key(public_path, public_key, error)) {
		return false;
	}

	std::string private_public_pem;
	std::string supplied_public_pem;
	if (!public_pem(private_key.get(), private_public_pem, error) ||
		!public_pem(public_key.get(), supplied_public_pem, error)) {
		return false;
	}
	if (private_public_pem != supplied_public_pem) {
		error = "RSA private and public key files do not form a matching pair";
		return false;
	}

	loaded.private_key = std::move(private_key);
	loaded.public_key_pem = std::move(private_public_pem);
	loaded.private_key_path = private_path.display_path;
	loaded.public_key_path = public_path.display_path;
	loaded.ciphertext_size = static_cast<size_t>(EVP_PKEY_size(loaded.private_key.get()));
	return true;
}

bool generate_rsa_key(std::shared_ptr<EVP_PKEY>& key, std::string& error) {
	EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	if (raw_context == nullptr) {
		error = "cannot allocate RSA key-generation context";
		return false;
	}
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
		raw_context, &EVP_PKEY_CTX_free
	);
	if (EVP_PKEY_keygen_init(context.get()) <= 0 ||
		EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), MINIMUM_RSA_KEY_BITS) <= 0) {
		error = "cannot initialize RSA-2048 key generation";
		return false;
	}
	EVP_PKEY* raw_key = nullptr;
	if (EVP_PKEY_keygen(context.get(), &raw_key) <= 0 || raw_key == nullptr) {
		error = "cannot generate RSA-2048 key";
		return false;
	}
	key = std::shared_ptr<EVP_PKEY>(raw_key, &EVP_PKEY_free);
	return true;
}

bool write_all(int fd, const std::string& content, const std::string& path, std::string& error) {
	size_t written = 0;
	while (written < content.size()) {
		const ssize_t rc = write(fd, content.data() + written, content.size() - written);
		if (rc < 0 && errno == EINTR) {
			continue;
		}
		if (rc <= 0) {
			error = errno_message("cannot write temporary key file", path);
			return false;
		}
		written += static_cast<size_t>(rc);
	}
	if (fsync(fd) != 0) {
		error = errno_message("cannot sync temporary key file", path);
		return false;
	}
	return true;
}

bool create_temporary_key_file(
	const ResolvedKeyPath& final_path,
	mode_t mode,
	const std::string& content,
	std::string& temporary_leaf,
	std::string& error
) {
	static std::atomic<unsigned long> sequence { 0 };
	for (unsigned int attempt = 0; attempt < 100; ++attempt) {
		temporary_leaf = final_path.leaf + ".tmp." + std::to_string(getpid()) + "." +
			std::to_string(sequence.fetch_add(1, std::memory_order_relaxed)); // NOSONAR(cpp:S8417): suffix uniqueness needs no publication ordering.
		int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
		flags |= O_CLOEXEC;
#endif
		ScopedFd fd(openat(final_path.parent_fd.get(), temporary_leaf.c_str(), flags, mode));
		if (fd.get() < 0) {
			if (errno == EEXIST) {
				continue;
			}
			error = errno_message("cannot create temporary key file beside", final_path.display_path);
			return false;
		}
		if (fchmod(fd.get(), mode) != 0) {
			error = errno_message("cannot set temporary key-file permissions beside", final_path.display_path);
			unlinkat(final_path.parent_fd.get(), temporary_leaf.c_str(), 0);
			return false;
		}
		if (!write_all(fd.get(), content, final_path.display_path, error)) {
			unlinkat(final_path.parent_fd.get(), temporary_leaf.c_str(), 0);
			return false;
		}
		return true;
	}
	error = "cannot allocate a unique temporary file beside '" + final_path.display_path + "'";
	return false;
}

void unlink_if_same_file(const ResolvedKeyPath& path, const std::string& temporary_leaf) {
	struct stat published {};
	struct stat temporary {};
	if (fstatat(path.parent_fd.get(), path.leaf.c_str(), &published, AT_SYMLINK_NOFOLLOW) == 0 &&
		fstatat(path.parent_fd.get(), temporary_leaf.c_str(), &temporary, AT_SYMLINK_NOFOLLOW) == 0 &&
		published.st_dev == temporary.st_dev && published.st_ino == temporary.st_ino) {
		unlinkat(path.parent_fd.get(), path.leaf.c_str(), 0);
	}
}

bool publish_generated_pair(
	const ResolvedKeyPath& private_path,
	const ResolvedKeyPath& public_path,
	const std::string& private_content,
	const std::string& public_content,
	std::string& error
) {
	std::string private_temp_leaf;
	std::string public_temp_leaf;
	if (!create_temporary_key_file(private_path, 0600, private_content, private_temp_leaf, error)) {
		return false;
	}
	if (!create_temporary_key_file(public_path, 0644, public_content, public_temp_leaf, error)) {
		unlinkat(private_path.parent_fd.get(), private_temp_leaf.c_str(), 0);
		return false;
	}

	bool success = false;
	if (linkat(
			private_path.parent_fd.get(), private_temp_leaf.c_str(),
			private_path.parent_fd.get(), private_path.leaf.c_str(), 0
		) != 0) {
		error = errno_message("cannot publish private key without overwriting", private_path.display_path);
	} else if (linkat(
			public_path.parent_fd.get(), public_temp_leaf.c_str(),
			public_path.parent_fd.get(), public_path.leaf.c_str(), 0
		) != 0) {
		error = errno_message("cannot publish public key without overwriting", public_path.display_path);
		unlink_if_same_file(private_path, private_temp_leaf);
	} else if (!fsync_parent_directory(private_path, error) ||
		!fsync_parent_directory(public_path, error)) {
		// The pair is valid and published even if directory fsync failed. Report the
		// durability failure so the caller keeps the previous in-memory snapshot.
	} else {
		success = true;
	}

	unlinkat(private_path.parent_fd.get(), private_temp_leaf.c_str(), 0);
	unlinkat(public_path.parent_fd.get(), public_temp_leaf.c_str(), 0);
	return success;
}

bool generate_pair(
	const ResolvedKeyPath& private_path,
	const ResolvedKeyPath& public_path,
	std::string& error
) {
	const std::string lock_leaf = private_path.leaf + ".lock";
	struct stat private_parent {};
	struct stat public_parent {};
	if (fstat(private_path.parent_fd.get(), &private_parent) != 0 ||
		fstat(public_path.parent_fd.get(), &public_parent) != 0) {
		error = "cannot inspect RSA key parent directories before generation";
		return false;
	}
	const bool same_parent = private_parent.st_dev == public_parent.st_dev &&
		private_parent.st_ino == public_parent.st_ino;
	const std::string private_temp_prefix = private_path.leaf + ".tmp.";
	const std::string public_temp_prefix = public_path.leaf + ".tmp.";
	if (same_parent && (
		private_path.leaf == public_path.leaf ||
		public_path.leaf == lock_leaf ||
		private_path.leaf.rfind(public_temp_prefix, 0) == 0 ||
		public_path.leaf.rfind(private_temp_prefix, 0) == 0
	)) {
		error = "RSA key targets collide with the generation lock or temporary-file namespace";
		return false;
	}
	int lock_flags = O_RDWR | O_CREAT;
#ifdef O_CLOEXEC
	lock_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
	lock_flags |= O_NOFOLLOW;
#endif
	ScopedFd lock_fd(openat(private_path.parent_fd.get(), lock_leaf.c_str(), lock_flags, 0600));
	if (lock_fd.get() < 0) {
		error = errno_message("cannot open RSA key-generation lock beside", private_path.display_path);
		return false;
	}
	while (flock(lock_fd.get(), LOCK_EX) != 0) {
		if (errno != EINTR) {
			error = errno_message("cannot lock RSA key generation beside", private_path.display_path);
			return false;
		}
	}

	bool private_exists = false;
	bool public_exists = false;
	if (!path_exists(private_path, private_exists, error) ||
		!path_exists(public_path, public_exists, error)) {
		return false;
	}
	if (private_exists || public_exists) {
		if (private_exists && public_exists) {
			return true;
		}
		error = "only one RSA key file exists; refusing to generate or overwrite a partial pair";
		return false;
	}

	std::shared_ptr<EVP_PKEY> key;
	if (!generate_rsa_key(key, error)) {
		return false;
	}
	std::string private_content;
	std::string public_content;
	if (!private_pem(key.get(), private_content, error) ||
		!public_pem(key.get(), public_content, error)) {
		if (!private_content.empty()) {
			OPENSSL_cleanse(private_content.data(), private_content.size());
		}
		return false;
	}
	const bool published = publish_generated_pair(
		private_path, public_path, private_content, public_content, error
	);
	OPENSSL_cleanse(private_content.data(), private_content.size());
	return published;
}

MySQL_Caching_Sha2_RSA_Reload_Result rejected_result(
	const std::string& error,
	const std::shared_ptr<const MySQL_Caching_Sha2_RSA_Key_Snapshot>& current
) {
	return { false, false, current != nullptr, error };
}

} // namespace

MySQL_Caching_Sha2_RSA::~MySQL_Caching_Sha2_RSA() {
	pthread_mutex_destroy(&mutex_);
}

MySQL_Caching_Sha2_RSA_Reload_Result MySQL_Caching_Sha2_RSA::reload(
	const MySQL_Caching_Sha2_RSA_Config& config
) {
	if (config.private_key_path.empty() != config.public_key_path.empty()) {
		const auto current = acquire();
		return rejected_result("both RSA private and public key paths must be configured together", current);
	}
	if (config.private_key_path.empty()) {
		if (config.auto_generate) {
			const auto current = acquire();
			return rejected_result("automatic RSA key generation requires non-empty key paths", current);
		}
		pthread_mutex_lock(&mutex_);
		const bool changed = snapshot_ != nullptr;
		snapshot_.reset();
		pthread_mutex_unlock(&mutex_);
		return { true, changed, false, {} };
	}

	ResolvedKeyPath private_path;
	ResolvedKeyPath public_path;
	std::string error;
	if (!resolve_key_path(config.private_key_path, config.datadir, private_path, error) ||
		!resolve_key_path(config.public_key_path, config.datadir, public_path, error)) {
		return rejected_result(error, acquire());
	}
	bool private_exists = false;
	bool public_exists = false;
	if (!path_exists(private_path, private_exists, error) ||
		!path_exists(public_path, public_exists, error)) {
		return rejected_result(error, acquire());
	}
	if (!private_exists || !public_exists) {
		if (!config.auto_generate) {
			const std::string missing_error = private_exists != public_exists
				? "only one RSA key file exists; refusing to load or generate a partial pair"
				: "configured RSA key files do not exist";
			return rejected_result(missing_error, acquire());
		}
		// Another process publishes the pair under the generation lock using two
		// non-overwriting links. Recheck every missing/partial state while holding
		// that same lock so observers wait for an in-flight publisher.
		if (!generate_pair(private_path, public_path, error)) {
			return rejected_result(error, acquire());
		}
	}

	LoadedKeyPair loaded;
	if (!load_key_pair(private_path, public_path, loaded, error)) {
		return rejected_result(error, acquire());
	}

	auto candidate = std::make_shared<MySQL_Caching_Sha2_RSA_Key_Snapshot>();
	candidate->private_key_ = std::move(loaded.private_key);
	candidate->public_key_pem_ = std::move(loaded.public_key_pem);
	candidate->private_key_path_ = std::move(loaded.private_key_path);
	candidate->public_key_path_ = std::move(loaded.public_key_path);
	candidate->ciphertext_size_ = loaded.ciphertext_size;

	pthread_mutex_lock(&mutex_);
	if (snapshot_ != nullptr &&
		snapshot_->private_key_path_ == candidate->private_key_path_ &&
		snapshot_->public_key_path_ == candidate->public_key_path_ &&
		snapshot_->public_key_pem_ == candidate->public_key_pem_) {
		pthread_mutex_unlock(&mutex_);
		return { true, false, true, {} };
	}
	snapshot_ = std::move(candidate);
	pthread_mutex_unlock(&mutex_);
	return { true, true, true, {} };
}

std::shared_ptr<const MySQL_Caching_Sha2_RSA_Key_Snapshot> MySQL_Caching_Sha2_RSA::acquire() const {
	pthread_mutex_lock(&mutex_);
	auto snapshot = snapshot_;
	pthread_mutex_unlock(&mutex_);
	return snapshot;
}

bool MySQL_Caching_Sha2_RSA::decrypt_password(
	const std::shared_ptr<const MySQL_Caching_Sha2_RSA_Key_Snapshot>& snapshot,
	const unsigned char* ciphertext,
	size_t ciphertext_length,
	const unsigned char* scramble,
	size_t scramble_length,
	std::string& password,
	std::string* error
) const {
	if (!password.empty()) {
		OPENSSL_cleanse(password.data(), password.size());
	}
	password.clear();
	auto fail = [error](const char* message) {
		if (error != nullptr) {
			*error = message;
		}
		return false;
	};
	if (snapshot == nullptr || snapshot->private_key_ == nullptr) {
		return fail("RSA key snapshot is unavailable");
	}
	if (ciphertext == nullptr || ciphertext_length != snapshot->ciphertext_size_) {
		return fail("RSA ciphertext has an invalid length");
	}
	if (scramble == nullptr || scramble_length == 0) {
		return fail("authentication scramble is unavailable");
	}

	EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new(snapshot->private_key_.get(), nullptr);
	if (raw_context == nullptr) {
		return fail("cannot allocate RSA decryption context");
	}
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
		raw_context, &EVP_PKEY_CTX_free
	);
	if (EVP_PKEY_decrypt_init(context.get()) <= 0 ||
		EVP_PKEY_CTX_set_rsa_padding(context.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
		EVP_PKEY_CTX_set_rsa_oaep_md(context.get(), EVP_sha1()) <= 0 || // NOSONAR(cpp:S4790): MySQL caching_sha2_password requires OAEP SHA-1.
		EVP_PKEY_CTX_set_rsa_mgf1_md(context.get(), EVP_sha1()) <= 0) { // NOSONAR(cpp:S4790): MySQL caching_sha2_password requires MGF1 SHA-1.
		return fail("cannot initialize RSA OAEP decryption");
	}

	size_t plaintext_length = 0;
	if (EVP_PKEY_decrypt(
		context.get(), nullptr, &plaintext_length, ciphertext, ciphertext_length
	) <= 0 || plaintext_length == 0) {
		return fail("RSA OAEP decryption failed");
	}
	const size_t plaintext_allocation_size = plaintext_length;
	std::vector<unsigned char> plaintext(plaintext_allocation_size);
	ScopedBufferCleanser plaintext_cleanser(plaintext, plaintext_allocation_size);
	if (EVP_PKEY_decrypt(
		context.get(), plaintext.data(), &plaintext_length, ciphertext, ciphertext_length
	) <= 0 || plaintext_length == 0) {
		return fail("RSA OAEP decryption failed");
	}
	if (plaintext_length > plaintext_allocation_size) {
		return fail("RSA OAEP decryption returned an invalid length");
	}
	for (size_t index = 0; index < plaintext_length; ++index) {
		plaintext[index] ^= scramble[index % scramble_length];
	}
	if (plaintext[plaintext_length - 1] != '\0' ||
		std::memchr(plaintext.data(), '\0', plaintext_length - 1) != nullptr) {
		return fail("decrypted password is not a single NUL-terminated string");
	}
	password.assign(reinterpret_cast<const char*>(plaintext.data()), plaintext_length - 1);
	if (error != nullptr) {
		error->clear();
	}
	return true;
}
