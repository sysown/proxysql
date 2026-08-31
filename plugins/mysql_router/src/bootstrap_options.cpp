#include "mysql_router_bootstrap.h"

#include <fcntl.h>
#include <openssl/crypto.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <stdexcept>
#include <utility>

namespace {

constexpr std::size_t kMaximumPasswordBytes = 4096;

unsigned parse_unsigned(const std::string& value, const char* option,
	unsigned maximum) {
	if (value.empty()) throw std::invalid_argument(std::string(option) + " requires a value");
	unsigned long long parsed = 0;
	for (unsigned char character : value) {
		if (!std::isdigit(character)) {
			throw std::invalid_argument(std::string(option) + " must be an unsigned integer");
		}
		const unsigned digit = static_cast<unsigned>(character - '0');
		if (parsed > (maximum - digit) / 10) {
			throw std::invalid_argument(std::string(option) + " is outside the allowed range");
		}
		parsed = parsed * 10 + digit;
	}
	return static_cast<unsigned>(parsed);
}

int hex_value(char value) {
	if (value >= '0' && value <= '9') return value - '0';
	if (value >= 'a' && value <= 'f') return value - 'a' + 10;
	if (value >= 'A' && value <= 'F') return value - 'A' + 10;
	return -1;
}

std::string percent_decode(std::string_view value) {
	std::string decoded;
	decoded.reserve(value.size());
	for (std::size_t i = 0; i < value.size(); ++i) {
		if (value[i] != '%') {
			decoded.push_back(value[i]);
			continue;
		}
		if (i + 2 >= value.size()) throw std::invalid_argument("invalid username percent encoding");
		const int high = hex_value(value[i + 1]);
		const int low = hex_value(value[i + 2]);
		if (high < 0 || low < 0) throw std::invalid_argument("invalid username percent encoding");
		const char decoded_byte = static_cast<char>((high << 4) | low);
		if (decoded_byte == '\0') throw std::invalid_argument("bootstrap username contains NUL");
		decoded.push_back(decoded_byte);
		i += 2;
	}
	return decoded;
}

MetadataTlsMode parse_tls_mode(const std::string& value, const char* option) {
	if (value == "DISABLED") return MetadataTlsMode::disabled;
	if (value == "PREFERRED") return MetadataTlsMode::preferred;
	if (value == "REQUIRED") return MetadataTlsMode::required;
	if (value == "VERIFY_CA") return MetadataTlsMode::verify_ca;
	if (value == "VERIFY_IDENTITY") return MetadataTlsMode::verify_identity;
	throw std::invalid_argument(std::string("invalid ") + option + " value");
}

bool is_set(const ProxySQL_PluginEarlyActionContext& context, const char* name) {
	return context.is_set != nullptr && context.is_set(context.option_context, name);
}

std::optional<std::string> get_value(
	const ProxySQL_PluginEarlyActionContext& context, const char* name) {
	if (!is_set(context, name)) return std::nullopt;
	if (context.get_string == nullptr) {
		throw std::invalid_argument(std::string("cannot read ") + name);
	}
	std::string value;
	if (!context.get_string(context.option_context, name, value)) {
		throw std::invalid_argument(std::string("cannot read ") + name);
	}
	return value;
}

void register_option(ProxySQL_PluginCLIRegistry& registry, const char* short_name,
	const char* long_name, uint8_t values, const char* help) {
	const ProxySQL_PluginCLIOptionDef option {short_name, long_name, values, false, help};
	const char* error = nullptr;
	if (!registry.add(registry.opaque, option, &error)) {
		throw std::runtime_error(error != nullptr ? error : "cannot register Router CLI option");
	}
}

class TerminalEchoGuard {
public:
	explicit TerminalEchoGuard(int fd) : fd_(fd) {
		if (tcgetattr(fd_, &saved_) != 0) throw std::runtime_error("cannot read terminal attributes");
		termios hidden = saved_;
		hidden.c_lflag &= ~ECHO;
		if (tcsetattr(fd_, TCSAFLUSH, &hidden) != 0) {
			throw std::runtime_error("cannot disable terminal echo");
		}
		active_ = true;
	}
	~TerminalEchoGuard() {
		if (active_) (void)tcsetattr(fd_, TCSAFLUSH, &saved_);
	}

private:
	int fd_;
	termios saved_ {};
	bool active_ {false};
};

std::vector<unsigned char> read_password_bytes(int fd) {
	std::vector<unsigned char> bytes;
	bytes.reserve(128);
	while (bytes.size() <= kMaximumPasswordBytes) {
		unsigned char buffer[256];
		const std::size_t remaining = kMaximumPasswordBytes + 1 - bytes.size();
		const ssize_t count = read(fd, buffer, remaining < sizeof(buffer) ? remaining : sizeof(buffer));
		if (count < 0) {
			if (errno == EINTR) continue;
			OPENSSL_cleanse(bytes.data(), bytes.size());
			throw std::runtime_error("cannot read bootstrap password");
		}
		if (count == 0) break;
		bytes.insert(bytes.end(), buffer, buffer + count);
		if (bytes.back() == '\n') break;
	}
	if (bytes.size() > kMaximumPasswordBytes) {
		OPENSSL_cleanse(bytes.data(), bytes.size());
		throw std::invalid_argument("bootstrap password exceeds 4096 bytes");
	}
	if (!bytes.empty() && bytes.back() == '\n') bytes.pop_back();
	return bytes;
}

void write_all(int fd, const char* bytes, std::size_t length) {
	std::size_t written = 0;
	while (written < length) {
		const ssize_t count = write(fd, bytes + written, length - written);
		if (count < 0) {
			if (errno == EINTR) continue;
			throw std::runtime_error("cannot write bootstrap password prompt");
		}
		if (count == 0) throw std::runtime_error("cannot write bootstrap password prompt");
		written += static_cast<std::size_t>(count);
	}
}

} // namespace

SecureBytes::SecureBytes(std::vector<unsigned char> bytes) : bytes_(std::move(bytes)) {}

SecureBytes::~SecureBytes() {
	cleanse();
}

SecureBytes::SecureBytes(SecureBytes&& other) noexcept : bytes_(std::move(other.bytes_)) {}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
	if (this != &other) {
		cleanse();
		bytes_ = std::move(other.bytes_);
	}
	return *this;
}

void SecureBytes::cleanse() {
	if (!bytes_.empty()) OPENSSL_cleanse(bytes_.data(), bytes_.size());
	bytes_.clear();
}

bool mysql_router_register_cli_options(ProxySQL_PluginCLIRegistry* registry) {
	if (registry == nullptr || registry->add == nullptr) return false;
	try {
		register_option(*registry, "-B", "--bootstrap", 1, "Bootstrap using USER@HOST[:PORT]");
		register_option(*registry, "", "--router-name", 1, "Router instance name");
		register_option(*registry, "", "--account", 1, "Router service account");
		register_option(*registry, "", "--account-create", 1, "Service account creation policy");
		register_option(*registry, "", "--account-host", 1, "Service account host pattern");
		register_option(*registry, "", "--password-retries", 1, "Password prompt retry count");
		register_option(*registry, "", "--bootstrap-password-fd", 1, "Read bootstrap password from FD");
		register_option(*registry, "", "--force", 0, "Replace an existing Router registration");
		register_option(*registry, "", "--replace-topology", 0, "Replace a different managed topology");
		register_option(*registry, "", "--conf-bind-address", 1, "Generated listener bind address");
		register_option(*registry, "", "--conf-base-port", 1, "Generated listener base port");
		register_option(*registry, "", "--conf-use-sockets", 0, "Configure Unix socket listeners");
		register_option(*registry, "", "--conf-skip-tcp", 0, "Do not configure TCP listeners");
		register_option(*registry, "", "--ssl-ca", 1, "Metadata TLS CA file");
		register_option(*registry, "", "--ssl-capath", 1, "Metadata TLS CA directory");
		register_option(*registry, "", "--ssl-cert", 1, "Metadata TLS certificate");
		register_option(*registry, "", "--ssl-key", 1, "Metadata TLS private key");
		register_option(*registry, "", "--ssl-cipher", 1, "Metadata TLS cipher list");
		register_option(*registry, "", "--ssl-crl", 1, "Metadata TLS revocation list");
		register_option(*registry, "", "--ssl-crlpath", 1, "Metadata TLS revocation directory");
		register_option(*registry, "", "--ssl-mode", 1, "Metadata TLS verification mode");
		return true;
	} catch (...) {
		return false;
	}
}

MetadataEndpoint parse_metadata_uri(std::string_view uri) {
	const std::size_t at = uri.rfind('@');
	if (at == std::string_view::npos) throw std::invalid_argument("bootstrap URI requires username@host");
	if (uri.find('@') != at) throw std::invalid_argument("bootstrap URI contains multiple @ delimiters");
	const std::string_view userinfo = uri.substr(0, at);
	if (userinfo.empty()) throw std::invalid_argument("bootstrap username is empty");
	if (userinfo.find(':') != std::string_view::npos) {
		throw std::invalid_argument("bootstrap URI passwords are not accepted");
	}

	MetadataEndpoint endpoint;
	endpoint.username = percent_decode(userinfo);
	if (endpoint.username.empty()) throw std::invalid_argument("bootstrap username is empty");
	const std::string_view authority = uri.substr(at + 1);
	if (authority.empty()) throw std::invalid_argument("bootstrap host is empty");
	std::string_view port;
	if (authority.front() == '[') {
		const std::size_t close = authority.find(']');
		if (close == std::string_view::npos || close == 1) throw std::invalid_argument("invalid bracketed IPv6 host");
		endpoint.host.assign(authority.substr(1, close - 1));
		if (close + 1 < authority.size()) {
			if (authority[close + 1] != ':') throw std::invalid_argument("invalid bracketed IPv6 endpoint");
			port = authority.substr(close + 2);
		}
	} else {
		const std::size_t colon = authority.rfind(':');
		if (colon != std::string_view::npos) {
			if (authority.find(':') != colon) throw std::invalid_argument("IPv6 bootstrap hosts must be bracketed");
			endpoint.host.assign(authority.substr(0, colon));
			port = authority.substr(colon + 1);
		} else {
			endpoint.host.assign(authority);
		}
	}
	if (endpoint.host.empty()) throw std::invalid_argument("bootstrap host is empty");
	if (!port.empty()) endpoint.port = static_cast<uint16_t>(parse_unsigned(std::string(port), "bootstrap port", 65535));
	else if ((!authority.empty() && authority.back() == ':') ||
		(authority.front() == '[' && authority.back() != ']')) {
		throw std::invalid_argument("bootstrap port is empty");
	}
	if (endpoint.port == 0) throw std::invalid_argument("bootstrap port must be nonzero");
	return endpoint;
}

BootstrapOptions parse_bootstrap_options(const ProxySQL_PluginEarlyActionContext& context) {
	BootstrapOptions options;
	if (auto value = get_value(context, "--bootstrap")) {
		options.requested = true;
		options.seed = parse_metadata_uri(*value);
	}
	if (auto value = get_value(context, "--router-name")) options.router_name = *value;
	if (auto value = get_value(context, "--account")) options.service_account = *value;
	if (auto value = get_value(context, "--account-host")) options.account_host = *value;
	if (auto value = get_value(context, "--account-create")) {
		if (*value == "if-not-exists") options.account_create = AccountCreatePolicy::if_not_exists;
		else if (*value == "always") options.account_create = AccountCreatePolicy::always;
		else if (*value == "never") options.account_create = AccountCreatePolicy::never;
		else throw std::invalid_argument("invalid --account-create value");
	}
	if (auto value = get_value(context, "--password-retries")) {
		options.password_retries = parse_unsigned(*value, "--password-retries",
			std::numeric_limits<unsigned>::max());
	}
	if (auto value = get_value(context, "--bootstrap-password-fd")) {
		options.password_fd = static_cast<int>(parse_unsigned(*value,
			"--bootstrap-password-fd", static_cast<unsigned>(std::numeric_limits<int>::max())));
	}
	options.force = is_set(context, "--force");
	options.replace_topology = is_set(context, "--replace-topology");
	if (auto value = get_value(context, "--conf-bind-address")) options.listeners.bind_address = *value;
	if (auto value = get_value(context, "--conf-base-port")) {
		const unsigned base = parse_unsigned(*value, "--conf-base-port", 65531);
		if (base == 0) throw std::invalid_argument("--conf-base-port must be nonzero");
		options.listeners.rw_port = static_cast<uint16_t>(base);
		options.listeners.ro_port = static_cast<uint16_t>(base + 1);
		options.listeners.rw_split_port = static_cast<uint16_t>(base + 4);
	}
	options.listeners.use_sockets = is_set(context, "--conf-use-sockets");
	options.listeners.skip_tcp = is_set(context, "--conf-skip-tcp");
	if (options.listeners.use_sockets && options.listeners.skip_tcp) {
		throw std::invalid_argument("--conf-use-sockets and --conf-skip-tcp conflict");
	}
	if (auto value = get_value(context, "--ssl-mode")) options.tls.mode = parse_tls_mode(*value, "--ssl-mode");
	if (auto value = get_value(context, "--ssl-ca")) options.tls.ca = *value;
	if (auto value = get_value(context, "--ssl-capath")) options.tls.capath = *value;
	if (auto value = get_value(context, "--ssl-cert")) options.tls.cert = *value;
	if (auto value = get_value(context, "--ssl-key")) options.tls.key = *value;
	if (auto value = get_value(context, "--ssl-cipher")) options.tls.cipher = *value;
	if (auto value = get_value(context, "--ssl-crl")) options.tls.crl = *value;
	if (auto value = get_value(context, "--ssl-crlpath")) options.tls.crlpath = *value;
	return options;
}

SecureBytes read_bootstrap_password(const BootstrapOptions& options) {
	if (options.password_fd) {
		const int flags = fcntl(*options.password_fd, F_GETFL);
		if (flags < 0 || (flags & O_ACCMODE) == O_WRONLY) {
			throw std::invalid_argument("--bootstrap-password-fd is not an open readable descriptor");
		}
		return SecureBytes(read_password_bytes(*options.password_fd));
	}
	const int tty = open("/dev/tty", O_RDWR | O_CLOEXEC);
	if (tty < 0) throw std::runtime_error("cannot open /dev/tty for bootstrap password");
	try {
		std::vector<unsigned char> bytes;
		{
			TerminalEchoGuard guard(tty);
			const std::string prompt = "Please enter MySQL password for " + options.seed.username + ": ";
			write_all(tty, prompt.data(), prompt.size());
			bytes = read_password_bytes(tty);
			write_all(tty, "\n", 1);
		}
		close(tty);
		return SecureBytes(std::move(bytes));
	} catch (...) {
		close(tty);
		throw;
	}
}
