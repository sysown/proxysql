#include "tap.h"

#include "ProxySQL_Plugin.h"
#include "mysql_router_bootstrap.h"
#include "mysql_router_config.h"
#include "sqlite3db.h"

#include <cerrno>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

struct OptionFixture {
	std::map<std::string, std::string> values;
	std::vector<ProxySQL_PluginCLIOptionDef> definitions;
	std::string error;

	static bool add(void* opaque, const ProxySQL_PluginCLIOptionDef& option,
		const char**) {
		auto& self = *static_cast<OptionFixture*>(opaque);
		self.definitions.push_back(option);
		return true;
	}

	static bool is_set(void* opaque, const char* name) {
		auto& self = *static_cast<OptionFixture*>(opaque);
		return name != nullptr && self.values.count(name) != 0;
	}

	static bool get_string(void* opaque, const char* name, std::string& value) {
		auto& self = *static_cast<OptionFixture*>(opaque);
		auto it = name != nullptr ? self.values.find(name) : self.values.end();
		if (it == self.values.end()) return false;
		value = it->second;
		return true;
	}

	ProxySQL_PluginCLIRegistry registry() {
		return {this, &OptionFixture::add};
	}

	ProxySQL_PluginEarlyActionContext context() {
		return {this, &OptionFixture::is_set, &OptionFixture::get_string,
			nullptr, nullptr, nullptr};
	}
};

bool throws_with(const OptionFixture& source, const char* needle) {
	auto fixture = source;
	try {
		(void)parse_bootstrap_options(fixture.context());
	} catch (const std::exception& e) {
		return std::string(e.what()).find(needle) != std::string::npos;
	}
	return false;
}

bool uri_throws(const char* uri, const char* needle) {
	try {
		(void)parse_metadata_uri(uri);
	} catch (const std::exception& e) {
		return std::string(e.what()).find(needle) != std::string::npos;
	}
	return false;
}

} // namespace

int main() {
	plan(53);

	OptionFixture registry_fixture;
	auto registry = registry_fixture.registry();
	ok(mysql_router_register_cli_options(&registry),
	   "the Router plugin registers its bootstrap CLI surface");
	ok(registry_fixture.definitions.size() == 21,
	   "all 21 Router-compatible options are registered");
	bool bootstrap_shape = false;
	for (const auto& option : registry_fixture.definitions) {
		if (std::string(option.long_name) == "--bootstrap") {
			bootstrap_shape = std::string(option.short_name) == "-B" &&
				option.value_count == 1 && !option.required;
		}
	}
	ok(bootstrap_shape, "--bootstrap owns the -B alias and one value");

	auto ipv4 = parse_metadata_uri("metadata%5Fuser@127.0.0.1");
	ok(ipv4.username == "metadata_user", "bootstrap usernames are percent-decoded");
	ok(ipv4.host == "127.0.0.1", "IPv4 metadata hosts are accepted");
	ok(ipv4.port == 3306, "metadata endpoints default to port 3306");

	auto ipv6 = parse_metadata_uri("router@[2001:db8::7]:3310");
	ok(ipv6.username == "router", "bracketed IPv6 retains its username");
	ok(ipv6.host == "2001:db8::7", "bracketed IPv6 is normalized without brackets");
	ok(ipv6.port == 3310, "bracketed IPv6 accepts an explicit port");

	ok(uri_throws("user:secret@metadata:3306", "password"),
	   "bootstrap URIs containing passwords are rejected");
	ok(uri_throws("user@metadata:65536", "port"), "overflowing ports are rejected");
	ok(uri_throws("user@2001:db8::7", "IPv6"), "unbracketed IPv6 is rejected");
	ok(uri_throws("user%ZZ@metadata", "percent"), "invalid percent encoding is rejected");
	ok(uri_throws("@metadata", "username"), "empty bootstrap usernames are rejected");

	OptionFixture defaults;
	auto default_options = parse_bootstrap_options(defaults.context());
	ok(!default_options.requested, "bootstrap is not requested by default");
	ok(default_options.listeners.bind_address == "0.0.0.0", "default bind address is 0.0.0.0");
	ok(default_options.listeners.rw_port == 6446, "default read-write port is 6446");
	ok(default_options.listeners.ro_port == 6447, "default read-only port is 6447");
	ok(default_options.listeners.rw_split_port == 6450, "default split port is 6450");
	ok(default_options.password_retries == 20, "default password retry count is 20");
	ok(default_options.account_create == AccountCreatePolicy::if_not_exists,
	   "default account creation policy is if-not-exists");
	ok(default_options.tls.mode == MetadataTlsMode::preferred,
	   "default metadata TLS mode is PREFERRED");

	OptionFixture complete;
	complete.values = {
		{"--bootstrap", "seed@metadata.example:4406"},
		{"--router-name", "proxysql-east"}, {"--account", "router_svc"},
		{"--account-create", "always"}, {"--account-host", "10.%"},
		{"--password-retries", "7"}, {"--bootstrap-password-fd", "9"},
		{"--force", ""}, {"--replace-topology", ""},
		{"--conf-bind-address", "127.0.0.1"}, {"--conf-base-port", "7000"},
		{"--ssl-mode", "VERIFY_IDENTITY"},
		{"--ssl-ca", "/ca.pem"}, {"--ssl-cert", "/cert.pem"},
		{"--ssl-key", "/key.pem"}
	};
	auto parsed = parse_bootstrap_options(complete.context());
	ok(parsed.requested && parsed.seed.host == "metadata.example" && parsed.seed.port == 4406,
	   "the bootstrap seed is parsed from the action option");
	ok(parsed.router_name == "proxysql-east" && parsed.service_account == "router_svc",
	   "owned Router and service-account names are parsed");
	ok(parsed.account_create == AccountCreatePolicy::always && parsed.account_host == "10.%",
	   "account policy and host pattern are parsed");
	ok(parsed.password_retries == 7 && parsed.password_fd && *parsed.password_fd == 9,
	   "password retry and descriptor settings are parsed");
	ok(parsed.force && parsed.replace_topology, "bootstrap action flags are parsed");
	ok(parsed.listeners.bind_address == "127.0.0.1" && parsed.listeners.rw_port == 7000 &&
	   parsed.listeners.ro_port == 7001 && parsed.listeners.rw_split_port == 7004,
	   "the base port derives the three advertised listener ports");
	ok(!parsed.listeners.use_sockets && !parsed.listeners.skip_tcp,
	   "the supported listener profile remains TCP-only");
	ok(parsed.tls.mode == MetadataTlsMode::verify_identity && parsed.tls.ca == "/ca.pem" &&
	   parsed.tls.cert == "/cert.pem" && parsed.tls.key == "/key.pem",
	   "TLS mode and certificate paths are parsed");

	OptionFixture conflict;
	conflict.values = {{"--conf-use-sockets", ""}};
	ok(throws_with(conflict, "not supported"), "unsupported socket listeners are rejected explicitly");
	OptionFixture skip_tcp;
	skip_tcp.values = {{"--conf-skip-tcp", ""}};
	ok(throws_with(skip_tcp, "not supported"), "unsupported TCP suppression is rejected explicitly");
	OptionFixture bad_policy;
	bad_policy.values = {{"--account-create", "sometimes"}};
	ok(throws_with(bad_policy, "account-create"), "invalid account creation policy is rejected");
	OptionFixture bad_tls;
	bad_tls.values = {{"--ssl-mode", "INSECURE"}};
	ok(throws_with(bad_tls, "ssl-mode"), "invalid metadata TLS mode is rejected");
	OptionFixture bad_base;
	bad_base.values = {{"--conf-base-port", "65535"}};
	ok(throws_with(bad_base, "port"), "base ports whose derived listeners overflow are rejected");

	int fds[2] {-1, -1};
	ok(pipe(fds) == 0, "a password pipe is available");
	const char password[] = "s3cr3t-from-fd\n"; // NOSONAR: synthetic pipe-input fixture.
	ok(write(fds[1], password, sizeof(password) - 1) ==
	   static_cast<ssize_t>(sizeof(password) - 1), "the password fixture is written");
	close(fds[1]);
	BootstrapOptions password_options;
	password_options.password_fd = fds[0];
	SecureBytes secret = read_bootstrap_password(password_options);
	close(fds[0]);
	ok(secret.size() == 14, "one trailing password newline is stripped");
	ok(std::string(reinterpret_cast<const char*>(secret.data()), secret.size()) ==
	   "s3cr3t-from-fd", "password bytes are read exactly from the descriptor");
	int newline_fds[2] {-1, -1};
	ok(pipe(newline_fds) == 0, "an embedded-newline password pipe is available");
	const char embedded[] = "first-line\nignored";
	ok(write(newline_fds[1], embedded, sizeof(embedded) - 1) ==
	   static_cast<ssize_t>(sizeof(embedded) - 1), "the embedded-newline fixture is written");
	close(newline_fds[1]);
	BootstrapOptions newline_options;
	newline_options.password_fd = newline_fds[0];
	SecureBytes first_line = read_bootstrap_password(newline_options);
	close(newline_fds[0]);
	ok(std::string(reinterpret_cast<const char*>(first_line.data()), first_line.size()) ==
	   "first-line", "password input stops at the first newline in a single read");
	int write_only_fds[2] {-1, -1};
	ok(pipe(write_only_fds) == 0, "a write-only descriptor fixture is available");
	BootstrapOptions write_only_options;
	write_only_options.password_fd = write_only_fds[1];
	bool write_only_rejected = false;
	try {
		(void)read_bootstrap_password(write_only_options);
	} catch (const std::exception& exception) {
		write_only_rejected = std::string(exception.what()).find("readable") != std::string::npos;
	}
	close(write_only_fds[0]);
	close(write_only_fds[1]);
	ok(write_only_rejected, "a write-only password descriptor is rejected");

	SQLite3DB db;
	db.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	ok(db.execute("CREATE TABLE mysql_router_config (config_key TEXT PRIMARY KEY,config_value TEXT NOT NULL)"),
	   "the Router config table fixture is created");
	ok(db.execute("INSERT INTO mysql_router_config VALUES"
		"('refresh_interval_ms','2500'),('bind_address','127.0.0.2'),"
		"('rw_port','7446'),('metadata_ssl_mode','REQUIRED')"),
	   "valid Router configuration is seeded");
	MysqlRouterConfigStore store;
	std::string error;
	ok(store.load(db, error), "valid typed Router configuration loads: %s", error.c_str());
	auto snapshot = store.snapshot();
	ok(snapshot.refresh_interval_ms == 2500 && snapshot.connect_timeout_ms == 5000 &&
	   snapshot.read_timeout_ms == 30000, "configured and default timeouts coexist");
	ok(snapshot.bind_address == "127.0.0.2" && snapshot.rw_port == 7446 &&
	   snapshot.ro_port == 6447 && snapshot.rw_split_port == 6450,
	   "configured and default listener values coexist");
	ok(snapshot.metadata_ssl_mode == MetadataTlsMode::required,
	   "typed metadata TLS configuration is installed");
	ok(db.execute("INSERT INTO mysql_router_config VALUES('unknown_key','value')"),
	   "an undeclared config key is staged");
	ok(!store.load(db, error) && error.find("unknown_key") != std::string::npos,
	   "undeclared Router configuration keys fail closed");
	auto unchanged = store.snapshot();
	ok(unchanged.refresh_interval_ms == 2500 && unchanged.rw_port == 7446,
	   "invalid loads do not replace the prior in-memory snapshot");

	return exit_status();
}
