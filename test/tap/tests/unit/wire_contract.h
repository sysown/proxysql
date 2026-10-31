#ifndef GTID_WIRE_CONTRACT_H
#define GTID_WIRE_CONTRACT_H

/**
 * Shared reader/ProxySQL wire-contract fixture.
 *
 * The MariaDB GTID reader and the ProxySQL parser that consumes its output live
 * in two repositories, and CI never runs them against each other: ProxySQL
 * pins the reader to a published image that predates MariaDB support, and has
 * no MariaDB binlog-reader infrastructure at all. Without this fixture the
 * format is pinned only by a markdown design doc, so the two sides can drift
 * with every check still green.
 *
 * The fixture lives at test/tap/wire_contract/mariadb_gtid_wire.txt and is
 * duplicated byte-identically in the ProxySQL repository. The reader's live
 * test matches what the running reader emitted against the fixture; ProxySQL's
 * unit test expands the fixture into concrete wire text and asserts its parser
 * produces the documented watermark.
 *
 * Both directions are asserted on purpose: the reader side catches a format
 * change at the source, and the ProxySQL side catches a format change the
 * reader made without ProxySQL noticing.
 *
 * This header is duplicated in the ProxySQL repository. Keep the two copies
 * identical.
 */

#include <cstddef>
#include <fstream>
#include <map>
#include <regex>
#include <string>
#include <vector>

/** One "<kind>\t<template>" record from the fixture. */
struct WireContractRecord {
	std::string kind;
	std::string templ;
};

/**
 * Reads the fixture, skipping blank lines and '#' comments.
 *
 * @return false if the file cannot be opened.
 */
inline bool load_wire_contract(const std::string &path, std::vector<WireContractRecord> *out) {
	std::ifstream in(path);
	if (!in) {
		return false;
	}
	std::string line;
	while (std::getline(in, line)) {
		if (!line.empty() && line.back() == '\r') {
			line.pop_back();
		}
		if (line.empty() || line[0] == '#') {
			continue;
		}
		const size_t tab = line.find('\t');
		if (tab == std::string::npos) {
			continue;
		}
		WireContractRecord record;
		record.kind = line.substr(0, tab);
		record.templ = line.substr(tab + 1);
		out->push_back(record);
	}
	return true;
}

namespace wire_contract {

/** Finds the '<' starting a placeholder at or after `from`, or npos. */
inline size_t placeholder_start(const std::string &templ, size_t from) {
	return templ.find('<', from);
}

/** Returns the placeholder name (without angle brackets) starting at `open`. */
inline std::string placeholder_name(const std::string &templ, size_t open) {
	const size_t close = templ.find('>', open);
	if (close == std::string::npos) {
		return std::string();
	}
	return templ.substr(open + 1, close - open - 1);
}

/** Escapes ECMAScript regex metacharacters in a literal run. */
inline std::string regex_escape_literal(const std::string &text) {
	static const std::string kMeta = "\\^$.|?*+()[]{}";
	std::string out;
	for (size_t i = 0; i < text.size(); i++) {
		if (kMeta.find(text[i]) != std::string::npos) {
			out += '\\';
		}
		out += text[i];
	}
	return out;
}

/**
 * Turns a fixture template into a regular expression: every literal character
 * is matched exactly (regex-escaped), and every <placeholder> becomes one or
 * more digits.
 *
 * Matching a run of digits rather than a fixed count is deliberate: how many
 * transactions a server has executed at test time is not reproducible, so the
 * snapshot watermark and streamed sequences differ on every run. The literal
 * skeleton -- kind, separators, field order, and the domain id -- is still
 * matched exactly, which is the part that actually encodes the contract.
 */
inline std::string templ_to_regex(const std::string &templ) {
	std::string pattern;
	size_t i = 0;
	while (i < templ.size()) {
		if (templ[i] == '<') {
			const size_t close = templ.find('>', i);
			if (close == std::string::npos) {
				pattern += regex_escape_literal(templ.substr(i));
				break;
			}
			pattern += "[0-9]+";
			i = close + 1;
			continue;
		}
		const size_t next = placeholder_start(templ, i + 1);
		const size_t end = (next == std::string::npos) ? templ.size() : next;
		pattern += regex_escape_literal(templ.substr(i, end - i));
		i = end;
	}
	return pattern;
}

/** True if `line` matches the fixture template's literal skeleton. */
inline bool matches(const std::string &templ, const std::string &line) {
	return std::regex_match(line, std::regex(templ_to_regex(templ)));
}

/**
 * Substitutes placeholders with concrete values, so a template becomes the
 * exact wire text a reader would send. Unknown placeholders are left in place
 * so a typo fails loudly instead of silently producing a wrong expectation.
 */
inline std::string expand(const std::string &templ,
                          const std::map<std::string, std::string> &values) {
	std::string out;
	size_t i = 0;
	while (i < templ.size()) {
		if (templ[i] == '<') {
			const size_t close = templ.find('>', i);
			if (close == std::string::npos) {
				out += templ.substr(i);
				break;
			}
			const std::string name = placeholder_name(templ, i);
			const auto it = values.find(name);
			out += (it == values.end()) ? templ.substr(i, close - i + 1) : it->second;
			i = close + 1;
			continue;
		}
		out += templ[i];
		i++;
	}
	return out;
}

} // namespace wire_contract

#endif /* GTID_WIRE_CONTRACT_H */
