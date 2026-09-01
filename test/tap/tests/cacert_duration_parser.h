#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>

inline std::optional<uint64_t> parse_proxysqltest_duration_ms(std::string_view response) {
	constexpr std::string_view start_marker { "Took " };
	constexpr std::string_view end_marker { "ms " };

	const std::size_t start_pos { response.find(start_marker) };
	const std::size_t duration_start { start_pos + start_marker.size() };
	const std::size_t end_pos { response.find(end_marker) };
	if (start_pos == std::string_view::npos || end_pos == std::string_view::npos ||
		duration_start >= end_pos) {
		return std::nullopt;
	}

	const std::string_view duration { response.substr(duration_start, end_pos - duration_start) };
	if (duration.front() == '-') {
		return std::nullopt;
	}

	uint64_t value {};
	const auto [parsed_end, error] {
		std::from_chars(duration.data(), duration.data() + duration.size(), value)
	};
	if (error != std::errc {} || parsed_end != duration.data() + duration.size()) {
		return std::nullopt;
	}

	return value;
}
