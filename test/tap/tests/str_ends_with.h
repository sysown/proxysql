#pragma once

#include <string>

// Whether s ends with suffix. A string shorter than suffix gives false: taking the last
// suffix.size() characters of it with substr() would throw std::out_of_range and abort the test.
inline bool ends_with(const std::string& s, const std::string& suffix) {
	return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}
