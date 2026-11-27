#ifndef EMBEDDED_FLOAT_TEXT_H
#define EMBEDDED_FLOAT_TEXT_H

#include <charconv>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>

namespace embedded {
namespace detail {

template <typename T>
auto format_float_text(char* first, char* last, T value, int)
    -> decltype(std::to_chars(first, last, value)) {
    return std::to_chars(first, last, value);
}

template <typename T>
std::to_chars_result format_float_text(char* first, char* last, T value, long) {
    // Older standard libraries provide only the integer to_chars overloads.
    // Use the classic locale and enough digits to round-trip the value.
    std::ostringstream stream;
    stream.imbue(std::locale::classic());
    stream << std::setprecision(std::numeric_limits<T>::max_digits10) << value;
    if (!stream) return {last, std::errc::io_error};

    const auto text = stream.str();
    if (text.size() > static_cast<std::size_t>(last - first)) {
        return {last, std::errc::value_too_large};
    }
    std::memcpy(first, text.data(), text.size());
    return {first + text.size(), {}};
}

} // namespace detail

inline std::to_chars_result format_embedded_double(char* first, char* last,
                                                   double value) {
    return detail::format_float_text(first, last, value, 0);
}

} // namespace embedded

#endif
