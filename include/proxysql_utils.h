#ifndef __PROXYSQL_UTILS_H
#define __PROXYSQL_UTILS_H

#include <type_traits>
#include <memory>
#include <string>

template<class...> struct conjunction : std::true_type { };
template<class B1> struct conjunction<B1> : B1 { };
template<class B1, class... Bn>
struct conjunction<B1, Bn...> 
    : std::conditional<bool(B1::value), conjunction<Bn...>, B1>::type {};

/**
 * @brief Stores the result of formatting the first parameter with the provided
 *  arguments, into the std::string reference provided in the second parameter.
 *
 * @param str The string to be formatted.
 * @param result A std::string reference in which store the formatted result.
 * @param args The additional arguments to be formatted into the string.
 * @return int In case of success 0 is returned, otherwise, the formatting error provided
 *  by 'snprintf' is provided.
 */
template<
	typename... Args,
	typename std::enable_if<conjunction<std::is_trivial<Args>...>::value,int>::type = 0
>
int string_format(const std::string& str, std::string& result, Args... args) {
	int err = 0;
	size_t size = snprintf(nullptr, 0, str.c_str(), args... ) + 1;

	if(size <= 0) {
		err = size;
	} else {
		std::unique_ptr<char[]> buf(new char[size]);
		snprintf(buf.get(), size, str.c_str(), args...);
		result = std::string(buf.get(), buf.get() + size - 1);
	}

	return err;
}

#endif