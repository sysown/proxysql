#ifndef __PROXYSQL_UTILS_H
#define __PROXYSQL_UTILS_H

#include <cstdarg>
#include <type_traits>
#include <memory>
#include <string>
#include <vector>
#include <sys/time.h>

#ifndef ETIME
// ETIME is not defined on FreeBSD
// ETIME is used internaly to report API timer expired
// replace with ETIMEDOUT as closest alternative
#define	ETIME	ETIMEDOUT
#endif

#ifdef CXX17
template<class...> struct conjunction : std::true_type { };
template<class B1> struct std::conjunction<B1> : B1 { };
template<class B1, class... Bn>
struct std::conjunction<B1, Bn...> 
    : std::conditional<bool(B1::value), std::conjunction<Bn...>, B1>::type {};
#else
template<class...> struct conjunction : std::true_type { };
template<class B1> struct conjunction<B1> : B1 { };
template<class B1, class... Bn>
struct conjunction<B1, Bn...> 
    : std::conditional<bool(B1::value), conjunction<Bn...>, B1>::type {};
#endif // CXX17
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
#ifdef CXX17
	typename std::enable_if<std::conjunction<std::is_trivial<Args>...>::value,int>::type = 0
#else
	typename std::enable_if<conjunction<std::is_trivial<Args>...>::value,int>::type = 0
#endif // CXX17
>
int string_format(const std::string& str, std::string& result, Args... args) {
	int size = snprintf(nullptr, 0, str.c_str(), args...);

	if (size <= 0) {
		return size;
	} else {
		size += 1;
		std::unique_ptr<char[]> buf(new char[size]);
		size = snprintf(buf.get(), size, str.c_str(), args...);
		result = std::string(buf.get(), buf.get() + size);
	}

	return size;
}

/**
 * @brief Output struct of 'cstr_format' functions family.
 */
struct cfmt_t {
	// @brief If negative, the error returned from 'snprintf' while formatting. Otherwise the number of bytes
	// copied into the resulting formatted string.
    int size;
	// @brief In case of success the resulting formatted string, empty otherwise.
    std::string str;
};

/**
 * @brief Formats the provided string literal with the extra variadic arguments.
 * @details This is an improved version on 'string_format' function. When used against an string literal,
 *   allows the compiler to issue the proper warnings in case the format parameters are ill-formed.
 * @param fmt The string literal to be formatted with variadic arguments.
 * @param ... The variadic arguments to use for formatting.
 * @return An 'cfmt_t' holding the number of bytes copied to the resulting string and the formatted string
 *   itself. In case of error the 'size' field will hold 'snprintf' returned error and 'str' will be empty.
 */
__attribute__((__format__ (__printf__, 1, 2)))
cfmt_t cstr_format(const char* fmt, ...);

/**
 * @brief Formats the provided string literal with the extra variadic arguments, and place the formatted
 *   string either in the returned 'cfmt_t::string' or in the supplied buffer.
 * @details This is an improved version on 'string_format' function. When used against an string literal,
 *   allows the compiler to issue the proper warnings in case the format parameters are ill-formed.
 * @param out_buf The output buffer in which to place the resulting formatted string in case it fits.
 * @param fmt The string literal to be formatted with variadic arguments.
 * @param ... The variadic arguments to use for formatting.
 * @return On success, an 'cfmt_t' holding the number of bytes copied to the resulting string, in case this
 *   result fits in the provided buffer, this buffer is directly written and the returned 'cfmt_t::str' will
 *   be empty. In case of error the 'size' field will hold 'snprintf' returned error and 'str' will be empty.
 */
template <int N> __attribute__((__format__ (__printf__, 2, 3)))
cfmt_t cstr_format(char (&out_buf)[N], const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    int size = vsnprintf(nullptr, 0, fmt, args);
    va_end(args);

    if (size <= 0) {
        return { size, {} };
    } else {
        size += 1;

        if (size <= N) {
            va_start(args, fmt);
            size = vsnprintf(out_buf, size, fmt, args);
            va_end(args);

            return { size, {} };
        } else {
            std::unique_ptr<char[]> buf(new char[size]);

            va_start(args, fmt);
            size = vsnprintf(buf.get(), size, fmt, args);
            va_end(args);

            if (size <= 0) {
                return { size, {} };
            } else {
                return { size, std::string(buf.get(), buf.get() + size) };
            }
        }
    }
}

/**
 * @brief Simple struct that holds the 'timeout options' for 'wexecvp'.
 */
struct to_opts_t {
	/**
	 * @brief Timeout for the script execution to be completed, in case of being
	 *   exceeded, the script will be terminated.
	 */
	unsigned int timeout_us;
	/**
	 * @brief Timeout used for 'poll()' non blocking calls.
	 */
	suseconds_t poll_to_us;
	/**
	 * @brief The duration of the sleeps between the checks being performed
	 *   on the child process waiting it to exit after being signaled to terminate,
	 *   before issuing 'SIGKILL'.
	 */
	unsigned int waitpid_delay_us;
	/**
	 * @brief The timeout to be waited on the child process after being signaled
	 *   with 'SIGTERM' before being forcely terminated by 'SIGKILL'.
	 */
	unsigned int sigkill_to_us;
};

/**
 * @brief Helper function to launch an executable in a child process through 'fork()' and
 *   'execvp()' and retrieve their 'stderr' and 'stdout' to the caller toguether with
 *   the result of it's execution.
 *
 * @param file The file to be executed.
 * @param argv The arguments to be supplied to the file being executed.
 * @param opts Struct holding timeout options to consider for the launched process.
 * @param s_stdout Output string to hold the output 'stdout' of the child process.
 * @param s_stderr Output string to hold the output 'stderr' of the child process.
 *
 * @return 0 In case of success or one of the following error codes:
 *   - '-1' in case any 'pipe()' creation failed.
 *   - '-2' in case 'fork()' call failed.
 *   - '-3' in case 'fcntl()' call failed.
 *   - '-4' in case 'poll()' call failed.
 *   - '-5' in case 'read()' from pipes failed with a non-expected error.
 *   - 'ETIME' in case the executable has exceeded the timeout supplied in 'opts.timeout_us'.
 *  In all this cases 'errno' is set to the error reported by the failing 'system call'.
 */
int wexecvp(
	const std::string& file,
	const std::vector<const char*>& argv,
	const to_opts_t& opts,
	std::string& s_stdout,
	std::string& s_stderr
);

/**
 * @brief Returns the current timestamp in microseconds.
 * @return The current timestamp in microseconds.
 */
uint64_t get_timestamp_us();

/**
 * @brief Helper function to replace all the occurrences in a string of a matching substring in favor
 *   of another string.
 *
 * @param str The string which copy is going to be searched for matches to be replaced.
 * @param match The substring to be matched inside the string.
 * @param repl The string for which matches are going to be replaced.
 *
 * @return A string in which all the matches of 'match' within 'str' has been replaced by 'repl'.
 */
std::string replace_str(const std::string& str, const std::string& match, const std::string& repl);


std::string generate_multi_rows_query(int rows, int params);
#endif
