#ifndef __PROXYSQL_UTILS_H
#define __PROXYSQL_UTILS_H

#include <type_traits>
#include <memory>
#include <string>
#include <vector>

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

/**
 * @brief Simple struct that holds the 'timeout options' for 'wexecvp'.
 */
struct to_opts {
	/**
	 * @brief Timeout for the script execution to be completed, in case of being
	 *   exceeded, the script will be terminated.
	 */
	uint timeout_us;
	/**
	 * @brief Timeout used for 'select()' non blocking calls.
	 */
	uint select_to_us;
	/**
	 * @brief The duration of the sleeps between the checks being performed
	 *   on the child process waiting it to exit after being signaled to terminate,
	 *   before issuing 'SIGKILL'.
	 */
	uint it_delay_us;
	/**
	 * @brief The timeout to be waited on the child process after being signaled
	 *   with 'SIGTERM' before being forcely terminated by 'SIGKILL'.
	 */
	uint sigkill_timeout_us;
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
 *   - '-3' in case 'fcntl()' call failed .
 *   - '-4' in case of resource exhaustion, file descriptors being used exceeds 'FD_SETSIZE'.
 *   - '-5' in case 'select()' call failed.
 *   - '-6' in case 'read()' from pipes failed with a non-expected error.
 *   - 'ETIME' in case the executable has exceeded the timeout supplied in 'opts.timeout_us'.
 *  In all this cases 'errno' is set to the error reported by the failing 'system call'.
 */
int wexecvp(
	const std::string& file,
	const std::vector<const char*>& argv,
	const to_opts* opts,
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

#endif
