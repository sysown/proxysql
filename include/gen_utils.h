#ifndef __CLASS_PTR_ARRAY_H
#define __CLASS_PTR_ARRAY_H

#include <memory>
#include <queue>
#include "proxysql.h"
#include "sqlite3db.h"

#define MIN_ARRAY_LEN 8
#define MIN_ARRAY_DELETE_RATIO  8

static unsigned int l_near_pow_2 (unsigned int n) {
	unsigned int i = 1;
	while (i < n) i <<= 1;
	return i ? i : n;
}


#ifndef def_fastrand
inline int fastrand() {
	g_seed = (214013*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}
#define def_fastrand
#endif

/**
 * @brief Thread-local state for the xoshiro128++ PRNG.
 *
 * s[0..3] hold the internal 128-bit state. Keeping it thread_local guarantees
 * that each thread uses an independent sequence without synchronization.
 */
static thread_local uint32_t s[4];

/**
 * @brief Thread-local flag indicating whether the PRNG state has been seeded.
 *
 * Lazy initialization is used to seed the state on the first use per thread.
 */
static thread_local uint8_t seeded = 0;

/**
 * @brief Initialize the thread-local PRNG state.
 *
 * Seeds the 128-bit xoshiro state using a mix of the monotonic clock and the
 * calling thread identifier. A splitmix-like mixing function is applied to
 * produce well-dispersed bits. Ensures the state is not all zeros.
 *
 * Important:
 * - Uses CLOCK_MONOTONIC to reduce susceptibility to wall-clock changes.
 * - Not cryptographically secure. Do not use for security-sensitive code.
 */
static void init_seed(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);

	uint64_t t = ((uint64_t)ts.tv_nsec) ^ ((uint64_t)ts.tv_sec << 32);
	uint64_t tid = (uintptr_t)pthread_self();

	// Simple mixing: XOR, shifts, multiplies
	uint64_t x = t ^ tid;
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdULL;
	x ^= x >> 33;
	x *= 0xc4ceb9fe1a85ec53ULL;
	x ^= x >> 33;

	// Split into four 32-bit words
	s[0] = (uint32_t)x;
	s[1] = (uint32_t)(x >> 32);
	s[2] = ~s[0];  // invert for extra diversity
	s[3] = ~s[1];

	// avoid all-zero state
	if (!s[0] && !s[1] && !s[2] && !s[3])
		s[0] = 1;

	seeded = 1;
}

/**
 * @brief Rotate left utility.
 *
 * @param x Value to rotate.
 * @param k Rotation amount in bits (0..31).
 * @return x rotated left by k bits.
 */
static inline uint32_t rotl(uint32_t x, int k) {
	return (x << k) | (x >> (32 - k));
}

/**
 * @brief xoshiro128++ PRNG round function.
 *
 * This is the "++" variant: result = rotl(s0 + s3, 7) + s0.
 * It updates the internal state using xorshift operations and a rotation.
 * The algorithm is designed for speed and statistical quality.
 *
 * Thread safety:
 * - Uses thread-local state; no locks required.
 *
 * @return A 32-bit pseudo-random number.
 */
static uint32_t xoshiro128_plus_plus(void) {
	if (!seeded) init_seed();

	const uint32_t result = rotl(s[0] + s[3], 7) + s[0];
	const uint32_t t = s[1] << 9;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];
	s[2] ^= t;
	s[3] = rotl(s[3], 11);

	return result;
}

/**
 * @brief Fast, non-cryptographic random number generator.
 *
 * Convenience wrapper over xoshiro128_plus_plus(). Returns a 32-bit
 * pseudo-random value. On first call per thread, the generator is seeded.
 *
 * @return A 32-bit pseudo-random number.
 */
static inline uint32_t rand_fast() {
	return xoshiro128_plus_plus();
}

class PtrArray {
	private:
	void expand(unsigned int more) {
		if ( (len+more) > size ) {
			unsigned int new_size=l_near_pow_2(len+more);
			void *new_pdata=malloc(new_size*sizeof(void *));
			memset(new_pdata,0,new_size*sizeof(void *));
			if (pdata) {
				memcpy(new_pdata,pdata,size*sizeof(void *));
				free(pdata);
			}
			size=new_size;
			pdata=(void **)new_pdata;
		}
	}
	void shrink() {
		unsigned int new_size=l_near_pow_2(len+1);
		pdata=(void **)realloc(pdata,new_size*sizeof(void *));
		size=new_size;
	}
	public:
	unsigned int len;
	unsigned int size;
	void **pdata;
	PtrArray(unsigned int __size=0) {
		len=0;
		pdata=NULL;
		size=0;
		if (__size) {
			expand(__size);
		}
		size=__size;
	}
	~PtrArray() {
		if (pdata) ( free(pdata) );
		pdata=NULL;
	}

	void reset() {
		len=0;
		if (pdata) ( free(pdata) );
		pdata=NULL;
		size=0;
	}

	void *index(unsigned int i) { return pdata[i];}

	void add(void *p) {
		if (len==size) {
			expand(1);
		}
		pdata[len++]=p;
	}

	bool remove(void *p) {
		unsigned int i;
		for (i=0; i<len; i++) {
			if (pdata[i]==p) {
				remove_index(i);
				return true;
			}
		}
		return false;
	}

	void * remove_index(unsigned int i) {
		void *r=pdata[i];
		if (i != (len-1)) {
			memmove((void **)pdata+i,(void **)pdata+i+1,(len-i-1)*sizeof(void *));
		}
		len--;
		if ( ( len>MIN_ARRAY_LEN ) && ( size > len*MIN_ARRAY_DELETE_RATIO ) ) {
			shrink();
		}
		return r;
	}

	bool remove_fast(void *p) {
		unsigned int i;
		for (i=0; i<len; i++) {
			if (pdata[i]==p) {
				remove_index_fast(i);
				return true;
			}
		}
		return false;
	}

	void * remove_index_fast(unsigned int i) {
		void *r=pdata[i];
		if (i != (len-1))
			pdata[i]=pdata[len-1];
		len--;
		if ( ( len>MIN_ARRAY_LEN ) && ( size > len*MIN_ARRAY_DELETE_RATIO ) ) {
			//shrink(); // FIXME: when shrink is called, is r invalid ??
		}
		return r;
	}
};


class PtrSizeArray {
	private:
	void expand(unsigned int);
	void shrink();
	public:
	void * operator new(size_t);
	void operator delete(void *);
	unsigned int len;
	unsigned int size;
	PtrSize_t *pdata;
	PtrSizeArray(unsigned int __size=0);
	~PtrSizeArray();

	void add(void *p, unsigned int s) {
		if (len==size) {
			expand(1);
		}
		pdata[len].ptr=p;
		pdata[len].size=s;
		len++;
//#ifdef DEBUG
//		mysql_hdr *m=(mysql_hdr *)p;
//		fprintf(stderr,"%u %u\n", m->pkt_id, m->pkt_length);
//#endif /* DEBUG */
	};

	void remove_index(unsigned int i, PtrSize_t *ps) {
		if (ps) {
			ps->ptr=pdata[i].ptr;
			ps->size=pdata[i].size;
		}
		if (i != (len-1)) {
			memmove(pdata+i,pdata+i+1,(len-i-1)*sizeof(PtrSize_t));
		}
		len--;
	};

	void remove_index_range(unsigned int i, unsigned int s) {
		if (i != (len-s)) {
			memmove(pdata+i,pdata+i+s,(len-i-s)*sizeof(PtrSize_t));	
		}
		len-=s;
	};

	void remove_index_fast(unsigned int, PtrSize_t *);
	void copy_add(PtrSizeArray *, unsigned int, unsigned int);

	PtrSize_t * index(unsigned int i) {
		return &pdata[i];
	}
	unsigned int total_size(unsigned int _min_size=0) {
		unsigned int intsize=0;
		unsigned int i=0;
		for (i = 0 ; i < len ; i++) {
			PtrSize_t *pts = index(i);
			if (pts->size > _min_size) {
				intsize += pts->size;
			} else {
				intsize += _min_size;
			}
		}
		return intsize;
	}
};

struct buffer_t {
	void * data = nullptr;
	size_t len = 0;
	size_t capacity = 0;
};

class FixedSizeQueue : public std::queue<buffer_t> {
private:
	using std::queue<buffer_t>::push;
	using std::queue<buffer_t>::emplace;
	using std::queue<buffer_t>::swap;
	size_t _max_size = 0;

public:
	FixedSizeQueue() = default;
	FixedSizeQueue(size_t max_size) : _max_size(max_size) {}
	~FixedSizeQueue() {
		while (empty() == false) {
			auto& node = front();
			l_free(node.len, node.data);
			pop();
		}
	}
	
	inline
	size_t get_max_size() const {
		return _max_size;
	}

	void set_max_size(size_t max_size) {
		if (_max_size == max_size)
			return;

		_max_size = max_size;

		if (size() > max_size) {
			while (size() != max_size) {
				auto& node = front();
				l_free(node.len, node.data);
				pop();
			}
		}
	}

	// using template here to create compile-time separate definition of push, one for true and one for false
	template<bool ALLOC_MEM = true>
	void push(void* buff, size_t len) {
		if (_max_size == 0) return;
		assert(buff && len);

		buffer_t mybuff;

		if (size() == _max_size) {
			mybuff = front();
			pop();
		}

		if (ALLOC_MEM == true) {
			if (mybuff.capacity < len) {
				if (mybuff.data) free(mybuff.data);

				mybuff.data = l_alloc(len);
				mybuff.capacity = len;
			}

			memcpy(mybuff.data, buff, len);
			mybuff.len = len;

		} else {
			if (mybuff.data) free(mybuff.data);

			mybuff.data = buff;
			mybuff.capacity = mybuff.len = len;
		}

		emplace(mybuff);
	}
};

#endif /* __CLASS_PTR_ARRAY_H */


#ifdef CLOCK_MONOTONIC_RAW
#define PROXYSQL_CLOCK_MONOTONIC CLOCK_MONOTONIC_RAW
#else
#define PROXYSQL_CLOCK_MONOTONIC CLOCK_MONOTONIC
#endif

#ifndef __GEN_FUNCTIONS
#define __GEN_FUNCTIONS

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/_types/_timespec.h>
#include <mach/mach.h>
#include <mach/clock.h>
#include <mach/mach_time.h>

#ifndef mach_time_h
#define mach_time_h 
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC SYSTEM_CLOCK
#endif // CLOCK_MONOTONIC

static void clock_gettime(int clk_id, struct timespec *tp) {
	clock_serv_t cclock;
	mach_timespec_t mts;
	host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
	//retval = clock_get_time(cclock, &mts);
	mach_port_deallocate(mach_task_self(), cclock);
	tp->tv_sec = mts.tv_sec;
	tp->tv_nsec = mts.tv_nsec;
}
#endif /* mach_time_t */
#endif /* __APPLE__ */


inline unsigned long long monotonic_time() {
  struct timespec ts;
  clock_gettime(PROXYSQL_CLOCK_MONOTONIC, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

inline unsigned long long realtime_time() {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

template<int FACTOR, typename T>
inline T overflow_safe_multiply(T val) {
	static_assert(std::is_integral<T>::value, "T must be an integer type.");
	static_assert(std::is_unsigned_v<T>, "T must be an unsigned integer type.");
	static_assert(FACTOR > 0, "Negative factors are not supported.");

	if constexpr (FACTOR == 0) return 0;
	if (val == 0)  return 0;
	if (val > std::numeric_limits<T>::max() / FACTOR) return std::numeric_limits<T>::max();
	return (val * FACTOR);
}

/**
 * @brief Read a 64-bit unsigned integer from a big-endian byte buffer.
 *
 * Reads 8 bytes from the provided buffer and converts them from
 * big-endian (network byte order) into host byte order.
 *
 * @param pkt   Pointer to at least 8 bytes of input data.
 * @param dst_p Pointer to the destination uint64_t where the result
 *              will be stored.
 *
 * @return true Always returns true.
 */
inline bool get_uint64be(const unsigned char* pkt, uint64_t* dst_p) {
	*dst_p =
		((uint64_t)pkt[0] << 56) |
		((uint64_t)pkt[1] << 48) |
		((uint64_t)pkt[2] << 40) |
		((uint64_t)pkt[3] << 32) |
		((uint64_t)pkt[4] << 24) |
		((uint64_t)pkt[5] << 16) |
		((uint64_t)pkt[6] << 8)  |
		((uint64_t)pkt[7]);
	return true;
}

/*
 * @brief Reads and converts a big endian 32-bit unsigned integer from the provided packet buffer into the destination pointer.
 *
 * This function is used to extract the big endian 32-bit unsigned integer value at the specified position in a given
 * packet buffer, and stores it in the destination pointer passed as an argument.
 *
 * @param[in] pkt A pointer to the start of the input packet buffer from which to read the 32-bit integer.
 *
 * @param[out] dst_p A pointer where the extracted big endian 32-bit unsigned integer value will be stored.
 */
inline bool get_uint32be(const unsigned char* pkt, uint32_t* dst_p) {
	*dst_p = ((uint32_t)pkt[0] << 24) |
		((uint32_t)pkt[1] << 16) |
		((uint32_t)pkt[2] << 8) |
		((uint32_t)pkt[3]);
	return true;
}

/**
 * @brief Extracts a 16-bit unsigned integer from a packet and stores it in the provided destination pointer.
 *
 * This function reads two bytes from the packet `pkt` starting from the beginning, interprets them as a big-endian unsigned 16-bit integer,
 * and stores the result into the memory location pointed to by `dst_p`. It consistently returns true to indicate successful execution.
 *
 * @param pkt Pointer to the packet data (array of unsigned chars) from which the 16-bit integer will be extracted.
 *             The caller must ensure this pointer is valid and points to at least two bytes of data.
 * @param dst_p Pointer to a uint16_t variable where the extracted integer will be stored. The caller must ensure that
 *             this pointer is valid and points to a uint16_t variable.
 *
 * @return Always returns true to indicate success.
 *
 * @note This function uses big-endian byte order (network byte order) for interpreting the packet data.
 *       It is assumed that the packet buffer `pkt` contains at least two bytes (the size of a uint16_t).
 *       The function uses post-increment to move the reading position after extracting each byte.
 */
inline bool get_uint16be(const unsigned char* pkt, uint16_t* dst_p) {
	*dst_p = ((uint16_t)pkt[0] << 8) |
			 ((uint16_t)pkt[1]);
	return true;
}

bool Proxy_file_exists(const char *);
bool Proxy_file_regular(const char *);

char *escape_string_single_quotes(char *input, bool free_it);
int remove_spaces(const char *);
char *trim_spaces_in_place(char *str);
char *trim_spaces_and_quotes_in_place(char *str);
bool mywildcmp(const char *p, const char *str);
std::string trim(const std::string& s);
char* escape_string_single_quotes_and_backslashes(char* input, bool free_it);
const char* escape_string_backslash_spaces(const char* input);
std::string strip_schema_from_query(const char* query, const char* schema,
                                    const std::vector<std::string>& tables = {}, bool ansi_quotes = false);
/**
 * @brief Helper function that converts a MYSQL_RES into a 'SQLite3_result'.
 * @param resultset The resultset to be converted into a 'SQLite3_result'.
 * @return An 'unique_ptr' holding the resulting 'SQLite3_result'.
 */
std::unique_ptr<SQLite3_result> get_SQLite3_resulset(MYSQL_RES* resultset);

std::vector<std::string> split_string(const std::string& str, char delimiter);

inline constexpr bool fast_isspace(unsigned char c) noexcept
{
	// Matches: '\t' (0x09) through '\r' (0x0D), and ' ' (0x20)
	// That is: '\t', '\n', '\v', '\f', '\r', ' '
	//
	// (c - '\t') < 5   -> true for 0x09-0x0D inclusive
	// (c == ' ')       -> true for space
	//
	// Use bitwise OR `|` (not logical `||`) to keep it branchless.
	return (c == ' ') | (static_cast<unsigned char>(c - '\t') < 5);
}

inline constexpr char* fast_uint32toa(uint32_t value, char* out) noexcept {
	char* p = out;
	do {
		*p++ = '0' + (value % 10);
		value /= 10;
	} while (value);
	*p = '\0';
	char* start = out;
	char* end = p - 1;
	while (start < end) {
		char t = *start;
		*start++ = *end;
		*end-- = t;
	}
	return p;
}

#endif /* __GEN_FUNCTIONS */
