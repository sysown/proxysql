#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "StatCounters.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "ProxySQL_Poll.h"
#include "proxysql_structs.h"
#include <poll.h>
#include "cpp.h"

/**
 * @file ProxySQL_Poll.cpp
 *
 * @brief Core I/O Multiplexing Engine for ProxySQL's Event-Driven Architecture
 *
 * The ProxySQL_Poll class is the heart of ProxySQL's event-driven I/O system, managing file descriptors
 * and their associated data streams using the poll() system call. It serves as the central mechanism
 * for handling thousands of concurrent connections efficiently.
 *
 * @section Architecture Integration
 *
 * ProxySQL_Poll is integrated throughout the ProxySQL codebase as follows:
 *
 * - **Thread Classes**: Each MySQL_Thread and PgSQL_Thread contains a ProxySQL_Poll instance
 * - **Data Stream Classes**: MySQL_Data_Stream and PgSQL_Data_Stream maintain pointers to their poll instance
 * - **Main Event Loop**: Forms the core of the poll() loop in both thread types
 *
 * @section Template Specialization
 *
 * ProxySQL_Poll is templated to work with different data stream types:
 * - ProxySQL_Poll<MySQL_Data_Stream> for MySQL protocol connections
 * - ProxySQL_Poll<PgSQL_Data_Stream> for PostgreSQL protocol connections
 *
 * @section Memory Management
 *
 * The class implements sophisticated memory management:
 * - Initial allocation: MIN_POLL_LEN (32) FDs
 * - Dynamic expansion: Uses l_near_pow_2() for power-of-2 sizing
 * - Automatic shrinking: When FD count drops below threshold
 * - Efficient cleanup: Proper deallocation in destructor
 *
 * @section Event Processing Pipeline
 *
 * ProxySQL_Poll integrates into the event processing pipeline:
 * 1. Before Poll: ProcessAllMyDS_BeforePoll() - set up poll events, handle timeouts
 * 2. Poll Execution: poll() system call with dynamic timeout
 * 3. After Poll: ProcessAllMyDS_AfterPoll() - process events, handle new connections
 *
 * @section Key Features
 *
 * - **Scalability**: Efficiently handles thousands of concurrent connections
 * - **Event-Driven**: Non-blocking I/O for high performance
 * - **Bidirectional Integration**: Data streams maintain poll array indices
 * - **Memory Efficiency**: Dynamic resizing optimizes memory usage
 * - **Thread Safety**: Each thread maintains its own poll instance
 *
 * @section Integration with Data Streams
 *
 * Each data stream maintains critical integration fields:
 * - `mypolls`: Pointer to parent ProxySQL_Poll instance
 * - `poll_fds_idx`: Index in poll array for quick lookup
 * - `last_recv/sent`: Timestamps managed by poll system
 *
 * This tight integration enables ProxySQL to achieve high performance by minimizing
 * lookup overhead and maintaining efficient event-driven processing across all connections.
 *
 * For usage patterns and examples, see the documentation in:
 * - MySQL_Thread.cpp
 * - PgSQL_Thread.cpp
 * - MySQL_Data_Stream.cpp
 * - PgSQL_Data_Stream.cpp
 *
 * @see MySQL_Thread
 * @see PgSQL_Thread
 * @see MySQL_Data_Stream
 * @see PgSQL_Data_Stream
 */


/**
 * @brief Shrinks the ProxySQL_Poll object by reallocating memory to fit the current number of elements.
 *
 * This function reduces the size of the ProxySQL_Poll object by reallocating memory to fit the current number of elements.
 * It adjusts the size of internal arrays to a size that is a power of two near the current number of elements.
 *
 * @note Called automatically when FD count drops below MIN_POLL_DELETE_RATIO threshold
 *        (see lib/ProxySQL_Poll.cpp:166 in remove_index_fast())
 */
 template<class T>
void ProxySQL_Poll<T>::shrink() {
	unsigned int new_size=l_near_pow_2(len+1);
	fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
	myds=(T **)realloc(myds,new_size*sizeof(T *));
	last_recv=(unsigned long long *)realloc(last_recv,new_size*sizeof(unsigned long long));
	last_sent=(unsigned long long *)realloc(last_sent,new_size*sizeof(unsigned long long));
	size=new_size;
}

/**
 * @brief Expands the ProxySQL_Poll object to accommodate additional elements.
 *
 * This function expands the ProxySQL_Poll object to accommodate the specified number of additional elements.
 * If the resulting size after expansion exceeds the current size, it reallocates memory to fit the expanded size.
 *
 * @note Called automatically in add() method when current capacity is exhausted
 *        (see lib/ProxySQL_Poll.cpp:114 in add())
 *
 * @param more The number of additional elements to accommodate.
 */
 template<class T>
void ProxySQL_Poll<T>::expand(unsigned int more) {
	if ( (len+more) > size ) {
		unsigned int new_size=l_near_pow_2(len+more);
		fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
		myds=(T **)realloc(myds,new_size*sizeof(T *));
		last_recv=(unsigned long long *)realloc(last_recv,new_size*sizeof(unsigned long long));
		last_sent=(unsigned long long *)realloc(last_sent,new_size*sizeof(unsigned long long));
		size=new_size;
	}
}


/**
 * @brief Constructs a new ProxySQL_Poll object.
 * 
 * This constructor initializes a new ProxySQL_Poll object with default values and allocates memory for internal arrays.
 */
template<class T>
ProxySQL_Poll<T>::ProxySQL_Poll() {
	loop_counters=new StatCounters(15,10);
	poll_timeout=0;
	loops=0;
	len=0;
	pending_listener_add=0;
	pending_listener_del=0;
	size=MIN_POLL_LEN;
	fds=(struct pollfd *)malloc(size*sizeof(struct pollfd));
	myds=(T**)malloc(size*sizeof(T *));
	last_recv=(unsigned long long *)malloc(size*sizeof(unsigned long long));
	last_sent=(unsigned long long *)malloc(size*sizeof(unsigned long long));
}

/**
 * @brief Destroys the ProxySQL_Poll object and frees allocated memory.
 * 
 * This destructor deallocates memory for internal arrays and releases resources associated with the ProxySQL_Poll object.
 */
template<class T>
ProxySQL_Poll<T>::~ProxySQL_Poll() {
	unsigned int i;
	for (i=0;i<len;i++) {
		if (
			myds[i] && // fix bug #278 . This should be caused by not initialized datastreams used to ping the backend
			myds[i]->myds_type==MYDS_LISTENER) {
				delete myds[i];
		}
	}
	free(myds);
	free(fds);
	free(last_recv);
	free(last_sent);
	delete loop_counters;
}

/**
 * @brief Adds a new file descriptor (FD) and its associated data stream to the ProxySQL_Poll object.
 *
 * This function adds a new file descriptor (FD) along with its associated data stream and relevant metadata
 * to the ProxySQL_Poll object. It automatically expands the internal arrays if needed.
 *
 * @section Integration
 * - Sets up bidirectional relationship: data stream -> poll instance via myds[i]->mypolls=this
 * - Sets up index tracking: data stream -> poll array index via myds[i]->poll_fds_idx=i
 * - Initializes timestamps for connection timeout management
 *
 * @section Usage Patterns
 * Called during:
 * - New client connections (MySQL_Thread.cpp:4518)
 * - New server connections (MySQL_Thread.cpp:3600)
 * - Listener socket registration (MySQL_Thread.cpp:3015)
 * - PostgreSQL session establishment (PgSQL_Session.cpp:1094)
 *
 * @param _events The events to monitor for the FD (POLLIN, POLLOUT, POLLIN|POLLOUT)
 * @param _fd The file descriptor (FD) to add
 * @param _myds The data stream object associated with the FD
 * @param sent_time The timestamp when data was last sent on the FD
 */
template<class T>
void ProxySQL_Poll<T>::add(uint32_t _events, int _fd, T *_myds, unsigned long long sent_time) {
	if (len==size) {
		expand(1);
	}
	myds[len]=_myds;
	fds[len].fd=_fd;
	fds[len].events=_events;
	fds[len].revents=0;
	if (_myds) {
		_myds->mypolls=this;
		_myds->poll_fds_idx=len;  // fix a serious bug
	}
	last_recv[len]=monotonic_time();
	last_sent[len]=sent_time;
	len++;
}

/**
 * @brief Updates the file descriptor (FD) at a specific index in the ProxySQL_Poll object.
 *
 * This function updates the file descriptor (FD) at a specific index in the ProxySQL_Poll object.
 * It does not modify any other associated data or metadata.
 *
 * @param idx The index of the file descriptor (FD) to update.
 * @param _fd The new file descriptor (FD) value.
 */
template<class T>
void ProxySQL_Poll<T>::update_fd_at_index(unsigned int idx, int _fd) {
	if ((int)idx == -1 || idx >= len) return;
	fds[idx].fd = _fd;
}

/**
 * @brief Removes a file descriptor (FD) and its associated data stream from the ProxySQL_Poll object.
 *
 * This function removes a file descriptor (FD) along with its associated data stream from the ProxySQL_Poll object.
 * It uses a swap-and-pop technique for efficient removal and may shrink the object if necessary.
 *
 * @section Removal Algorithm
 * 1. Sets data stream's poll_fds_idx to -1 to prevent double-free
 * 2. If not last element, swaps with last element (O(1) removal)
 * 3. Updates swapped element's poll_fds_idx to new position
 * 4. Decrement length and potentially shrink arrays
 *
 * @section Usage Patterns
 * Called during:
 * - Data stream destruction (MySQL_Data_Stream.cpp:337, PgSQL_Data_Stream.cpp:1114)
 * - Thread cleanup operations (MySQL_Thread.cpp:3451)
 * - Connection termination and cleanup
 *
 * @param i The index of the file descriptor (FD) to remove
 */
template<class T>
void ProxySQL_Poll<T>::remove_index_fast(unsigned int i) {
	if ((int)i==-1) return;
	myds[i]->poll_fds_idx=-1; // this prevents further delete
	if (i != (len-1)) {
		myds[i]=myds[len-1];
		fds[i].fd=fds[len-1].fd;
		fds[i].events=fds[len-1].events;
		fds[i].revents=fds[len-1].revents;
		myds[i]->poll_fds_idx=i;  // fix a serious bug
		last_recv[i]=last_recv[len-1];
		last_sent[i]=last_sent[len-1];
	}
	len--;
	if ( ( len>MIN_POLL_LEN ) && ( size > len*MIN_POLL_DELETE_RATIO ) ) {
		shrink();
	}
}

/**
 * @brief Finds the index of a file descriptor (FD) in the ProxySQL_Poll object.
 *
 * This function performs a linear search for a file descriptor (FD) in the ProxySQL_Poll object and returns its index if found.
 * If the FD is not found, it returns -1.
 *
 * @section Performance Notes
 * - O(n) complexity where n is number of FDs in poll set
 * - Used for lookup operations where FD is known but poll index is needed
 * - Data streams maintain their own poll_fds_idx for O(1) access in most cases
 *
 * @section Usage Patterns
 * Called during:
 * - Listener socket operations (MySQL_Thread.cpp:3019)
 * - Connection management and lookup (PgSQL_Thread.cpp:2789)
 * - Debugging and diagnostic operations
 *
 * @param fd The file descriptor (FD) to search for
 * @return The index of the file descriptor (FD) if found, otherwise -1
 */
template<class T>
int ProxySQL_Poll<T>::find_index(int fd) {
	unsigned int i;
	for (i=0; i<len; i++) {
		if (fds[i].fd==fd) {
			return i;
		}
	}
	return -1;
}

template class ProxySQL_Poll<PgSQL_Data_Stream>;
template class ProxySQL_Poll<MySQL_Data_Stream>;
