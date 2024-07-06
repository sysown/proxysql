#include "Base_Session.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"

// Explicitly instantiate the required template class and member functions
template void Base_Session::init<MySQL_Session>();
template void Base_Session::init<PgSQL_Session>();
template MySQL_Backend * Base_Session::find_backend<MySQL_Backend,MySQL_Session>(int);
template PgSQL_Backend * Base_Session::find_backend<PgSQL_Backend,PgSQL_Session>(int);

template MySQL_Backend * Base_Session::create_backend<MySQL_Backend,MySQL_Session,MySQL_Data_Stream>(int, MySQL_Data_Stream *);
template PgSQL_Backend * Base_Session::create_backend<PgSQL_Backend,PgSQL_Session,PgSQL_Data_Stream>(int, PgSQL_Data_Stream *);
template MySQL_Backend * Base_Session::find_or_create_backend<MySQL_Backend,MySQL_Session,MySQL_Data_Stream>(int, MySQL_Data_Stream *);
template PgSQL_Backend * Base_Session::find_or_create_backend<PgSQL_Backend,PgSQL_Session,PgSQL_Data_Stream>(int, PgSQL_Data_Stream *);

Base_Session::Base_Session() {
};

Base_Session::~Base_Session() {
};

template<typename T>
void Base_Session::init() {
	transaction_persistent_hostgroup = -1;
	transaction_persistent = false;
	mybes = new PtrArray(4);
	// Conditional initialization based on derived class
	if constexpr (std::is_same_v<T, MySQL_Session>) {
		sess_STMTs_meta = new MySQL_STMTs_meta();
		SLDH = new StmtLongDataHandler();
	}
};


template<typename B, typename S>
B * Base_Session::find_backend(int hostgroup_id) {
	B *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(B *)mybes->index(i);
		if (_mybe->hostgroup_id==hostgroup_id) {
			return _mybe;
		}
	}
	return NULL; // NULL = backend not found
};

/**
 * @brief Create a new MySQL backend associated with the specified hostgroup ID and data stream.
 * 
 * This function creates a new MySQL backend object and associates it with the provided hostgroup ID
 * and data stream. If the data stream is not provided (_myds is nullptr), a new MySQL_Data_Stream
 * object is created and initialized.
 * 
 * @param hostgroup_id The ID of the hostgroup to which the backend belongs.
 * @param _myds The MySQL data stream associated with the backend.
 * @return A pointer to the newly created MySQL_Backend object.
 */
template<typename B, typename S, typename D>
B * Base_Session::create_backend(int hostgroup_id, D *_myds) {
	B *_mybe = new B();
	proxy_debug(PROXY_DEBUG_NET,4,"HID=%d, _myds=%p, _mybe=%p\n" , hostgroup_id, _myds, _mybe);
	_mybe->hostgroup_id=hostgroup_id;
	if (_myds) {
		_mybe->server_myds=_myds;
	} else {
		_mybe->server_myds = new D();
		_mybe->server_myds->DSS=STATE_NOT_INITIALIZED;
		_mybe->server_myds->init(MYDS_BACKEND_NOT_CONNECTED, static_cast<S*>(this), 0);
	}
	// the newly created backend is added to the session's list of backends (mybes) and a pointer to it is returned.
	mybes->add(_mybe);
	return _mybe;
};

/**
 * @brief Find or create a MySQL backend associated with the specified hostgroup ID and data stream.
 * 
 * This function first attempts to find an existing MySQL backend associated with the provided
 * hostgroup ID. If a backend is found, its pointer is returned. Otherwise, a new MySQL backend
 * is created and associated with the hostgroup ID and data stream. If the data stream is not provided
 * (_myds is nullptr), a new MySQL_Data_Stream object is created and initialized for the new backend.
 * 
 * @param hostgroup_id The ID of the hostgroup to which the backend belongs.
 * @param _myds The MySQL data stream associated with the backend.
 * @return A pointer to the MySQL_Backend object found or created.
 */
template<typename B, typename S, typename D>
B * Base_Session::find_or_create_backend(int hostgroup_id, D *_myds) {
	B * _mybe = find_backend<B,S>(hostgroup_id);
	proxy_debug(PROXY_DEBUG_NET,4,"HID=%d, _myds=%p, _mybe=%p\n" , hostgroup_id, _myds, _mybe);
	// The pointer to the found or newly created backend is returned.
	return ( _mybe ? _mybe : create_backend<B,S,D>(hostgroup_id, _myds) );
};

