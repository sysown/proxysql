#ifndef __CLASS_UNSAFE_SHARED_PTR_H
#define __CLASS_UNSAFE_SHARED_PTR_H

#include <memory>
#include <cstddef>

/**
 * @brief A shared pointer implementation similar to std::shared_ptr but with non-atomic reference counting.
 *
 * This class provides shared ownership semantics for dynamically allocated objects,
 * similar to std::shared_ptr, but uses non-atomic reference counting for performance.
 * This class should only be used for tracking lifetimes of objects which do not have
 * concurrent access from multiple threads.
 *
 * @warning This class is NOT thread-safe.
 *
 * Thread Safety Considerations:
 * - This implementation uses non-atomic reference counting for performance reasons
 * - DO NOT use this class when multiple threads may concurrently access the managed object
 * - Safe usage patterns:
 *   * Single-threaded applications
 *   * Objects accessed by only one thread at a time (thread confinement)
 *   * Read-only access by multiple threads if reference counts are stable
 * - Unsafe patterns to avoid:
 *   * One thread modifies the object while another thread accesses it
 *   * Concurrent calls to copy constructor/copy assignment from multiple threads
 *   * Concurrent calls to destructor/reset from multiple threads
 *
 * ProxySQL Usage Context:
 * - In ProxySQL, this is used for OTelSpanStack objects in session management
 * - Session objects should ensure thread-local access to their span_stack
 * - Global GloOTelTracer provides thread-safe access through its rwlock
 * - Consider migrating to std::shared_ptr with atomic counters if concurrent access becomes necessary
 *
 * @tparam T The type of object being managed
 */
template<typename T>
class unsafe_shared_ptr {
private:
	T* ptr_;
	size_t* ref_count_;

public:
	unsafe_shared_ptr() noexcept : ptr_(nullptr), ref_count_(nullptr) {}

	unsafe_shared_ptr(std::nullptr_t) noexcept : ptr_(nullptr), ref_count_(nullptr) {}

	explicit unsafe_shared_ptr(T* p) : ptr_(p), ref_count_(nullptr) {
    if (ptr_) {
        try {
            ref_count_ = new size_t(1);
        } catch (...) {
            delete ptr_;
            throw;
        }
    }
}

	unsafe_shared_ptr(const unsafe_shared_ptr& other) noexcept
		: ptr_(other.ptr_), ref_count_(other.ref_count_) {
		if (ref_count_)
			++(*ref_count_);
	}

	unsafe_shared_ptr(unsafe_shared_ptr&& other) noexcept
		: ptr_(other.ptr_), ref_count_(other.ref_count_) {
		other.ptr_ = nullptr;
		other.ref_count_ = nullptr;
	}

	unsafe_shared_ptr& operator=(const unsafe_shared_ptr& other) noexcept {
		if (this == &other)
			return *this;

		if (ref_count_ && --(*ref_count_) == 0) {
			delete ptr_;
			delete ref_count_;
		}

		ptr_ = other.ptr_;
		ref_count_ = other.ref_count_;

		if (ref_count_)
			++(*ref_count_);

		return *this;
	}

	unsafe_shared_ptr& operator=(unsafe_shared_ptr&& other) noexcept {
		if (this == &other)
			return *this;

		if (ref_count_ && --(*ref_count_) == 0) {
			delete ptr_;
			delete ref_count_;
		}

		ptr_ = other.ptr_;
		ref_count_ = other.ref_count_;
		other.ptr_ = nullptr;
		other.ref_count_ = nullptr;

		return *this;
	}

	~unsafe_shared_ptr() noexcept {
		if (ref_count_ && --(*ref_count_) == 0) {
			delete ptr_;
			delete ref_count_;
		}
	}

	T& operator*() const noexcept { return *ptr_; }
	T* operator->() const noexcept { return ptr_; }
	T* get() const noexcept { return ptr_; }

	size_t use_count() const noexcept { return ref_count_ ? *ref_count_ : 0; }

	bool unique() const noexcept { return ref_count_ && *ref_count_ == 1; }

	explicit operator bool() const noexcept { return ptr_ != nullptr; }

	void reset() noexcept {
		if (ref_count_ && --(*ref_count_) == 0) {
			delete ptr_;
			delete ref_count_;
		}

		ptr_ = nullptr;
		ref_count_ = nullptr;
	}

	void reset(T* p) {
		unsafe_shared_ptr temp(p);
		std::swap(ptr_, temp.ptr_);
		std::swap(ref_count_, temp.ref_count_);
	}
};

#endif // __CLASS_UNSAFE_SHARED_PTR_H
