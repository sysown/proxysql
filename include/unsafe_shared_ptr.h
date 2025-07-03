#ifndef __CLASS_UNSAFE_SHARED_PTR_H
#define __CLASS_UNSAFE_SHARED_PTR_H

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
 * @tparam T The type of object being managed
 */
template<typename T>
class unsafe_shared_ptr {
private:
	T* ptr_;
	size_t* ref_count_;

public:
	unsafe_shared_ptr() noexcept : ptr_(nullptr), ref_count_(nullptr) {}

	explicit unsafe_shared_ptr(T* p) : ptr_(p), ref_count_(p ? new size_t(1) : nullptr) {}

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
		if (ref_count_ && --(*ref_count_) == 0) {
			delete ptr_;
			delete ref_count_;
		}

		ptr_ = p;
		ref_count_ = p ? new size_t(1) : nullptr;
	}
};

#endif // __CLASS_UNSAFE_SHARED_PTR_H
