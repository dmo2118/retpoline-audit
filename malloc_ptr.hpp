#ifndef MALLOC_PTR
#define MALLOC_PTR

#include "errno_exception.hpp"

#include <cassert>
#include <cstdlib>
#include <type_traits>

class malloc_ptr
{
private:
	void *_ptr;

	malloc_ptr(const malloc_ptr &) = delete;
	malloc_ptr &operator =(const malloc_ptr &) = delete;

public:
	static void *check(void *ptr)
	{
		return ptr;
	}

	template<typename Proc> malloc_ptr(const Proc &proc) // It's my hot program I'll do what I want.
	{
#ifndef NDEBUG
		_ptr = reinterpret_cast<void *>(0xbaadf00d);
#endif
		proc(_ptr);
		assert(_ptr != reinterpret_cast<void *>(0xbaadf00d));
	}

	malloc_ptr(malloc_ptr &&x): _ptr(x._ptr)
	{
		x._ptr = nullptr;
	}

	malloc_ptr(): _ptr(nullptr)
	{
	}

	~malloc_ptr()
	{
		std::free(_ptr);
	}

	malloc_ptr &operator =(malloc_ptr &&ptr)
	{
		free(_ptr);
		_ptr = ptr._ptr;
		ptr._ptr = nullptr;
		return *this;
	}

	template<typename T> T *get() const
	{
		static_assert(std::is_pod<T>::value, "malloc_ptr can only contain POD types");
		return static_cast<T *>(_ptr);
	}

	void resize(size_t new_size)
	{
		void *new_ptr = std::realloc(_ptr, new_size);
		if(!new_ptr) // POSIX guarantees that errno is set, but C (and C++) does not.
			errno_exception::throw_exception(ENOMEM); // Could also use std::bad_alloc.
		_ptr = new_ptr;
	}
};

#endif
