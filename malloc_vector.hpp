#ifndef MALLOC_VECTOR_HPP
#define MALLOC_VECTOR_HPP

#include "malloc_ptr.hpp"

#include <algorithm>

// Pointless optimization alert: std::vector<char> zeros out its memory; this doesn't.
class malloc_vector
{
private:
	malloc_ptr _ptr;
	size_t _size, _capacity;

public:
	malloc_vector(): _size(0), _capacity(0)
	{
	}

	void *append0(size_t n)
	{
		size_t new_size = _size + n;
		if(new_size > _capacity)
		{
			_capacity = std::max(_capacity * 2, new_size);
			_ptr.resize(_capacity);
		}
		return _ptr.get<char>() + _size;
	}

	void append1(size_t n)
	{
		_size += n;
		assert(_size <= _capacity);
	}

	size_t size() const
	{
		return _size;
	}

	size_t capacity() const
	{
		return _capacity;
	}

	template<typename T> T *data()
	{
		return _ptr.get<T>();
	}
};

#endif
