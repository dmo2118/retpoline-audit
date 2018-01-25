#ifndef ERRNO_EXCEPTION
#define ERRNO_EXCEPTION

#include <cerrno>
#include <exception>

class errno_exception: public std::exception
{
private:
	int _error;

public:
	errno_exception(int error = errno): _error(error)
	{
	}

	const char *what() const noexcept;

	[[noreturn]] static void throw_exception(int error = errno);

	template<typename T> static T check(T result) // There's a few different int types in use here.
	{
		if(result < 0)
			throw_exception();
		return result;
	}

	template<typename T> static T *check(T *result)
	{
		if(!result)
			throw_exception();
		return result;
	}
};

#endif
