#include "errno_exception.hpp"

#include <cstring>

const char *errno_exception::what() const throw()
{
	return std::strerror(_error); // Not thread-safe, but we're not multithreaded.
}

[[noreturn]] void errno_exception::throw_exception(int error)
{
	throw errno_exception(error);
}
