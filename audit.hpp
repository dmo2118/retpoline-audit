#ifndef AUDIT_HPP
#define AUDIT_HPP

// BFD needs this as of the fix for https://sourceware.org/bugzilla/show_bug.cgi?id=14072. (Kind of looks like the binutils folx
// forgot that BFD can be consumed by non-binutils software.)
#undef PACKAGE
#undef PACKAGE_VERSION
#define PACKAGE
#define PACKAGE_VERSION

// dis-asm.h needs this.
#include <cstring>
using std::strchr;

#include <bfd.h>
#include <dis-asm.h>

#undef PACKAGE
#undef PACKAGE_VERSION

#include "malloc_vector.hpp"

// bfd.h and dis-asm.h both bring in C headers, so there's a bunch of places where "std::" just isn't necessary.
#include <cstdlib>
#include <unordered_set>
#include <vector>

#include "config.h" // Bring in the real PACKAGE/PACKAGE_VERSION.

class audit
{
private:
	typedef file_ptr (*pread_type)(bfd *, void *, void *, file_ptr, file_ptr);

	unsigned long _max_errors;
	bool _recursive;

	int _result;

	struct _string
	{
		size_t size;
		malloc_ptr begin;

		_string(malloc_vector &&v): size(v.size()), begin(std::move(v).into_ptr()) // Order is important.
		{
		}

		_string(malloc_ptr &&_begin, size_t _size): size(_size), begin(std::move(_begin))
		{
		}

		size_t hash() const;

		bool operator ==(const _string &x) const
		{
			return size == x.size && !memcmp(begin.get<void>(), x.begin.get<void>(), size);
		}
	};

	struct _hash_string
	{
	public:
		size_t operator ()(const _string &s) const
		{
			return s.hash();
		}
	};

	// A custom string_set class could combine a hash table node with string data in the same block of memory, saving one
	// allocation per string. Or I could do things the easy way.
	typedef std::unordered_set<_string, _hash_string> _done_type;
	_done_type _done;
	std::unordered_set<const char *> _done_exe;

	disassemble_info _dinfo;

	void _prefix(const char *text);
	void _error(const char *prefix, const char *message);
	void _errorf(const char *prefix, const char *format, ...);

	static int _print_nothing(void *, const char *, ...);
	bool _found_indirect(
		const char *path,
		const asection *section,
		bfd_vma vma,
		unsigned long &error_count,
		std::vector<const char *> &bad_sections);

	static void _pread(bfd *abfd, void *stream, pread_type pread, void *buf, file_ptr nbytes, file_ptr offset);
	template<typename T> static void _pread(bfd *abfd, void *stream, pread_type pread, T &buf, file_ptr offset)
	{
		_pread(abfd, stream, pread, &buf, sizeof(T), offset);
	}

	void _add_dependency(_string &&path);
	void _add_dependency(malloc_vector &&path);
	static malloc_vector _read_null_str(bfd *abfd, void *stream, pread_type pread, file_ptr offset);
	void _do_bfd(bfd *abfd, void *stream, pread_type pread, bool check_insn);
	void _run(const char *path, bool check_insn);

public:
	audit(unsigned long max_errors, bool recursive): _max_errors(max_errors), _recursive(recursive), _result(EXIT_SUCCESS)
	{
		init_disassemble_info(&_dinfo, nullptr, _print_nothing);
		// init_disassemble_info(&dinfo, stderr, (fprintf_ftype)fprintf);
	}

	void run(const char *path)
	{
		_done_exe.clear();
		_run(path, true);
	}

	int finish() const
	{
		return _result;
	}
};

#endif
