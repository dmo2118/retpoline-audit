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

#if HAVE_MACH_O_LOADER_H
#       include <mach-o/loader.h>
#endif

class audit
{
private:
	typedef file_ptr (*pread_type)(bfd *, void *, void *, file_ptr, file_ptr);

	struct _string
	{
		size_t size;
		malloc_ptr begin;

		void validate()
		{
			assert(!begin.get<char>()[size]);
		}

		_string(malloc_vector &&v): size(v.size() - 1), begin(std::move(v).into_ptr()) // Order is important.
		{
			validate();
		}

		_string(malloc_ptr &&_begin, size_t _size): size(_size), begin(std::move(_begin))
		{
			validate();
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

	unsigned long _max_errors;
	bool _recursive;

	int _result;

	// A custom string_set class could combine a hash table node with string data in the same block of memory, saving one
	// allocation per string. Or I could do things the easy way.
	typedef std::unordered_set<_string, _hash_string> _done_type;
	_done_type _done;
	std::unordered_set<const char *> _done_exe;

	disassemble_info _dinfo;

	std::vector<_string> _rpaths;

	const char *_executable_path;
	size_t _executable_path_size;

	[[noreturn]] static void _truncated();

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

#if HAVE_MACH_O_LOADER_H
	template<typename LC> static void _read_lc(bfd *abfd, void *stream, pread_type pread, LC &lc, file_ptr offset)
	{
		static_assert(
			sizeof(lc) >= sizeof(load_command) &&
				offsetof(load_command, cmd) == offsetof(LC, cmd) &&
				offsetof(load_command, cmdsize) == offsetof(LC, cmdsize),
			"LC not a load command.");

		if(lc.cmdsize < sizeof(lc))
			_truncated(); // TODO: Probably needs a better message. (bfd_error_malformed_archive?)

		_pread(abfd, stream, pread, lc, offset);
	}
#endif

	static _string _expand_dyld_var(
		const char *prefix,
		size_t prefix_size,
		const char *suffix,
		size_t suffix_kill,
		size_t suffix_size);
	void _expand_dyld_vars(_string &path, const char *loader_path, size_t loader_path_size) const;

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

	void run(const char *path);

	int finish() const
	{
		return _result;
	}
};

#endif
