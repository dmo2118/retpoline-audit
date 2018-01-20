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

#include <unordered_set>
#include <vector>

#include "config.h" // Bring in the real PACKAGE/PACKAGE_VERSION.

class audit
{
private:
	unsigned long _max_errors;
	bool _recursive;

	// A custom string_set class could combine a hash table node with string data in the same block of memory, saving one
	// allocation per string. Or I could do things the easy way.
	std::unordered_set<std::string> _pending;
	std::vector<const char *> _todo;

	disassemble_info _dinfo;

	bool _do_bfd(bfd *new_bfd);

	static int _print_nothing(void *, const char *, ...);
	bool _found_indirect(
		const char *path,
		const asection *section,
		bfd_vma vma,
		unsigned long &error_count,
		std::vector<const char *> &bad_sections);

public:
	audit(unsigned long max_errors, bool recursive): _max_errors(max_errors), _recursive(recursive)
	{
		init_disassemble_info(&_dinfo, nullptr, _print_nothing);
		// init_disassemble_info(&dinfo, stderr, (fprintf_ftype)fprintf);
	}

	bool run(const char *path);

	void finish(int &result)
	{
		while(!_todo.empty())
		{
			const char *path = _todo.back();
			_todo.pop_back();
			if(!run(path))
				result = EXIT_FAILURE;
		}
	}
};

#endif
