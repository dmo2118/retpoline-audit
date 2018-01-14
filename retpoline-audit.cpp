#include <bfd.h>
#include <getopt.h>
#include <dis-asm.h>

#include <cassert>
#include <cstdio> // Not in the mood for <iostream> right now.
#include <cstdlib>
#include <cstdarg>
#include <cstring>
#include <type_traits>
#include <unordered_set>

namespace // Lots of little functions and classes, too small to warrant their own header files.
{
	template<typename T, size_t N> constexpr inline size_t _arraysize(T (&)[N])
	{
		return N;
	}

	template<typename T> inline void _verify(T x)
	{
	#ifndef NDEBUG
	if(!x)
		abort();
	#endif
	}

	class _malloc_ptr
	{
	private:
		void *_ptr;

	public:
		template<typename Proc> _malloc_ptr(const Proc &proc) // It's my hot program I'll do what I want.
		{
#ifndef NDEBUG
			_ptr = reinterpret_cast<void *>(0xbaadf00d);
#endif
			proc(_ptr);
			assert(_ptr != reinterpret_cast<void *>(0xbaadf00d));
		}

		_malloc_ptr(): _ptr(nullptr)
		{
		}

		~_malloc_ptr()
		{
			free(_ptr);
		}

		_malloc_ptr &operator =(_malloc_ptr &&ptr)
		{
			free(_ptr);
			_ptr = ptr._ptr;
			ptr._ptr = nullptr;
			return *this;
		}

		template<typename T> T *get() const
		{
			static_assert(std::is_pod<T>::value);
			return static_cast<T *>(_ptr);
		}
	};

	/*
	class _stdio_stream
	{
	private:
		FILE *_stream;

	public:
		_stdio_stream(FILE *stream): _stream(stream)
		{
		}

		~_stdio_stream()
		{
		}

		FILE *get() const
		{
			return _stream;
		}
	};
	*/

	/*
	class _errno_exception: public std::exception
	{
	private:
		int _error;

	public:
		_errno_exception(int error = errno): _error(error)
		{
		}

		const char *what() const throw()
		{
			return strerror(_error);
		}
	};
	*/

	class _static_string_exception: public std::exception
	{
	private:
		const char *_what;

	public:
		_static_string_exception(const char *what): _what(what)
		{
		}

		const char *what() const throw()
		{
			return _what;
		}
	};

	class _bfd
	{
	private:
		bfd *_p;

	public:
		class exception: public _static_string_exception // Must be captured early for bfd_error_system_call.
		{
		private:
			bfd_error_type _error;

		public:
			exception(bfd_error_type error = bfd_get_error()): _static_string_exception(bfd_errmsg(error)), _error(error)
			{
			}

			bfd_error_type error() const
			{
				return _error;
			}
		};

		_bfd(const char *filename, const char *target = nullptr):
			_p(check(bfd_openr(filename, target)))
		{
		}

		~_bfd()
		{
			_verify(bfd_close(_p));
		}

		operator bfd *() const
		{
			return _p;
		}

		bfd *operator ->() const
		{
			return _p;
		}

		/*
		static int check(int x)
		{
			if(x < 0)
				throw_exception();
			return x;
		}
		*/

		static void check(bfd_boolean x)
		{
			if(!x)
				throw_exception();
		}

		template<typename T> static T *check(T *ptr)
		{
			if(!ptr)
				throw_exception();
			return ptr;
		}

		[[noreturn]] static void throw_exception(bfd_error_type error = bfd_get_error());
	};

	[[noreturn]] void _bfd::throw_exception(bfd_error_type error)
	{
		throw _bfd::exception(error);
	}

	const char *_program_name;

	static void _print_help()
	{
		fputs("Usage: ", stdout);
		fputs(_program_name, stdout);
		fputs(" [--help] [--version] [-n max_errors] [file...]\n", stdout);
	}

	void _prefix(char **argv, bool warning)
	{
		fputs(*argv, stderr);
		fputs(": ", stderr);
		if(warning)
			fputs("warning: ", stderr);

	}

	void _warn(char **argv, const char *msg, bool warning = true)
	{
		_prefix(argv, warning);
		fputs(msg, stderr);
		fputc('\n', stderr);
	}

	void _error(char **argv, const char *msg)
	{
		_warn(argv, msg, false);
	}

	struct _insn_str
	{
		char buf[40];
		size_t size;
	};

	/*
	int _print_insn(void *str_raw, const char *fmt, ...)
	{
		_insn_str &str = *static_cast<_insn_str *>(str_raw);

		va_list ap;
		va_start(ap, fmt);
		int result = vsnprintf(str.buf + str.size, _arraysize(str.buf) - str.size, fmt, ap);
		va_end(ap);

		if(result < 0)
			return 0;
		str.size += result;
		return result;
	}
	*/

	int _print_nothing(void *, const char *, ...)
	{
		return 0;
	}

	[[noreturn]] void _unsupported_insn()
	{
		throw _static_string_exception("unsupported instruction set");
	}

	bool _found_indirect(
		char **argv,
		const asection *section,
		bfd_vma vma,
		unsigned long &error_count,
		unsigned long max_errors)
	{
		if(!max_errors)
			throw _static_string_exception("indirect branch found");

		if(error_count == max_errors)
		{
			_prefix(argv, false);
			fputs("maximum error count reached for section ", stderr);
			fputs(section->name, stderr);
			fputc('\n', stderr);
			return false;
		}

		// TODO: Handle max_errors == 0

		_prefix(argv, false);
		fprintf(
			stderr,
			"indirect branch at %s:0x%.8llx\n",
			section->name,
			static_cast<unsigned long long>(vma));

		++error_count;
		if(max_errors == 1) // Skip the 'maximum error count' message in this instance.
			return false;

		return true;
	}
}

int main(int argc, char **argv)
{
	_program_name = argv[0];

	unsigned long max_errors = 4;

	for(;;)
	{
		static const struct option longopts[] =
		{
			{"help", no_argument, nullptr, 'h'},
			{"version", no_argument, nullptr, 'v'},
			{nullptr, 0, nullptr, 0}
		};

		int optc = getopt_long(argc, argv, "hn:vV", longopts, nullptr);
		if(optc < 0)
			break;

		switch(optc)
		{
		case 'h':
			_print_help();
			return EXIT_SUCCESS;

		case 'n':
			char *end;
			max_errors = strtoul(optarg, &end, 0);
			if(*end)
			{
				_print_help();
				return EXIT_FAILURE;
			}
			break;

		case 'V':
		case 'v':
			fputs(
				"retpoline-audit 0.1.0\n"
				"Copyright (C) 2018  Dave Odell <dmo2118@gmail.com>\n"
				"\n"
				"This program is free software: you can redistribute it and/or modify\n"
				"it under the terms of the GNU General Public License as published by\n"
				"the Free Software Foundation, either version 3 of the License, or\n"
				"(at your option) any later version.\n"
				"\n"
				"This program is distributed in the hope that it will be useful,\n"
				"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
				"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
				"GNU General Public License for more details.\n"
				"\n"
				"You should have received a copy of the GNU General Public License\n"
				"along with this program.  If not, see <https://www.gnu.org/licenses/>.\n",
				stdout);
			return EXIT_SUCCESS;

		default:
			return EXIT_FAILURE;
		}
	}

	argv += optind;
	if(*argv == nullptr)
	{
		_print_help();
		return EXIT_FAILURE;
	}

	bfd_init();
	disassemble_info dinfo;
	init_disassemble_info(&dinfo, NULL, _print_nothing);
	// init_disassemble_info(&dinfo, stderr, (fprintf_ftype)fprintf);

	int result = EXIT_SUCCESS;

	do
	{
		try
		{
			_bfd abfd(*argv);

			_bfd::check(bfd_check_format(abfd, bfd_object));

			bfd_architecture arch = bfd_get_arch(abfd);
			unsigned long mach = bfd_get_mach(abfd);

			if(arch != bfd_arch_i386)
				_unsupported_insn();

			if(!(mach & (bfd_mach_x86_64 | bfd_mach_i386_i386)))
				_unsupported_insn();

			disassembler_ftype dis_asm = disassembler(abfd);
			assert(dis_asm);
			// Stolen from objdump(1).
			dinfo.flavour = bfd_get_flavour(abfd);
			dinfo.arch = bfd_get_arch(abfd);
			dinfo.mach = bfd_get_mach(abfd);
			dinfo.octets_per_byte = bfd_octets_per_byte(abfd);

			/*
			std::unordered_set<bfd_vma> pending_vmas;
			assert(abfd->start_address);
			pending_vmas.insert(abfd->start_address);
			*/

			/*
			try
			{
				int symcount;
				unsigned minisym_size;
				_malloc_ptr minisyms(
					[&](void *&ptr)
					{
						symcount = bfd_read_minisymbols(abfd, true, &ptr, &minisym_size);
						_bfd::check(symcount >= 0);
					});
				asymbol *symbol = bfd_make_empty_symbol(abfd);
				const char *minisym = minisyms.get<const char>();
				const void *minisyms_end = minisym + symcount * minisym_size;
				for(; minisym != minisyms_end; minisym += minisym_size)
				{
					asymbol *sym0 = _bfd::check(bfd_minisymbol_to_symbol(abfd, true, minisym, symbol));
					printf("  %s\n", sym0->name);
				}
			}
			catch(_bfd::exception exc)
			{
				if(exc.error() != bfd_error_no_symbols)
					throw;
			}
			*/

			// printf("flags: %x %d\n", abfd->flags, abfd->flags & EXEC_P);
			// printf("start: %lx\n", abfd->start_address);

			for(asection *section = abfd->sections; section != nullptr; section = section->next)
			{
				unsigned long error_count = 0;

				if(section->flags & SEC_CODE)
				{
					/*
					printf(
						"section: %s @ %lx -> %lx (%lx) flags = %x\n",
						section->name,
						section->filepos,
						section->vma,
						section->size,
						section->flags);
					*/

					_malloc_ptr section_data(
						[&, section](void *&ptr)
						{
							_bfd::check(bfd_malloc_and_get_section(abfd, section, reinterpret_cast<bfd_byte **>(&ptr)));
						});

					dinfo.buffer = section_data.get<bfd_byte>();
					dinfo.buffer_vma = section->vma;
					dinfo.buffer_length = section->size;
					dinfo.section = section;

					bfd_vma vma = section->vma;
					bfd_vma vma_end = vma + section->size;
					while(vma < vma_end)
					{
						int bytes = dis_asm(vma, &dinfo);
						if(bytes < 0)
							break;
						// printf("  %*s\n", (int)insn_str.size, insn_str.buf);

						if(arch == bfd_arch_i386)
						{
							bfd_byte *ptr = section_data.get<bfd_byte>() + (vma - section->vma);

							unsigned remaining = bytes;
							// Prefixes: SEG=(CS|DS|ES|FS|GS|SS), operand/address size, LOCK, REP*, REX.* (only 64-bit)
							while(
								remaining &&
								(*ptr == 0x26 || *ptr == 0x36 || *ptr == 0x2e || *ptr == 0x3e ||
								 *ptr == 0x64 || *ptr == 0x65 || *ptr == 0x66 || *ptr == 0x67 ||
								 *ptr == 0xf0 || *ptr == 0xf2 || *ptr == 0xf3 ||
								((mach & bfd_mach_x86_64) && ((*ptr & 0xf0) == 0x40))))
							{
								++ptr;
								--remaining;
							}

							if(remaining >= 2 && ptr[0] == 0xff)
							{
								bfd_byte modrm543 = ptr[1] & 0x38;
								if(modrm543 == 0x10 || modrm543 == 0x18 || modrm543 == 0x20 || modrm543 == 0x28)
								{
									if(!_found_indirect(argv, section, vma, error_count, max_errors))
										break;
								}
							}
						}

						vma += bytes;
					}
				}

				if(error_count)
					result = EXIT_FAILURE;
			}
		}
		catch(const std::exception &exc)
		{
			_error(argv, exc.what());
			result = EXIT_FAILURE;
		}

		++argv;
	} while(*argv);

	return result;
}
