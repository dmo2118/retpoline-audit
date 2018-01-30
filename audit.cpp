/* -*- mode: c; tab-width: 4; fill-column: 128 -*- */
/* vi: set ts=4 tw=128: */

#include "audit.hpp"

#include "errno_exception.hpp"
#include "malloc_ptr.hpp"

#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <sys/wait.h>
#include <unistd.h>

#if HAVE_MACH_O_FAT_H
#	include <mach-o/fat.h>
#endif

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

	inline std::uint32_t _byte_swap(std::uint32_t x)
	{
#if 0 // defined __GNUC__ || defined __clang__
		return __builtin_bswap32(x);
#else
		std::uint32_t a = x << 8;
		x = (((x >> 8) ^ a) & 0x00ff00ff) ^ a;
		x = (x >> 16) | (x << 16);
		return x;
#endif
	}

	inline std::int32_t _byte_swap(std::int32_t x)
	{
		return _byte_swap(std::uint32_t(x));
	}

#if HAVE_MACH_O_LOADER_H
	std::uint32_t _no_swap(std::uint32_t x)
	{
		return x;
	}
#endif

	template<typename T> inline T _big_endian(T x)
	{
		return
#if WORDS_BIGENDIAN
			x;
#else
			_byte_swap(x);
#endif
	}

	class _static_string_exception: public std::exception
	{
	private:
		const char *_what;

	public:
		_static_string_exception(const char *what): _what(what)
		{
		}

		const char *what() const throw();
	};

	const char *_static_string_exception::what() const throw()
	{
		return _what;
	}

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
			fclose(_stream);
		}

		FILE *get() const
		{
			return _stream;
		}

#if HAVE_MACH_O_FAT_H
		size_t check(size_t n) const;
#endif
	};

#if HAVE_MACH_O_FAT_H
	size_t _stdio_stream::check(size_t n) const
	{
		if(!n && ferror(_stream))
			throw _static_string_exception("I/O error"); // How descriptive.
		return n;
	}
#endif

	class _file
	{
	private:
		int _fd;

	public:
		explicit _file(int fd): _fd(fd)
		{
		}

		~_file()
		{
			close(_fd);
		}

		operator int() const
		{
			return _fd;
		}
	};

	class _bfd
	{
	private:
		bfd *_abfd;

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

		_bfd(bfd *abfd): _abfd(abfd)
		{
		}

		~_bfd()
		{
			_verify(bfd_close(_abfd));
		}

		bfd *get() const
		{
			return _abfd;
		}

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

	[[noreturn]] void _unsupported_insn()
	{
		throw _static_string_exception("unsupported instruction set");
	}

	void *_bfd_no_open(bfd *nbfd, void *open_closure)
	{
		return open_closure;
	}

	int _bfd_no_close(bfd *nbfd, void *stream)
	{
		return 0;
	}

#if HAVE_MACH_O_FAT_H
	struct _stdio_subset
	{
		FILE *stream;
		file_ptr begin;
		file_ptr size;

		static file_ptr pread(bfd *nbfd, void *stream, void *buf, file_ptr nbytes, file_ptr offset);
		static int stat(bfd *nbfd, void *stream, struct stat *sb);
	};

	file_ptr _stdio_subset::pread(bfd *nbfd, void *stream, void *buf, file_ptr nbytes, file_ptr offset)
	{
		_stdio_subset *self = static_cast<_stdio_subset *>(stream);
		if(offset > self->size)
			return 0;

		file_ptr max_bytes = self->size - offset;
		if(nbytes > max_bytes)
			nbytes = max_bytes;

		if(fseek(self->stream, offset + self->begin, SEEK_SET) < 0)
		{
			bfd_set_error(bfd_error_system_call);
			return -1;
		}

		int result = fread(buf, 1, nbytes, self->stream);
		if(!result && ferror(self->stream))
		{
			bfd_set_error(bfd_error_system_call); // Assuming errno is set...somewhere?
			return -1;
		}

		return result;
	}

	int _stdio_subset::stat(bfd *nbfd, void *stream, struct stat *sb)
	{
		_stdio_subset *self = static_cast<_stdio_subset *>(stream);

		// ####: Who doesn't support fileno?
		int result = fstat(fileno(self->stream), sb);
		if(result >= 0)
			sb->st_size = self->size;
		return result;
	}
#endif

	// This is a lot like _stdio_subset::pread().
	file_ptr _stdio_pread(bfd *nbfd, void *stream_raw, void *buf, file_ptr nbytes, file_ptr offset)
	{
		FILE *stream = static_cast<FILE *>(stream_raw);
		if(fseek(stream, offset, SEEK_SET) < 0)
		{
			bfd_set_error(bfd_error_system_call);
			return -1;
		}

		int result = fread(buf, 1, nbytes, stream);
		if(!result && ferror(stream))
		{
			bfd_set_error(bfd_error_system_call); // Assuming errno is set...somewhere?
			return -1;
		}

		return result;
	}

	int _stdio_stat(bfd *nbfd, void *stream_raw, struct stat *sb)
	{
		FILE *stream = static_cast<FILE *>(stream_raw);
		return fstat(fileno(stream), sb);
	}

	inline bool _cmp_prefix(const char *s, size_t n, const char *prefix)
	{
		size_t prefix_size = strlen(prefix);
		return n >= prefix_size && !memcmp(s, prefix, prefix_size);
	}
}

audit::_string audit::_expand_dyld_var(
	const char *prefix,
	size_t prefix_size,
	const char *suffix,
	size_t suffix_kill,
	size_t suffix_size)
{
	size_t size = prefix_size + suffix_size - suffix_kill;
	malloc_ptr result(malloc_ptr::check(malloc(size + 1)));
	*std::copy(
		suffix + suffix_kill,
		suffix + suffix_size,
		std::copy(prefix, prefix + prefix_size, result.get<char>())) = 0;
	return _string(std::move(result), size);
}

void audit::_expand_dyld_vars(_string &path, const char *loader_path, size_t loader_path_size) const
{
	if(_cmp_prefix(path.begin.get<char>(), path.size, "@executable_path/"))
	{
		path = _expand_dyld_var(
			_executable_path,
			_executable_path_size,
			path.begin.get<char>(),
			strlen("@executable_path/"),
			path.size);
	}
	else if(_cmp_prefix(path.begin.get<char>(), path.size, "@loader_path/"))
	{
		path = _expand_dyld_var(
			loader_path,
			loader_path_size,
			path.begin.get<char>(),
			strlen("@loader_path/"),
			path.size);
	}
}

size_t audit::_string::hash() const
{
	const size_t prime = sizeof(size_t) >= 8 ? 0x00000100000001B3 : 0x01000193;
	const size_t offset_basis = sizeof(size_t) >= 8 ? 0xcbf29ce484222325 : 0x811c9dc5;

	// FNV-1a.
	size_t hash = offset_basis; // wheeeeeeee
	for(unsigned i = 0; i != size; ++i)
	{
		// Good compilers should be able to optimize the multiplication here to shifts and adds when the CPU is lacking.
		hash = (hash ^ begin.get<char>()[i]) * prime;
	}

	return hash;
}

[[noreturn]] void audit::_truncated()
{
	_bfd::throw_exception(bfd_error_file_truncated);
}

void audit::_prefix(const char *text)
{
	_result = EXIT_FAILURE;
	fputs(text, stderr);
	fputs(": ", stderr);
}

void audit::_error(const char *prefix, const char *message)
{
	_prefix(prefix);
	fputs(message, stderr);
	fputc('\n', stderr);
}

void audit::_errorf(const char *prefix, const char *format, ...)
{
	_prefix(prefix);
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fputc('\n', stderr);
}

int audit::_print_nothing(void *, const char *, ...)
{
	return 0;
}

bool audit::_found_indirect(
	const char *path,
	const asection *section,
	bfd_vma vma,
	unsigned long &error_count,
	std::vector<const char *> &bad_sections)
{
	if(bad_sections.empty() || bad_sections.back() != section->name)
		bad_sections.push_back(section->name);

	++error_count;
	if(error_count > _max_errors)
		return false;

	_errorf(path, "indirect branch at %s:0x%.8llx", section->name, static_cast<unsigned long long>(vma));
	return true;
}

void audit::_pread(bfd *abfd, void *stream, pread_type pread, void *buf, file_ptr nbytes, file_ptr offset)
{
	file_ptr result = pread(abfd, stream, buf, nbytes, offset);
	if(result < 0)
		_bfd::throw_exception();

	assert(result <= nbytes);
	if(result < nbytes)
		_truncated();
}

void audit::_add_dependency(_string &&path)
{
	std::pair<_done_type::iterator, bool> r0 = _done.insert(std::move(path));
	std::pair<std::unordered_set<const char *>::iterator, bool> r1 = _done_exe.insert(r0.first->begin.get<char>());

	if(r1.second)
		_run(*r1.first, r0.second);
}

void audit::_add_dependency(malloc_vector &&path)
{
	_add_dependency(_string(std::move(path)));
}

malloc_vector audit::_read_null_str(bfd *abfd, void *stream, pread_type pread, file_ptr offset)
{
	malloc_vector path;

	for(;;)
	{
		size_t buf_capacity = path.size() ? path.size() : 128;
		char *buf = static_cast<char *>(path.append0(buf_capacity));

		file_ptr buf_size = pread(abfd, stream, buf, buf_capacity, offset);
		_bfd::check(buf_size >= 0);

		if(!buf_size)
			_truncated();

		size_t append_size = strnlen(buf, buf_size);
		assert(append_size <= uint64_t(buf_size));
		path.append1(append_size);

		if(append_size != uint64_t(buf_size))
			break;

		offset += append_size;
	}

	path.append1(1); // The null-terminator is explicitly included in the result.
	path.shrink_to_fit();
	assert(!path.data<char>()[path.size() - 1]);
	return path;
}

void audit::_do_bfd(bfd *abfd, void *stream, pread_type pread, bool check_insn)
{
	const char *path = abfd->filename;

	try
	{
		const char *vdso_name = nullptr;

		_bfd::check(bfd_check_format(abfd, bfd_object));

		// Stolen from objdump(1).
		_dinfo.flavour = bfd_get_flavour(abfd);
		_dinfo.arch = bfd_get_arch(abfd);
		_dinfo.mach = bfd_get_mach(abfd);
		_dinfo.octets_per_byte = bfd_octets_per_byte(abfd);
		if(bfd_big_endian(abfd))
			_dinfo.endian = BFD_ENDIAN_BIG;
		else if(bfd_little_endian(abfd))
			_dinfo.endian = BFD_ENDIAN_LITTLE;
		else
			_dinfo.endian = BFD_ENDIAN_UNKNOWN;

		if(_dinfo.arch == bfd_arch_i386) // See vdso(1).
		{
			switch(_dinfo.mach & (bfd_mach_i386_i386 | bfd_mach_x86_64 | bfd_mach_x64_32))
			{
			case bfd_mach_i386_i386:
				vdso_name = "linux-gate.so.1";
				break;
			case bfd_mach_x86_64:
			case bfd_mach_x64_32:
				vdso_name = "linux-vdso.so.1";
				break;
			default:
				_unsupported_insn();
				break;
			}
		}
		else
		{
			_unsupported_insn();
		}

		if(check_insn)
		{
			unsigned long error_count = 0;

			disassembler_ftype dis_asm = disassembler(
#ifndef HAVE_DISASSEMBLER_ONE_ARG
				_dinfo.arch,
				_dinfo.endian == BFD_ENDIAN_BIG,
				_dinfo.mach,
#endif
				abfd
				);
			assert(dis_asm);

			// printf("flags: %x %d\n", abfd->flags, abfd->flags & EXEC_P);
			// printf("start: %lx\n", abfd->start_address);

			std::vector<const char *> bad_sections;

			for(asection *section = abfd->sections; section != nullptr; section = section->next)
			{
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

					malloc_ptr section_data(
						[&, section](void *&ptr)
						{
							_bfd::check(bfd_malloc_and_get_section(abfd, section, reinterpret_cast<bfd_byte **>(&ptr)));
						});

					_dinfo.buffer = section_data.get<bfd_byte>();
					_dinfo.buffer_vma = section->vma;
					_dinfo.buffer_length = section->size;
					_dinfo.section = section;

					bfd_vma vma = section->vma;
					bfd_vma vma_end = vma + section->size;
					while(vma < vma_end)
					{
						int bytes = dis_asm(vma, &_dinfo);
						if(bytes < 0)
							break;
						// printf("  %*s\n", (int)insn_str.size, insn_str.buf);

						// TODO: ARM is probably LDR PC, (something) for indirect jumps.
						if(_dinfo.arch == bfd_arch_i386)
						{
							bfd_byte *ptr = section_data.get<bfd_byte>() + (vma - section->vma);

							unsigned remaining = bytes;
							// Prefixes: SEG=(CS|DS|ES|FS|GS|SS), operand/address size, LOCK, REP*, REX.* (only 64-bit)
							while(
								remaining &&
								(*ptr == 0x26 || *ptr == 0x36 || *ptr == 0x2e || *ptr == 0x3e ||
								 *ptr == 0x64 || *ptr == 0x65 || *ptr == 0x66 || *ptr == 0x67 ||
								 *ptr == 0xf0 || *ptr == 0xf2 || *ptr == 0xf3 ||
								((_dinfo.mach & (bfd_mach_x86_64 | bfd_mach_x64_32)) && ((*ptr & 0xf0) == 0x40))))
							{
								++ptr;
								--remaining;
							}

							if(remaining >= 2 && ptr[0] == 0xff)
							{
								bfd_byte modrm543 = ptr[1] & 0x38;
								if(modrm543 == 0x10 || modrm543 == 0x18 || modrm543 == 0x20 || modrm543 == 0x28)
								{
									if(!_found_indirect(path, section, vma, error_count, bad_sections))
										break;
								}
							}
						}

						vma += bytes;
					}
				}
			}

			if(error_count)
			{
				if(_max_errors > 1 && error_count > _max_errors)
					_error(path, "additional indirect branches suppressed");

				// Do this before closing the BFD.
				_prefix(path);
				fputs("indirect branch(es) found in sections:", stderr);
				for(const char *section_name: bad_sections)
				{
					fputc(' ', stderr);
					fputs(section_name, stderr);
				}
				fputc('\n', stderr);
			}
		}

		if(!_recursive)
			return;

#if HAVE_MACH_O_LOADER_H
		if(abfd->xvec->flavour == bfd_target_mach_o_flavour)
		{
			mach_header header; // mach_header_64 contains a mach_header, more or less.
			_pread(abfd, stream, pread, header, 0);

			uint32_t (*read32)(uint32_t);

			if(header.magic == MH_MAGIC || header.magic == MH_MAGIC_64)
				read32 = _no_swap;
			else if(header.magic == MH_CIGAM || header.magic == MH_CIGAM_64)
				read32 = _byte_swap;
			else
				_bfd::throw_exception(bfd_error_file_not_recognized); // Save a string.

			file_ptr offset =
				header.magic == MH_MAGIC_64 || header.magic == MH_CIGAM_64 ?
				sizeof(mach_header_64) :
				sizeof(mach_header);

			// TODO: Make sure header.sizeofcmds matches offset at the end of this.
			// uint32_t sizeofcmds = read32(header.sizeofcmds);

			// TODO: An error: /Applications/Xcode.app/Contents/MacOS/../Frameworks/IDEKit.framework/Versions/A/IDEKit:
			// @rpath/XCTest.framework/Versions/A/XCTest: No such file or directory
			// dyld(1) sez: RPATH successful expansion of @rpath/XCTest.framework/Versions/A/XCTest to:
			// /Applications/Xcode.app/Contents/SharedFrameworks/DVTKit.framework/Versions/A/../../../../Developer/Platforms/MacOSX.platform/Developer/Library/Frameworks//XCTest.framework/Versions/A/XCTest
			// Not sure where it's pulling that MacOSX.platform path from.
			// Also from Xcode: Note /System/Library/PrivateFrameworks/LoggingSupport.framework/Versions/A/LoggingSupport.

			union
			{
				load_command base;
				dylinker_command dylinker;
				dylib_command dylib;
				rpath_command rpath;
			} lc;

			size_t rpaths_size = _rpaths.size();
			std::vector<_string> deps;
			deps.reserve(header.ncmds);

			// loader_path and executable_path require slashes on the end unless they are empty.
			const char *loader_path_end = strrchr(abfd->filename, '/');
			size_t loader_path_size = loader_path_end ? loader_path_end - abfd->filename + 1 : 0;

			for(uint32_t i = read32(header.ncmds); i; --i)
			{
				_pread(abfd, stream, pread, lc.base, offset);
				switch(read32(lc.base.cmd))
				{
				case LC_LOAD_DYLINKER:
					_read_lc(abfd, stream, pread, lc.dylinker, offset);
					deps.emplace_back(_read_null_str(abfd, stream, pread, offset + read32(lc.dylinker.name.offset)));
					break;

				case LC_LOAD_DYLIB:
				case LC_LOAD_WEAK_DYLIB: // TODO: If this is a no such file, should retpoline-audit(1) really error out?
				case LC_REEXPORT_DYLIB:
				case LC_LAZY_LOAD_DYLIB: // TODO: Likewise with no such file.
				case LC_LOAD_UPWARD_DYLIB:
					_read_lc(abfd, stream, pread, lc.dylib, offset);
					deps.emplace_back(_read_null_str(abfd, stream, pread, offset + read32(lc.dylib.dylib.name.offset)));
					break;

				case LC_RPATH:
					_read_lc(abfd, stream, pread, lc.rpath, offset);
					{
						_string rpath = _read_null_str(abfd, stream, pread, offset + read32(lc.rpath.path.offset));
						_expand_dyld_vars(rpath, abfd->filename, loader_path_size);
						_rpaths.push_back(std::move(rpath));
					}
					break;
				}

				offset += lc.base.cmdsize;
			}

			std::reverse(_rpaths.begin() + _rpaths.size(), _rpaths.end());

			for(auto &dep: deps)
			{
				const char *p = dep.begin.get<char>();
				size_t s = dep.size;
				if(_cmp_prefix(p, s, "@rpath/"))
				{
					for(auto rpath = _rpaths.crbegin();; ++rpath)
					{
						if(rpath == _rpaths.crend())
						{
							_errorf(path, "%*s: %s", s, p, strerror(ENOENT));
							break;
						}

						_string name(_expand_dyld_var(rpath->begin.get<char>(), rpath->size, p, strlen("@rpath/") - 1, s));
						if(!access(name.begin.get<char>(), F_OK))
						{
							_add_dependency(std::move(name));
							break;
						}
					}
				}
				else // TODO: loader_path, executable_path
				{
					_expand_dyld_vars(dep, abfd->filename, loader_path_size);
					_add_dependency(std::move(dep));
				}
			}

			_rpaths.erase(_rpaths.begin() + rpaths_size, _rpaths.end()); // Can't use vector<>::resize, natch.

			return;
		}
#endif

		// PE uses bfd_target_coff_flavour. (Maybe they shouldn't? Hmm.)

		// Using ldd(1) to find dependencies. The second-best alternative is probably to run through the search order
		// mentioned in Linux's ld.so man page, but that doesn't cover stuff like the /usr/lib/x86_64-linux-gnu path on
		// Debian.
		// TODO: ldd(1) is itself recursive; don't call it for every binary.
		int pipefd[2];
		errno_exception::check(pipe(pipefd));
		_file pipe_read(pipefd[0]);

		pid_t child_pid;

		{
			_file pipe_write(pipefd[1]);
			child_pid = errno_exception::check(fork());
			if(!child_pid)
			{
				if(dup2(pipe_write, 1) >= 0)
					execlp("ldd", "ldd", path, nullptr);
				_errorf(path, "couldn't execute ldd: %s", strerror(errno));
				fflush(stderr);
				_exit(EXIT_FAILURE);
			}
		} // Close pipe_write.

		malloc_vector ldd_output;
		for(;;)
		{
			size_t size = ldd_output.capacity() - ldd_output.size();
			if(!size)
				size = std::max(ldd_output.size(), size_t(8192));

			size = errno_exception::check(read(pipe_read, ldd_output.append0(size), size));

			ldd_output.append1(size);
			if(!size)
				break;
		}

		int status;
		errno_exception::check(waitpid(child_pid, &status, 0));
		if(!status)
			_result = EXIT_FAILURE;

		*static_cast<char *>(ldd_output.append0(1)) = 0;
		ldd_output.append1(1);

		// Manual, destructive string parsing; POSIX regex apparently doesn't do non-greedy/minimal matching. And PCRE is
		// overkill just for this.
		// Parsing breaks down for libraries with " => " in the name.
		char *p = ldd_output.data<char>();
		char *end = p + ldd_output.size() - 1;
		*end = 0;
		while(p != end)
		{
			char *eol = strchr(p, '\n');
			if(!eol)
				eol = end;
			*eol = 0;

			if(*p == '\t')
				++p;

			if(strcmp(p, "statically linked"))
			{
				char *arrow = strstr(p, " => ");
				if(arrow)
					arrow += 4;
				else
					arrow = p; // Shared object is using an absolute path.

				if(arrow != eol && eol[-1] == ')')
				{
					bool got_paren = false;
					char *paren = eol - 1;
					if(paren != arrow)
					{
						--paren;
						do
						{
							if(paren[0] == ' ' && paren[1] == '(')
							{
								got_paren = true;
								break;
							}

							--paren;
						}
						while(paren >= arrow);
					}

					if(!got_paren)
					{
						_error(path, p);
					}
					else
					{
						*paren = 0;
						if(!*arrow)
						{
							// "blah =>  (0x0123abcd) is probably something like a vDSO.
							if(p == arrow)
							{
								_error(path, "ldd(1) parse error");
							}
							else
							{
								arrow[-4] = 0;
								if(!vdso_name || strcmp(vdso_name, p))
								{
									_errorf(path, "can't handle dependency: %s", p);
								}
							}
						}
						else if(!vdso_name || strcmp(vdso_name, arrow))
						{
							size_t size = paren - arrow;
							malloc_ptr str(malloc_ptr::check(malloc(size + 1)));
							*std::copy(arrow, paren, str.get<char>()) = 0;
							_add_dependency(_string(std::move(str), size));
						}
					}
				}
				else
				{
					// Expecting a 'not found' here.
					_error(path, p);
				}
			}

			p = eol;
			if(p == end)
				break;
			++p;
		}
	}
	catch(const std::exception &exc)
	{
		_error(path, exc.what());
	}
}

void audit::_run(const char *path, bool check_insn) // TODO: This and _add_dependency could use some cleanup.
{
	try
	{
		_stdio_stream bin_strm(errno_exception::check(fopen(path, "rb")));
#if HAVE_MACH_O_FAT_H
		fat_header header;
		// FAT_MAGIC (0xCAFEBABE) is the same magic number that Java uses for its .class files.
		// James Gosling says it's his fault: <http://radio-weblogs.com/0100490/2003/01/28.html>.
		if(bin_strm.check(fread(&header, sizeof(header), 1, bin_strm.get())) && header.magic == _big_endian(FAT_MAGIC))
		{
			uint32_t nfat_arch = _big_endian(header.nfat_arch);

			std::unique_ptr<char []> path_with_suffix(new char[strlen(path) + 32]);
			char *suffix = stpcpy(path_with_suffix.get(), path); // stpcpy: Only sort of portable.
			*suffix = ':';
			++suffix;

			for(uint32_t i = 0; i != nfat_arch; ++i)
			{
				fat_arch arch;
				errno_exception::check(fseek(bin_strm.get(), sizeof(fat_header) + i * sizeof(fat_arch), SEEK_SET));
				if(!bin_strm.check(fread(&arch, sizeof(arch), 1, bin_strm.get())))
					_truncated();

				// TODO: Make sure the image starts after the end of the fat_arch array.
				// TODO: Verify that the architecture contains a Mach-O image, and not something else.
				_stdio_subset subset = {bin_strm.get(), _big_endian(arch.offset), _big_endian(arch.size)};

				cpu_type_t cputype = _big_endian(arch.cputype);
				cpu_subtype_t cpusubtype = _big_endian(arch.cpusubtype) & ~cpu_subtype_t(CPU_SUBTYPE_MASK);

				if(cputype == CPU_TYPE_I386 && cpusubtype == CPU_SUBTYPE_I386_ALL)
					strcpy(suffix, "i386");
				else if(cputype == CPU_TYPE_X86_64 && cpusubtype == CPU_SUBTYPE_X86_64_ALL)
					strcpy(suffix, "x86_64");
				else if(cputype == CPU_TYPE_X86_64 && cpusubtype == CPU_SUBTYPE_X86_64_H)
					strcpy(suffix, "x86-64h");
				else
					sprintf(suffix, "%x,%x", (int)_big_endian(arch.cputype), (int)_big_endian(arch.cpusubtype));

				_bfd abfd(
					_bfd::check(
						bfd_openr_iovec(
							path_with_suffix.get(),
							nullptr,
							_bfd_no_open,
							&subset,
							_stdio_subset::pread,
							_bfd_no_close,
							_stdio_subset::stat)));
				_do_bfd(abfd.get(), &subset, _stdio_subset::pread, check_insn);
			}
			return;
		}

		errno = 0;
		rewind(bin_strm.get());
		int error = errno;
		if(error)
			errno_exception::throw_exception();
#endif
		_bfd abfd(_bfd::check(bfd_openr_iovec(
			path,
			nullptr,
			_bfd_no_open,
			bin_strm.get(),
			_stdio_pread,
			_bfd_no_close,
			_stdio_stat)));
		_do_bfd(abfd.get(), bin_strm.get(), _stdio_pread, check_insn);
	}
	catch(const std::exception &exc)
	{
		_error(path, exc.what());
	}
}

void audit::run(const char *path)
{
	_executable_path = path;
	const char *executable_path_end = strrchr(path, '/'); // Will need to change for PE, obviously.
	_executable_path_size = executable_path_end ? executable_path_end - _executable_path + 1 : 0;

	_done_exe.clear();
	_run(path, true);
}
