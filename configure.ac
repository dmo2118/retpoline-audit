AC_PREREQ(2.69)
AC_INIT(retpoline-audit, 0.1.2, https://github.com/dmo2118/retpoline-audit/issues)

AH_TEMPLATE([HAVE_DISASSEMBLER_ONE_ARG], [Define for old style disassembler().])

AC_CONFIG_SRCDIR(main.cpp)
AC_CONFIG_HEADERS(config.h)
AC_LANG(C++)

# Checks for programs.
AX_CXX_COMPILE_STDCXX(11)
AX_CXXFLAGS_WARN_ALL

# autoscan(1) recommends a barrage of tests for libraries, headers, etc., but much of what it found are hard requirements
# (C++11, binutils libs), without which retpoline-audit won't build. These will not be checked for; failure happens during make.

# Checks for libraries.
if test "$(uname -o 2>/dev/null || uname -s)" = Cygwin
then
	AC_CHECK_LIB(iberty, xmalloc) # BFD needs this on Cygwin.
	AC_CHECK_LIB(cygwin, getopt) # Order is important: libiberty coming first screws up Cygwin's getopt.
fi
AC_CHECK_LIB(intl, libintl_dgettext) # BFD needs this on macOS.
AC_CHECK_LIB(z, deflate) # BFD needs this on Cygwin.

# Checks for header files.
AC_CHECK_HEADERS(mach-o/fat.h)
AC_CHECK_HEADERS(mach-o/loader.h)

# Checks for typedefs, structures, and compiler characteristics. (No need for full POSIX to be a hard requirement.)
# Unfortunately checks for a bunch of C headers as a prerequisite.
AC_TYPE_PID_T
AC_TYPE_SSIZE_T
AC_C_BIGENDIAN

# Checks for library functions.
AC_MSG_CHECKING([for old-style libopcodes disassembler])
AC_COMPILE_IFELSE(
	[AC_LANG_SOURCE([
		#include <dis-asm.h>

		int main()
		{
			bfd *abfd = nullptr;
			disassembler(abfd);
		}
	])],
	[
		AC_DEFINE(HAVE_DISASSEMBLER_ONE_ARG)
		AC_MSG_RESULT(yes)
	],
	[AC_MSG_RESULT(no)])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
