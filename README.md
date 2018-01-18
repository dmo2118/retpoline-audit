retpoline-audit
===============

A quick-and-dirty utility to verify that an executable or shared object is using
[retpolines](https://support.google.com/faqs/answer/7625886) to mitigate the [Spectre](https://spectreattack.com) vulnerability
(Variant 2: branch target injection, CVE-2017-5715). Specifically, `retpoline-audit` searches for indirect branches in a binary
and its shared object dependencies. This is currently known to compile on and work with binaries for `x86_64-linux-gnu`. (This
excludes the Linux kernel itself.) Other systems may also work, but don't count on it.

`retpoline-audit` will not be able to detect all indirect branches, including but not limited to the following scenarios:

* Code in data sections
* Code generated at runtime
* The disassembler can (usually briefly) get out of sync with the instruction stream in the padding between legitimate code
  sequences.

At this time (January 2018), very few executables in the wild have been compiled with retpoline support, and compiler support is
still in the process of trickling down to end users. For now, running this program on random binaries will show indirect
branches in nearly everything.

Note that `retpoline-audit` is still somewhat of a prototype at this point.

Security
--------

Do not run `retpoline-audit` on untrusted executables, or executables which link with untrusted shared objects.
`retpoline-audit` uses [ldd(1)](http://man7.org/linux/man-pages/man1/ldd.1.html) to find dependencies, which "may lead to the
execution of whatever code is defined in the program's ELF interpreter, and perhaps to execution of the program itself."

Building
--------

`retpoline-audit` requires `libbfd` and `libopcodes`, both part of [GNU Binutils](https://www.gnu.org/software/binutils/). On
Debian and Ubuntu, this requires the `binutils-dev` package. Once prerequisites are installed, type:

	$ make
	$ ./retpoline-audit [program]

Usage
-----

`-n 4` Display up to 4 indirect branch locations (per binary)
`-x` Do not scan shared object dependencies
`-h` Show help
`-V` Show version

License
-------

`retpoline-audit` is copyright (C) 2018 Dave Odell <<dmo2118@gmail.com>>

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see
<https://www.gnu.org/licenses/>.
