/* -*- mode: c; tab-width: 4; fill-column: 128 -*- */
/* vi: set ts=4 tw=128: */

#include "audit.hpp"

#include <unistd.h>

namespace
{
	void _print_help(const char *program_name)
	{
		printf("Usage: %s [-h] [-V] [-n max_branches] [-x] [files...]\n", program_name);
	}
}

int main(int argc, char **argv)
{
	const char *program_name = argv[0];
	unsigned long max_errors = 0;
	bool recursive = true;

	for(;;)
	{
		int optc = getopt(argc, argv, "hn:vVx");
		if(optc < 0)
			break;

		switch(optc)
		{
		case 'h':
			_print_help(program_name);
			return EXIT_SUCCESS;

		case 'n':
			char *end;
			max_errors = strtoul(optarg, &end, 0);
			if(*end)
			{
				_print_help(program_name);
				return EXIT_FAILURE;
			}
			break;

		case 'V':
		case 'v':
			fputs(
				"retpoline-audit 0.1.1\n"
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

		case 'x':
			recursive = false;
			break;

		default:
			return EXIT_FAILURE;
		}
	}

	argv += optind;
	if(*argv == nullptr)
	{
		_print_help(program_name);
		return EXIT_FAILURE;
	}

	bfd_init();

	audit auditor(max_errors, recursive);

	do
	{
		auditor.run(*argv);
		++argv;
	} while(*argv);

	return auditor.finish();
}
