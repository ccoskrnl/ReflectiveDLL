#include "framework.h"
#include "args.h"

#include <string>
#include <iostream>

i_arg_t argument_parser(int argc, char* argv[]) {
	i_arg_t args = { 0 };

	args.is_local = false;

	for (int i = 1; i < argc; i++) {
		std::string arg = argv[i];

		if (arg == "--url" || arg == "-u") {
			if (i + 1 < argc) {
				args.url = argv[i + 1];

				// Skip the next argument since it's already processed.
				++i;
			}
			else
			{
				// Handle error: "--url" option requires an argument
				std::cerr << "[-] Error: -url option requires an argument." << std::endl;
			}
		}
		else if (arg == "--process" || arg == "-p") {
			if (i + 1 < argc) {
				args.process = argv[i + 1];

				// Skip the next argument since it's already processed.
				++i;
			}
			else
			{
				// Handle error: "-process" option requires an argument
				std::cerr << "[-] Error: -process option requires an argument." << std::endl;
			}
		}
		else if (arg == "--local") {
			args.is_local = true;
		}
		else {
			// Handle unknown arguments or options here if needed
			std::cerr << "[!] Warning: Unknown argument '" << arg << "'. Ignored." << std::endl;
		}
	}

	return args;
}
