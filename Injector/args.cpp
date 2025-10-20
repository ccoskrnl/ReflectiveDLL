#include "framework.h"
#include "args.h"

#include <string>
#include <iostream>

i_arg_t argument_parser(int argc, char* argv[]) {
	i_arg_t args = { dll_path_type::filename, 0, 0, 0 };

	args.is_local = false;

	for (int i = 1; i < argc; i++) {
		std::string arg = argv[i];

		if (arg == "--help" || arg == "-h") {
			std::cout << "Usage: " << argv[0] << " [OPTIONS]\n"
				<< "Inject DLL into a target process.\n\n"
				<< "Options:\n"
				<< "  -h, --help           Show this help message and exit\n"
				<< "  -u, --url URL        Specify DLL URL for remote download\n"
				<< "  -f, --file FILE      Specify local DLL filename\n"
				<< "  -p, --process NAME   Target process name to inject into\n"
				<< "      --local          Enable local injection mode\n\n"
				<< "Examples:\n"
				<< "  " << argv[0] << " --file mydll.dll --process target.exe\n"
				<< "  " << argv[0] << " --url http://example.com/mydll.dll --process game.exe\n"
				<< "  " << argv[0] << " --file payload.dll --local\n";
			exit(0);
		}

		else if (arg == "--url" || arg == "-u") {
			if (i + 1 < argc) {
				args.dll_src = dll_path_type::url;
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
		else if (arg == "--file" || arg == "-f") {
			if (i + 1 < argc) {
				args.dll_src = dll_path_type::filename;
				args.filename = argv[i + 1];

				// Skip the next argument since it's already processed.
				++i;
			}
			else
			{
				std::cerr << "[-] Error: --file option requires an argument." << std::endl;
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
				std::cerr << "[-] Error: --process option requires an argument." << std::endl;
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
