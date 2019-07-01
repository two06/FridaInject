using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;


namespace FridaInject
{
    class Program
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        // privileges
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        // used for memory allocation
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;

        public static int Main(String[] args)
        {
            if(args.Length < 2)
            {
                PrintHeader();
                return 1;
            }
            Inject(args[1], args[0]);
            return 0;
        }

        /// <summary>
        /// Load a DLL into a process. Mostly taken from https://github.cm/pwndizzle/c-sharp-memory-injection/
        /// </summary>
        private static void Inject(string processName, string dllName)
        {
            // Get process id
            Process targetProcess = Process.GetProcessesByName(processName)[0];

            // Get handle of the process - with required privileges
            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);

            // Get address of LoadLibraryA and store in a pointer
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            // Allocate memory for dll path and store pointer
            IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            // Write path of dll to memory
            UIntPtr bytesWritten;
            bool resp1 = WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            // Read contents of memory
            int bytesRead = 0;
            byte[] buffer = new byte[24];
            ReadProcessMemory(procHandle, allocMemAddress, buffer, buffer.Length, ref bytesRead);

            // Create a thread that will call LoadLibraryA with allocMemAddress as argument
            CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
        }
        private static void PrintHeader()
        {
            var header = @"
     ____   ___        _           _   
    / _  | |_ _|_ __  (_) ___  ___| |_   
   | (_| |  | || '_ \ | |/ _ \/ __| __|
    > _  |  | || | | || |  __/ (__| |_   
   /_/ |_| |___|_| |_|/ |\___|\___|\__|  	   
   . . . .           |__/        @two06                         
   . . . . FridaInject  
   . . . . Usage: FridaInject.exe ProcessName c:\path\to\dll
   . . . .        FridaInject.exe notepad c:\frida-gadget.dll 	";

            Console.WriteLine(header);
        }
    }
}

