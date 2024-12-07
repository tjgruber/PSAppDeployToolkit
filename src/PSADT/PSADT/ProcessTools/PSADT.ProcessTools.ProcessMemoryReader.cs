using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PSADT.PInvoke;

namespace PSADT.ProcessTools
{
    internal class ProcessMemoryReader
    {
        public static bool GetPebAddress(
            SafeProcessHandle processHandle,
            bool isTarget64BitProcess,
            bool isTargetWow64Process,
            out long pebAddress)
        {
            if (isTargetWow64Process)
            {
                return TryReadPebAddress(processHandle, PROCESSINFOCLASS.ProcessWow64Information, out pebAddress);
            }
            else if (ProcessHelper.IsCurrent32BitProcess() && isTarget64BitProcess)
            {
                return TryReadPebAddressWow64Process64(processHandle, out pebAddress);
            }
            else
            {
                return TryReadPebAddress(processHandle, PROCESSINFOCLASS.ProcessBasicInformation, out pebAddress);
            }
        }

        private static bool TryReadPebAddress(
        SafeProcessHandle processHandle,
        PROCESSINFOCLASS processInfoClass,
        out long pebAddress)
        {
            pebAddress = 0;
            uint bufferSize = (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
            using var buffer = new SafeHGlobalHandle((int)bufferSize);

            // First call to get required buffer size
            int status = NativeMethods.NtQueryInformationProcess(
                processHandle,
                processInfoClass,
                buffer.DangerousGetHandle(),
                bufferSize,
                out uint returnLength);

            if (status == NTStatus.STATUS_INFO_LENGTH_MISMATCH)
            {
                // Reallocate buffer with correct size
                using var newBuffer = new SafeHGlobalHandle((int)returnLength);
                status = NativeMethods.NtQueryInformationProcess(
                    processHandle,
                    processInfoClass,
                    newBuffer.DangerousGetHandle(),
                    returnLength,
                    out returnLength);

                if (status == NTStatus.STATUS_SUCCESS)
                {
                    var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(newBuffer.DangerousGetHandle());
                    pebAddress = pbi.PebBaseAddress.ToInt64();
                    return true;
                }
            }
            else if (status == NTStatus.STATUS_SUCCESS)
            {
                var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(buffer.DangerousGetHandle());
                pebAddress = pbi.PebBaseAddress.ToInt64();
                return true;
            }

            return false;
        }

        private static bool TryReadPebAddressWow64Process64(
        SafeProcessHandle processHandle,
        out long pebAddress)
        {
            pebAddress = 0;
            ulong bufferSize = (ulong)Marshal.SizeOf<PROCESS_BASIC_INFORMATION_WOW64>();
            using var buffer = new SafeHGlobalHandle((int)bufferSize);

            // First call to get required buffer size
            int status = NativeMethods.NtWow64QueryInformationProcess64(
                processHandle,
                PROCESSINFOCLASS.ProcessBasicInformation,
                buffer.DangerousGetHandle(),
                bufferSize,
                out ulong returnLength);

            if (status == NTStatus.STATUS_INFO_LENGTH_MISMATCH)
            {
                // Reallocate buffer with correct size
                using var newBuffer = new SafeHGlobalHandle((int)returnLength);
                status = NativeMethods.NtWow64QueryInformationProcess64(
                    processHandle,
                    PROCESSINFOCLASS.ProcessBasicInformation,
                    newBuffer.DangerousGetHandle(),
                    returnLength,
                    out returnLength);

                if (status == NTStatus.STATUS_SUCCESS)
                {
                    var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION_WOW64>(newBuffer.DangerousGetHandle());
                    pebAddress = pbi.PebBaseAddress;
                    return true;
                }
            }
            else if (status == NTStatus.STATUS_SUCCESS)
            {
                var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION_WOW64>(buffer.DangerousGetHandle());
                pebAddress = pbi.PebBaseAddress;
                return true;
            }

            return false;
        }
    }

    internal class Peb
    {
        public string? FullyQualifiedPath { get; private set; }

        public string? WindowTitle { get; private set; }

        public string? CommandLine { get; private set; }
        public string? WorkingDirectory { get; private set; }

        public string? Owner { get; private set; }
        public int SessionId { get; private set; }

        public DateTime StartTimeUtc { get; private set; }
        public DateTime StartTimeLocal { get; private set; }

        public string? DesktopInfo { get; private set; }


        public Peb(
            SafeProcessHandle processHandle,
            long pebAddress,
            bool isTarget64BitProcess)
        {
            PebOffsets offsets = PebOffsets.Get(isTarget64BitProcess);

            if (!TryReadRemoteStructure<IntPtr>(processHandle, pebAddress + offsets.ProcessParametersOffset, out var processParametersAddress))
            {
                return;
            }

            if (!TryReadRemoteStructure<int>(processHandle, pebAddress + offsets.SessionIdOffset, out int sessionId))
            {
                return;
            }
            SessionId = sessionId;

            // Read strings from process parameters
            CommandLine = ReadRemoteUnicodeString(processHandle, processParametersAddress.ToInt64() + offsets.CommandLineOffset, isTarget64BitProcess);
            WorkingDirectory = ReadRemoteUnicodeString(processHandle, processParametersAddress.ToInt64() + offsets.CurrentDirectoryOffset, isTarget64BitProcess);
            FullyQualifiedPath = ReadRemoteUnicodeString(processHandle, processParametersAddress.ToInt64() + offsets.ImagePathNameOffset, isTarget64BitProcess);
            WindowTitle = ReadRemoteUnicodeString(processHandle, processParametersAddress.ToInt64() + offsets.WindowTitleOffset, isTarget64BitProcess);
            DesktopInfo = ReadRemoteUnicodeString(processHandle, processParametersAddress.ToInt64() + offsets.DesktopInfoOffset, isTarget64BitProcess);

            // Get process owner
            Owner = ProcessHelper.GetProcessOwner(processHandle);

            // Get process start time
            long processStartTimeLUtc = ProcessHelper.GetProcessStartTimeLongUtc(processHandle);
            StartTimeUtc = DateTime.FromFileTimeUtc(processStartTimeLUtc);
            StartTimeLocal = DateTime.FromFileTime(processStartTimeLUtc);
        }

        internal static bool TryReadRemoteStructure<T>(
            SafeProcessHandle processHandle,
            long address,
            out T result) where T : struct
        {
            result = default;
            if (address == 0)
            {
                return false;
            }

            var size = Marshal.SizeOf(typeof(T));
            using var buffer = new SafeHGlobalHandle(size);

            try
            {
                // ReadProcessMemory can fail if the memory is not accessible
                if (!NativeMethods.ReadProcessMemory(
                    processHandle,
                    new IntPtr(address),
                    buffer.DangerousGetHandle(),
                    size,
                    out long bytesRead))
                {
                    return false;
                }

                // Verify we read the expected number of bytes
                if (bytesRead != size)
                {
                    return false;
                }

                result = Marshal.PtrToStructure<T>(buffer.DangerousGetHandle());
                return true;
            }
            catch
            {
                return false;
            }
        }

        internal static string? ReadRemoteUnicodeString(
            SafeProcessHandle processHandle,
            long address,
            bool isTarget64BitProcess)
        {
            if (address == 0)
            {
                return null;
            }

            try
            {
                if (isTarget64BitProcess)
                {
                    if (!TryReadRemoteStructure<UNICODE_STRING>(processHandle, address, out var unicodeString))
                    {
                        return null;
                    }

                    // Validate buffer pointer and length
                    if (unicodeString.Buffer == IntPtr.Zero || unicodeString.Length == 0 || unicodeString.Length > 32767)
                    {
                        return null;
                    }

                    return ReadUnicodeString(processHandle, unicodeString.Buffer, unicodeString.Length);
                }
                else
                {
                    if (!TryReadRemoteStructure<UNICODE_STRING_32>(processHandle, address, out var unicodeString32))
                    {
                        return null;
                    }

                    // Validate buffer pointer and length for 32-bit
                    if (unicodeString32.Buffer == 0 || unicodeString32.Length == 0 || unicodeString32.Length > 32767)
                    {
                        return null;
                    }

                    return ReadUnicodeString(processHandle, new IntPtr(unicodeString32.Buffer), unicodeString32.Length);
                }
            }
            catch
            {
                return null;
            }
        }

        internal static string? ReadUnicodeString(
            SafeProcessHandle processHandle,
            IntPtr bufferAddress,
            ushort length)
        {
            if (bufferAddress == IntPtr.Zero || length == 0 || length > 32767) // Max reasonable string length
            {
                return null;
            }

            // Ensure length is even as it's Unicode (2 bytes per char)
            if (length % 2 != 0)
            {
                return null;
            }

            try
            {
                using var stringBuffer = new SafeHGlobalHandle(length);

                if (!NativeMethods.ReadProcessMemory(
                    processHandle,
                    bufferAddress,
                    stringBuffer.DangerousGetHandle(),
                    length,
                    out long bytesRead))
                {
                    return null;
                }

                // Verify we read the expected number of bytes
                if (bytesRead != length)
                {
                    return null;
                }

                byte[] data = new byte[length];
                Marshal.Copy(stringBuffer.DangerousGetHandle(), data, 0, length);

                // Verify the data contains valid Unicode characters
                try
                {
                    string result = System.Text.Encoding.Unicode.GetString(data);
                    return string.IsNullOrWhiteSpace(result) ? null : result.TrimEnd('\0');
                }
                catch (ArgumentException)
                {
                    // Invalid Unicode data
                    return null;
                }
            }
            catch
            {
                return null;
            }
        }

        internal readonly struct PebOffsets
        {
            // Constants for 64-bit process offsets
            private const int PEB_64_PROCESS_PARAMETERS = 0x20;
            private const int PEB_64_SESSION_ID = 0x02c0;
            private const int RTL_USER_PROCESS_PARAMETERS_64_COMMANDLINE = 0x70;
            private const int RTL_USER_PROCESS_PARAMETERS_64_CURRENTDIRECTORY = 0x38;
            private const int RTL_USER_PROCESS_PARAMETERS_64_WINDOWTITLE = 0xb0;
            private const int RTL_USER_PROCESS_PARAMETERS_64_DESKTOPINFO = 0xc0;
            private const int RTL_USER_PROCESS_PARAMETERS_64_IMAGEPATHNAME = 0x60;
            private const int RTL_USER_PROCESS_PARAMETERS_64_ENVIRONMENT = 0x80;
            private const int PEB_64_ENVIRONMENT_SIZE = 0x03f0;

            // Constants for 32-bit process offsets
            private const int PEB_32_PROCESS_PARAMETERS = 0x10;
            private const int PEB_32_SESSION_ID = 0x01d4;
            private const int RTL_USER_PROCESS_PARAMETERS_32_COMMANDLINE = 0x40;
            private const int RTL_USER_PROCESS_PARAMETERS_32_CURRENTDIRECTORY = 0x24;
            private const int RTL_USER_PROCESS_PARAMETERS_32_WINDOWTITLE = 0x70;
            private const int RTL_USER_PROCESS_PARAMETERS_32_DESKTOPINFO = 0x78;
            private const int RTL_USER_PROCESS_PARAMETERS_32_IMAGEPATHNAME = 0x38;
            private const int RTL_USER_PROCESS_PARAMETERS_32_ENVIRONMENT = 0x48;
            private const int PEB_32_ENVIRONMENT_SIZE = 0x0290;

            public readonly int ProcessParametersOffset;
            public readonly int CommandLineOffset;
            public readonly int CurrentDirectoryOffset;
            public readonly int WindowTitleOffset;
            public readonly int DesktopInfoOffset;
            public readonly int ImagePathNameOffset;
            public readonly int EnvironmentOffset;
            public readonly int EnvironmentSizeOffset;
            public readonly int SessionIdOffset;

            private PebOffsets(bool isTarget64BitProcess)
            {
                if (isTarget64BitProcess)
                {
                    ProcessParametersOffset = PEB_64_PROCESS_PARAMETERS;
                    SessionIdOffset = PEB_64_SESSION_ID;
                    CommandLineOffset = RTL_USER_PROCESS_PARAMETERS_64_COMMANDLINE;
                    CurrentDirectoryOffset = RTL_USER_PROCESS_PARAMETERS_64_CURRENTDIRECTORY;
                    WindowTitleOffset = RTL_USER_PROCESS_PARAMETERS_64_WINDOWTITLE;
                    DesktopInfoOffset = RTL_USER_PROCESS_PARAMETERS_64_DESKTOPINFO;
                    ImagePathNameOffset = RTL_USER_PROCESS_PARAMETERS_64_IMAGEPATHNAME;
                    EnvironmentOffset = RTL_USER_PROCESS_PARAMETERS_64_ENVIRONMENT;
                    EnvironmentSizeOffset = PEB_64_ENVIRONMENT_SIZE;
                }
                else
                {
                    ProcessParametersOffset = PEB_32_PROCESS_PARAMETERS;
                    SessionIdOffset = PEB_32_SESSION_ID;
                    CommandLineOffset = RTL_USER_PROCESS_PARAMETERS_32_COMMANDLINE;
                    CurrentDirectoryOffset = RTL_USER_PROCESS_PARAMETERS_32_CURRENTDIRECTORY;
                    WindowTitleOffset = RTL_USER_PROCESS_PARAMETERS_32_WINDOWTITLE;
                    DesktopInfoOffset = RTL_USER_PROCESS_PARAMETERS_32_DESKTOPINFO;
                    ImagePathNameOffset = RTL_USER_PROCESS_PARAMETERS_32_IMAGEPATHNAME;
                    EnvironmentOffset = RTL_USER_PROCESS_PARAMETERS_32_ENVIRONMENT;
                    EnvironmentSizeOffset = PEB_32_ENVIRONMENT_SIZE;
                }
            }

            public static PebOffsets Get(bool isTarget64BitProcess) => new PebOffsets(isTarget64BitProcess);

            // Helper method to validate offsets are within expected ranges
            public bool Validate()
            {
                // Basic validation of offsets to ensure they're within reasonable ranges
                // These ranges are based on typical PEB structure sizes
                const int MAX_PEB_OFFSET = 0x1000;           // 4KB
                const int MAX_PARAMETERS_OFFSET = 0x200;     // 512 bytes

                return ProcessParametersOffset >= 0 && ProcessParametersOffset < MAX_PEB_OFFSET
                    && SessionIdOffset >= 0 && SessionIdOffset < MAX_PEB_OFFSET
                    && CommandLineOffset >= 0 && CommandLineOffset < MAX_PARAMETERS_OFFSET
                    && CurrentDirectoryOffset >= 0 && CurrentDirectoryOffset < MAX_PARAMETERS_OFFSET
                    && WindowTitleOffset >= 0 && WindowTitleOffset < MAX_PARAMETERS_OFFSET
                    && DesktopInfoOffset >= 0 && DesktopInfoOffset < MAX_PARAMETERS_OFFSET
                    && ImagePathNameOffset >= 0 && ImagePathNameOffset < MAX_PARAMETERS_OFFSET
                    && EnvironmentOffset >= 0 && EnvironmentOffset < MAX_PARAMETERS_OFFSET
                    && EnvironmentSizeOffset >= 0 && EnvironmentSizeOffset < MAX_PEB_OFFSET;
            }
        }
    }
}
