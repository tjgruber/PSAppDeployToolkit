using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.ComponentModel;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PSADT.PInvoke;

namespace PSADT.ProcessTools
{
    public static class ProcessHelper
    {
        public static string? GetWorkingDirectory(SafeProcessHandle processHandle)
        {
            // Determine target process architecture
            bool isTargetWow64Process = IsWow64Process(processHandle);
            bool isTarget64BitProcess = Environment.Is64BitOperatingSystem && !isTargetWow64Process;

            if (!ProcessMemoryReader.GetPebAddress(processHandle, isTarget64BitProcess, isTargetWow64Process, out long pebAddress))
            {
                return null;
            }

            Peb.PebOffsets offsets = Peb.PebOffsets.Get(isTarget64BitProcess);

            if (!Peb.TryReadRemoteStructure<IntPtr>(processHandle, pebAddress + offsets.ProcessParametersOffset, out var processParametersAddress))
            {
                return null;
            }

            // Read the WorkingDirectory from process parameters
            return Peb.ReadRemoteUnicodeString(processHandle, processParametersAddress.ToInt64() + offsets.CurrentDirectoryOffset, isTarget64BitProcess);
        }

        public static string? GetCommandLine(SafeProcessHandle processHandle)
        {
            // Determine target process architecture
            bool isTargetWow64Process = IsWow64Process(processHandle);
            bool isTarget64BitProcess = Environment.Is64BitOperatingSystem && !isTargetWow64Process;

            if (!ProcessMemoryReader.GetPebAddress(processHandle, isTarget64BitProcess, isTargetWow64Process, out long pebAddress))
            {
                return null;
            }

            Peb.PebOffsets offsets = Peb.PebOffsets.Get(isTarget64BitProcess);

            if (!Peb.TryReadRemoteStructure<IntPtr>(processHandle, pebAddress + offsets.ProcessParametersOffset, out var processParametersAddress))
            {
                return null;
            }

            // Read the CommandLine from process parameters
            return Peb.ReadRemoteUnicodeString(processHandle, processParametersAddress.ToInt64() + offsets.CommandLineOffset, isTarget64BitProcess);
        }

        public static SafeProcessHandle? OpenProcessHandle(int processId)
        {
            if (processId <= 0)
            {
                return null;
            }

            SafeProcessHandle handle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ,
                false,
                (uint)processId);

            return handle.IsInvalid ? null : handle;
        }

        public static long GetProcessStartTimeLongUtc(SafeProcessHandle processHandle)
        {
            if (!NativeMethods.GetProcessTimes(
                processHandle,
                out PInvoke.FILETIME processStartTimeFT,
                out _,
                out _,
                out _))
            {
                int errorCode = Marshal.GetLastWin32Error();
                Debug.WriteLine($"Failed to get process start time with error code [{errorCode}].");

                return 0;
            }

            return FileTimeToLongUtc(processStartTimeFT);
        }

        public static long FileTimeToLongUtc(PInvoke.FILETIME fileTime)
        {
            // Combine the high and low parts into a ulong to avoid overflow
            ulong fileTimeLong = ((ulong)fileTime.dwHighDateTime << 32) | (ulong)fileTime.dwLowDateTime;

            // If the FILETIME is zero or invalid, return zero
            if (fileTimeLong == 0 || fileTimeLong > (ulong)DateTime.MaxValue.ToFileTimeUtc())
                return 0;

            return (long)fileTimeLong;
        }

        public static string GetProcessOwner(SafeProcessHandle processHandle)
        {
            if (processHandle.IsInvalid)
                return "Unknown";

            SafeAccessToken? tokenHandle = null;
            try
            {
                if (!NativeMethods.OpenProcessToken(processHandle, NativeMethods.TOKEN_QUERY, out tokenHandle))
                    return "Unknown";

                using (tokenHandle)
                {
                    NativeMethods.GetTokenInformation(
                        tokenHandle,
                        TOKEN_INFORMATION_CLASS.TokenUser,
                        IntPtr.Zero,
                        0,
                        out int tokenInfoLength);

                    if (tokenInfoLength == 0)
                        return "Unknown";

                    using var tokenInfo = new SafeHGlobalHandle((int)tokenInfoLength);
                    if (NativeMethods.GetTokenInformation(
                        tokenHandle,
                        TOKEN_INFORMATION_CLASS.TokenUser,
                        tokenInfo.DangerousGetHandle(),
                        tokenInfoLength,
                        out tokenInfoLength))
                    {
                        var tokenUser = Marshal.PtrToStructure<TOKEN_USER>(tokenInfo.DangerousGetHandle());

                        var sid = new SecurityIdentifier(tokenUser.User.Sid);
                        try
                        {
                            var account = sid.Translate(typeof(NTAccount)) as NTAccount;
                            return account?.Value ?? "Unknown";
                        }
                        catch
                        {
                            return sid.Value;
                        }
                    }
                }
            }
            catch
            {
                // Ignore any errors and return Unknown
            }

            return "Unknown";
        }

        public static bool IsCurrent32BitProcess()
        {
            return IntPtr.Size == 4;
        }

        public static bool IsWow64Process(SafeProcessHandle processHandle)
        {
            bool isWow64;
            if (!NativeMethods.IsWow64Process(processHandle, out isWow64))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return isWow64;
        }

        public static int? GetProcessSessionId(int processId)
        {
            if (processId < 0)
                return null;

            if (NativeMethods.ProcessIdToSessionId((uint)processId, out uint sessionId))
            {
                return (int)sessionId;
            }

            return null;
        }

        public static string GetProcessFullyQualifiedPath(SafeProcessHandle processHandle)
        {
            string path = string.Empty;

            uint bufferSize = 1024;
            var pathBuilder = new StringBuilder((int)bufferSize);

            uint bufferLength = (uint)pathBuilder.Capacity + 1;
            if (NativeMethods.QueryFullProcessImageName(processHandle, 0, pathBuilder, ref bufferLength))
            {
                path = pathBuilder.ToString(0, (int)bufferLength).TrimEnd('\0');
            }

            return path;
        }

        public static string GetFileNameFromFullyQualifiedPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return string.Empty;

            return Path.GetFileName(path);
        }

        public static FileVersionInfo? GetProcessFileVersionInfo(string? path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return null;

            return FileVersionInfo.GetVersionInfo(path);
        }

        public static string RemoveTrailingBackslash(string? path)
        {
            return string.IsNullOrWhiteSpace(path) ? string.Empty : path!.TrimEnd(Path.DirectorySeparatorChar);
        }
    }
}
