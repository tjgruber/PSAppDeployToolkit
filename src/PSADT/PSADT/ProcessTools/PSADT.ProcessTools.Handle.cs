using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PSADT.PInvoke;


namespace PSADT.ProcessTools
{
    public static class Handle
    {
        #region Constants and Enums

        private const uint DUPLICATE_SAME_ACCESS = 0x00000002;
        private const uint DUPLICATE_CLOSE_SOURCE = 0x00000001;

        private const uint PROCESS_DUP_HANDLE = 0x0040;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;

        private enum OBJECT_INFORMATION_CLASS
        {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2
        }

        private enum SYSTEM_INFORMATION_CLASS
        {
            SystemExtendedHandleInformation = 64
        }

        private enum FILE_INFORMATION_CLASS
        {
            FileProcessIdsUsingFileInformation = 47
        }

        // Short timeout for name queries
        private static readonly TimeSpan NameQueryTimeout = TimeSpan.FromMilliseconds(5);

        // Limit concurrency for name queries
        private static readonly SemaphoreSlim nameQuerySemaphore = new SemaphoreSlim(Environment.ProcessorCount, Environment.ProcessorCount);

        #endregion

        #region Structures

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_STATUS_BLOCK
        {
            public uint Status;
            public IntPtr Information;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_NAME_INFORMATION
        {
            public UNICODE_STRING Name;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_TYPE_INFORMATION
        {
            public UNICODE_STRING Name;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_HANDLE_INFORMATION_EX
        {
            public IntPtr NumberOfHandles;
            public IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        {
            public IntPtr Object;
            public IntPtr UniqueProcessId;
            public IntPtr HandleValue;
            public uint GrantedAccess;
            public ushort CreatorBackTraceIndex;
            public ushort ObjectTypeIndex;
            public uint HandleAttributes;
            public uint Reserved;
        }

        #endregion

        #region P/Invoke Declarations

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationFile(
            SafeFileHandle FileHandle,
            ref IO_STATUS_BLOCK IoStatusBlock,
            IntPtr FileInformation,
            uint Length,
            FILE_INFORMATION_CLASS FileInformationClass
        );

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        private static extern int NtQueryObject(
            IntPtr Handle,
            OBJECT_INFORMATION_CLASS ObjectInformationClass,
            IntPtr ObjectInformation,
            int ObjectInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        private static extern uint RtlNtStatusToDosError(int Status);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeProcessHandle OpenProcess(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(
            SafeProcessHandle hSourceProcessHandle,
            IntPtr hSourceHandle,
            SafeProcessHandle hTargetProcessHandle,
            out SafeFileHandle lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwOptions
        );

        [DllImport("kernel32.dll")]
        private static extern SafeProcessHandle GetCurrentProcess();

        #endregion

        #region Public Methods

        public static IEnumerable<ProcessHandleInfo> GetPathHandles(string path, PathHandleOptions? options = null)
        {
            if (string.IsNullOrEmpty(path))
                throw new ArgumentNullException(nameof(path));

            bool isDirectory = Directory.Exists(path);

            // Retrieve all system handles once
            var systemHandles = GetSystemHandles().ToList();

            // Get all accessible processes once
            var accessibleProcesses = System.Diagnostics.Process.GetProcesses()
                .Where(p => p.Id > 0 && CanAccessProcess(p.Id))
                .ToList();

            var processIds = new HashSet<int>();

            if (isDirectory)
            {
                processIds.UnionWith(GetProcessesByWorkingDirectory(path, accessibleProcesses));
                processIds.UnionWith(GetProcessesWithDirectoryHandles(path, accessibleProcesses, options, systemHandles));
            }
            else if (File.Exists(path))
            {
                var handlesByProcess = systemHandles
                    .GroupBy(h => h.UniqueProcessId.ToInt32())
                    .ToDictionary(g => g.Key, g => g.ToList());

                foreach (var process in accessibleProcesses)
                {
                    if (!handlesByProcess.ContainsKey(process.Id))
                        continue;

                    using var processHandle = OpenProcess(
                        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                        false,
                        (uint)process.Id
                    );

                    if (processHandle.IsInvalid)
                        continue;

                    bool found = false;
                    foreach (var handleEntry in handlesByProcess[process.Id])
                    {
                        using var duplicatedHandle = DuplicateProcessHandle(processHandle, handleEntry.HandleValue);
                        if (duplicatedHandle == null || duplicatedHandle.IsInvalid)
                            continue;

                        string? typeName = GetTypeNameFromHandle(duplicatedHandle);
                        if (!string.Equals(typeName, "File", StringComparison.OrdinalIgnoreCase))
                            continue;

                        if (IsUnsafeToQueryFileHandleName(handleEntry.GrantedAccess, handleEntry.HandleAttributes))
                            continue;

                        string? objectName = GetObjectNameFromHandleWithTimeout(duplicatedHandle);
                        if (string.IsNullOrEmpty(objectName) || !objectName!.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                            continue;

                        string dosPath = NtFileNameConverter.NtFileNameToDos(objectName);
                        string normalizedDosPath = dosPath.TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant();
                        string normalizedPath = path.TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant();

                        // For a file, exact match
                        if (normalizedDosPath.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase))
                        {
                            processIds.Add(process.Id);
                            found = true;
                            break;
                        }
                    }

                    if (found)
                        continue;
                }
            }

            var accessibleProcessIds = new HashSet<int>(accessibleProcesses.Select(p => p.Id));
            processIds.IntersectWith(accessibleProcessIds);

            if (processIds.Count == 0)
                yield break;

            foreach (ProcessHandleInfo handleInfo in GetLockingHandles(processIds, path, isDirectory, options, systemHandles))
            {
                yield return handleInfo;
            }
        }

        public static void CloseHandle(uint processId, IntPtr handleValue)
        {
            using var sourceProcess = OpenProcess(
                PROCESS_DUP_HANDLE,
                false,
                processId
            );

            if (sourceProcess.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    $"Failed to open process {processId}");
            }

            bool success = DuplicateHandle(
                sourceProcess,
                handleValue,
                GetCurrentProcess(),
                out SafeFileHandle targetHandle,
                0,
                false,
                DUPLICATE_CLOSE_SOURCE
            );

            if (!success)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    $"Failed to close handle {handleValue} in process {processId}");
            }

            if (!targetHandle.IsInvalid)
            {
                targetHandle.Dispose();
            }
        }

        #endregion

        #region Private Methods

        // Aggressive filtering to avoid hangs
        private static bool IsUnsafeToQueryFileHandleName(uint grantedAccess, uint handleAttributes)
        {
            // Known problematic patterns
            if ((grantedAccess == 0x120089 && handleAttributes == 2) ||
                (grantedAccess == 0x120189 && (handleAttributes == 0 || handleAttributes == 2)) ||
                (grantedAccess == 0x12019f && (handleAttributes == 0 || handleAttributes == 2)) ||
                (grantedAccess == 0x1a019f && (handleAttributes == 0 || handleAttributes == 2)) ||
                (grantedAccess == 0x0012019f && handleAttributes == 0))
            {
                return true;
            }

            return false;
        }

        private static IEnumerable<int> GetProcessesByWorkingDirectory(string directoryPath, IEnumerable<System.Diagnostics.Process> accessibleProcesses)
        {
            var processIds = new HashSet<int>();
            string? targetDirectory = ProcessHelper.RemoveTrailingBackslash(directoryPath)?.ToLowerInvariant();

            foreach (var process in accessibleProcesses)
            {
                try
                {
                    string? workingDirectory = process.GetWorkingDirectory()?.ToLowerInvariant();
                    if (workingDirectory != null && workingDirectory.Equals(targetDirectory))
                    {
                        processIds.Add(process.Id);
                    }
                }
                catch
                {
                    // Ignore
                }
            }

            return processIds;
        }

        private static IEnumerable<int> GetProcessesWithDirectoryHandles(
            string directoryPath,
            IEnumerable<System.Diagnostics.Process> accessibleProcesses,
            PathHandleOptions? options,
            List<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> systemHandles)
        {
            var processIds = new HashSet<int>();
            string normalizedPath = ProcessHelper.RemoveTrailingBackslash(directoryPath)?.ToLowerInvariant() ?? string.Empty;

            foreach (var process in accessibleProcesses)
            {
                try
                {
                    using var processHandle = OpenProcess(
                        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                        false,
                        (uint)process.Id
                    );

                    if (processHandle.IsInvalid)
                        continue;

                    var handlesForProcess = systemHandles.Where(h => h.UniqueProcessId.ToInt32() == process.Id);
                    bool found = false;

                    foreach (var handleEntry in handlesForProcess)
                    {
                        using var duplicatedHandle = DuplicateProcessHandle(processHandle, handleEntry.HandleValue);
                        if (duplicatedHandle == null || duplicatedHandle.IsInvalid)
                            continue;

                        string? typeName = GetTypeNameFromHandle(duplicatedHandle);
                        if (!string.Equals(typeName, "File", StringComparison.OrdinalIgnoreCase))
                            continue;

                        if (IsUnsafeToQueryFileHandleName(handleEntry.GrantedAccess, handleEntry.HandleAttributes))
                            continue;

                        string? objectName = GetObjectNameFromHandleWithTimeout(duplicatedHandle);
                        if (string.IsNullOrEmpty(objectName) || !objectName!.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                            continue;

                        string dosPath = NtFileNameConverter.NtFileNameToDos(objectName);
                        string normalizedDosPath = dosPath.TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant();

                        if (IsPathMatch(normalizedDosPath, normalizedPath, true, options))
                        {
                            processIds.Add(process.Id);
                            found = true;
                            break;
                        }
                    }

                    if (found)
                        continue;
                }
                catch
                {
                    continue;
                }
            }

            return processIds;
        }

        private static IEnumerable<ProcessHandleInfo> GetLockingHandles(
            IEnumerable<int> processIds,
            string path,
            bool isDirectory,
            PathHandleOptions? options,
            List<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> systemHandles)
        {
            foreach (int processId in processIds)
            {
                var processHandles = systemHandles.Where(h => h.UniqueProcessId.ToInt32() == processId);
                foreach (var handleInfo in GetProcessHandlesForPath(processId, path, isDirectory, processHandles, options))
                {
                    yield return handleInfo;
                }
            }
        }

        private static IEnumerable<ProcessHandleInfo> GetProcessHandlesForPath(
            int processId,
            string path,
            bool isDirectory,
            IEnumerable<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> processHandles,
            PathHandleOptions? options)
        {
            using var processHandle = OpenProcess(
                PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                false,
                (uint)processId
            );

            if (processHandle.IsInvalid)
                yield break;

            string normalizedPath = Path.GetFullPath(path)
                .TrimEnd(Path.DirectorySeparatorChar)
                .ToLowerInvariant();

            foreach (var handleEntry in processHandles)
            {
                using var duplicatedHandle = DuplicateProcessHandle(processHandle, handleEntry.HandleValue);
                if (duplicatedHandle == null || duplicatedHandle.IsInvalid)
                    continue;

                string? typeName = GetTypeNameFromHandle(duplicatedHandle);
                if (!string.Equals(typeName, "File", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (IsUnsafeToQueryFileHandleName(handleEntry.GrantedAccess, handleEntry.HandleAttributes))
                    continue;

                string? objectName = GetObjectNameFromHandleWithTimeout(duplicatedHandle);
                if (string.IsNullOrEmpty(objectName) || !objectName!.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                    continue;

                string dosPath = NtFileNameConverter.NtFileNameToDos(objectName);
                string normalizedDosPath = dosPath.TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant();

                if (IsPathMatch(normalizedDosPath, normalizedPath, isDirectory, options))
                {
                    yield return new ProcessHandleInfo(processId, getDescription: true)
                    {
                        HandlePath = dosPath,
                        IsHandlePathDirectory = isDirectory,
                        HandleDisplay = $"0x{handleEntry.HandleValue.ToInt64():X}",
                        Handle = handleEntry.HandleValue.ToInt32(),
                        HandleType = typeName,
                        HandleFlags = handleEntry.HandleAttributes.ToString(),
                        HandleAccessMask = $"0x{handleEntry.GrantedAccess:X8} ({HandleUtilities.GetAccessMaskString(handleEntry.GrantedAccess, enhanced: true)})"
                    };
                }
            }
        }

        private static SafeFileHandle? DuplicateProcessHandle(SafeProcessHandle processHandle, IntPtr handleValue)
        {
            try
            {
                bool success = DuplicateHandle(
                    processHandle,
                    handleValue,
                    GetCurrentProcess(),
                    out SafeFileHandle duplicatedHandle,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS
                );

                if (!success || duplicatedHandle == null || duplicatedHandle.IsInvalid)
                {
                    duplicatedHandle?.Dispose();
                    return null;
                }

                return duplicatedHandle;
            }
            catch
            {
                return null;
            }
        }

        private static string? GetObjectNameFromHandleWithTimeout(SafeFileHandle handle)
        {
            if (!nameQuerySemaphore.Wait(0))
            {
                if (!nameQuerySemaphore.Wait((int)NameQueryTimeout.TotalMilliseconds))
                    return null;
            }

            try
            {
                var cts = new CancellationTokenSource(NameQueryTimeout);
                var task = Task.Run(() => GetObjectNameFromHandle(handle), cts.Token);

                try
                {
                    if (task.Wait(NameQueryTimeout))
                    {
                        return task.Result;
                    }
                    else
                    {
                        // Timed out; skip this handle
                        return null;
                    }
                }
                catch
                {
                    return null;
                }
                finally
                {
                    cts.Cancel();
                }
            }
            finally
            {
                nameQuerySemaphore.Release();
            }
        }

        private static string? GetObjectNameFromHandle(SafeFileHandle handle)
        {
            int bufferSize = 0x1000;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                int status = NtQueryObject(
                    handle.DangerousGetHandle(),
                    OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                    buffer,
                    bufferSize,
                    out int returnLength
                );

                if (status == NTStatus.STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    bufferSize = returnLength;
                    buffer = Marshal.AllocHGlobal(bufferSize);

                    status = NtQueryObject(
                        handle.DangerousGetHandle(),
                        OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                        buffer,
                        bufferSize,
                        out returnLength
                    );
                }

                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return null;
                }

                var objectNameInfo = Marshal.PtrToStructure<OBJECT_NAME_INFORMATION>(buffer);
                if (objectNameInfo.Name.Buffer == IntPtr.Zero || objectNameInfo.Name.Length == 0)
                    return null;

                string name = Marshal.PtrToStringUni(objectNameInfo.Name.Buffer, objectNameInfo.Name.Length / 2);
                return name;
            }
            catch
            {
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string? GetTypeNameFromHandle(SafeFileHandle handle)
        {
            int bufferSize = 0x1000;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                int status = NtQueryObject(
                    handle.DangerousGetHandle(),
                    OBJECT_INFORMATION_CLASS.ObjectTypeInformation,
                    buffer,
                    bufferSize,
                    out int returnLength
                );

                if (status == NTStatus.STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    bufferSize = returnLength;
                    buffer = Marshal.AllocHGlobal(bufferSize);

                    status = NtQueryObject(
                        handle.DangerousGetHandle(),
                        OBJECT_INFORMATION_CLASS.ObjectTypeInformation,
                        buffer,
                        bufferSize,
                        out returnLength
                    );
                }

                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return null;
                }

                var objectTypeInfo = Marshal.PtrToStructure<OBJECT_TYPE_INFORMATION>(buffer);
                if (objectTypeInfo.Name.Buffer == IntPtr.Zero || objectTypeInfo.Name.Length == 0)
                    return null;

                string name = Marshal.PtrToStringUni(objectTypeInfo.Name.Buffer, objectTypeInfo.Name.Length / 2);
                return name;
            }
            catch
            {
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static IEnumerable<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> GetSystemHandles()
        {
            int handleInfoSize = 0x10000;
            IntPtr handleInfoPtr = IntPtr.Zero;

            try
            {
                while (true)
                {
                    handleInfoPtr = Marshal.AllocHGlobal(handleInfoSize);

                    int status = NtQuerySystemInformation(
                        SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                        handleInfoPtr,
                        handleInfoSize,
                        out int returnLength
                    );

                    if (status == NTStatus.STATUS_INFO_LENGTH_MISMATCH)
                    {
                        Marshal.FreeHGlobal(handleInfoPtr);
                        handleInfoPtr = IntPtr.Zero;
                        handleInfoSize = returnLength + 0x1000;
                        continue;
                    }

                    if (status != NTStatus.STATUS_SUCCESS)
                    {
                        yield break;
                    }

                    var handleInfo = Marshal.PtrToStructure<SYSTEM_HANDLE_INFORMATION_EX>(handleInfoPtr);
                    long handleCount = handleInfo.NumberOfHandles.ToInt64();

                    if (handleCount <= 0 || handleCount > 1_000_000)
                    {
                        yield break;
                    }

                    IntPtr handleEntryPtr = handleInfoPtr + Marshal.SizeOf<SYSTEM_HANDLE_INFORMATION_EX>();
                    int sizeOfHandleEntry = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();

                    for (long i = 0; i < handleCount; i++)
                    {
                        var handleEntry = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(handleEntryPtr);
                        yield return handleEntry;

                        handleEntryPtr += sizeOfHandleEntry;
                    }

                    break;
                }
            }
            finally
            {
                if (handleInfoPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(handleInfoPtr);
                }
            }
        }

        private static Exception GetException(int status)
        {
            uint error = RtlNtStatusToDosError(status);
            return new Win32Exception((int)error);
        }

        private static bool CanAccessProcess(int processId)
        {
            try
            {
                using (var handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)processId))
                {
                    return !handle.IsInvalid;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Determine if a given path matches the criteria based on isDirectory, CheckFiles, and CheckChildPaths.
        /// </summary>
        private static bool IsPathMatch(string normalizedDosPath, string normalizedSearchPath, bool isDirectory, PathHandleOptions? options)
        {
            // If this is a file scenario (from tests?), we assume isDirectory is true if original path is a directory.
            // Determine if dosPath is a file or directory:
            bool pathIsFile = File.Exists(normalizedDosPath);
            bool pathIsDirectory = !pathIsFile && Directory.Exists(normalizedDosPath);

            // If neither file nor directory is found, treat as file by default (some handles might not map to real FS objects)
            if (!pathIsFile && !pathIsDirectory)
                pathIsFile = true; // safer default

            // If the original target was a directory:
            if (isDirectory)
            {
                bool checkFiles = options?.CheckFiles == true;
                bool checkChildPaths = options?.CheckChildPaths == true;

                // Scenario: Exact directory only (no files, no subdirs)
                if (!checkFiles && !checkChildPaths)
                {
                    // Must match exactly the directory itself
                    return normalizedDosPath.Equals(normalizedSearchPath, StringComparison.OrdinalIgnoreCase);
                }

                // Scenario: Directory with files in directory only (CheckFiles = true, CheckChildPaths = false)
                if (checkFiles && !checkChildPaths)
                {
                    // Allow exact directory match
                    if (normalizedDosPath.Equals(normalizedSearchPath, StringComparison.OrdinalIgnoreCase))
                        return true;

                    // If path is a file directly in that directory: parent must be exactly normalizedSearchPath
                    if (pathIsFile)
                    {
                        string? parent = Path.GetDirectoryName(normalizedDosPath)?.ToLowerInvariant();
                        return parent != null && parent.Equals(normalizedSearchPath, StringComparison.OrdinalIgnoreCase);
                    }

                    // No subdirectories allowed here
                    return false;
                }

                // Scenario: Directory with subdirectories only (CheckChildPaths = true, CheckFiles = false)
                if (!checkFiles && checkChildPaths)
                {
                    // Allow directory itself
                    if (normalizedDosPath.Equals(normalizedSearchPath, StringComparison.OrdinalIgnoreCase))
                        return true;

                    // No files allowed
                    if (pathIsFile)
                        return false;

                    // Must be a subdirectory under search path
                    // If path is directory, check if it starts with normalizedSearchPath + "\"
                    return normalizedDosPath.StartsWith($"{normalizedSearchPath}{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase);
                }

                // Scenario: Directory with files and subdirectories (CheckChildPaths = true, CheckFiles = true)
                if (checkFiles && checkChildPaths)
                {
                    // Allow directory itself
                    if (normalizedDosPath.Equals(normalizedSearchPath, StringComparison.OrdinalIgnoreCase))
                        return true;

                    // Allow any file or directory under the search path
                    return normalizedDosPath.StartsWith($"{normalizedSearchPath}{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase);
                }

                // Fallback
                return false;
            }
            else
            {
                // If it's a file path scenario:
                // For a file test, must match exactly the file path.
                return normalizedDosPath.Equals(normalizedSearchPath, StringComparison.OrdinalIgnoreCase);
            }
        }

        #endregion
    }

    public class PathHandleOptions
    {
        public bool CheckFiles { get; set; }
        public bool CheckChildPaths { get; set; }
    }
}
