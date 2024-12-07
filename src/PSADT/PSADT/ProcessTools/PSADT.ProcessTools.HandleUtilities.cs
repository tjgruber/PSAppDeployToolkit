using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Net.NetworkInformation;

namespace PSADT.ProcessTools
{
    public static class HandleUtilities
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle hFile,
            out BY_HANDLE_FILE_INFORMATION lpFileInformation);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        // Windows error codes
        private const int ERROR_SHARING_VIOLATION = 32;
        private const int ERROR_LOCK_VIOLATION = 33;
        private const int ERROR_FILE_NOT_FOUND = 2;
        private const int ERROR_PATH_NOT_FOUND = 3;
        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_NETWORK_UNREACHABLE = 1231;
        private const int ERROR_BAD_NETPATH = 53;
        private const int ERROR_NETWORK_ACCESS_DENIED = 65;
        private const int ERROR_BAD_NET_NAME = 67;

        // Access rights
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint GENERIC_EXECUTE = 0x20000000;
        private const uint GENERIC_ALL = 0x10000000;

        // Share modes
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;

        // File flags
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

        // File attributes
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        private const uint FILE_ATTRIBUTE_OFFLINE = 0x00001000;
        private const uint FILE_ATTRIBUTE_REMOTE = 0x00000010;

        public class LockCheckResult
        {
            public bool IsLocked { get; set; }
            public string? ErrorMessage { get; set; }
            public int ErrorCode { get; set; }
            public FileSystemObjectType ObjectType { get; set; }
            public bool IsNetworkPath { get; set; }
            public bool IsOffline { get; set; }
            public NetworkPathInfo? NetworkInfo { get; set; }
        }

        public class NetworkPathInfo
        {
            public string? ServerName { get; set; }
            public string? ShareName { get; set; }
            public bool IsServerReachable { get; set; }
            public long PingResponseTime { get; set; }
        }

        public enum FileSystemObjectType
        {
            Unknown,
            File,
            Directory,
            SymbolicLink,
            JunctionPoint,
            MountPoint,
            HardLink
        }

        public struct AccessRights
        {
            public bool CanRead { get; set; }
            public bool CanWrite { get; set; }
            public bool CanDelete { get; set; }
            public bool CanExecute { get; set; }
        }

        /// <summary>
        /// Checks if a path is a UNC network path
        /// </summary>
        public static bool IsUncPath(string path)
        {
            return !string.IsNullOrEmpty(path) &&
                   path.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Gets network path information for UNC paths
        /// </summary>
        private static NetworkPathInfo? GetNetworkPathInfo(string path)
        {
            if (!IsUncPath(path))
                return null;

            var pathParts = path.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            if (pathParts.Length < 2)
                return null;

            var info = new NetworkPathInfo
            {
                ServerName = pathParts[0],
                ShareName = pathParts.Length > 1 ? pathParts[1] : null
            };

            try
            {
                using (var ping = new Ping())
                {
                    var reply = ping.Send(info.ServerName, 1000);
                    info.IsServerReachable = reply?.Status == IPStatus.Success;
                    info.PingResponseTime = reply?.RoundtripTime ?? -1;
                }
            }
            catch
            {
                info.IsServerReachable = false;
                info.PingResponseTime = -1;
            }

            return info;
        }

        /// <summary>
        /// Gets the type of file system object at the specified path
        /// </summary>
        private static FileSystemObjectType GetFileSystemObjectType(string path, SafeFileHandle? handle = null)
        {
            try
            {
                var attributes = File.GetAttributes(path);

                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    // Open the reparse point itself if we need to
                    bool shouldCloseHandle = false;
                    if (handle == null || handle.IsInvalid)
                    {
                        handle = CreateFile(
                            path,
                            GENERIC_READ,
                            FileShare.ReadWrite,
                            IntPtr.Zero,
                            FileMode.Open,
                            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                            IntPtr.Zero);
                        shouldCloseHandle = true;
                    }

                    if (!handle.IsInvalid)
                    {
                        try
                        {
                            if (GetFileInformationByHandle(handle, out var fileInfo))
                            {
                                // Check the reparse point type
                                if ((fileInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                                {
                                    // For simplicity, we're not distinguishing between different reparse point types
                                    // You could add more specific checks here if needed
                                    return attributes.HasFlag(FileAttributes.Directory)
                                        ? FileSystemObjectType.JunctionPoint
                                        : FileSystemObjectType.SymbolicLink;
                                }
                            }
                        }
                        finally
                        {
                            if (shouldCloseHandle)
                                handle.Dispose();
                        }
                    }
                }

                if (attributes.HasFlag(FileAttributes.Directory))
                    return FileSystemObjectType.Directory;

                return FileSystemObjectType.File;
            }
            catch
            {
                return FileSystemObjectType.Unknown;
            }
        }

        /// <summary>
        /// Attempts to open the file or directory with exclusive access to determine if it is locked.
        /// Handles network paths and special file system objects.
        /// </summary>
        public static LockCheckResult CheckPathLockStatus(string path, bool? isDirectory = null)
        {
            if (string.IsNullOrEmpty(path))
            {
                return new LockCheckResult
                {
                    IsLocked = true,
                    ErrorMessage = "Path cannot be null or empty",
                    ErrorCode = -1
                };
            }

            // Check if it's a network path and get network information
            bool isNetworkPath = IsUncPath(path);
            var networkInfo = isNetworkPath ? GetNetworkPathInfo(path) : null;

            if (isNetworkPath && networkInfo != null && !networkInfo.IsServerReachable)
            {
                return new LockCheckResult
                {
                    IsLocked = true,
                    ErrorMessage = "Network path is unreachable",
                    ErrorCode = ERROR_NETWORK_UNREACHABLE,
                    IsNetworkPath = true,
                    NetworkInfo = networkInfo
                };
            }

            try
            {
                // Try to determine the type of file system object if not specified
                FileSystemObjectType objectType = FileSystemObjectType.Unknown;
                bool pathExists = false;

                try
                {
                    pathExists = File.Exists(path) || Directory.Exists(path);
                    if (!pathExists)
                    {
                        return new LockCheckResult
                        {
                            IsLocked = false,
                            ErrorMessage = "Path does not exist",
                            ErrorCode = ERROR_PATH_NOT_FOUND,
                            IsNetworkPath = isNetworkPath,
                            NetworkInfo = networkInfo
                        };
                    }
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    // Handle network path errors or access denied errors
                    return new LockCheckResult
                    {
                        IsLocked = true,
                        ErrorMessage = ex.Message,
                        ErrorCode = Marshal.GetLastWin32Error(),
                        IsNetworkPath = isNetworkPath,
                        NetworkInfo = networkInfo
                    };
                }

                // Determine flags based on the file system object type
                uint flags = FILE_FLAG_BACKUP_SEMANTICS; // Always include this for directories
                if (isDirectory ?? File.GetAttributes(path).HasFlag(FileAttributes.Directory))
                {
                    objectType = FileSystemObjectType.Directory;
                }
                else
                {
                    flags |= FILE_FLAG_OPEN_REPARSE_POINT; // Open reparse points directly
                }

                using SafeFileHandle handle = CreateFile(
                    path,
                    GENERIC_READ | GENERIC_WRITE,
                    FileShare.None, // Try exclusive access
                    IntPtr.Zero,
                    FileMode.Open,
                    flags,
                    IntPtr.Zero);

                if (handle.IsInvalid)
                {
                    int error = Marshal.GetLastWin32Error();
                    string errorMessage = GetErrorMessage(error);

                    // Get more detailed file system object type information
                    if (objectType == FileSystemObjectType.Unknown)
                    {
                        objectType = GetFileSystemObjectType(path);
                    }

                    // Check if the file is offline
                    bool isOffline = false;
                    try
                    {
                        var attributes = File.GetAttributes(path);
                        isOffline = attributes.HasFlag(FileAttributes.Offline);
                    }
                    catch
                    {
                        // Ignore attribute reading errors
                    }

                    return new LockCheckResult
                    {
                        IsLocked = error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION,
                        ErrorMessage = errorMessage,
                        ErrorCode = error,
                        ObjectType = objectType,
                        IsNetworkPath = isNetworkPath,
                        IsOffline = isOffline,
                        NetworkInfo = networkInfo
                    };
                }

                // If we successfully opened the handle, get the file system object type
                objectType = GetFileSystemObjectType(path, handle);

                return new LockCheckResult
                {
                    IsLocked = false,
                    ErrorMessage = "Path is not locked",
                    ErrorCode = 0,
                    ObjectType = objectType,
                    IsNetworkPath = isNetworkPath,
                    IsOffline = false,
                    NetworkInfo = networkInfo
                };
            }
            catch (Exception ex)
            {
                return new LockCheckResult
                {
                    IsLocked = true,
                    ErrorMessage = ex.Message,
                    ErrorCode = Marshal.GetLastWin32Error(),
                    ObjectType = FileSystemObjectType.Unknown,
                    IsNetworkPath = isNetworkPath,
                    NetworkInfo = networkInfo
                };
            }
        }

        private static string GetErrorMessage(int errorCode)
        {
            return errorCode switch
            {
                ERROR_SHARING_VIOLATION => "The process cannot access the file because it is being used by another process",
                ERROR_LOCK_VIOLATION => "The process cannot access the file because another process has locked a portion of the file",
                ERROR_ACCESS_DENIED => "Access is denied",
                ERROR_FILE_NOT_FOUND => "The system cannot find the file specified",
                ERROR_PATH_NOT_FOUND => "The system cannot find the path specified",
                ERROR_NETWORK_UNREACHABLE => "The network is unreachable",
                ERROR_BAD_NETPATH => "The network path was not found",
                ERROR_NETWORK_ACCESS_DENIED => "Network access is denied",
                ERROR_BAD_NET_NAME => "The network name cannot be found",
                _ => $"Unknown error occurred (Error code: {errorCode})"
            };
        }

        private static AccessRights DecodeBasicAccess(uint grantedAccess)
        {
            return new AccessRights
            {
                CanRead = (grantedAccess & GENERIC_READ) != 0
                         || (grantedAccess & 0x0001) != 0  // FILE_READ_DATA
                         || (grantedAccess & 0x0008) != 0  // FILE_READ_EA
                         || (grantedAccess & 0x0080) != 0, // FILE_READ_ATTRIBUTES

                CanWrite = (grantedAccess & GENERIC_WRITE) != 0
                          || (grantedAccess & 0x0002) != 0  // FILE_WRITE_DATA
                          || (grantedAccess & 0x0004) != 0  // FILE_APPEND_DATA
                          || (grantedAccess & 0x0010) != 0  // FILE_WRITE_EA
                          || (grantedAccess & 0x0100) != 0, // FILE_WRITE_ATTRIBUTES

                CanDelete = (grantedAccess & 0x00010000) != 0, // DELETE

                CanExecute = (grantedAccess & GENERIC_EXECUTE) != 0
                            || (grantedAccess & 0x0020) != 0  // FILE_EXECUTE
            };
        }

        public static string GetAccessMaskString(uint grantedAccess, bool enhanced = false)
        {
            var accessRights = DecodeBasicAccess(grantedAccess);
            var sb = new StringBuilder();

            // Basic permissions
            sb.Append(accessRights.CanRead ? 'R' : '-');
            sb.Append(accessRights.CanWrite ? 'W' : '-');
            sb.Append(accessRights.CanDelete ? 'D' : '-');
            sb.Append(accessRights.CanExecute ? 'X' : '-');

            if (enhanced)
            {
                var extraRights = new List<string>();

                if ((grantedAccess & 0x00100000) != 0) extraRights.Add("SYNCHRONIZE");
                if ((grantedAccess & 0x0040) != 0) extraRights.Add("FILE_DELETE_CHILD");
                if (((grantedAccess & 0x0001) != 0) && !accessRights.CanRead) extraRights.Add("FILE_LIST_DIRECTORY");

                if (extraRights.Count > 0)
                {
                    sb.Append(", ");
                    sb.Append(string.Join(", ", extraRights));
                }
            }

            return sb.ToString();
        }
    }
}