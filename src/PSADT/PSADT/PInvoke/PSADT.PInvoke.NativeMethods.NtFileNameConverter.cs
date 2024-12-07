using System;
using System.Linq;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PSADT.PInvoke
{
    public static class NtFileNameConverter
    {
        #region Native Types & Constants

        [Flags]
        public enum SymbolicLinkAccessRights : uint
        {
            SYMBOLIC_LINK_QUERY = 0x0001,
        }

        [Flags]
        public enum AttributeFlags : uint
        {
            None = 0x00000000,
            CaseInsensitive = 0x00000040,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                if (Buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(Buffer);
                    Buffer = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName; // PUNICODE_STRING
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        private static extern int NtOpenSymbolicLinkObject(
            out SafeKernelObjectHandle LinkHandle,
            SymbolicLinkAccessRights DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        private static extern int NtQuerySymbolicLinkObject(
            SafeKernelObjectHandle LinkHandle,
            ref UNICODE_STRING LinkTarget,
            out uint ReturnedLength);

        [DllImport("ntdll.dll")]
        private static extern int NtClose(IntPtr Handle);

        // SafeHandle implementation for kernel objects
        public class SafeKernelObjectHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeKernelObjectHandle() : base(true) { }

            protected override bool ReleaseHandle()
            {
                return NtClose(handle) == 0;
            }
        }

        #endregion

        #region Device Map Cache

        private static readonly ConcurrentDictionary<string, string> deviceMap = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly object deviceMapLock = new object();
        private static bool deviceMapInitialized = false;

        private static void EnsureDeviceMap()
        {
            if (deviceMapInitialized)
                return;

            lock (deviceMapLock)
            {
                if (deviceMapInitialized)
                    return;

                BuildDeviceMap();
                deviceMapInitialized = true;
            }
        }

        private static void BuildDeviceMap()
        {
            // Map drive letters
            for (char drive = 'A'; drive <= 'Z'; drive++)
            {
                string driveLetter = $"{drive}:";
                try
                {
                    using NtSymbolicLink link = NtSymbolicLink.Open($@"\??\{driveLetter}");
                    string target = link.GetTarget();
                    if (!string.IsNullOrEmpty(target))
                    {
                        deviceMap.TryAdd(target.TrimEnd('\\'), driveLetter);
                    }
                }
                catch
                {
                    // Ignore exceptions and continue
                    continue;
                }
            }

            // Add network device mapping
            deviceMap.TryAdd(@"\Device\Mup", @"\");

            // Add system root mapping
            deviceMap.TryAdd(@"\SystemRoot", Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        }

        #endregion

        #region NtSymbolicLink Class

        public class NtSymbolicLink : IDisposable
        {
            private SafeKernelObjectHandle _handle;

            private NtSymbolicLink(SafeKernelObjectHandle handle)
            {
                _handle = handle;
            }

            public static NtSymbolicLink Open(string path)
            {
                using UNICODE_STRING objectName = new UNICODE_STRING(path);
                OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                    RootDirectory = IntPtr.Zero,
                    ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING))),
                    Attributes = (uint)AttributeFlags.CaseInsensitive,
                    SecurityDescriptor = IntPtr.Zero,
                    SecurityQualityOfService = IntPtr.Zero
                };
                Marshal.StructureToPtr(objectName, objAttr.ObjectName, false);

                int status = NtOpenSymbolicLinkObject(
                    out SafeKernelObjectHandle handle,
                    SymbolicLinkAccessRights.SYMBOLIC_LINK_QUERY,
                    ref objAttr);

                Marshal.FreeHGlobal(objAttr.ObjectName);
                objectName.Dispose();

                if (status != 0 || handle.IsInvalid)
                {
                    throw new InvalidOperationException($"Failed to open symbolic link '{path}'. NTSTATUS: 0x{status:X8}");
                }

                return new NtSymbolicLink(handle);
            }

            public string GetTarget()
            {
                const int MAX_PATH = 1024;
                using var targetBuffer = new SafeHGlobalHandle(MAX_PATH * 2);
                var targetUs = new UNICODE_STRING
                {
                    Buffer = targetBuffer.DangerousGetHandle(),
                    Length = 0,
                    MaximumLength = (ushort)(MAX_PATH * 2)
                };

                int status = NtQuerySymbolicLinkObject(_handle, ref targetUs, out _);

                if (status != 0)
                {
                    throw new InvalidOperationException($"Failed to query symbolic link. NTSTATUS: 0x{status:X8}");
                }

                string? target = Marshal.PtrToStringUni(targetUs.Buffer, targetUs.Length / 2);
                return target ?? string.Empty;
            }

            public void Dispose()
            {
                if (_handle != null && !_handle.IsInvalid)
                {
                    _handle.Dispose();
                    _handle = null!;
                }
                GC.SuppressFinalize(this);
            }
        }

        #endregion

        #region NtFileNameToDos Method

        /// <summary>
        /// Attempt to convert an NT device filename to a DOS filename.
        /// </summary>
        /// <param name="filename">The filename to convert.</param>
        /// <returns>
        /// The converted string. Returns a path prefixed with GLOBALROOT if it doesn't understand the format.
        /// </returns>
        public static string NtFileNameToDos(string filename)
        {
            if (string.IsNullOrEmpty(filename) || !filename.StartsWith(@"\"))
            {
                return filename;
            }

            EnsureDeviceMap();

            // Handle special cases
            if (filename.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                return $@"\\{filename.Substring(8)}";
            }
            else if (filename.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
            {
                return filename.Substring(4);
            }

            // Search for the longest matching device name
            string result = filename;
            foreach (var mapping in deviceMap.OrderByDescending(k => k.Key.Length))
            {
                if (filename.StartsWith(mapping.Key, StringComparison.OrdinalIgnoreCase))
                {
                    string pathRest = filename.Substring(mapping.Key.Length);
                    result = $"{mapping.Value}{pathRest}";
                    return result;
                }
            }

            return $@"\\.\GLOBALROOT{filename}";
        }

        #endregion
    }
}
