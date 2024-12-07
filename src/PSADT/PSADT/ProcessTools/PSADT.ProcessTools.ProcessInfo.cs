using System;
using System.IO;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace PSADT.ProcessTools
{
    public class ProcessInfo
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ProcessInfo"/> class.
        /// This constructor does NOT populate process details.
        /// </summary>
        /// <param name="processId">The process identifier.</param>
        public ProcessInfo(int processId)
        {
            if (processId < 0)
                throw new ArgumentException(nameof(processId));

            Id = processId;
        }

        /// <summary>
        /// The process identifier.
        /// </summary>
        public int Id { get; }

        /// <summary>
        /// The name of the process.
        /// </summary>
        public string? Name { get; set; }

        /// <summary>
        /// The friendly name of the process.
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// The window title of the process.
        /// </summary>
        public string WindowTitle { get; set; } = string.Empty;

        /// <summary>
        /// The full path to the process executable.
        /// </summary>
        public string? FullyQualifiedPath { get; set; }

        /// <summary>
        /// The working directory of the process.
        /// </summary>
        public string WorkingDirectory { get; set; } = string.Empty;

        /// <summary>
        /// The command line used to start the process.
        /// </summary>
        public string CommandLine { get; set; } = string.Empty;

        /// <summary>
        /// The user name under which the process is running.
        /// </summary>
        public string? Owner { get; set; }

        /// <summary>
        /// The session ID of the process.
        /// </summary>
        public int? SessionId { get; set; }

        /// <summary>
        /// The desktop info of the process.
        /// </summary>
        public string Desktop { get; set; } = string.Empty;

        /// <summary>
        /// The process start time in UTC.
        /// </summary>
        public DateTime StartTimeUtc { get; set; }

        /// <summary>
        /// The process start time in local time.
        /// </summary>
        public DateTime StartTimeLocal { get; set; }

        /// <summary>
        /// Creates and returns a fully populated ProcessInfo object for the specified process.
        /// </summary>
        /// <param name="processId">The process id.</param>
        /// <param name="getDescription">Whether to retrieve description info.</param>
        /// <returns>A fully populated ProcessInfo instance.</returns>
        public static ProcessInfo GetProcessInfo(int processId, bool getDescription = false)
        {
            var info = new ProcessInfo(processId);
            info.Populate(getDescription);
            return info;
        }

        /// <summary>
        /// Populates the current ProcessInfo instance with detailed process information.
        /// </summary>
        /// <param name="getDescription">Whether to get description or not.</param>
        private void Populate(bool getDescription)
        {
            try
            {
                using SafeProcessHandle? processHandle = ProcessHelper.OpenProcessHandle(Id);
                if (processHandle == null || processHandle.IsInvalid)
                {
                    // Can't open process, return what we have.
                    return;
                }

                bool isTargetWow64Process = ProcessHelper.IsWow64Process(processHandle);
                bool isTarget64BitProcess = Environment.Is64BitOperatingSystem && !isTargetWow64Process;

                if (!ProcessMemoryReader.GetPebAddress(processHandle, isTarget64BitProcess, isTargetWow64Process, out long pebAddress))
                {
                    return;
                }

                Peb peb = new Peb(processHandle, pebAddress, isTarget64BitProcess);
                
                FullyQualifiedPath = Path.Combine(Path.GetDirectoryName(peb.FullyQualifiedPath) ?? string.Empty, Path.GetFileName(peb.FullyQualifiedPath!).ToLowerInvariant());
                Name = ProcessHelper.GetFileNameFromFullyQualifiedPath(FullyQualifiedPath).ToLowerInvariant();

                if (getDescription)
                {
                    Description = ProcessHelper.GetProcessFileVersionInfo(FullyQualifiedPath)?.FileDescription ?? string.Empty;
                }

                WindowTitle = peb.WindowTitle ?? string.Empty;
                WorkingDirectory = ProcessHelper.RemoveTrailingBackslash(peb.WorkingDirectory);
                CommandLine = peb.CommandLine ?? string.Empty;
                Owner = peb.Owner;
                SessionId = peb.SessionId;
                Desktop = peb.DesktopInfo ?? string.Empty;
                StartTimeUtc = peb.StartTimeUtc;
                StartTimeLocal = peb.StartTimeLocal;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error retrieving process info: {ex.Message}");
            }
        }
    }
}
