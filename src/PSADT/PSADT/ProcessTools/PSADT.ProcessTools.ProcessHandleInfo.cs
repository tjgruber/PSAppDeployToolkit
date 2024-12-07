using System;
using static PSADT.ProcessTools.HandleUtilities;

namespace PSADT.ProcessTools
{
    /// <summary>
    /// Contains detailed information about a process that has locks on files or directories.
    /// Inherits from ProcessInfo.
    /// </summary>
    public class ProcessHandleInfo : ProcessInfo
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ProcessHandleInfo"/> class.
        /// </summary>
        /// <param name="processId">The process identifier.</param>
        /// <param name="getDescription">Whether to retrieve the description.</param>
        public ProcessHandleInfo(int processId, bool getDescription = false) : base(processId)
        {
            var info = ProcessInfo.GetProcessInfo(processId, getDescription);

            this.Id = info.Id;
            this.Name = info.Name;
            this.Description = info.Description;
            this.WindowTitle = info.WindowTitle;
            this.FullyQualifiedPath = info.FullyQualifiedPath;
            this.WorkingDirectory = info.WorkingDirectory;
            this.CommandLine = info.CommandLine;
            this.Owner = info.Owner;
            this.SessionId = info.SessionId;
            this.Desktop = info.Desktop;
            this.StartTimeUtc = info.StartTimeUtc;
            this.StartTimeLocal = info.StartTimeLocal;
        }

        /// <summary>
        /// The process identifier.
        /// </summary>
        new public int Id { get; }

        /// <summary>
        /// The name of the process.
        /// </summary>
        new public string? Name { get; set; }

        /// <summary>
        /// The friendly name of the process.
        /// </summary>
        new public string? Description { get; set; }

        /// <summary>
        /// The window title of the process.
        /// </summary>
        new public string WindowTitle { get; set; } = string.Empty;

        /// <summary>
        /// The full path to the process executable.
        /// </summary>
        new public string? FullyQualifiedPath { get; set; }

        /// <summary>
        /// The working directory of the process.
        /// </summary>
        new public string WorkingDirectory { get; set; } = string.Empty;

        /// <summary>
        /// The command line used to start the process.
        /// </summary>
        new public string CommandLine { get; set; } = string.Empty;

        /// <summary>
        /// The user name under which the process is running.
        /// </summary>
        new public string? Owner { get; set; }

        /// <summary>
        /// The session ID of the process.
        /// </summary>
        new public int? SessionId { get; set; }

        /// <summary>
        /// The desktop info of the process.
        /// </summary>
        new public string Desktop { get; set; } = string.Empty;

        /// <summary>
        /// The process start time in UTC.
        /// </summary>
        new public DateTime StartTimeUtc { get; set; }

        /// <summary>
        /// The process start time in local time.
        /// </summary>
        new public DateTime StartTimeLocal { get; set; }

        /// <summary>
        /// The path that this process has locked.
        /// </summary>
        public string HandlePath { get; set; } = string.Empty;

        /// <summary>
        /// The path that this process has locked.
        /// </summary>
        public bool? IsHandlePathDirectory { get; set; }

        /// <summary>
        /// The handle that this process has locked displayed as a hexadecimal string.
        /// </summary>
        public string? HandleDisplay { get; set; }

        /// <summary>
        /// The handle that this process has locked.
        /// </summary>
        public int? Handle { get; set; }

        /// <summary>
        /// The type of lock that this process has on the file or directory.
        /// </summary>
        public string? HandleType { get; set; }

        /// <summary>
        /// The flags of the handle that this process has on the file or directory.
        /// </summary>
        public string? HandleFlags { get; set; }

        /// <summary>
        /// The access mask of the handle that this process has on the file or directory.
        /// </summary>
        public string? HandleAccessMask { get; set; }

        /// <summary>
        /// Indicates whethere the the handle is a locking handle or not.
        /// </summary>
        public LockCheckResult GetPathLockStatus => CheckPathLockStatus(HandlePath, IsHandlePathDirectory);
    }
}
