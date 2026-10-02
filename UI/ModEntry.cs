using System;

namespace HKMP.Whitelist.UI
{
    public sealed class ModEntry
    {
        public string Name { get; set; }

        public string AssemblyFullName { get; set; }

        public string ModId { get; set; }

        public string Version { get; set; }

        public string FilePath { get; set; }

        public string Hash { get; set; }

        public bool IsDisabled { get; set; }

        public long Size { get; set; }

        public DateTime LastWriteTimeUtc { get; set; }
    }
}