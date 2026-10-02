using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using HKMP.Whitelist.Security;
using Modding;

namespace HKMP.Whitelist.UI
{
    internal static class ModScanner
    {
        private sealed class HashCacheEntry
        {
            public long Size;
            public DateTime LastWriteTimeUtc;
            public string Hash;
        }

        private static readonly object _gate =
            new object();

        private static List<ModEntry> _entries;

        private static readonly Dictionary<string, HashCacheEntry> _hashCache =
            new Dictionary<string, HashCacheEntry>(StringComparer.OrdinalIgnoreCase);

        public static List<ModEntry> GetMods()
        {
            lock (_gate)
            {
                if (_entries == null)
                {
                    _entries = ScanInstalledMods();
                }

                return Clone(_entries);
            }
        }

        public static List<ModEntry> Refresh()
        {
            lock (_gate)
            {
                _entries = ScanInstalledMods();
                _hashCache.Clear();
                return Clone(_entries);
            }
        }

        public static string GetHash(ModEntry entry)
        {
            if (entry == null || string.IsNullOrWhiteSpace(entry.FilePath))
            {
                return "";
            }

            string path;

            try
            {
                path = Path.GetFullPath(entry.FilePath);
            }
            catch
            {
                return "";
            }

            try
            {
                FileInfo info = new FileInfo(path);

                if (!info.Exists)
                {
                    return "";
                }

                lock (_gate)
                {
                    HashCacheEntry cached;

                    if (_hashCache.TryGetValue(path, out cached) &&
                        cached != null &&
                        cached.Size == info.Length &&
                        cached.LastWriteTimeUtc == info.LastWriteTimeUtc &&
                        !string.IsNullOrEmpty(cached.Hash))
                    {
                        entry.Hash = cached.Hash;
                        return cached.Hash;
                    }

                    string hash = ComputeSha256(path);

                    if (string.IsNullOrEmpty(hash) || !HashUtil.IsSha256(hash))
                    {
                        return "";
                    }

                    _hashCache[path] = new HashCacheEntry
                    {
                        Size = info.Length,
                        LastWriteTimeUtc = info.LastWriteTimeUtc,
                        Hash = hash
                    };

                    entry.Hash = hash;
                    return hash;
                }
            }
            catch
            {
                return "";
            }
        }

        public static string ComputeSha256(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "";
            }

            try
            {
                string hash = HashUtil.Sha256File(path);
                return string.IsNullOrEmpty(hash) ? "" : hash;
            }
            catch
            {
                return "";
            }
        }

        private static List<ModEntry> ScanInstalledMods()
        {
            List<ModEntry> result =
                new List<ModEntry>();

            string modsDirectory;

            try
            {
                modsDirectory =
                    Path.Combine(
                        UnityEngine.Application.dataPath,
                        "Managed",
                        "Mods");
            }
            catch
            {
                return result;
            }

            if (!Directory.Exists(modsDirectory))
            {
                return result;
            }

            ScanFolder(
                modsDirectory,
                false,
                result);

            string disabledDirectory;

            try
            {
                disabledDirectory =
                    Path.Combine(
                        modsDirectory,
                        "Disabled");
            }
            catch
            {
                disabledDirectory = null;
            }

            if (!string.IsNullOrWhiteSpace(disabledDirectory) &&
                Directory.Exists(disabledDirectory))
            {
                ScanFolder(
                    disabledDirectory,
                    true,
                    result);
            }

            return result
                .Where(x => x != null)
                .GroupBy(
                    x =>
                        NormalizePath(x.FilePath),
                    StringComparer.OrdinalIgnoreCase)
                .Select(x => x.First())
                .OrderBy(
                    x => x.Name ?? "",
                    StringComparer.OrdinalIgnoreCase)
                .ThenBy(
                    x => x.Version ?? "",
                    StringComparer.OrdinalIgnoreCase)
                .ThenBy(
                    x => x.FilePath ?? "",
                    StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static void ScanFolder(
            string folder,
            bool disabled,
            List<ModEntry> result)
        {
            if (string.IsNullOrWhiteSpace(folder) || result == null)
            {
                return;
            }

            string disabledRoot;

            try
            {
                disabledRoot =
                    Path.Combine(
                        folder,
                        "Disabled");
            }
            catch
            {
                disabledRoot = null;
            }

            string[] files;

            try
            {
                files =
                    Directory.GetFiles(
                        folder,
                        "*.dll",
                        SearchOption.AllDirectories);
            }
            catch
            {
                return;
            }

            foreach (string file in files)
            {
                if (string.IsNullOrWhiteSpace(file))
                {
                    continue;
                }

                if (!disabled &&
                    !string.IsNullOrWhiteSpace(disabledRoot) &&
                    IsInside(
                        file,
                        disabledRoot))
                {
                    continue;
                }

                ModEntry entry =
                    CreateEntry(
                        file,
                        disabled);

                if (entry != null)
                {
                    result.Add(entry);
                }
            }
        }

        private static ModEntry CreateEntry(
            string path,
            bool disabled)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            try
            {
                AssemblyName assembly =
                    AssemblyName.GetAssemblyName(path);

                string name =
                    assembly == null
                        ? null
                        : assembly.Name;

                if (string.IsNullOrWhiteSpace(name))
                {
                    name =
                        Path.GetFileNameWithoutExtension(path);
                }

                string modId =
                    ResolveModId(
                        assembly,
                        path);

                FileInfo info =
                    new FileInfo(path);

                Version version =
                    assembly == null
                        ? null
                        : assembly.Version;

                return
                    new ModEntry
                    {
                        Name =
                            string.IsNullOrWhiteSpace(name)
                                ? Path.GetFileNameWithoutExtension(path)
                                : name.Trim(),

                        ModId =
                            string.IsNullOrWhiteSpace(modId)
                                ? name
                                : modId.Trim(),

                        AssemblyFullName =
                            assembly == null
                                ? null
                                : assembly.FullName,

                        Version =
                            version == null
                                ? "?"
                                : version.ToString(),

                        FilePath =
                            path,

                        Hash =
                            null,

                        IsDisabled =
                            disabled,

                        Size =
                            info.Length,

                        LastWriteTimeUtc =
                            info.LastWriteTimeUtc
                    };
            }
            catch
            {
                try
                {
                    FileInfo info = new FileInfo(path);
                    string name = Path.GetFileNameWithoutExtension(path);

                    return
                        new ModEntry
                        {
                            Name = name,
                            ModId = ResolveModId(null, path),
                            AssemblyFullName = null,
                            Version = "?",
                            FilePath = path,
                            Hash = null,
                            IsDisabled = disabled,
                            Size = info.Exists ? info.Length : 0,
                            LastWriteTimeUtc = info.Exists
                                ? info.LastWriteTimeUtc
                                : default(DateTime)
                        };
                }
                catch
                {
                    return null;
                }
            }
        }

        private static string ResolveModId(
            AssemblyName assembly,
            string path)
        {
            string simpleName =
                assembly == null
                    ? null
                    : assembly.Name;

            string fullName =
                assembly == null
                    ? null
                    : assembly.FullName;

            try
            {
                Dictionary<string, string> loadedMods =
                    ModHooks.LoadedModsWithVersions;

                if (loadedMods != null &&
                    loadedMods.Count > 0)
                {
                    foreach (KeyValuePair<string, string> mod in loadedMods)
                    {
                        if (string.Equals(
                                mod.Key,
                                simpleName,
                                StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(
                                mod.Key,
                                fullName,
                                StringComparison.OrdinalIgnoreCase))
                        {
                            return mod.Key.Trim();
                        }
                    }
                }
            }
            catch
            {
            }

            if (!string.IsNullOrWhiteSpace(simpleName))
            {
                return simpleName.Trim();
            }

            try
            {
                string fileName =
                    Path.GetFileNameWithoutExtension(path);

                return string.IsNullOrWhiteSpace(fileName)
                    ? "UnknownMod"
                    : fileName.Trim();
            }
            catch
            {
                return "UnknownMod";
            }
        }

        private static bool IsInside(
            string file,
            string directory)
        {
            try
            {
                string normalizedDirectory =
                    Path.GetFullPath(directory)
                        .TrimEnd(
                            Path.DirectorySeparatorChar,
                            Path.AltDirectorySeparatorChar) +
                    Path.DirectorySeparatorChar;

                string normalizedFile =
                    Path.GetFullPath(file);

                return
                    normalizedFile.StartsWith(
                        normalizedDirectory,
                        StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private static string NormalizePath(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "";
            }

            try
            {
                return
                    Path.GetFullPath(path)
                        .TrimEnd(
                            Path.DirectorySeparatorChar,
                            Path.AltDirectorySeparatorChar);
            }
            catch
            {
                return path.Trim();
            }
        }

        private static List<ModEntry> Clone(
            List<ModEntry> source)
        {
            if (source == null)
            {
                return new List<ModEntry>();
            }

            return
                source
                    .Where(x => x != null)
                    .Select(
                        x =>
                            new ModEntry
                            {
                                Name = x.Name,
                                ModId = x.ModId,
                                AssemblyFullName = x.AssemblyFullName,
                                Version = x.Version,
                                FilePath = x.FilePath,
                                Hash = x.Hash,
                                IsDisabled = x.IsDisabled,
                                Size = x.Size,
                                LastWriteTimeUtc = x.LastWriteTimeUtc
                            })
                    .ToList();
        }
    }
}
