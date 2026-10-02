using HKMP.Whitelist.Core;
using HKMP.Whitelist.Security;
using HKMP.Whitelist.Shared;
using Modding;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace HKMP.Whitelist.Client
{
    internal sealed class AssemblyScannerResult
    {
        public bool Complete { get; set; }

        public List<AssemblyScanEntry> UnknownAssemblies { get; } =
            new List<AssemblyScanEntry>();

        public List<string> IntegrityFailures { get; } =
            new List<string>();

        public List<string> TrustedModIds { get; } =
            new List<string>();

        public List<AssemblyScanEntry> TrustedAssemblies { get; } =
            new List<AssemblyScanEntry>();

        public List<AssemblyEvidence> Assemblies { get; } =
            new List<AssemblyEvidence>();
    }

    internal static class AssemblyScanner
    {
        public static AssemblyScannerResult Scan(
            HostBaseline baseline)
        {
            AssemblyScannerResult result =
                new AssemblyScannerResult
                {
                    Complete = true
                };

            if (baseline == null)
            {
                return Fail(
                    result,
                    "Host baseline is null.");
            }

            if (baseline.Artifacts == null)
            {
                return Fail(
                    result,
                    "Host baseline artifacts are missing.");
            }

            Assembly[] assemblies;

            try
            {
                assemblies =
                    AppDomain.CurrentDomain.GetAssemblies();
            }
            catch (Exception ex)
            {
                return Fail(
                    result,
                    "Assembly enumeration failed: " +
                    ex.GetType().Name);
            }

            if (assemblies == null)
            {
                return Fail(
                    result,
                    "Assembly enumeration returned null.");
            }

            List<string> discoveryFailures;
            IReadOnlyList<LoadedModInfo> loadedMods =
                LoadedModDiscovery.GetLoadedMods(
                    out discoveryFailures);

            foreach (string failure in discoveryFailures)
            {
                result.IntegrityFailures.Add(failure);
            }

            string gameRoot =
                GetGameRoot();

            foreach (Assembly assembly in assemblies
                .Where(x => x != null)
                .OrderBy(
                    x => SafeFullName(x) ?? "",
                    StringComparer.Ordinal))
            {
                try
                {
                    LoadedModInfo loadedMod =
                        LoadedModDiscovery.FindByAssembly(
                            loadedMods,
                            assembly);

                    AssemblyScanEntry entry =
                        ClassifySingle(
                            baseline,
                            assembly);

                    if (entry == null)
                    {
                        result.Complete = false;
                        result.IntegrityFailures.Add(
                            "Assembly classifier returned null.");
                        continue;
                    }

                    entry.ModId =
                        loadedMod == null
                            ? entry.ModId
                            : loadedMod.ModId;

                    result.Assemblies.Add(
                        ToEvidence(
                            entry));

                    if (entry.Status == FileTrustStatus.Trusted)
                    {
                        result.TrustedAssemblies.Add(entry);

                        AddTrustedModId(
                            result,
                            entry.ModId);

                        continue;
                    }

                    if (entry.Status == FileTrustStatus.KnownGood)
                    {
                        result.TrustedAssemblies.Add(entry);

                        AddTrustedModId(
                            result,
                            entry.ModId);

                        continue;
                    }

                    result.UnknownAssemblies.Add(entry);
                }
                catch (Exception ex)
                {
                    result.Complete = false;

                    AssemblyScanEntry unknown =
                        CreateUnknownEntry(
                            assembly,
                            "scan-error:" +
                            ex.GetType().Name);

                    result.UnknownAssemblies.Add(
                        unknown);

                    result.Assemblies.Add(
                        ToEvidence(unknown));

                    result.IntegrityFailures.Add(
                        "Assembly scan failed: " +
                        SafeFullName(assembly) +
                        " [" +
                        ex.GetType().Name +
                        "].");
                }
            }

            return result;
        }

        public static AssemblyScanEntry ClassifySingle(
            HostBaseline baseline,
            Assembly assembly)
        {
            if (assembly == null)
            {
                return null;
            }

            string fullName =
                SafeFullName(assembly);

            string location =
                NormalizeFullPath(
                    SafeLocation(assembly));

            AssemblyName assemblyName =
                SafeAssemblyName(assembly);

            string simpleName =
                assemblyName == null
                    ? null
                    : assemblyName.Name;

            string version =
                assemblyName == null ||
                assemblyName.Version == null
                    ? null
                    : assemblyName.Version.ToString();

            string gameRoot =
                GetGameRoot();

            string relativePath =
                GetNormalizedRelativePath(
                    gameRoot,
                    location);

            LoadedModInfo loadedMod =
                ResolveLoadedMod(assembly);

            bool isModAssembly =
                loadedMod != null;

            string modId =
                loadedMod == null
                    ? null
                    : loadedMod.ModId;

            BaselineArtifact expected =
                FindExpectedArtifact(
                    baseline,
                    fullName,
                    relativePath,
                    modId);

            BaselineAssembly expectedAssembly =
                FindExpectedAssembly(
                    baseline,
                    fullName,
                    location);

            bool isSecurityRelevant =
                isModAssembly ||
                expected != null &&
                !IsOrdinaryGameAssembly(
                    expected);

            long fileSize =
                isSecurityRelevant
                    ? GetFileSizeSafe(location)
                    : 0;

            string sha256 =
                null;

            if (isSecurityRelevant &&
                !string.IsNullOrWhiteSpace(location) &&
                File.Exists(location))
            {
                try
                {
                    sha256 =
                        ComputeStableSha256(
                            location);
                }
                catch
                {
                    sha256 = null;
                }
            }

            AssemblyScanEntry entry =
                new AssemblyScanEntry
                {
                    FullName = fullName,
                    Location = location,
                    ModId =
                        loadedMod != null
                            ? loadedMod.ModId
                            : expected != null
                                ? expected.ModId
                                : expectedAssembly != null
                                    ? expectedAssembly.ModId
                                    : null,
                    ArtifactId =
                        expected == null
                            ? expectedAssembly == null
                                ? null
                                : expectedAssembly.ArtifactId
                            : expected.ArtifactId,
                    ManifestVersion = null,
                    AssemblyVersion = version,
                    Sha256 = sha256,
                    ExpectedSha256 =
                        expected == null
                            ? null
                            : expected.Sha256,
                    Status = FileTrustStatus.Unknown
                };

            if (!isModAssembly &&
                expected == null &&
                expectedAssembly != null &&
                !expectedAssembly.IsModAssembly)
            {
                entry.Status =
                    FileTrustStatus.KnownGood;

                return entry;
            }

            if (!isModAssembly &&
                IsFrameworkAssembly(assembly))
            {
                entry.Status =
                    FileTrustStatus.KnownGood;

                return entry;
            }

            if (loadedMod != null &&
                expected == null)
            {
                entry.Status =
                    FileTrustStatus.Unknown;

                return entry;
            }

            if (expected == null)
            {
                entry.Status =
                    FileTrustStatus.Unknown;

                return entry;
            }

            if (string.IsNullOrWhiteSpace(location))
            {
                entry.Status =
                    FileTrustStatus.Unknown;

                return entry;
            }

            if (!File.Exists(location))
            {
                entry.Status =
                    FileTrustStatus.Unknown;

                return entry;
            }

            if (HasReparsePoint(location))
            {
                entry.Status =
                    FileTrustStatus.PathMismatch;

                return entry;
            }

            bool exact =
                string.Equals(
                    expected.FileName,
                    Path.GetFileName(location),
                    StringComparison.OrdinalIgnoreCase) &&
                PathsEqual(
                    expected.RelativePath,
                    relativePath) &&
                expected.FileSize == fileSize &&
                string.Equals(
                    expected.Sha256,
                    sha256,
                    StringComparison.OrdinalIgnoreCase) &&
                StringEqualsExact(
                    expected.AssemblyFullName,
                    fullName) &&
                StringEqualsExact(
                    expected.AssemblyName,
                    simpleName) &&
                StringEqualsExact(
                    expected.AssemblyVersion,
                    version) &&
                string.Equals(
                    NormalizeFullPath(expected.AssemblyLocation),
                    NormalizeFullPath(location),
                    StringComparison.OrdinalIgnoreCase) &&
                expected.IsLoaded;

            entry.Status =
                exact
                    ? FileTrustStatus.Trusted
                    : DetermineMismatchStatus(
                        expected,
                        location,
                        relativePath,
                        sha256,
                        fullName,
                        version);

            return entry;
        }

        private static bool IsOrdinaryGameAssembly(
            BaselineArtifact artifact)
        {
            if (artifact == null)
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(artifact.ModId))
            {
                return
                    string.Equals(
                        artifact.AssemblyName,
                        "Assembly-CSharp",
                        StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        private static BaselineAssembly FindExpectedAssembly(
            HostBaseline baseline,
            string fullName,
            string location)
        {
            if (baseline == null ||
                baseline.Assemblies == null)
            {
                return null;
            }

            foreach (BaselineAssembly assembly in
                     baseline.Assemblies)
            {
                if (assembly == null)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(location) &&
                    string.Equals(
                        NormalizeFullPath(assembly.Location),
                        NormalizeFullPath(location),
                        StringComparison.OrdinalIgnoreCase))
                {
                    return assembly;
                }
            }

            if (!string.IsNullOrWhiteSpace(fullName))
            {
                foreach (BaselineAssembly assembly in
                         baseline.Assemblies)
                {
                    if (assembly == null)
                    {
                        continue;
                    }

                    if (string.Equals(
                            assembly.FullName,
                            fullName,
                            StringComparison.Ordinal))
                    {
                        return assembly;
                    }
                }
            }

            return null;
        }

        private static LoadedModInfo ResolveLoadedMod(
            Assembly assembly)
        {
            try
            {
                List<string> failures;

                IReadOnlyList<LoadedModInfo> mods =
                    LoadedModDiscovery.GetLoadedMods(
                        out failures);

                return LoadedModDiscovery.FindByAssembly(
                    mods,
                    assembly);
            }
            catch
            {
                return null;
            }
        }

        private static FileTrustStatus DetermineMismatchStatus(
            BaselineArtifact expected,
            string location,
            string relativePath,
            string sha256,
            string fullName,
            string version)
        {
            if (!PathsEqual(
                    expected.RelativePath,
                    relativePath) ||
                !string.Equals(
                    expected.FileName,
                    Path.GetFileName(location),
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(
                    NormalizeFullPath(expected.AssemblyLocation),
                    NormalizeFullPath(location),
                    StringComparison.OrdinalIgnoreCase))
            {
                return FileTrustStatus.PathMismatch;
            }

            if (!string.Equals(
                    expected.Sha256,
                    sha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                return FileTrustStatus.Unknown;
            }

            if (!StringEqualsExact(
                    expected.AssemblyFullName,
                    fullName) ||
                !StringEqualsExact(
                    expected.AssemblyVersion,
                    version))
            {
                return FileTrustStatus.Unknown;
            }

            return FileTrustStatus.Unknown;
        }

        private static BaselineArtifact FindExpectedArtifact(
            HostBaseline baseline,
            string fullName,
            string relativePath,
            string modId)
        {
            if (baseline == null ||
                baseline.Artifacts == null)
            {
                return null;
            }

            foreach (BaselineArtifact artifact in baseline.Artifacts)
            {
                if (artifact == null)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(relativePath) &&
                    PathsEqual(
                        artifact.RelativePath,
                        relativePath))
                {
                    return artifact;
                }
            }

            foreach (BaselineArtifact artifact in baseline.Artifacts)
            {
                if (artifact == null)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(fullName) &&
                    StringEqualsExact(
                        artifact.AssemblyFullName,
                        fullName))
                {
                    return artifact;
                }
            }

            foreach (BaselineArtifact artifact in baseline.Artifacts)
            {
                if (artifact == null)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(modId) &&
                    string.Equals(
                        artifact.ModId,
                        modId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return artifact;
                }
            }

            return null;
        }

        private static void AddTrustedModId(
            AssemblyScannerResult result,
            string modId)
        {
            if (result == null ||
                string.IsNullOrWhiteSpace(modId))
            {
                return;
            }

            if (!result.TrustedModIds.Any(
                x => string.Equals(
                    x,
                    modId,
                    StringComparison.OrdinalIgnoreCase)))
            {
                result.TrustedModIds.Add(modId.Trim());
            }
        }

        private static AssemblyEvidence ToEvidence(
            AssemblyScanEntry entry)
        {
            return new AssemblyEvidence
            {
                Source = EvidenceSource.LoadedAssembly,
                FullName = entry == null ? null : entry.FullName,
                Name = entry == null
                    ? null
                    : GetAssemblyNameFromFullName(entry.FullName),
                AssemblyVersion = entry == null ? null : entry.AssemblyVersion,
                Location = entry == null ? null : entry.Location,
                RelativePath = entry == null
                    ? null
                    : GetNormalizedRelativePath(
                        GetGameRoot(),
                        entry.Location),
                ModId = entry == null ? null : entry.ModId,
                ArtifactId = entry == null ? null : entry.ArtifactId,
                Sha256 = entry == null ? null : entry.Sha256,
                ExpectedSha256 = entry == null ? null : entry.ExpectedSha256,
                HasPhysicalLocation =
                    entry != null &&
                    !string.IsNullOrWhiteSpace(entry.Location),
                IsLoaded = true,
                IsModAssembly =
                    entry != null &&
                    !string.IsNullOrWhiteSpace(entry.ModId),
                IsUnknown =
                    entry == null ||
                    (entry.Status != FileTrustStatus.Trusted &&
                     entry.Status != FileTrustStatus.KnownGood),
                ObservedAtUtc = DateTime.UtcNow,
                Details =
                    entry == null
                        ? "null-entry"
                        : entry.Status.ToString()
            };
        }

        private static bool IsFrameworkAssembly(
            Assembly assembly)
        {
            string name =
                SafeAssemblyName(assembly)?.Name;

            if (string.IsNullOrWhiteSpace(name))
            {
                return false;
            }

            return
                string.Equals(name, "mscorlib", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("System", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("Mono", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("UnityEngine", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("Unity", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "netstandard", StringComparison.OrdinalIgnoreCase);
        }

        private static AssemblyScanEntry CreateUnknownEntry(
            Assembly assembly,
            string details)
        {
            string location =
                NormalizeFullPath(
                    SafeLocation(assembly));

            return new AssemblyScanEntry
            {
                FullName = SafeFullName(assembly),
                Location = location,
                ModId = null,
                ArtifactId = null,
                AssemblyVersion = SafeAssemblyVersion(assembly),
                Sha256 =
                    string.IsNullOrWhiteSpace(location)
                        ? null
                        : ComputeStableSha256Safe(location),
                ExpectedSha256 = null,
                Status = FileTrustStatus.Unknown,
                ManifestVersion = details
            };
        }

        private static string GetAssemblyNameFromFullName(
            string fullName)
        {
            if (string.IsNullOrWhiteSpace(fullName))
            {
                return null;
            }

            int separator =
                fullName.IndexOf(',');

            return separator < 0
                ? fullName.Trim()
                : fullName.Substring(0, separator).Trim();
        }

        private static string ComputeStableSha256(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path) ||
                !File.Exists(path))
            {
                return null;
            }

            FileInfo before =
                new FileInfo(path);

            string hash =
                HashUtil.Sha256File(path);

            FileInfo after =
                new FileInfo(path);

            if (!after.Exists ||
                before.Length != after.Length ||
                before.LastWriteTimeUtc != after.LastWriteTimeUtc)
            {
                throw new IOException(
                    "Assembly changed during hash.");
            }

            return hash;
        }

        private static string ComputeStableSha256Safe(
            string path)
        {
            try { return ComputeStableSha256(path); }
            catch { return null; }
        }

        private static bool HasReparsePoint(
            string path)
        {
            try
            {
                string current =
                    NormalizeFullPath(path);

                while (!string.IsNullOrWhiteSpace(current))
                {
                    if (File.Exists(current) || Directory.Exists(current))
                    {
                        if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                        {
                            return true;
                        }
                    }

                    DirectoryInfo parent =
                        Directory.GetParent(current);

                    if (parent == null)
                    {
                        break;
                    }

                    string next =
                        NormalizeFullPath(parent.FullName);

                    if (string.Equals(
                        next,
                        current,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }

                    current = next;
                }
            }
            catch
            {
                return true;
            }

            return false;
        }

        private static long GetFileSizeSafe(
            string path)
        {
            try
            {
                return string.IsNullOrWhiteSpace(path) ||
                       !File.Exists(path)
                    ? 0
                    : new FileInfo(path).Length;
            }
            catch
            {
                return 0;
            }
        }

        private static string GetGameRoot()
        {
            try
            {
                DirectoryInfo data =
                    new DirectoryInfo(
                        UnityEngine.Application.dataPath);

                return data.Parent == null
                    ? null
                    : NormalizeFullPath(
                        data.Parent.FullName);
            }
            catch
            {
                return null;
            }
        }

        private static string GetNormalizedRelativePath(
            string gameRoot,
            string location)
        {
            if (string.IsNullOrWhiteSpace(gameRoot) ||
                string.IsNullOrWhiteSpace(location))
            {
                return null;
            }

            string root =
                NormalizeDirectoryPath(gameRoot);

            string full =
                NormalizeFullPath(location);

            if (!PathsWithin(root, full))
            {
                return null;
            }

            return full.Substring(root.Length)
                .TrimStart(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar)
                .Replace('\\', '/');
        }

        private static bool PathsEqual(
            string first,
            string second)
        {
            return string.Equals(
                NormalizePath(first),
                NormalizePath(second),
                StringComparison.OrdinalIgnoreCase);
        }

        private static bool PathsWithin(
            string root,
            string path)
        {
            if (string.IsNullOrWhiteSpace(root) ||
                string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string normalizedRoot =
                NormalizeDirectoryPath(root);

            string normalizedPath =
                NormalizeFullPath(path);

            if (string.IsNullOrWhiteSpace(normalizedRoot) ||
                string.IsNullOrWhiteSpace(normalizedPath))
            {
                return false;
            }

            return
                string.Equals(
                    normalizedRoot,
                    normalizedPath,
                    StringComparison.OrdinalIgnoreCase) ||
                normalizedPath.StartsWith(
                    normalizedRoot + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase) ||
                normalizedPath.StartsWith(
                    normalizedRoot + Path.AltDirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeFullPath(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            try
            {
                return Path.GetFullPath(path)
                    .TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar);
            }
            catch
            {
                return null;
            }
        }

        private static string NormalizeDirectoryPath(
            string path)
        {
            return NormalizeFullPath(path);
        }

        private static string NormalizePath(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            string value =
                path.Trim()
                    .Replace('\\', '/');

            while (value.Contains("//"))
            {
                value = value.Replace("//", "/");
            }

            while (value.StartsWith("./", StringComparison.Ordinal))
            {
                value = value.Substring(2);
            }

            return value.TrimStart('/');
        }

        private static string SafeFullName(
            Assembly assembly)
        {
            try { return assembly == null ? null : assembly.FullName; }
            catch { return null; }
        }

        private static string SafeLocation(
            Assembly assembly)
        {
            try { return assembly == null ? null : assembly.Location; }
            catch { return null; }
        }

        private static AssemblyName SafeAssemblyName(
            Assembly assembly)
        {
            try { return assembly == null ? null : assembly.GetName(); }
            catch { return null; }
        }

        private static string SafeAssemblyVersion(
            Assembly assembly)
        {
            try
            {
                Version version =
                    assembly == null
                        ? null
                        : assembly.GetName().Version;

                return version == null
                    ? null
                    : version.ToString();
            }
            catch
            {
                return null;
            }
        }

        private static AssemblyScannerResult Fail(
            AssemblyScannerResult result,
            string reason)
        {
            result.Complete = false;
            result.IntegrityFailures.Add(reason);
            return result;
        }

        private static bool StringEqualsExact(
            string first,
            string second)
        {
            return string.Equals(
                first ?? "",
                second ?? "",
                StringComparison.Ordinal);
        }
    }
}
