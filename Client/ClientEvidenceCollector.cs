using HKMP.Whitelist.Security;
using HKMP.Whitelist.Core;
using HKMP.Whitelist.Shared;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;

namespace HKMP.Whitelist.Client
{
    internal static class ClientEvidenceCollector
    {
        public static SecurityEvidence Collect(
            HostBaseline baseline,
            string gameRoot)
        {
            SecurityEvidence evidence =
                new SecurityEvidence
                {
                    SessionId =
                        baseline == null
                            ? null
                            : baseline.SessionId,

                    BaselineId =
                        baseline == null
                            ? null
                            : baseline.BaselineId,

                    WhitelistVersion =
                        baseline == null
                            ? null
                            : baseline.WhitelistVersion,

                    ScanStatus =
                        "Incomplete",

                    ScanTimestampUtc =
                        DateTime.UtcNow
                };

            if (baseline == null)
            {
                evidence.AddIntegrityFailure(
                    "Host baseline is null.");

                return evidence;
            }

            Dictionary<string, Assembly> loadedByPath =
                BuildLoadedAssemblyMap(
                    evidence);

            List<string> discoveryFailures;
            IReadOnlyList<LoadedModInfo> loadedMods =
                LoadedModDiscovery.GetLoadedMods(
                    out discoveryFailures);

            if (discoveryFailures != null)
            {
                foreach (string failure in discoveryFailures)
                {
                    evidence.AddIntegrityFailure(failure);
                }
            }

            if (baseline.Artifacts == null)
            {
                evidence.AddIntegrityFailure(
                    "Host baseline artifacts are missing.");
            }
            else
            {
                foreach (BaselineArtifact artifact
                         in baseline.Artifacts)
                {
                    if (artifact == null)
                    {
                        evidence.AddIntegrityFailure(
                            "Host baseline contains a null artifact.");

                        continue;
                    }

                    evidence.AddArtifact(
                        CaptureArtifact(
                            baseline,
                            artifact,
                            gameRoot,
                            loadedByPath));
                }
            }

            CaptureLoadedAssemblies(
                baseline,
                evidence,
                loadedByPath,
                loadedMods);

            CaptureNativeModules(
                baseline,
                evidence);

            evidence.DebuggerDetected =
                AntiTamperGuard.IsDebuggerDetected();

            evidence.ScanStatus =
                evidence.IntegrityFailures.Count == 0
                    ? "Complete"
                    : "Incomplete";

            return evidence;
        }

        private static ArtifactEvidence CaptureArtifact(
            HostBaseline baseline,
            BaselineArtifact artifact,
            string gameRoot,
            Dictionary<string, Assembly> loadedByPath)
        {
            ArtifactEvidence evidence =
                new ArtifactEvidence
                {
                    Source =
                        EvidenceSource.FileSystem,

                    ModId =
                        artifact.ModId,

                    ArtifactId =
                        artifact.ArtifactId,

                    FileName =
                        artifact.FileName,

                    RelativePath =
                        NormalizePath(
                            artifact.RelativePath),

                    FileSize =
                        0,

                    Sha256 =
                        null,

                    AssemblyName =
                        null,

                    AssemblyFullName =
                        null,

                    AssemblyVersion =
                        null,

                    AssemblyLocation =
                        null,

                    IsLoaded =
                        false,

                    Exists =
                        false,

                    IsReadable =
                        false,

                    ObservedAtUtc =
                        DateTime.UtcNow
                };

            string effectiveGameRoot =
                string.IsNullOrWhiteSpace(gameRoot)
                    ? ResolveGameRoot()
                    : gameRoot;

            string fullPath =
                ResolveGameRelativePath(
                    effectiveGameRoot,
                    artifact.RelativePath);

            if (string.IsNullOrWhiteSpace(fullPath))
            {
                evidence.Details =
                    "Unable to resolve artifact path.";

                return evidence;
            }

            evidence.FileName =
                Path.GetFileName(
                    fullPath);

            evidence.RelativePath =
                MakeRelativeGamePath(
                    effectiveGameRoot,
                    fullPath);

            try
            {
                FileInfo before =
                    new FileInfo(fullPath);

                if (!before.Exists)
                {
                    evidence.Details =
                        "Artifact file is missing.";

                    return evidence;
                }

                evidence.Exists =
                    true;

                evidence.FileSize =
                    before.Length;

                string hash =
                    ComputeStableHash(
                        fullPath,
                        before,
                        out FileInfo after);

                if (hash == null)
                {
                    evidence.Details =
                        "Artifact changed or could not be hashed.";

                    return evidence;
                }

                evidence.Sha256 =
                    hash;

                evidence.FileSize =
                    after.Length;

                evidence.IsReadable =
                    true;

                AssemblyName assemblyName =
                    TryGetAssemblyName(
                        fullPath);

                if (assemblyName != null)
                {
                    evidence.AssemblyName =
                        assemblyName.Name;

                    evidence.AssemblyFullName =
                        assemblyName.FullName;

                    evidence.AssemblyVersion =
                        assemblyName.Version == null
                            ? null
                            : assemblyName.Version.ToString();
                }

                string normalizedFullPath =
                    NormalizeFullPath(
                        fullPath);

                Assembly loadedAssembly =
                    null;

                if (!string.IsNullOrWhiteSpace(
                        normalizedFullPath))
                {
                    loadedByPath.TryGetValue(
                        normalizedFullPath,
                        out loadedAssembly);
                }

                if (loadedAssembly != null)
                {
                    evidence.IsLoaded =
                        true;

                    evidence.AssemblyLocation =
                        SafeAssemblyLocation(
                            loadedAssembly);

                    if (string.IsNullOrWhiteSpace(
                            evidence.AssemblyFullName))
                    {
                        evidence.AssemblyFullName =
                            SafeAssemblyFullName(
                                loadedAssembly);
                    }

                    if (string.IsNullOrWhiteSpace(
                            evidence.AssemblyName))
                    {
                        AssemblyName loadedName =
                            SafeAssemblyName(
                                loadedAssembly);

                        evidence.AssemblyName =
                            loadedName == null
                                ? null
                                : loadedName.Name;
                    }

                    if (string.IsNullOrWhiteSpace(
                            evidence.AssemblyVersion))
                    {
                        AssemblyName loadedName =
                            SafeAssemblyName(
                                loadedAssembly);

                        evidence.AssemblyVersion =
                            loadedName == null ||
                            loadedName.Version == null
                                ? null
                                : loadedName.Version.ToString();
                    }
                }

                if (!evidence.IsLoaded)
                {
                    evidence.AssemblyLocation =
                        null;
                }

                evidence.Details =
                    "Observed successfully.";
            }
            catch (Exception ex)
            {
                evidence.Details =
                    "Artifact inspection failed: " +
                    ex.GetType().Name;
            }

            return evidence;
        }

        private static void CaptureLoadedAssemblies(
            HostBaseline baseline,
            SecurityEvidence evidence,
            Dictionary<string, Assembly> loadedByPath,
            IReadOnlyList<LoadedModInfo> loadedMods)
        {
            Assembly[] assemblies;

            try
            {
                assemblies =
                    AppDomain.CurrentDomain.GetAssemblies();
            }
            catch (Exception ex)
            {
                evidence.AddIntegrityFailure(
                    "Loaded assembly enumeration failed: " +
                    ex.GetType().Name);

                return;
            }

            if (assemblies == null)
            {
                evidence.AddIntegrityFailure(
                    "Loaded assembly enumeration returned null.");

                return;
            }

            foreach (Assembly assembly in
                     assemblies
                         .Where(x => x != null)
                         .OrderBy(
                             SafeAssemblyFullName,
                             StringComparer.Ordinal))
            {
                try
                {
                    AssemblyName name =
                        SafeAssemblyName(
                            assembly);

                    string location =
                        SafeAssemblyLocation(
                            assembly);

                    bool hasPhysicalLocation =
                        !string.IsNullOrWhiteSpace(
                            location);

                    string normalizedLocation =
                        hasPhysicalLocation
                            ? NormalizeFullPath(
                                location)
                            : null;

                    LoadedModInfo loadedMod =
                        LoadedModDiscovery.FindByAssembly(
                            loadedMods,
                            assembly);

                    bool isModAssembly =
                        loadedMod != null;

                    BaselineAssembly baselineAssembly =
                        FindBaselineAssembly(
                            baseline,
                            assembly,
                            normalizedLocation,
                            name);

                    BaselineArtifact baselineArtifact =
                        FindBaselineArtifact(
                            baseline,
                            loadedMod,
                            name,
                            normalizedLocation);

                    bool securityRelevant =
                        isModAssembly ||
                        IsSecurityRelevantAssembly(
                            name,
                            baselineArtifact);

                    AssemblyEvidence item =
                        new AssemblyEvidence
                        {
                            Source =
                                EvidenceSource.LoadedAssembly,

                            FullName =
                                SafeAssemblyFullName(
                                    assembly),

                            Name =
                                name == null
                                    ? null
                                    : name.Name,

                            AssemblyVersion =
                                name == null ||
                                name.Version == null
                                    ? null
                                    : name.Version.ToString(),

                            Location =
                                normalizedLocation,

                            RelativePath =
                                hasPhysicalLocation
                                    ? MakeRelativeGamePath(
                                        ResolveGameRoot(),
                                        normalizedLocation)
                                    : null,

                            ModId =
                                loadedMod != null &&
                                !string.IsNullOrWhiteSpace(
                                    loadedMod.ModId)
                                    ? loadedMod.ModId
                                    : baselineAssembly == null
                                        ? null
                                        : baselineAssembly.ModId,

                            ArtifactId =
                                baselineAssembly == null
                                    ? baselineArtifact == null
                                        ? null
                                        : baselineArtifact.ArtifactId
                                    : baselineAssembly.ArtifactId,

                            Sha256 =
                                securityRelevant &&
                                hasPhysicalLocation
                                    ? TryHashFile(
                                        normalizedLocation)
                                    : null,

                            ExpectedSha256 =
                                securityRelevant
                                    ? baselineArtifact == null
                                        ? baselineAssembly == null
                                            ? null
                                            : baselineAssembly.Sha256
                                        : baselineArtifact.Sha256
                                    : null,

                            HasPhysicalLocation =
                                hasPhysicalLocation,

                            IsLoaded =
                                true,

                            IsModAssembly =
                                isModAssembly,

                            IsUnknown =
                                baselineAssembly == null &&
                                !IsFrameworkAssembly(name),

                            ObservedAtUtc =
                                DateTime.UtcNow
                        };

                    if (baselineArtifact != null &&
                        securityRelevant &&
                        !string.IsNullOrWhiteSpace(
                            baselineArtifact.Sha256) &&
                        !string.IsNullOrWhiteSpace(
                            item.Sha256) &&
                        !string.Equals(
                            baselineArtifact.Sha256,
                            item.Sha256,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        item.Details =
                            "Security-relevant assembly hash differs from host baseline.";
                    }
                    else if (baselineAssembly != null &&
                             !isModAssembly)
                    {
                        item.Details =
                            "Ordinary host game/runtime assembly observed without integrity hashing.";
                    }
                    else
                    {
                        item.Details =
                            "Loaded assembly observed.";
                    }

                    bool shouldReport =
                        securityRelevant ||
                        baselineAssembly == null &&
                        !IsFrameworkAssembly(
                            name);

                    if (shouldReport)
                    {
                        evidence.AddAssembly(
                            item);
                    }
                }
                catch (Exception ex)
                {
                    evidence.AddIntegrityFailure(
                        "Loaded assembly evidence failed: " +
                        ex.GetType().Name);
                }
            }
        }

        private static void CaptureNativeModules(
            HostBaseline baseline,
            SecurityEvidence evidence)
        {
            ProcessModuleCollection modules;

            try
            {
                modules =
                    Process.GetCurrentProcess().Modules;
            }
            catch (Exception ex)
            {
                evidence.AddIntegrityFailure(
                    "Native module enumeration failed: " +
                    ex.GetType().Name);

                return;
            }

            if (modules == null)
            {
                evidence.AddIntegrityFailure(
                    "Native module enumeration returned null.");

                return;
            }

            foreach (ProcessModule module in modules)
            {
                if (module == null)
                {
                    continue;
                }

                try
                {
                    string name =
                        SafeModuleName(
                            module);

                    string rawPath =
                        SafeModulePath(
                            module);

                    if (IsPseudoNativeModule(
                            name,
                            rawPath))
                    {
                        continue;
                    }

                    string path =
                        NormalizeFullPath(
                            rawPath);

                    string relativePath =
                        MakeRelativeGamePath(
                            ResolveGameRoot(),
                            path);

                    bool securityRelevant =
                        !IsSystemNativePath(
                            path);

                    BaselineNativeModule baselineModule =
                        FindBaselineNativeModule(
                            baseline,
                            name,
                            path);

                    string hash =
                        securityRelevant
                            ? TryHashFile(path)
                            : null;

                    long size =
                        GetFileSizeSafe(
                            path);

                    evidence.AddNativeModule(
                        new NativeModuleEvidence
                        {
                            Source =
                                EvidenceSource.NativeModule,

                            Name =
                                name,

                            Path =
                                path,

                            RelativePath =
                                relativePath,

                            FileSize =
                                size,

                            Sha256 =
                                hash,

                            ExpectedSha256 =
                                baselineModule == null
                                    ? null
                                    : baselineModule.Sha256,

                            Classification =
                                baselineModule == null
                                    ? (securityRelevant
                                        ? "Unknown"
                                        : "System")
                                    : baselineModule.Classification,

                            IsSecurityRelevant =
                                securityRelevant,

                            IsUnknown =
                                baselineModule == null &&
                                securityRelevant,

                            IsReadable =
                                !securityRelevant ||
                                !string.IsNullOrWhiteSpace(hash),

                            ObservedAtUtc =
                                DateTime.UtcNow,

                            Details =
                                baselineModule == null
                                    ? "Native module is not present in host baseline."
                                    : "Native module observed."
                        });
                }
                catch (Exception ex)
                {
                    evidence.AddIntegrityFailure(
                        "Native module evidence failed: " +
                        ex.GetType().Name);
                }
            }
        }

        private static Dictionary<string, Assembly> BuildLoadedAssemblyMap(
            SecurityEvidence evidence)
        {
            Dictionary<string, Assembly> result =
                new Dictionary<string, Assembly>(
                    StringComparer.OrdinalIgnoreCase);

            try
            {
                Assembly[] assemblies =
                    AppDomain.CurrentDomain.GetAssemblies();

                if (assemblies == null)
                {
                    return result;
                }

                foreach (Assembly assembly in assemblies)
                {
                    if (assembly == null)
                    {
                        continue;
                    }

                    string location =
                        SafeAssemblyLocation(
                            assembly);

                    string normalized =
                        NormalizeFullPath(
                            location);

                    if (!string.IsNullOrWhiteSpace(normalized))
                    {
                        result[normalized] =
                            assembly;
                    }
                }
            }
            catch (Exception ex)
            {
                evidence.AddIntegrityFailure(
                    "Loaded assembly map failed: " +
                    ex.GetType().Name);
            }

            return result;
        }

        private static BaselineArtifact FindBaselineArtifact(
            HostBaseline baseline,
            LoadedModInfo loadedMod,
            AssemblyName name,
            string normalizedLocation)
        {
            if (baseline == null ||
                baseline.Artifacts == null)
            {
                return null;
            }

            string relativePath =
                MakeRelativeGamePath(
                    ResolveGameRoot(),
                    normalizedLocation);

            foreach (BaselineArtifact artifact in
                     baseline.Artifacts)
            {
                if (artifact == null)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(relativePath) &&
                    string.Equals(
                        NormalizePath(artifact.RelativePath),
                        NormalizePath(relativePath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    return artifact;
                }
            }

            if (loadedMod != null &&
                !string.IsNullOrWhiteSpace(
                    loadedMod.ModId))
            {
                foreach (BaselineArtifact artifact in
                         baseline.Artifacts)
                {
                    if (artifact == null ||
                        string.IsNullOrWhiteSpace(
                            artifact.ModId))
                    {
                        continue;
                    }

                    if (string.Equals(
                            artifact.ModId,
                            loadedMod.ModId,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        return artifact;
                    }
                }
            }

            if (name != null &&
                !string.IsNullOrWhiteSpace(name.Name))
            {
                foreach (BaselineArtifact artifact in
                         baseline.Artifacts)
                {
                    if (artifact == null)
                    {
                        continue;
                    }

                    if (string.Equals(
                            artifact.AssemblyName,
                            name.Name,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        return artifact;
                    }
                }
            }

            return null;
        }

        private static bool IsSecurityRelevantAssembly(
            AssemblyName name,
            BaselineArtifact artifact)
        {
            if (artifact != null &&
                !string.IsNullOrWhiteSpace(
                    artifact.ModId))
            {
                return true;
            }

            if (name == null ||
                string.IsNullOrWhiteSpace(
                    name.Name))
            {
                return false;
            }

            return
                string.Equals(
                    name.Name,
                    "HKMP",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(
                    name.Name,
                    "HKMP.Whitelist",
                    StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsFrameworkAssembly(
            AssemblyName name)
        {
            if (name == null ||
                string.IsNullOrWhiteSpace(
                    name.Name))
            {
                return false;
            }

            string value =
                name.Name;

            return
                string.Equals(
                    value,
                    "mscorlib",
                    StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(
                    "System",
                    StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(
                    "Microsoft",
                    StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(
                    "Mono",
                    StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(
                    "UnityEngine",
                    StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(
                    "Unity",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(
                    value,
                    "netstandard",
                    StringComparison.OrdinalIgnoreCase);
        }

        private static BaselineAssembly FindBaselineAssembly(
            HostBaseline baseline,
            Assembly assembly,
            string normalizedLocation,
            AssemblyName name)
        {
            if (baseline == null ||
                baseline.Assemblies == null)
            {
                return null;
            }

            foreach (BaselineAssembly item in
                     baseline.Assemblies)
            {
                if (item == null)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(
                        normalizedLocation) &&
                    string.Equals(
                        NormalizeFullPath(item.Location),
                        normalizedLocation,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return item;
                }

                if (name != null &&
                    string.Equals(
                        item.FullName,
                        name.FullName,
                        StringComparison.Ordinal))
                {
                    return item;
                }
            }

            return null;
        }

        private static BaselineNativeModule FindBaselineNativeModule(
            HostBaseline baseline,
            string name,
            string path)
        {
            if (baseline == null ||
                baseline.NativeModules == null)
            {
                return null;
            }

            foreach (BaselineNativeModule item in
                     baseline.NativeModules)
            {
                if (item == null)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(path) &&
                    string.Equals(
                        NormalizeFullPath(item.Path),
                        path,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return item;
                }

                if (string.Equals(
                        item.Name,
                        name,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return item;
                }
            }

            return null;
        }

        private static string ResolveGameRoot()
        {
            string gameRoot;
            string failureReason;

            return GamePathResolver.TryResolve(
                    null,
                    out gameRoot,
                    out failureReason)
                ? gameRoot
                : null;
        }

        private static AssemblyName TryGetAssemblyName(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            try
            {
                return AssemblyName.GetAssemblyName(path);
            }
            catch
            {
                return null;
            }
        }

        private static string ComputeStableHash(
            string path,
            FileInfo before,
            out FileInfo after)
        {
            after = null;

            if (before == null ||
                !before.Exists)
            {
                return null;
            }

            string hash;

            try
            {
                hash =
                    HashUtil.Sha256File(
                        path);

                after =
                    new FileInfo(
                        path);
            }
            catch
            {
                return null;
            }

            if (hash == null ||
                after == null ||
                !after.Exists)
            {
                return null;
            }

            if (before.Length != after.Length ||
                before.LastWriteTimeUtc !=
                after.LastWriteTimeUtc)
            {
                return null;
            }

            return hash;
        }

        private static string TryHashFile(
            string path)
        {
            try
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

                if (before.Length != after.Length ||
                    before.LastWriteTimeUtc !=
                    after.LastWriteTimeUtc)
                {
                    return null;
                }

                return hash;
            }
            catch
            {
                return null;
            }
        }

        private static string MakeRelativeGamePath(
            string gameRoot,
            string fullPath)
        {
            if (string.IsNullOrWhiteSpace(gameRoot) ||
                string.IsNullOrWhiteSpace(fullPath))
            {
                return null;
            }

            try
            {
                string root =
                    NormalizeFullPath(
                        gameRoot);

                string file =
                    NormalizeFullPath(
                        fullPath);

                if (string.IsNullOrWhiteSpace(root) ||
                    string.IsNullOrWhiteSpace(file))
                {
                    return null;
                }

                Uri rootUri =
                    new Uri(
                        root.TrimEnd(
                            Path.DirectorySeparatorChar,
                            Path.AltDirectorySeparatorChar) +
                        Path.DirectorySeparatorChar);

                Uri fileUri =
                    new Uri(file);

                string relative =
                    Uri.UnescapeDataString(
                        rootUri
                            .MakeRelativeUri(fileUri)
                            .ToString());

                return NormalizePath(
                    relative);
            }
            catch
            {
                return null;
            }
        }

        private static string ResolveGameRelativePath(
            string gameRoot,
            string relativePath)
        {
            if (string.IsNullOrWhiteSpace(gameRoot) ||
                string.IsNullOrWhiteSpace(relativePath))
            {
                return null;
            }

            try
            {
                string root =
                    NormalizeFullPath(
                        gameRoot);

                string relative =
                    relativePath
                        .Trim()
                        .Replace(
                            '/',
                            Path.DirectorySeparatorChar)
                        .Replace(
                            '\\',
                            Path.DirectorySeparatorChar);

                string combined =
                    NormalizeFullPath(
                        Path.Combine(
                            root,
                            relative));

                if (string.IsNullOrWhiteSpace(root) ||
                    string.IsNullOrWhiteSpace(combined))
                {
                    return null;
                }

                string prefix =
                    root.TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar) +
                    Path.DirectorySeparatorChar;

                if (!combined.StartsWith(
                        prefix,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }

                return combined;
            }
            catch
            {
                return null;
            }
        }

        private static string SafeModuleName(
            ProcessModule module)
        {
            try
            {
                return module == null
                    ? "<unknown-module>"
                    : module.ModuleName ?? "<unknown-module>";
            }
            catch
            {
                return "<unknown-module>";
            }
        }

        private static string SafeModulePath(
            ProcessModule module)
        {
            try
            {
                return module == null
                    ? null
                    : module.FileName;
            }
            catch
            {
                return null;
            }
        }
        private static bool IsPseudoNativeModule(
            string name,
            string path)
        {
            return
                IsPseudoNativeModuleValue(name) ||
                IsPseudoNativeModuleValue(path);
        }

        private static bool IsPseudoNativeModuleValue(
            string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return
                value.IndexOf(
                    "[In Memory]",
                    StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string SafeAssemblyFullName(Assembly assembly)
        {
            try
            {
                return assembly == null ? null : assembly.FullName;
            }
            catch
            {
                return null;
            }
        }

        private static AssemblyName SafeAssemblyName(Assembly assembly)
        {
            try
            {
                return assembly == null ? null : assembly.GetName();
            }
            catch
            {
                return null;
            }
        }

        private static string SafeAssemblyLocation(Assembly assembly)
        {
            try
            {
                return assembly == null ? null : assembly.Location;
            }
            catch
            {
                return null;
            }
        }

        private static string NormalizeFullPath(string path)
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

        private static string NormalizePath(string path)
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

        private static bool IsSystemNativePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string normalized =
                NormalizeFullPath(path);

            if (string.IsNullOrWhiteSpace(normalized))
            {
                return false;
            }

            string windowsDirectory;

            try
            {
                windowsDirectory =
                    NormalizeFullPath(
                        Environment.GetFolderPath(
                            Environment.SpecialFolder.Windows));
            }
            catch
            {
                windowsDirectory = null;
            }

            if (string.IsNullOrWhiteSpace(windowsDirectory))
            {
                return false;
            }

            string system32 =
                Path.Combine(
                    windowsDirectory,
                    "System32");

            string sysWow64 =
                Path.Combine(
                    windowsDirectory,
                    "SysWOW64");

            string winSxS =
                Path.Combine(
                    windowsDirectory,
                    "WinSxS");

            return
                IsPathWithin(
                    normalized,
                    NormalizeFullPath(system32)) ||
                IsPathWithin(
                    normalized,
                    NormalizeFullPath(sysWow64)) ||
                IsPathWithin(
                    normalized,
                    NormalizeFullPath(winSxS));
        }

        public static bool IsPathWithin(
            string path,
            string directory)
        {
            if (string.IsNullOrWhiteSpace(path) ||
                string.IsNullOrWhiteSpace(directory))
            {
                return false;
            }

            string normalizedDirectory =
                directory.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar) +
                Path.DirectorySeparatorChar;

            return
                string.Equals(
                    path,
                    directory,
                    StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith(
                    normalizedDirectory,
                    StringComparison.OrdinalIgnoreCase);
        }

        private static long GetFileSizeSafe(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return 0;
            }

            try
            {
                FileInfo info = new FileInfo(path);

                return info.Exists
                    ? info.Length
                    : 0;
            }
            catch
            {
                return 0;
            }
        }

    }
}
