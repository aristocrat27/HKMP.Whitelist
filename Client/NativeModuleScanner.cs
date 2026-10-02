using HKMP.Whitelist.Core;
using HKMP.Whitelist.Security;
using HKMP.Whitelist.Shared;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security;

namespace HKMP.Whitelist.Client
{
    internal sealed class NativeModuleScannerResult
    {
        public bool Complete { get; set; } = true;

        public List<NativeModuleScanEntry> UnknownNativeModules { get; } =
            new List<NativeModuleScanEntry>();

        public List<NativeModuleScanEntry> TrustedNativeModules { get; } =
            new List<NativeModuleScanEntry>();

        public List<string> IntegrityFailures { get; } =
            new List<string>();
    }

    internal static class NativeModuleScanner
    {
        public static NativeModuleScannerResult Scan(
            HostBaseline baseline)
        {
            NativeModuleScannerResult result =
                new NativeModuleScannerResult();

            if (baseline == null)
            {
                result.Complete = false;

                result.IntegrityFailures.Add(
                    "Host baseline is null.");

                result.UnknownNativeModules.Add(
                    CreateEntry(
                        "<baseline-invalid>",
                        "",
                        "unknown",
                        FileTrustStatus.Unknown));

                return result;
            }

            if (baseline.Artifacts == null)
            {
                result.Complete = false;

                result.IntegrityFailures.Add(
                    "Host baseline artifacts are missing.");

                result.UnknownNativeModules.Add(
                    CreateEntry(
                        "<baseline-artifacts-missing>",
                        "",
                        "unknown",
                        FileTrustStatus.Unknown));

                return result;
            }

            Process process;

            try
            {
                process =
                    Process.GetCurrentProcess();
            }
            catch (Exception ex)
            {
                result.Complete = false;

                result.IntegrityFailures.Add(
                    "Current process access failed: " +
                    ex.GetType().Name);

                result.UnknownNativeModules.Add(
                    CreateEntry(
                        "<process-access-failed>",
                        "",
                        ex.GetType().Name,
                        FileTrustStatus.Unknown));

                return result;
            }

            ProcessModuleCollection modules;

            try
            {
                modules =
                    process.Modules;
            }
            catch (Exception ex)
            {
                result.Complete = false;

                result.IntegrityFailures.Add(
                    "Native module enumeration failed: " +
                    ex.GetType().Name);

                result.UnknownNativeModules.Add(
                    CreateEntry(
                        "<module-enumeration-failed>",
                        "",
                        ex.GetType().Name,
                        FileTrustStatus.Unknown));

                return result;
            }

            if (modules == null)
            {
                result.Complete = false;

                result.IntegrityFailures.Add(
                    "Native module enumeration returned null.");

                result.UnknownNativeModules.Add(
                    CreateEntry(
                        "<module-enumeration-null>",
                        "",
                        "unknown",
                        FileTrustStatus.Unknown));

                return result;
            }

            HashSet<string> seen =
                new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

            foreach (ProcessModule module in modules)
            {
                if (module == null)
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            "<null-module>",
                            "",
                            "unknown",
                            FileTrustStatus.Unknown));

                    continue;
                }

                string moduleName =
                    SafeModuleName(module);

                string modulePath =
                    SafeModulePath(module);

                if (IsPseudoNativeModule(
                        moduleName,
                        modulePath))
                {
                    continue;
                }

                if (string.IsNullOrEmpty(modulePath))
                {
                    if (IsKnownPlatformModuleName(moduleName))
                    {
                        result.TrustedNativeModules.Add(
                            CreateEntry(
                                moduleName,
                                "",
                                "known-platform",
                                FileTrustStatus.KnownGood));

                        continue;
                    }

                    result.Complete = false;

                    result.IntegrityFailures.Add(
                        "Native module path unavailable: " +
                        moduleName);

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            "",
                            "unknown-location",
                            FileTrustStatus.Unknown));

                    continue;
                }

                string fullPath;

                try
                {
                    fullPath =
                        Path.GetFullPath(
                            modulePath);
                }
                catch (Exception ex)
                {
                    result.Complete = false;

                    result.IntegrityFailures.Add(
                        "Invalid native module path for " +
                        moduleName +
                        ": " +
                        ex.GetType().Name);

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            modulePath,
                            "invalid-path",
                            FileTrustStatus.Unknown));

                    continue;
                }

                if (!seen.Add(fullPath))
                {
                    continue;
                }

                if (IsSystemModule(fullPath))
                {
                    continue;
                }

                if (!GamePathResolver.IsPathWithin(
                        GetGameRoot(),
                        fullPath))
                {
                    continue;
                }

                if (HasReparsePoint(fullPath))
                {
                    NativeModuleScanEntry reparseEntry =
                        CreateEntry(
                            moduleName,
                            fullPath,
                            "reparse-point",
                            FileTrustStatus.Unknown);

                    result.UnknownNativeModules.Add(
                        reparseEntry);

                    result.IntegrityFailures.Add(
                        "Native module uses a reparse-point path: " +
                        fullPath);

                    continue;
                }

                if (!File.Exists(fullPath))
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            "missing-file",
                            FileTrustStatus.Unknown));

                    result.IntegrityFailures.Add(
                        "Native module file does not exist: " +
                        fullPath);

                    continue;
                }

                FileInfo initialInfo;

                try
                {
                    initialInfo =
                        new FileInfo(fullPath);
                }
                catch (Exception ex) when (
                    ex is IOException ||
                    ex is UnauthorizedAccessException ||
                    ex is SecurityException)
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            ex.GetType().Name,
                            FileTrustStatus.Unknown));

                    result.IntegrityFailures.Add(
                        "Native module metadata read failed: " +
                        fullPath +
                        " [" +
                        ex.GetType().Name +
                        "].");

                    continue;
                }

                long initialLength =
                    initialInfo.Length;

                DateTime initialWriteTimeUtc =
                    initialInfo.LastWriteTimeUtc;

                string hash;

                try
                {
                    hash =
                        HashUtil.Sha256File(
                            fullPath);
                }
                catch (Exception ex) when (
                    ex is IOException ||
                    ex is UnauthorizedAccessException ||
                    ex is SecurityException)
                {
                    if (IsKnownPlatformModuleName(moduleName) &&
                        !IsSecurityRelevantPath(fullPath))
                    {
                        result.TrustedNativeModules.Add(
                            CreateEntry(
                                moduleName,
                                fullPath,
                                "known-platform",
                                FileTrustStatus.KnownGood));

                        continue;
                    }

                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            ex.GetType().Name,
                            FileTrustStatus.Unknown));

                    result.IntegrityFailures.Add(
                        "Native module hash failed: " +
                        fullPath +
                        " [" +
                        ex.GetType().Name +
                        "].");

                    continue;
                }
                catch (Exception ex)
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            "hash-error:" +
                            ex.GetType().Name,
                            FileTrustStatus.Unknown));

                    result.IntegrityFailures.Add(
                        "Native module hash failed: " +
                        fullPath +
                        " [" +
                        ex.GetType().Name +
                        "].");

                    continue;
                }

                if (string.IsNullOrEmpty(hash))
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            "hash-unavailable",
                            FileTrustStatus.Unknown));

                    continue;
                }

                FileInfo finalInfo;

                try
                {
                    finalInfo =
                        new FileInfo(fullPath);
                }
                catch (Exception ex)
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            "final-metadata-error:" +
                            ex.GetType().Name,
                            FileTrustStatus.Unknown));

                    continue;
                }

                if (!finalInfo.Exists)
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            hash,
                            FileTrustStatus.Unknown));

                    result.IntegrityFailures.Add(
                        "Native module disappeared during hashing: " +
                        fullPath);

                    continue;
                }

                if (finalInfo.Length != initialLength ||
                    finalInfo.LastWriteTimeUtc != initialWriteTimeUtc)
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            hash,
                            FileTrustStatus.Unknown));

                    result.IntegrityFailures.Add(
                        "Native module changed during hashing: " +
                        fullPath);

                    continue;
                }

                string relativePath =
                    GetNormalizedRelativePath(
                        fullPath);

                BaselineNativeModule exact =
                    FindExactBaselineNativeModule(
                        baseline,
                        relativePath,
                        moduleName,
                        fullPath,
                        finalInfo.Length,
                        hash);

                if (exact != null)
                {
                    if (IsForbiddenNativeModule(exact))
                    {
                        result.UnknownNativeModules.Add(
                            CreateEntry(
                                moduleName,
                                fullPath,
                                hash,
                                FileTrustStatus.Forbidden));

                        continue;
                    }

                    result.TrustedNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            hash,
                            FileTrustStatus.Trusted));

                    continue;
                }

                BaselineNativeModule hashMatch =
                    FindNativeModuleByHash(
                        baseline,
                        hash);

                if (hashMatch != null)
                {
                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            hash,
                            FileTrustStatus.PathMismatch));

                    continue;
                }

                BaselineNativeModule pathMatch =
                    FindNativeModuleByPath(
                        baseline,
                        relativePath,
                        fullPath);

                if (pathMatch != null)
                {
                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            hash,
                            FileTrustStatus.Unknown));

                    continue;
                }

                result.UnknownNativeModules.Add(
                    CreateEntry(
                        moduleName,
                        fullPath,
                        hash,
                        FileTrustStatus.Unknown));
            }

            return result;
        }

        public static NativeModuleScannerResult Scan(
            TrustedManifest manifest)
        {
            NativeModuleScannerResult result =
                new NativeModuleScannerResult();

            if (manifest == null ||
                manifest.Entries == null)
            {
                result.Complete = false;

                result.IntegrityFailures.Add(
                    "Manifest is null or invalid.");

                result.UnknownNativeModules.Add(
                    CreateEntry(
                        "<manifest-invalid>",
                        "",
                        "unknown",
                        FileTrustStatus.Unknown));

                return result;
            }

            Process process;

            try
            {
                process =
                    Process.GetCurrentProcess();
            }
            catch (Exception ex)
            {
                result.Complete = false;

                result.IntegrityFailures.Add(
                    "Current process access failed: " +
                    ex.GetType().Name);

                result.UnknownNativeModules.Add(
                    CreateEntry(
                        "<process-access-failed>",
                        "",
                        ex.GetType().Name,
                        FileTrustStatus.Unknown));

                return result;
            }

            ProcessModuleCollection modules;

            try
            {
                modules =
                    process.Modules;
            }
            catch (Exception ex)
            {
                result.Complete = false;

                result.IntegrityFailures.Add(
                    "Native module enumeration failed: " +
                    ex.GetType().Name);

                result.UnknownNativeModules.Add(
                    CreateEntry(
                        "<module-enumeration-failed>",
                        "",
                        ex.GetType().Name,
                        FileTrustStatus.Unknown));

                return result;
            }

            if (modules == null)
            {
                result.Complete = false;

                result.IntegrityFailures.Add(
                    "Native module enumeration returned null.");

                return result;
            }

            HashSet<string> seen =
                new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

            foreach (ProcessModule module in modules)
            {
                if (module == null)
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            "<null-module>",
                            "",
                            "unknown",
                            FileTrustStatus.Unknown));

                    continue;
                }

                string moduleName =
                    SafeModuleName(module);

                string modulePath =
                    SafeModulePath(module);

                if (IsPseudoNativeModule(
                        moduleName,
                        modulePath))
                {
                    continue;
                }

                if (string.IsNullOrEmpty(modulePath))
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            "",
                            "unknown-location",
                            FileTrustStatus.Unknown));

                    continue;
                }

                string fullPath;

                try
                {
                    fullPath =
                        Path.GetFullPath(
                            modulePath);
                }
                catch
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            modulePath,
                            "invalid-path",
                            FileTrustStatus.Unknown));

                    continue;
                }

                if (!seen.Add(fullPath))
                {
                    continue;
                }

                if (IsSystemModule(
                        fullPath))
                {
                    result.TrustedNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            "system",
                            FileTrustStatus.KnownGood));

                    continue;
                }

                if (HasReparsePoint(fullPath))
                {
                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            "reparse-point",
                            FileTrustStatus.Unknown));

                    continue;
                }

                if (!File.Exists(fullPath))
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            "missing-file",
                            FileTrustStatus.Unknown));

                    continue;
                }

                string hash;

                try
                {
                    hash =
                        HashUtil.Sha256File(
                            fullPath);
                }
                catch (Exception ex)
                {
                    result.Complete = false;

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            ex.GetType().Name,
                            FileTrustStatus.Unknown));

                    continue;
                }

                string relativePath =
                    GetNormalizedRelativePath(
                        fullPath);

                ManifestEntry match =
                    manifest.Entries.FirstOrDefault(
                        entry =>
                            entry != null &&
                            !string.IsNullOrEmpty(
                                entry.Sha256) &&
                            string.Equals(
                                entry.Sha256,
                                hash,
                                StringComparison.OrdinalIgnoreCase));

                if (match == null)
                {
                    if (IsKnownPlatformModule(
                            fullPath,
                            moduleName))
                    {
                        result.TrustedNativeModules.Add(
                            CreateEntry(
                                moduleName,
                                fullPath,
                                hash,
                                FileTrustStatus.KnownGood));

                        continue;
                    }

                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            hash,
                            FileTrustStatus.Unknown));

                    continue;
                }

                if (match.PolicyFlags != null &&
                    match.PolicyFlags.Any(
                        flag =>
                            string.Equals(
                                flag,
                                "FORBIDDEN",
                                StringComparison.OrdinalIgnoreCase)))
                {
                    result.UnknownNativeModules.Add(
                        CreateEntry(
                            moduleName,
                            fullPath,
                            hash,
                            FileTrustStatus.Forbidden));

                    continue;
                }

                if (match.AllowedPaths != null &&
                    match.AllowedPaths.Count > 0)
                {
                    bool pathAllowed =
                        match.AllowedPaths.Any(
                            allowedPath =>
                                PathsEqual(
                                    allowedPath,
                                    relativePath));

                    if (!pathAllowed)
                    {
                        result.UnknownNativeModules.Add(
                            CreateEntry(
                                moduleName,
                                fullPath,
                                hash,
                                FileTrustStatus.PathMismatch));

                        continue;
                    }
                }

                result.TrustedNativeModules.Add(
                    CreateEntry(
                        moduleName,
                        fullPath,
                        hash,
                        FileTrustStatus.Trusted));
            }

            return result;
        }

        private static BaselineNativeModule FindExactBaselineNativeModule(
            HostBaseline baseline,
            string relativePath,
            string moduleName,
            string fullPath,
            long fileSize,
            string sha256)
        {
            if (baseline == null ||
                baseline.NativeModules == null)
            {
                return null;
            }

            foreach (BaselineNativeModule module in
                     baseline.NativeModules)
            {
                if (module == null ||
                    !module.IsSecurityRelevant)
                {
                    continue;
                }

                bool pathMatches =
                    PathsEqual(
                        module.RelativePath,
                        relativePath) ||
                    FullPathsEqual(
                        module.Path,
                        fullPath);

                if (!pathMatches)
                {
                    continue;
                }

                if (!string.Equals(
                        module.Name,
                        moduleName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (module.FileSize != fileSize)
                {
                    continue;
                }

                if (!string.Equals(
                        module.Sha256,
                        sha256,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                return module;
            }

            return null;
        }

        private static BaselineNativeModule FindNativeModuleByHash(
            HostBaseline baseline,
            string sha256)
        {
            if (baseline == null ||
                baseline.NativeModules == null ||
                string.IsNullOrWhiteSpace(sha256))
            {
                return null;
            }

            return baseline.NativeModules.FirstOrDefault(
                module =>
                    module != null &&
                    module.IsSecurityRelevant &&
                    !string.IsNullOrWhiteSpace(module.Sha256) &&
                    string.Equals(
                        module.Sha256,
                        sha256,
                        StringComparison.OrdinalIgnoreCase));
        }

        private static BaselineNativeModule FindNativeModuleByPath(
            HostBaseline baseline,
            string relativePath,
            string fullPath)
        {
            if (baseline == null ||
                baseline.NativeModules == null)
            {
                return null;
            }

            return baseline.NativeModules.FirstOrDefault(
                module =>
                    module != null &&
                    module.IsSecurityRelevant &&
                    (PathsEqual(module.RelativePath, relativePath) ||
                     FullPathsEqual(module.Path, fullPath)));
        }

        private static bool FullPathsEqual(
            string first,
            string second)
        {
            string a =
                NormalizeFullPath(first);

            string b =
                NormalizeFullPath(second);

            return
                !string.IsNullOrWhiteSpace(a) &&
                !string.IsNullOrWhiteSpace(b) &&
                string.Equals(
                    a,
                    b,
                    StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsForbiddenNativeModule(
            BaselineNativeModule module)
        {
            if (module == null ||
                string.IsNullOrWhiteSpace(module.Classification))
            {
                return false;
            }

            return string.Equals(
                module.Classification,
                "Forbidden",
                StringComparison.OrdinalIgnoreCase);
        }

        private static string GetGameRoot()
        {
            string root;
            string reason;

            if (GamePathResolver.TryResolve(
                    null,
                    out root,
                    out reason))
            {
                return root;
            }

            return null;
        }

        private static bool IsSecurityRelevantPath(
            string path)
        {
            string normalized =
                NormalizePath(path);

            string gameRoot =
                NormalizePath(
                    AppDomain.CurrentDomain.BaseDirectory);

            if (string.IsNullOrEmpty(
                    normalized))
            {
                return false;
            }

            if (StartsWithPath(
                    normalized,
                    gameRoot))
            {
                return true;
            }

            return
                normalized.IndexOf(
                    "/managed/",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf(
                    "/mods/",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf(
                    "/bepinex/",
                    StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsSystemModule(
            string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }

            string fullPath;

            try
            {
                fullPath =
                    Path.GetFullPath(path);
            }
            catch
            {
                return false;
            }

            string windows =
                Environment.GetFolderPath(
                    Environment.SpecialFolder.Windows);

            if (string.IsNullOrEmpty(windows))
            {
                return false;
            }

            windows =
                Path.GetFullPath(
                    windows)
                    .TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar);

            return
                StartsWithPath(
                    fullPath,
                    windows +
                    Path.DirectorySeparatorChar +
                    "System32") ||
                StartsWithPath(
                    fullPath,
                    windows +
                    Path.DirectorySeparatorChar +
                    "SysWOW64") ||
                StartsWithPath(
                    fullPath,
                    windows +
                    Path.DirectorySeparatorChar +
                    "WinSxS");
        }

        private static bool IsKnownPlatformModuleName(
            string moduleName)
        {
            string normalizedName =
                (moduleName ?? "")
                .Trim()
                .ToLowerInvariant();

            return
                normalizedName == "steamclient64.dll" ||
                normalizedName == "steam_api64.dll" ||
                normalizedName == "gameoverlayrenderer64.dll" ||
                normalizedName == "tier0_s64.dll" ||
                normalizedName == "vstdlib_s64.dll" ||
                normalizedName == "unityplayer.dll" ||
                normalizedName == "mono-2.0-bdwgc.dll" ||
                normalizedName.StartsWith("nv", StringComparison.Ordinal) ||
                normalizedName.StartsWith("amd", StringComparison.Ordinal) ||
                normalizedName.StartsWith("ig", StringComparison.Ordinal);
        }

        private static bool IsKnownPlatformModule(
            string path,
            string moduleName)
        {
            string normalizedPath =
                NormalizePath(path);

            string normalizedName =
                (moduleName ?? "")
                .Trim()
                .ToLowerInvariant();

            if (normalizedName == "steamclient64.dll" ||
                normalizedName == "steam_api64.dll" ||
                normalizedName == "gameoverlayrenderer64.dll" ||
                normalizedName == "tier0_s64.dll" ||
                normalizedName == "vstdlib_s64.dll")
            {
                return true;
            }

            if (normalizedName == "unityplayer.dll" ||
                normalizedName == "mono-2.0-bdwgc.dll")
            {
                return IsGameRelatedPlatformPath(
                    normalizedPath);
            }

            if (normalizedPath.IndexOf(
                    "/steam/",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            if (normalizedPath.IndexOf(
                    "/steamapps/",
                    StringComparison.OrdinalIgnoreCase) >= 0 &&
                normalizedName.IndexOf(
                    "overlay",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            if (normalizedName.StartsWith(
                    "nv",
                    StringComparison.OrdinalIgnoreCase) ||
                normalizedName.StartsWith(
                    "amd",
                    StringComparison.OrdinalIgnoreCase) ||
                normalizedName.StartsWith(
                    "ig",
                    StringComparison.OrdinalIgnoreCase))
            {
                return IsLikelyDriverPath(
                    normalizedPath);
            }

            return false;
        }

        private static bool IsGameRelatedPlatformPath(
            string normalizedPath)
        {
            string gameRoot =
                NormalizePath(
                    AppDomain.CurrentDomain.BaseDirectory);

            return StartsWithPath(
                normalizedPath,
                gameRoot);
        }

        private static bool IsLikelyDriverPath(
            string normalizedPath)
        {
            string windows =
                NormalizePath(
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.Windows));

            if (string.IsNullOrEmpty(windows))
            {
                return false;
            }

            return
                normalizedPath.IndexOf(
                    windows +
                    "/system32/",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalizedPath.IndexOf(
                    windows +
                    "/syswow64/",
                    StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool StartsWithPath(
            string path,
            string root)
        {
            if (string.IsNullOrEmpty(path) ||
                string.IsNullOrEmpty(root))
            {
                return false;
            }

            string normalizedPath =
                NormalizePath(path)
                    .TrimEnd('/');

            string normalizedRoot =
                NormalizePath(root)
                    .TrimEnd('/');

            return
                string.Equals(
                    normalizedPath,
                    normalizedRoot,
                    StringComparison.OrdinalIgnoreCase) ||
                normalizedPath.StartsWith(
                    normalizedRoot + "/",
                    StringComparison.OrdinalIgnoreCase);
        }

        private static bool HasReparsePoint(
            string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }

            try
            {
                FileInfo fileInfo =
                    new FileInfo(path);

                if ((fileInfo.Attributes &
                     FileAttributes.ReparsePoint) != 0)
                {
                    return true;
                }

                DirectoryInfo directory =
                    fileInfo.Directory;

                while (directory != null)
                {
                    if ((directory.Attributes &
                         FileAttributes.ReparsePoint) != 0)
                    {
                        return true;
                    }

                    directory =
                        directory.Parent;
                }
            }
            catch
            {
                return true;
            }

            return false;
        }

        private static NativeModuleScanEntry CreateEntry(
            string name,
            string path,
            string sha256,
            FileTrustStatus status)
        {
            return new NativeModuleScanEntry
            {
                Name =
                    string.IsNullOrEmpty(name)
                        ? "<unknown-module>"
                        : name,

                Path =
                    path ?? "",

                Sha256 =
                    string.IsNullOrEmpty(sha256)
                        ? "unknown"
                        : sha256,

                Status =
                    status
            };
        }

        private static string SafeModuleName(
            ProcessModule module)
        {
            try
            {
                if (module == null ||
                    string.IsNullOrEmpty(
                        module.ModuleName))
                {
                    return "<unknown-module>";
                }

                return module.ModuleName;
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
                if (module == null)
                {
                    return "";
                }

                return module.FileName ?? "";
            }
            catch
            {
                return "";
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

        private static string SafeFileName(
            string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "";
            }

            try
            {
                return Path.GetFileName(value) ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string GetNormalizedRelativePath(
            string fullPath)
        {
            if (string.IsNullOrEmpty(fullPath))
            {
                return "";
            }

            try
            {
                string root =
                    AppDomain.CurrentDomain.BaseDirectory;

                return NormalizeRelativePath(
                    fullPath,
                    root);
            }
            catch
            {
                return NormalizePath(
                    fullPath);
            }
        }

        private static string NormalizeRelativePath(
            string fullPath,
            string rootPath)
        {
            string full =
                Path.GetFullPath(fullPath);

            string root =
                Path.GetFullPath(rootPath)
                    .TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar);

            if (full.StartsWith(
                    root +
                    Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
            {
                return full
                    .Substring(
                        root.Length + 1)
                    .Replace(
                        '\\',
                        '/');
            }

            if (full.StartsWith(
                    root +
                    Path.AltDirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
            {
                return full
                    .Substring(
                        root.Length + 1)
                    .Replace(
                        '\\',
                        '/');
            }

            return NormalizePath(full);
        }

        private static string NormalizePath(
            string path)
        {
            return (path ?? "")
                .Replace(
                    '\\',
                    '/')
                .TrimStart('/');
        }

        private static bool PathsEqual(
            string first,
            string second)
        {
            string a =
                NormalizePath(first);

            string b =
                NormalizePath(second);

            return string.Equals(
                a,
                b,
                StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeFullPath(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "";
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
                return path.Trim();
            }
        }

        private static bool IsForbiddenArtifact(
            BaselineArtifact artifact)
        {
            if (artifact == null ||
                artifact.PolicyFlags == null)
            {
                return false;
            }

            return artifact.PolicyFlags.Any(
                flag =>
                    string.Equals(
                        flag,
                        "FORBIDDEN",
                        StringComparison.OrdinalIgnoreCase));
        }
    }
}