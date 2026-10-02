using HKMP.Whitelist.Security;
using HKMP.Whitelist.Shared;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace HKMP.Whitelist.Client
{
    internal sealed class FileScannerResult
    {
        public bool Complete { get; set; } = true;

        public List<FileScanEntry> UnknownFiles { get; } =
            new List<FileScanEntry>();

        public List<FileScanEntry> ForbiddenFiles { get; } =
            new List<FileScanEntry>();

        public List<string> IntegrityFailures { get; } =
            new List<string>();

        public List<string> TrustedModIds { get; } =
            new List<string>();

        public List<string> UnreadableFiles { get; } =
            new List<string>();

        public List<ArtifactEvidence> Artifacts { get; } =
            new List<ArtifactEvidence>();
    }

    internal static class FileScanner
    {
        private const int StableHashAttempts = 3;

        public static FileScannerResult Scan(
            HostBaseline baseline,
            string gameRoot)
        {
            FileScannerResult result =
                new FileScannerResult();

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

            string normalizedGameRoot =
                NormalizeGameRoot(gameRoot);

            if (string.IsNullOrWhiteSpace(normalizedGameRoot) ||
                !Directory.Exists(normalizedGameRoot))
            {
                return Fail(
                    result,
                    "Game root is unavailable.");
            }

            foreach (BaselineArtifact expected in
                     baseline.Artifacts
                        .Where(x => x != null)
                        .OrderBy(
                            x => x.RelativePath ?? "",
                            StringComparer.OrdinalIgnoreCase))
            {
                ScanExpectedArtifact(
                    expected,
                    normalizedGameRoot,
                    result);
            }

            return result;
        }

        private static void ScanExpectedArtifact(
            BaselineArtifact expected,
            string gameRoot,
            FileScannerResult result)
        {
            string path;

            if (!TryResolveArtifactPath(
                expected.RelativePath,
                gameRoot,
                out path))
            {
                result.Complete = false;
                result.IntegrityFailures.Add(
                    "INVALID_BASELINE_ARTIFACT_PATH:" +
                    (expected.RelativePath ?? "<null>"));

                result.UnreadableFiles.Add(
                    expected.RelativePath ?? "<null>");

                result.Artifacts.Add(
                    CreateEvidence(
                        expected,
                        null,
                        false,
                        false,
                        "invalid-path"));

                return;
            }

            if (HasReparsePoint(path))
            {
                result.Complete = false;
                result.IntegrityFailures.Add(
                    "REPARSE_POINT_DETECTED:" +
                    path);

                result.UnreadableFiles.Add(path);

                result.Artifacts.Add(
                    CreateEvidence(
                        expected,
                        path,
                        true,
                        false,
                        "reparse-point"));

                return;
            }

            if (!File.Exists(path))
            {
                result.Complete = false;
                result.IntegrityFailures.Add(
                    "EXPECTED_ARTIFACT_MISSING:" +
                    SafePath(expected.RelativePath));

                result.UnreadableFiles.Add(path);

                result.Artifacts.Add(
                    CreateEvidence(
                        expected,
                        path,
                        false,
                        false,
                        "missing"));

                return;
            }

            FileInfo before;

            try
            {
                before =
                    new FileInfo(path);
            }
            catch (Exception ex)
            {
                result.Complete = false;
                result.IntegrityFailures.Add(
                    "FILE_STAT_FAILED:" +
                    path +
                    ":" +
                    ex.GetType().Name);

                result.UnreadableFiles.Add(path);

                result.Artifacts.Add(
                    CreateEvidence(
                        expected,
                        path,
                        true,
                        false,
                        "stat-failed"));

                return;
            }

            string hash;
            string hashFailure;

            if (!TryComputeStableHash(
                path,
                out hash,
                out hashFailure))
            {
                result.Complete = false;
                result.IntegrityFailures.Add(
                    "FILE_HASH_FAILED:" +
                    path +
                    ":" +
                    hashFailure);

                result.UnreadableFiles.Add(path);

                result.Artifacts.Add(
                    CreateEvidence(
                        expected,
                        path,
                        true,
                        false,
                        hashFailure));

                return;
            }

            FileInfo after;

            try
            {
                after =
                    new FileInfo(path);
            }
            catch (Exception ex)
            {
                result.Complete = false;
                result.IntegrityFailures.Add(
                    "FILE_RESTAT_FAILED:" +
                    path +
                    ":" +
                    ex.GetType().Name);

                result.Artifacts.Add(
                    CreateEvidence(
                        expected,
                        path,
                        true,
                        false,
                        "restat-failed"));

                return;
            }

            string relativePath =
                NormalizePath(
                    MakeRelativePath(
                        gameRoot,
                        path));

            ArtifactEvidence evidence =
                CreateEvidence(
                    expected,
                    path,
                    true,
                    true,
                    null,
                    before.Length,
                    hash,
                    relativePath);

            result.Artifacts.Add(evidence);

            bool valid =
                string.Equals(
                    expected.FileName,
                    Path.GetFileName(path),
                    StringComparison.OrdinalIgnoreCase) &&
                PathsEqual(
                    expected.RelativePath,
                    relativePath) &&
                expected.FileSize == after.Length &&
                string.Equals(
                    expected.Sha256,
                    hash,
                    StringComparison.OrdinalIgnoreCase);

            if (before.Length != after.Length ||
                before.LastWriteTimeUtc != after.LastWriteTimeUtc)
            {
                valid = false;

                result.Complete = false;
                result.IntegrityFailures.Add(
                    "FILE_CHANGED_DURING_SCAN:" +
                    path);
            }

            if (!valid)
            {
                result.UnknownFiles.Add(
                    CreateEntry(
                        expected,
                        path,
                        after.Length,
                        hash,
                        FileTrustStatus.PathMismatch));

                return;
            }

            if (!string.IsNullOrWhiteSpace(expected.ModId) &&
                !ContainsIgnoreCase(
                    result.TrustedModIds,
                    expected.ModId))
            {
                result.TrustedModIds.Add(
                    expected.ModId);
            }
        }

        private static ArtifactEvidence CreateEvidence(
            BaselineArtifact expected,
            string path,
            bool exists,
            bool readable,
            string details,
            long size = 0,
            string hash = null,
            string relativePath = null)
        {
            return new ArtifactEvidence
            {
                Source = EvidenceSource.FileSystem,
                ModId = expected == null ? null : expected.ModId,
                ArtifactId = expected == null ? null : expected.ArtifactId,
                FileName = expected == null
                    ? null
                    : expected.FileName,
                Path = path,
                RelativePath = string.IsNullOrWhiteSpace(relativePath)
                    ? expected == null ? null : expected.RelativePath
                    : relativePath,
                FileSize = size,
                Sha256 = hash,
                ExpectedSha256 = expected == null ? null : expected.Sha256,
                AssemblyName = expected == null ? null : expected.AssemblyName,
                AssemblyFullName = expected == null ? null : expected.AssemblyFullName,
                AssemblyVersion = expected == null ? null : expected.AssemblyVersion,
                AssemblyLocation = expected == null
                    ? null
                    : expected.AssemblyLocation,
                IsLoaded = expected != null && expected.IsLoaded,
                Exists = exists,
                IsReadable = readable,
                ObservedAtUtc = DateTime.UtcNow,
                Details = details
            };
        }

        private static FileScanEntry CreateEntry(
            BaselineArtifact expected,
            string path,
            long size,
            string hash,
            FileTrustStatus status)
        {
            return new FileScanEntry
            {
                Path = path,
                ModId = expected == null ? null : expected.ModId,
                ArtifactId = expected == null ? null : expected.ArtifactId,
                Sha256 = hash,
                ExpectedSha256 = expected == null ? null : expected.Sha256,
                Size = size,
                LastWriteTimeUtc = GetLastWriteTimeUtc(path),
                Status = status
            };
        }

        private static bool TryResolveArtifactPath(
            string relativePath,
            string gameRoot,
            out string absolutePath)
        {
            absolutePath = null;

            string normalized =
                NormalizePath(relativePath);

            if (string.IsNullOrWhiteSpace(normalized) ||
                Path.IsPathRooted(normalized) ||
                normalized.StartsWith("..", StringComparison.Ordinal))
            {
                return false;
            }

            foreach (string segment in
                     normalized.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (string.Equals(segment, "..", StringComparison.Ordinal))
                {
                    return false;
                }
            }

            try
            {
                string combined =
                    Path.GetFullPath(
                        Path.Combine(
                            gameRoot,
                            normalized.Replace('/', Path.DirectorySeparatorChar)));

                string root =
                    NormalizeDirectoryPath(gameRoot);

                if (!PathsWithin(root, combined))
                {
                    return false;
                }

                absolutePath = combined;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryComputeStableHash(
            string path,
            out string hash,
            out string failure)
        {
            hash = null;
            failure = null;

            for (int attempt = 0;
                 attempt < StableHashAttempts;
                 attempt++)
            {
                FileInfo before;

                try
                {
                    before = new FileInfo(path);

                    if (!before.Exists)
                    {
                        failure = "FILE_NOT_FOUND";
                        continue;
                    }
                }
                catch (Exception ex)
                {
                    failure =
                        "STAT_FAILED:" +
                        ex.GetType().Name;
                    continue;
                }

                string computed;

                try
                {
                    computed =
                        HashUtil.Sha256File(path);
                }
                catch (Exception ex)
                {
                    failure =
                        "HASH_FAILED:" +
                        ex.GetType().Name;
                    continue;
                }

                if (string.IsNullOrWhiteSpace(computed))
                {
                    failure = "HASH_EMPTY";
                    continue;
                }

                FileInfo after;

                try
                {
                    after = new FileInfo(path);
                }
                catch (Exception ex)
                {
                    failure =
                        "RESTAT_FAILED:" +
                        ex.GetType().Name;
                    continue;
                }

                if (!after.Exists)
                {
                    failure = "FILE_DISAPPEARED_AFTER_HASH";
                    continue;
                }

                if (before.Length != after.Length ||
                    before.LastWriteTimeUtc != after.LastWriteTimeUtc)
                {
                    failure = "FILE_CHANGED_DURING_HASH";
                    continue;
                }

                hash = computed;
                return true;
            }

            return false;
        }

        private static bool HasReparsePoint(string path)
        {
            try
            {
                string current =
                    NormalizeFullPath(path);

                while (!string.IsNullOrWhiteSpace(current))
                {
                    if (File.Exists(current) || Directory.Exists(current))
                    {
                        FileAttributes attributes =
                            File.GetAttributes(current);

                        if ((attributes & FileAttributes.ReparsePoint) != 0)
                        {
                            return true;
                        }
                    }

                    DirectoryInfo directory =
                        Directory.GetParent(current);

                    if (directory == null)
                    {
                        break;
                    }

                    string parent =
                        NormalizeFullPath(directory.FullName);

                    if (string.Equals(
                        parent,
                        current,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }

                    current = parent;
                }
            }
            catch
            {
                return true;
            }

            return false;
        }

        private static string NormalizeGameRoot(string gameRoot)
        {
            string normalized =
                NormalizeFullPath(gameRoot);

            if (!string.IsNullOrWhiteSpace(normalized))
            {
                return normalized;
            }

            try
            {
                string dataPath =
                    UnityEngine.Application.dataPath;

                DirectoryInfo dataDirectory =
                    new DirectoryInfo(dataPath);

                return dataDirectory.Parent == null
                    ? null
                    : NormalizeFullPath(
                        dataDirectory.Parent.FullName);
            }
            catch
            {
                return null;
            }
        }

        private static string MakeRelativePath(
            string root,
            string path)
        {
            string normalizedRoot =
                NormalizeDirectoryPath(root);

            string normalizedPath =
                NormalizeFullPath(path);

            if (string.IsNullOrWhiteSpace(normalizedRoot) ||
                string.IsNullOrWhiteSpace(normalizedPath) ||
                !PathsWithin(normalizedRoot, normalizedPath))
            {
                return null;
            }

            return normalizedPath.Substring(
                normalizedRoot.Length)
                .TrimStart(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar);
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

        private static DateTime GetLastWriteTimeUtc(string path)
        {
            try { return File.GetLastWriteTimeUtc(path); }
            catch { return default(DateTime); }
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

        private static string NormalizeDirectoryPath(string path)
        {
            return NormalizeFullPath(path);
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

        private static bool ContainsIgnoreCase(
            IEnumerable<string> values,
            string value)
        {
            if (values == null ||
                string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return values.Any(
                x => string.Equals(
                    x,
                    value,
                    StringComparison.OrdinalIgnoreCase));
        }

        private static string SafePath(string value)
        {
            return string.IsNullOrWhiteSpace(value)
                ? "<unknown>"
                : value;
        }

        private static FileScannerResult Fail(
            FileScannerResult result,
            string reason)
        {
            result.Complete = false;
            result.IntegrityFailures.Add(reason);
            return result;
        }
    }
}
