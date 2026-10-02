using System;
using System.Collections.Generic;
using System.IO;

namespace HKMP.Whitelist.Shared
{
    public enum SecurityMode
    {
        Normal,
        Strict,
        Maximum
    }

    public enum FileTrustStatus
    {
        Trusted,
        KnownGood,
        PathMismatch,
        Unknown,
        Forbidden
    }

    public sealed class TrustedManifest
    {
        public int SchemaVersion { get; set; } =
            1;

        public string ManifestId { get; set; }

        public int Version { get; set; }

        public string MinWhitelistVersion { get; set; }

        public DateTime IssuedAtUtc { get; set; }

        public DateTime? ExpiresAtUtc { get; set; }

        public string Signature { get; set; }

        public string SignatureAlgo { get; set; } =
            "ed25519";

        public string SignatureEncoding { get; set; } =
            "base64";

        public string SignatureKeyId { get; set; }

        public string SignaturePublicKey { get; set; }

        public string Canonicalization { get; set; } =
            "json-canonical-v1";

        public string WhitelistSelfSha256 { get; set; }

        public List<ManifestEntry> Entries { get; set; } =
            new List<ManifestEntry>();

        public List<CoreManifestEntry> CoreEntries { get; set; } =
            new List<CoreManifestEntry>();
    }

    public sealed class ManifestEntry
    {
        public string ArtifactId { get; set; }

        public string ModId { get; set; }

        public string PublisherId { get; set; }

        public string DisplayName { get; set; }

        public string AssemblyName { get; set; }

        public string AssemblyFullName { get; set; }

        public string Version { get; set; }

        public string Sha256 { get; set; }

        public List<string> AllowedPaths { get; set; } =
            new List<string>();

        public List<string> Dependencies { get; set; } =
            new List<string>();

        public List<string> HarmonyTargetAllowlist { get; set; } =
            new List<string>();

        public List<string> PolicyFlags { get; set; } =
            new List<string>();

        public bool IsComplete()
        {
            return
                !string.IsNullOrWhiteSpace(ArtifactId) &&
                !string.IsNullOrWhiteSpace(ModId) &&
                !string.IsNullOrWhiteSpace(AssemblyFullName) &&
                !string.IsNullOrWhiteSpace(Version) &&
                !string.IsNullOrWhiteSpace(Sha256) &&
                AllowedPaths != null &&
                AllowedPaths.Count > 0;
        }

        public bool MatchesExact(
            string modId,
            string version,
            string assemblyFullName,
            string sha256,
            string filePath)
        {
            if (!IsComplete())
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(modId) ||
                string.IsNullOrWhiteSpace(version) ||
                string.IsNullOrWhiteSpace(assemblyFullName) ||
                string.IsNullOrWhiteSpace(sha256) ||
                string.IsNullOrWhiteSpace(filePath))
            {
                return false;
            }

            if (!string.Equals(
                ModId,
                modId,
                StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.Equals(
                Version,
                version,
                StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.Equals(
                AssemblyFullName,
                assemblyFullName,
                StringComparison.Ordinal))
            {
                return false;
            }

            if (!string.Equals(
                Sha256,
                sha256,
                StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!MatchesAllowedPath(
                filePath))
            {
                return false;
            }

            return true;
        }

        private bool MatchesAllowedPath(
            string filePath)
        {
            if (AllowedPaths == null ||
                AllowedPaths.Count == 0 ||
                string.IsNullOrWhiteSpace(filePath))
            {
                return false;
            }

            foreach (string allowedPath in AllowedPaths)
            {
                if (string.IsNullOrWhiteSpace(allowedPath))
                {
                    continue;
                }

                if (PathsEqual(
                    allowedPath,
                    filePath))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool PathsEqual(
            string first,
            string second)
        {
            string normalizedFirst =
                NormalizePath(first);

            string normalizedSecond =
                NormalizePath(second);

            return string.Equals(
                normalizedFirst,
                normalizedSecond,
                StringComparison.OrdinalIgnoreCase);
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
                        .Replace(
                            Path.AltDirectorySeparatorChar,
                            Path.DirectorySeparatorChar)
                        .TrimEnd(
                            Path.DirectorySeparatorChar,
                            Path.AltDirectorySeparatorChar);
            }
            catch
            {
                return
                    path
                        .Replace(
                            '\\',
                            '/')
                        .TrimEnd('/');
            }
        }
    }

    public sealed class CoreManifestEntry
    {
        public string CoreId { get; set; }

        public string DisplayName { get; set; }

        public string Version { get; set; }

        public string AssemblyFullName { get; set; }

        public string Sha256 { get; set; }

        public List<string> AllowedPaths { get; set; } =
            new List<string>();

        public List<string> PolicyFlags { get; set; } =
            new List<string>();
    }

    public sealed class PresetConfig
    {
        public string PresetName { get; set; } =
            "Default Deny All";

        public SecurityMode SecurityMode { get; set; } =
            SecurityMode.Maximum;

        public bool UnknownPolicyDeny { get; set; } =
            true;

        public bool RequireCompleteScan { get; set; } =
            true;

        public bool CheckCoreIntegrity { get; set; } =
            true;

        public bool CheckSelfIntegrity { get; set; } =
            true;

        public bool RuntimeMonitoringEnabled { get; set; } =
            true;

        public int RuntimeScanIntervalSeconds { get; set; } =
            30;

        public bool ChallengeEnabled { get; set; } =
            true;

        public int ChallengeTimeoutMs { get; set; } =
            3000;

        public List<string> RequiredMods { get; set; } =
            new List<string>();

        public List<string> AllowedMods { get; set; } =
            new List<string>();

        public List<string> IgnoredMods { get; set; } =
            new List<string>();

        public List<string> ForbiddenMods { get; set; } =
            new List<string>();
    }

    public sealed class FileScanEntry
    {
        public string Path { get; set; }

        public string ModId { get; set; }

        public string ArtifactId { get; set; }

        public string Sha256 { get; set; }

        public string ExpectedSha256 { get; set; }

        public long Size { get; set; }

        public DateTime LastWriteTimeUtc { get; set; }

        public FileTrustStatus Status { get; set; }
    }

    public sealed class AssemblyScanEntry
    {
        public string FullName { get; set; }

        public string Location { get; set; }

        public string ModId { get; set; }

        public string ArtifactId { get; set; }

        public string ManifestVersion { get; set; }

        public string AssemblyVersion { get; set; }

        public string Sha256 { get; set; }

        public string ExpectedSha256 { get; set; }

        public FileTrustStatus Status { get; set; }
    }

    public sealed class NativeModuleScanEntry
    {
        public string Name { get; set; }

        public string Path { get; set; }

        public string ModId { get; set; }

        public string ArtifactId { get; set; }

        public string Sha256 { get; set; }

        public string ExpectedSha256 { get; set; }

        public FileTrustStatus Status { get; set; }
    }

    public sealed class ModArtifactScanEntry
    {
        public string ModId { get; set; }

        public string ArtifactId { get; set; }

        public string Version { get; set; }

        public string AssemblyFullName { get; set; }

        public string Sha256 { get; set; }

        public string Path { get; set; }

        public FileTrustStatus Status { get; set; }
    }

    public sealed class SecurityReport
    {
        public int ProtocolVersion { get; set; } =
            2;

        public string SessionId { get; set; }

        public string ManifestId { get; set; }

        public int ManifestVersion { get; set; }

        public string WhitelistVersion { get; set; }

        public string ScanStatus { get; set; }

        public DateTime ScanTimestampUtc { get; set; }

        public long ScanDurationMs { get; set; }

        public string SelfHash { get; set; }

        public SecurityEvidence Evidence { get; set; }

        public bool DebuggerDetected { get; set; }

        public List<FileScanEntry> UnknownFiles { get; set; } =
            new List<FileScanEntry>();

        public List<FileScanEntry> ForbiddenFiles { get; set; } =
            new List<FileScanEntry>();

        public List<AssemblyScanEntry> UnknownAssemblies { get; set; } =
            new List<AssemblyScanEntry>();

        public List<NativeModuleScanEntry> UnknownNativeModules { get; set; } =
            new List<NativeModuleScanEntry>();

        public List<ModArtifactScanEntry> ModArtifacts { get; set; } =
            new List<ModArtifactScanEntry>();

        public List<string> IntegrityFailures { get; set; } =
            new List<string>();

        public List<string> UnreadableFiles { get; set; } =
            new List<string>();

        public List<string> TrustedModIds { get; set; } =
            new List<string>();

        public List<string> RuntimeEvents { get; set; } =
            new List<string>();
    }

    public sealed class SecurityDecision
    {
        public bool Allowed { get; set; }

        public string Reason { get; set; }

        public string DenyCode { get; set; }

        public string SessionId { get; set; }

        public string ManifestId { get; set; }

        public int ManifestVersion { get; set; }

        public bool RuntimeMonitoringEnabled { get; set; }

        public int RuntimeScanIntervalSeconds { get; set; }

        public bool ChallengeEnabled { get; set; }

        public int ChallengeTimeoutMs { get; set; }
    }
}
