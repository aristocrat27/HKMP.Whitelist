using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using HKMP.Whitelist.Shared;

namespace HKMP.Whitelist.Server
{
    internal static class PolicyEngine
    {
        public static SecurityDecision Evaluate(
            SecurityReport report,
            HostBaseline baseline,
            PresetConfig preset)
        {
            if (report == null)
            {
                return Deny(
                    "INTERNAL_ERROR",
                    "Security report is null.");
            }

            if (baseline == null)
            {
                return Deny(
                    "BASELINE_UNAVAILABLE",
                    "Host security baseline is unavailable.");
            }

            if (preset == null)
            {
                return Deny(
                    "PRESET_UNAVAILABLE",
                    "Whitelist preset is unavailable.");
            }

            SecurityDecision baselineDecision =
                EvaluateHostBaseline(
                    baseline,
                    preset);

            if (!baselineDecision.Allowed)
            {
                return baselineDecision;
            }

            if (preset.RequireCompleteScan &&
                !IsCompleteScan(report))
            {
                return Deny(
                    "SCAN_INCOMPLETE",
                    "Client security scan is incomplete.");
            }

            if (preset.SecurityMode != SecurityMode.Normal &&
                report.DebuggerDetected)
            {
                return Deny(
                    "DEBUGGER_DETECTED",
                    "Debugger detected.");
            }

            if (report.IntegrityFailures != null &&
                report.IntegrityFailures.Count > 0)
            {
                return Deny(
                    "INTEGRITY_FAILURE",
                    string.Join(
                        ", ",
                        report.IntegrityFailures));
            }

            if (report.UnreadableFiles != null &&
                report.UnreadableFiles.Count > 0 &&
                preset.SecurityMode != SecurityMode.Normal)
            {
                return Deny(
                    "UNREADABLE_FILE",
                    string.Join(
                        ", ",
                        report.UnreadableFiles));
            }

            if (report.ForbiddenFiles != null &&
                report.ForbiddenFiles.Count > 0)
            {
                return Deny(
                    "FORBIDDEN_FILE_DETECTED",
                    DescribeFiles(
                        report.ForbiddenFiles));
            }

            if (preset.UnknownPolicyDeny &&
                preset.SecurityMode != SecurityMode.Normal)
            {
                if (report.UnknownFiles != null &&
                    report.UnknownFiles.Count > 0)
                {
                    return Deny(
                        "UNKNOWN_FILE",
                        DescribeFiles(
                            report.UnknownFiles));
                }

                if (report.UnknownAssemblies != null &&
                    report.UnknownAssemblies.Count > 0)
                {
                    return Deny(
                        "UNKNOWN_ASSEMBLY",
                        DescribeAssemblies(
                            report.UnknownAssemblies));
                }

                if (report.UnknownNativeModules != null &&
                    report.UnknownNativeModules.Count > 0)
                {
                    return Deny(
                        "UNKNOWN_NATIVE_MODULE",
                        DescribeNativeModules(
                            report.UnknownNativeModules));
                }
            }

            string[] requiredMods =
                NormalizeList(
                    preset.RequiredMods);

            string[] allowedMods =
                NormalizeList(
                    preset.AllowedMods);

            string[] ignoredMods =
                NormalizeList(
                    preset.IgnoredMods);

            string[] forbiddenMods =
                NormalizeList(
                    preset.ForbiddenMods);

            HashSet<string> baselineModIds =
                GetBaselineModIds(
                    baseline);

            string[] reportedModIds =
                NormalizeList(
                    report.TrustedModIds);

            foreach (string required in requiredMods)
            {
                if (!baselineModIds.Contains(
                        required))
                {
                    return Deny(
                        "REQUIRED_MOD_NOT_PRESENT_ON_HOST",
                        required);
                }

                if (!reportedModIds.Contains(
                        required))
                {
                    return Deny(
                        "REQUIRED_MOD_MISSING",
                        required);
                }
            }

            foreach (string forbidden in forbiddenMods)
            {
                if (baselineModIds.Contains(
                        forbidden))
                {
                    return Deny(
                        "FORBIDDEN_MOD_PRESENT_ON_HOST",
                        forbidden);
                }

                if (reportedModIds.Contains(
                        forbidden))
                {
                    return Deny(
                        "FORBIDDEN_MOD_DETECTED",
                        forbidden);
                }
            }

            foreach (string reportedMod in reportedModIds)
            {
                ModPolicy policy =
                    ModPolicyResolver.Resolve(
                        preset,
                        reportedMod);

                if (policy == ModPolicy.Forbidden)
                {
                    if (ModPolicyResolver.IsExplicitForbidden(
                            preset,
                            reportedMod))
                    {
                        return Deny(
                            "FORBIDDEN_MOD_DETECTED",
                            reportedMod);
                    }

                    return Deny(
                        "MOD_NOT_IN_PRESET",
                        reportedMod);
                }

                if (policy == ModPolicy.Ignored)
                {
                    continue;
                }

                if (!baselineModIds.Contains(
                        reportedMod))
                {
                    return Deny(
                        "MOD_NOT_PRESENT_IN_HOST_BASELINE",
                        reportedMod);
                }
            }

            if (preset.SecurityMode != SecurityMode.Normal)
            {
                SecurityDecision artifactDecision =
                    EnsureExactArtifactEvidence(
                        baseline,
                        report);

                if (!artifactDecision.Allowed)
                {
                    return artifactDecision;
                }
            }

            return Allow(
                "Policy checks passed for the currently available evidence.");
        }

        public static SecurityDecision EvaluateHostBaseline(
            HostBaseline baseline,
            PresetConfig preset)
        {
            if (baseline == null)
            {
                return Deny(
                    "BASELINE_UNAVAILABLE",
                    "Host security baseline is unavailable.");
            }

            if (preset == null)
            {
                return Deny(
                    "PRESET_UNAVAILABLE",
                    "Whitelist preset is unavailable.");
            }

            if (string.IsNullOrWhiteSpace(
                    baseline.BaselineId))
            {
                return Deny(
                    "BASELINE_ID_MISSING",
                    "Host baseline does not contain a baseline ID.");
            }

            if (string.IsNullOrWhiteSpace(
                    baseline.SessionId))
            {
                return Deny(
                    "BASELINE_SESSION_ID_MISSING",
                    "Host baseline does not contain a session ID.");
            }

            if (baseline.IntegrityFailures != null &&
                baseline.IntegrityFailures.Count > 0)
            {
                return Deny(
                    "HOST_INTEGRITY_FAILURE",
                    string.Join(
                        ", ",
                        baseline.IntegrityFailures));
            }

            if (baseline.Artifacts == null)
            {
                return Deny(
                    "BASELINE_ARTIFACTS_MISSING",
                    "Host baseline artifact collection is unavailable.");
            }

            if (baseline.Assemblies == null)
            {
                return Deny(
                    "BASELINE_ASSEMBLIES_MISSING",
                    "Host baseline assembly collection is unavailable.");
            }

            if (baseline.NativeModules == null)
            {
                return Deny(
                    "BASELINE_NATIVE_MODULES_MISSING",
                    "Host baseline native module collection is unavailable.");
            }

            string[] requiredMods =
                NormalizeList(
                    preset.RequiredMods);

            string[] allowedMods =
                NormalizeList(
                    preset.AllowedMods);

            string[] forbiddenMods =
                NormalizeList(
                    preset.ForbiddenMods);

            HashSet<string> baselineModIds =
                GetBaselineModIds(
                    baseline);

            foreach (string forbidden in forbiddenMods)
            {
                if (baselineModIds.Contains(
                        forbidden))
                {
                    return Deny(
                        "FORBIDDEN_MOD_PRESENT_ON_HOST",
                        forbidden);
                }
            }

            foreach (string required in requiredMods)
            {
                if (!baselineModIds.Contains(
                        required))
                {
                    return Deny(
                        "REQUIRED_MOD_NOT_PRESENT_ON_HOST",
                        required);
                }
            }

            if (preset.SecurityMode != SecurityMode.Normal)
            {
                foreach (BaselineArtifact artifact
                         in baseline.Artifacts)
                {
                    if (artifact == null)
                    {
                        return Deny(
                            "BASELINE_ARTIFACT_INVALID",
                            "Host baseline contains a null artifact.");
                    }

                    if (string.IsNullOrWhiteSpace(
                            artifact.FileName))
                    {
                        return Deny(
                            "BASELINE_ARTIFACT_FILENAME_MISSING",
                            "Host baseline contains an artifact without a file name.");
                    }

                    if (string.IsNullOrWhiteSpace(
                            artifact.RelativePath))
                    {
                        return Deny(
                            "BASELINE_ARTIFACT_PATH_MISSING",
                            artifact.FileName);
                    }

                    if (string.IsNullOrWhiteSpace(
                            artifact.Sha256))
                    {
                        return Deny(
                            "BASELINE_ARTIFACT_HASH_MISSING",
                            artifact.RelativePath);
                    }

                    if (!IsNormalizedHash(
                            artifact.Sha256))
                    {
                        return Deny(
                            "BASELINE_ARTIFACT_HASH_INVALID",
                            artifact.RelativePath);
                    }

                    if (!string.IsNullOrWhiteSpace(
                            artifact.ModId) &&
                        forbiddenMods.Contains(
                            artifact.ModId))
                    {
                        return Deny(
                            "FORBIDDEN_MOD_PRESENT_ON_HOST",
                            artifact.ModId);
                    }
                }
            }

            return Allow(
                "Host baseline is valid for the selected preset.");
        }

        private static SecurityDecision EnsureExactArtifactEvidence(
            HostBaseline baseline,
            SecurityReport report)
        {
            if (baseline == null)
            {
                return Deny(
                    "BASELINE_UNAVAILABLE",
                    "Host security baseline is unavailable.");
            }

            if (report == null)
            {
                return Deny(
                    "SECURITY_REPORT_MISSING",
                    "Security report is unavailable.");
            }

            SecurityEvidence evidence =
                report.Evidence;

            if (evidence == null)
            {
                return Deny(
                    "EXACT_ARTIFACT_EVIDENCE_MISSING",
                    "Client did not provide exact artifact evidence.");
            }

            if (!string.Equals(
                    evidence.SessionId,
                    baseline.SessionId,
                    StringComparison.Ordinal))
            {
                return Deny(
                    "EVIDENCE_SESSION_MISMATCH",
                    "Security evidence session ID does not match the host session.");
            }

            if (!string.Equals(
                    evidence.BaselineId,
                    baseline.BaselineId,
                    StringComparison.Ordinal))
            {
                return Deny(
                    "EVIDENCE_BASELINE_MISMATCH",
                    "Security evidence baseline ID does not match the host baseline.");
            }

            if (!string.Equals(
                    evidence.ScanStatus,
                    "Complete",
                    StringComparison.OrdinalIgnoreCase))
            {
                return Deny(
                    "EXACT_ARTIFACT_EVIDENCE_INCOMPLETE",
                    "Client exact artifact evidence is incomplete.");
            }

            if (baseline.Artifacts == null ||
                baseline.Artifacts.Count == 0)
            {
                return Allow(
                    "Host baseline contains no file artifacts requiring exact client tuple comparison.");
            }

            if (evidence.Artifacts == null)
            {
                return Deny(
                    "EXACT_ARTIFACT_EVIDENCE_MISSING",
                    "Client artifact evidence collection is missing.");
            }

            foreach (BaselineArtifact expected in baseline.Artifacts)
            {
                if (expected == null)
                {
                    return Deny(
                        "BASELINE_ARTIFACT_INVALID",
                        "Host baseline contains a null artifact entry.");
                }

                ArtifactEvidence observed =
                    FindArtifactEvidence(
                        evidence.Artifacts,
                        expected);

                if (observed == null)
                {
                    return Deny(
                        "EXACT_ARTIFACT_EVIDENCE_MISSING",
                        DescribeExpectedArtifact(
                            expected));
                }

                if (!observed.Exists ||
                    !observed.IsReadable)
                {
                    return Deny(
                        "ARTIFACT_UNREADABLE",
                        DescribeObservedArtifact(
                            observed));
                }

                if (!string.Equals(
                        expected.FileName,
                        observed.FileName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return Deny(
                        "ARTIFACT_FILENAME_MISMATCH",
                        DescribeObservedArtifact(
                            observed));
                }

                if (!string.Equals(
                        NormalizePath(expected.RelativePath),
                        NormalizePath(observed.RelativePath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    return Deny(
                        "ARTIFACT_PATH_MISMATCH",
                        DescribeObservedArtifact(
                            observed));
                }

                if (expected.FileSize != observed.FileSize)
                {
                    return Deny(
                        "ARTIFACT_SIZE_MISMATCH",
                        DescribeObservedArtifact(
                            observed));
                }

                if (!HashEquals(
                        expected.Sha256,
                        observed.Sha256))
                {
                    return Deny(
                        "ARTIFACT_HASH_MISMATCH",
                        DescribeObservedArtifact(
                            observed));
                }

                if (!StringEqualsExact(
                        expected.AssemblyFullName,
                        observed.AssemblyFullName))
                {
                    return Deny(
                        "ARTIFACT_ASSEMBLY_MISMATCH",
                        DescribeObservedArtifact(
                            observed));
                }

                if (!StringEqualsExact(
                        expected.AssemblyName,
                        observed.AssemblyName))
                {
                    return Deny(
                        "ARTIFACT_ASSEMBLY_NAME_MISMATCH",
                        DescribeObservedArtifact(
                            observed));
                }

                if (!StringEqualsExact(
                        expected.AssemblyVersion,
                        observed.AssemblyVersion))
                {
                    return Deny(
                        "ARTIFACT_VERSION_MISMATCH",
                        DescribeObservedArtifact(
                            observed));
                }

                if (!string.Equals(
                        NormalizeFullPath(expected.AssemblyLocation),
                        NormalizeFullPath(observed.AssemblyLocation),
                        StringComparison.OrdinalIgnoreCase))
                {
                    return Deny(
                        "ARTIFACT_ASSEMBLY_LOCATION_MISMATCH",
                        DescribeObservedArtifact(
                            observed));
                }

                if (expected.IsLoaded != observed.IsLoaded)
                {
                    return Deny(
                        "ARTIFACT_LOADED_STATE_MISMATCH",
                        DescribeObservedArtifact(
                            observed));
                }
            }

            return Allow(
                "Exact host-baseline artifact evidence matched the client observation.");
        }

        private static ArtifactEvidence FindArtifactEvidence(
            IEnumerable<ArtifactEvidence> artifacts,
            BaselineArtifact expected)
        {
            if (artifacts == null ||
                expected == null)
            {
                return null;
            }

            foreach (ArtifactEvidence item in artifacts)
            {
                if (item == null)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(expected.ArtifactId) &&
                    !string.IsNullOrWhiteSpace(item.ArtifactId) &&
                    string.Equals(
                        expected.ArtifactId,
                        item.ArtifactId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return item;
                }

                if (string.Equals(
                        NormalizePath(expected.RelativePath),
                        NormalizePath(item.RelativePath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    return item;
                }
            }

            return null;
        }

        private static bool HashEquals(
            string first,
            string second)
        {
            return
                string.Equals(
                    first,
                    second,
                    StringComparison.OrdinalIgnoreCase);
        }

        private static bool StringEqualsExact(
            string first,
            string second)
        {
            return
                string.Equals(
                    first ?? "",
                    second ?? "",
                    StringComparison.Ordinal);
        }

        private static string NormalizePath(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "";
            }

            string value =
                path.Trim()
                    .Replace(
                        '\\',
                        '/');

            while (value.Contains("//"))
            {
                value =
                    value.Replace(
                        "//",
                        "/");
            }

            while (value.StartsWith(
                       "./",
                       StringComparison.Ordinal))
            {
                value =
                    value.Substring(2);
            }

            return value.TrimStart('/');
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

        private static string DescribeExpectedArtifact(
            BaselineArtifact artifact)
        {
            if (artifact == null)
            {
                return "<null artifact>";
            }

            return
                (artifact.RelativePath ?? artifact.FileName ?? "<unknown>") +
                " | " +
                (artifact.Sha256 ?? "<no hash>");
        }

        private static string DescribeObservedArtifact(
            ArtifactEvidence artifact)
        {
            if (artifact == null)
            {
                return "<null evidence>";
            }

            return
                (artifact.RelativePath ?? artifact.FileName ?? "<unknown>") +
                " | " +
                (artifact.Sha256 ?? "<no hash>");
        }

        private static HashSet<string> GetBaselineModIds(
            HostBaseline baseline)
        {
            HashSet<string> result =
                new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

            if (baseline == null)
            {
                return result;
            }

            if (baseline.Artifacts != null)
            {
                foreach (BaselineArtifact artifact
                         in baseline.Artifacts)
                {
                    if (artifact == null ||
                        string.IsNullOrWhiteSpace(
                            artifact.ModId))
                    {
                        continue;
                    }

                    result.Add(
                        artifact.ModId.Trim());
                }
            }

            if (baseline.Assemblies != null)
            {
                foreach (BaselineAssembly assembly
                         in baseline.Assemblies)
                {
                    if (assembly == null ||
                        !assembly.IsModAssembly ||
                        string.IsNullOrWhiteSpace(
                            assembly.ModId))
                    {
                        continue;
                    }

                    result.Add(
                        assembly.ModId.Trim());
                }
            }

            return result;
        }

        private static string[] NormalizeList(
            IEnumerable<string> values)
        {
            if (values == null)
            {
                return new string[0];
            }

            return values
                .Where(
                    value =>
                        !string.IsNullOrWhiteSpace(
                            value))
                .Select(
                    value =>
                        value.Trim())
                .Distinct(
                    StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private static bool IsCompleteScan(
            SecurityReport report)
        {
            if (report == null)
            {
                return false;
            }

            return string.Equals(
                report.ScanStatus,
                "Complete",
                StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsNormalizedHash(
            string hash)
        {
            if (string.IsNullOrWhiteSpace(hash))
            {
                return false;
            }

            string value =
                hash.Trim();

            if (value.Length != 64)
            {
                return false;
            }

            for (int i = 0;
                 i < value.Length;
                 i++)
            {
                char c =
                    value[i];

                bool valid =
                    (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F');

                if (!valid)
                {
                    return false;
                }
            }

            return true;
        }

        private static string DescribeFiles(
            IEnumerable<FileScanEntry> files)
        {
            if (files == null)
            {
                return string.Empty;
            }

            return string.Join(
                "; ",
                files
                    .Where(
                        file =>
                            file != null)
                    .Select(
                        file =>
                            (file.Path ?? "<unknown>") +
                            " SHA256=" +
                            (file.Sha256 ?? "<unknown>")));
        }

        private static string DescribeAssemblies(
            IEnumerable<AssemblyScanEntry> assemblies)
        {
            if (assemblies == null)
            {
                return string.Empty;
            }

            return string.Join(
                "; ",
                assemblies
                    .Where(
                        assembly =>
                            assembly != null)
                    .Select(
                        assembly =>
                            (assembly.FullName ?? "<unknown>") +
                            " Path=" +
                            (assembly.Location ?? "<unknown>") +
                            " SHA256=" +
                            (assembly.Sha256 ?? "<unknown>")));
        }

        private static string DescribeNativeModules(
            IEnumerable<NativeModuleScanEntry> modules)
        {
            if (modules == null)
            {
                return string.Empty;
            }

            return string.Join(
                "; ",
                modules
                    .Where(
                        module =>
                            module != null)
                    .Select(
                        module =>
                            (module.Name ?? "<unknown>") +
                            " Path=" +
                            (module.Path ?? "<unknown>") +
                            " SHA256=" +
                            (module.Sha256 ?? "<unknown>")));
        }

        private static SecurityDecision Allow(
            string reason)
        {
            return new SecurityDecision
            {
                Allowed = true,
                Reason = reason,
                DenyCode = null
            };
        }

        private static SecurityDecision Deny(
            string code,
            string reason)
        {
            return new SecurityDecision
            {
                Allowed = false,
                Reason = reason,
                DenyCode = code
            };
        }

        public static SecurityDecision Evaluate(
            SecurityReport report,
            TrustedManifest manifest,
            PresetConfig preset)
        {
            return Deny(
                "LEGACY_POLICY_PATH_UNSUPPORTED",
                "The static TrustedManifest policy path has been retired. Server policy must use HostBaseline.");
        }
    }
}
