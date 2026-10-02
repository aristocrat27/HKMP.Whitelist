using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using HKMP.Whitelist.Security;
using HKMP.Whitelist.Shared;
using Modding;
using UnityEngine;

namespace HKMP.Whitelist.Core
{
    public sealed class HostBaselineBuildResult
    {
        private readonly List<string> _failures =
            new List<string>();

        private readonly List<string> _warnings =
            new List<string>();

        public bool Success { get; internal set; }

        public bool Complete { get; internal set; }

        public HostBaseline Baseline { get; internal set; }

        public long DurationMs { get; internal set; }

        public IReadOnlyList<string> Failures
        {
            get { return _failures.AsReadOnly(); }
        }

        public IReadOnlyList<string> Warnings
        {
            get { return _warnings.AsReadOnly(); }
        }

        public HostReadinessResult Readiness { get; internal set; }

        internal void AddFailure(string message)
        {
            if (!string.IsNullOrWhiteSpace(message))
            {
                _failures.Add(message);
            }
        }

        internal void AddWarning(string message)
        {
            if (!string.IsNullOrWhiteSpace(message))
            {
                _warnings.Add(message);
            }
        }
    }

    public sealed class HostBaselineBuilder
    {
        private const int StableHashAttempts = 3;

        private string _gameRoot;

        public HostBaselineBuilder(string gameRoot = null)
        {
            string resolvedRoot;
            string ignoredReason;

            if (GamePathResolver.TryResolve(
                    gameRoot,
                    out resolvedRoot,
                    out ignoredReason))
            {
                _gameRoot = resolvedRoot;
            }
            else
            {
                _gameRoot =
                    string.IsNullOrWhiteSpace(gameRoot)
                        ? null
                        : NormalizeFullPath(gameRoot);
            }
        }

        public string GameRoot
        {
            get { return _gameRoot; }
        }

        internal void UpdateGameRoot(
            string gameRoot)
        {
            if (string.IsNullOrWhiteSpace(gameRoot))
            {
                return;
            }

            _gameRoot =
                NormalizeFullPath(
                    gameRoot);
        }

        public HostBaselineBuildResult Build(
            string sessionId,
            PresetConfig preset,
            bool includeDisabledMods)
        {
            Stopwatch stopwatch =
                Stopwatch.StartNew();

            HostBaselineBuildResult result =
                new HostBaselineBuildResult();

            HostReadinessResult readiness =
                GamePathResolver.GetHostReadiness(
                    _gameRoot);

            result.Readiness =
                readiness;

            if (readiness == null)
            {
                result.AddFailure(
                    "HOST_READINESS_RESULT_UNAVAILABLE");
            }
            else
            {
                if (!readiness.IsReady)
                {
                    result.AddFailure(
                        (readiness.FailureCode ??
                         "HOST_READINESS_FAILED") +
                        ":" +
                        (readiness.FailureDetails ??
                         "Host execution context is not ready."));
                }

                if (!string.IsNullOrWhiteSpace(
                    readiness.GameRoot))
                {
                    _gameRoot =
                        readiness.GameRoot;
                }
            }

            if (string.IsNullOrWhiteSpace(sessionId))
            {
                result.AddFailure("SESSION_ID_MISSING");
            }

            if (string.IsNullOrWhiteSpace(_gameRoot) ||
                !Directory.Exists(_gameRoot))
            {
                string resolvedRoot;
                string reason;

                if (GamePathResolver.TryResolve(
                        _gameRoot,
                        out resolvedRoot,
                        out reason))
                {
                    _gameRoot = resolvedRoot;
                }
                else
                {
                    result.AddFailure(
                        "GAME_ROOT_UNAVAILABLE:" +
                        (reason ?? "Hollow Knight game root could not be resolved."));
                }
            }

            if (!string.IsNullOrWhiteSpace(_gameRoot) &&
                Directory.Exists(_gameRoot))
            {
                string managedDirectory =
                    Path.Combine(
                        _gameRoot,
                        "hollow_knight_Data",
                        "Managed");

                if (!Directory.Exists(managedDirectory))
                {
                    result.AddFailure(
                        "MANAGED_DIRECTORY_UNAVAILABLE:" +
                        SafeDisplayPath(managedDirectory));
                }
            }

            if (preset == null)
            {
                result.AddFailure("PRESET_UNAVAILABLE");
            }

            if (result.Failures.Count > 0)
            {
                stopwatch.Stop();
                result.DurationMs = stopwatch.ElapsedMilliseconds;
                result.Complete = false;
                result.Success = false;
                return result;
            }

            HostBaseline baseline =
                new HostBaseline
                {
                    BaselineId = Guid.NewGuid().ToString("N"),
                    SessionId = sessionId.Trim(),
                    CreatedAtUtc = DateTime.UtcNow,
                    GameVersion = GetGameVersion(),
                    HKMPVersion = GetHKMPVersion(),
                    WhitelistVersion = GetWhitelistVersion(),
                    PresetName = preset.PresetName,
                    PresetVersion = null,
                    PresetHash = ComputePresetHash(preset),
                    BaselineDigest = null
                };

            int assemblyFailuresBefore =
                result.Failures.Count;

            int assemblyCountBefore =
                baseline.Assemblies.Count;

            ScanLoadedAssemblies(
                baseline,
                preset,
                result);

            baseline.AddProviderSummary(
                new BaselineProviderSummary
                {
                    ProviderName =
                        "LoadedAssembly",
                    Status =
                        result.Failures.Count ==
                        assemblyFailuresBefore
                            ? "Complete"
                            : "Failed",
                    Complete =
                        result.Failures.Count ==
                        assemblyFailuresBefore,
                    FindingCount =
                        baseline.Assemblies.Count -
                        assemblyCountBefore,
                    FailureCount =
                        result.Failures.Count -
                        assemblyFailuresBefore,
                    CompletedAtUtc =
                        DateTime.UtcNow
                });

            int fileFailuresBefore =
                result.Failures.Count;

            int artifactCountBefore =
                baseline.Artifacts.Count;

            ScanInstalledModFiles(
                baseline,
                preset,
                result,
                includeDisabledMods);

            baseline.AddProviderSummary(
                new BaselineProviderSummary
                {
                    ProviderName =
                        "Filesystem",
                    Status =
                        result.Failures.Count ==
                        fileFailuresBefore
                            ? "Complete"
                            : "Failed",
                    Complete =
                        result.Failures.Count ==
                        fileFailuresBefore,
                    FindingCount =
                        baseline.Artifacts.Count -
                        artifactCountBefore,
                    FailureCount =
                        result.Failures.Count -
                        fileFailuresBefore,
                    CompletedAtUtc =
                        DateTime.UtcNow
                });

            int nativeFailuresBefore =
                result.Failures.Count;

            int nativeCountBefore =
                baseline.NativeModules.Count;

            ScanNativeModules(
                baseline,
                result);

            int nativeFindings =
                baseline.NativeModules.Count -
                nativeCountBefore;

            if (result.Readiness != null)
            {
                result.Readiness.SecurityRelevantNativeModuleCount =
                    baseline.NativeModules
                        .Count(
                            module =>
                                module != null &&
                                module.IsSecurityRelevant);
            }

            baseline.AddProviderSummary(
                new BaselineProviderSummary
                {
                    ProviderName =
                        "NativeModule",
                    Status =
                        result.Failures.Count ==
                        nativeFailuresBefore
                            ? "Complete"
                            : "Failed",
                    Complete =
                        result.Failures.Count ==
                        nativeFailuresBefore,
                    FindingCount =
                        nativeFindings,
                    FailureCount =
                        result.Failures.Count -
                        nativeFailuresBefore,
                    CompletedAtUtc =
                        DateTime.UtcNow
                });

            ScanCoreIntegrity(
                baseline,
                preset,
                result);

            ScanSelfIntegrity(
                baseline,
                preset,
                result);

            ScanHarmony(
                baseline,
                preset,
                result);

            ValidateProviderCompleteness(
                baseline,
                preset,
                result);

            if (result.Readiness != null)
            {
                result.Readiness.SetProviderStatusSummary(
                    baseline.Providers);

                if (result.Failures.Count > 0)
                {
                    result.Readiness.SetFailure(
                        "HOST_BASELINE_INCOMPLETE",
                        result.Failures[0]);
                }

                if (result.Warnings.Count > 0)
                {
                    foreach (string warning in result.Warnings)
                    {
                        result.Readiness.AddWarning(warning);
                    }
                }
                result.Readiness.LoadedAssemblyCount =
                    baseline.Assemblies.Count;

                result.Readiness.InstalledArtifactCount =
                    baseline.Artifacts.Count;

                result.Readiness.InitialScanStarted =
                    true;

                result.Readiness.InitialScanCompleted =
                    true;
            }

            if (result.Failures.Count > 0)
            {
                foreach (string failure in result.Failures)
                {
                    baseline.AddIntegrityFailure(
                        failure);
                }
            }

            baseline.BaselineDigest =
                ComputeBaselineDigest(baseline);

            result.Baseline = baseline;

            stopwatch.Stop();
            result.DurationMs = stopwatch.ElapsedMilliseconds;
            result.Complete =
                result.Failures.Count == 0;
            result.Success =
                result.Complete;

            if (result.Readiness != null)
            {
                result.Readiness.ScanDurationMs =
                    result.DurationMs;

                result.Readiness.BaselineCreated =
                    baseline != null;

                result.Readiness.BaselineComplete =
                    result.Complete;

                result.Readiness.BaselineValid =
                    result.Success &&
                    baseline != null &&
                    baseline.IntegrityFailures != null &&
                    baseline.IntegrityFailures.Count == 0;
            }

            return result;
        }

        private void ScanCoreIntegrity(
            HostBaseline baseline,
            PresetConfig preset,
            HostBaselineBuildResult result)
        {
            if (baseline == null ||
                result == null)
            {
                return;
            }

            DateTime completedAt =
                DateTime.UtcNow;

            if (preset != null &&
                !preset.CheckCoreIntegrity)
            {
                baseline.AddProviderSummary(
                    new BaselineProviderSummary
                    {
                        ProviderName = "CoreIntegrity",
                        Status = "Disabled",
                        Complete = true,
                        FindingCount = 0,
                        FailureCount = 0,
                        CompletedAtUtc = completedAt
                    });
                return;
            }

            int failuresBefore =
                result.Failures.Count;

            int findings = 0;

            string managedRoot =
                string.IsNullOrWhiteSpace(_gameRoot)
                    ? null
                    : NormalizeFullPath(
                        Path.Combine(
                            _gameRoot,
                            "hollow_knight_Data",
                            "Managed"));

            VerifyCoreAssembly(
                "Assembly-CSharp",
                managedRoot,
                baseline,
                preset,
                result,
                ref findings,
                true);

            VerifyCoreAssembly(
                "HKMP",
                _gameRoot,
                baseline,
                preset,
                result,
                ref findings,
                true);

            VerifyCoreAssembly(
                "HKMP.Whitelist",
                _gameRoot,
                baseline,
                preset,
                result,
                ref findings,
                true);

            int failureCount =
                result.Failures.Count -
                failuresBefore;

            baseline.AddProviderSummary(
                new BaselineProviderSummary
                {
                    ProviderName = "CoreIntegrity",
                    Status = failureCount == 0
                        ? "Complete"
                        : "Failed",
                    Complete = failureCount == 0,
                    FindingCount = findings,
                    FailureCount = failureCount,
                    CompletedAtUtc = DateTime.UtcNow
                });
        }

        private void VerifyCoreAssembly(
            string simpleName,
            string expectedRoot,
            HostBaseline baseline,
            PresetConfig preset,
            HostBaselineBuildResult result,
            ref int findings,
            bool requireLoaded)
        {
            if (string.IsNullOrWhiteSpace(simpleName) ||
                result == null)
            {
                return;
            }

            BaselineAssembly assembly =
                baseline == null ||
                baseline.Assemblies == null
                    ? null
                    : baseline.Assemblies.FirstOrDefault(
                        x => x != null &&
                             string.Equals(
                                 x.Name,
                                 simpleName,
                                 StringComparison.OrdinalIgnoreCase));

            if (assembly == null)
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_MISSING:" +
                    simpleName);
                return;
            }

            findings++;

            if (requireLoaded &&
                !assembly.IsLoaded)
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_NOT_LOADED:" +
                    simpleName);
            }

            string location =
                NormalizeFullPath(
                    assembly.Location);

            if (string.IsNullOrWhiteSpace(location))
            {
                location =
                    ResolveCriticalAssemblyLocation(
                        simpleName,
                        null);
            }

            if (string.IsNullOrWhiteSpace(location) ||
                !File.Exists(location))
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_FILE_MISSING:" +
                    simpleName);
                return;
            }

            if (!string.IsNullOrWhiteSpace(expectedRoot) &&
                !IsPathWithin(
                    expectedRoot,
                    location))
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_PATH_INVALID:" +
                    simpleName);
                return;
            }

            AssemblyName loadedName =
                FindLoadedAssemblyName(
                    simpleName);

            AssemblyName fileName;

            try
            {
                fileName =
                    AssemblyName.GetAssemblyName(
                        location);
            }
            catch (Exception ex)
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_METADATA_UNAVAILABLE:" +
                    simpleName +
                    ":" +
                    ex.GetType().Name);
                return;
            }

            if (fileName == null ||
                !string.Equals(
                    fileName.Name,
                    simpleName,
                    StringComparison.OrdinalIgnoreCase))
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_FILE_IDENTITY_MISMATCH:" +
                    simpleName);
                return;
            }

            if (loadedName != null &&
                !string.Equals(
                    loadedName.Name,
                    fileName.Name,
                    StringComparison.OrdinalIgnoreCase))
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_IDENTITY_MISMATCH:" +
                    simpleName);
            }

            if (loadedName != null &&
                loadedName.Version != null &&
                fileName.Version != null &&
                loadedName.Version != fileName.Version)
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_VERSION_MISMATCH:" +
                    simpleName);
            }

            if (!string.IsNullOrWhiteSpace(
                    assembly.FullName) &&
                !string.Equals(
                    assembly.FullName,
                    fileName.FullName,
                    StringComparison.Ordinal))
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_FULL_NAME_MISMATCH:" +
                    simpleName);
            }

            string hash;
            string hashFailure;

            if (!TryComputeStableHash(
                    location,
                    out hash,
                    out hashFailure))
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_HASH_UNAVAILABLE:" +
                    simpleName +
                    ":" +
                    hashFailure);
                return;
            }

            assembly.Location =
                location;

            assembly.RelativePath =
                TryGetRelativeGamePath(
                    location);

            assembly.Sha256 =
                hash;

            assembly.HasPhysicalLocation =
                true;

            assembly.ArtifactId =
                ComputeArtifactId(
                    assembly.ModId,
                    assembly.Name,
                    assembly.FullName,
                    assembly.RelativePath,
                    hash);

            UpsertCoreArtifact(
                baseline,
                assembly,
                preset);

            if (!IsNormalizedHash(
                    assembly.Sha256))
            {
                result.AddFailure(
                    "CORE_ASSEMBLY_HASH_INVALID:" +
                    simpleName);
            }
        }

        private string ResolveCriticalAssemblyLocation(
            string simpleName,
            string currentLocation)
        {
            string normalizedCurrent =
                NormalizeFullPath(currentLocation);

            if (!string.IsNullOrWhiteSpace(
                    normalizedCurrent))
            {
                return normalizedCurrent;
            }

            if (string.Equals(
                    simpleName,
                    "Assembly-CSharp",
                    StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(_gameRoot))
                {
                    return null;
                }

                return NormalizeFullPath(
                    Path.Combine(
                        _gameRoot,
                        "hollow_knight_Data",
                        "Managed",
                        "Assembly-CSharp.dll"));
            }

            if (string.Equals(
                    simpleName,
                    "HKMP.Whitelist",
                    StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    return NormalizeFullPath(
                        typeof(HostBaselineBuilder)
                            .Assembly
                            .Location);
                }
                catch
                {
                    return null;
                }
            }

            Assembly loaded =
                FindLoadedAssembly(
                    simpleName);

            if (loaded != null)
            {
                string loadedLocation =
                    NormalizeFullPath(
                        SafeAssemblyLocation(
                            loaded));

                if (!string.IsNullOrWhiteSpace(
                        loadedLocation))
                {
                    return loadedLocation;
                }
            }

            if (string.Equals(
                    simpleName,
                    "HKMP",
                    StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(_gameRoot))
            {
                string managedRoot =
                    NormalizeFullPath(
                        Path.Combine(
                            _gameRoot,
                            "hollow_knight_Data",
                            "Managed"));

                string found =
                    FindFileByName(
                        managedRoot,
                        "HKMP.dll");

                if (!string.IsNullOrWhiteSpace(found))
                {
                    return found;
                }
            }

            return null;
        }

        private static Assembly FindLoadedAssembly(
            string simpleName)
        {
            if (string.IsNullOrWhiteSpace(
                    simpleName))
            {
                return null;
            }

            try
            {
                return
                    AppDomain.CurrentDomain
                        .GetAssemblies()
                        .Where(
                            x =>
                                x != null)
                        .FirstOrDefault(
                            x =>
                            {
                                try
                                {
                                    AssemblyName name =
                                        x.GetName();

                                    return
                                        name != null &&
                                        string.Equals(
                                            name.Name,
                                            simpleName,
                                            StringComparison.OrdinalIgnoreCase);
                                }
                                catch
                                {
                                    return false;
                                }
                            });
            }
            catch
            {
                return null;
            }
        }

        private static AssemblyName FindLoadedAssemblyName(
            string simpleName)
        {
            Assembly assembly =
                FindLoadedAssembly(
                    simpleName);

            return
                assembly == null
                    ? null
                    : SafeAssemblyName(
                        assembly);
        }

        private string FindFileByName(
            string directory,
            string fileName)
        {
            if (string.IsNullOrWhiteSpace(directory) ||
                string.IsNullOrWhiteSpace(fileName) ||
                !Directory.Exists(directory))
            {
                return null;
            }

            try
            {
                string direct =
                    Path.Combine(
                        directory,
                        fileName);

                if (File.Exists(direct))
                {
                    return NormalizeFullPath(direct);
                }

                string[] files =
                    Directory.GetFiles(
                        directory,
                        fileName,
                        SearchOption.AllDirectories);

                return
                    files == null || files.Length == 0
                        ? null
                        : NormalizeFullPath(
                            files
                                .OrderBy(
                                    x => x,
                                    StringComparer.OrdinalIgnoreCase)
                                .First());
            }
            catch
            {
                return null;
            }
        }

        private void UpsertCoreArtifact(
            HostBaseline baseline,
            BaselineAssembly assembly,
            PresetConfig preset)
        {
            if (baseline == null ||
                assembly == null ||
                string.IsNullOrWhiteSpace(
                    assembly.Location) ||
                string.IsNullOrWhiteSpace(
                    assembly.Sha256))
            {
                return;
            }

            BaselineArtifact artifact =
                baseline.Artifacts
                    .FirstOrDefault(
                        x =>
                            x != null &&
                            string.Equals(
                                NormalizeFullPath(
                                    x.AssemblyLocation),
                                NormalizeFullPath(
                                    assembly.Location),
                                StringComparison.OrdinalIgnoreCase));

            if (artifact == null)
            {
                artifact =
                    baseline.Artifacts
                        .FirstOrDefault(
                            x =>
                                x != null &&
                                string.Equals(
                                    NormalizePath(
                                        x.RelativePath),
                                    NormalizePath(
                                        assembly.RelativePath),
                                    StringComparison.OrdinalIgnoreCase));
            }

            if (artifact == null)
            {
                artifact =
                    new BaselineArtifact();

                baseline.AddArtifact(
                    artifact);
            }

            artifact.ModId =
                assembly.ModId;

            artifact.ArtifactId =
                assembly.ArtifactId;

            artifact.FileName =
                Path.GetFileName(
                    assembly.Location);

            artifact.RelativePath =
                assembly.RelativePath;

            artifact.FileSize =
                GetFileSize(
                    assembly.Location);

            artifact.Sha256 =
                assembly.Sha256;

            artifact.AssemblyFullName =
                assembly.FullName;

            artifact.AssemblyName =
                assembly.Name;

            artifact.AssemblyVersion =
                assembly.Version;

            artifact.AssemblyLocation =
                assembly.Location;

            artifact.IsLoaded =
                assembly.IsLoaded;

            artifact.Dependencies =
                GetDependencies(
                    FindLoadedAssembly(
                        assembly.Name));

            artifact.PolicyFlags =
                BuildPolicyFlags(
                    preset,
                    assembly.ModId,
                    assembly.Name);
        }

        private static void ScanSelfIntegrity(
            HostBaseline baseline,
            PresetConfig preset,
            HostBaselineBuildResult result)
        {
            if (baseline == null ||
                result == null)
            {
                return;
            }

            if (preset != null &&
                !preset.CheckSelfIntegrity)
            {
                baseline.AddProviderSummary(
                    new BaselineProviderSummary
                    {
                        ProviderName = "SelfIntegrity",
                        Status = "Disabled",
                        Complete = true,
                        FindingCount = 0,
                        FailureCount = 0,
                        CompletedAtUtc = DateTime.UtcNow
                    });
                return;
            }

            int failuresBefore =
                result.Failures.Count;

            string selfPath =
                AntiTamperGuard.GetExecutingAssemblyPath();

            if (string.IsNullOrWhiteSpace(selfPath))
            {
                result.AddFailure(
                    "WHITELIST_SELF_PATH_UNAVAILABLE");
            }
            else
            {
                string normalizedPath =
                    NormalizeFullPath(selfPath);

                if (string.IsNullOrWhiteSpace(normalizedPath) ||
                    !File.Exists(normalizedPath))
                {
                    result.AddFailure(
                        "WHITELIST_SELF_FILE_UNAVAILABLE:" +
                        SafeDisplayPath(selfPath));
                }
                else
                {
                    string hash = null;

                    try
                    {
                        hash =
                            AntiTamperGuard.ComputeSelfHash();
                    }
                    catch (Exception ex)
                    {
                        result.AddFailure(
                            "WHITELIST_SELF_HASH_EXCEPTION:" +
                            ex.GetType().Name);
                    }

                    if (string.IsNullOrWhiteSpace(hash) ||
                        !IsNormalizedHash(hash))
                    {
                        result.AddFailure(
                            "WHITELIST_SELF_HASH_UNAVAILABLE");
                    }

                    BaselineAssembly selfAssembly =
                        baseline.Assemblies.FirstOrDefault(
                            x => x != null &&
                                 string.Equals(
                                     x.Name,
                                     "HKMP.Whitelist",
                                     StringComparison.OrdinalIgnoreCase));

                    if (selfAssembly == null)
                    {
                        result.AddFailure(
                            "WHITELIST_SELF_ASSEMBLY_MISSING");
                    }
                    else
                    {
                        if (!string.Equals(
                                normalizedPath,
                                NormalizeFullPath(selfAssembly.Location),
                                StringComparison.OrdinalIgnoreCase))
                        {
                            result.AddFailure(
                                "WHITELIST_SELF_PATH_MISMATCH");
                        }
                    }
                }
            }

            int failureCount =
                result.Failures.Count -
                failuresBefore;

            baseline.AddProviderSummary(
                new BaselineProviderSummary
                {
                    ProviderName = "SelfIntegrity",
                    Status = failureCount == 0
                        ? "Complete"
                        : "Failed",
                    Complete = failureCount == 0,
                    FindingCount = 1,
                    FailureCount = failureCount,
                    CompletedAtUtc = DateTime.UtcNow
                });
        }

        private static void ScanHarmony(
            HostBaseline baseline,
            PresetConfig preset,
            HostBaselineBuildResult result)
        {
            if (baseline == null ||
                result == null)
            {
                return;
            }

            if (preset != null &&
                preset.SecurityMode == SecurityMode.Normal)
            {
                baseline.AddProviderSummary(
                    new BaselineProviderSummary
                    {
                        ProviderName = "Harmony",
                        Status = "Disabled",
                        Complete = true,
                        FindingCount = 0,
                        FailureCount = 0,
                        CompletedAtUtc = DateTime.UtcNow
                    });
                return;
            }

            int failuresBefore =
                result.Failures.Count;

            Type harmonyType =
                FindLoadedType(
                    "HarmonyLib.Harmony");

            if (harmonyType == null)
            {
                baseline.AddProviderSummary(
                    new BaselineProviderSummary
                    {
                        ProviderName = "Harmony",
                        Status = "NotPresent",
                        Complete = true,
                        FindingCount = 0,
                        FailureCount = 0,
                        CompletedAtUtc = DateTime.UtcNow
                    });
                return;
            }

            MethodInfo getAllPatchedMethods =
                harmonyType.GetMethod(
                    "GetAllPatchedMethods",
                    BindingFlags.Public |
                    BindingFlags.Static);

            MethodInfo getPatchInfo =
                harmonyType.GetMethod(
                    "GetPatchInfo",
                    BindingFlags.Public |
                    BindingFlags.Static);

            if (getAllPatchedMethods == null ||
                getPatchInfo == null)
            {
                result.AddFailure(
                    "HARMONY_API_UNAVAILABLE");

                baseline.AddProviderSummary(
                    new BaselineProviderSummary
                    {
                        ProviderName = "Harmony",
                        Status = "Failed",
                        Complete = false,
                        FindingCount = 0,
                        FailureCount = 1,
                        CompletedAtUtc = DateTime.UtcNow
                    });
                return;
            }

            int patchCount = 0;

            try
            {
                IEnumerable methods =
                    getAllPatchedMethods.Invoke(
                        null,
                        null) as IEnumerable;

                if (methods != null)
                {
                    foreach (object method in methods)
                    {
                        MethodBase target =
                            method as MethodBase;

                        if (target == null)
                        {
                            result.AddFailure(
                                "HARMONY_INVALID_TARGET");
                            continue;
                        }

                        object patchInfo =
                            getPatchInfo.Invoke(
                                null,
                                new object[] { target });

                        if (patchInfo == null)
                        {
                            continue;
                        }

                        patchCount +=
                            CountHarmonyCollection(
                                patchInfo,
                                "Prefixes");
                        patchCount +=
                            CountHarmonyCollection(
                                patchInfo,
                                "Postfixes");
                        patchCount +=
                            CountHarmonyCollection(
                                patchInfo,
                                "Transpilers");
                        patchCount +=
                            CountHarmonyCollection(
                                patchInfo,
                                "Finalizers");
                    }
                }
            }
            catch (Exception ex)
            {
                result.AddFailure(
                    "HARMONY_ENUMERATION_FAILED:" +
                    ex.GetType().Name);
            }

            int failureCount =
                result.Failures.Count -
                failuresBefore;

            baseline.AddProviderSummary(
                new BaselineProviderSummary
                {
                    ProviderName = "Harmony",
                    Status = failureCount == 0
                        ? "Complete"
                        : "Failed",
                    Complete = failureCount == 0,
                    FindingCount = patchCount,
                    FailureCount = failureCount,
                    CompletedAtUtc = DateTime.UtcNow
                });
        }

        private static int CountHarmonyCollection(
            object patchInfo,
            string propertyName)
        {
            if (patchInfo == null ||
                string.IsNullOrWhiteSpace(propertyName))
            {
                return 0;
            }

            object value =
                GetPropertyOrField(
                    patchInfo,
                    propertyName);

            if (value == null ||
                value is string)
            {
                return 0;
            }

            IEnumerable enumerable =
                value as IEnumerable;

            if (enumerable == null)
            {
                return 0;
            }

            int count = 0;

            foreach (object unused in enumerable)
            {
                count++;
            }

            return count;
        }

        private static object GetPropertyOrField(
            object instance,
            string name)
        {
            if (instance == null ||
                string.IsNullOrWhiteSpace(name))
            {
                return null;
            }

            Type type =
                instance.GetType();

            try
            {
                PropertyInfo property =
                    type.GetProperty(
                        name,
                        BindingFlags.Public |
                        BindingFlags.NonPublic |
                        BindingFlags.Instance |
                        BindingFlags.Static);

                if (property != null)
                {
                    return property.GetValue(
                        instance,
                        null);
                }
            }
            catch
            {
            }

            try
            {
                FieldInfo field =
                    type.GetField(
                        name,
                        BindingFlags.Public |
                        BindingFlags.NonPublic |
                        BindingFlags.Instance |
                        BindingFlags.Static);

                if (field != null)
                {
                    return field.GetValue(
                        instance);
                }
            }
            catch
            {
            }

            return null;
        }

        private static Type FindLoadedType(
            string fullName)
        {
            if (string.IsNullOrWhiteSpace(fullName))
            {
                return null;
            }

            try
            {
                Type direct =
                    Type.GetType(
                        fullName + ", 0Harmony",
                        false);

                if (direct != null)
                {
                    return direct;
                }
            }
            catch
            {
            }

            Assembly[] assemblies;

            try
            {
                assemblies =
                    AppDomain.CurrentDomain.GetAssemblies();
            }
            catch
            {
                return null;
            }

            foreach (Assembly assembly in assemblies)
            {
                if (assembly == null)
                {
                    continue;
                }

                try
                {
                    Type type =
                        assembly.GetType(
                            fullName,
                            false);

                    if (type != null)
                    {
                        return type;
                    }
                }
                catch
                {
                }
            }

            return null;
        }

        private static void ValidateProviderCompleteness(
            HostBaseline baseline,
            PresetConfig preset,
            HostBaselineBuildResult result)
        {
            if (baseline == null ||
                result == null)
            {
                return;
            }

            List<string> requiredProviders =
                new List<string>
                {
                    "LoadedAssembly",
                    "LoadedModDiscovery",
                    "Filesystem",
                    "NativeModule"
                };

            if (preset == null ||
                preset.CheckCoreIntegrity)
            {
                requiredProviders.Add(
                    "CoreIntegrity");
            }

            if (preset == null ||
                preset.CheckSelfIntegrity)
            {
                requiredProviders.Add(
                    "SelfIntegrity");
            }

            if (preset == null ||
                preset.SecurityMode != SecurityMode.Normal)
            {
                requiredProviders.Add(
                    "Harmony");
            }

            foreach (string providerName in requiredProviders)
            {
                BaselineProviderSummary summary =
                    baseline.Providers.FirstOrDefault(
                        x =>
                            x != null &&
                            string.Equals(
                                x.ProviderName,
                                providerName,
                                StringComparison.OrdinalIgnoreCase));

                if (summary == null)
                {
                    result.AddFailure(
                        "PROVIDER_RESULT_MISSING:" +
                        providerName);
                    continue;
                }

                if (!summary.Complete)
                {
                    result.AddFailure(
                        "PROVIDER_INCOMPLETE:" +
                        providerName);
                }
            }
        }

        private void ScanLoadedAssemblies(
            HostBaseline baseline,
            PresetConfig preset,
            HostBaselineBuildResult result)
        {
            Assembly[] assemblies;

            try
            {
                assemblies =
                    AppDomain.CurrentDomain.GetAssemblies();
            }
            catch (Exception ex)
            {
                result.AddFailure(
                    "ASSEMBLY_ENUMERATION_FAILED:" +
                    ex.GetType().Name);
                return;
            }

            List<string> discoveryFailures;
            IReadOnlyList<LoadedModInfo> loadedMods =
                LoadedModDiscovery.GetLoadedMods(
                    out discoveryFailures);

            int discoveryFailureCount =
                discoveryFailures == null
                    ? 0
                    : discoveryFailures.Count;

            if (discoveryFailures != null)
            {
                foreach (string failure in discoveryFailures)
                {
                    result.AddFailure(
                        "LOADED_MOD_DISCOVERY_FAILED:" +
                        failure);
                }
            }

            int discoveredLoadedMods =
                loadedMods == null
                    ? 0
                    : loadedMods.Count;

            baseline.AddProviderSummary(
                new BaselineProviderSummary
                {
                    ProviderName =
                        "LoadedModDiscovery",
                    Status =
                        discoveryFailureCount == 0
                            ? "Complete"
                            : "Failed",
                    Complete =
                        discoveryFailureCount == 0,
                    FindingCount =
                        discoveredLoadedMods,
                    FailureCount =
                        discoveryFailureCount,
                    CompletedAtUtc =
                        DateTime.UtcNow
                });

            foreach (Assembly assembly in assemblies
                .Where(x => x != null)
                .OrderBy(x => SafeAssemblyFullName(x) ?? "", StringComparer.Ordinal))
            {
                try
                {
                    string fullName =
                        SafeAssemblyFullName(assembly);

                    if (string.IsNullOrWhiteSpace(fullName))
                    {
                        result.AddFailure(
                            "ASSEMBLY_FULL_NAME_UNAVAILABLE");
                        continue;
                    }

                    AssemblyName assemblyName =
                        SafeAssemblyName(assembly);

                    string simpleName =
                        assemblyName == null
                            ? null
                            : assemblyName.Name;

                    string version =
                        assemblyName == null || assemblyName.Version == null
                            ? null
                            : assemblyName.Version.ToString();

                    string location =
                        SafeAssemblyLocation(assembly);

                    string normalizedLocation =
                        NormalizeFullPath(location);

                    LoadedModInfo loadedMod =
                        LoadedModDiscovery.FindByAssembly(
                            loadedMods,
                            assembly);

                    bool isModAssembly =
                        loadedMod != null;

                    bool isCriticalAssembly =
                        IsCriticalAssembly(assembly);

                    if (isCriticalAssembly)
                    {
                        string criticalLocation =
                            ResolveCriticalAssemblyLocation(
                                simpleName,
                                normalizedLocation);

                        if (!string.IsNullOrWhiteSpace(
                                criticalLocation))
                        {
                            normalizedLocation =
                                criticalLocation;
                        }
                    }

                    bool securityRelevant =
                        isModAssembly ||
                        isCriticalAssembly;

                    bool hasLocation =
                        !string.IsNullOrWhiteSpace(normalizedLocation);

                    string relativePath =
                        hasLocation
                            ? TryGetRelativeGamePath(normalizedLocation)
                            : null;

                    string modId =
                        loadedMod == null
                            ? null
                            : loadedMod.ModId;

                    if (string.IsNullOrWhiteSpace(modId) &&
                        isModAssembly)
                    {
                        modId = simpleName;
                    }

                    string hash = null;

                    if (securityRelevant)
                    {
                        if (!hasLocation)
                        {
                            result.AddFailure(
                                "SECURITY_RELEVANT_ASSEMBLY_LOCATION_UNAVAILABLE:" +
                                fullName);
                        }
                        else if (!File.Exists(normalizedLocation))
                        {
                            result.AddFailure(
                                "SECURITY_RELEVANT_ASSEMBLY_FILE_MISSING:" +
                                SafeDisplayPath(normalizedLocation));
                        }
                        else if (!TryComputeStableHash(
                            normalizedLocation,
                            out hash,
                            out string hashFailure))
                        {
                            if (isCriticalAssembly)
                            {
                                result.AddWarning(
                                    "CORE_ASSEMBLY_HASH_RETRY_REQUIRED:" +
                                    SafeDisplayPath(normalizedLocation) +
                                    ":" +
                                    hashFailure);
                            }
                            else
                            {
                                result.AddFailure(
                                    "ASSEMBLY_HASH_FAILED:" +
                                    SafeDisplayPath(normalizedLocation) +
                                    ":" +
                                    hashFailure);
                            }
                        }
                    }

                    List<string> dependencies =
                        GetDependencies(
                            assembly);

                    string artifactId =
                        securityRelevant &&
                        !string.IsNullOrWhiteSpace(hash)
                            ? ComputeArtifactId(
                                modId,
                                simpleName,
                                fullName,
                                relativePath,
                                hash)
                            : null;

                    BaselineAssembly baselineAssembly =
                        new BaselineAssembly
                        {
                            FullName = fullName,
                            Name = simpleName,
                            Version = version,
                            Location = normalizedLocation,
                            RelativePath = relativePath,
                            Sha256 = hash,
                            HasPhysicalLocation = hasLocation,
                            IsLoaded = true,
                            IsModAssembly = isModAssembly,
                            ModId = modId,
                            ArtifactId = artifactId
                        };

                    baseline.AddAssembly(
                        baselineAssembly);

                    if (!securityRelevant)
                    {
                        continue;
                    }

                    BaselineArtifact artifact =
                        new BaselineArtifact
                        {
                            ModId = modId,
                            ArtifactId = artifactId,
                            FileName = hasLocation
                                ? Path.GetFileName(normalizedLocation)
                                : simpleName,
                            RelativePath = relativePath,
                            FileSize = GetFileSize(normalizedLocation),
                            Sha256 = hash,
                            AssemblyFullName = fullName,
                            AssemblyName = simpleName,
                            AssemblyVersion = version,
                            AssemblyLocation = normalizedLocation,
                            IsLoaded = true,
                            Dependencies = dependencies,
                            PolicyFlags = BuildPolicyFlags(
                                preset,
                                modId,
                                simpleName)
                        };

                    if (string.IsNullOrWhiteSpace(artifact.Sha256))
                    {
                        continue;
                    }

                    baseline.AddArtifact(artifact);
                }
                catch (Exception ex)
                {
                    result.AddFailure(
                        "ASSEMBLY_SCAN_FAILED:" +
                        ex.GetType().Name);
                }
            }
        }

        private void ScanInstalledModFiles(
            HostBaseline baseline,
            PresetConfig preset,
            HostBaselineBuildResult result,
            bool includeDisabledMods)
        {
            if (baseline == null ||
                result == null ||
                string.IsNullOrWhiteSpace(_gameRoot))
            {
                return;
            }

            string modsDirectory;

            try
            {
                modsDirectory =
                    Path.Combine(
                        _gameRoot,
                        "hollow_knight_Data",
                        "Managed",
                        "Mods");
            }
            catch
            {
                result.AddFailure(
                    "MOD_DIRECTORY_RESOLUTION_FAILED");
                return;
            }

            if (!Directory.Exists(modsDirectory))
            {
                result.AddFailure(
                    "MOD_DIRECTORY_UNAVAILABLE:" +
                    SafeDisplayPath(modsDirectory));
                return;
            }

            HashSet<string> existingArtifactPaths =
                new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

            if (baseline.Artifacts != null)
            {
                foreach (BaselineArtifact artifact
                         in baseline.Artifacts)
                {
                    if (artifact == null ||
                        string.IsNullOrWhiteSpace(
                            artifact.RelativePath))
                    {
                        continue;
                    }

                    existingArtifactPaths.Add(
                        NormalizePath(
                            artifact.RelativePath));
                }
            }

            List<string> files =
                new List<string>();

            CollectDllFiles(
                modsDirectory,
                false,
                files,
                result);

            if (includeDisabledMods)
            {
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
                    CollectDllFiles(
                        disabledDirectory,
                        true,
                        files,
                        result);
                }
            }

            HashSet<string> seen =
                new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

            foreach (string file in files)
            {
                string normalizedFile =
                    NormalizeFullPath(file);

                if (string.IsNullOrWhiteSpace(normalizedFile) ||
                    !seen.Add(normalizedFile))
                {
                    continue;
                }

                string relativePath =
                    TryGetRelativeGamePath(
                        normalizedFile);

                if (string.IsNullOrWhiteSpace(relativePath))
                {
                    result.AddFailure(
                        "MOD_ARTIFACT_RELATIVE_PATH_UNAVAILABLE:" +
                        SafeDisplayPath(normalizedFile));
                    continue;
                }

                if (existingArtifactPaths.Contains(
                        relativePath))
                {
                    continue;
                }

                FileInfo info;

                try
                {
                    info =
                        new FileInfo(
                            normalizedFile);

                    if (!info.Exists)
                    {
                        result.AddFailure(
                            "MOD_ARTIFACT_FILE_MISSING:" +
                            SafeDisplayPath(normalizedFile));
                        continue;
                    }
                }
                catch (Exception ex)
                {
                    result.AddFailure(
                        "MOD_ARTIFACT_METADATA_FAILED:" +
                        SafeDisplayPath(normalizedFile) +
                        ":" +
                        ex.GetType().Name);
                    continue;
                }

                string hash;

                if (!TryComputeStableHash(
                        normalizedFile,
                        out hash,
                        out string hashFailure))
                {
                    result.AddFailure(
                        "MOD_ARTIFACT_HASH_FAILED:" +
                        SafeDisplayPath(normalizedFile) +
                        ":" +
                        hashFailure);
                    continue;
                }

                AssemblyName assemblyName = null;

                try
                {
                    assemblyName =
                        AssemblyName.GetAssemblyName(
                            normalizedFile);
                }
                catch
                {
                }

                string simpleName =
                    assemblyName == null
                        ? Path.GetFileNameWithoutExtension(
                            normalizedFile)
                        : assemblyName.Name;

                string fullName =
                    assemblyName == null
                        ? null
                        : assemblyName.FullName;

                string version =
                    assemblyName == null ||
                    assemblyName.Version == null
                        ? null
                        : assemblyName.Version.ToString();

                string modId =
                    ResolveModId(
                        assemblyName,
                        normalizedFile);

                bool isLoaded =
                    IsAssemblyLoadedFromPath(
                        normalizedFile);

                string artifactId =
                    ComputeArtifactId(
                        modId,
                        simpleName,
                        fullName,
                        relativePath,
                        hash);

                baseline.AddArtifact(
                    new BaselineArtifact
                    {
                        ModId = modId,
                        ArtifactId = artifactId,
                        FileName =
                            Path.GetFileName(
                                normalizedFile),
                        RelativePath =
                            relativePath,
                        FileSize =
                            info.Length,
                        Sha256 =
                            hash,
                        AssemblyFullName =
                            fullName,
                        AssemblyName =
                            simpleName,
                        AssemblyVersion =
                            version,
                        AssemblyLocation =
                            normalizedFile,
                        IsLoaded =
                            isLoaded,
                        Dependencies =
                            new List<string>(),
                        PolicyFlags =
                            BuildPolicyFlags(
                                preset,
                                modId,
                                simpleName)
                    });

                existingArtifactPaths.Add(
                    relativePath);

                if (!isLoaded)
                {
                    baseline.AddAssembly(
                        new BaselineAssembly
                        {
                            FullName =
                                fullName,
                            Name =
                                simpleName,
                            Version =
                                version,
                            Location =
                                normalizedFile,
                            RelativePath =
                                relativePath,
                            Sha256 =
                                hash,
                            HasPhysicalLocation =
                                true,
                            IsLoaded =
                                false,
                            IsModAssembly =
                                true,
                            ModId =
                                modId,
                            ArtifactId =
                                artifactId
                        });
                }
            }
        }

        private static void CollectDllFiles(
            string directory,
            bool disabled,
            List<string> destination,
            HostBaselineBuildResult result)
        {
            if (string.IsNullOrWhiteSpace(directory) ||
                destination == null)
            {
                return;
            }

            string[] files;

            try
            {
                files =
                    Directory.GetFiles(
                        directory,
                        "*.dll",
                        SearchOption.AllDirectories);
            }
            catch (Exception ex)
            {
                if (result != null)
                {
                    result.AddFailure(
                        "MOD_DIRECTORY_SCAN_FAILED:" +
                        directory +
                        ":" +
                        ex.GetType().Name);
                }

                return;
            }

            foreach (string file in files)
            {
                if (string.IsNullOrWhiteSpace(file))
                {
                    continue;
                }

                if (!disabled)
                {
                    string disabledDirectory =
                        NormalizeDirectoryPath(
                            Path.Combine(
                                directory,
                                "Disabled"));

                    if (IsPathWithin(
                            disabledDirectory,
                            file))
                    {
                        continue;
                    }
                }

                destination.Add(
                    file);
            }
        }

        private static bool IsAssemblyLoadedFromPath(
            string path)
        {
            string normalizedPath =
                NormalizeFullPath(path);

            if (string.IsNullOrWhiteSpace(normalizedPath))
            {
                return false;
            }

            Assembly[] assemblies;

            try
            {
                assemblies =
                    AppDomain.CurrentDomain.GetAssemblies();
            }
            catch
            {
                return false;
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

                string normalizedLocation =
                    NormalizeFullPath(
                        location);

                if (!string.IsNullOrWhiteSpace(
                        normalizedLocation) &&
                    string.Equals(
                        normalizedPath,
                        normalizedLocation,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static string ResolveModId(
            AssemblyName assemblyName,
            string path)
        {
            string simpleName =
                assemblyName == null
                    ? null
                    : assemblyName.Name;

            string fullName =
                assemblyName == null
                    ? null
                    : assemblyName.FullName;

            try
            {
                Dictionary<string, string> loadedMods =
                    ModHooks.LoadedModsWithVersions;

                if (loadedMods != null &&
                    loadedMods.Count > 0)
                {
                    foreach (KeyValuePair<string, string> mod
                             in loadedMods)
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
                    Path.GetFileNameWithoutExtension(
                        path);

                return string.IsNullOrWhiteSpace(fileName)
                    ? "UnknownMod"
                    : fileName.Trim();
            }
            catch
            {
                return "UnknownMod";
            }
        }

        private void ScanNativeModules(
            HostBaseline baseline,
            HostBaselineBuildResult result)
        {
            ProcessModuleCollection modules;

            try
            {
                modules =
                    Process.GetCurrentProcess().Modules;
            }
            catch (Exception ex)
            {
                result.AddFailure(
                    "NATIVE_MODULE_ENUMERATION_FAILED:" +
                    ex.GetType().Name);
                return;
            }

            foreach (ProcessModule module in modules
                .Cast<ProcessModule>()
                .Where(x => x != null)
                .OrderBy(x => SafeModuleName(x) ?? "", StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => SafeModulePath(x) ?? "", StringComparer.OrdinalIgnoreCase))
            {
                string name = SafeModuleName(module);
                string rawPath = SafeModulePath(module);

                if (IsPseudoNativeModule(name, rawPath))
                {
                    continue;
                }

                string path = NormalizeFullPath(rawPath);

                if (string.IsNullOrWhiteSpace(path))
                {
                    result.AddFailure(
                        "NATIVE_MODULE_PATH_UNAVAILABLE:" +
                        name);

                    continue;
                }

                if (IsWindowsSystemModulePath(path))
                {
                    continue;
                }

                bool gameRelated =
                    IsPathWithin(
                        NormalizeDirectoryPath(_gameRoot),
                        path);

                if (!gameRelated)
                {
                    continue;
                }

                string classification =
                    "GameLocal";

                bool securityRelevant =
                    true;

                string relativePath =
                    TryGetRelativeGamePath(path);

                long size =
                    GetFileSize(path);

                string hash = null;

                if (!File.Exists(path))
                {
                    result.AddFailure(
                        "NATIVE_MODULE_FILE_MISSING:" +
                        SafeDisplayPath(path));
                }
                else if (!TryComputeStableHash(
                             path,
                             out hash,
                             out string hashFailure))
                {
                    result.AddFailure(
                        "NATIVE_MODULE_HASH_FAILED:" +
                        SafeDisplayPath(path) +
                        ":" +
                        hashFailure);
                }

                baseline.AddNativeModule(
                    new BaselineNativeModule
                    {
                        Name = name,
                        Path = path,
                        RelativePath = relativePath,
                        FileSize = size,
                        Sha256 = hash,
                        Classification = classification,
                        IsSecurityRelevant = securityRelevant
                    });
            }
        }

        private static bool IsCriticalAssembly(
            Assembly assembly)
        {
            if (assembly == null)
            {
                return false;
            }

            if (assembly ==
                typeof(HostBaselineBuilder).Assembly)
            {
                return true;
            }

            string name = SafeAssemblyName(assembly)?.Name;

            return
                string.Equals(name, "Assembly-CSharp", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "HKMP", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "HKMP.Whitelist", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsUnderModLoadPath(
            string path)
        {
            string managedDirectory =
                NormalizeDirectoryPath(
                    Path.Combine(
                        _gameRoot,
                        "hollow_knight_Data",
                        "Managed"));

            string modsDirectory =
                NormalizeDirectoryPath(
                    Path.Combine(
                        managedDirectory,
                        "Mods"));

            return IsPathWithin(
                modsDirectory,
                path);
        }

        private static bool IsPathWithin(
            string directory,
            string path)
        {
            if (string.IsNullOrWhiteSpace(directory) ||
                string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string parent =
                NormalizeDirectoryPath(directory);

            string child =
                NormalizeFullPath(path);

            if (string.IsNullOrWhiteSpace(parent) ||
                string.IsNullOrWhiteSpace(child))
            {
                return false;
            }

            return
                string.Equals(
                    child,
                    parent,
                    StringComparison.OrdinalIgnoreCase) ||
                child.StartsWith(
                    parent + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase) ||
                child.StartsWith(
                    parent + Path.AltDirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase);
        }

        private string TryGetRelativeGamePath(
            string path)
        {
            string normalizedPath =
                NormalizeFullPath(path);

            if (string.IsNullOrWhiteSpace(normalizedPath) ||
                string.IsNullOrWhiteSpace(_gameRoot))
            {
                return null;
            }

            string root =
                NormalizeDirectoryPath(_gameRoot);

            if (!IsPathWithin(root, normalizedPath))
            {
                return null;
            }

            string relative =
                normalizedPath.Substring(
                    root.Length)
                    .TrimStart(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar);

            return NormalizePath(relative);
        }

        private static List<string> GetDependencies(
            Assembly assembly)
        {
            List<string> result =
                new List<string>();

            if (assembly == null)
            {
                return result;
            }

            try
            {
                foreach (AssemblyName dependency in
                         assembly.GetReferencedAssemblies())
                {
                    if (dependency == null ||
                        string.IsNullOrWhiteSpace(dependency.Name))
                    {
                        continue;
                    }

                    result.Add(dependency.Name);
                }
            }
            catch
            {
            }

            return result
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static List<string> BuildPolicyFlags(
            PresetConfig preset,
            string modId,
            string fallbackIdentity)
        {
            ModPolicy policy =
                ModPolicyResolver.Resolve(
                    preset,
                    modId,
                    fallbackIdentity);

            switch (policy)
            {
                case ModPolicy.Required:
                    return new List<string> { "REQUIRED" };

                case ModPolicy.Allowed:
                    return new List<string> { "ALLOWED" };

                case ModPolicy.Ignored:
                    return new List<string> { "IGNORED" };

                default:
                    if (ModPolicyResolver.IsExplicitForbidden(
                        preset,
                        modId,
                        fallbackIdentity))
                    {
                        return new List<string> { "FORBIDDEN" };
                    }

                    return new List<string> { "DEFAULT_FORBIDDEN" };
            }
        }

        private static string ComputeArtifactId(
            string modId,
            string assemblyName,
            string assemblyFullName,
            string relativePath,
            string sha256)
        {
            string value =
                (modId ?? "") + "|" +
                (assemblyName ?? "") + "|" +
                (assemblyFullName ?? "") + "|" +
                (relativePath ?? "") + "|" +
                (sha256 ?? "");

            using (SHA256 sha = SHA256.Create())
            {
                byte[] bytes =
                    Encoding.UTF8.GetBytes(value);

                byte[] digest =
                    sha.ComputeHash(bytes);

                StringBuilder builder =
                    new StringBuilder(digest.Length * 2);

                foreach (byte item in digest)
                {
                    builder.Append(
                        item.ToString("x2"));
                }

                return builder.ToString();
            }
        }

        private bool TryComputeStableHash(
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

        private static long GetFileSize(string path)
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

        private static bool IsKnownPlatformModuleName(
            string name)
        {
            string normalized =
                (name ?? "")
                .Trim()
                .ToLowerInvariant();

            return
                normalized == "steamclient64.dll" ||
                normalized == "steam_api64.dll" ||
                normalized == "gameoverlayrenderer64.dll" ||
                normalized == "tier0_s64.dll" ||
                normalized == "vstdlib_s64.dll" ||
                normalized == "unityplayer.dll" ||
                normalized == "mono-2.0-bdwgc.dll" ||
                normalized.StartsWith("nv", StringComparison.Ordinal) ||
                normalized.StartsWith("amd", StringComparison.Ordinal) ||
                normalized.StartsWith("ig", StringComparison.Ordinal);
        }



        private static string SafeAssemblyFullName(
            Assembly assembly)
        {
            try { return assembly == null ? null : assembly.FullName; }
            catch { return null; }
        }

        private static AssemblyName SafeAssemblyName(
            Assembly assembly)
        {
            try { return assembly == null ? null : assembly.GetName(); }
            catch { return null; }
        }

        private static string SafeAssemblyLocation(
            Assembly assembly)
        {
            try { return assembly == null ? null : assembly.Location; }
            catch { return null; }
        }

        private static string SafeModuleName(
            ProcessModule module)
        {
            try { return module == null ? null : module.ModuleName; }
            catch { return null; }
        }

        private static string SafeModulePath(
            ProcessModule module)
        {
            try { return module == null ? null : module.FileName; }
            catch { return null; }
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
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            string normalized =
                NormalizeFullPath(path);

            return string.IsNullOrWhiteSpace(normalized)
                ? null
                : normalized.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar);
        }

        private static bool IsNormalizedHash(string hash)
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

        private static string SafeDisplayPath(string path)
        {
            return string.IsNullOrWhiteSpace(path)
                ? "<unknown>"
                : path;
        }

        private static string GetGameVersion()
        {
            try { return Application.version; }
            catch { return null; }
        }

        private static string GetWhitelistVersion()
        {
            try
            {
                Version version =
                    typeof(HostBaselineBuilder)
                        .Assembly
                        .GetName()
                        .Version;

                return version == null
                    ? null
                    : version.ToString();
            }
            catch
            {
                return null;
            }
        }

        private static string GetHKMPVersion()
        {
            try
            {
                Assembly hkmp =
                    AppDomain.CurrentDomain.GetAssemblies()
                        .FirstOrDefault(
                            x =>
                            {
                                try
                                {
                                    return x != null &&
                                           string.Equals(
                                               x.GetName().Name,
                                               "HKMP",
                                               StringComparison.OrdinalIgnoreCase);
                                }
                                catch
                                {
                                    return false;
                                }
                            });

                if (hkmp == null)
                {
                    return null;
                }

                Version version =
                    hkmp.GetName().Version;

                return version == null
                    ? null
                    : version.ToString();
            }
            catch
            {
                return null;
            }
        }

        private static string ComputePresetHash(
            PresetConfig preset)
        {
            if (preset == null)
            {
                return null;
            }

            try
            {
                string json =
                    Newtonsoft.Json.JsonConvert.SerializeObject(
                        preset,
                        Newtonsoft.Json.Formatting.None);

                using (SHA256 sha = SHA256.Create())
                {
                    byte[] bytes =
                        Encoding.UTF8.GetBytes(json);

                    return ToHex(sha.ComputeHash(bytes));
                }
            }
            catch
            {
                return null;
            }
        }

        private static string ComputeBaselineDigest(
            HostBaseline baseline)
        {
            if (baseline == null)
            {
                return null;
            }

            try
            {
                StringBuilder text =
                    new StringBuilder();

                text.Append("GameVersion=")
                    .Append(baseline.GameVersion ?? "")
                    .Append('\n');

                text.Append("HKMPVersion=")
                    .Append(baseline.HKMPVersion ?? "")
                    .Append('\n');

                text.Append("WhitelistVersion=")
                    .Append(baseline.WhitelistVersion ?? "")
                    .Append('\n');

                text.Append("PresetName=")
                    .Append(baseline.PresetName ?? "")
                    .Append('\n');

                text.Append("PresetVersion=")
                    .Append(baseline.PresetVersion ?? "")
                    .Append('\n');

                text.Append("PresetHash=")
                    .Append(baseline.PresetHash ?? "")
                    .Append('\n');

                foreach (BaselineProviderSummary provider in
                         baseline.Providers
                            .Where(x => x != null)
                            .OrderBy(
                                x => x.ProviderName ?? "",
                                StringComparer.OrdinalIgnoreCase))
                {
                    text.Append("Provider=")
                        .Append(provider.ProviderName ?? "").Append('|')
                        .Append(provider.Status ?? "").Append('|')
                        .Append(provider.Complete).Append('|')
                        .Append(provider.FindingCount).Append('|')
                        .Append(provider.FailureCount)
                        .Append('\n');
                }

                foreach (BaselineAssembly assembly in
                         baseline.Assemblies
                            .Where(x => x != null)
                            .OrderBy(
                                x => x.RelativePath ?? "",
                                StringComparer.OrdinalIgnoreCase)
                            .ThenBy(
                                x => x.FullName ?? "",
                                StringComparer.Ordinal))
                {
                    text.Append("Assembly=")
                        .Append(assembly.ModId ?? "").Append('|')
                        .Append(assembly.ArtifactId ?? "").Append('|')
                        .Append(assembly.FullName ?? "").Append('|')
                        .Append(assembly.Name ?? "").Append('|')
                        .Append(assembly.Version ?? "").Append('|')
                        .Append(assembly.Location ?? "").Append('|')
                        .Append(assembly.RelativePath ?? "").Append('|')
                        .Append(assembly.Sha256 ?? "").Append('|')
                        .Append(assembly.IsLoaded).Append('\n');
                }

                foreach (BaselineArtifact artifact in
                         baseline.Artifacts
                            .Where(x => x != null)
                            .OrderBy(
                                x => x.RelativePath ?? "",
                                StringComparer.OrdinalIgnoreCase)
                            .ThenBy(
                                x => x.Sha256 ?? "",
                                StringComparer.OrdinalIgnoreCase))
                {
                    text.Append("Artifact=")
                        .Append(artifact.ModId ?? "").Append('|')
                        .Append(artifact.ArtifactId ?? "").Append('|')
                        .Append(artifact.FileName ?? "").Append('|')
                        .Append(artifact.RelativePath ?? "").Append('|')
                        .Append(artifact.FileSize).Append('|')
                        .Append(artifact.Sha256 ?? "").Append('|')
                        .Append(artifact.AssemblyFullName ?? "").Append('|')
                        .Append(artifact.AssemblyName ?? "").Append('|')
                        .Append(artifact.AssemblyVersion ?? "").Append('|')
                        .Append(artifact.AssemblyLocation ?? "").Append('|')
                        .Append(artifact.IsLoaded).Append('\n');
                }

                foreach (BaselineNativeModule module in
                         baseline.NativeModules
                            .Where(x => x != null)
                            .OrderBy(
                                x => x.RelativePath ?? "",
                                StringComparer.OrdinalIgnoreCase)
                            .ThenBy(
                                x => x.Name ?? "",
                                StringComparer.OrdinalIgnoreCase))
                {
                    text.Append("Native=")
                        .Append(module.Name ?? "").Append('|')
                        .Append(module.RelativePath ?? "").Append('|')
                        .Append(module.FileSize).Append('|')
                        .Append(module.Sha256 ?? "").Append('|')
                        .Append(module.Classification ?? "").Append('|')
                        .Append(module.IsSecurityRelevant).Append('\n');
                }

                using (SHA256 sha = SHA256.Create())
                {
                    return ToHex(
                        sha.ComputeHash(
                            Encoding.UTF8.GetBytes(
                                text.ToString())));
                }
            }
            catch
            {
                return null;
            }
        }
        private static bool IsWindowsSystemModulePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;

            string lowPath = path.ToLowerInvariant();
            string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
            return lowPath.StartsWith(windir) && (lowPath.Contains("system32") || lowPath.Contains("syswow64"));
        }

        private static string ToHex(byte[] bytes)
        {
            if (bytes == null)
            {
                return null;
            }

            StringBuilder builder =
                new StringBuilder(bytes.Length * 2);

            foreach (byte item in bytes)
            {
                builder.Append(item.ToString("x2"));
            }

            return builder.ToString();
        }
    }
}
