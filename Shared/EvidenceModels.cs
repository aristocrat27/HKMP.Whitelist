using System;
using System.Collections.Generic;

namespace HKMP.Whitelist.Shared
{
    public enum EvidenceSource
    {
        Unknown,
        FileSystem,
        LoadedAssembly,
        NativeModule,
        Harmony,
        CoreIntegrity,
        RuntimeMonitor,
        SaveMonitor,
        SelfIntegrity,
        Protocol
    }

    public sealed class SecurityEvidence
    {
        public int ProtocolVersion { get; set; } = 2;

        public string SessionId { get; set; }

        public string BaselineId { get; set; }

        public string ManifestId { get; set; }

        public int ManifestVersion { get; set; }

        public string WhitelistVersion { get; set; }

        public string ScanStatus { get; set; }

        public DateTime ScanTimestampUtc { get; set; }

        public long ScanDurationMs { get; set; }

        public string SelfHash { get; set; }

        public bool DebuggerDetected { get; set; }

        public List<ArtifactEvidence> Artifacts { get; set; } =
            new List<ArtifactEvidence>();

        public List<AssemblyEvidence> Assemblies { get; set; } =
            new List<AssemblyEvidence>();

        public List<NativeModuleEvidence> NativeModules { get; set; } =
            new List<NativeModuleEvidence>();

        public List<HarmonyEvidence> HarmonyPatches { get; set; } =
            new List<HarmonyEvidence>();

        public List<CoreIntegrityEvidence> CoreIntegrity { get; set; } =
            new List<CoreIntegrityEvidence>();

        public List<RuntimeEvidence> RuntimeEvents { get; set; } =
            new List<RuntimeEvidence>();

        public List<SaveEvidence> SaveEvents { get; set; } =
            new List<SaveEvidence>();

        public List<string> IntegrityFailures { get; set; } =
            new List<string>();

        public List<string> UnreadableFiles { get; set; } =
            new List<string>();

        public List<string> ProtocolViolations { get; set; } =
            new List<string>();

        public SecurityEvidence()
        {
            ScanTimestampUtc =
                DateTime.UtcNow;
        }

        public bool IsComplete
        {
            get
            {
                return
                    !string.IsNullOrWhiteSpace(
                        ScanStatus) &&
                    ScanTimestampUtc !=
                        default(DateTime);
            }
        }

        public void AddArtifact(
            ArtifactEvidence evidence)
        {
            if (evidence == null)
            {
                return;
            }

            Artifacts.Add(
                evidence);
        }

        public void AddAssembly(
            AssemblyEvidence evidence)
        {
            if (evidence == null)
            {
                return;
            }

            Assemblies.Add(
                evidence);
        }

        public void AddNativeModule(
            NativeModuleEvidence evidence)
        {
            if (evidence == null)
            {
                return;
            }

            NativeModules.Add(
                evidence);
        }

        public void AddHarmonyPatch(
            HarmonyEvidence evidence)
        {
            if (evidence == null)
            {
                return;
            }

            HarmonyPatches.Add(
                evidence);
        }

        public void AddCoreIntegrity(
            CoreIntegrityEvidence evidence)
        {
            if (evidence == null)
            {
                return;
            }

            CoreIntegrity.Add(
                evidence);
        }

        public void AddRuntimeEvent(
            RuntimeEvidence evidence)
        {
            if (evidence == null)
            {
                return;
            }

            RuntimeEvents.Add(
                evidence);
        }

        public void AddSaveEvent(
            SaveEvidence evidence)
        {
            if (evidence == null)
            {
                return;
            }

            SaveEvents.Add(
                evidence);
        }

        public void AddIntegrityFailure(
            string failure)
        {
            if (string.IsNullOrWhiteSpace(
                    failure))
            {
                return;
            }

            IntegrityFailures.Add(
                failure.Trim());
        }

        public void AddUnreadableFile(
            string path)
        {
            if (string.IsNullOrWhiteSpace(
                    path))
            {
                return;
            }

            UnreadableFiles.Add(
                path.Trim());
        }

        public void AddProtocolViolation(
            string violation)
        {
            if (string.IsNullOrWhiteSpace(
                    violation))
            {
                return;
            }

            ProtocolViolations.Add(
                violation.Trim());
        }
    }

    public sealed class ArtifactEvidence
    {
        public EvidenceSource Source { get; set; }

        public string ModId { get; set; }

        public string ArtifactId { get; set; }

        public string FileName { get; set; }

        public string Path { get; set; }

        public string RelativePath { get; set; }

        public long FileSize { get; set; }

        public string Sha256 { get; set; }

        public string ExpectedSha256 { get; set; }

        public string AssemblyName { get; set; }

        public string AssemblyFullName { get; set; }

        public string AssemblyVersion { get; set; }

        public string AssemblyLocation { get; set; }

        public bool IsLoaded { get; set; }

        public bool Exists { get; set; }

        public bool IsReadable { get; set; }

        public DateTime ObservedAtUtc { get; set; }

        public string Details { get; set; }

        public ArtifactEvidence()
        {
            ObservedAtUtc =
                DateTime.UtcNow;
        }
    }

    public sealed class AssemblyEvidence
    {
        public EvidenceSource Source { get; set; } =
            EvidenceSource.LoadedAssembly;

        public string FullName { get; set; }

        public string Name { get; set; }

        public string AssemblyVersion { get; set; }

        public string Location { get; set; }

        public string RelativePath { get; set; }

        public string ModId { get; set; }

        public string ArtifactId { get; set; }

        public string Sha256 { get; set; }

        public string ExpectedSha256 { get; set; }

        public bool HasPhysicalLocation { get; set; }

        public bool IsLoaded { get; set; }

        public bool IsModAssembly { get; set; }

        public bool IsUnknown { get; set; }

        public DateTime ObservedAtUtc { get; set; }

        public string Details { get; set; }

        public AssemblyEvidence()
        {
            ObservedAtUtc =
                DateTime.UtcNow;
        }
    }

    public sealed class NativeModuleEvidence
    {
        public EvidenceSource Source { get; set; } =
            EvidenceSource.NativeModule;

        public string Name { get; set; }

        public string Path { get; set; }

        public string RelativePath { get; set; }

        public long FileSize { get; set; }

        public string Sha256 { get; set; }

        public string ExpectedSha256 { get; set; }

        public string Classification { get; set; }

        public bool IsSecurityRelevant { get; set; }

        public bool IsUnknown { get; set; }

        public bool IsReadable { get; set; }

        public DateTime ObservedAtUtc { get; set; }

        public string Details { get; set; }

        public NativeModuleEvidence()
        {
            ObservedAtUtc =
                DateTime.UtcNow;
        }
    }

    public sealed class HarmonyEvidence
    {
        public EvidenceSource Source { get; set; } =
            EvidenceSource.Harmony;

        public string OwnerAssemblyFullName { get; set; }

        public string OwnerModId { get; set; }

        public string OwnerArtifactId { get; set; }

        public string OwnerSha256 { get; set; }

        public string TargetType { get; set; }

        public string TargetMethod { get; set; }

        public string TargetSignature { get; set; }

        public string PatchType { get; set; }

        public string PatchMethod { get; set; }

        public string PatchMethodAssemblyFullName { get; set; }

        public string ExpectedTarget { get; set; }

        public bool IsAllowed { get; set; }

        public bool IsUnknownOwner { get; set; }

        public bool IsUnknownTarget { get; set; }

        public DateTime ObservedAtUtc { get; set; }

        public string Details { get; set; }

        public HarmonyEvidence()
        {
            ObservedAtUtc =
                DateTime.UtcNow;
        }
    }

    public sealed class CoreIntegrityEvidence
    {
        public EvidenceSource Source { get; set; } =
            EvidenceSource.CoreIntegrity;

        public string CoreId { get; set; }

        public string DisplayName { get; set; }

        public string Path { get; set; }

        public string RelativePath { get; set; }

        public string Version { get; set; }

        public string AssemblyFullName { get; set; }

        public string Sha256 { get; set; }

        public string ExpectedSha256 { get; set; }

        public bool Exists { get; set; }

        public bool IsReadable { get; set; }

        public bool HashMatches { get; set; }

        public bool AssemblyMatches { get; set; }

        public bool VersionMatches { get; set; }

        public bool PathMatches { get; set; }

        public bool Passed { get; set; }

        public DateTime ObservedAtUtc { get; set; }

        public string FailureReason { get; set; }

        public CoreIntegrityEvidence()
        {
            ObservedAtUtc =
                DateTime.UtcNow;
        }
    }

    public sealed class RuntimeEvidence
    {
        public EvidenceSource Source { get; set; } =
            EvidenceSource.RuntimeMonitor;

        public string EventType { get; set; }

        public string ModId { get; set; }

        public string ArtifactId { get; set; }

        public string AssemblyFullName { get; set; }

        public string AssemblyName { get; set; }

        public string AssemblyVersion { get; set; }

        public string Path { get; set; }

        public string RelativePath { get; set; }

        public string Sha256 { get; set; }

        public string ExpectedSha256 { get; set; }

        public bool IsKnownArtifact { get; set; }

        public bool IsAllowed { get; set; }

        public bool IsSecurityRelevant { get; set; }

        public DateTime TimestampUtc { get; set; }

        public string Details { get; set; }

        public RuntimeEvidence()
        {
            TimestampUtc =
                DateTime.UtcNow;
        }
    }

    public sealed class SaveEvidence
    {
        public EvidenceSource Source { get; set; } =
            EvidenceSource.SaveMonitor;

        public string ProviderName { get; set; }

        public string SlotIdentity { get; set; }

        public string EventType { get; set; }

        public string FilePath { get; set; }

        public string BeforeFingerprint { get; set; }

        public string AfterFingerprint { get; set; }

        public bool IsExpectedTransition { get; set; }

        public bool IsSecurityRelevant { get; set; }

        public DateTime TimestampUtc { get; set; }

        public string Details { get; set; }

        public SaveEvidence()
        {
            TimestampUtc =
                DateTime.UtcNow;
        }
    }
}