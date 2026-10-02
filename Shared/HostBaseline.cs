using System;
using System.Collections.Generic;

namespace HKMP.Whitelist.Shared
{
    public sealed class HostBaseline
    {
        private readonly List<BaselineArtifact> _artifacts =
            new List<BaselineArtifact>();

        private readonly List<BaselineAssembly> _assemblies =
            new List<BaselineAssembly>();

        private readonly List<BaselineNativeModule> _nativeModules =
            new List<BaselineNativeModule>();

        private readonly List<BaselineProviderSummary> _providers =
            new List<BaselineProviderSummary>();

        private readonly List<string> _integrityFailures =
            new List<string>();

        public string BaselineId { get; internal set; }

        public string SessionId { get; internal set; }

        public DateTime CreatedAtUtc { get; internal set; }

        public string GameVersion { get; internal set; }

        public string HKMPVersion { get; internal set; }

        public string WhitelistVersion { get; internal set; }

        public string PresetName { get; internal set; }

        public string PresetVersion { get; internal set; }

        public string PresetHash { get; internal set; }

        public string BaselineDigest { get; internal set; }

        public bool IsFrozen { get; private set; }

        public IReadOnlyList<BaselineArtifact> Artifacts
        {
            get
            {
                return _artifacts.AsReadOnly();
            }
        }

        public IReadOnlyList<BaselineAssembly> Assemblies
        {
            get
            {
                return _assemblies.AsReadOnly();
            }
        }

        public IReadOnlyList<BaselineNativeModule> NativeModules
        {
            get
            {
                return _nativeModules.AsReadOnly();
            }
        }

        public IReadOnlyList<BaselineProviderSummary> Providers
        {
            get
            {
                return _providers.AsReadOnly();
            }
        }

        public IReadOnlyList<string> IntegrityFailures
        {
            get
            {
                return _integrityFailures.AsReadOnly();
            }
        }

        public void AddArtifact(
            BaselineArtifact artifact)
        {
            EnsureNotFrozen();

            if (artifact == null)
            {
                return;
            }

            _artifacts.Add(
                artifact);
        }

        public void AddAssembly(
            BaselineAssembly assembly)
        {
            EnsureNotFrozen();

            if (assembly == null)
            {
                return;
            }

            _assemblies.Add(
                assembly);
        }

        public void AddNativeModule(
            BaselineNativeModule module)
        {
            EnsureNotFrozen();

            if (module == null)
            {
                return;
            }

            _nativeModules.Add(
                module);
        }

        public void AddProviderSummary(
            BaselineProviderSummary summary)
        {
            EnsureNotFrozen();

            if (summary == null)
            {
                return;
            }

            _providers.Add(
                summary);
        }

        public void AddIntegrityFailure(
            string failure)
        {
            EnsureNotFrozen();

            if (string.IsNullOrWhiteSpace(
                    failure))
            {
                return;
            }

            _integrityFailures.Add(
                failure);
        }

        public void Freeze()
        {
            IsFrozen = true;
        }

        private void EnsureNotFrozen()
        {
            if (IsFrozen)
            {
                throw new InvalidOperationException(
                    "HostBaseline is already frozen.");
            }
        }
    }

    public sealed class BaselineArtifact
    {
        public string ModId { get; set; }

        public string ArtifactId { get; set; }

        public string FileName { get; set; }

        public string RelativePath { get; set; }

        public long FileSize { get; set; }

        public string Sha256 { get; set; }

        public string AssemblyFullName { get; set; }

        public string AssemblyName { get; set; }

        public string AssemblyVersion { get; set; }

        public string AssemblyLocation { get; set; }

        public bool IsLoaded { get; set; }

        public List<string> Dependencies { get; set; } =
            new List<string>();

        public List<string> PolicyFlags { get; set; } =
            new List<string>();
    }

    public sealed class BaselineAssembly
    {
        public string FullName { get; set; }

        public string Name { get; set; }

        public string Version { get; set; }

        public string Location { get; set; }

        public string RelativePath { get; set; }

        public string Sha256 { get; set; }

        public bool HasPhysicalLocation { get; set; }

        public bool IsLoaded { get; set; }

        public bool IsModAssembly { get; set; }

        public string ModId { get; set; }

        public string ArtifactId { get; set; }
    }

    public sealed class BaselineNativeModule
    {
        public string Name { get; set; }

        public string Path { get; set; }

        public string RelativePath { get; set; }

        public long FileSize { get; set; }

        public string Sha256 { get; set; }

        public string Classification { get; set; }

        public bool IsSecurityRelevant { get; set; }
    }

    public sealed class BaselineProviderSummary
    {
        public string ProviderName { get; set; }

        public string Status { get; set; }

        public bool Complete { get; set; }

        public int FindingCount { get; set; }

        public int FailureCount { get; set; }

        public DateTime CompletedAtUtc { get; set; }
    }
}
