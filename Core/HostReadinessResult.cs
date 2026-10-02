using HKMP.Whitelist.Shared;
using System.Collections.Generic;

namespace HKMP.Whitelist.Core
{
    public enum HostExecutionMode
    {
        InGameHost,
        StandaloneServer,
        Unsupported
    }

    public sealed class HostReadinessResult
    {
        private readonly List<string> _warnings =
            new List<string>();

        private readonly List<BaselineProviderSummary>
            _providerStatusSummary =
                new List<BaselineProviderSummary>();

        public HostExecutionMode ExecutionMode { get; internal set; }

        public string GameRoot { get; internal set; }

        public string ManagedRoot { get; internal set; }

        public string AssemblyCSharpPath { get; internal set; }

        public bool AssemblyCSharpPresent { get; internal set; }

        public bool HkmpAssemblyPresent { get; internal set; }

        public string HkmpAssemblyPath { get; internal set; }

        public bool WhitelistAssemblyPresent { get; internal set; }

        public string WhitelistAssemblyPath { get; internal set; }

        public bool IsUnityGameProcess { get; internal set; }

        public bool InitialScanStarted { get; internal set; }

        public bool InitialScanCompleted { get; internal set; }

        public bool BaselineCreated { get; internal set; }

        public bool BaselineComplete { get; internal set; }

        public bool BaselineValid { get; internal set; }

        public string FailureCode { get; internal set; }

        public string FailureDetails { get; internal set; }

        public long ScanDurationMs { get; internal set; }

        public int LoadedAssemblyCount { get; internal set; }

        public int InstalledArtifactCount { get; internal set; }

        public int SecurityRelevantNativeModuleCount { get; internal set; }

        public IReadOnlyList<BaselineProviderSummary> ProviderStatusSummary
        {
            get
            {
                return _providerStatusSummary.AsReadOnly();
            }
        }

        public IReadOnlyList<string> Warnings
        {
            get
            {
                return _warnings.AsReadOnly();
            }
        }

        public bool IsReady
        {
            get
            {
                return
                    ExecutionMode ==
                        HostExecutionMode.InGameHost &&
                    IsUnityGameProcess &&
                    AssemblyCSharpPresent &&
                    HkmpAssemblyPresent &&
                    WhitelistAssemblyPresent &&
                    !string.IsNullOrWhiteSpace(GameRoot) &&
                    !string.IsNullOrWhiteSpace(ManagedRoot) &&
                    string.IsNullOrWhiteSpace(FailureCode);
            }
        }

        internal void AddWarning(
            string warning)
        {
            if (!string.IsNullOrWhiteSpace(warning))
            {
                _warnings.Add(warning);
            }
        }

        internal void SetProviderStatusSummary(
            IEnumerable<BaselineProviderSummary> summaries)
        {
            _providerStatusSummary.Clear();

            if (summaries == null)
            {
                return;
            }

            foreach (BaselineProviderSummary summary in summaries)
            {
                if (summary == null)
                {
                    continue;
                }

                _providerStatusSummary.Add(
                    new BaselineProviderSummary
                    {
                        ProviderName = summary.ProviderName,
                        Status = summary.Status,
                        Complete = summary.Complete,
                        FindingCount = summary.FindingCount,
                        FailureCount = summary.FailureCount,
                        CompletedAtUtc = summary.CompletedAtUtc
                    });
            }
        }

        internal void SetFailure(
            string code,
            string details)
        {
            if (string.IsNullOrWhiteSpace(FailureCode))
            {
                FailureCode = code;
                FailureDetails = details;
            }
        }
    }
}