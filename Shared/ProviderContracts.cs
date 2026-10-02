using System;

namespace HKMP.Whitelist.Shared
{
    public sealed class SecurityProviderContext
    {
        public string SessionId { get; set; }

        public string BaselineId { get; set; }

        public string ParticipantIdentity { get; set; }

        public bool IsHost { get; set; }

        public bool IsInitialHostScan { get; set; }

        public bool IsFinalHostScan { get; set; }

        public bool IsReconnect { get; set; }

        public DateTime UtcNow { get; set; }
    }

    public sealed class SecurityProviderResult
    {
        public string ProviderName { get; set; }

        public bool Complete { get; set; }

        public bool Passed { get; set; }

        public string Status { get; set; }

        public SecurityEvidence Evidence { get; set; }
    }

    public interface ISecurityProvider
    {
        string Name { get; }

        void Initialize(
            SecurityProviderContext context);

        void Shutdown();
    }

    public interface IInitialScanProvider
    {
        SecurityProviderResult ScanInitialHost(
            SecurityProviderContext context);
    }

    public interface IHostFinalScanProvider
    {
        SecurityProviderResult ScanFinalHost(
            SecurityProviderContext context);
    }

    public interface IParticipantScanProvider
    {
        SecurityProviderResult ScanParticipant(
            SecurityProviderContext context);
    }

    public interface IRuntimeProvider
    {
        void StartRuntimeMonitoring(
            SecurityProviderContext context);

        void StopRuntimeMonitoring();
    }

    public interface ISaveIntegrityProvider
    {
        SecurityProviderResult ScanSaveIntegrity(
            SecurityProviderContext context);
    }
}