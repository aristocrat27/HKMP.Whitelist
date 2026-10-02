using System;

namespace HKMP.Whitelist.Shared
{
    public enum ViolationType
    {
        UnknownMod,
        ForbiddenMod,
        HashMismatch,
        VersionMismatch,
        AssemblyMismatch,
        PathMismatch,
        UnknownAssembly,
        UnknownNativeModule,
        HarmonyMismatch,
        IntegrityFailure,
        Unreadable,
        RuntimeArtifactAdded,
        HostIntegrityChanged,
        SaveIntegrityViolation,
        ChallengeFailure,
        ProtocolViolation
    }

    public enum ViolationClassification
    {
        Unknown,
        Candidate,
        Benign,
        Forbidden,
        KnownCheat,
        FalsePositive
    }

    public sealed class ObservedViolation
    {
        public string ObservationId { get; set; }

        public string SessionId { get; set; }

        public string FirstSessionId { get; set; }

        public string LastSessionId { get; set; }

        public int SessionCount { get; set; }

        public string PlayerIdentityKey { get; set; }

        public string DisplayName { get; set; }

        public string ModId { get; set; }

        public string ArtifactId { get; set; }

        public string FileName { get; set; }

        public string Path { get; set; }

        public string Version { get; set; }

        public string AssemblyFullName { get; set; }

        public string Sha256 { get; set; }

        public ViolationType ViolationType { get; set; }

        public SecuritySeverity Severity { get; set; }

        public DateTime FirstSeenUtc { get; set; }

        public DateTime LastSeenUtc { get; set; }

        public int SeenCount { get; set; }

        public string FirstPlayer { get; set; }

        public string LastPlayer { get; set; }

        public string Notes { get; set; }

        public ViolationClassification Classification { get; set; }

        public ObservedViolation()
        {
            ObservationId =
                Guid.NewGuid().ToString("N");

            FirstSeenUtc =
                DateTime.UtcNow;

            LastSeenUtc =
                FirstSeenUtc;

            SeenCount =
                1;

            SessionCount =
                1;

            Classification =
                ViolationClassification.Unknown;
        }

        public void RegisterObservation(
            DateTime utcNow,
            string playerIdentityKey,
            string displayName)
        {
            DateTime normalized =
                NormalizeUtc(
                    utcNow);

            if (SeenCount <= 0)
            {
                SeenCount = 1;
            }
            else
            {
                SeenCount++;
            }

            LastSeenUtc =
                normalized;

            if (!string.IsNullOrWhiteSpace(
                playerIdentityKey))
            {
                LastPlayer =
                    playerIdentityKey.Trim();
            }

            if (!string.IsNullOrWhiteSpace(
                displayName))
            {
                DisplayName =
                    displayName.Trim();
            }
        }

        public void SetClassification(
            ViolationClassification classification)
        {
            Classification =
                classification;
        }

        private static DateTime NormalizeUtc(
            DateTime value)
        {
            if (value.Kind ==
                DateTimeKind.Utc)
            {
                return value;
            }

            return value.ToUniversalTime();
        }
    }
}
