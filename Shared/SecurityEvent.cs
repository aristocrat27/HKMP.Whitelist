using System;
using System.Globalization;

namespace HKMP.Whitelist.Shared
{
    public enum SecurityEventType
    {
        HostStarted,
        HostInitialScanStarted,
        HostInitialScanCompleted,
        HostBaselineFinalizing,
        HostBaselineFrozen,
        HostIntegrityChanged,
        SessionStarted,
        SessionInvalidated,
        SessionEnded,

        PlayerConnected,
        PlayerScanStarted,
        PlayerScanCompleted,
        PlayerVerified,
        PlayerRejected,
        PlayerDisconnected,
        PlayerReconnected,

        MembershipLocked,

        ArtifactMismatch,
        UnknownArtifact,
        ForbiddenArtifact,
        RuntimeChangeDetected,
        SaveChangeDetected,

        ChallengeIssued,
        ChallengeAccepted,
        ChallengeRejected,

        ProtocolViolation
    }

    public enum SecuritySeverity
    {
        Info,
        Warning,
        High,
        Critical
    }

    public sealed class SecurityEvent
    {
        public string EventId { get; private set; }

        public DateTime TimestampUtc { get; private set; }

        public string SessionId { get; private set; }

        public SecurityEventType EventType { get; private set; }

        public SecuritySeverity Severity { get; private set; }

        public string PlayerIdentityKey { get; private set; }

        public string DisplayName { get; private set; }

        public string EvidenceSummary { get; private set; }

        public string ProviderName { get; private set; }

        public string Message { get; private set; }

        public SecurityEvent()
        {
            EventId =
                Guid.NewGuid().ToString("N");

            TimestampUtc =
                DateTime.UtcNow;

            EventType =
                SecurityEventType.ProtocolViolation;

            Severity =
                SecuritySeverity.Info;
        }

        public SecurityEvent(
            SecurityEventType eventType,
            SecuritySeverity severity,
            string sessionId,
            string message)
        {
            EventId =
                Guid.NewGuid().ToString("N");

            TimestampUtc =
                DateTime.UtcNow;

            EventType =
                eventType;

            Severity =
                severity;

            SessionId =
                sessionId;

            Message =
                message;
        }

        public SecurityEvent(
            SecurityEventType eventType,
            SecuritySeverity severity,
            string sessionId,
            string playerIdentityKey,
            string displayName,
            string message,
            string evidenceSummary,
            string providerName)
        {
            EventId =
                Guid.NewGuid().ToString("N");

            TimestampUtc =
                DateTime.UtcNow;

            EventType =
                eventType;

            Severity =
                severity;

            SessionId =
                sessionId;

            PlayerIdentityKey =
                playerIdentityKey;

            DisplayName =
                displayName;

            Message =
                message;

            EvidenceSummary =
                evidenceSummary;

            ProviderName =
                providerName;
        }

        public static SecurityEvent CreateHostEvent(
            SecurityEventType eventType,
            string sessionId,
            SecuritySeverity severity,
            string message)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                SessionId =
                    sessionId,

                EventType =
                    eventType,

                Severity =
                    severity,

                Message =
                    message
            };
        }

        public static SecurityEvent CreateHostEvent(
            string eventName,
            SecurityEventType eventType,
            SecuritySeverity severity,
            string message)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                EventType =
                    eventType,

                Severity =
                    severity,

                Message =
                    message
            };
        }

        public static SecurityEvent CreateHostEvent(
            SecurityEventType eventType,
            string sessionId,
            string message,
            SecuritySeverity severity)
        {
            return CreateHostEvent(
                eventType,
                sessionId,
                severity,
                message);
        }

        public static SecurityEvent CreateHostEvent(
            string eventName,
            string sessionId,
            SecurityEventType eventType,
            SecuritySeverity severity,
            string message)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                SessionId =
                    sessionId,

                EventType =
                    eventType,

                Severity =
                    severity,

                Message =
                    message
            };
        }

        public static SecurityEvent CreateHostEvent(
            SecurityEventType eventType,
            string sessionId,
            SecuritySeverity severity,
            string message,
            string providerName)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                SessionId =
                    sessionId,

                EventType =
                    eventType,

                Severity =
                    severity,

                Message =
                    message,

                ProviderName =
                    providerName
            };
        }

        public static SecurityEvent CreateHostEvent(
            string eventName,
            string sessionId,
            SecurityEventType eventType,
            SecuritySeverity severity,
            string message,
            string providerName)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                SessionId =
                    sessionId,

                EventType =
                    eventType,

                Severity =
                    severity,

                Message =
                    message,

                ProviderName =
                    providerName
            };
        }

        public static SecurityEvent CreateHostEvent(
            SecurityEventType eventType,
            string sessionId,
            string message,
            SecuritySeverity severity,
            string providerName)
        {
            return CreateHostEvent(
                eventType,
                sessionId,
                severity,
                message,
                providerName);
        }

        public static SecurityEvent CreatePlayerEvent(
            SecurityEventType eventType,
            SecuritySeverity severity,
            string sessionId,
            string playerIdentityKey,
            string displayName,
            string message)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                SessionId =
                    sessionId,

                EventType =
                    eventType,

                Severity =
                    severity,

                PlayerIdentityKey =
                    playerIdentityKey,

                DisplayName =
                    displayName,

                Message =
                    message
            };
        }

        public static SecurityEvent CreatePlayerEvent(
            SecurityEventType eventType,
            string sessionId,
            string playerIdentityKey,
            string displayName,
            SecuritySeverity severity,
            string message)
        {
            return CreatePlayerEvent(
                eventType,
                severity,
                sessionId,
                playerIdentityKey,
                displayName,
                message);
        }

        public static SecurityEvent CreateArtifactEvent(
            SecurityEventType eventType,
            SecuritySeverity severity,
            string sessionId,
            string playerIdentityKey,
            string displayName,
            string message,
            string evidenceSummary)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                SessionId =
                    sessionId,

                EventType =
                    eventType,

                Severity =
                    severity,

                PlayerIdentityKey =
                    playerIdentityKey,

                DisplayName =
                    displayName,

                Message =
                    message,

                EvidenceSummary =
                    evidenceSummary
            };
        }

        public static SecurityEvent CreateRuntimeEvent(
            SecurityEventType eventType,
            SecuritySeverity severity,
            string sessionId,
            string playerIdentityKey,
            string displayName,
            string message,
            string providerName)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                SessionId =
                    sessionId,

                EventType =
                    eventType,

                Severity =
                    severity,

                PlayerIdentityKey =
                    playerIdentityKey,

                DisplayName =
                    displayName,

                Message =
                    message,

                ProviderName =
                    providerName
            };
        }

        public static SecurityEvent CreateSaveEvent(
            SecurityEventType eventType,
            SecuritySeverity severity,
            string sessionId,
            string playerIdentityKey,
            string displayName,
            string message,
            string evidenceSummary)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                SessionId =
                    sessionId,

                EventType =
                    eventType,

                Severity =
                    severity,

                PlayerIdentityKey =
                    playerIdentityKey,

                DisplayName =
                    displayName,

                Message =
                    message,

                EvidenceSummary =
                    evidenceSummary
            };
        }

        public static SecurityEvent CreateChallengeEvent(
            SecurityEventType eventType,
            SecuritySeverity severity,
            string sessionId,
            string playerIdentityKey,
            string displayName,
            string message)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                SessionId =
                    sessionId,

                EventType =
                    eventType,

                Severity =
                    severity,

                PlayerIdentityKey =
                    playerIdentityKey,

                DisplayName =
                    displayName,

                Message =
                    message
            };
        }

        public static SecurityEvent CreateProtocolEvent(
            SecurityEventType eventType,
            SecuritySeverity severity,
            string sessionId,
            string playerIdentityKey,
            string displayName,
            string message)
        {
            return new SecurityEvent
            {
                EventId =
                    Guid.NewGuid().ToString("N"),

                TimestampUtc =
                    DateTime.UtcNow,

                SessionId =
                    sessionId,

                EventType =
                    eventType,

                Severity =
                    severity,

                PlayerIdentityKey =
                    playerIdentityKey,

                DisplayName =
                    displayName,

                Message =
                    message
            };
        }

        public void SetEvidence(
            string evidenceSummary)
        {
            EvidenceSummary =
                evidenceSummary;
        }

        public void SetProvider(
            string providerName)
        {
            ProviderName =
                providerName;
        }

        public void SetPlayer(
            string playerIdentityKey,
            string displayName)
        {
            PlayerIdentityKey =
                playerIdentityKey;

            DisplayName =
                displayName;
        }

        public override string ToString()
        {
            return
                "[" +
                TimestampUtc.ToString(
                    "o",
                    CultureInfo.InvariantCulture) +
                "] " +
                EventType +
                " / " +
                Severity +
                " / Session=" +
                (SessionId ?? "<none>") +
                " / Player=" +
                (PlayerIdentityKey ?? "<none>") +
                " / " +
                (Message ?? string.Empty);
        }
    }
}