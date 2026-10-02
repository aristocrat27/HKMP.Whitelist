using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using HKMP.Whitelist.Core;
using HKMP.Whitelist.Shared;
using Newtonsoft.Json;

namespace HKMP.Whitelist.Server
{
    public sealed class SessionAuditStore
    {
        private readonly object _sync =
            new object();

        private readonly string _baseDirectory;

        private string _sessionId;
        private string _baselineId;
        private DateTime _sessionCreatedUtc;
        private DateTime _lastUpdatedUtc;
        private bool _locked;
        private DateTime? _lockedUtc;
        private string _status;
        private string _lastEventId;
        private SecurityEventType? _lastEventType;
        private DateTime? _lastEventUtc;
        private string _presetName;
        private SecurityMode _securityMode;

        private HostBaseline _baseline;

        private readonly Dictionary<string, ParticipantSnapshot>
            _participants =
                new Dictionary<string, ParticipantSnapshot>(
                    StringComparer.OrdinalIgnoreCase);

        private readonly Dictionary<SecurityEventType, int>
            _eventCounts =
                new Dictionary<SecurityEventType, int>();

        public SessionAuditStore(
            string baseDirectory)
        {
            _baseDirectory =
                string.IsNullOrWhiteSpace(
                    baseDirectory)
                    ? null
                    : baseDirectory.Trim();
        }

        public void Initialize(
            HostSecurityService securityService,
            HostBaseline baseline,
            PresetConfig preset)
        {
            if (securityService == null ||
                baseline == null)
            {
                return;
            }

            lock (_sync)
            {
                _sessionId =
                    baseline.SessionId;

                _baselineId =
                    baseline.BaselineId;

                _sessionCreatedUtc =
                    securityService.CreatedAtUtc == default(DateTime)
                        ? DateTime.UtcNow
                        : securityService.CreatedAtUtc;

                _lastUpdatedUtc =
                    DateTime.UtcNow;

                _presetName =
                    preset == null
                        ? null
                        : preset.PresetName;

                _securityMode =
                    preset == null
                        ? SecurityMode.Maximum
                        : preset.SecurityMode;

                _locked =
                    securityService.IsProtected;

                _lockedUtc =
                    securityService.LockedAtUtc;

                _status =
                    securityService.IsProtected
                        ? "Locked"
                        : "Open";

                _lastEventId = null;
                _lastEventType = null;
                _lastEventUtc = null;

                _baseline =
                    baseline;

                _participants.Clear();
                _eventCounts.Clear();

                foreach (ParticipantSession participant
                         in securityService.GetParticipants())
                {
                    UpsertParticipantInternal(
                        participant,
                        null);
                }

                WriteAllInternal();
            }
        }

        public void UpdateBaseline(
            HostBaseline baseline)
        {
            if (baseline == null)
            {
                return;
            }

            lock (_sync)
            {
                if (!string.IsNullOrWhiteSpace(_sessionId) &&
                    !string.Equals(
                        _sessionId,
                        baseline.SessionId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                _sessionId =
                    baseline.SessionId;

                _baselineId =
                    baseline.BaselineId;

                _baseline =
                    baseline;

                _lastUpdatedUtc =
                    DateTime.UtcNow;

                WriteBaselineInternal();
                WriteParticipantsInternal();
                WriteSessionInternal();
            }
        }

        public void HandleEvent(
            SecurityEvent securityEvent)
        {
            if (securityEvent == null)
            {
                return;
            }

            lock (_sync)
            {
                if (string.IsNullOrWhiteSpace(
                        _sessionId) &&
                    !string.IsNullOrWhiteSpace(
                        securityEvent.SessionId))
                {
                    _sessionId =
                        securityEvent.SessionId;
                }

                if (!string.IsNullOrWhiteSpace(
                        securityEvent.SessionId) &&
                    !string.Equals(
                        _sessionId,
                        securityEvent.SessionId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                _lastEventId =
                    securityEvent.EventId;

                _lastEventType =
                    securityEvent.EventType;

                _lastEventUtc =
                    securityEvent.TimestampUtc;

                UpdateStatusFromEvent(
                    securityEvent);

                int count;

                if (!_eventCounts.TryGetValue(
                        securityEvent.EventType,
                        out count))
                {
                    count = 0;
                }

                _eventCounts[
                    securityEvent.EventType] =
                    count + 1;

                _lastUpdatedUtc =
                    DateTime.UtcNow;

                if (securityEvent.EventType ==
                    SecurityEventType.SessionEnded)
                {
                    _lastUpdatedUtc =
                        securityEvent.TimestampUtc;
                }

                WriteSessionInternal();
            }
        }

        public void RefreshParticipants(
            IEnumerable<ParticipantSession> participants)
        {
            if (participants == null)
            {
                return;
            }

            lock (_sync)
            {
                if (string.IsNullOrWhiteSpace(_sessionId))
                {
                    return;
                }

                foreach (ParticipantSession participant
                         in participants)
                {
                    if (participant == null ||
                        !string.Equals(
                            _sessionId,
                            participant.SessionId,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    UpsertParticipantInternal(
                        participant,
                        null);
                }

                _lastUpdatedUtc =
                    DateTime.UtcNow;

                WriteParticipantsInternal();
                WriteSessionInternal();
            }
        }

        public void RecordParticipant(
            ParticipantSession participant,
            SecurityReport report)
        {
            if (participant == null)
            {
                return;
            }

            lock (_sync)
            {
                if (string.IsNullOrWhiteSpace(
                        _sessionId))
                {
                    return;
                }

                if (report != null &&
                    !string.IsNullOrWhiteSpace(
                        report.SessionId) &&
                    !string.Equals(
                        _sessionId,
                        report.SessionId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                UpsertParticipantInternal(
                    participant,
                    report);

                _lastUpdatedUtc =
                    DateTime.UtcNow;

                WriteParticipantsInternal();
                WriteSessionInternal();
            }
        }


        private void UpsertParticipantInternal(
            ParticipantSession participant,
            SecurityReport report)
        {
            if (participant == null ||
                string.IsNullOrWhiteSpace(
                    participant.IdentityKey))
            {
                return;
            }

            ParticipantSnapshot snapshot;

            if (!_participants.TryGetValue(
                    participant.IdentityKey,
                    out snapshot) ||
                snapshot == null)
            {
                snapshot =
                    new ParticipantSnapshot();

                _participants[
                    participant.IdentityKey] =
                    snapshot;
            }

            snapshot.Player =
                new ParticipantInfo
                {
                    IdentityKey =
                        participant.IdentityKey,

                    PlayerId =
                        participant.PlayerId,

                    DisplayName =
                        participant.DisplayName,

                    State =
                        participant.State.ToString(),

                    IsConnected =
                        participant.IsConnected,

                    IsVerified =
                        participant.IsVerified,

                    IsActive =
                        participant.State ==
                        ParticipantState.Active,

                    IsLockedMember =
                        participant.WasMemberWhenLocked,

                    FirstSeenUtc =
                        participant.FirstSeenUtc,

                    LastSeenUtc =
                        participant.LastSeenUtc,

                    LastVerifiedUtc =
                        participant.LastVerifiedUtc,

                    LastDisconnectedUtc =
                        participant.LastDisconnectedUtc,

                    VerificationGeneration =
                        participant.VerificationGeneration,

                    ReconnectCount =
                        participant.ReconnectCount,

                    WasMemberWhenLocked =
                        participant.WasMemberWhenLocked,

                    LastBaselineId =
                        participant.LastBaselineId,

                    LastRejectionCode =
                        participant.LastRejectionCode,

                    LastRejectionReason =
                        participant.LastRejectionReason
                };

            if (report != null)
            {
                snapshot.LatestSoftwareState =
                    BuildSoftwareState(
                        report);
            }
        }

        private static ParticipantSoftwareState
            BuildSoftwareState(
                SecurityReport report)
        {
            if (report == null)
            {
                return null;
            }

            SecurityEvidence evidence =
                report.Evidence;

            return
                new ParticipantSoftwareState
                {
                    ProtocolVersion =
                        report.ProtocolVersion,

                    SessionId =
                        report.SessionId,

                    BaselineId =
                        evidence == null
                            ? null
                            : evidence.BaselineId,

                    ManifestId =
                        report.ManifestId,

                    ManifestVersion =
                        report.ManifestVersion,

                    WhitelistVersion =
                        report.WhitelistVersion,

                    ScanStatus =
                        report.ScanStatus,

                    ScanTimestampUtc =
                        report.ScanTimestampUtc,

                    ScanDurationMs =
                        report.ScanDurationMs,

                    SelfHash =
                        report.SelfHash,

                    DebuggerDetected =
                        report.DebuggerDetected,

                    TrustedModIds =
                        report.TrustedModIds == null
                            ? new List<string>()
                            : report.TrustedModIds.ToList(),

                    ModArtifacts =
                        report.ModArtifacts == null
                            ? new List<ModArtifactScanEntry>()
                            : report.ModArtifacts.ToList(),

                    Artifacts =
                        evidence == null ||
                        evidence.Artifacts == null
                            ? new List<ArtifactEvidence>()
                            : evidence.Artifacts.ToList(),

                    Assemblies =
                        evidence == null ||
                        evidence.Assemblies == null
                            ? new List<AssemblyEvidence>()
                            : evidence.Assemblies.ToList(),

                    NativeModules =
                        evidence == null ||
                        evidence.NativeModules == null
                            ? new List<NativeModuleEvidence>()
                            : evidence.NativeModules.ToList(),

                    HarmonyPatches =
                        evidence == null ||
                        evidence.HarmonyPatches == null
                            ? new List<HarmonyEvidence>()
                            : evidence.HarmonyPatches.ToList(),

                    CoreIntegrity =
                        evidence == null ||
                        evidence.CoreIntegrity == null
                            ? new List<CoreIntegrityEvidence>()
                            : evidence.CoreIntegrity.ToList(),

                    RuntimeEvents =
                        evidence == null ||
                        evidence.RuntimeEvents == null
                            ? new List<RuntimeEvidence>()
                            : evidence.RuntimeEvents.ToList(),

                    SaveEvents =
                        evidence == null ||
                        evidence.SaveEvents == null
                            ? new List<SaveEvidence>()
                            : evidence.SaveEvents.ToList(),

                    UnknownFiles =
                        report.UnknownFiles == null
                            ? new List<FileScanEntry>()
                            : report.UnknownFiles.ToList(),

                    ForbiddenFiles =
                        report.ForbiddenFiles == null
                            ? new List<FileScanEntry>()
                            : report.ForbiddenFiles.ToList(),

                    UnknownAssemblies =
                        report.UnknownAssemblies == null
                            ? new List<AssemblyScanEntry>()
                            : report.UnknownAssemblies.ToList(),

                    UnknownNativeModules =
                        report.UnknownNativeModules == null
                            ? new List<NativeModuleScanEntry>()
                            : report.UnknownNativeModules.ToList(),

                    IntegrityFailures =
                        report.IntegrityFailures == null
                            ? new List<string>()
                            : report.IntegrityFailures.ToList(),

                    UnreadableFiles =
                        report.UnreadableFiles == null
                            ? new List<string>()
                            : report.UnreadableFiles.ToList(),

                    ProtocolViolations =
                        evidence == null ||
                        evidence.ProtocolViolations == null
                            ? new List<string>()
                            : evidence.ProtocolViolations.ToList(),

                    RuntimeEventSummary =
                        report.RuntimeEvents == null
                            ? new List<string>()
                            : report.RuntimeEvents.ToList()
                };
        }

        private void UpdateStatusFromEvent(
            SecurityEvent securityEvent)
        {
            if (securityEvent == null)
            {
                return;
            }

            switch (securityEvent.EventType)
            {
                case SecurityEventType.HostStarted:
                    _status = "Open";
                    break;

                case SecurityEventType.HostBaselineFinalizing:
                    _status = "FinalizingBaseline";
                    break;

                case SecurityEventType.HostBaselineFrozen:
                case SecurityEventType.MembershipLocked:
                    _status = "Locked";
                    _locked = true;
                    _lockedUtc =
                        securityEvent.TimestampUtc;
                    break;

                case SecurityEventType.SessionInvalidated:
                    _status = "Invalidated";
                    break;

                case SecurityEventType.SessionEnded:
                    _status = "Ended";
                    break;
            }
        }

        private void WriteAllInternal()
        {
            WriteSessionInternal();
            WriteBaselineInternal();
            WriteParticipantsInternal();
        }

        private void WriteSessionInternal()
        {
            string directory =
                GetSessionDirectory();

            if (directory == null)
            {
                return;
            }

            List<string> connectedPlayers =
                _participants.Values
                    .Where(
                        x =>
                            x != null &&
                            x.Player != null &&
                            x.Player.IsConnected)
                    .Select(
                        x =>
                            x.Player.DisplayName)
                    .Where(
                        x =>
                            !string.IsNullOrWhiteSpace(x))
                    .Distinct(
                        StringComparer.OrdinalIgnoreCase)
                    .OrderBy(
                        x =>
                            x,
                        StringComparer.OrdinalIgnoreCase)
                    .ToList();

            List<string> activePlayers =
                _participants.Values
                    .Where(
                        x =>
                            x != null &&
                            x.Player != null &&
                            x.Player.IsActive)
                    .Select(
                        x =>
                            x.Player.DisplayName)
                    .Where(
                        x =>
                            !string.IsNullOrWhiteSpace(x))
                    .Distinct(
                        StringComparer.OrdinalIgnoreCase)
                    .OrderBy(
                        x =>
                            x,
                        StringComparer.OrdinalIgnoreCase)
                    .ToList();

            List<string> rejectedPlayers =
                _participants.Values
                    .Where(
                        x =>
                            x != null &&
                            x.Player != null &&
                            string.Equals(
                                x.Player.State,
                                ParticipantState.Rejected.ToString(),
                                StringComparison.OrdinalIgnoreCase))
                    .Select(
                        x =>
                            x.Player.DisplayName)
                    .Where(
                        x =>
                            !string.IsNullOrWhiteSpace(x))
                    .Distinct(
                        StringComparer.OrdinalIgnoreCase)
                    .OrderBy(
                        x =>
                            x,
                        StringComparer.OrdinalIgnoreCase)
                    .ToList();

            SessionSnapshot snapshot =
                new SessionSnapshot
                {
                    SessionId =
                        _sessionId,

                    BaselineId =
                        _baselineId,

                    PresetName =
                        _presetName,

                    SecurityMode =
                        _securityMode.ToString(),

                    Status =
                        _status ?? "Unknown",

                    LastEventId =
                        _lastEventId,

                    LastEventType =
                        _lastEventType.HasValue
                            ? _lastEventType.Value.ToString()
                            : null,

                    LastEventUtc =
                        _lastEventUtc,

                    SessionCreatedUtc =
                        _sessionCreatedUtc,

                    LastUpdatedUtc =
                        _lastUpdatedUtc,

                    Locked =
                        _locked,

                    LockedUtc =
                        _lockedUtc,

                    ParticipantCount =
                        _participants.Count,

                    ConnectedPlayerCount =
                        connectedPlayers.Count,

                    ActivePlayerCount =
                        activePlayers.Count,

                    VerifiedPlayerCount =
                        _participants.Values.Count(
                            x =>
                                x != null &&
                                x.Player != null &&
                                x.Player.IsVerified),

                    DisconnectedPlayerCount =
                        _participants.Values.Count(
                            x =>
                                x != null &&
                                x.Player != null &&
                                !x.Player.IsConnected &&
                                !string.Equals(
                                    x.Player.State,
                                    ParticipantState.Rejected.ToString(),
                                    StringComparison.OrdinalIgnoreCase)),

                    RejectedPlayerCount =
                        rejectedPlayers.Count,

                    ConnectedPlayers =
                        connectedPlayers,

                    ActivePlayers =
                        activePlayers,

                    RejectedPlayers =
                        rejectedPlayers,

                    EventCounts =
                        _eventCounts
                            .OrderBy(
                                x =>
                                    x.Key.ToString(),
                                StringComparer.Ordinal)
                            .ToDictionary(
                                x =>
                                    x.Key.ToString(),
                                x =>
                                    x.Value)
                };

            WriteJson(
                Path.Combine(
                    directory,
                    "session.json"),
                snapshot);
        }

        private void WriteBaselineInternal()
        {
            if (_baseline == null)
            {
                return;
            }

            string directory =
                GetSessionDirectory();

            if (directory == null)
            {
                return;
            }

            WriteJson(
                Path.Combine(
                    directory,
                    "baseline.json"),
                _baseline);
        }

        private void WriteParticipantsInternal()
        {
            string directory =
                GetSessionDirectory();

            if (directory == null)
            {
                return;
            }

            List<ParticipantSnapshot> players =
                _participants.Values
                    .Where(
                        x =>
                            x != null &&
                            x.Player != null)
                    .OrderBy(
                        x =>
                            x.Player.DisplayName,
                        StringComparer.OrdinalIgnoreCase)
                    .ThenBy(
                        x =>
                            x.Player.IdentityKey,
                        StringComparer.Ordinal)
                    .ToList();

            ParticipantsSnapshot snapshot =
                new ParticipantsSnapshot
                {
                    SessionId =
                        _sessionId,

                    BaselineId =
                        _baselineId,

                    GeneratedAtUtc =
                        DateTime.UtcNow,

                    Players =
                        players
                };

            WriteJson(
                Path.Combine(
                    directory,
                    "participants.json"),
                snapshot);
        }

        private string GetSessionDirectory()
        {
            if (string.IsNullOrWhiteSpace(
                    _baseDirectory) ||
                string.IsNullOrWhiteSpace(
                    _sessionId))
            {
                return null;
            }

            string safeSessionId =
                SanitizePathSegment(
                    _sessionId);

            if (string.IsNullOrWhiteSpace(
                    safeSessionId))
            {
                return null;
            }

            try
            {
                string directory =
                    Path.Combine(
                        _baseDirectory,
                        "sessions",
                        safeSessionId);

                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                return directory;
            }
            catch
            {
                return null;
            }
        }

        private static void WriteJson(
            string path,
            object value)
        {
            if (string.IsNullOrWhiteSpace(path) ||
                value == null)
            {
                return;
            }

            try
            {
                string directory =
                    Path.GetDirectoryName(path);

                if (!string.IsNullOrWhiteSpace(directory) &&
                    !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                string json =
                    JsonConvert.SerializeObject(
                        value,
                        Formatting.Indented);

                string temporary =
                    path +
                    ".tmp";

                File.WriteAllText(
                    temporary,
                    json);

                if (File.Exists(path))
                {
                    try
                    {
                        File.Replace(
                            temporary,
                            path,
                            null);
                    }
                    catch
                    {
                        File.Delete(path);
                        File.Move(
                            temporary,
                            path);
                    }
                }
                else
                {
                    File.Move(
                        temporary,
                        path);
                }
            }
            catch
            {
                try
                {
                    string temporary =
                        path +
                        ".tmp";

                    if (File.Exists(temporary))
                    {
                        File.Delete(temporary);
                    }
                }
                catch
                {
                }
            }
        }

        private static string SanitizePathSegment(
            string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            char[] invalid =
                Path.GetInvalidFileNameChars();

            string result =
                new string(
                    value
                        .Trim()
                        .Select(
                            c =>
                                invalid.Contains(c)
                                    ? '_'
                                    : c)
                        .ToArray());

            if (result == "." ||
                result == "..")
            {
                return null;
            }

            return result;
        }

        private sealed class SessionSnapshot
        {
            public string SessionId { get; set; }
            public string BaselineId { get; set; }
            public string PresetName { get; set; }
            public string SecurityMode { get; set; }
            public string Status { get; set; }
            public string LastEventId { get; set; }
            public string LastEventType { get; set; }
            public DateTime? LastEventUtc { get; set; }
            public DateTime SessionCreatedUtc { get; set; }
            public DateTime LastUpdatedUtc { get; set; }
            public bool Locked { get; set; }
            public DateTime? LockedUtc { get; set; }
            public int ParticipantCount { get; set; }
            public int ConnectedPlayerCount { get; set; }
            public int ActivePlayerCount { get; set; }
            public int VerifiedPlayerCount { get; set; }
            public int DisconnectedPlayerCount { get; set; }
            public int RejectedPlayerCount { get; set; }
            public List<string> ConnectedPlayers { get; set; }
            public List<string> ActivePlayers { get; set; }
            public List<string> RejectedPlayers { get; set; }
            public Dictionary<string, int> EventCounts { get; set; }
        }

        private sealed class ParticipantsSnapshot
        {
            public string SessionId { get; set; }
            public string BaselineId { get; set; }
            public DateTime GeneratedAtUtc { get; set; }
            public List<ParticipantSnapshot> Players { get; set; }
        }

        private sealed class ParticipantSnapshot
        {
            public ParticipantInfo Player { get; set; }
            public ParticipantSoftwareState LatestSoftwareState { get; set; }
        }

        private sealed class ParticipantInfo
        {
            public string IdentityKey { get; set; }
            public ushort PlayerId { get; set; }
            public string DisplayName { get; set; }
            public string State { get; set; }
            public bool IsConnected { get; set; }
            public bool IsVerified { get; set; }
            public bool IsActive { get; set; }
            public bool IsLockedMember { get; set; }
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public DateTime LastVerifiedUtc { get; set; }
            public DateTime LastDisconnectedUtc { get; set; }
            public int VerificationGeneration { get; set; }
            public int ReconnectCount { get; set; }
            public bool WasMemberWhenLocked { get; set; }
            public string LastBaselineId { get; set; }
            public string LastRejectionCode { get; set; }
            public string LastRejectionReason { get; set; }
        }

        private sealed class ParticipantSoftwareState
        {
            public int ProtocolVersion { get; set; }
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
            public List<string> TrustedModIds { get; set; }
            public List<ModArtifactScanEntry> ModArtifacts { get; set; }
            public List<ArtifactEvidence> Artifacts { get; set; }
            public List<AssemblyEvidence> Assemblies { get; set; }
            public List<NativeModuleEvidence> NativeModules { get; set; }
            public List<HarmonyEvidence> HarmonyPatches { get; set; }
            public List<CoreIntegrityEvidence> CoreIntegrity { get; set; }
            public List<RuntimeEvidence> RuntimeEvents { get; set; }
            public List<SaveEvidence> SaveEvents { get; set; }
            public List<FileScanEntry> UnknownFiles { get; set; }
            public List<FileScanEntry> ForbiddenFiles { get; set; }
            public List<AssemblyScanEntry> UnknownAssemblies { get; set; }
            public List<NativeModuleScanEntry> UnknownNativeModules { get; set; }
            public List<string> IntegrityFailures { get; set; }
            public List<string> UnreadableFiles { get; set; }
            public List<string> ProtocolViolations { get; set; }
            public List<string> RuntimeEventSummary { get; set; }
        }
    }
}
