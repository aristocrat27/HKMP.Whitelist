using System;
using System.Collections.Generic;
using System.Linq;
using HKMP.Whitelist.Shared;

namespace HKMP.Whitelist.Core
{
    public sealed class ParticipantRegistry
    {
        private readonly object _gate =
            new object();

        private readonly Dictionary<string, ParticipantSession>
            _participants =
                new Dictionary<string, ParticipantSession>(
                    StringComparer.OrdinalIgnoreCase);

        private string _sessionId;

        private string _baselineId;

        public string SessionId
        {
            get
            {
                lock (_gate)
                {
                    return _sessionId;
                }
            }
        }

        public string BaselineId
        {
            get
            {
                lock (_gate)
                {
                    return _baselineId;
                }
            }
        }

        public int Count
        {
            get
            {
                lock (_gate)
                {
                    return _participants.Count;
                }
            }
        }

        public IReadOnlyList<ParticipantSession> Participants
        {
            get
            {
                lock (_gate)
                {
                    return _participants.Values
                        .Where(
                            participant =>
                                participant != null)
                        .Select(
                            CloneParticipant)
                        .ToList()
                        .AsReadOnly();
                }
            }
        }

        public ParticipantRegistry()
        {
        }

        public ParticipantRegistry(
            string sessionId,
            string baselineId)
        {
            Configure(
                sessionId,
                baselineId);
        }

        public bool Configure(
            string sessionId,
            string baselineId)
        {
            if (string.IsNullOrWhiteSpace(
                    sessionId))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    baselineId))
            {
                return false;
            }

            lock (_gate)
            {
                if (_participants.Count > 0)
                {
                    return false;
                }

                _sessionId =
                    sessionId.Trim();

                _baselineId =
                    baselineId.Trim();

                return true;
            }
        }

        public bool SetSessionIdentity(
            string sessionId,
            string baselineId)
        {
            if (string.IsNullOrWhiteSpace(
                    sessionId))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    baselineId))
            {
                return false;
            }

            lock (_gate)
            {
                if (_participants.Count > 0)
                {
                    return
                        string.Equals(
                            _sessionId,
                            sessionId.Trim(),
                            StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(
                            _baselineId,
                            baselineId.Trim(),
                            StringComparison.OrdinalIgnoreCase);
                }

                _sessionId =
                    sessionId.Trim();

                _baselineId =
                    baselineId.Trim();

                return true;
            }
        }

        public bool RegisterParticipant(
            string identityKey,
            string displayName,
            DateTime utcNow,
            out ParticipantSession participant,
            out string reason)
        {
            return RegisterParticipant(
                identityKey,
                null,
                0,
                displayName,
                utcNow,
                out participant,
                out reason);
        }

        public bool RegisterParticipant(
            string identityKey,
            string playerKey,
            string displayName,
            DateTime utcNow,
            out ParticipantSession participant,
            out string reason)
        {
            return RegisterParticipant(
                identityKey,
                playerKey,
                0,
                displayName,
                utcNow,
                out participant,
                out reason);
        }

        public bool RegisterParticipant(
            string identityKey,
            string playerKey,
            ushort playerId,
            string displayName,
            DateTime utcNow,
            out ParticipantSession participant,
            out string reason)
        {
            participant =
                null;

            reason =
                null;

            string normalizedIdentity =
                NormalizeIdentity(
                    identityKey);

            if (normalizedIdentity == null)
            {
                reason =
                    "Participant identity is missing.";

                return false;
            }

            DateTime normalizedTime =
                NormalizeUtc(
                    utcNow);

            lock (_gate)
            {
                ParticipantSession existing;

                if (_participants.TryGetValue(
                        normalizedIdentity,
                        out existing) &&
                    existing != null)
                {
                    if (existing.State ==
                        ParticipantState.Disconnected)
                    {
                        existing.BeginReconnect(
                            playerId,
                            displayName,
                            normalizedTime);

                        if (!string.IsNullOrWhiteSpace(
                                playerKey))
                        {
                            existing.PlayerKey =
                                playerKey.Trim();
                        }

                        if (!string.IsNullOrWhiteSpace(
                                _sessionId))
                        {
                            existing.SessionId =
                                _sessionId;
                        }

                        participant =
                            CloneParticipant(
                                existing);

                        return true;
                    }

                    existing.UpdateConnection(
                        playerId,
                        displayName,
                        normalizedTime);

                    if (!string.IsNullOrWhiteSpace(
                            playerKey))
                    {
                        existing.PlayerKey =
                            playerKey.Trim();
                    }

                    participant =
                        CloneParticipant(
                            existing);

                    return true;
                }

                ParticipantSession created =
                    new ParticipantSession(
                        _sessionId,
                        normalizedIdentity,
                        playerId,
                        displayName,
                        normalizedTime);

                if (!string.IsNullOrWhiteSpace(
                        playerKey))
                {
                    created.PlayerKey =
                        playerKey.Trim();
                }

                created.LastBaselineId =
                    _baselineId;

                _participants.Add(
                    normalizedIdentity,
                    created);

                participant =
                    CloneParticipant(
                        created);

                return true;
            }
        }

        public bool TryGetParticipant(
            string identityKey,
            out ParticipantSession participant)
        {
            participant =
                null;

            string normalizedIdentity =
                NormalizeIdentity(
                    identityKey);

            if (normalizedIdentity == null)
            {
                return false;
            }

            lock (_gate)
            {
                ParticipantSession existing;

                if (!_participants.TryGetValue(
                        normalizedIdentity,
                        out existing) ||
                    existing == null)
                {
                    return false;
                }

                participant =
                    CloneParticipant(
                        existing);

                return true;
            }
        }

        public bool ContainsIdentity(
            string identityKey)
        {
            string normalizedIdentity =
                NormalizeIdentity(
                    identityKey);

            if (normalizedIdentity == null)
            {
                return false;
            }

            lock (_gate)
            {
                return _participants.ContainsKey(
                    normalizedIdentity);
            }
        }

        public bool MarkConnecting(
            string identityKey,
            ushort playerId,
            string displayName,
            DateTime utcNow)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            lock (_gate)
            {
                participant.UpdateConnection(
                    playerId,
                    displayName,
                    NormalizeUtc(
                        utcNow));

                participant.State =
                    ParticipantState.Connecting;

                return true;
            }
        }

        public bool MarkQuarantine(
            string identityKey,
            DateTime utcNow)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            lock (_gate)
            {
                return participant.MarkQuarantine(
                    NormalizeUtc(
                        utcNow));
            }
        }

        public bool MarkScanning(
            string identityKey,
            DateTime utcNow)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            lock (_gate)
            {
                return participant.MarkScanning(
                    NormalizeUtc(
                        utcNow));
            }
        }

        public bool MarkChallenging(
            string identityKey,
            DateTime utcNow)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            lock (_gate)
            {
                return participant.MarkChallenging(
                    NormalizeUtc(
                        utcNow));
            }
        }

        public bool MarkVerified(
            string identityKey,
            string baselineId,
            DateTime utcNow)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(
                    baselineId))
            {
                lock (_gate)
                {
                    if (!string.IsNullOrWhiteSpace(
                            _baselineId) &&
                        !string.Equals(
                            _baselineId,
                            baselineId.Trim(),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
            }

            lock (_gate)
            {
                participant.LastBaselineId =
                    string.IsNullOrWhiteSpace(
                        baselineId)
                        ? _baselineId
                        : baselineId.Trim();

                return participant.MarkVerified(
                    participant.LastBaselineId,
                    NormalizeUtc(
                        utcNow));
            }
        }

        public bool MarkActive(
            string identityKey,
            DateTime utcNow)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            lock (_gate)
            {
                return participant.MarkActive(
                    NormalizeUtc(
                        utcNow));
            }
        }

        public bool MarkDisconnected(
            string identityKey,
            DateTime utcNow)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            lock (_gate)
            {
                return participant.MarkDisconnected(
                    NormalizeUtc(
                        utcNow));
            }
        }

        public bool BeginReconnect(
            string identityKey,
            ushort playerId,
            string displayName,
            DateTime utcNow)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            lock (_gate)
            {
                return participant.BeginReconnect(
                    playerId,
                    displayName,
                    NormalizeUtc(
                        utcNow));
            }
        }

        public bool MarkRejected(
            string identityKey,
            string denyCode,
            string reason,
            DateTime utcNow)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            lock (_gate)
            {
                return participant.MarkRejected(
                    denyCode,
                    reason,
                    NormalizeUtc(
                        utcNow));
            }
        }

        public bool SetPlayerInfo(
            string identityKey,
            string playerKey,
            ushort playerId,
            string displayName,
            DateTime utcNow)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            lock (_gate)
            {
                participant.UpdateConnection(
                    playerId,
                    displayName,
                    NormalizeUtc(
                        utcNow));

                if (!string.IsNullOrWhiteSpace(
                        playerKey))
                {
                    participant.PlayerKey =
                        playerKey.Trim();
                }

                return true;
            }
        }

        public bool SetBaseline(
            string baselineId)
        {
            if (string.IsNullOrWhiteSpace(
                    baselineId))
            {
                return false;
            }

            string normalized =
                baselineId.Trim();

            lock (_gate)
            {
                if (!string.IsNullOrWhiteSpace(
                        _baselineId) &&
                    !string.Equals(
                        _baselineId,
                        normalized,
                        StringComparison.OrdinalIgnoreCase))
                {
                    foreach (ParticipantSession participant
                             in _participants.Values)
                    {
                        if (participant == null)
                        {
                            continue;
                        }

                        if (participant.IsVerified)
                        {
                            return false;
                        }
                    }
                }

                _baselineId =
                    normalized;

                return true;
            }
        }

        public IReadOnlyList<ParticipantSession>
            GetConnectedParticipants()
        {
            lock (_gate)
            {
                return _participants.Values
                    .Where(
                        participant =>
                            participant != null &&
                            participant.IsConnected)
                    .Select(
                        CloneParticipant)
                    .ToList()
                    .AsReadOnly();
            }
        }

        public IReadOnlyList<ParticipantSession>
            GetVerifiedParticipants(
                bool connectedOnly)
        {
            lock (_gate)
            {
                IEnumerable<ParticipantSession> query =
                    _participants.Values
                        .Where(
                            participant =>
                                participant != null &&
                                participant.IsVerified);

                if (connectedOnly)
                {
                    query =
                        query.Where(
                            participant =>
                                participant.IsConnected);
                }

                return query
                    .Select(
                        CloneParticipant)
                    .ToList()
                    .AsReadOnly();
            }
        }

        public IReadOnlyList<ParticipantSession>
            GetLockedParticipants()
        {
            lock (_gate)
            {
                return _participants.Values
                    .Where(
                        participant =>
                            participant != null &&
                            participant.WasMemberWhenLocked)
                    .Select(
                        CloneParticipant)
                    .ToList()
                    .AsReadOnly();
            }
        }

        public bool MarkMemberWhenLocked(
            string identityKey)
        {
            ParticipantSession participant;

            if (!TryGetInternal(
                    identityKey,
                    out participant))
            {
                return false;
            }

            lock (_gate)
            {
                participant.MarkMemberWhenLocked();

                return true;
            }
        }

        public bool RemoveParticipant(
            string identityKey)
        {
            string normalizedIdentity =
                NormalizeIdentity(
                    identityKey);

            if (normalizedIdentity == null)
            {
                return false;
            }

            lock (_gate)
            {
                ParticipantSession participant;

                if (!_participants.TryGetValue(
                        normalizedIdentity,
                        out participant) ||
                    participant == null)
                {
                    return false;
                }

                if (participant.WasMemberWhenLocked)
                {
                    return false;
                }

                return _participants.Remove(
                    normalizedIdentity);
            }
        }

        public void Clear()
        {
            lock (_gate)
            {
                _participants.Clear();
            }
        }

        private bool TryGetInternal(
            string identityKey,
            out ParticipantSession participant)
        {
            participant =
                null;

            string normalizedIdentity =
                NormalizeIdentity(
                    identityKey);

            if (normalizedIdentity == null)
            {
                return false;
            }

            lock (_gate)
            {
                return _participants.TryGetValue(
                    normalizedIdentity,
                    out participant);
            }
        }

        private static ParticipantSession CloneParticipant(
            ParticipantSession source)
        {
            if (source == null)
            {
                return null;
            }

            ParticipantSession clone =
                new ParticipantSession
                {
                    SessionId =
                        source.SessionId,

                    IdentityKey =
                        source.IdentityKey,

                    PlayerKey =
                        source.PlayerKey,

                    PlayerId =
                        source.PlayerId,

                    DisplayName =
                        source.DisplayName,

                    State =
                        source.State,

                    FirstSeenUtc =
                        source.FirstSeenUtc,

                    LastSeenUtc =
                        source.LastSeenUtc,

                    LastVerifiedUtc =
                        source.LastVerifiedUtc,

                    LastDisconnectedUtc =
                        source.LastDisconnectedUtc,

                    VerificationGeneration =
                        source.VerificationGeneration,

                    ReconnectCount =
                        source.ReconnectCount,

                    WasMemberWhenLocked =
                        source.WasMemberWhenLocked,

                    LastBaselineId =
                        source.LastBaselineId,

                    LastRejectionCode =
                        source.LastRejectionCode,

                    LastRejectionReason =
                        source.LastRejectionReason
                };

            return clone;
        }

        private static string NormalizeIdentity(
            string identity)
        {
            if (string.IsNullOrWhiteSpace(
                    identity))
            {
                return null;
            }

            return identity.Trim();
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