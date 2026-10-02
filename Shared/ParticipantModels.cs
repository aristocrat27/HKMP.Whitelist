using System;
using System.Collections.Generic;
using System.Linq;

namespace HKMP.Whitelist.Shared
{
    public enum HostSessionState
    {
        Idle,
        HostDetected,
        InitialScanning,
        ReadyOpen,
        FinalizingBaseline,
        Locked,
        Running,
        Invalidated,
        Finished
    }

    public enum ParticipantState
    {
        Connecting,
        Quarantine,
        Scanning,
        Challenging,
        Verified,
        Active,
        Disconnected,
        Reconnecting,
        Rejected
    }

    public sealed class HostSession
    {
        public string SessionId { get; set; }

        public string BaselineId { get; set; }

        public HostSessionState State { get; set; }

        public DateTime CreatedAtUtc { get; set; }

        public DateTime LastStateChangeUtc { get; set; }

        public DateTime LockedAtUtc { get; set; }

        public DateTime FinishedAtUtc { get; set; }

        public string InvalidationReason { get; set; }

        public HostSession()
        {
            SessionId =
                Guid.NewGuid().ToString("N");

            State =
                HostSessionState.Idle;

            CreatedAtUtc =
                DateTime.UtcNow;

            LastStateChangeUtc =
                CreatedAtUtc;
        }

        public HostSession(
            string sessionId,
            DateTime createdAtUtc)
        {
            SessionId =
                string.IsNullOrWhiteSpace(sessionId)
                    ? Guid.NewGuid().ToString("N")
                    : sessionId.Trim();

            CreatedAtUtc =
                NormalizeUtc(
                    createdAtUtc);

            LastStateChangeUtc =
                CreatedAtUtc;

            State =
                HostSessionState.Idle;
        }

        public bool IsProtected
        {
            get
            {
                return
                    State == HostSessionState.Locked ||
                    State == HostSessionState.Running;
            }
        }

        public bool IsTerminal
        {
            get
            {
                return
                    State == HostSessionState.Invalidated ||
                    State == HostSessionState.Finished;
            }
        }

        public bool TryTransition(
            HostSessionState nextState,
            DateTime utcNow,
            string reason)
        {
            if (!CanTransition(
                    State,
                    nextState))
            {
                return false;
            }

            DateTime normalized =
                NormalizeUtc(
                    utcNow);

            State =
                nextState;

            LastStateChangeUtc =
                normalized;

            if (nextState ==
                    HostSessionState.Locked)
            {
                LockedAtUtc =
                    normalized;
            }

            if (nextState ==
                    HostSessionState.Finished)
            {
                FinishedAtUtc =
                    normalized;
            }

            if (nextState ==
                    HostSessionState.Invalidated)
            {
                InvalidationReason =
                    string.IsNullOrWhiteSpace(reason)
                        ? null
                        : reason.Trim();
            }

            return true;
        }

        public void SetBaseline(
            string baselineId)
        {
            if (string.IsNullOrWhiteSpace(
                    baselineId))
            {
                BaselineId =
                    null;

                return;
            }

            BaselineId =
                baselineId.Trim();
        }

        private static bool CanTransition(
            HostSessionState current,
            HostSessionState next)
        {
            if (current == next)
            {
                return true;
            }

            switch (current)
            {
                case HostSessionState.Idle:
                    return
                        next ==
                            HostSessionState.HostDetected;

                case HostSessionState.HostDetected:
                    return
                        next ==
                            HostSessionState.InitialScanning ||
                        next ==
                            HostSessionState.Invalidated;

                case HostSessionState.InitialScanning:
                    return
                        next ==
                            HostSessionState.ReadyOpen ||
                        next ==
                            HostSessionState.Invalidated;

                case HostSessionState.ReadyOpen:
                    return
                        next ==
                            HostSessionState.FinalizingBaseline ||
                        next ==
                            HostSessionState.Invalidated ||
                        next ==
                            HostSessionState.Finished;

                case HostSessionState.FinalizingBaseline:
                    return
                        next ==
                            HostSessionState.Locked ||
                        next ==
                            HostSessionState.ReadyOpen ||
                        next ==
                            HostSessionState.Invalidated;

                case HostSessionState.Locked:
                    return
                        next ==
                            HostSessionState.Running ||
                        next ==
                            HostSessionState.Invalidated ||
                        next ==
                            HostSessionState.Finished;

                case HostSessionState.Running:
                    return
                        next ==
                            HostSessionState.Invalidated ||
                        next ==
                            HostSessionState.Finished;

                case HostSessionState.Invalidated:
                    return
                        next ==
                            HostSessionState.Finished;

                case HostSessionState.Finished:
                    return false;

                default:
                    return false;
            }
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

    public sealed class ParticipantSession
    {
        public string SessionId { get; set; }

        public string IdentityKey { get; set; }

        public string PlayerKey { get; set; }

        public ushort PlayerId { get; set; }

        public string DisplayName { get; set; }

        public ParticipantState State { get; set; }

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

        public bool IsConnected
        {
            get
            {
                return
                    State == ParticipantState.Connecting ||
                    State == ParticipantState.Quarantine ||
                    State == ParticipantState.Scanning ||
                    State == ParticipantState.Challenging ||
                    State == ParticipantState.Verified ||
                    State == ParticipantState.Active ||
                    State == ParticipantState.Reconnecting;
            }
        }

        public bool IsVerified
        {
            get
            {
                return
                    State == ParticipantState.Verified ||
                    State == ParticipantState.Active;
            }
        }

        public bool IsLockedMember
        {
            get
            {
                return WasMemberWhenLocked;
            }
        }

        public ParticipantSession()
        {
            DisplayName =
                string.Empty;

            State =
                ParticipantState.Connecting;

            FirstSeenUtc =
                DateTime.UtcNow;

            LastSeenUtc =
                FirstSeenUtc;

            VerificationGeneration =
                0;

            ReconnectCount =
                0;
        }

        public ParticipantSession(
            string sessionId,
            string identityKey,
            ushort playerId,
            string displayName,
            DateTime utcNow)
        {
            SessionId =
                NormalizeOptional(
                    sessionId);

            IdentityKey =
                NormalizeIdentity(
                    identityKey);

            PlayerId =
                playerId;

            DisplayName =
                displayName ?? string.Empty;

            DateTime normalized =
                NormalizeUtc(
                    utcNow);

            FirstSeenUtc =
                normalized;

            LastSeenUtc =
                normalized;

            State =
                ParticipantState.Connecting;

            VerificationGeneration =
                0;

            ReconnectCount =
                0;
        }

        public bool UpdateConnection(
            ushort playerId,
            string displayName,
            DateTime utcNow)
        {
            PlayerId =
                playerId;

            if (!string.IsNullOrWhiteSpace(
                    displayName))
            {
                DisplayName =
                    displayName.Trim();
            }

            LastSeenUtc =
                NormalizeUtc(
                    utcNow);

            return true;
        }

        public bool BeginReconnect(
            ushort playerId,
            string displayName,
            DateTime utcNow)
        {
            if (State !=
                    ParticipantState.Disconnected &&
                State !=
                    ParticipantState.Reconnecting)
            {
                return false;
            }

            UpdateConnection(
                playerId,
                displayName,
                utcNow);

            ReconnectCount++;

            VerificationGeneration++;

            LastVerifiedUtc =
                default(DateTime);

            LastBaselineId =
                null;

            LastRejectionCode =
                null;

            LastRejectionReason =
                null;

            State =
                ParticipantState.Reconnecting;

            return true;
        }

        public bool MarkQuarantine(
            DateTime utcNow)
        {
            LastSeenUtc =
                NormalizeUtc(
                    utcNow);

            State =
                ParticipantState.Quarantine;

            return true;
        }

        public bool MarkScanning(
            DateTime utcNow)
        {
            LastSeenUtc =
                NormalizeUtc(
                    utcNow);

            State =
                ParticipantState.Scanning;

            return true;
        }

        public bool MarkChallenging(
            DateTime utcNow)
        {
            LastSeenUtc =
                NormalizeUtc(
                    utcNow);

            State =
                ParticipantState.Challenging;

            return true;
        }

        public bool MarkVerified(
            string baselineId,
            DateTime utcNow)
        {
            DateTime normalized =
                NormalizeUtc(
                    utcNow);

            LastSeenUtc =
                normalized;

            LastVerifiedUtc =
                normalized;

            LastBaselineId =
                NormalizeOptional(
                    baselineId);

            LastRejectionCode =
                null;

            LastRejectionReason =
                null;

            State =
                ParticipantState.Verified;

            return true;
        }

        public bool MarkActive(
            DateTime utcNow)
        {
            if (!IsVerified)
            {
                return false;
            }

            LastSeenUtc =
                NormalizeUtc(
                    utcNow);

            State =
                ParticipantState.Active;

            return true;
        }

        public bool MarkDisconnected(
            DateTime utcNow)
        {
            DateTime normalized =
                NormalizeUtc(
                    utcNow);

            LastSeenUtc =
                normalized;

            LastDisconnectedUtc =
                normalized;

            State =
                ParticipantState.Disconnected;

            return true;
        }

        public bool MarkRejected(
            string denyCode,
            string reason,
            DateTime utcNow)
        {
            LastSeenUtc =
                NormalizeUtc(
                    utcNow);

            LastRejectionCode =
                NormalizeOptional(
                    denyCode);

            LastRejectionReason =
                NormalizeOptional(
                    reason);

            State =
                ParticipantState.Rejected;

            return true;
        }

        public void MarkMemberWhenLocked()
        {
            WasMemberWhenLocked =
                true;
        }

        private static string NormalizeIdentity(
            string value)
        {
            if (string.IsNullOrWhiteSpace(
                    value))
            {
                return null;
            }

            return value.Trim();
        }

        private static string NormalizeOptional(
            string value)
        {
            if (string.IsNullOrWhiteSpace(
                    value))
            {
                return null;
            }

            return value.Trim();
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

    public sealed class MembershipMember
    {
        public string SessionId { get; set; }

        public string IdentityKey { get; set; }

        public string PlayerKey { get; set; }

        public ushort PlayerId { get; set; }

        public string DisplayName { get; set; }

        public DateTime VerifiedAtUtc { get; set; }

        public DateTime LastVerifiedUtc { get; set; }

        public string BaselineId { get; set; }

        public ParticipantState State { get; set; }

        public MembershipMember()
        {
            DisplayName =
                string.Empty;
        }

        public MembershipMember(
            ParticipantSession participant)
        {
            if (participant == null)
            {
                return;
            }

            SessionId =
                participant.SessionId;

            IdentityKey =
                participant.IdentityKey;

            PlayerKey =
                participant.PlayerKey;

            PlayerId =
                participant.PlayerId;

            DisplayName =
                participant.DisplayName;

            VerifiedAtUtc =
                participant.LastVerifiedUtc;

            LastVerifiedUtc =
                participant.LastVerifiedUtc;

            BaselineId =
                participant.LastBaselineId;

            State =
                participant.State;
        }

        public MembershipMember Clone()
        {
            return
                new MembershipMember
                {
                    SessionId =
                        SessionId,

                    IdentityKey =
                        IdentityKey,

                    PlayerKey =
                        PlayerKey,

                    PlayerId =
                        PlayerId,

                    DisplayName =
                        DisplayName,

                    VerifiedAtUtc =
                        VerifiedAtUtc,

                    LastVerifiedUtc =
                        LastVerifiedUtc,

                    BaselineId =
                        BaselineId,

                    State =
                        State
                };
        }
    }

    public sealed class MembershipSnapshot
    {
        private readonly List<MembershipMember>
            _members =
                new List<MembershipMember>();

        public string SessionId { get; private set; }

        public string BaselineId { get; private set; }

        public DateTime CreatedAtUtc { get; private set; }

        public DateTime LockedAtUtc { get; private set; }

        public bool IsFrozen { get; private set; }

        public IReadOnlyList<MembershipMember> Members
        {
            get
            {
                return
                    _members
                        .Select(
                            member =>
                                member == null
                                    ? null
                                    : member.Clone())
                        .ToList()
                        .AsReadOnly();
            }
        }

        public int Count
        {
            get
            {
                return _members.Count;
            }
        }

        public MembershipSnapshot()
        {
            CreatedAtUtc =
                DateTime.UtcNow;
        }

        public MembershipSnapshot(
            string sessionId,
            string baselineId,
            DateTime createdAtUtc)
        {
            SessionId =
                string.IsNullOrWhiteSpace(
                    sessionId)
                    ? null
                    : sessionId.Trim();

            BaselineId =
                string.IsNullOrWhiteSpace(
                    baselineId)
                    ? null
                    : baselineId.Trim();

            CreatedAtUtc =
                NormalizeUtc(
                    createdAtUtc);
        }

        public bool Add(
            ParticipantSession participant)
        {
            if (IsFrozen ||
                participant == null ||
                string.IsNullOrWhiteSpace(
                    participant.IdentityKey))
            {
                return false;
            }

            string identity =
                participant.IdentityKey.Trim();

            foreach (MembershipMember member
                     in _members)
            {
                if (member == null)
                {
                    continue;
                }

                if (string.Equals(
                        member.IdentityKey,
                        identity,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            MembershipMember snapshotMember =
                new MembershipMember(
                    participant);

            if (string.IsNullOrWhiteSpace(
                    snapshotMember.SessionId))
            {
                snapshotMember.SessionId =
                    SessionId;
            }

            if (string.IsNullOrWhiteSpace(
                    snapshotMember.BaselineId))
            {
                snapshotMember.BaselineId =
                    BaselineId;
            }

            _members.Add(
                snapshotMember);

            return true;
        }

        public bool Add(
            MembershipMember member)
        {
            if (IsFrozen ||
                member == null ||
                string.IsNullOrWhiteSpace(
                    member.IdentityKey))
            {
                return false;
            }

            string identity =
                member.IdentityKey.Trim();

            foreach (MembershipMember existing
                     in _members)
            {
                if (existing == null)
                {
                    continue;
                }

                if (string.Equals(
                        existing.IdentityKey,
                        identity,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            MembershipMember clone =
                member.Clone();

            if (string.IsNullOrWhiteSpace(
                    clone.SessionId))
            {
                clone.SessionId =
                    SessionId;
            }

            if (string.IsNullOrWhiteSpace(
                    clone.BaselineId))
            {
                clone.BaselineId =
                    BaselineId;
            }

            _members.Add(
                clone);

            return true;
        }

        public bool ContainsIdentity(
            string identityKey)
        {
            if (string.IsNullOrWhiteSpace(
                    identityKey))
            {
                return false;
            }

            string normalized =
                identityKey.Trim();

            foreach (MembershipMember member
                     in _members)
            {
                if (member == null)
                {
                    continue;
                }

                if (string.Equals(
                        member.IdentityKey,
                        normalized,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        public bool TryGetMember(
            string identityKey,
            out MembershipMember member)
        {
            member =
                null;

            if (string.IsNullOrWhiteSpace(
                    identityKey))
            {
                return false;
            }

            string normalized =
                identityKey.Trim();

            foreach (MembershipMember existing
                     in _members)
            {
                if (existing == null)
                {
                    continue;
                }

                if (string.Equals(
                        existing.IdentityKey,
                        normalized,
                        StringComparison.OrdinalIgnoreCase))
                {
                    member =
                        existing.Clone();

                    return true;
                }
            }

            return false;
        }

        public void Freeze(
            DateTime lockedAtUtc)
        {
            if (IsFrozen)
            {
                return;
            }

            LockedAtUtc =
                NormalizeUtc(
                    lockedAtUtc);

            IsFrozen =
                true;
        }

        public void SetIdentity(
            string sessionId,
            string baselineId)
        {
            if (IsFrozen)
            {
                return;
            }

            if (!string.IsNullOrWhiteSpace(
                    sessionId))
            {
                SessionId =
                    sessionId.Trim();
            }

            if (!string.IsNullOrWhiteSpace(
                    baselineId))
            {
                BaselineId =
                    baselineId.Trim();
            }
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