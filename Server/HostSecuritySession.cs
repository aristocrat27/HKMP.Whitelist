using System;
using System.Collections.Generic;
using HKMP.Whitelist.Shared;

namespace HKMP.Whitelist.Server
{
    public enum HostSecuritySessionState
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

    public sealed class HostSecuritySession
    {
        private readonly string _preconfiguredSessionId;

        private readonly Dictionary<string, ParticipantSession> _participants =
            new Dictionary<string, ParticipantSession>(
                StringComparer.OrdinalIgnoreCase);

        public string SessionId { get; private set; }

        public HostSecuritySessionState State { get; private set; }

        public DateTime CreatedAtUtc { get; private set; }

        public DateTime LastStateChangeUtc { get; private set; }

        public DateTime? LockedAtUtc { get; private set; }

        public DateTime? FinishedAtUtc { get; private set; }

        public string InvalidationReason { get; private set; }

        public HostBaseline Baseline { get; private set; }

        public MembershipSnapshot Membership { get; private set; }

        public bool IsProtected
        {
            get
            {
                return State ==
                           HostSecuritySessionState.Locked ||
                       State ==
                           HostSecuritySessionState.Running;
            }
        }

        public bool IsRunning
        {
            get
            {
                return State ==
                       HostSecuritySessionState.Running;
            }
        }

        public bool IsLocked
        {
            get
            {
                return State ==
                           HostSecuritySessionState.Locked ||
                       State ==
                           HostSecuritySessionState.Running;
            }
        }

        public bool IsTerminal
        {
            get
            {
                return State ==
                           HostSecuritySessionState.Invalidated ||
                       State ==
                           HostSecuritySessionState.Finished;
            }
        }

        public IReadOnlyCollection<ParticipantSession> Participants
        {
            get
            {
                return
                    new List<ParticipantSession>(
                        _participants.Values)
                    .AsReadOnly();
            }
        }

        public HostSecuritySession()
            : this(null)
        {
        }

        public HostSecuritySession(
            string sessionId)
        {
            _preconfiguredSessionId =
                string.IsNullOrWhiteSpace(sessionId)
                    ? null
                    : sessionId.Trim();

            State =
                HostSecuritySessionState.Idle;
        }

        public bool DetectHost(
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            if (State !=
                HostSecuritySessionState.Idle)
            {
                reason =
                    "HOST_SESSION_ALREADY_STARTED";

                return false;
            }

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            SessionId =
                string.IsNullOrWhiteSpace(_preconfiguredSessionId)
                    ? Guid.NewGuid().ToString("N")
                    : _preconfiguredSessionId;

            CreatedAtUtc =
                normalizedNow;

            LastStateChangeUtc =
                normalizedNow;

            State =
                HostSecuritySessionState.HostDetected;

            return true;
        }

        public bool BeginInitialScan(
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            if (State !=
                HostSecuritySessionState.HostDetected)
            {
                reason =
                    "INVALID_STATE_FOR_INITIAL_SCAN";

                return false;
            }

            LastStateChangeUtc =
                NormalizeUtc(
                    utcNow);

            State =
                HostSecuritySessionState.InitialScanning;

            return true;
        }

        public bool CompleteInitialScan(
            bool passed,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            if (State !=
                HostSecuritySessionState.InitialScanning)
            {
                reason =
                    "INVALID_STATE_FOR_INITIAL_SCAN_COMPLETION";

                return false;
            }

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            LastStateChangeUtc =
                normalizedNow;

            if (!passed)
            {
                State =
                    HostSecuritySessionState.HostDetected;

                reason =
                    "HOST_INITIAL_SCAN_FAILED";

                return false;
            }

            State =
                HostSecuritySessionState.ReadyOpen;

            return true;
        }

        public bool BeginFinalization(
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            if (State !=
                HostSecuritySessionState.ReadyOpen)
            {
                reason =
                    "INVALID_STATE_FOR_BASELINE_FINALIZATION";

                return false;
            }

            if (Baseline != null)
            {
                reason =
                    "BASELINE_ALREADY_EXISTS";

                return false;
            }

            if (Membership != null)
            {
                reason =
                    "MEMBERSHIP_ALREADY_EXISTS";

                return false;
            }

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            LastStateChangeUtc =
                normalizedNow;

            State =
                HostSecuritySessionState.FinalizingBaseline;

            return true;
        }

        public bool TryFreezeProtectedSession(
            HostBaseline baseline,
            MembershipSnapshot membership,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            if (State !=
                HostSecuritySessionState.FinalizingBaseline)
            {
                reason =
                    "INVALID_STATE_FOR_SESSION_LOCK";

                return false;
            }

            if (baseline == null)
            {
                reason =
                    "BASELINE_NULL";

                return false;
            }

            if (membership == null)
            {
                reason =
                    "MEMBERSHIP_NULL";

                return false;
            }

            if (baseline.IsFrozen)
            {
                reason =
                    "BASELINE_ALREADY_FROZEN";

                return false;
            }

            if (membership.IsFrozen)
            {
                reason =
                    "MEMBERSHIP_ALREADY_FROZEN";

                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    SessionId))
            {
                reason =
                    "SESSION_ID_MISSING";

                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    baseline.BaselineId))
            {
                reason =
                    "BASELINE_ID_MISSING";

                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    baseline.SessionId))
            {
                reason =
                    "BASELINE_SESSION_ID_MISSING";

                return false;
            }

            if (!string.Equals(
                    baseline.SessionId,
                    SessionId,
                    StringComparison.Ordinal))
            {
                reason =
                    "BASELINE_SESSION_MISMATCH";

                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    membership.SessionId))
            {
                reason =
                    "MEMBERSHIP_SESSION_ID_MISSING";

                return false;
            }

            if (!string.Equals(
                    membership.SessionId,
                    SessionId,
                    StringComparison.Ordinal))
            {
                reason =
                    "MEMBERSHIP_SESSION_MISMATCH";

                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    membership.BaselineId))
            {
                reason =
                    "MEMBERSHIP_BASELINE_ID_MISSING";

                return false;
            }

            if (!string.Equals(
                    membership.BaselineId,
                    baseline.BaselineId,
                    StringComparison.Ordinal))
            {
                reason =
                    "MEMBERSHIP_BASELINE_MISMATCH";

                return false;
            }

            if (baseline.IntegrityFailures == null)
            {
                reason =
                    "BASELINE_INTEGRITY_FAILURES_NULL";

                return false;
            }

            if (baseline.IntegrityFailures.Count > 0)
            {
                reason =
                    "BASELINE_INTEGRITY_FAILURE";

                return false;
            }

            if (membership.Count == 0)
            {
                reason =
                    "NO_VERIFIED_MEMBERS";

                return false;
            }

            /*
             * MembershipSnapshot.Members содержит MembershipMember,
             * поэтому мы не рассматриваем его как список string.
             *
             * Проверяем каждый текущий verified/active participant:
             * он обязан присутствовать в membership и иметь тот же baseline.
             *
             * Затем проверяем, что количество таких совпадений равно
             * количеству членов membership. Это также не позволяет
             * snapshot содержать участника, которого нет в реестре.
             */
            int matchedMembershipParticipants =
                0;

            foreach (ParticipantSession participant
                     in _participants.Values)
            {
                if (participant == null)
                {
                    continue;
                }

                if (!participant.IsVerified)
                {
                    continue;
                }

                if (!participant.IsConnected)
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(
                        participant.IdentityKey))
                {
                    reason =
                        "MEMBERSHIP_PARTICIPANT_IDENTITY_MISSING";

                    return false;
                }

                if (!string.Equals(
                        participant.SessionId,
                        SessionId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    reason =
                        "MEMBERSHIP_PARTICIPANT_SESSION_MISMATCH";

                    return false;
                }

                if (!string.Equals(
                        participant.LastBaselineId,
                        baseline.BaselineId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    reason =
                        "MEMBERSHIP_PARTICIPANT_BASELINE_MISMATCH";

                    return false;
                }

                MembershipMember member;

                if (!membership.TryGetMember(
                        participant.IdentityKey,
                        out member) ||
                    member == null)
                {
                    reason =
                        "VERIFIED_PARTICIPANT_NOT_IN_MEMBERSHIP";

                    return false;
                }

                if (string.IsNullOrWhiteSpace(
                        member.BaselineId))
                {
                    reason =
                        "MEMBERSHIP_MEMBER_BASELINE_MISSING";

                    return false;
                }

                if (!string.Equals(
                        member.BaselineId,
                        baseline.BaselineId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    reason =
                        "MEMBERSHIP_MEMBER_BASELINE_MISMATCH";

                    return false;
                }

                matchedMembershipParticipants++;
            }

            if (matchedMembershipParticipants !=
                membership.Count)
            {
                reason =
                    "MEMBERSHIP_PARTICIPANT_COUNT_MISMATCH";

                return false;
            }

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            try
            {
                baseline.Freeze();

                membership.Freeze(
                    normalizedNow);
            }
            catch
            {
                reason =
                    "SESSION_FREEZE_FAILED";

                return false;
            }

            Baseline =
                baseline;

            Membership =
                membership;

            LockedAtUtc =
                normalizedNow;

            LastStateChangeUtc =
                normalizedNow;

            State =
                HostSecuritySessionState.Locked;

            return true;
        }

        public bool StartRunning(
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            if (State !=
                HostSecuritySessionState.Locked)
            {
                reason =
                    "INVALID_STATE_FOR_RUNNING";

                return false;
            }

            if (Baseline == null ||
                !Baseline.IsFrozen)
            {
                reason =
                    "BASELINE_NOT_FROZEN";

                return false;
            }

            if (Membership == null ||
                !Membership.IsFrozen)
            {
                reason =
                    "MEMBERSHIP_NOT_FROZEN";

                return false;
            }

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            LastStateChangeUtc =
                normalizedNow;

            State =
                HostSecuritySessionState.Running;

            return true;
        }

        public bool Invalidate(
            string reason,
            DateTime utcNow)
        {
            if (State ==
                    HostSecuritySessionState.Invalidated ||
                State ==
                    HostSecuritySessionState.Finished)
            {
                return false;
            }

            InvalidationReason =
                reason ??
                string.Empty;

            LastStateChangeUtc =
                NormalizeUtc(
                    utcNow);

            State =
                HostSecuritySessionState.Invalidated;

            return true;
        }

        public bool Finish(
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            if (State ==
                HostSecuritySessionState.Idle)
            {
                reason =
                    "HOST_SESSION_NOT_STARTED";

                return false;
            }

            if (State ==
                HostSecuritySessionState.Finished)
            {
                reason =
                    "HOST_SESSION_ALREADY_FINISHED";

                return false;
            }

            if (State !=
                    HostSecuritySessionState.Running &&
                State !=
                    HostSecuritySessionState.Locked &&
                State !=
                    HostSecuritySessionState.Invalidated &&
                State !=
                    HostSecuritySessionState.ReadyOpen &&
                State !=
                    HostSecuritySessionState.HostDetected)
            {
                reason =
                    "INVALID_STATE_FOR_SESSION_FINISH";

                return false;
            }

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            FinishedAtUtc =
                normalizedNow;

            LastStateChangeUtc =
                normalizedNow;

            State =
                HostSecuritySessionState.Finished;

            return true;
        }

        public bool TryGetParticipant(
            string identityKey,
            out ParticipantSession participant)
        {
            participant = null;

            if (string.IsNullOrWhiteSpace(
                    identityKey))
            {
                return false;
            }

            string normalizedIdentity =
                identityKey.Trim();

            return _participants.TryGetValue(
                normalizedIdentity,
                out participant);
        }

        public bool RegisterParticipant(
            string identityKey,
            string displayName,
            DateTime utcNow,
            out ParticipantSession participant,
            out string reason)
        {
            participant = null;
            reason = null;

            if (string.IsNullOrWhiteSpace(
                    identityKey))
            {
                reason =
                    "PARTICIPANT_IDENTITY_MISSING";

                return false;
            }

            string normalizedIdentity =
                identityKey.Trim();

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            ParticipantSession existing;

            if (_participants.TryGetValue(
                    normalizedIdentity,
                    out existing))
            {
                if (existing == null)
                {
                    reason =
                        "PARTICIPANT_RECORD_NULL";

                    return false;
                }

                /*
                 * После блокировки ранее неизвестный identity
                 * не может войти только потому, что запись
                 * ParticipantSession уже когда-то существовала.
                 */
                if (State ==
                        HostSecuritySessionState.Locked ||
                    State ==
                        HostSecuritySessionState.Running)
                {
                    if (Membership == null ||
                        !Membership.ContainsIdentity(
                            normalizedIdentity))
                    {
                        reason =
                            "MEMBERSHIP_LOCKED";

                        existing.MarkRejected(
                            "MEMBERSHIP_LOCKED",
                            reason,
                            normalizedNow);

                        return false;
                    }
                }

                /*
                 * Реальный ParticipantSession не имеет
                 * UpdateDisplayName(). DisplayName доступен
                 * напрямую, поэтому обновляем его здесь.
                 */
                if (!string.IsNullOrWhiteSpace(
                        displayName))
                {
                    existing.DisplayName =
                        displayName;
                }

                /*
                 * Реальный ParticipantSession предоставляет
                 * BeginReconnect() и UpdateConnection().
                 *
                 * Для disconnected участника создаём новую
                 * security generation через BeginReconnect().
                 *
                 * Для уже подключённого участника просто
                 * обновляем connection info, не сбрасывая
                 * текущий security state.
                 */
                if (existing.State ==
                    ParticipantState.Disconnected)
                {
                    existing.BeginReconnect(
                        existing.PlayerId,
                        displayName,
                        normalizedNow);

                    if (!string.IsNullOrWhiteSpace(
                            SessionId))
                    {
                        existing.SessionId =
                            SessionId;
                    }
                }
                else
                {
                    existing.UpdateConnection(
                        existing.PlayerId,
                        displayName,
                        normalizedNow);
                }

                participant =
                    existing;

                return true;
            }

            /*
             * После LOCKED/RUNNING новый identity не может
             * быть зарегистрирован вообще.
             */
            if (State ==
                    HostSecuritySessionState.Locked ||
                State ==
                    HostSecuritySessionState.Running)
            {
                reason =
                    "MEMBERSHIP_LOCKED";

                return false;
            }

            participant =
                new ParticipantSession(
                    SessionId,
                    normalizedIdentity,
                    0,
                    displayName,
                    normalizedNow);

            participant.LastBaselineId =
                Baseline == null
                    ? null
                    : Baseline.BaselineId;

            _participants.Add(
                normalizedIdentity,
                participant);

            return true;
        }

        public bool CanAcceptNewParticipant(
            string identityKey)
        {
            if (string.IsNullOrWhiteSpace(
                    identityKey))
            {
                return false;
            }

            string normalizedIdentity =
                identityKey.Trim();

            if (State !=
                    HostSecuritySessionState.Locked &&
                State !=
                    HostSecuritySessionState.Running)
            {
                return true;
            }

            return Membership != null &&
                   Membership.ContainsIdentity(
                       normalizedIdentity);
        }

        public bool MarkParticipantScanning(
            string identityKey,
            DateTime utcNow)
        {
            if (string.IsNullOrWhiteSpace(identityKey))
            {
                return false;
            }

            ParticipantSession participant;

            if (!_participants.TryGetValue(
                    identityKey.Trim(),
                    out participant) ||
                participant == null)
            {
                return false;
            }

            return participant.MarkScanning(
                NormalizeUtc(utcNow));
        }

        public bool MarkParticipantChallenging(
            string identityKey,
            DateTime utcNow)
        {
            if (string.IsNullOrWhiteSpace(identityKey))
            {
                return false;
            }

            ParticipantSession participant;

            if (!_participants.TryGetValue(
                    identityKey.Trim(),
                    out participant) ||
                participant == null)
            {
                return false;
            }

            return participant.MarkChallenging(
                NormalizeUtc(utcNow));
        }

        public bool MarkParticipantRejected(
            string identityKey,
            string denyCode,
            string reason,
            DateTime utcNow)
        {
            if (string.IsNullOrWhiteSpace(identityKey))
            {
                return false;
            }

            ParticipantSession participant;

            if (!_participants.TryGetValue(
                    identityKey.Trim(),
                    out participant) ||
                participant == null)
            {
                return false;
            }

            return participant.MarkRejected(
                denyCode,
                reason,
                NormalizeUtc(utcNow));
        }

        public bool MarkParticipantDisconnected(
            string identityKey,
            DateTime utcNow)
        {
            if (string.IsNullOrWhiteSpace(
                    identityKey))
            {
                return false;
            }

            string normalizedIdentity =
                identityKey.Trim();

            ParticipantSession participant;

            if (!_participants.TryGetValue(
                    normalizedIdentity,
                    out participant))
            {
                return false;
            }

            if (participant == null)
            {
                return false;
            }

            participant.MarkDisconnected(
                NormalizeUtc(
                    utcNow));

            return true;
        }

        public bool MarkParticipantReconnecting(
            string identityKey,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            if (string.IsNullOrWhiteSpace(
                    identityKey))
            {
                reason =
                    "PARTICIPANT_IDENTITY_MISSING";

                return false;
            }

            string normalizedIdentity =
                identityKey.Trim();

            ParticipantSession participant;

            if (!_participants.TryGetValue(
                    normalizedIdentity,
                    out participant))
            {
                reason =
                    "PARTICIPANT_NOT_REGISTERED";

                return false;
            }

            if (participant == null)
            {
                reason =
                    "PARTICIPANT_RECORD_NULL";

                return false;
            }

            if (!CanAcceptNewParticipant(
                    normalizedIdentity))
            {
                reason =
                    "MEMBERSHIP_LOCKED";

                participant.MarkRejected(
                    "MEMBERSHIP_LOCKED",
                    reason,
                    NormalizeUtc(
                        utcNow));

                return false;
            }

            participant.BeginReconnect(
                participant.PlayerId,
                participant.DisplayName,
                NormalizeUtc(
                    utcNow));

            if (!string.IsNullOrWhiteSpace(
                    SessionId))
            {
                participant.SessionId =
                    SessionId;
            }

            return true;
        }

        public bool RemoveParticipant(
            string identityKey)
        {
            if (string.IsNullOrWhiteSpace(
                    identityKey))
            {
                return false;
            }

            return _participants.Remove(
                identityKey.Trim());
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