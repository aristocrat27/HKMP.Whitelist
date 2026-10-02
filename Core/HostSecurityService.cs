using System;
using System.Collections.Generic;
using System.Linq;
using Hkmp.Api.Server;
using HKMP.Whitelist.Server;
using HKMP.Whitelist.Shared;

namespace HKMP.Whitelist.Core
{
    public sealed class HostSecurityService
    {
        private readonly object _sync =
        new object();

        private readonly HostSecuritySession _session;

        private readonly ParticipantRegistry _participants;

        private readonly MembershipManager _membership;

        private readonly HostBaselineBuilder _baselineBuilder;

        private readonly SecurityEventBus _eventBus;

        private readonly ViolationStore _violationStore;

        private HostBaseline _openBaseline;

        private HostReadinessResult _lastReadiness;

        public HostReadinessResult Readiness
        {
            get
            {
                lock (_sync)
                {
                    return _lastReadiness;
                }
            }
        }

        public HostBaseline OpenBaseline
        {
            get
            {
                lock (_sync)
                {
                    return _openBaseline;
                }
            }
        }

        public HostSecuritySessionState State
        {
            get
            {
                lock (_sync)
                {
                    return _session.State;
                }
            }
        }

        public DateTime CreatedAtUtc
        {
            get
            {
                lock (_sync)
                {
                    return _session.CreatedAtUtc;
                }
            }
        }

        public DateTime? LockedAtUtc
        {
            get
            {
                lock (_sync)
                {
                    return _session.LockedAtUtc;
                }
            }
        }

        public string InvalidationReason
        {
            get
            {
                lock (_sync)
                {
                    return _session.InvalidationReason;
                }
            }
        }

        public string SessionId
        {
            get
            {
                lock (_sync)
                {
                    return _session.SessionId;
                }
            }
        }

        public bool IsLocked
        {
            get
            {
                lock (_sync)
                {
                    return _session.IsLocked;
                }
            }
        }

        public ParticipantRegistry Participants
        {
            get
            {
                return _participants;
            }
        }

        public MembershipManager Membership
        {
            get
            {
                return _membership;
            }
        }

        public SecurityEventBus EventBus
        {
            get
            {
                return _eventBus;
            }
        }

        public ViolationStore Violations
        {
            get
            {
                return _violationStore;
            }
        }

        public bool IsProtected
        {
            get
            {
                lock (_sync)
                {
                    return _session.IsProtected;
                }
            }
        }

        public HostSecurityService(
            HostBaselineBuilder baselineBuilder,
            ParticipantRegistry participants = null,
            MembershipManager membership = null,
            SecurityEventBus eventBus = null,
            ViolationStore violationStore = null,
            string sessionId = null)
        {
            if (baselineBuilder == null)
            {
                throw new ArgumentNullException(
                    nameof(baselineBuilder));
            }

            _session =
                new HostSecuritySession(
                    sessionId);

            _participants =
                participants ??
                new ParticipantRegistry();

            _membership =
                membership ??
                new MembershipManager();

            _baselineBuilder =
                baselineBuilder;

            _eventBus =
                eventBus ??
                new SecurityEventBus();

            _violationStore =
                violationStore ??
                new ViolationStore();
        }

        public bool StartHost(
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            lock (_sync)
            {
                _lastReadiness =
                    GamePathResolver.GetHostReadiness(
                        _baselineBuilder.GameRoot);

                if (_lastReadiness == null)
                {
                    reason =
                        "HOST_READINESS_RESULT_UNAVAILABLE";
                    return false;
                }

                HostSecuritySessionState state =
                    _session.State;

                if (state == HostSecuritySessionState.Idle)
                {
                    return _session.DetectHost(
                        NormalizeUtc(
                            utcNow),
                        out reason);
                }

                if (state == HostSecuritySessionState.HostDetected ||
                    state == HostSecuritySessionState.InitialScanning ||
                    state == HostSecuritySessionState.ReadyOpen)
                {
                    return true;
                }

                reason =
                    "HOST_SESSION_ALREADY_FINALIZED:" +
                    state;

                return false;
            }
        }

        public bool BeginInitialScan(
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            lock (_sync)
            {
                return _session.BeginInitialScan(
                    NormalizeUtc(
                        utcNow),
                    out reason);
            }
        }

        public bool CompleteInitialScan(
            bool passed,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            lock (_sync)
            {
                return _session.CompleteInitialScan(
                    passed,
                    NormalizeUtc(
                        utcNow),
                    out reason);
            }
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

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            lock (_sync)
            {
                if (!_session.RegisterParticipant(
                    identityKey,
                    displayName,
                    normalizedNow,
                    out participant,
                    out reason))
                {
                    return false;
                }

                ParticipantSession registered;

                if (!_participants.RegisterParticipant(
                    identityKey,
                    displayName,
                    normalizedNow,
                    out registered,
                    out reason))
                {
                    return false;
                }

                participant =
                    registered;

                return true;
            }
        }

        public bool MarkParticipantScanning(
            string identityKey,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            DateTime normalizedNow =
                NormalizeUtc(utcNow);

            lock (_sync)
            {
                if (!_participants.MarkScanning(
                        identityKey,
                        normalizedNow))
                {
                    reason =
                        "PARTICIPANT_SCANNING_FAILED";

                    return false;
                }

                if (!_session.MarkParticipantScanning(
                        identityKey,
                        normalizedNow))
                {
                    reason =
                        "SESSION_PARTICIPANT_SCANNING_FAILED";

                    return false;
                }

                return true;
            }
        }

        public bool MarkParticipantChallenging(
            string identityKey,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            DateTime normalizedNow =
                NormalizeUtc(utcNow);

            lock (_sync)
            {
                if (!_participants.MarkChallenging(
                        identityKey,
                        normalizedNow))
                {
                    reason =
                        "PARTICIPANT_CHALLENGE_STATE_FAILED";

                    return false;
                }

                if (!_session.MarkParticipantChallenging(
                        identityKey,
                        normalizedNow))
                {
                    reason =
                        "SESSION_PARTICIPANT_CHALLENGE_STATE_FAILED";

                    return false;
                }

                return true;
            }
        }

        public bool MarkParticipantRejected(
            string identityKey,
            string denyCode,
            string rejectionReason,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            DateTime normalizedNow =
                NormalizeUtc(utcNow);

            lock (_sync)
            {
                if (!_participants.MarkRejected(
                        identityKey,
                        denyCode,
                        rejectionReason,
                        normalizedNow))
                {
                    reason =
                        "PARTICIPANT_REJECTION_STATE_FAILED";

                    return false;
                }

                if (!_session.MarkParticipantRejected(
                        identityKey,
                        denyCode,
                        rejectionReason,
                        normalizedNow))
                {
                    reason =
                        "SESSION_PARTICIPANT_REJECTION_STATE_FAILED";

                    return false;
                }

                return true;
            }
        }

        public bool MarkParticipantVerified(
            string identityKey,
            string baselineId,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            lock (_sync)
            {
                ParticipantSession sessionParticipant;

                if (!_session.TryGetParticipant(
                    identityKey,
                    out sessionParticipant) ||
                    sessionParticipant == null)
                {
                    reason =
                        "SESSION_PARTICIPANT_NOT_REGISTERED";

                    return false;
                }

                ParticipantSession registryParticipant;

                if (!_participants.TryGetParticipant(
                    identityKey,
                    out registryParticipant) ||
                    registryParticipant == null)
                {
                    reason =
                        "PARTICIPANT_NOT_REGISTERED";

                    return false;
                }

                if (!_participants.MarkVerified(
                    identityKey,
                    baselineId,
                    normalizedNow))
                {
                    reason =
                        "PARTICIPANT_VERIFICATION_FAILED";

                    return false;
                }

                string effectiveBaselineId =
                    string.IsNullOrWhiteSpace(
                        baselineId)
                        ? _participants.BaselineId
                        : baselineId.Trim();

                if (!sessionParticipant.MarkVerified(
                    effectiveBaselineId,
                    normalizedNow))
                {
                    reason =
                        "SESSION_PARTICIPANT_VERIFICATION_FAILED";

                    return false;
                }

                return true;
            }
        }

        public bool MarkParticipantActive(
            string identityKey,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            lock (_sync)
            {
                ParticipantSession sessionParticipant;

                if (!_session.TryGetParticipant(
                    identityKey,
                    out sessionParticipant) ||
                    sessionParticipant == null)
                {
                    reason =
                        "SESSION_PARTICIPANT_NOT_REGISTERED";

                    return false;
                }

                ParticipantSession registryParticipant;

                if (!_participants.TryGetParticipant(
                    identityKey,
                    out registryParticipant) ||
                    registryParticipant == null)
                {
                    reason =
                        "PARTICIPANT_NOT_REGISTERED";

                    return false;
                }
                if (!_participants.MarkActive(
                    identityKey,
                    normalizedNow))
                {
                    reason = "PARTICIPANT_MARK_ACTIVE_FAILED";

                    return false;
                }

                if (!sessionParticipant.MarkActive(
                    normalizedNow))
                {
                    reason =
                        "SESSION_PARTICIPANT_ACTIVATION_FAILED";

                    return false;
                }

                return true;
            }
        }

        public bool MarkParticipantDisconnected(
            string identityKey,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            lock (_sync)
            {
                if (!_participants.MarkDisconnected(
                    identityKey,
                    normalizedNow))
                {
                    reason =
                        "PARTICIPANT_DISCONNECT_FAILED";

                    return false;
                }

                if (!_session.MarkParticipantDisconnected(
                    identityKey,
                    normalizedNow))
                {
                    reason =
                        "SESSION_PARTICIPANT_NOT_REGISTERED";

                    return false;
                }

                return true;
            }
        }

        public bool MarkParticipantReconnecting(
            string identityKey,
            DateTime utcNow,
            out string reason)
        {
            reason = null;

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            lock (_sync)
            {
                if (!CanAcceptParticipant(
                    identityKey))
                {
                    reason =
                        "MEMBERSHIP_LOCKED";

                    return false;
                }

                ParticipantSession existing;

                if (!_participants.TryGetParticipant(
                    identityKey,
                    out existing) ||
                    existing == null)
                {
                    reason =
                        "PARTICIPANT_NOT_REGISTERED";

                    return false;
                }

                if (!_participants.BeginReconnect(
                    identityKey,
                    existing.PlayerId,
                    existing.DisplayName,
                    normalizedNow))
                {
                    reason =
                        "PARTICIPANT_RECONNECT_FAILED";

                    return false;
                }

                if (!_session.MarkParticipantReconnecting(
                    identityKey,
                    normalizedNow,
                    out reason))
                {
                    return false;
                }

                return true;
            }
        }

        public bool CanAcceptParticipant(
            string identityKey)
        {
            lock (_sync)
            {
                if (!_session.CanAcceptNewParticipant(
                    identityKey))
                {
                    return false;
                }

                return _membership.CanAcceptIdentity(
                    identityKey);
            }
        }

        public bool BeginInitialAudit(
            PresetConfig preset,
            bool includeDisabledMods,
            DateTime utcNow,
            out HostBaseline baseline,
            out string reason)
        {
            baseline = null;
            reason = null;

            if (preset == null)
            {
                reason = "PRESET_NULL";
                return false;
            }

            DateTime normalizedNow =
                NormalizeUtc(
                    utcNow);

            lock (_sync)
            {
                if (_session.State == HostSecuritySessionState.Idle)
                {
                    if (!_session.DetectHost(
                        normalizedNow,
                        out reason))
                    {
                        return false;
                    }
                }

                if (_session.State == HostSecuritySessionState.HostDetected)
                {
                    if (!_session.BeginInitialScan(
                        normalizedNow,
                        out reason))
                    {
                        return false;
                    }
                }

                if (_session.State != HostSecuritySessionState.InitialScanning)
                {
                    if (_session.State == HostSecuritySessionState.ReadyOpen &&
                        _openBaseline != null)
                    {
                        baseline = _openBaseline;
                        return true;
                    }

                    reason =
                        "HOST_INITIAL_AUDIT_INVALID_STATE:" +
                        _session.State;
                    return false;
                }

                _lastReadiness =
                    GamePathResolver.GetHostReadiness(
                        _baselineBuilder.GameRoot);

                if (_lastReadiness == null)
                {
                    reason =
                        "HOST_READINESS_RESULT_UNAVAILABLE";
                    _session.CompleteInitialScan(
                        false,
                        normalizedNow,
                        out _);
                    return false;
                }

                HostBaselineBuildResult result;

                try
                {
                    result =
                        _baselineBuilder.Build(
                            _session.SessionId,
                            preset,
                            includeDisabledMods);
                }
                catch (Exception ex)
                {
                    reason =
                        "HOST_SCAN_EXCEPTION:" +
                        ex.GetType().Name +
                        ":" +
                        (ex.Message ?? "<no message>");

                    _lastReadiness =
                        GamePathResolver.GetHostReadiness(
                            _baselineBuilder.GameRoot);

                    _session.CompleteInitialScan(
                        false,
                        normalizedNow,
                        out _);
                    return false;
                }

                if (result == null)
                {
                    reason =
                        "HOST_BASELINE_BUILD_RESULT_NULL";
                    _session.CompleteInitialScan(
                        false,
                        normalizedNow,
                        out _);
                    return false;
                }

                _lastReadiness =
                    result.Readiness;

                string buildFailure =
                    GetBuildFailureReason(
                        result);

                if (!result.Success ||
                    !result.Complete ||
                    result.Baseline == null ||
                    string.IsNullOrWhiteSpace(
                        result.Baseline.BaselineId) ||
                    string.IsNullOrWhiteSpace(
                        result.Baseline.SessionId) ||
                    result.Baseline.IntegrityFailures == null ||
                    result.Baseline.IntegrityFailures.Count > 0)
                {
                    reason =
                        buildFailure ??
                        "HOST_SCAN_INCOMPLETE";

                    _session.CompleteInitialScan(
                        false,
                        normalizedNow,
                        out _);
                    return false;
                }

                if (!string.Equals(
                        result.Baseline.SessionId,
                        _session.SessionId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    reason =
                        "BASELINE_SESSION_MISMATCH";
                    _session.CompleteInitialScan(
                        false,
                        normalizedNow,
                        out _);
                    return false;
                }

                _openBaseline =
                    result.Baseline;

                baseline =
                    _openBaseline;

                if (!string.IsNullOrWhiteSpace(
                        _lastReadiness == null
                            ? null
                            : _lastReadiness.GameRoot))
                {
                    _baselineBuilder.UpdateGameRoot(
                        _lastReadiness.GameRoot);
                }

                if (!_session.CompleteInitialScan(
                        true,
                        normalizedNow,
                        out reason))
                {
                    baseline = null;
                    _openBaseline = null;
                    return false;
                }

                return true;
            }
        }

        public bool TryFinalizeProtectedSession(
            PresetConfig preset,
            bool includeDisabledMods,
            DateTime utcNow,
            out HostBaseline baseline,
            out MembershipSnapshot membership,
            out string reason)
        {
            baseline = null;
            membership = null;
            reason = null;

            if (preset == null)
            {
                reason =
                    "PRESET_NULL";

                return false;
            }

            lock (_sync)
            {
                DateTime normalizedNow =
                    NormalizeUtc(
                        utcNow);

                if (!_session.BeginFinalization(
                    normalizedNow,
                    out reason))
                {
                    return false;
                }

                bool membershipLocked =
                    false;

                try
                {
                    HostBaselineBuildResult buildResult =
                        _baselineBuilder.Build(
                            _session.SessionId,
                            preset,
                            includeDisabledMods);

                    if (buildResult == null)
                    {
                        reason =
                            "HOST_BASELINE_BUILD_RESULT_NULL";

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    if (!buildResult.Success ||
                        !buildResult.Complete)
                    {
                        reason =
                            GetBuildFailureReason(
                                buildResult);

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    baseline =
                        buildResult.Baseline;

                    if (baseline == null)
                    {
                        reason =
                            "HOST_BASELINE_BUILD_FAILED";

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    if (string.IsNullOrWhiteSpace(
                        baseline.BaselineId))
                    {
                        reason =
                            "BASELINE_ID_MISSING";

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    if (!string.Equals(
                        baseline.SessionId,
                        _session.SessionId,
                        StringComparison.Ordinal))
                    {
                        reason =
                            "BASELINE_SESSION_MISMATCH";

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    if (baseline.IntegrityFailures == null)
                    {
                        reason =
                            "BASELINE_INTEGRITY_FAILURES_NULL";

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    if (baseline.IntegrityFailures.Count > 0)
                    {
                        reason =
                            "BASELINE_INTEGRITY_FAILURE";

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    List<ParticipantSession>
                        verifiedParticipants =
                            _participants
                                .GetVerifiedParticipants(
                                    true)
                                .Where(
                                    participant =>
                                        participant != null)
                                .ToList();

                    if (verifiedParticipants.Count == 0)
                    {
                        reason =
                            "NO_VERIFIED_MEMBERS";

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    foreach (ParticipantSession participant
                             in verifiedParticipants)
                    {
                        if (participant == null)
                        {
                            reason =
                                "MEMBERSHIP_CONTAINS_NULL_PARTICIPANT";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }

                        if (string.IsNullOrWhiteSpace(
                            participant.IdentityKey))
                        {
                            reason =
                                "MEMBERSHIP_PARTICIPANT_IDENTITY_MISSING";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }

                        if (!participant.IsVerified)
                        {
                            reason =
                                "MEMBERSHIP_PARTICIPANT_NOT_VERIFIED";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }

                        if (!participant.IsConnected)
                        {
                            reason =
                                "MEMBERSHIP_PARTICIPANT_DISCONNECTED";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }

                        if (!string.IsNullOrWhiteSpace(
                            participant.SessionId) &&
                            !string.Equals(
                                participant.SessionId,
                                _session.SessionId,
                                StringComparison.OrdinalIgnoreCase))
                        {
                            reason =
                                "MEMBERSHIP_PARTICIPANT_SESSION_MISMATCH";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }

                        if (!string.Equals(
                            participant.LastBaselineId,
                            baseline.BaselineId,
                            StringComparison.OrdinalIgnoreCase))
                        {
                            reason =
                                "MEMBERSHIP_PARTICIPANT_BASELINE_MISMATCH";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }

                        ParticipantSession sessionParticipant;

                        if (!_session.TryGetParticipant(
                            participant.IdentityKey,
                            out sessionParticipant) ||
                            sessionParticipant == null)
                        {
                            reason =
                                "SESSION_PARTICIPANT_NOT_REGISTERED";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }

                        if (!sessionParticipant.IsVerified)
                        {
                            reason =
                                "SESSION_PARTICIPANT_NOT_VERIFIED";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }

                        if (!sessionParticipant.IsConnected)
                        {
                            reason =
                                "SESSION_PARTICIPANT_DISCONNECTED";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }

                        if (!string.Equals(
                            sessionParticipant.LastBaselineId,
                            baseline.BaselineId,
                            StringComparison.OrdinalIgnoreCase))
                        {
                            reason =
                                "SESSION_PARTICIPANT_BASELINE_MISMATCH";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }
                    }

                    if (!_membership.BuildAndLock(
                        _session.SessionId,
                        baseline.BaselineId,
                        verifiedParticipants,
                        normalizedNow,
                        out membership,
                        out reason))
                    {
                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    membershipLocked =
                        true;

                    if (membership == null)
                    {
                        reason =
                            "MEMBERSHIP_SNAPSHOT_NULL";

                        _membership.Clear();

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    if (!membership.IsFrozen)
                    {
                        reason =
                            "MEMBERSHIP_NOT_FROZEN";

                        _membership.Clear();

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    if (membership.Count == 0)
                    {
                        reason =
                            "NO_VERIFIED_MEMBERS";

                        _membership.Clear();

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    if (membership.Count !=
                        verifiedParticipants.Count)
                    {
                        reason =
                            "MEMBERSHIP_PARTICIPANT_COUNT_MISMATCH";

                        _membership.Clear();

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    foreach (ParticipantSession participant
                             in verifiedParticipants)
                    {
                        MembershipMember member;

                        if (!membership.TryGetMember(
                            participant.IdentityKey,
                            out member) ||
                            member == null)
                        {
                            reason =
                                "MEMBERSHIP_MEMBER_MISSING";

                            _membership.Clear();

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }

                        if (!string.Equals(
                            member.BaselineId,
                            baseline.BaselineId,
                            StringComparison.OrdinalIgnoreCase))
                        {
                            reason =
                                "MEMBERSHIP_MEMBER_BASELINE_MISMATCH";

                            _membership.Clear();

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }
                    }

                    if (!_session.TryFreezeProtectedSession(
                        baseline,
                        membership,
                        normalizedNow,
                        out reason))
                    {
                        _membership.Clear();

                        _session.Invalidate(
                            reason,
                            normalizedNow);

                        return false;
                    }

                    foreach (ParticipantSession participant
                             in verifiedParticipants)
                    {
                        if (!_participants.MarkMemberWhenLocked(
                            participant.IdentityKey))
                        {
                            reason =
                                "PARTICIPANT_LOCK_MARK_FAILED";

                            _session.Invalidate(
                                reason,
                                normalizedNow);

                            return false;
                        }
                    }

                    return true;
                }
                catch (Exception ex)
                {
                    reason =
                        "PROTECTED_SESSION_FINALIZATION_FAILED: " +
                        ex.GetType().Name +
                        ": " +
                        ex.Message;

                    if (membershipLocked &&
                        !_session.IsProtected)
                    {
                        _membership.Clear();
                    }

                    _session.Invalidate(
                        reason,
                        normalizedNow);

                    return false;
                }
            }
        }

        public bool StartRunning(
            DateTime utcNow,
            out string reason)
        {
            lock (_sync)
            {
                return _session.StartRunning(
                    NormalizeUtc(
                        utcNow),
                    out reason);
            }
        }

        public bool HandleHostIntegrityChanged(
            string reason,
            DateTime utcNow)
        {
            lock (_sync)
            {
                if (!_session.IsProtected)
                {
                    return false;
                }

                string normalizedReason =
                    string.IsNullOrWhiteSpace(
                        reason)
                        ? "HOST_INTEGRITY_CHANGED"
                        : reason.Trim();

                bool invalidated =
                    _session.Invalidate(
                        normalizedReason,
                        NormalizeUtc(
                            utcNow));

                if (invalidated)
                {
                    _eventBus.Publish(
                        SecurityEvent.CreateHostEvent(
                            _session.SessionId,
                            SecurityEventType.HostIntegrityChanged,
                            SecuritySeverity.Critical,
                            normalizedReason));

                    _eventBus.Publish(
                        SecurityEvent.CreateHostEvent(
                            _session.SessionId,
                            SecurityEventType.SessionInvalidated,
                            SecuritySeverity.Critical,
                            normalizedReason));
                }

                return invalidated;
            }
        }

        public bool RecordViolation(
            ObservedViolation violation)
        {
            if (violation == null)
            {
                return false;
            }

            ObservedViolation stored =
                _violationStore.Record(
                    violation);

            return stored != null;
        }

        public bool Finish(
            DateTime utcNow,
            out string reason)
        {
            lock (_sync)
            {
                return _session.Finish(
                    NormalizeUtc(
                        utcNow),
                    out reason);
            }
        }

        public IReadOnlyCollection<ParticipantSession>
            GetParticipants()
        {
            return _participants.Participants;
        }

        public bool TryGetParticipant(
            string identityKey,
            out ParticipantSession participant)
        {
            return _participants.TryGetParticipant(
                identityKey,
                out participant);
        }

        public bool TryGetParticipant(
            IServerPlayer player,
            out ParticipantSession participant)
        {
            participant = null;

            string identity =
                NormalizeIdentity(
                    player == null ? null : player.AuthKey);

            if (identity == null)
            {
                return false;
            }

            return TryGetParticipant(
                identity,
                out participant);
        }

        public bool IsLockedParticipant(
            string identityKey)
        {
            string identity =
                NormalizeIdentity(identityKey);

            if (identity == null)
            {
                return false;
            }

            lock (_sync)
            {
                return _session.IsLocked &&
                       _membership.CanAcceptIdentity(identity);
            }
        }

        public bool IsLockedParticipant(
            IServerPlayer player)
        {
            return IsLockedParticipant(
                player == null ? null : player.AuthKey);
        }

        public bool RegisterParticipant(
            IServerPlayer player,
            out ParticipantSession participant,
            out string reason)
        {
            participant = null;
            reason = null;

            if (player == null)
            {
                reason = "PLAYER_NULL";
                return false;
            }

            string identity =
                NormalizeIdentity(
                    player.AuthKey);

            if (identity == null)
            {
                reason = "PARTICIPANT_IDENTITY_MISSING";
                return false;
            }

            return RegisterParticipant(
                identity,
                player.Username,
                DateTime.UtcNow,
                out participant,
                out reason);
        }

        public bool MarkParticipantScanning(
            IServerPlayer player)
        {
            string identity =
                NormalizeIdentity(
                    player == null ? null : player.AuthKey);

            if (identity == null)
            {
                return false;
            }

            string reason;
            return MarkParticipantScanning(
                identity,
                DateTime.UtcNow,
                out reason);
        }

        public bool MarkParticipantChallenging(
            IServerPlayer player)
        {
            string identity =
                NormalizeIdentity(
                    player == null ? null : player.AuthKey);

            if (identity == null)
            {
                return false;
            }

            string reason;
            return MarkParticipantChallenging(
                identity,
                DateTime.UtcNow,
                out reason);
        }

        public bool MarkParticipantVerified(
            IServerPlayer player,
            string baselineId)
        {
            string identity =
                NormalizeIdentity(
                    player == null ? null : player.AuthKey);

            if (identity == null)
            {
                return false;
            }

            string reason;
            return MarkParticipantVerified(
                identity,
                baselineId,
                DateTime.UtcNow,
                out reason);
        }

        public bool MarkParticipantActive(
            IServerPlayer player)
        {
            string identity =
                NormalizeIdentity(
                    player == null ? null : player.AuthKey);

            if (identity == null)
            {
                return false;
            }

            string reason;
            return MarkParticipantActive(
                identity,
                DateTime.UtcNow,
                out reason);
        }

        public bool MarkParticipantDisconnected(
            IServerPlayer player)
        {
            string identity =
                NormalizeIdentity(
                    player == null ? null : player.AuthKey);

            if (identity == null)
            {
                return false;
            }

            string reason;
            return MarkParticipantDisconnected(
                identity,
                DateTime.UtcNow,
                out reason);
        }

        public bool MarkParticipantReconnecting(
            IServerPlayer player)
        {
            string identity =
                NormalizeIdentity(
                    player == null ? null : player.AuthKey);

            if (identity == null)
            {
                return false;
            }

            string reason;
            return MarkParticipantReconnecting(
                identity,
                DateTime.UtcNow,
                out reason);
        }

        public bool MarkParticipantRejected(
            IServerPlayer player,
            string denyCode,
            string rejectionReason)
        {
            string identity =
                NormalizeIdentity(
                    player == null ? null : player.AuthKey);

            if (identity == null)
            {
                return false;
            }

            string reason;
            return MarkParticipantRejected(
                identity,
                denyCode,
                rejectionReason,
                DateTime.UtcNow,
                out reason);
        }

        private static string NormalizeIdentity(
            string identity)
        {
            if (string.IsNullOrWhiteSpace(identity))
            {
                return null;
            }

            return identity.Trim();
        }

        private static string GetBuildFailureReason(
            HostBaselineBuildResult result)
        {
            if (result == null)
            {
                return "HOST_BASELINE_BUILD_RESULT_NULL";
            }

            if (result.Failures != null &&
                result.Failures.Count > 0)
            {
                string firstFailure =
                    result.Failures[0];

                if (!string.IsNullOrWhiteSpace(
                    firstFailure))
                {
                    return
                        "HOST_BASELINE_BUILD_FAILED: " +
                        firstFailure;
                }
            }

            return
                "HOST_BASELINE_BUILD_INCOMPLETE";
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
