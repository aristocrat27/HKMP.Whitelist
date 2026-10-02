using HKMP.Whitelist.Security;
using HKMP.Whitelist.Shared;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace HKMP.Whitelist.Server
{
    internal sealed class ChallengeService
    {
        private const int ProtocolVersion = 2;
        private const int NonceSize = 32;
        private const int DefaultTimeoutMs = 3000;
        private const int MinimumTimeoutMs = 500;
        private const int MaximumTimeoutMs = 30000;
        private const int MaximumRetiredChallenges = 1024;

        private readonly object _gate =
            new object();

        private readonly Dictionary<string, ParticipantChallengeState>
            _participants =
                new Dictionary<string, ParticipantChallengeState>(
                    StringComparer.OrdinalIgnoreCase);

        private readonly Dictionary<string, RetiredChallenge>
            _retiredChallenges =
                new Dictionary<string, RetiredChallenge>(
                    StringComparer.Ordinal);

        private bool _disposed;

        public event Action<string, ChallengeValidationResult>
            ChallengeExpired;

        public int PendingCount
        {
            get
            {
                lock (_gate)
                {
                    if (_disposed)
                    {
                        return 0;
                    }

                    int count = 0;

                    foreach (ParticipantChallengeState state
                             in _participants.Values)
                    {
                        if (state != null &&
                            state.Pending != null)
                        {
                            count++;
                        }
                    }

                    return count;
                }
            }
        }

        public ChallengeIssueResult IssueChallenge(
            string sessionId,
            string participantIdentityKey,
            byte[] expectedArtifactBytes,
            TimeSpan timeout)
        {
            if (_disposed)
            {
                return Failure(
                    participantIdentityKey,
                    "ChallengeService is disposed.");
            }

            if (string.IsNullOrWhiteSpace(sessionId))
            {
                return Failure(
                    participantIdentityKey,
                    "SessionId is empty.");
            }

            if (string.IsNullOrWhiteSpace(
                    participantIdentityKey))
            {
                return Failure(
                    participantIdentityKey,
                    "Participant identity is empty.");
            }

            if (expectedArtifactBytes == null ||
                expectedArtifactBytes.Length == 0)
            {
                return Failure(
                    participantIdentityKey,
                    "Expected challenge artifact is empty.");
            }

            timeout =
                NormalizeTimeout(
                    timeout);

            byte[] nonce =
                new byte[NonceSize];

            try
            {
                using (RandomNumberGenerator rng =
                       RandomNumberGenerator.Create())
                {
                    rng.GetBytes(
                        nonce);
                }
            }
            catch
            {
                return Failure(
                    participantIdentityKey,
                    "Failed to generate a secure challenge nonce.");
            }

            DateTime issuedAtUtc =
                DateTime.UtcNow;

            DateTime expiresAtUtc =
                issuedAtUtc +
                timeout;

            string challengeId =
                Guid.NewGuid().ToString("N");

            ChallengeRequest request =
                new ChallengeRequest
                {
                    ProtocolVersion =
                        ProtocolVersion,

                    SessionId =
                        sessionId,

                    ChallengeId =
                        challengeId,

                    NonceBase64 =
                        Convert.ToBase64String(
                            nonce),

                    IssuedAtUtc =
                        issuedAtUtc,

                    ExpiresAtUtc =
                        expiresAtUtc,

                    SecurityGeneration =
                        0,

                    SequenceNumber =
                        0
                };

            PendingChallenge pending;

            lock (_gate)
            {
                if (_disposed)
                {
                    return Failure(
                        participantIdentityKey,
                        "ChallengeService is disposed.");
                }

                ParticipantChallengeState state =
                    GetOrCreateParticipantState(
                        participantIdentityKey);

                if (state.Pending != null)
                {
                    RetireChallengeLocked(
                        state.Pending,
                        ChallengeDisposition.Superseded);
                }

                if (state.Generation <= 0)
                {
                    state.Generation = 1;
                }

                state.SequenceNumber++;

                request.SecurityGeneration =
                    state.Generation;

                request.SequenceNumber =
                    state.SequenceNumber;

                pending =
                    new PendingChallenge
                    {
                        ParticipantIdentityKey =
                            participantIdentityKey,

                        SessionId =
                            sessionId,

                        ChallengeId =
                            challengeId,

                        Nonce =
                            nonce,

                        ExpectedArtifactBytes =
                            (byte[])expectedArtifactBytes.Clone(),

                        IssuedAtUtc =
                            issuedAtUtc,

                        ExpiresAtUtc =
                            expiresAtUtc,

                        SecurityGeneration =
                            state.Generation,

                        SequenceNumber =
                            state.SequenceNumber
                    };

                state.Pending =
                    pending;
            }

            ScheduleExpiration(
                participantIdentityKey,
                challengeId,
                expiresAtUtc);

            return new ChallengeIssueResult
            {
                Success = true,
                Request = request,
                ParticipantIdentityKey =
                    participantIdentityKey,
                Error = null
            };
        }

        public long BeginSecurityGeneration(
            string participantIdentityKey)
        {
            if (string.IsNullOrWhiteSpace(
                    participantIdentityKey))
            {
                return 0;
            }

            lock (_gate)
            {
                if (_disposed)
                {
                    return 0;
                }

                ParticipantChallengeState state =
                    GetOrCreateParticipantState(
                        participantIdentityKey);

                if (state.Pending != null)
                {
                    RetireChallengeLocked(
                        state.Pending,
                        ChallengeDisposition.Superseded);

                    state.Pending = null;
                }

                state.Generation++;

                if (state.Generation <= 0)
                {
                    state.Generation = 1;
                }

                state.SequenceNumber = 0;

                return state.Generation;
            }
        }

        public long GetSecurityGeneration(
            string participantIdentityKey)
        {
            if (string.IsNullOrWhiteSpace(
                    participantIdentityKey))
            {
                return 0;
            }

            lock (_gate)
            {
                if (_disposed)
                {
                    return 0;
                }

                ParticipantChallengeState state;

                if (!_participants.TryGetValue(
                        participantIdentityKey,
                        out state) ||
                    state == null)
                {
                    return 0;
                }

                return state.Generation;
            }
        }

        public bool HasPendingChallenge(
            string participantIdentityKey)
        {
            if (string.IsNullOrWhiteSpace(
                    participantIdentityKey))
            {
                return false;
            }

            lock (_gate)
            {
                if (_disposed)
                {
                    return false;
                }

                ParticipantChallengeState state;

                if (!_participants.TryGetValue(
                        participantIdentityKey,
                        out state) ||
                    state == null)
                {
                    return false;
                }

                return state.Pending != null;
            }
        }

        public bool TryGetPendingChallenge(
            string participantIdentityKey,
            out ChallengeRequest request)
        {
            request = null;

            if (string.IsNullOrWhiteSpace(
                    participantIdentityKey))
            {
                return false;
            }

            lock (_gate)
            {
                if (_disposed)
                {
                    return false;
                }

                ParticipantChallengeState state;

                if (!_participants.TryGetValue(
                        participantIdentityKey,
                        out state) ||
                    state == null ||
                    state.Pending == null)
                {
                    return false;
                }

                PendingChallenge pending =
                    state.Pending;

                if (DateTime.UtcNow >
                    pending.ExpiresAtUtc)
                {
                    RetireChallengeLocked(
                        pending,
                        ChallengeDisposition.Expired);

                    state.Pending = null;

                    return false;
                }

                request =
                    CreateRequest(
                        pending);

                return true;
            }
        }

        public ChallengeValidationResult ValidateResponse(
            string actualSessionId,
            string actualParticipantIdentityKey,
            ChallengeResponse response)
        {
            if (_disposed)
            {
                return Result(
                    ChallengeValidationCode.InvalidParticipant,
                    response,
                    "ChallengeService is disposed.");
            }

            if (string.IsNullOrWhiteSpace(
                    actualParticipantIdentityKey))
            {
                return Result(
                    ChallengeValidationCode.InvalidParticipant,
                    response,
                    "Participant identity is empty.");
            }

            if (response == null)
            {
                return Result(
                    ChallengeValidationCode.NullResponse,
                    null,
                    "Challenge response is null.");
            }

            if (response.ProtocolVersion !=
                ProtocolVersion)
            {
                return Result(
                    ChallengeValidationCode.ProtocolVersionMismatch,
                    response,
                    "Unsupported challenge protocol version.");
            }

            if (string.IsNullOrWhiteSpace(
                    actualSessionId))
            {
                return Result(
                    ChallengeValidationCode.SessionMismatch,
                    response,
                    "Current session ID is empty.");
            }

            if (string.IsNullOrWhiteSpace(
                    response.SessionId) ||
                !string.Equals(
                    response.SessionId,
                    actualSessionId,
                    StringComparison.Ordinal))
            {
                return Result(
                    ChallengeValidationCode.SessionMismatch,
                    response,
                    "Challenge response session does not match the current session.");
            }

            if (string.IsNullOrWhiteSpace(
                    response.ChallengeId))
            {
                return Result(
                    ChallengeValidationCode.ChallengeNotFound,
                    response,
                    "Challenge ID is empty.");
            }

            lock (_gate)
            {
                ParticipantChallengeState state;

                if (!_participants.TryGetValue(
                        actualParticipantIdentityKey,
                        out state) ||
                    state == null)
                {
                    return Result(
                        ChallengeValidationCode.ChallengeNotFound,
                        response,
                        "No challenge state exists for this participant.");
                }

                PendingChallenge pending =
                    state.Pending;

                if (pending == null)
                {
                    if (IsRetiredChallengeLocked(
                            response.ChallengeId))
                    {
                        return Result(
                            ChallengeValidationCode.ReplayDetected,
                            response,
                            "Challenge has already been consumed or invalidated.");
                    }

                    return Result(
                        ChallengeValidationCode.ChallengeNotFound,
                        response,
                        "No outstanding challenge exists.");
                }

                if (!string.Equals(
                        response.ChallengeId,
                        pending.ChallengeId,
                        StringComparison.Ordinal))
                {
                    if (IsRetiredChallengeLocked(
                            response.ChallengeId))
                    {
                        return Result(
                            ChallengeValidationCode.ReplayDetected,
                            response,
                            "Response references an old challenge.");
                    }

                    return Result(
                        ChallengeValidationCode.ChallengeNotFound,
                        response,
                        "Challenge ID does not match the current outstanding challenge.");
                }

                if (!string.Equals(
                        pending.SessionId,
                        actualSessionId,
                        StringComparison.Ordinal))
                {
                    return Result(
                        ChallengeValidationCode.SessionMismatch,
                        response,
                        "Outstanding challenge belongs to another session.");
                }

                if (response.SecurityGeneration !=
                    pending.SecurityGeneration)
                {
                    return Result(
                        ChallengeValidationCode.GenerationMismatch,
                        response,
                        "Challenge security generation mismatch.");
                }

                if (response.SequenceNumber !=
                    pending.SequenceNumber)
                {
                    return Result(
                        ChallengeValidationCode.SequenceMismatch,
                        response,
                        "Challenge sequence mismatch.");
                }

                if (DateTime.UtcNow >
                    pending.ExpiresAtUtc)
                {
                    RetireChallengeLocked(
                        pending,
                        ChallengeDisposition.Expired);

                    state.Pending = null;

                    return Result(
                        ChallengeValidationCode.Expired,
                        response,
                        "Challenge has expired.");
                }

                if (string.IsNullOrWhiteSpace(
                        response.Hmac))
                {
                    RetireChallengeLocked(
                        pending,
                        ChallengeDisposition.Cancelled);

                    state.Pending = null;

                    return Result(
                        ChallengeValidationCode.HmacMissing,
                        response,
                        "Challenge response contains no proof.");
                }

                ChallengeRequest request =
                    CreateRequest(
                        pending);

                byte[] proofMessage =
                    ChallengeProofBuilder.BuildMessage(
                        request,
                        pending.ExpectedArtifactBytes);

                if (proofMessage == null ||
                    proofMessage.Length == 0)
                {
                    RetireChallengeLocked(
                        pending,
                        ChallengeDisposition.Cancelled);

                    state.Pending = null;

                    return Result(
                        ChallengeValidationCode.HmacMismatch,
                        response,
                        "Challenge proof payload could not be constructed.");
                }

                string expectedHmac =
                    HashUtil.HmacSha256(
                        pending.Nonce,
                        proofMessage);

                if (string.IsNullOrWhiteSpace(
                        expectedHmac) ||
                    !HashUtil.FixedTimeEquals(
                        response.Hmac,
                        expectedHmac))
                {
                    RetireChallengeLocked(
                        pending,
                        ChallengeDisposition.Cancelled);

                    state.Pending = null;

                    return Result(
                        ChallengeValidationCode.HmacMismatch,
                        response,
                        "Challenge proof does not match.");
                }

                RetireChallengeLocked(
                    pending,
                    ChallengeDisposition.Accepted);

                state.Pending = null;

                return Result(
                    ChallengeValidationCode.Accepted,
                    response,
                    "Challenge proof accepted.");
            }
        }

        public void CancelParticipant(
            string participantIdentityKey)
        {
            if (string.IsNullOrWhiteSpace(
                    participantIdentityKey))
            {
                return;
            }

            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                ParticipantChallengeState state;

                if (!_participants.TryGetValue(
                        participantIdentityKey,
                        out state) ||
                    state == null ||
                    state.Pending == null)
                {
                    return;
                }

                RetireChallengeLocked(
                    state.Pending,
                    ChallengeDisposition.Cancelled);

                state.Pending = null;
            }
        }

        public void CancelSession(
            string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
            {
                return;
            }

            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                foreach (ParticipantChallengeState state
                         in _participants.Values)
                {
                    if (state == null ||
                        state.Pending == null)
                    {
                        continue;
                    }

                    if (!string.Equals(
                            state.Pending.SessionId,
                            sessionId,
                            StringComparison.Ordinal))
                    {
                        continue;
                    }

                    RetireChallengeLocked(
                        state.Pending,
                        ChallengeDisposition.Cancelled);

                    state.Pending = null;
                }
            }
        }

        public void RemoveParticipant(
            string participantIdentityKey)
        {
            if (string.IsNullOrWhiteSpace(
                    participantIdentityKey))
            {
                return;
            }

            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                ParticipantChallengeState state;

                if (_participants.TryGetValue(
                        participantIdentityKey,
                        out state) &&
                    state != null &&
                    state.Pending != null)
                {
                    RetireChallengeLocked(
                        state.Pending,
                        ChallengeDisposition.Cancelled);
                }

                _participants.Remove(
                    participantIdentityKey);
            }
        }

        public void Clear()
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                foreach (ParticipantChallengeState state
                         in _participants.Values)
                {
                    if (state == null ||
                        state.Pending == null)
                    {
                        continue;
                    }

                    RetireChallengeLocked(
                        state.Pending,
                        ChallengeDisposition.Cancelled);
                }

                _participants.Clear();
                _retiredChallenges.Clear();
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;

                _participants.Clear();
                _retiredChallenges.Clear();
            }
        }

        private void ScheduleExpiration(
            string participantIdentityKey,
            string challengeId,
            DateTime expiresAtUtc)
        {
            Task.Run(
                async () =>
                {
                    TimeSpan delay =
                        expiresAtUtc -
                        DateTime.UtcNow;

                    if (delay > TimeSpan.Zero)
                    {
                        await Task.Delay(
                            delay)
                            .ConfigureAwait(false);
                    }

                    ChallengeValidationResult result =
                        null;

                    bool expired =
                        false;

                    lock (_gate)
                    {
                        if (_disposed)
                        {
                            return;
                        }

                        ParticipantChallengeState state;

                        if (!_participants.TryGetValue(
                                participantIdentityKey,
                                out state) ||
                            state == null ||
                            state.Pending == null)
                        {
                            return;
                        }

                        if (!string.Equals(
                                state.Pending.ChallengeId,
                                challengeId,
                                StringComparison.Ordinal))
                        {
                            return;
                        }

                        if (DateTime.UtcNow <=
                            state.Pending.ExpiresAtUtc)
                        {
                            return;
                        }

                        PendingChallenge pending =
                            state.Pending;

                        RetireChallengeLocked(
                            pending,
                            ChallengeDisposition.Expired);

                        state.Pending =
                            null;

                        result =
                            Result(
                                ChallengeValidationCode.Expired,
                                new ChallengeResponse
                                {
                                    ProtocolVersion =
                                        ProtocolVersion,

                                    SessionId =
                                        pending.SessionId,

                                    ChallengeId =
                                        pending.ChallengeId,

                                    SecurityGeneration =
                                        pending.SecurityGeneration,

                                    SequenceNumber =
                                        pending.SequenceNumber,

                                    Hmac =
                                        null
                                },
                                "Challenge has expired.");

                        expired =
                            true;
                    }

                    if (expired)
                    {
                        Action<string, ChallengeValidationResult> handler =
                            ChallengeExpired;

                        if (handler != null)
                        {
                            try
                            {
                                handler(
                                    participantIdentityKey,
                                    result);
                            }
                            catch
                            {
                            }
                        }
                    }
                });
        }

        private ParticipantChallengeState
            GetOrCreateParticipantState(
                string participantIdentityKey)
        {
            ParticipantChallengeState state;

            if (_participants.TryGetValue(
                    participantIdentityKey,
                    out state) &&
                state != null)
            {
                return state;
            }

            state =
                new ParticipantChallengeState
                {
                    Generation = 1,
                    SequenceNumber = 0
                };

            _participants[
                participantIdentityKey] =
                state;

            return state;
        }

        private void RetireChallengeLocked(
            PendingChallenge challenge,
            ChallengeDisposition disposition)
        {
            if (challenge == null ||
                string.IsNullOrWhiteSpace(
                    challenge.ChallengeId))
            {
                return;
            }

            _retiredChallenges[
                challenge.ChallengeId] =
                new RetiredChallenge
                {
                    ChallengeId =
                        challenge.ChallengeId,

                    Disposition =
                        disposition,

                    RetiredAtUtc =
                        DateTime.UtcNow
                };

            TrimRetiredChallengesLocked();
        }

        private bool IsRetiredChallengeLocked(
            string challengeId)
        {
            if (string.IsNullOrWhiteSpace(
                    challengeId))
            {
                return false;
            }

            return _retiredChallenges.ContainsKey(
                challengeId);
        }

        private void TrimRetiredChallengesLocked()
        {
            if (_retiredChallenges.Count <=
                MaximumRetiredChallenges)
            {
                return;
            }

            int removeCount =
                _retiredChallenges.Count -
                MaximumRetiredChallenges;

            List<RetiredChallenge> ordered =
                new List<RetiredChallenge>(
                    _retiredChallenges.Values);

            ordered.Sort(
                delegate (
                    RetiredChallenge left,
                    RetiredChallenge right)
                {
                    return left.RetiredAtUtc.CompareTo(
                        right.RetiredAtUtc);
                });

            for (int i = 0;
                 i < ordered.Count &&
                 i < removeCount;
                 i++)
            {
                _retiredChallenges.Remove(
                    ordered[i].ChallengeId);
            }
        }

        private static ChallengeRequest CreateRequest(
            PendingChallenge pending)
        {
            return new ChallengeRequest
            {
                ProtocolVersion =
                    ProtocolVersion,

                SessionId =
                    pending.SessionId,

                ChallengeId =
                    pending.ChallengeId,

                NonceBase64 =
                    Convert.ToBase64String(
                        pending.Nonce),

                IssuedAtUtc =
                    pending.IssuedAtUtc,

                ExpiresAtUtc =
                    pending.ExpiresAtUtc,

                SecurityGeneration =
                    pending.SecurityGeneration,

                SequenceNumber =
                    pending.SequenceNumber
            };
        }

        private static ChallengeValidationResult Result(
            ChallengeValidationCode code,
            ChallengeResponse response,
            string reason)
        {
            return new ChallengeValidationResult
            {
                Code =
                    code,

                ChallengeId =
                    response == null
                        ? null
                        : response.ChallengeId,

                SessionId =
                    response == null
                        ? null
                        : response.SessionId,

                SecurityGeneration =
                    response == null
                        ? 0
                        : response.SecurityGeneration,

                SequenceNumber =
                    response == null
                        ? 0
                        : response.SequenceNumber,

                Reason =
                    reason
            };
        }

        private static ChallengeIssueResult Failure(
            string participantIdentityKey,
            string error)
        {
            return new ChallengeIssueResult
            {
                Success = false,
                Request = null,
                ParticipantIdentityKey =
                    participantIdentityKey,
                Error = error
            };
        }

        private static TimeSpan NormalizeTimeout(
            TimeSpan timeout)
        {
            if (timeout <= TimeSpan.Zero)
            {
                return TimeSpan.FromMilliseconds(
                    DefaultTimeoutMs);
            }

            double milliseconds =
                timeout.TotalMilliseconds;

            if (milliseconds <
                MinimumTimeoutMs)
            {
                milliseconds =
                    MinimumTimeoutMs;
            }

            if (milliseconds >
                MaximumTimeoutMs)
            {
                milliseconds =
                    MaximumTimeoutMs;
            }

            return TimeSpan.FromMilliseconds(
                milliseconds);
        }

        private sealed class ParticipantChallengeState
        {
            public long Generation;
            public long SequenceNumber;
            public PendingChallenge Pending;
        }

        private sealed class PendingChallenge
        {
            public string ParticipantIdentityKey;
            public string SessionId;
            public string ChallengeId;
            public byte[] Nonce;
            public byte[] ExpectedArtifactBytes;
            public DateTime IssuedAtUtc;
            public DateTime ExpiresAtUtc;
            public long SecurityGeneration;
            public long SequenceNumber;
        }

        private sealed class RetiredChallenge
        {
            public string ChallengeId;
            public ChallengeDisposition Disposition;
            public DateTime RetiredAtUtc;
        }
    }
}