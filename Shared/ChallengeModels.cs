using System;

namespace HKMP.Whitelist.Shared
{
    public enum ChallengeValidationCode
    {
        Accepted,
        NullResponse,
        InvalidParticipant,
        SessionMismatch,
        ChallengeNotFound,
        ReplayDetected,
        GenerationMismatch,
        SequenceMismatch,
        Expired,
        HmacMissing,
        HmacMismatch,
        ProtocolVersionMismatch
    }

    public enum ChallengeDisposition
    {
        Pending,
        Accepted,
        Expired,
        Superseded,
        Cancelled
    }

    public sealed class ChallengeRequest
    {
        public int ProtocolVersion { get; set; } = 2;

        public string SessionId { get; set; }

        public string ChallengeId { get; set; }

        public string NonceBase64 { get; set; }

        public DateTime IssuedAtUtc { get; set; }

        public DateTime ExpiresAtUtc { get; set; }

        public long SecurityGeneration { get; set; }

        public long SequenceNumber { get; set; }
    }

    public sealed class ChallengeResponse
    {
        public int ProtocolVersion { get; set; } = 2;

        public string SessionId { get; set; }

        public string ChallengeId { get; set; }

        public long SecurityGeneration { get; set; }

        public long SequenceNumber { get; set; }

        public string Hmac { get; set; }
    }

    public sealed class ChallengeValidationResult
    {
        public ChallengeValidationCode Code { get; internal set; }

        public bool Accepted
        {
            get
            {
                return Code ==
                    ChallengeValidationCode.Accepted;
            }
        }

        public string ChallengeId { get; internal set; }

        public string SessionId { get; internal set; }

        public long SecurityGeneration { get; internal set; }

        public long SequenceNumber { get; internal set; }

        public string Reason { get; internal set; }
    }

    public sealed class ChallengeIssueResult
    {
        public bool Success { get; internal set; }

        public ChallengeRequest Request { get; internal set; }

        public string ParticipantIdentityKey { get; internal set; }

        public string Error { get; internal set; }
    }
}