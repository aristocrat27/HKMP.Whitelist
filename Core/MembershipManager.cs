using System;
using System.Collections.Generic;
using System.Linq;
using HKMP.Whitelist.Shared;

namespace HKMP.Whitelist.Core
{
    public sealed class MembershipManager
    {
        private readonly object _gate =
            new object();

        private MembershipSnapshot _snapshot;

        public bool IsLocked
        {
            get
            {
                lock (_gate)
                {
                    return
                        _snapshot != null &&
                        _snapshot.IsFrozen;
                }
            }
        }

        public MembershipSnapshot Snapshot
        {
            get
            {
                lock (_gate)
                {
                    return CloneSnapshot(
                        _snapshot);
                }
            }
        }

        public int Count
        {
            get
            {
                lock (_gate)
                {
                    return
                        _snapshot == null
                            ? 0
                            : _snapshot.Count;
                }
            }
        }

        public bool TryCreateSnapshot(
            string sessionId,
            string baselineId,
            IEnumerable<ParticipantSession> participants,
            DateTime utcNow,
            out MembershipSnapshot snapshot,
            out string reason)
        {
            snapshot =
                null;

            reason =
                null;

            if (string.IsNullOrWhiteSpace(
                    sessionId))
            {
                reason =
                    "Session ID is missing.";

                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    baselineId))
            {
                reason =
                    "Baseline ID is missing.";

                return false;
            }

            if (participants == null)
            {
                reason =
                    "Participant collection is missing.";

                return false;
            }

            lock (_gate)
            {
                if (_snapshot != null &&
                    _snapshot.IsFrozen)
                {
                    reason =
                        "Membership is already locked.";

                    return false;
                }

                MembershipSnapshot created =
                    new MembershipSnapshot(
                        sessionId,
                        baselineId,
                        NormalizeUtc(
                            utcNow));

                HashSet<string> identities =
                    new HashSet<string>(
                        StringComparer.OrdinalIgnoreCase);

                foreach (ParticipantSession participant
                         in participants)
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
                            "A verified participant has no identity key.";

                        return false;
                    }

                    if (!string.IsNullOrWhiteSpace(
                            participant.SessionId) &&
                        !string.Equals(
                            participant.SessionId,
                            sessionId.Trim(),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        reason =
                            "Participant belongs to another session.";

                        return false;
                    }

                    if (!string.IsNullOrWhiteSpace(
                            participant.LastBaselineId) &&
                        !string.Equals(
                            participant.LastBaselineId,
                            baselineId.Trim(),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        reason =
                            "Participant baseline does not match the session baseline.";

                        return false;
                    }

                    string identity =
                        participant.IdentityKey.Trim();

                    if (!identities.Add(
                            identity))
                    {
                        continue;
                    }

                    if (!created.Add(
                            participant))
                    {
                        reason =
                            "Failed to add participant to membership snapshot.";

                        return false;
                    }
                }

                snapshot =
                    CloneSnapshot(
                        created);

                return true;
            }
        }

        public bool Lock(
            MembershipSnapshot snapshot,
            DateTime utcNow,
            out string reason)
        {
            reason =
                null;

            if (snapshot == null)
            {
                reason =
                    "Membership snapshot is missing.";

                return false;
            }

            lock (_gate)
            {
                if (_snapshot != null &&
                    _snapshot.IsFrozen)
                {
                    if (ReferenceEquals(
                            _snapshot,
                            snapshot))
                    {
                        reason =
                            "Membership is already locked.";

                        return false;
                    }

                    reason =
                        "Another membership snapshot is already locked.";

                    return false;
                }

                if (snapshot.IsFrozen)
                {
                    reason =
                        "Membership snapshot is already frozen.";

                    return false;
                }

                snapshot.Freeze(
                    NormalizeUtc(
                        utcNow));

                _snapshot =
                    CloneSnapshot(
                        snapshot);

                return true;
            }
        }

        public bool BuildAndLock(
            string sessionId,
            string baselineId,
            IEnumerable<ParticipantSession> participants,
            DateTime utcNow,
            out MembershipSnapshot snapshot,
            out string reason)
        {
            snapshot =
                null;

            reason =
                null;

            MembershipSnapshot created;

            if (!TryCreateSnapshot(
                    sessionId,
                    baselineId,
                    participants,
                    utcNow,
                    out created,
                    out reason))
            {
                return false;
            }

            if (!Lock(
                    created,
                    utcNow,
                    out reason))
            {
                return false;
            }

            snapshot =
                Snapshot;

            return
                snapshot != null &&
                snapshot.IsFrozen;
        }

        public bool ContainsIdentity(
            string identityKey)
        {
            lock (_gate)
            {
                if (_snapshot == null)
                {
                    return false;
                }

                return _snapshot.ContainsIdentity(
                    identityKey);
            }
        }

        public bool CanAcceptIdentity(
            string identityKey)
        {
            if (string.IsNullOrWhiteSpace(
                    identityKey))
            {
                return false;
            }

            lock (_gate)
            {
                if (_snapshot == null ||
                    !_snapshot.IsFrozen)
                {
                    return true;
                }

                return _snapshot.ContainsIdentity(
                    identityKey);
            }
        }

        public bool TryGetMember(
            string identityKey,
            out MembershipMember member)
        {
            lock (_gate)
            {
                member =
                    null;

                if (_snapshot == null)
                {
                    return false;
                }

                return _snapshot.TryGetMember(
                    identityKey,
                    out member);
            }
        }

        public IReadOnlyList<MembershipMember>
            GetMembers()
        {
            lock (_gate)
            {
                if (_snapshot == null)
                {
                    return
                        new List<MembershipMember>()
                            .AsReadOnly();
                }

                return _snapshot.Members;
            }
        }

        public bool IsMemberAndBaselineMatch(
            string identityKey,
            string baselineId)
        {
            if (string.IsNullOrWhiteSpace(
                    identityKey) ||
                string.IsNullOrWhiteSpace(
                    baselineId))
            {
                return false;
            }

            lock (_gate)
            {
                if (_snapshot == null ||
                    !_snapshot.IsFrozen)
                {
                    return false;
                }

                MembershipMember member;

                if (!_snapshot.TryGetMember(
                        identityKey,
                        out member) ||
                    member == null)
                {
                    return false;
                }

                if (string.IsNullOrWhiteSpace(
                        member.BaselineId))
                {
                    return false;
                }

                return string.Equals(
                    member.BaselineId,
                    baselineId.Trim(),
                    StringComparison.OrdinalIgnoreCase);
            }
        }

        public bool MarkParticipantLocked(
            ParticipantSession participant)
        {
            if (participant == null)
            {
                return false;
            }

            lock (_gate)
            {
                if (_snapshot == null ||
                    !_snapshot.IsFrozen)
                {
                    return false;
                }

                if (!_snapshot.ContainsIdentity(
                        participant.IdentityKey))
                {
                    return false;
                }

                participant.MarkMemberWhenLocked();

                return true;
            }
        }

        public void Clear()
        {
            lock (_gate)
            {
                _snapshot =
                    null;
            }
        }

        private static MembershipSnapshot CloneSnapshot(
            MembershipSnapshot source)
        {
            if (source == null)
            {
                return null;
            }

            MembershipSnapshot clone =
                new MembershipSnapshot();

            clone.SetIdentity(
                source.SessionId,
                source.BaselineId);

            foreach (MembershipMember member
                     in source.Members)
            {
                if (member == null)
                {
                    continue;
                }

                clone.Add(
                    member);
            }

            if (source.IsFrozen)
            {
                clone.Freeze(
                    source.LockedAtUtc);
            }

            return clone;
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