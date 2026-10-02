using System;
using System.IO;
using Hkmp.Api.Server;
using HKMP.Whitelist.Shared;
using Modding;
using Newtonsoft.Json;

namespace HKMP.Whitelist.Server
{
    public sealed class SecurityAuditLogger
    {
        private readonly object _sync =
            new object();

        private readonly IServerApi _api;

        private readonly string _baseDirectory;

        public SecurityAuditLogger(
            IServerApi api,
            string baseDirectory)
        {
            _api =
                api;

            _baseDirectory =
                string.IsNullOrWhiteSpace(
                    baseDirectory)
                    ? null
                    : baseDirectory.Trim();
        }

        public void HandleEvent(
            SecurityEvent securityEvent)
        {
            if (securityEvent == null)
            {
                return;
            }

            string structured =
                BuildStructuredLog(
                    securityEvent);

            try
            {
                if (securityEvent.EventType ==
                        SecurityEventType.PlayerRejected ||
                    securityEvent.EventType ==
                        SecurityEventType.ChallengeRejected ||
                    securityEvent.EventType ==
                        SecurityEventType.UnknownArtifact ||
                    securityEvent.EventType ==
                        SecurityEventType.ForbiddenArtifact ||
                    securityEvent.EventType ==
                        SecurityEventType.ArtifactMismatch ||
                    securityEvent.EventType ==
                        SecurityEventType.RuntimeChangeDetected ||
                    securityEvent.EventType ==
                        SecurityEventType.SaveChangeDetected ||
                    securityEvent.EventType ==
                        SecurityEventType.ProtocolViolation)
                {
                    SendHostChat(
                        securityEvent);
                }
            }
            catch
            {
            }

            try
            {
                Modding.Logger.Log(
                    "[Whitelist][SecurityAudit] " +
                    structured);
            }
            catch
            {
            }

            PersistEvent(
                securityEvent,
                structured);
        }

        private void SendHostChat(
            SecurityEvent securityEvent)
        {
            if (_api == null ||
                _api.ServerManager == null)
            {
                return;
            }

            string displayName =
                string.IsNullOrWhiteSpace(
                    securityEvent.DisplayName)
                    ? "<unknown>"
                    : securityEvent.DisplayName.Trim();

            string message =
                string.IsNullOrWhiteSpace(
                    securityEvent.Message)
                    ? securityEvent.EventType.ToString()
                    : securityEvent.Message.Trim();

            message =
                Truncate(
                    message,
                    500);

            string chat =
                "[Whitelist] " +
                displayName +
                " rejected: " +
                message;

            try
            {
                _api.ServerManager.BroadcastMessage(
                    chat);
            }
            catch
            {
            }
        }

        private string BuildStructuredLog(
            SecurityEvent securityEvent)
        {
            object payload =
                new
                {
                    EventId =
                        securityEvent.EventId,

                    TimestampUtc =
                        securityEvent.TimestampUtc,

                    SessionId =
                        securityEvent.SessionId,

                    EventType =
                        securityEvent.EventType.ToString(),

                    Severity =
                        securityEvent.Severity.ToString(),

                    PlayerIdentityKey =
                        securityEvent.PlayerIdentityKey,

                    DisplayName =
                        securityEvent.DisplayName,

                    ProviderName =
                        securityEvent.ProviderName,

                    Message =
                        securityEvent.Message,

                    EvidenceSummary =
                        securityEvent.EvidenceSummary
                };

            try
            {
                return
                    JsonConvert.SerializeObject(
                        payload,
                        Formatting.None);
            }
            catch
            {
                return
                    securityEvent.ToString();
            }
        }

        private void PersistEvent(
            SecurityEvent securityEvent,
            string structured)
        {
            if (string.IsNullOrWhiteSpace(
                    _baseDirectory))
            {
                return;
            }

            string sessionId =
                SanitizePathSegment(
                    securityEvent.SessionId);

            if (string.IsNullOrWhiteSpace(
                    sessionId))
            {
                sessionId =
                    "unknown-session";
            }

            string sessionDirectory;

            try
            {
                sessionDirectory =
                    Path.Combine(
                        _baseDirectory,
                        "sessions",
                        sessionId);
            }
            catch
            {
                return;
            }

            string path;

            try
            {
                path =
                    Path.Combine(
                        sessionDirectory,
                        "events.jsonl");
            }
            catch
            {
                return;
            }

            lock (_sync)
            {
                try
                {
                    if (!Directory.Exists(
                            sessionDirectory))
                    {
                        Directory.CreateDirectory(
                            sessionDirectory);
                    }

                    File.AppendAllText(
                        path,
                        structured +
                        Environment.NewLine);
                }
                catch
                {
                }
            }
        }

        private static string SanitizePathSegment(
            string value)
        {
            if (string.IsNullOrWhiteSpace(
                    value))
            {
                return null;
            }

            char[] invalid =
                Path.GetInvalidFileNameChars();

            string trimmed =
                value.Trim();

            System.Text.StringBuilder builder =
                new System.Text.StringBuilder(
                    trimmed.Length);

            foreach (char c in trimmed)
            {
                bool invalidCharacter =
                    false;

                for (int i = 0;
                     i < invalid.Length;
                     i++)
                {
                    if (c == invalid[i])
                    {
                        invalidCharacter = true;
                        break;
                    }
                }

                if (invalidCharacter)
                {
                    builder.Append('_');
                }
                else
                {
                    builder.Append(c);
                }
            }

            string result =
                builder.ToString();

            if (result.Length > 128)
            {
                result =
                    result.Substring(
                        0,
                        128);
            }

            return result;
        }

        private static string Truncate(
            string value,
            int maximumLength)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            if (value.Length <= maximumLength)
            {
                return value;
            }

            return
                value.Substring(
                    0,
                    maximumLength) +
                "...";
        }
    }
}