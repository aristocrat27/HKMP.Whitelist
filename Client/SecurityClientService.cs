
using Hkmp.Api.Client;
using Hkmp.Api.Client.Networking;
using Hkmp.Networking.Packet;
using HKMP.Whitelist.Security;
using HKMP.Whitelist.Core;
using HKMP.Whitelist.Shared;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WhitelistServerPacketId = HKMP.Whitelist.Shared.WhitelistServerPacketId;

namespace HKMP.Whitelist.Client
{
    internal sealed class WhitelistClientSecurityService
    {
        private readonly ClientAddon _addon;
        private readonly IClientApi _api;
        private readonly IClientAddonNetworkSender<WhitelistServerPacketId> _sender;
        private readonly object _gate =
            new object();

        private HostBaseline _baseline;

        private RuntimeProvider _runtimeProvider;

        private bool _allowed;

        private const int BaselineChunkSize =
            20000;

        private const int MaximumBaselineCharacters =
            8 * 1024 * 1024;

        private const int MaximumBaselineChunks =
            512;

        private const int BaselineTransferTimeoutMs =
            30000;

        private const int SecurityReportTransferTimeoutMs =
            30000;

        private const int SecurityReportChunkSize =
            18000;

        private const int MaximumSecurityReportCharacters =
            8 * 1024 * 1024;

        private const int MaximumSecurityReportChunks =
            512;

        private BaselineTransferState _baselineTransfer;

        private SecurityReportTransferState _reportTransfer;

        public WhitelistClientSecurityService(
            ClientAddon addon,
            IClientApi api)
        {
            _addon =
                addon;

            _api =
                api;

            _sender =
                api.NetClient.GetNetworkSender<WhitelistServerPacketId>(
                    addon);
        }

        public void BeginHandshake()
        {
            lock (_gate)
            {
                _allowed = false;
                _baseline = null;
                _baselineTransfer = null;
                StopRuntimeMonitorInternal();
            }

            Send(
                WhitelistServerPacketId.SecurityHello,
                new JsonPacket
                {
                    Json = JsonConvert.SerializeObject(
                        new SecurityHelloData
                        {
                            ProtocolVersion = 2
                        },
                        Formatting.None)
                });
        }

        public void HandleManifest(
            string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                LogClientError(
                    "Received an empty host baseline payload.");
                RejectAndDisconnect();
                return;
            }

            JObject root;

            try
            {
                root =
                    JObject.Parse(
                        json);
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Received malformed host baseline payload: " +
                    ex.GetType().Name);
                RejectAndDisconnect();
                return;
            }

            bool isChunk =
                root["TransferId"] != null ||
                root["ChunkIndex"] != null ||
                root["ChunkCount"] != null;

            if (!isChunk)
            {
                LogClientError(
                    "Received a host baseline payload without transfer metadata.");
                RejectAndDisconnect();
                return;
            }

            HandleBaselineChunk(
                json);
        }

        private void ResetForNewBaseline()
        {
            lock (_gate)
            {
                _allowed =
                    false;

                _baseline =
                    null;

                _baselineTransfer =
                    null;

                _reportTransfer =
                    null;

                StopRuntimeMonitorInternal();
            }
        }

        private void HandleBaselineChunk(
            string json)
        {
            HostBaselineChunkPacketData chunk;

            try
            {
                chunk =
                    JsonConvert.DeserializeObject<HostBaselineChunkPacketData>(
                        json);
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Failed to deserialize host baseline chunk: " +
                    ex.GetType().Name);
                ResetForNewBaseline();
                RejectAndDisconnect();
                return;
            }

            if (chunk == null ||
                chunk.ProtocolVersion != 1 ||
                string.IsNullOrWhiteSpace(chunk.TransferId) ||
                string.IsNullOrWhiteSpace(chunk.SessionId) ||
                string.IsNullOrWhiteSpace(chunk.BaselineId) ||
                string.IsNullOrWhiteSpace(chunk.Sha256) ||
                !HashUtil.IsSha256(chunk.Sha256) ||
                chunk.ChunkCount < 1 ||
                chunk.ChunkCount > MaximumBaselineChunks ||
                chunk.ChunkIndex < 0 ||
                chunk.ChunkIndex >= chunk.ChunkCount ||
                chunk.TotalLength < 1 ||
                chunk.TotalLength > MaximumBaselineCharacters ||
                string.IsNullOrEmpty(chunk.Data) ||
                chunk.Data.Length > BaselineChunkSize)
            {
                LogClientError(
                    "Received invalid host baseline transfer chunk.");
                ResetForNewBaseline();
                RejectAndDisconnect();
                return;
            }

            string completedJson = null;
            bool startTransfer = false;
            bool valid = true;
            string failure = null;

            lock (_gate)
            {
                if (_baselineTransfer == null ||
                    !string.Equals(
                        _baselineTransfer.TransferId,
                        chunk.TransferId,
                        StringComparison.Ordinal))
                {
                    _allowed = false;
                    _baseline = null;
                    _reportTransfer = null;
                    StopRuntimeMonitorInternal();

                    _baselineTransfer =
                        new BaselineTransferState
                        {
                            TransferId = chunk.TransferId,
                            SessionId = chunk.SessionId,
                            BaselineId = chunk.BaselineId,
                            ChunkCount = chunk.ChunkCount,
                            TotalLength = chunk.TotalLength,
                            Sha256 = chunk.Sha256,
                            CreatedUtc = DateTime.UtcNow
                        };

                    startTransfer = true;
                }

                BaselineTransferState transfer =
                    _baselineTransfer;

                if (!string.Equals(
                        transfer.SessionId,
                        chunk.SessionId,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        transfer.BaselineId,
                        chunk.BaselineId,
                        StringComparison.Ordinal) ||
                    transfer.ChunkCount != chunk.ChunkCount ||
                    transfer.TotalLength != chunk.TotalLength ||
                    !string.Equals(
                        transfer.Sha256,
                        chunk.Sha256,
                        StringComparison.OrdinalIgnoreCase))
                {
                    valid = false;
                    failure =
                        "Host baseline transfer metadata changed during reassembly.";
                }
                else
                {
                    string existing;

                    if (transfer.Chunks.TryGetValue(
                            chunk.ChunkIndex,
                            out existing))
                    {
                        if (!string.Equals(
                                existing,
                                chunk.Data,
                                StringComparison.Ordinal))
                        {
                            valid = false;
                            failure =
                                "Host baseline duplicate chunk contains different data.";
                        }
                    }
                    else
                    {
                        transfer.Chunks.Add(
                            chunk.ChunkIndex,
                            chunk.Data);

                        transfer.CurrentLength +=
                            chunk.Data.Length;

                        if (transfer.CurrentLength >
                            transfer.TotalLength)
                        {
                            valid = false;
                            failure =
                                "Host baseline transfer exceeds its declared total length.";
                        }
                        else if (transfer.Chunks.Count ==
                                 transfer.ChunkCount)
                        {
                            StringBuilder builder =
                                new StringBuilder(
                                    transfer.TotalLength);

                            for (int index = 0;
                                 index < transfer.ChunkCount;
                                 index++)
                            {
                                string value;

                                if (!transfer.Chunks.TryGetValue(
                                        index,
                                        out value))
                                {
                                    builder = null;
                                    break;
                                }

                                builder.Append(
                                    value);
                            }

                            if (builder == null ||
                                builder.Length != transfer.TotalLength)
                            {
                                valid = false;
                                failure =
                                    "Host baseline transfer length is inconsistent.";
                            }
                            else
                            {
                                string assembled =
                                    builder.ToString();

                                string actualHash =
                                    ComputeTextSha256(
                                        assembled);

                                if (!string.Equals(
                                        actualHash,
                                        transfer.Sha256,
                                        StringComparison.OrdinalIgnoreCase))
                                {
                                    valid = false;
                                    failure =
                                        "Host baseline transfer SHA-256 mismatch.";
                                }
                                else
                                {
                                    completedJson =
                                        assembled;
                                    _baselineTransfer = null;
                                }
                            }
                        }
                    }
                }

                if (!valid)
                {
                    _baselineTransfer = null;
                }
            }

            if (!valid)
            {
                LogClientError(
                    failure ??
                    "Host baseline transfer failed validation.");
                ResetForNewBaseline();
                RejectAndDisconnect();
                return;
            }

            if (!SendHostBaselineChunkAck(
                    chunk))
            {
                RejectAndDisconnect();
                return;
            }

            if (completedJson != null)
            {
                LogClientInfo(
                    "Host baseline transfer completed in " +
                    chunk.ChunkCount +
                    " chunk(s).");

                Task.Run(
                    () =>
                        ScanAndReport(
                            completedJson));

                return;
            }

            if (startTransfer)
            {
                string transferId =
                    chunk.TransferId;

                Task.Run(
                    async () =>
                    {
                        await Task.Delay(
                            BaselineTransferTimeoutMs)
                            .ConfigureAwait(false);

                        bool expired = false;

                        lock (_gate)
                        {
                            if (_baselineTransfer != null &&
                                string.Equals(
                                    _baselineTransfer.TransferId,
                                    transferId,
                                    StringComparison.Ordinal))
                            {
                                _baselineTransfer = null;
                                expired = true;
                            }
                        }

                        if (expired)
                        {
                            LogClientError(
                                "Host baseline transfer timed out before all chunks were received.");
                            RejectAndDisconnect();
                        }
                    });
            }
        }

        private bool SendHostBaselineChunkAck(
            HostBaselineChunkPacketData chunk)
        {
            if (chunk == null)
            {
                return false;
            }

            HostBaselineChunkAckData ack =
                new HostBaselineChunkAckData
                {
                    ProtocolVersion = 1,
                    TransferId = chunk.TransferId,
                    SessionId = chunk.SessionId,
                    BaselineId = chunk.BaselineId,
                    ChunkIndex = chunk.ChunkIndex
                };

            try
            {
                _sender.SendSingleData(
                    WhitelistServerPacketId.HostBaselineChunkAck,
                    new JsonPacket
                    {
                        Json =
                            JsonConvert.SerializeObject(
                                ack,
                                Formatting.None)
                    });
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Failed to acknowledge host baseline chunk " +
                    chunk.ChunkIndex +
                    ": " +
                    ex.GetType().Name);
                return false;
            }

            return true;
        }

        private static string ComputeTextSha256(
            string value)
        {
            if (value == null)
            {
                return null;
            }

            try
            {
                byte[] bytes =
                    Encoding.UTF8.GetBytes(
                        value);

                using (SHA256 sha =
                       SHA256.Create())
                {
                    byte[] hash =
                        sha.ComputeHash(
                            bytes);

                    StringBuilder result =
                        new StringBuilder(
                            hash.Length * 2);

                    for (int i = 0;
                         i < hash.Length;
                         i++)
                    {
                        result.Append(
                            hash[i].ToString(
                                "x2"));
                    }

                    return result.ToString();
                }
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Security hash operation failed: " +
                    ex.GetType().Name);
                return null;
            }
        }


        public void HandleChallenge(
            string json)
        {
            Task.Run(
                () =>
                {
                    ChallengeRequest challenge =
                        null;

                    try
                    {
                        challenge =
                            JsonConvert.DeserializeObject<ChallengeRequest>(
                                json);

                        if (challenge == null ||
                            challenge.ProtocolVersion != 2 ||
                            string.IsNullOrWhiteSpace(
                                challenge.SessionId) ||
                            string.IsNullOrWhiteSpace(
                                challenge.ChallengeId) ||
                            string.IsNullOrWhiteSpace(
                                challenge.NonceBase64))
                        {
                            SendChallengeFailure(
                                challenge);

                            return;
                        }

                        byte[] nonce =
                            Convert.FromBase64String(
                                challenge.NonceBase64);

                        if (nonce == null ||
                            nonce.Length != 32)
                        {
                            SendChallengeFailure(
                                challenge);

                            return;
                        }

                        string selfPath =
                            AntiTamperGuard.GetExecutingAssemblyPath();

                        if (string.IsNullOrWhiteSpace(
                                selfPath))
                        {
                            SendChallengeFailure(
                                challenge);

                            return;
                        }

                        byte[] selfBytes =
                            HashUtil.ReadAllBytesShared(
                                selfPath);

                        if (selfBytes == null ||
                            selfBytes.Length == 0)
                        {
                            SendChallengeFailure(
                                challenge);

                            return;
                        }

                        byte[] proofMessage =
                            ChallengeProofBuilder.BuildMessage(
                                challenge,
                                selfBytes);

                        if (proofMessage == null ||
                            proofMessage.Length == 0)
                        {
                            SendChallengeFailure(
                                challenge);

                            return;
                        }

                        string hmac =
                            HashUtil.HmacSha256(
                                nonce,
                                proofMessage);

                        if (string.IsNullOrWhiteSpace(hmac))
                        {
                            SendChallengeFailure(
                                challenge);

                            return;
                        }

                        Send(
                            WhitelistServerPacketId.ChallengeResponse,
                            new JsonPacket
                            {
                                Json =
                                    JsonConvert.SerializeObject(
                                        new ChallengeResponse
                                        {
                                            ProtocolVersion =
                                                challenge.ProtocolVersion,

                                            SessionId =
                                                challenge.SessionId,

                                            ChallengeId =
                                                challenge.ChallengeId,

                                            SecurityGeneration =
                                                challenge.SecurityGeneration,

                                            SequenceNumber =
                                                challenge.SequenceNumber,

                                            Hmac =
                                                hmac
                                        },
                                        Formatting.None)
                            });
                    }
                    catch
                    {
                        SendChallengeFailure(
                            challenge);
                    }
                });
        }

        public void HandleDecision(
            string json)
        {
            try
            {
                SecurityDecision decision =
                    JsonConvert.DeserializeObject<SecurityDecision>(
                        json);

                if (decision == null)
                {
                    RejectAndDisconnect();
                    return;
                }

                if (decision.Allowed)
                {
                    bool runtimeEnabled =
                        decision.RuntimeMonitoringEnabled;

                    lock (_gate)
                    {
                        _allowed =
                            true;
                    }

                    if (runtimeEnabled)
                    {
                        if (!StartRuntimeMonitor(
                                decision.RuntimeScanIntervalSeconds))
                        {
                            RejectAndDisconnect();
                        }
                    }
                    else
                    {
                        StopRuntimeMonitor();
                    }
                }
                else
                {
                    RejectAndDisconnect();
                }
            }
            catch
            {
                RejectAndDisconnect();
            }
        }

        private void ScanAndReport(
            string json)
        {
            Stopwatch stopwatch =
                Stopwatch.StartNew();

            SecurityReport report =
                new SecurityReport
                {
                    ScanTimestampUtc =
                        DateTime.UtcNow,

                    ScanStatus =
                        "Incomplete"
                };

            try
            {
                HostBaseline baseline =
                    DeserializeHostBaseline(
                        json);

                if (baseline == null)
                {
                    report.IntegrityFailures.Add(
                        "Host baseline is missing or malformed.");
                }
                else if (string.IsNullOrWhiteSpace(
                    baseline.BaselineId))
                {
                    report.IntegrityFailures.Add(
                        "Host baseline ID is missing.");
                }
                else if (string.IsNullOrWhiteSpace(
                    baseline.SessionId))
                {
                    report.IntegrityFailures.Add(
                        "Host session ID is missing.");
                }
                else
                {

                    _baseline =
                        baseline;

                    report.DebuggerDetected =
                        AntiTamperGuard.IsDebuggerDetected();

                    report.SelfHash =
                        AntiTamperGuard.ComputeSelfHash();

                    ValidateSelfAgainstBaseline(
                        baseline,
                        report);

                    string gameRoot;
                    string gameRootFailure;

                    if (!GamePathResolver.TryResolve(
                            null,
                            out gameRoot,
                            out gameRootFailure))
                    {
                        report.IntegrityFailures.Add(
                            "Game root could not be resolved: " +
                            (gameRootFailure ?? "unknown reason"));

                        gameRoot =
                            AppDomain.CurrentDomain.BaseDirectory;
                    }

                    FileScannerResult files =
                        FileScanner.Scan(
                            baseline,
                            gameRoot);

                    AssemblyScannerResult assemblies =
                        AssemblyScanner.Scan(
                            baseline);

                    NativeModuleScannerResult native =
                        NativeModuleScanner.Scan(
                            baseline);

                    if (files != null)
                    {
                        if (files.UnknownFiles != null)
                        {
                            report.UnknownFiles.AddRange(
                                files.UnknownFiles);
                        }

                        if (files.ForbiddenFiles != null)
                        {
                            report.ForbiddenFiles.AddRange(
                                files.ForbiddenFiles);
                        }

                        if (files.IntegrityFailures != null)
                        {
                            report.IntegrityFailures.AddRange(
                                files.IntegrityFailures);
                        }

                        if (files.TrustedModIds != null)
                        {
                            report.TrustedModIds.AddRange(
                                files.TrustedModIds);
                        }
                    }
                    else
                    {
                        report.IntegrityFailures.Add(
                            "File scanner returned null.");
                    }

                    if (assemblies != null)
                    {
                        if (assemblies.UnknownAssemblies != null)
                        {
                            report.UnknownAssemblies.AddRange(
                                assemblies.UnknownAssemblies);
                        }

                        if (assemblies.IntegrityFailures != null)
                        {
                            report.IntegrityFailures.AddRange(
                                assemblies.IntegrityFailures);
                        }

                        if (assemblies.TrustedModIds != null)
                        {
                            report.TrustedModIds.AddRange(
                                assemblies.TrustedModIds);
                        }
                    }
                    else
                    {
                        report.IntegrityFailures.Add(
                            "Assembly scanner returned null.");
                    }

                    if (native != null)
                    {
                        if (native.UnknownNativeModules != null)
                        {
                            report.UnknownNativeModules.AddRange(
                                native.UnknownNativeModules);
                        }
                    }
                    else
                    {
                        report.IntegrityFailures.Add(
                            "Native module scanner returned null.");
                    }

                    report.TrustedModIds =
                        report.TrustedModIds
                            .Where(
                                value =>
                                    !string.IsNullOrWhiteSpace(
                                        value))
                            .Select(
                                value =>
                                    value.Trim())
                            .Distinct(
                                StringComparer.OrdinalIgnoreCase)
                            .ToList();

                    bool complete =
                        files != null &&
                        assemblies != null &&
                        native != null &&
                        files.Complete &&
                        assemblies.Complete &&
                        native.Complete &&
                        report.UnreadableFiles.Count == 0;

                    if (report.IntegrityFailures.Count > 0)
                    {
                        complete =
                            false;
                    }

                    report.ScanStatus =
                        complete
                            ? "Complete"
                            : "Incomplete";

                    report.RuntimeEvents.Add(
                        "BaselineId=" +
                        baseline.BaselineId);

                    report.RuntimeEvents.Add(
                        "SessionId=" +
                        baseline.SessionId);

                    report.Evidence =
                        ClientEvidenceCollector.Collect(
                            baseline,
                            gameRoot);

                    if (report.Evidence == null)
                    {
                        report.IntegrityFailures.Add(
                            "Client evidence collection returned null.");
                    }
                    else
                    {
                        if (!string.Equals(
                                report.Evidence.SessionId,
                                baseline.SessionId,
                                StringComparison.Ordinal))
                        {
                            report.IntegrityFailures.Add(
                                "Client evidence session ID does not match host baseline.");
                        }

                        if (!string.Equals(
                                report.Evidence.BaselineId,
                                baseline.BaselineId,
                                StringComparison.Ordinal))
                        {
                            report.IntegrityFailures.Add(
                                "Client evidence baseline ID does not match host baseline.");
                        }

                        if (report.Evidence.IntegrityFailures != null &&
                            report.Evidence.IntegrityFailures.Count > 0)
                        {
                            report.IntegrityFailures.AddRange(
                                report.Evidence.IntegrityFailures);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                report.ScanStatus =
                    "Incomplete";

                report.IntegrityFailures.Add(
                    "Scanner exception: " +
                    ex.GetType().Name);
            }
            finally
            {
                stopwatch.Stop();

                report.ScanDurationMs =
                    stopwatch.ElapsedMilliseconds;
            }

            SendReport(
                report);
        }

        private static HostBaseline DeserializeHostBaseline(
            string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }

            try
            {
                JObject root =
                    JObject.Parse(
                        json);

                JToken baselineToken =
                    root["Baseline"];

                if (baselineToken != null &&
                    baselineToken.Type != JTokenType.Null)
                {
                    return
                        baselineToken.ToObject<HostBaseline>();
                }

                if (root["BaselineId"] != null)
                {
                    return
                        root.ToObject<HostBaseline>();
                }
            }
            catch (Exception ex)
            {
                UnityEngine.Debug.LogError(
                    "[HKMP.Whitelist] Failed to deserialize host baseline: " +
                    ex.GetType().Name);
            }

            return null;
        }

        private static void ValidateSelfAgainstBaseline(
            HostBaseline baseline,
            SecurityReport report)
        {
            if (baseline == null ||
                report == null)
            {
                return;
            }

            string selfPath =
                AntiTamperGuard.GetExecutingAssemblyPath();

            if (string.IsNullOrWhiteSpace(
                    selfPath))
            {
                report.IntegrityFailures.Add(
                    "Whitelist self path is unavailable.");

                return;
            }

            string selfHash =
                report.SelfHash;

            if (string.IsNullOrWhiteSpace(
                    selfHash))
            {
                report.IntegrityFailures.Add(
                    "Whitelist self hash is unavailable.");

                return;
            }

            BaselineArtifact selfArtifact =
                FindSelfArtifact(
                    baseline);

            if (selfArtifact == null)
            {
                report.IntegrityFailures.Add(
                    "HKMP.Whitelist is absent from HostBaseline.");

                return;
            }

            if (!string.IsNullOrWhiteSpace(
                    selfArtifact.Sha256) &&
                !string.Equals(
                    selfArtifact.Sha256,
                    selfHash,
                    StringComparison.OrdinalIgnoreCase))
            {
                report.IntegrityFailures.Add(
                    "Whitelist self hash mismatch.");
            }

            string normalizedExpectedPath =
                NormalizePath(
                    selfArtifact.RelativePath);

            string normalizedActualPath =
                NormalizePath(
                    MakeRelativeGamePath(
                        selfPath));

            if (!string.IsNullOrWhiteSpace(
                    normalizedExpectedPath) &&
                !string.IsNullOrWhiteSpace(
                    normalizedActualPath) &&
                !string.Equals(
                    normalizedExpectedPath,
                    normalizedActualPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                report.IntegrityFailures.Add(
                    "Whitelist self path mismatch.");
            }

            if (!string.IsNullOrWhiteSpace(
                    selfArtifact.AssemblyFullName))
            {
                string actualFullName;

                try
                {
                    actualFullName =
                        typeof(
                            WhitelistClientSecurityService)
                            .Assembly
                            .FullName;
                }
                catch
                {
                    actualFullName =
                        null;
                }

                if (!string.IsNullOrWhiteSpace(
                        actualFullName) &&
                    !string.Equals(
                        actualFullName,
                        selfArtifact.AssemblyFullName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    report.IntegrityFailures.Add(
                        "Whitelist AssemblyFullName mismatch.");
                }
            }

            if (!string.IsNullOrWhiteSpace(
                    selfArtifact.AssemblyVersion))
            {
                string actualVersion;

                try
                {
                    actualVersion =
                        typeof(
                            WhitelistClientSecurityService)
                            .Assembly
                            .GetName()
                            .Version
                            .ToString();
                }
                catch (Exception ex)
                {
                    LogClientError(
                        "Failed to read whitelist assembly version: " +
                        ex.GetType().Name);
                    actualVersion =
                        null;
                }

                if (!string.IsNullOrWhiteSpace(
                        actualVersion) &&
                    !string.Equals(
                        actualVersion,
                        selfArtifact.AssemblyVersion,
                        StringComparison.OrdinalIgnoreCase))
                {
                    report.IntegrityFailures.Add(
                        "Whitelist AssemblyVersion mismatch.");
                }
            }
        }

        private static BaselineArtifact FindSelfArtifact(
            HostBaseline baseline)
        {
            if (baseline == null ||
                baseline.Artifacts == null)
            {
                return null;
            }

            string assemblyFullName;

            try
            {
                assemblyFullName =
                    typeof(
                        WhitelistClientSecurityService)
                        .Assembly
                        .FullName;
            }
            catch
            {
                assemblyFullName =
                    null;
            }

            string selfFileName =
                "HKMP.Whitelist.dll";

            foreach (BaselineArtifact artifact
                     in baseline.Artifacts)
            {
                if (artifact == null)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(
                        artifact.FileName) &&
                    string.Equals(
                        artifact.FileName,
                        selfFileName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return artifact;
                }

                if (!string.IsNullOrWhiteSpace(
                        assemblyFullName) &&
                    !string.IsNullOrWhiteSpace(
                        artifact.AssemblyFullName) &&
                    string.Equals(
                        artifact.AssemblyFullName,
                        assemblyFullName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return artifact;
                }

                if (!string.IsNullOrWhiteSpace(
                        artifact.AssemblyName) &&
                    string.Equals(
                        artifact.AssemblyName,
                        "HKMP.Whitelist",
                        StringComparison.OrdinalIgnoreCase))
                {
                    return artifact;
                }
            }

            return null;
        }

        private static string MakeRelativeGamePath(
            string absolutePath)
        {
            if (string.IsNullOrWhiteSpace(
                    absolutePath))
            {
                return "";
            }

            try
            {
                string root;
                string failureReason;

                if (!GamePathResolver.TryResolve(
                        null,
                        out root,
                        out failureReason))
                {
                    root =
                        AppDomain.CurrentDomain.BaseDirectory;
                }

                root =
                    Path.GetFullPath(root)
                        .TrimEnd(
                            Path.DirectorySeparatorChar,
                            Path.AltDirectorySeparatorChar);

                string full =
                    Path.GetFullPath(
                        absolutePath);

                Uri rootUri =
                    new Uri(
                        root +
                        Path.DirectorySeparatorChar);

                Uri fileUri =
                    new Uri(
                        full);

                string relative =
                    Uri.UnescapeDataString(
                        rootUri
                            .MakeRelativeUri(
                                fileUri)
                            .ToString());

                return
                    relative.Replace(
                        '\\',
                        '/');
            }
            catch
            {
                return
                    absolutePath.Replace(
                        '\\',
                        '/');
            }
        }

        private static string NormalizePath(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "";
            }

            string value =
                path.Trim()
                    .Replace(
                        '\\',
                        '/');

            while (value.Contains("//"))
            {
                value =
                    value.Replace(
                        "//",
                        "/");
            }

            while (value.StartsWith(
                       "./",
                       StringComparison.Ordinal))
            {
                value =
                    value.Substring(2);
            }

            return value.TrimStart(
                '/');
        }

        private void SendReport(
            SecurityReport report)
        {
            if (report == null)
            {
                return;
            }

            string json;

            try
            {
                json =
                    JsonConvert.SerializeObject(
                        report,
                        Formatting.None);
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Failed to serialize security report: " +
                    ex.GetType().Name);
                RejectAndDisconnect();
                return;
            }

            if (string.IsNullOrEmpty(json) ||
                json.Length > MaximumSecurityReportCharacters)
            {
                LogClientError(
                    "Security report payload is empty or exceeds the maximum transfer size.");
                RejectAndDisconnect();
                return;
            }

            string baselineId;
            string sessionId;

            lock (_gate)
            {
                baselineId =
                    _baseline == null
                        ? null
                        : _baseline.BaselineId;

                sessionId =
                    _baseline == null
                        ? null
                        : _baseline.SessionId;
            }

            if (string.IsNullOrWhiteSpace(baselineId) ||
                string.IsNullOrWhiteSpace(sessionId))
            {
                LogClientError(
                    "Cannot send security report because the active baseline/session identity is missing.");
                RejectAndDisconnect();
                return;
            }

            int chunkCount =
                (json.Length +
                 SecurityReportChunkSize -
                 1) /
                SecurityReportChunkSize;

            if (chunkCount < 1 ||
                chunkCount > MaximumSecurityReportChunks)
            {
                LogClientError(
                    "Security report requires an invalid number of transfer chunks: " +
                    chunkCount);
                RejectAndDisconnect();
                return;
            }

            string sha256 =
                ComputeTextSha256(
                    json);

            if (string.IsNullOrWhiteSpace(sha256))
            {
                LogClientError(
                    "Failed to calculate the security report transfer SHA-256.");
                RejectAndDisconnect();
                return;
            }

            string transferId =
                Guid.NewGuid().ToString("N");

            string[] chunks =
                new string[chunkCount];

            try
            {
                for (int index = 0;
                     index < chunkCount;
                     index++)
                {
                    int startIndex =
                        index *
                        SecurityReportChunkSize;

                    int length =
                        Math.Min(
                            SecurityReportChunkSize,
                            json.Length -
                            startIndex);

                    SecurityReportChunkPacketData chunk =
                        new SecurityReportChunkPacketData
                        {
                            ProtocolVersion = 2,
                            TransferId = transferId,
                            SessionId = sessionId,
                            BaselineId = baselineId,
                            ChunkIndex = index,
                            ChunkCount = chunkCount,
                            TotalLength = json.Length,
                            Sha256 = sha256,
                            Data = json.Substring(startIndex, length)
                        };

                    string chunkJson =
                        JsonConvert.SerializeObject(
                            chunk,
                            Formatting.None);

                    if (chunkJson.Length >= 60000)
                    {
                        throw new InvalidOperationException(
                            "Security report transfer chunk exceeds the safe packet size.");
                    }

                    chunks[index] = chunkJson;
                }
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Failed to prepare security report transfer: " +
                    ex.GetType().Name);
                RejectAndDisconnect();
                return;
            }

            lock (_gate)
            {
                _reportTransfer =
                    new SecurityReportTransferState
                    {
                        TransferId = transferId,
                        SessionId = sessionId,
                        BaselineId = baselineId,
                        ChunkCount = chunkCount,
                        TotalLength = json.Length,
                        Sha256 = sha256,
                        Chunks = chunks,
                        NextChunkIndex = 0,
                        CreatedUtc = DateTime.UtcNow
                    };
            }

            if (!SendNextSecurityReportChunk())
            {
                RejectAndDisconnect();
                return;
            }

            StartSecurityReportTransferTimeout();

            LogClientInfo(
                "Security report transfer started with " +
                chunkCount +
                " chunk(s).");
        }

        private bool SendNextSecurityReportChunk()
        {
            string payload;
            int chunkIndex;
            int chunkCount;

            lock (_gate)
            {
                if (_reportTransfer == null ||
                    _reportTransfer.Chunks == null ||
                    _reportTransfer.NextChunkIndex < 0 ||
                    _reportTransfer.NextChunkIndex >= _reportTransfer.Chunks.Length)
                {
                    return false;
                }

                chunkIndex =
                    _reportTransfer.NextChunkIndex;

                chunkCount =
                    _reportTransfer.ChunkCount;

                payload =
                    _reportTransfer.Chunks[chunkIndex];
            }

            if (string.IsNullOrEmpty(payload))
            {
                LogClientError(
                    "Security report transfer chunk " +
                    chunkIndex +
                    " is unavailable.");
                return false;
            }

            try
            {
                _sender.SendSingleData(
                    WhitelistServerPacketId.SecurityReport,
                    new JsonPacket
                    {
                        Json = payload
                    });
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Failed to send security report chunk " +
                    chunkIndex +
                    "/" +
                    chunkCount +
                    ": " +
                    ex.GetType().Name);
                return false;
            }

            return true;
        }

        public void HandleSecurityReportChunkAck(
            string json)
        {
            SecurityReportChunkAckData ack;

            try
            {
                ack =
                    JsonConvert.DeserializeObject<SecurityReportChunkAckData>(
                        json);
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Failed to deserialize security report chunk acknowledgement: " +
                    ex.GetType().Name);
                RejectAndDisconnect();
                return;
            }

            if (ack == null)
            {
                LogClientError(
                    "Security report chunk acknowledgement is empty.");
                RejectAndDisconnect();
                return;
            }

            bool complete = false;
            bool sendNext = false;
            bool invalid = false;

            lock (_gate)
            {
                if (_reportTransfer == null)
                {
                    return;
                }

                if (ack.ProtocolVersion != 2 ||
                    !string.Equals(
                        ack.TransferId,
                        _reportTransfer.TransferId,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        ack.SessionId,
                        _reportTransfer.SessionId,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        ack.BaselineId,
                        _reportTransfer.BaselineId,
                        StringComparison.Ordinal))
                {
                    invalid = true;
                }
                else if (ack.ChunkIndex <
                         _reportTransfer.NextChunkIndex)
                {
                    return;
                }
                else if (ack.ChunkIndex !=
                         _reportTransfer.NextChunkIndex)
                {
                    invalid = true;
                }
                else if (_reportTransfer.NextChunkIndex + 1 >=
                         _reportTransfer.ChunkCount)
                {
                    _reportTransfer = null;
                    complete = true;
                }
                else
                {
                    _reportTransfer.NextChunkIndex++;
                    sendNext = true;
                }
            }

            if (invalid)
            {
                LogClientError(
                    "Security report chunk acknowledgement does not match the active transfer.");
                RejectAndDisconnect();
                return;
            }

            if (complete)
            {
                LogClientInfo(
                    "Security report transfer completed and acknowledged by host.");
                return;
            }

            if (sendNext &&
                !SendNextSecurityReportChunk())
            {
                RejectAndDisconnect();
            }
        }

        private void StartSecurityReportTransferTimeout()
        {
            string transferId;

            lock (_gate)
            {
                if (_reportTransfer == null)
                {
                    return;
                }

                transferId =
                    _reportTransfer.TransferId;
            }

            Task.Run(
                async () =>
                {
                    await Task.Delay(
                        SecurityReportTransferTimeoutMs)
                        .ConfigureAwait(false);

                    bool expired = false;

                    lock (_gate)
                    {
                        if (_reportTransfer != null &&
                            string.Equals(
                                _reportTransfer.TransferId,
                                transferId,
                                StringComparison.Ordinal))
                        {
                            _reportTransfer = null;
                            expired = true;
                        }
                    }

                    if (expired)
                    {
                        LogClientError(
                            "Security report transfer timed out waiting for host acknowledgement.");
                        RejectAndDisconnect();
                    }
                });
        }

        private void SendChallengeFailure(
            ChallengeRequest challenge)
        {
            Send(
                WhitelistServerPacketId.ChallengeResponse,
                new JsonPacket
                {
                    Json =
                        JsonConvert.SerializeObject(
                            new ChallengeResponse
                            {
                                ProtocolVersion =
                                    challenge == null
                                        ? 2
                                        : challenge.ProtocolVersion,

                                SessionId =
                                    challenge == null
                                        ? ""
                                        : challenge.SessionId ?? "",

                                ChallengeId =
                                    challenge == null
                                        ? ""
                                        : challenge.ChallengeId ?? "",

                                SecurityGeneration =
                                    challenge == null
                                        ? 0
                                        : challenge.SecurityGeneration,

                                SequenceNumber =
                                    challenge == null
                                        ? 0
                                        : challenge.SequenceNumber,

                                Hmac =
                                    ""
                            },
                            Formatting.None)
                });
        }

        private bool StartRuntimeMonitor(
            int intervalSeconds)
        {
            HostBaseline baseline;

            int normalizedInterval =
                intervalSeconds;

            if (normalizedInterval < 1)
            {
                normalizedInterval =
                    30;
            }

            if (normalizedInterval > 3600)
            {
                normalizedInterval =
                    3600;
            }

            lock (_gate)
            {
                if (!_allowed ||
                    _baseline == null)
                {
                    return false;
                }

                if (_runtimeProvider != null)
                {
                    return true;
                }

                baseline =
                    _baseline;
            }

            RuntimeProvider provider;

            try
            {
                provider =
                    new RuntimeProvider(
                        baseline,
                        TimeSpan.FromSeconds(
                            normalizedInterval));

                provider.AssemblyObserved +=
                    OnRuntimeAssemblyObserved;

                provider.ScanCompleted +=
                    OnRuntimeScanCompleted;
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Failed to initialize runtime monitoring: " +
                    ex.GetType().Name);
                return false;
            }

            lock (_gate)
            {
                if (!_allowed ||
                    !object.ReferenceEquals(
                        baseline,
                        _baseline) ||
                    _runtimeProvider != null)
                {
                    provider.Dispose();
                    return _runtimeProvider != null;
                }

                _runtimeProvider =
                    provider;
            }

            try
            {
                provider.Start();
                return true;
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Runtime provider failed to start: " +
                    ex.GetType().Name);
                lock (_gate)
                {
                    if (object.ReferenceEquals(
                            _runtimeProvider,
                            provider))
                    {
                        _runtimeProvider =
                            null;
                    }
                }

                try
                {
                    provider.AssemblyObserved -=
                        OnRuntimeAssemblyObserved;

                    provider.ScanCompleted -=
                        OnRuntimeScanCompleted;

                    provider.Dispose();
                }
                catch (Exception x)
                {
                    LogClientError(
                        "Failed to dispose runtime provider after start failure: " +
                        x.GetType().Name);
                }

                return false;
            }
        }

        private void StopRuntimeMonitorInternal()
        {
            RuntimeProvider provider;

            lock (_gate)
            {
                provider =
                    _runtimeProvider;

                _runtimeProvider =
                    null;
            }

            if (provider == null)
            {
                return;
            }

            try
            {
                provider.AssemblyObserved -=
                    OnRuntimeAssemblyObserved;

                provider.ScanCompleted -=
                    OnRuntimeScanCompleted;

                provider.Dispose();
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Failed to stop runtime provider: " +
                    ex.GetType().Name);
            }
        }

        private void StopRuntimeMonitor()
        {
            lock (_gate)
            {
                StopRuntimeMonitorInternal();
            }
        }

        private void OnRuntimeAssemblyObserved(
            RuntimeAssemblyEvidence evidence)
        {
            if (evidence == null)
            {
                return;
            }

            bool allowed;

            lock (_gate)
            {
                allowed =
                    _allowed;
            }

            if (!allowed ||
                evidence.MatchesHostBaseline)
            {
                return;
            }

            SendRuntimeEvent(
                "RUNTIME_ARTIFACT_MISMATCH",
                BuildRuntimeEvidenceDetails(
                    evidence));
        }

        private void OnRuntimeScanCompleted(
            RuntimeProviderResult result)
        {
            if (result == null)
            {
                return;
            }

            bool allowed;

            lock (_gate)
            {
                allowed =
                    _allowed;
            }

            if (!allowed)
            {
                return;
            }

            if (!result.Complete &&
                result.Errors != null &&
                result.Errors.Count > 0)
            {
                SendRuntimeEvent(
                    "RUNTIME_SCAN_FAILED",
                    string.Join(
                        "; ",
                        result.Errors));
            }
        }

        private void SendRuntimeEvent(
            string type,
            string details)
        {
            HostBaseline baseline;

            lock (_gate)
            {
                baseline =
                    _baseline;
            }

            RuntimeEventData runtime =
                new RuntimeEventData
                {
                    ProtocolVersion =
                        2,

                    SessionId =
                        baseline == null
                            ? string.Empty
                            : baseline.SessionId ?? string.Empty,

                    Type =
                        type,

                    Details =
                        details ??
                        string.Empty,

                    TimestampUtc =
                        DateTime.UtcNow
                };

            Send(
                WhitelistServerPacketId.RuntimeEvent,
                new JsonPacket
                {
                    Json =
                        JsonConvert.SerializeObject(
                            runtime,
                            Formatting.None)
                });
        }

        private static string BuildRuntimeEvidenceDetails(
            RuntimeAssemblyEvidence evidence)
        {
            if (evidence == null)
            {
                return "<null runtime evidence>";
            }

            return
                "FullName=" +
                (evidence.FullName ?? "<unknown>") +
                " | AssemblyName=" +
                (evidence.AssemblyName ?? "<unknown>") +
                " | AssemblyVersion=" +
                (evidence.AssemblyVersion ?? "<unknown>") +
                " | Location=" +
                (evidence.Location ?? "<unknown>") +
                " | RelativePath=" +
                (evidence.RelativePath ?? "<unknown>") +
                " | FileName=" +
                (evidence.FileName ?? "<unknown>") +
                " | Size=" +
                evidence.FileSize +
                " | SHA256=" +
                (evidence.Sha256 ?? "<unknown>") +
                " | Status=" +
                (evidence.Status ?? "<unknown>") +
                " | Dynamic=" +
                evidence.IsDynamic;
        }

        private void RejectAndDisconnect()
        {
            lock (_gate)
            {
                _allowed = false;
                _baselineTransfer = null;
                _reportTransfer = null;
            }

            StopRuntimeMonitor();

            try
            {
                _api.ClientManager.Disconnect();
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Failed to disconnect after security rejection: " +
                    ex.GetType().Name);
            }
        }

        private void LogClientInfo(
            string message)
        {
            if (string.IsNullOrWhiteSpace(message))
            {
                return;
            }

            UnityEngine.Debug.Log(
                "[HKMP.Whitelist] " +
                message);
        }

        private static void LogClientError(
            string message)
        {
            if (string.IsNullOrWhiteSpace(message))
            {
                return;
            }

            UnityEngine.Debug.LogError(
                "[HKMP.Whitelist] " +
                message);
        }

        private void Send(
            WhitelistServerPacketId id,
            IPacketData data)
        {
            try
            {
                _sender.SendSingleData(
                    id,
                    data);
            }
            catch (Exception ex)
            {
                LogClientError(
                    "Failed to send packet " +
                    id +
                    ": " +
                    ex.GetType().Name);

                RejectAndDisconnect();
            }
        }

        private sealed class BaselineTransferState
        {
            public string TransferId;

            public string SessionId;

            public string BaselineId;

            public int ChunkCount;

            public int TotalLength;

            public string Sha256;

            public DateTime CreatedUtc;

            public int CurrentLength;

            public Dictionary<int, string> Chunks =
                new Dictionary<int, string>();
        }

        private sealed class SecurityReportTransferState
        {
            public string TransferId;

            public string SessionId;

            public string BaselineId;

            public int ChunkCount;

            public int TotalLength;

            public string Sha256;

            public DateTime CreatedUtc;

            public int NextChunkIndex;

            public string[] Chunks;
        }


    }

    internal sealed class RuntimeEventData
    {
        public int ProtocolVersion { get; set; }

        public string SessionId { get; set; }

        public string Type { get; set; }

        public string Details { get; set; }

        public DateTime TimestampUtc { get; set; }
    }
}
