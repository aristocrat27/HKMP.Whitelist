using Hkmp.Api.Server;
using Hkmp.Api.Server.Networking;
using Hkmp.Networking.Packet;
using Hkmp.Networking.Packet.Data;
using HKMP.Whitelist.Core;
using HKMP.Whitelist.Security;
using HKMP.Whitelist.Shared;
using Modding;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HKMP.Whitelist.Server
{
    public sealed class WhitelistServerAddon : ServerAddon
    {
        private IServerApi _api;

        private IServerAddonNetworkSender<WhitelistClientPacketId>
            _sender;

        private PresetConfig _preset;

        private HostBaseline _hostBaseline;

        private HostBaselineBuilder _baselineBuilder;

        private TimerIntegration _timerIntegration;

        private SecurityEventBus _eventBus;

        private ViolationStore _violationStore;

        private SecurityAuditLogger _auditLogger;

        private ChallengeService _challengeService;

        private HostSecurityService _hostSecurityService;

        private SessionAuditStore _sessionAuditStore;

        private string _configurationDirectory;

        private string _hostBaselineFailureReason;

        private readonly object _gate =
            new object();

        private const int BaselineChunkSize =
            20000;

        private const int MaximumBaselineCharacters =
            8 * 1024 * 1024;

        private const int MaximumBaselineChunks =
            512;

        private const int SecurityReportChunkSize =
            18000;

        private const int MaximumSecurityReportCharacters =
            8 * 1024 * 1024;

        private const int MaximumSecurityReportChunks =
            512;

        private const int HandshakeTimeoutMs =
            30000;

        private const int BaselineTransferTimeoutMs =
            15000;

        private const int SecurityReportTransferTimeoutMs =
            15000;

        private readonly Dictionary<ushort, PendingConnection>
            _pendingConnections =
                new Dictionary<ushort, PendingConnection>();

        private readonly Dictionary<ushort, SecurityReportTransferState>
            _reportTransfers =
                new Dictionary<ushort, SecurityReportTransferState>();

        private readonly Dictionary<ushort, HostBaselineTransferState>
            _baselineTransfers =
                new Dictionary<ushort, HostBaselineTransferState>();


        protected override string Name =>
            "HKMP.Whitelist";

        protected override string Version =>
            "1.1.0.0";

        public override bool NeedsNetwork =>
            true;

        public override void Initialize(
            IServerApi serverApi)
        {
            _api =
                serverApi;

            _sender =
                serverApi.NetServer
                    .GetNetworkSender<WhitelistClientPacketId>(
                        this);

            _configurationDirectory =
                Path.GetDirectoryName(
                    typeof(WhitelistServerAddon)
                        .Assembly
                        .Location);

            _preset =
                PresetLoader.Load(
                    _configurationDirectory);

            _eventBus =
                new SecurityEventBus();

            string violationIndexPath =
                null;

            string legacyViolationsPath =
                null;

            if (!string.IsNullOrWhiteSpace(
                    _configurationDirectory))
            {
                try
                {
                    violationIndexPath =
                        Path.Combine(
                            _configurationDirectory,
                            "observed_violation_index.json");

                    legacyViolationsPath =
                        Path.Combine(
                            _configurationDirectory,
                            "observed_violations.jsonl");
                }
                catch
                {
                    violationIndexPath = null;
                    legacyViolationsPath = null;
                }
            }

            _violationStore =
                new ViolationStore(
                    violationIndexPath,
                    legacyViolationsPath);

            _violationStore.Load();

            _auditLogger =
                new SecurityAuditLogger(
                    serverApi,
                    _configurationDirectory);

            _eventBus.Subscribe(
                _auditLogger.HandleEvent);

            _sessionAuditStore =
                new SessionAuditStore(
                    _configurationDirectory);

            _eventBus.Subscribe(
                _sessionAuditStore.HandleEvent);

            _challengeService =
                new ChallengeService();

            _challengeService.ChallengeExpired +=
                OnChallengeExpired;

            _baselineBuilder =
                new HostBaselineBuilder();

            _hostSecurityService =
                new HostSecurityService(
                    _baselineBuilder,
                    null,
                    null,
                    _eventBus,
                    _violationStore);

            string hostSessionReason;

            bool hostDetected =
                _hostSecurityService.StartHost(
                    DateTime.UtcNow,
                    out hostSessionReason);

            if (!hostDetected)
            {
                _hostBaselineFailureReason =
                    string.IsNullOrWhiteSpace(hostSessionReason)
                        ? "HOST_SECURITY_SESSION_INITIALIZATION_FAILED"
                        : hostSessionReason;

                serverApi.ServerManager.BroadcastMessage(
                    "Whitelist: host security session initialization failed: " +
                    _hostBaselineFailureReason);
            }

            PublishHostSecurityEvent(
                SecurityEventType.HostInitialScanStarted,
                SecuritySeverity.Info,
                "Initial host security baseline scan started.");

            HostBaseline initialBaseline =
                null;

            string initialAuditReason =
                null;

            bool initialAuditSucceeded =
                hostDetected &&
                _hostSecurityService.BeginInitialAudit(
                    _preset,
                    true,
                    DateTime.UtcNow,
                    out initialBaseline,
                    out initialAuditReason);

            if (!initialAuditSucceeded)
            {
                _hostBaseline = null;

                _hostBaselineFailureReason =
                    string.IsNullOrWhiteSpace(initialAuditReason)
                        ? "HOST_SCAN_INCOMPLETE"
                        : initialAuditReason;

                HostReadinessResult readiness =
                    _hostSecurityService.Readiness;

                try
                {
                    serverApi.ServerManager.BroadcastMessage(
                        "Whitelist host baseline unavailable: " +
                        _hostBaselineFailureReason);

                    if (readiness != null)
                    {
                        serverApi.ServerManager.BroadcastMessage(
                            "Whitelist host execution mode: " +
                            readiness.ExecutionMode);

                        serverApi.ServerManager.BroadcastMessage(
                            "Whitelist host root: " +
                            (readiness.GameRoot ?? "<unknown>"));

                        serverApi.ServerManager.BroadcastMessage(
                            "Whitelist host managed root: " +
                            (readiness.ManagedRoot ?? "<unknown>"));

                        serverApi.ServerManager.BroadcastMessage(
                            "Whitelist HKMP assembly: " +
                            (readiness.HkmpAssemblyPath ?? "<unknown>"));

                        serverApi.ServerManager.BroadcastMessage(
                            "Whitelist assembly: " +
                            (readiness.WhitelistAssemblyPath ?? "<unknown>"));

                        if (readiness.Warnings != null)
                        {
                            foreach (string warning in readiness.Warnings)
                            {
                                if (string.IsNullOrWhiteSpace(warning))
                                {
                                    continue;
                                }

                                serverApi.ServerManager.BroadcastMessage(
                                    "Whitelist host warning: " +
                                    warning);
                            }
                        }

                        if (!string.IsNullOrWhiteSpace(
                                readiness.FailureCode))
                        {
                            serverApi.ServerManager.BroadcastMessage(
                                "Whitelist host readiness failure: " +
                                readiness.FailureCode +
                                (string.IsNullOrWhiteSpace(
                                    readiness.FailureDetails)
                                    ? ""
                                    : " - " +
                                      readiness.FailureDetails));
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogServerError(
                        "Failed to log host readiness failure: " +
                        ex.GetType().Name);
                }
            }
            else
            {
                _hostBaseline =
                    initialBaseline;

                _sessionAuditStore.Initialize(
                    _hostSecurityService,
                    _hostBaseline,
                    _preset);

                PublishHostSecurityEvent(
                    SecurityEventType.HostStarted,
                    SecuritySeverity.Info,
                    "Whitelist security host session initialized.");

                PublishHostSecurityEvent(
                    SecurityEventType.HostInitialScanCompleted,
                    SecuritySeverity.Info,
                    "Initial host security baseline created successfully.");

                PublishHostSecurityEvent(
                    SecurityEventType.SessionStarted,
                    SecuritySeverity.Info,
                    "Whitelist security session started.");
            }

            var receiver =
                serverApi.NetServer
                    .GetNetworkReceiver<WhitelistServerPacketId>(
                        this,
                        InstantiatePacket);

            receiver.RegisterPacketHandler<JsonPacket>(
                WhitelistServerPacketId.SecurityReport,
                OnSecurityReport);

            receiver.RegisterPacketHandler<JsonPacket>(
                WhitelistServerPacketId.SecurityHello,
                OnSecurityHello);

            receiver.RegisterPacketHandler<JsonPacket>(
                WhitelistServerPacketId.HostBaselineChunkAck,
                OnHostBaselineChunkAck);

            receiver.RegisterPacketHandler<JsonPacket>(
                WhitelistServerPacketId.ChallengeResponse,
                OnChallengeResponse);

            receiver.RegisterPacketHandler<JsonPacket>(
                WhitelistServerPacketId.RuntimeEvent,
                OnRuntimeEvent);

            serverApi.ServerManager.PlayerConnectEvent +=
                OnPlayerConnect;

            serverApi.ServerManager.PlayerDisconnectEvent +=
                OnPlayerDisconnect;

            _timerIntegration =
                new TimerIntegration(
                    IsTimerIntegrationEnabled,
                    BeforeTimerStarted);

            AppDomain.CurrentDomain.AssemblyLoad +=
                OnAssemblyLoad;

            _timerIntegration.TryInstall();
            _timerIntegration.Activate();

            if (_hostBaseline == null)
            {
                serverApi.ServerManager.BroadcastMessage(
                    "Whitelist: host baseline is unavailable. Connections will be denied.");
            }
            else
            {
                serverApi.ServerManager.BroadcastMessage(
                    "Whitelist security server initialized.");
            }
        }

        private bool TryEnsureInitialHostBaseline()
        {
            if (_hostBaseline != null)
            {
                return true;
            }

            if (_hostSecurityService == null ||
                _preset == null)
            {
                return false;
            }

            HostBaseline baseline;
            string reason;

            if (!_hostSecurityService.BeginInitialAudit(
                    _preset,
                    true,
                    DateTime.UtcNow,
                    out baseline,
                    out reason))
            {
                _hostBaselineFailureReason =
                    string.IsNullOrWhiteSpace(reason)
                        ? "HOST_SCAN_INCOMPLETE"
                        : reason;

                HostReadinessResult readiness =
                    _hostSecurityService.Readiness;

                LogServerError(
                    "Host baseline recovery failed: " +
                    _hostBaselineFailureReason +
                    (readiness == null
                        ? ""
                        : " | readiness=" +
                          (readiness.FailureCode ?? "<none>") +
                          " | details=" +
                          (readiness.FailureDetails ?? "<none>")));

                return false;
            }

            if (baseline == null)
            {
                _hostBaselineFailureReason =
                    "HOST_SCAN_BASELINE_NULL";
                return false;
            }

            _hostBaseline =
                baseline;

            _hostBaselineFailureReason = null;

            LogServerInfo(
                "Host baseline recovery succeeded: baseline=" +
                (baseline.BaselineId ?? "<none>") +
                " artifacts=" +
                (baseline.Artifacts == null
                    ? 0
                    : baseline.Artifacts.Count) +
                " assemblies=" +
                (baseline.Assemblies == null
                    ? 0
                    : baseline.Assemblies.Count) +
                " native=" +
                (baseline.NativeModules == null
                    ? 0
                    : baseline.NativeModules.Count));

            if (_sessionAuditStore != null)
            {
                _sessionAuditStore.Initialize(
                    _hostSecurityService,
                    baseline,
                    _preset);
            }

            PublishHostSecurityEvent(
                SecurityEventType.HostStarted,
                SecuritySeverity.Info,
                "Whitelist security host session initialized after readiness recovery.");

            PublishHostSecurityEvent(
                SecurityEventType.HostInitialScanCompleted,
                SecuritySeverity.Info,
                "Initial host security baseline created successfully after readiness recovery.");

            PublishHostSecurityEvent(
                SecurityEventType.SessionStarted,
                SecuritySeverity.Info,
                "Whitelist security session started.");

            return true;
        }

        private bool ValidateServerConfiguration()
        {
            if (_preset == null)
            {
                return false;
            }

            if (_hostBaseline == null)
            {
                return false;
            }

            if (_preset.RequiredMods == null ||
                _preset.AllowedMods == null ||
                _preset.IgnoredMods == null ||
                _preset.ForbiddenMods == null)
            {
                return false;
            }

            return true;
        }

        private void OnAssemblyLoad(
            object sender,
            AssemblyLoadEventArgs args)
        {
            if (_timerIntegration != null)
            {
                _timerIntegration.TryInstall();
            }
        }

        private void OnPlayerConnect(
            IServerPlayer player)
        {
            if (player == null)
            {
                return;
            }

            if (_hostBaseline == null)
            {
                TryEnsureInitialHostBaseline();
            }

            if (!ValidateServerConfiguration())
            {
                RejectPlayer(
                    player,
                    "HOST_BASELINE_UNAVAILABLE",
                    "Host security baseline is unavailable." +
                    (string.IsNullOrWhiteSpace(_hostBaselineFailureReason)
                        ? ""
                        : " " + _hostBaselineFailureReason),
                    null,
                    false);

                return;
            }

            bool reconnectingLockedParticipant =
                _hostSecurityService != null &&
                _hostSecurityService.IsLocked;

            if (reconnectingLockedParticipant)
            {
                if (!_hostSecurityService.IsLockedParticipant(player))
                {
                    RejectPlayer(
                        player,
                        "SESSION_LOCKED",
                        "The whitelist session is already locked.",
                        null,
                        false);

                    return;
                }

                ParticipantSession reconnectParticipant;

                if (!_hostSecurityService.TryGetParticipant(
                        player,
                        out reconnectParticipant) ||
                    reconnectParticipant == null ||
                    string.IsNullOrWhiteSpace(
                        reconnectParticipant.IdentityKey))
                {
                    RejectPlayer(
                        player,
                        "RECONNECT_IDENTITY_UNAVAILABLE",
                        "The reconnect participant identity is unavailable.",
                        null,
                        false);

                    return;
                }

                if (_challengeService == null ||
                    _challengeService.BeginSecurityGeneration(
                        reconnectParticipant.IdentityKey) <= 0)
                {
                    RejectPlayer(
                        player,
                        "RECONNECT_GENERATION_FAILED",
                        "The reconnect security generation could not be initialized.",
                        null,
                        false);

                    return;
                }

                if (!MirrorParticipantReconnecting(player))
                {
                    RejectPlayer(
                        player,
                        "HOST_SECURITY_RECONNECT_REGISTRATION_FAILED",
                        "Host security reconnect state could not be synchronized.",
                        null,
                        false);
                    return;
                }

                PublishPlayerSecurityEvent(
                    player,
                    SecurityEventType.PlayerReconnected,
                    SecuritySeverity.Info,
                    "Locked participant entered reconnect verification.");

                RecordParticipantSnapshot(
                    player,
                    null);
            }
            else
            {
                if (!_hostSecurityService.RegisterParticipant(
                        player,
                        out _,
                        out _))
                {
                    RejectPlayer(
                        player,
                        "PARTICIPANT_REGISTRATION_FAILED",
                        "The player cannot be registered in the whitelist session.",
                        null,
                        false);

                    return;
                }

                if (!MirrorParticipantConnected(player))
                {
                    RejectPlayer(
                        player,
                        "HOST_SECURITY_PARTICIPANT_REGISTRATION_FAILED",
                        "Host security participant state could not be synchronized.",
                        null,
                        false);
                    return;
                }

                PublishPlayerSecurityEvent(
                    player,
                    SecurityEventType.PlayerConnected,
                    SecuritySeverity.Info,
                    "Participant connected and entered verification.");

                RecordParticipantSnapshot(
                    player,
                    null);
            }

            return;
        }

        private void OnSecurityHello(
            ushort playerId,
            JsonPacket packet)
        {
            IServerPlayer player =
                _api.ServerManager.GetPlayer(
                    playerId);

            if (player == null)
            {
                return;
            }

            if (IsParticipantRejected(player))
            {
                return;
            }

            if (!ValidateServerConfiguration())
            {
                RejectPlayer(
                    player,
                    "HOST_BASELINE_UNAVAILABLE",
                    "Host security baseline is unavailable." +
                    (string.IsNullOrWhiteSpace(_hostBaselineFailureReason)
                        ? ""
                        : " " + _hostBaselineFailureReason),
                    null,
                    false);

                return;
            }

            SecurityHelloData hello;

            try
            {
                hello =
                    JsonConvert.DeserializeObject<SecurityHelloData>(
                        packet == null
                            ? null
                            : packet.Json);
            }
            catch
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Malformed whitelist security hello.",
                    null,
                    true);

                return;
            }

            if (hello == null ||
                hello.ProtocolVersion != 2)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Unsupported whitelist security handshake protocol version.",
                    null,
                    true);

                return;
            }

            ParticipantSession participant;

            if (_hostSecurityService == null ||
                !_hostSecurityService.TryGetParticipant(
                    player,
                    out participant) ||
                participant == null)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Whitelist participant state is unavailable.",
                    null,
                    true);

                return;
            }

            if (participant.State !=
                    ParticipantState.Scanning &&
                participant.State !=
                    ParticipantState.Reconnecting)
            {
                if (participant.State ==
                    ParticipantState.Rejected)
                {
                    return;
                }

                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Whitelist security hello was received outside the active scan state.",
                    null,
                    true);

                return;
            }

            PublishPlayerSecurityEvent(
                player,
                SecurityEventType.PlayerScanStarted,
                SecuritySeverity.Info,
                "Client security scan handshake accepted.");

            RecordParticipantSnapshot(
                player,
                null);

            if (!MirrorParticipantScanning(player))
            {
                RejectPlayer(
                    player,
                    "HOST_SECURITY_SCAN_STATE_FAILED",
                    "Host security scan state could not be synchronized.",
                    null,
                    true);
                return;
            }

            if (IsPendingConnection(playerId))
            {
                return;
            }

            PendingConnection connection =
                new PendingConnection
                {
                    ConnectionId =
                        Guid.NewGuid().ToString("N"),

                    CreatedUtc =
                        DateTime.UtcNow
                };

            lock (_gate)
            {
                _pendingConnections[playerId] =
                    connection;
            }

            string baselineFailureCode;
            string baselineFailureReason;

            if (!TrySendHostBaseline(
                    player,
                    out baselineFailureCode,
                    out baselineFailureReason))
            {
                RemovePendingState(playerId);

                RejectPlayer(
                    player,
                    baselineFailureCode,
                    baselineFailureReason,
                    null,
                    true);

                return;
            }

            string connectionId =
                connection.ConnectionId;

            Task.Run(
                async () =>
                {
                    await Task.Delay(
                        HandshakeTimeoutMs)
                        .ConfigureAwait(false);

                    bool timedOut = false;

                    lock (_gate)
                    {
                        PendingConnection pending;

                        if (_pendingConnections.TryGetValue(
                                playerId,
                                out pending) &&
                            pending != null &&
                            string.Equals(
                                pending.ConnectionId,
                                connectionId,
                                StringComparison.Ordinal))
                        {
                            _pendingConnections.Remove(
                                playerId);

                            timedOut = true;
                        }
                    }

                    if (timedOut)
                    {
                        IServerPlayer currentPlayer =
                            _api.ServerManager.GetPlayer(
                                playerId);

                        ParticipantSession participant =
                            null;

                        if (currentPlayer != null &&
                            _hostSecurityService != null)
                        {
                            _hostSecurityService.TryGetParticipant(
                                currentPlayer,
                                out participant);
                        }

                        if (participant != null &&
                            participant.State !=
                                ParticipantState.Connecting &&
                            participant.State !=
                                ParticipantState.Scanning &&
                            participant.State !=
                                ParticipantState.Reconnecting)
                        {
                            return;
                        }

                        if (currentPlayer != null)
                        {
                            PublishPlayerSecurityEvent(
                                currentPlayer,
                                SecurityEventType.ProtocolViolation,
                                SecuritySeverity.Warning,
                                "Security handshake timed out after " +
                                (HandshakeTimeoutMs / 1000) +
                                " seconds without completing verification.");

                            RejectPlayer(
                                currentPlayer,
                                "HANDSHAKE_TIMEOUT",
                                "Security handshake timed out after " +
                                (HandshakeTimeoutMs / 1000) +
                                " seconds.",
                                null,
                                true);
                        }
                    }
                });
        }

        private bool TrySendHostBaseline(
            IServerPlayer player,
            out string failureCode,
            out string failureReason)
        {
            failureCode = null;
            failureReason = null;

            if (player == null ||
                _hostBaseline == null ||
                _sender == null)
            {
                failureCode =
                    "BASELINE_UNAVAILABLE";

                failureReason =
                    "Host security baseline is unavailable.";

                return false;
            }

            string json;

            try
            {
                json =
                    JsonConvert.SerializeObject(
                        new HostBaselinePacketData
                        {
                            Baseline =
                                _hostBaseline
                        },
                        Formatting.None);
            }
            catch (Exception ex)
            {
                LogServerError(
                    "Failed to serialize host baseline: " +
                    ex.GetType().Name);

                failureCode =
                    "BASELINE_SERIALIZATION_FAILED";

                failureReason =
                    "Failed to serialize the host security baseline.";

                return false;
            }

            if (string.IsNullOrEmpty(json))
            {
                failureCode =
                    "BASELINE_SERIALIZATION_FAILED";

                failureReason =
                    "The serialized host security baseline is empty.";

                return false;
            }

            if (json.Length > MaximumBaselineCharacters)
            {
                failureCode =
                    "BASELINE_TOO_LARGE";

                failureReason =
                    "Host security baseline exceeds the maximum transfer size.";

                return false;
            }

            int chunkCount =
                (json.Length + BaselineChunkSize - 1) /
                BaselineChunkSize;

            if (chunkCount < 1 ||
                chunkCount > MaximumBaselineChunks)
            {
                failureCode =
                    "BASELINE_TOO_LARGE";

                failureReason =
                    "Host security baseline requires too many transfer chunks.";

                return false;
            }

            string sha256 =
                ComputeTextSha256(
                    json);

            if (string.IsNullOrWhiteSpace(sha256))
            {
                failureCode =
                    "BASELINE_HASH_FAILED";

                failureReason =
                    "Failed to compute the host security baseline transfer hash.";

                return false;
            }

            string transferId =
                Guid.NewGuid().ToString("N");

            string[] chunks =
                new string[chunkCount];

            for (int index = 0;
                 index < chunkCount;
                 index++)
            {
                int startIndex =
                    index * BaselineChunkSize;

                int length =
                    Math.Min(
                        BaselineChunkSize,
                        json.Length - startIndex);

                string data =
                    json.Substring(
                        startIndex,
                        length);

                HostBaselineChunkPacketData chunk =
                    new HostBaselineChunkPacketData
                    {
                        ProtocolVersion = 1,
                        TransferId = transferId,
                        SessionId = _hostBaseline.SessionId,
                        BaselineId = _hostBaseline.BaselineId,
                        ChunkIndex = index,
                        ChunkCount = chunkCount,
                        TotalLength = json.Length,
                        Sha256 = sha256,
                        Data = data
                    };

                string chunkJson;

                try
                {
                    chunkJson =
                        JsonConvert.SerializeObject(
                            chunk,
                            Formatting.None);
                }
                catch (Exception ex)
                {
                    LogServerError(
                        "Failed to serialize host baseline chunk " +
                        index + ": " +
                        ex.GetType().Name);

                    failureCode =
                        "BASELINE_CHUNK_SERIALIZATION_FAILED";

                    failureReason =
                        "Failed to serialize host baseline transfer chunk " +
                        index + ".";

                    return false;
                }

                if (chunkJson.Length >= 60000)
                {
                    failureCode =
                        "BASELINE_CHUNK_TOO_LARGE";

                    failureReason =
                        "Host security baseline transfer chunk is too large.";

                    return false;
                }

                chunks[index] = chunkJson;
            }

            lock (_gate)
            {
                _baselineTransfers[player.Id] =
                    new HostBaselineTransferState
                    {
                        TransferId = transferId,
                        SessionId = _hostBaseline.SessionId,
                        BaselineId = _hostBaseline.BaselineId,
                        ChunkCount = chunkCount,
                        TotalLength = json.Length,
                        Sha256 = sha256,
                        Chunks = chunks,
                        NextChunkIndex = 0,
                        CreatedUtc = DateTime.UtcNow
                    };
            }

            StartBaselineTransferTimeout(
                player.Id,
                transferId);

            if (!SendHostBaselineChunk(player.Id))
            {
                lock (_gate)
                {
                    _baselineTransfers.Remove(
                        player.Id);
                }

                failureCode =
                    "BASELINE_SEND_FAILED";

                failureReason =
                    "Failed to send the host security baseline transfer.";

                return false;
            }

            return true;
        }

        private bool SendHostBaselineChunk(
            ushort playerId)
        {
            string payload;
            int chunkIndex;
            int chunkCount;

            lock (_gate)
            {
                HostBaselineTransferState state;

                if (!_baselineTransfers.TryGetValue(
                        playerId,
                        out state) ||
                    state == null ||
                    state.Chunks == null ||
                    state.NextChunkIndex < 0 ||
                    state.NextChunkIndex >= state.Chunks.Length)
                {
                    return false;
                }

                chunkIndex =
                    state.NextChunkIndex;

                chunkCount =
                    state.ChunkCount;

                payload =
                    state.Chunks[chunkIndex];
            }

            try
            {
                _sender.SendSingleData(
                    WhitelistClientPacketId.Manifest,
                    new JsonPacket
                    {
                        Json = payload
                    },
                    playerId);
            }
            catch (Exception ex)
            {
                LogServerError(
                    "Failed to send host baseline chunk " +
                    chunkIndex +
                    "/" +
                    chunkCount +
                    " to player " +
                    playerId +
                    ": " +
                    ex.GetType().Name);

                return false;
            }

            return true;
        }

        private void StartBaselineTransferTimeout(
            ushort playerId,
            string transferId)
        {
            Task.Run(
                async () =>
                {
                    await Task.Delay(
                        BaselineTransferTimeoutMs)
                        .ConfigureAwait(false);

                    bool expired = false;
                    int nextChunkIndex = -1;
                    int chunkCount = 0;

                    lock (_gate)
                    {
                        HostBaselineTransferState state;

                        if (_baselineTransfers.TryGetValue(
                                playerId,
                                out state) &&
                            state != null &&
                            string.Equals(
                                state.TransferId,
                                transferId,
                                StringComparison.Ordinal))
                        {
                            nextChunkIndex = state.NextChunkIndex;
                            chunkCount = state.ChunkCount;
                            _baselineTransfers.Remove(playerId);
                            expired = true;
                        }
                    }

                    if (!expired)
                    {
                        return;
                    }

                    IServerPlayer player =
                        _api.ServerManager.GetPlayer(playerId);

                    LogServerError(
                        "Host baseline transfer timed out for player " +
                        playerId +
                        " at chunk " +
                        nextChunkIndex +
                        "/" +
                        chunkCount +
                        ".");

                    if (player != null &&
                        !IsParticipantRejected(player))
                    {
                        RejectPlayer(
                            player,
                            "BASELINE_TRANSFER_TIMEOUT",
                            "Host security baseline transfer timed out while waiting for the client acknowledgement.",
                            null,
                            true);
                    }
                });
        }

        private void OnHostBaselineChunkAck(
            ushort playerId,
            JsonPacket packet)
        {
            IServerPlayer player =
                _api.ServerManager.GetPlayer(
                    playerId);

            if (player == null ||
                IsParticipantRejected(player))
            {
                return;
            }

            if (!IsPendingConnection(playerId))
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Host baseline chunk acknowledgement was received outside an active verification transfer.",
                    null,
                    true);
                return;
            }

            HostBaselineChunkAckData ack;

            try
            {
                ack =
                    JsonConvert.DeserializeObject<HostBaselineChunkAckData>(
                        packet == null
                            ? null
                            : packet.Json);
            }
            catch (Exception ex)
            {
                LogServerError(
                    "Failed to deserialize host baseline chunk acknowledgement from player " +
                    playerId +
                    ": " +
                    ex.GetType().Name);

                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Malformed host baseline chunk acknowledgement.",
                    null,
                    true);
                return;
            }

            if (ack == null)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Host baseline chunk acknowledgement is empty.",
                    null,
                    true);
                return;
            }

            bool complete = false;
            bool sendNext = false;

            lock (_gate)
            {
                HostBaselineTransferState state;

                if (!_baselineTransfers.TryGetValue(
                        playerId,
                        out state) ||
                    state == null)
                {
                    RejectPlayer(
                        player,
                        "PROTOCOL_INVALID",
                        "Host baseline transfer state is unavailable.",
                        null,
                        true);
                    return;
                }

                if (!string.Equals(
                        state.TransferId,
                        ack.TransferId,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        state.SessionId,
                        ack.SessionId,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        state.BaselineId,
                        ack.BaselineId,
                        StringComparison.Ordinal))
                {
                    RejectPlayer(
                        player,
                        "PROTOCOL_INVALID",
                        "Host baseline chunk acknowledgement does not match the active transfer.",
                        null,
                        true);
                    return;
                }

                if (ack.ChunkIndex < state.NextChunkIndex)
                {
                    return;
                }

                if (ack.ChunkIndex != state.NextChunkIndex)
                {
                    RejectPlayer(
                        player,
                        "PROTOCOL_INVALID",
                        "Host baseline chunk acknowledgement sequence is invalid.",
                        null,
                        true);
                    return;
                }

                if (state.NextChunkIndex + 1 >=
                    state.ChunkCount)
                {
                    _baselineTransfers.Remove(
                        playerId);

                    complete = true;
                }
                else
                {
                    state.NextChunkIndex++;
                    sendNext = true;
                }
            }

            if (complete)
            {
                return;
            }

            if (sendNext &&
                !SendHostBaselineChunk(playerId))
            {
                RejectPlayer(
                    player,
                    "BASELINE_SEND_FAILED",
                    "Failed to continue the host security baseline transfer.",
                    null,
                    true);
            }
        }

        private static bool IsValidSha256(
            string value)
        {
            if (string.IsNullOrWhiteSpace(
                    value) ||
                value.Length != 64)
            {
                return false;
            }

            for (int i = 0;
                 i < value.Length;
                 i++)
            {
                char c =
                    value[i];

                bool valid =
                    (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F');

                if (!valid)
                {
                    return false;
                }
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
            catch
            {
                return null;
            }
        }

        private void OnPlayerDisconnect(
            IServerPlayer player)
        {
            if (player == null)
            {
                return;
            }

            if (_hostSecurityService != null)
            {
                ParticipantSession participant;

                if (_hostSecurityService.TryGetParticipant(
                        player,
                        out participant) &&
                    participant != null &&
                    !string.IsNullOrWhiteSpace(
                        participant.IdentityKey) &&
                    _challengeService != null)
                {
                    _challengeService.CancelParticipant(
                        participant.IdentityKey);
                }
            }

            _hostSecurityService.MarkParticipantDisconnected(
                player);

            MirrorParticipantDisconnected(player);

            PublishPlayerSecurityEvent(
                player,
                SecurityEventType.PlayerDisconnected,
                SecuritySeverity.Info,
                "Participant disconnected.");

            RecordParticipantSnapshot(
                player,
                null);

            RemovePendingState(
                player.Id);
        }

        private void OnSecurityReport(
            ushort playerId,
            JsonPacket packet)
        {
            IServerPlayer player =
                _api.ServerManager.GetPlayer(
                    playerId);

            if (player == null)
            {
                return;
            }

            if (!IsPendingConnection(playerId))
            {
                if (IsParticipantRejected(player))
                {
                    return;
                }

                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Security report was received outside the active verification state.",
                    null,
                    true);

                return;
            }

            ParticipantSession participant;

            if (_hostSecurityService == null ||
                !_hostSecurityService.TryGetParticipant(
                    player,
                    out participant) ||
                participant == null)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Security report participant state is unavailable.",
                    null,
                    true);

                return;
            }

            if (participant.State !=
                    ParticipantState.Scanning &&
                participant.State !=
                    ParticipantState.Reconnecting)
            {
                if (participant.State ==
                        ParticipantState.Rejected)
                {
                    RemovePendingConnection(
                        playerId);
                    return;
                }

                RemovePendingConnection(
                    playerId);

                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Security report was received in an invalid participant state.",
                    null,
                    true);

                return;
            }

            SecurityReport report;
            string transferFailure;
            bool reportComplete;
            string transferId;
            int chunkIndex;

            if (!TryConsumeSecurityReport(
                    playerId,
                    packet,
                    out report,
                    out reportComplete,
                    out transferFailure,
                    out transferId,
                    out chunkIndex))
            {
                RemovePendingConnection(
                    playerId);

                RejectPlayer(
                    player,
                    "MALFORMED_REPORT",
                    transferFailure ??
                    "Security report could not be reconstructed.",
                    null,
                    true);

                return;
            }

            if (!string.IsNullOrWhiteSpace(transferId) &&
                chunkIndex >= 0)
            {
                if (chunkIndex == 0 &&
                    !reportComplete)
                {
                    StartSecurityReportTransferTimeout(
                        playerId,
                        transferId);
                }

                if (!SendSecurityReportChunkAck(
                        playerId,
                        transferId,
                        chunkIndex))
                {
                    RemovePendingConnection(
                        playerId);

                    RejectPlayer(
                        player,
                        "REPORT_ACK_FAILED",
                        "Failed to acknowledge the security report transfer chunk.",
                        null,
                        true);

                    return;
                }
            }

            if (!reportComplete)
            {
                return;
            }

            RemovePendingConnection(
                playerId);

            ProcessSecurityReport(
                player,
                report);
        }

        private bool SendSecurityReportChunkAck(
            ushort playerId,
            string transferId,
            int chunkIndex)
        {
            if (_sender == null ||
                _hostBaseline == null)
            {
                return false;
            }

            SecurityReportChunkAckData ack =
                new SecurityReportChunkAckData
                {
                    ProtocolVersion = 2,
                    TransferId = transferId,
                    SessionId = _hostBaseline.SessionId,
                    BaselineId = _hostBaseline.BaselineId,
                    ChunkIndex = chunkIndex
                };

            try
            {
                _sender.SendSingleData(
                    WhitelistClientPacketId.SecurityReportChunkAck,
                    new JsonPacket
                    {
                        Json =
                            JsonConvert.SerializeObject(
                                ack,
                                Formatting.None)
                    },
                    playerId);
            }
            catch (Exception ex)
            {
                LogServerError(
                    "Failed to acknowledge security report chunk " +
                    chunkIndex +
                    " for player " +
                    playerId +
                    ": " +
                    ex.GetType().Name);
                return false;
            }

            return true;
        }

        private void ProcessSecurityReport(
            IServerPlayer player,
            SecurityReport report)
        {
            if (player == null ||
                report == null)
            {
                return;
            }

            ushort playerId =
                player.Id;

            ParticipantSession participant;

            if (_hostSecurityService == null ||
                !_hostSecurityService.TryGetParticipant(
                    player,
                    out participant) ||
                participant == null)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Security report participant state is unavailable.",
                    report,
                    true);

                return;
            }

            RecordParticipantSnapshot(
                player,
                report);

            if (report.ProtocolVersion != 2)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Unsupported security report protocol version.",
                    report,
                    true);

                return;
            }

            if (_hostBaseline == null)
            {
                RejectPlayer(
                    player,
                    "HOST_BASELINE_UNAVAILABLE",
                    "Host security baseline is unavailable.",
                    report,
                    true);

                return;
            }

            if (!string.Equals(
                    report.SessionId,
                    _hostBaseline.SessionId,
                    StringComparison.Ordinal))
            {
                RejectPlayer(
                    player,
                    "SESSION_MISMATCH",
                    "Security report session ID does not match the current session.",
                    report,
                    true);

                return;
            }

            _preset =
                PresetLoader.Load(
                    _configurationDirectory);

            if (_preset == null)
            {
                RejectPlayer(
                    player,
                    "PRESET_UNAVAILABLE",
                    "Whitelist preset is unavailable.",
                    report,
                    true);

                return;
            }

            SecurityDecision decision =
                PolicyEngine.Evaluate(
                    report,
                    _hostBaseline,
                    _preset);

            PublishPlayerSecurityEvent(
                player,
                SecurityEventType.PlayerScanCompleted,
                decision.Allowed
                    ? SecuritySeverity.Info
                    : SecuritySeverity.Warning,
                decision.Allowed
                    ? "Client security scan completed and policy checks passed."
                    : "Client security scan completed but policy checks failed: " +
                      decision.DenyCode);

            if (!decision.Allowed)
            {
                RejectPlayer(
                    player,
                    decision,
                    report,
                    true);

                return;
            }

            if (_preset.ChallengeEnabled)
            {
                if (!SendChallenge(
                    playerId))
                {
                    SecurityDecision failed =
                        new SecurityDecision
                        {
                            Allowed = false,
                            Reason =
                                "Failed to initialize the security challenge.",
                            DenyCode =
                                "CHALLENGE_INITIALIZATION_FAILED"
                        };

                    RejectPlayer(
                        player,
                        failed,
                        report,
                        true);

                    return;
                }

                return;
            }

            AcceptVerifiedPlayer(
                player);
        }

        private bool TryConsumeSecurityReport(
            ushort playerId,
            JsonPacket packet,
            out SecurityReport report,
            out bool complete,
            out string failure,
            out string transferId,
            out int chunkIndex)
        {
            report = null;
            complete = false;
            failure = null;
            transferId = null;
            chunkIndex = -1;

            string json =
                packet == null
                    ? null
                    : packet.Json;

            if (string.IsNullOrWhiteSpace(json))
            {
                failure =
                    "Security report packet is empty.";

                return false;
            }

            if (json.Length > 65535)
            {
                failure =
                    "Security report packet exceeds the transport string limit.";

                return false;
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
                LogServerError(
                    "Failed to parse security report packet: " +
                    ex.GetType().Name);
                failure =
                    "Security report packet is not valid JSON.";

                return false;
            }

            bool isChunk =
                root["TransferId"] != null ||
                root["ChunkIndex"] != null ||
                root["ChunkCount"] != null ||
                root["TotalLength"] != null;

            if (!isChunk)
            {
                try
                {
                    report =
                        root.ToObject<SecurityReport>();
                }
                catch (Exception ex)
                {
                    LogServerError(
                        "Failed to deserialize direct security report: " +
                        ex.GetType().Name);
                    report = null;
                }

                if (report == null)
                {
                    failure =
                        "Security report payload could not be deserialized.";

                    return false;
                }

                complete = true;
                return true;
            }

            SecurityReportChunkPacketData chunk;

            try
            {
                chunk =
                    root.ToObject<
                        SecurityReportChunkPacketData>();
            }
            catch (Exception ex)
            {
                LogServerError(
                    "Failed to deserialize security report chunk: " +
                    ex.GetType().Name);
                chunk = null;
            }

            if (chunk == null)
            {
                failure =
                    "Security report chunk could not be deserialized.";

                return false;
            }

            if (chunk.ProtocolVersion != 2)
            {
                failure =
                    "Unsupported security report chunk protocol version.";

                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    chunk.TransferId))
            {
                failure =
                    "Security report transfer ID is missing.";

                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    chunk.SessionId) ||
                _hostBaseline == null ||
                !string.Equals(
                    chunk.SessionId,
                    _hostBaseline.SessionId,
                    StringComparison.Ordinal))
            {
                failure =
                    "Security report transfer session ID does not match the active host session.";

                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    chunk.BaselineId) ||
                _hostBaseline == null ||
                !string.Equals(
                    chunk.BaselineId,
                    _hostBaseline.BaselineId,
                    StringComparison.Ordinal))
            {
                failure =
                    "Security report transfer baseline ID does not match the active host baseline.";

                return false;
            }

            if (chunk.ChunkCount < 1 ||
                chunk.ChunkCount > MaximumSecurityReportChunks)
            {
                failure =
                    "Security report chunk count is outside the allowed range.";

                return false;
            }

            if (chunk.TotalLength < 1 ||
                chunk.TotalLength > MaximumSecurityReportCharacters)
            {
                failure =
                    "Security report total length is outside the allowed range.";

                return false;
            }

            if (chunk.ChunkIndex < 0 ||
                chunk.ChunkIndex >= chunk.ChunkCount)
            {
                failure =
                    "Security report chunk index is invalid.";

                return false;
            }

            if (string.IsNullOrEmpty(
                    chunk.Data) ||
                chunk.Data.Length > SecurityReportChunkSize)
            {
                failure =
                    "Security report chunk data is invalid.";

                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    chunk.Sha256) ||
                !IsValidSha256(
                    chunk.Sha256))
            {
                failure =
                    "Security report transfer hash is missing or invalid.";

                return false;
            }

            transferId =
                chunk.TransferId;

            chunkIndex =
                chunk.ChunkIndex;

            SecurityReportTransferState state;

            lock (_gate)
            {
                if (!_reportTransfers.TryGetValue(
                        playerId,
                        out state) ||
                    state == null)
                {
                    state =
                        new SecurityReportTransferState
                        {
                            TransferId =
                                chunk.TransferId,
                            SessionId =
                                chunk.SessionId,
                            BaselineId =
                                chunk.BaselineId,
                            ChunkCount =
                                chunk.ChunkCount,
                            TotalLength =
                                chunk.TotalLength,
                            Sha256 =
                                chunk.Sha256,
                            CreatedUtc =
                                DateTime.UtcNow
                        };

                    _reportTransfers[playerId] =
                        state;
                }
                else
                {
                    if (!string.Equals(
                            state.TransferId,
                            chunk.TransferId,
                            StringComparison.Ordinal))
                    {
                        failure =
                            "A different security report transfer is already pending for this participant.";

                        return false;
                    }

                    if (state.ChunkCount != chunk.ChunkCount ||
                        state.TotalLength != chunk.TotalLength ||
                        !string.Equals(
                            state.Sha256,
                            chunk.Sha256,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        failure =
                            "Security report transfer metadata changed during reassembly.";

                        return false;
                    }
                }

                string existing;

                if (state.Chunks.TryGetValue(
                        chunk.ChunkIndex,
                        out existing))
                {
                    if (!string.Equals(
                            existing,
                            chunk.Data,
                            StringComparison.Ordinal))
                    {
                        failure =
                            "Security report duplicate chunk contains different data.";

                        return false;
                    }
                }
                else
                {
                    if (state.CurrentLength +
                        chunk.Data.Length >
                        state.TotalLength)
                    {
                        failure =
                            "Security report transfer exceeds the declared total length.";

                        return false;
                    }

                    state.Chunks[
                        chunk.ChunkIndex] =
                            chunk.Data;

                    state.CurrentLength +=
                        chunk.Data.Length;
                }

                if (state.Chunks.Count !=
                    state.ChunkCount)
                {
                    complete = false;
                    return true;
                }

                if (state.CurrentLength !=
                    state.TotalLength)
                {
                    failure =
                        "Security report transfer is complete by chunk count but its length is inconsistent.";

                    return false;
                }

                StringBuilder builder =
                    new StringBuilder(
                        state.TotalLength);

                for (int index = 0;
                     index < state.ChunkCount;
                     index++)
                {
                    string value;

                    if (!state.Chunks.TryGetValue(
                            index,
                            out value))
                    {
                        failure =
                            "Security report transfer contains a missing chunk.";

                        return false;
                    }

                    builder.Append(
                        value);
                }

                string reconstructed =
                    builder.ToString();

                if (reconstructed.Length !=
                    state.TotalLength)
                {
                    failure =
                        "Security report reconstructed length does not match the declared length.";

                    return false;
                }

                string reconstructedHash =
                    ComputeTextSha256(
                        reconstructed);

                if (!string.Equals(
                        reconstructedHash,
                        state.Sha256,
                        StringComparison.OrdinalIgnoreCase))
                {
                    failure =
                        "Security report transfer SHA-256 mismatch.";

                    return false;
                }

                try
                {
                    report =
                        JsonConvert.DeserializeObject<
                            SecurityReport>(
                                reconstructed);
                }
                catch (Exception ex)
                {
                    LogServerError(
                        "Failed to deserialize reconstructed security report: " +
                        ex.GetType().Name);
                    report = null;
                }

                _reportTransfers.Remove(
                    playerId);
            }

            if (report == null)
            {
                failure =
                    "Reconstructed security report could not be deserialized.";

                return false;
            }

            complete = true;
            return true;
        }

        private void StartSecurityReportTransferTimeout(
            ushort playerId,
            string transferId)
        {
            Task.Run(
                async () =>
                {
                    await Task.Delay(
                        SecurityReportTransferTimeoutMs)
                        .ConfigureAwait(false);

                    bool expired = false;

                    lock (_gate)
                    {
                        SecurityReportTransferState state;

                        if (_reportTransfers.TryGetValue(
                                playerId,
                                out state) &&
                            state != null &&
                            string.Equals(
                                state.TransferId,
                                transferId,
                                StringComparison.Ordinal))
                        {
                            _reportTransfers.Remove(playerId);
                            expired = true;
                        }
                    }

                    if (!expired)
                    {
                        return;
                    }

                    IServerPlayer player =
                        _api.ServerManager.GetPlayer(playerId);

                    LogServerError(
                        "Security report transfer timed out for player " +
                        playerId +
                        " waiting for the next chunk.");

                    if (player != null &&
                        !IsParticipantRejected(player))
                    {
                        RejectPlayer(
                            player,
                            "SECURITY_REPORT_TRANSFER_TIMEOUT",
                            "Security report transfer timed out before all chunks were received.",
                            null,
                            true);
                    }
                });
        }

        private bool SendChallenge(
            ushort playerId)
        {
            if (_challengeService == null ||
                _hostSecurityService == null ||
                _hostBaseline == null)
            {
                return false;
            }

            IServerPlayer player =
                _api.ServerManager.GetPlayer(
                    playerId);

            if (player == null)
            {
                return false;
            }

            ParticipantSession participant;

            if (!_hostSecurityService.TryGetParticipant(
                    player,
                    out participant) ||
                participant == null ||
                string.IsNullOrWhiteSpace(
                    participant.IdentityKey))
            {
                return false;
            }

            string serverAssemblyPath;

            try
            {
                serverAssemblyPath =
                    typeof(WhitelistServerAddon)
                        .Assembly
                        .Location;
            }
            catch
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    serverAssemblyPath))
            {
                return false;
            }

            byte[] expectedBytes;

            try
            {
                expectedBytes =
                    HashUtil.ReadAllBytesShared(
                        serverAssemblyPath);
            }
            catch
            {
                return false;
            }

            if (expectedBytes == null ||
                expectedBytes.Length == 0)
            {
                return false;
            }

            ChallengeIssueResult issue =
                _challengeService.IssueChallenge(
                    _hostBaseline.SessionId,
                    participant.IdentityKey,
                    expectedBytes,
                    TimeSpan.FromMilliseconds(
                        _preset == null
                            ? 3000
                            : _preset.ChallengeTimeoutMs));

            if (issue == null ||
                !issue.Success ||
                issue.Request == null)
            {
                return false;
            }

            try
            {
                _sender.SendSingleData(
                    WhitelistClientPacketId.Challenge,
                    new JsonPacket
                    {
                        Json =
                            JsonConvert.SerializeObject(
                                issue.Request,
                                Formatting.None)
                    },
                    playerId);
            }
            catch
            {
                _challengeService.CancelParticipant(
                    participant.IdentityKey);

                return false;
            }

            PublishPlayerSecurityEvent(
                player,
                SecurityEventType.ChallengeIssued,
                SecuritySeverity.Info,
                "Security challenge issued.");

            if (!MirrorParticipantChallenging(player))
            {
                _challengeService.CancelParticipant(
                    participant.IdentityKey);
                return false;
            }

            RecordParticipantSnapshot(
                player,
                null);

            return true;
        }

        private void OnChallengeExpired(
            string participantIdentityKey,
            ChallengeValidationResult result)
        {
            if (string.IsNullOrWhiteSpace(
                    participantIdentityKey))
            {
                return;
            }

            ParticipantSession participant;

            if (_hostSecurityService == null ||
                !_hostSecurityService.TryGetParticipant(
                    participantIdentityKey,
                    out participant) ||
                participant == null)
            {
                return;
            }

            IServerPlayer player =
                _api.ServerManager.GetPlayer(
                    participant.PlayerId);

            if (player == null)
            {
                return;
            }

            PublishPlayerSecurityEvent(
                player,
                SecurityEventType.ChallengeRejected,
                SecuritySeverity.Warning,
                result == null ||
                string.IsNullOrWhiteSpace(
                    result.Reason)
                    ? "Security challenge timed out."
                    : result.Reason);

            RejectPlayer(
                player,
                "CHALLENGE_TIMEOUT",
                result == null ||
                string.IsNullOrWhiteSpace(
                    result.Reason)
                    ? "Security challenge timed out."
                    : result.Reason,
                null,
                true);
        }

        private void OnChallengeResponse(
            ushort playerId,
            JsonPacket packet)
        {
            IServerPlayer player =
                _api.ServerManager.GetPlayer(
                    playerId);

            if (player == null)
            {
                return;
            }

            if (_challengeService == null ||
                _hostSecurityService == null ||
                _hostBaseline == null)
            {
                if (IsParticipantRejected(player))
                {
                    return;
                }

                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Security challenge service is unavailable for the current participant state.",
                    null,
                    true);

                return;
            }

            ParticipantSession participant;

            if (!_hostSecurityService.TryGetParticipant(
                    player,
                    out participant) ||
                participant == null ||
                string.IsNullOrWhiteSpace(
                    participant.IdentityKey))
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Security challenge participant is invalid.",
                    null,
                    true);

                return;
            }

            if (participant.State ==
                    ParticipantState.Rejected)
            {
                return;
            }

            if (participant.State !=
                ParticipantState.Challenging)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Challenge response was received outside the challenge state.",
                    null,
                    true);

                return;
            }

            ChallengeResponse response;

            try
            {
                response =
                    JsonConvert.DeserializeObject<ChallengeResponse>(
                        packet == null
                            ? null
                            : packet.Json);
            }
            catch
            {
                RejectPlayer(
                    player,
                    "CHALLENGE_INVALID",
                    "Malformed challenge response.",
                    null,
                    true);

                return;
            }

            ChallengeValidationResult validation =
                _challengeService.ValidateResponse(
                    _hostBaseline.SessionId,
                    participant.IdentityKey,
                    response);

            if (validation == null ||
                !validation.Accepted)
            {
                string code =
                    validation == null
                        ? "CHALLENGE_INVALID"
                        : GetChallengeDenyCode(
                            validation.Code);

                PublishPlayerSecurityEvent(
                    player,
                    SecurityEventType.ChallengeRejected,
                    SecuritySeverity.Warning,
                    validation == null ||
                    string.IsNullOrWhiteSpace(
                        validation.Reason)
                        ? "Security challenge verification failed."
                        : validation.Reason);

                RejectPlayer(
                    player,
                    code,
                    validation == null ||
                    string.IsNullOrWhiteSpace(
                        validation.Reason)
                        ? "Security challenge verification failed."
                        : validation.Reason,
                    null,
                    true);

                return;
            }

            PublishPlayerSecurityEvent(
                player,
                SecurityEventType.ChallengeAccepted,
                SecuritySeverity.Info,
                "Security challenge accepted.");

            AcceptVerifiedPlayer(
                player);
        }

        private static string GetChallengeDenyCode(
            ChallengeValidationCode code)
        {
            switch (code)
            {
                case ChallengeValidationCode.SessionMismatch:
                    return "CHALLENGE_SESSION_MISMATCH";

                case ChallengeValidationCode.ReplayDetected:
                    return "CHALLENGE_REPLAY";

                case ChallengeValidationCode.GenerationMismatch:
                    return "CHALLENGE_GENERATION_MISMATCH";

                case ChallengeValidationCode.SequenceMismatch:
                    return "CHALLENGE_SEQUENCE_MISMATCH";

                case ChallengeValidationCode.Expired:
                    return "CHALLENGE_TIMEOUT";

                case ChallengeValidationCode.HmacMissing:
                    return "CHALLENGE_PROOF_MISSING";

                case ChallengeValidationCode.HmacMismatch:
                    return "CHALLENGE_PROOF_MISMATCH";

                case ChallengeValidationCode.ProtocolVersionMismatch:
                    return "CHALLENGE_PROTOCOL_MISMATCH";

                case ChallengeValidationCode.InvalidParticipant:
                    return "CHALLENGE_INVALID_PARTICIPANT";

                case ChallengeValidationCode.NullResponse:
                    return "CHALLENGE_INVALID";

                case ChallengeValidationCode.ChallengeNotFound:
                default:
                    return "CHALLENGE_INVALID";
            }
        }

        private void AcceptVerifiedPlayer(
            IServerPlayer player)
        {
            if (player == null)
            {
                return;
            }

            if (_hostBaseline == null)
            {
                SecurityDecision failed =
                    new SecurityDecision
                    {
                        Allowed = false,
                        Reason =
                            "Host security baseline is unavailable.",
                        DenyCode =
                            "HOST_BASELINE_UNAVAILABLE"
                    };

                RejectPlayer(
                    player,
                    failed,
                    null,
                    true);

                return;
            }

            ParticipantSession participant;

            if (_hostSecurityService == null ||
                !_hostSecurityService.TryGetParticipant(
                    player,
                    out participant) ||
                participant == null)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Participant state is unavailable during verification completion.",
                    null,
                    true);

                return;
            }

            if (participant.State ==
                    ParticipantState.Rejected)
            {
                return;
            }

            if (participant.State !=
                    ParticipantState.Scanning &&
                participant.State !=
                    ParticipantState.Reconnecting &&
                participant.State !=
                    ParticipantState.Challenging)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Verification completion was received in an invalid participant state.",
                    null,
                    true);

                return;
            }

            _hostSecurityService.MarkParticipantVerified(
                player,
                _hostBaseline.BaselineId);

            _hostSecurityService.MarkParticipantActive(
                player);

            if (!MirrorParticipantVerified(player))
            {
                RejectPlayer(
                    player,
                    "HOST_SECURITY_VERIFICATION_STATE_FAILED",
                    "Host security verification state could not be synchronized.",
                    null,
                    true);
                return;
            }

            PublishPlayerSecurityEvent(
                player,
                SecurityEventType.PlayerVerified,
                SecuritySeverity.Info,
                "Participant passed whitelist verification and became active.");

            RecordParticipantSnapshot(
                player,
                null);

            SendDecision(
                player.Id,
                new SecurityDecision
                {
                    Allowed = true,
                    Reason =
                        "All currently available whitelist checks passed.",

                    DenyCode = null,

                    SessionId =
                        _hostBaseline.SessionId,

                    ManifestId =
                        null,

                    ManifestVersion =
                        0,

                    RuntimeMonitoringEnabled =
                        _preset != null &&
                        _preset.RuntimeMonitoringEnabled,

                    RuntimeScanIntervalSeconds =
                        _preset == null
                            ? 30
                            : _preset.RuntimeScanIntervalSeconds,

                    ChallengeEnabled =
                        _preset != null &&
                        _preset.ChallengeEnabled,

                    ChallengeTimeoutMs =
                        _preset == null
                            ? 3000
                            : _preset.ChallengeTimeoutMs
                });
        }

        private void OnRuntimeEvent(
            ushort playerId,
            JsonPacket packet)
        {
            IServerPlayer player =
                _api.ServerManager.GetPlayer(
                    playerId);

            if (player == null ||
                _hostSecurityService == null)
            {
                return;
            }

            ParticipantSession participant;

            if (!_hostSecurityService.TryGetParticipant(
                    player,
                    out participant) ||
                participant == null)
            {
                return;
            }

            if (participant.State ==
                    ParticipantState.Rejected)
            {
                return;
            }

            if (participant.State !=
                    ParticipantState.Verified &&
                participant.State !=
                    ParticipantState.Active)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Runtime security event was received outside an active participant state.",
                    null,
                    true);

                return;
            }

            if (_preset == null)
            {
                RejectPlayer(
                    player,
                    "PRESET_UNAVAILABLE",
                    "Whitelist preset is unavailable for runtime security validation.",
                    null,
                    true);

                return;
            }

            if (!_preset.RuntimeMonitoringEnabled)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Runtime security event was received while runtime monitoring is disabled.",
                    null,
                    true);

                return;
            }

            if (_hostBaseline == null)
            {
                RejectPlayer(
                    player,
                    "HOST_BASELINE_UNAVAILABLE",
                    "Host security baseline is unavailable for runtime validation.",
                    null,
                    true);

                return;
            }

            RuntimeEventData runtime;

            try
            {
                runtime =
                    JsonConvert.DeserializeObject<RuntimeEventData>(
                        packet == null
                            ? null
                            : packet.Json);
            }
            catch
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Malformed runtime security event.",
                    null,
                    true);

                return;
            }

            if (runtime == null)
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Runtime security event is null.",
                    null,
                    true);

                return;
            }

            if (runtime.ProtocolVersion != 2 ||
                !string.Equals(
                    runtime.SessionId,
                    _hostBaseline.SessionId,
                    StringComparison.Ordinal))
            {
                RejectPlayer(
                    player,
                    "PROTOCOL_INVALID",
                    "Runtime security event session or protocol does not match the current session.",
                    null,
                    true);

                return;
            }

            string denyCode =
                runtime.Type ==
                "ASSEMBLY_LOADED_UNKNOWN"
                    ? "UNKNOWN_ASSEMBLY"
                    : runtime.Type ==
                      "RUNTIME_ARTIFACT_MISMATCH"
                        ? "RUNTIME_ARTIFACT_MISMATCH"
                        : "RUNTIME_SECURITY_EVENT";

            string reason =
                (runtime.Type ?? "RUNTIME_SECURITY_EVENT") +
                ": " +
                (runtime.Details ?? string.Empty);

            SecurityDecision decision =
                new SecurityDecision
                {
                    Allowed = false,
                    Reason = reason,
                    DenyCode = denyCode
                };

            PublishPlayerSecurityEvent(
                player,
                SecurityEventType.RuntimeChangeDetected,
                SecuritySeverity.High,
                reason);

            RejectPlayer(
                player,
                decision,
                null,
                true);
        }

        private bool IsTimerIntegrationEnabled()
        {
            WhitelistGlobalSettings settings =
                WhitelistMod.GlobalSettings;

            return settings == null ||
                   settings.TimerIntegrationEnabled;
        }

        private bool BeforeTimerStarted()
        {
            lock (_gate)
            {
                if (!IsTimerIntegrationEnabled())
                {
                    return true;
                }

                if (_hostSecurityService == null ||
                    _preset == null ||
                    !_hostSecurityService.GetParticipants().Any(
                        participant =>
                            participant != null &&
                            participant.IsVerified &&
                            participant.IsConnected))
                {
                    PublishHostSecurityEvent(
                        SecurityEventType.SessionInvalidated,
                        SecuritySeverity.Critical,
                        "Protected timer start was blocked because the host security session is not ready.");
                    return false;
                }

                PublishHostSecurityEvent(
                    SecurityEventType.HostBaselineFinalizing,
                    SecuritySeverity.Info,
                    "Final host security baseline finalization started for timer start.");

                HostBaseline finalBaseline;
                MembershipSnapshot membership;
                string reason;

                if (!_hostSecurityService.TryFinalizeProtectedSession(
                        _preset,
                        true,
                        DateTime.UtcNow,
                        out finalBaseline,
                        out membership,
                        out reason) ||
                    finalBaseline == null ||
                    membership == null)
                {
                    PublishHostSecurityEvent(
                        SecurityEventType.SessionInvalidated,
                        SecuritySeverity.Critical,
                        string.IsNullOrWhiteSpace(reason)
                            ? "Protected timer start was blocked because security finalization failed."
                            : "Protected timer start was blocked: " + reason);
                    return false;
                }

                string runningReason;

                if (!_hostSecurityService.StartRunning(
                        DateTime.UtcNow,
                        out runningReason))
                {
                    _hostSecurityService.HandleHostIntegrityChanged(
                        string.IsNullOrWhiteSpace(runningReason)
                            ? "PROTECTED_SESSION_RUNNING_TRANSITION_FAILED"
                            : runningReason,
                        DateTime.UtcNow);

                    PublishHostSecurityEvent(
                        SecurityEventType.SessionInvalidated,
                        SecuritySeverity.Critical,
                        string.IsNullOrWhiteSpace(runningReason)
                            ? "Protected timer start was blocked because the security session could not enter Running state."
                            : runningReason);
                    return false;
                }

                _hostBaseline =
                    finalBaseline;

                if (_sessionAuditStore != null)
                {
                    _sessionAuditStore.UpdateBaseline(
                        finalBaseline);

                    _sessionAuditStore.RefreshParticipants(
                        _hostSecurityService == null
                            ? null
                            : _hostSecurityService.GetParticipants());
                }

                PublishHostSecurityEvent(
                    SecurityEventType.HostBaselineFrozen,
                    SecuritySeverity.Info,
                    "Final host security baseline frozen.");

                PublishHostSecurityEvent(
                    SecurityEventType.MembershipLocked,
                    SecuritySeverity.Info,
                    "Protected participant membership locked for timer start.");

                return true;
            }
        }

        private bool MirrorParticipantConnected(
            IServerPlayer player)
        {
            if (_hostSecurityService == null ||
                player == null ||
                string.IsNullOrWhiteSpace(player.AuthKey))
            {
                return false;
            }

            ParticipantSession participant;
            string reason;

            if (!_hostSecurityService.RegisterParticipant(
                    player.AuthKey,
                    player.Username,
                    DateTime.UtcNow,
                    out participant,
                    out reason))
            {
                return false;
            }

            return _hostSecurityService.MarkParticipantScanning(
                player.AuthKey,
                DateTime.UtcNow,
                out reason);
        }

        private bool MirrorParticipantReconnecting(
            IServerPlayer player)
        {
            if (_hostSecurityService == null ||
                player == null ||
                string.IsNullOrWhiteSpace(player.AuthKey))
            {
                return false;
            }

            string reason;

            if (!_hostSecurityService.MarkParticipantReconnecting(
                    player.AuthKey,
                    DateTime.UtcNow,
                    out reason))
            {
                return false;
            }

            return _hostSecurityService.MarkParticipantScanning(
                player.AuthKey,
                DateTime.UtcNow,
                out reason);
        }

        private bool MirrorParticipantScanning(
            IServerPlayer player)
        {
            if (_hostSecurityService == null ||
                player == null ||
                string.IsNullOrWhiteSpace(player.AuthKey))
            {
                return false;
            }

            string reason;

            return _hostSecurityService.MarkParticipantScanning(
                player.AuthKey,
                DateTime.UtcNow,
                out reason);
        }

        private bool MirrorParticipantChallenging(
            IServerPlayer player)
        {
            if (_hostSecurityService == null ||
                player == null ||
                string.IsNullOrWhiteSpace(player.AuthKey))
            {
                return false;
            }

            string reason;

            return _hostSecurityService.MarkParticipantChallenging(
                player.AuthKey,
                DateTime.UtcNow,
                out reason);
        }

        private bool MirrorParticipantVerified(
            IServerPlayer player)
        {
            if (_hostSecurityService == null ||
                player == null ||
                string.IsNullOrWhiteSpace(player.AuthKey) ||
                _hostBaseline == null)
            {
                return false;
            }

            string reason;

            if (!_hostSecurityService.MarkParticipantVerified(
                    player.AuthKey,
                    _hostBaseline.BaselineId,
                    DateTime.UtcNow,
                    out reason))
            {
                return false;
            }

            return _hostSecurityService.MarkParticipantActive(
                player.AuthKey,
                DateTime.UtcNow,
                out reason);
        }

        private void MirrorParticipantDisconnected(
            IServerPlayer player)
        {
            if (_hostSecurityService == null ||
                player == null ||
                string.IsNullOrWhiteSpace(player.AuthKey))
            {
                return;
            }

            string reason;

            _hostSecurityService.MarkParticipantDisconnected(
                player.AuthKey,
                DateTime.UtcNow,
                out reason);
        }

        private void MirrorParticipantRejected(
            IServerPlayer player,
            string denyCode,
            string reason)
        {
            if (_hostSecurityService == null ||
                player == null ||
                string.IsNullOrWhiteSpace(player.AuthKey))
            {
                return;
            }

            string synchronizationReason;

            _hostSecurityService.MarkParticipantRejected(
                player.AuthKey,
                denyCode,
                reason,
                DateTime.UtcNow,
                out synchronizationReason);
        }

        private bool IsParticipantRejected(
            IServerPlayer player)
        {
            if (player == null ||
                _hostSecurityService == null)
            {
                return false;
            }

            ParticipantSession participant;

            if (!_hostSecurityService.TryGetParticipant(
                    player,
                    out participant) ||
                participant == null)
            {
                return false;
            }

            return
                participant.State ==
                ParticipantState.Rejected;
        }

        private void RejectPlayer(
            IServerPlayer player,
            string denyCode,
            string reason,
            SecurityReport report,
            bool sendDecision)
        {
            SecurityDecision decision =
                new SecurityDecision
                {
                    Allowed = false,

                    DenyCode =
                        string.IsNullOrWhiteSpace(
                            denyCode)
                            ? "SECURITY_REJECTION"
                            : denyCode.Trim(),

                    Reason =
                        string.IsNullOrWhiteSpace(
                            reason)
                            ? "Security validation failed."
                            : reason
                };

            RejectPlayer(
                player,
                decision,
                report,
                sendDecision);
        }

        private void RejectPlayer(
            IServerPlayer player,
            SecurityDecision decision,
            SecurityReport report,
            bool sendDecision)
        {
            if (player == null)
            {
                return;
            }

            if (decision == null)
            {
                decision =
                    new SecurityDecision
                    {
                        Allowed = false,

                        DenyCode =
                            "SECURITY_REJECTION",

                        Reason =
                            "Security validation failed."
                    };
            }

            if (string.IsNullOrWhiteSpace(
                    decision.DenyCode))
            {
                decision.DenyCode =
                    "SECURITY_REJECTION";
            }

            if (string.IsNullOrWhiteSpace(
                    decision.Reason))
            {
                decision.Reason =
                    "Security validation failed.";
            }

            LogServerError(
                "Rejecting player " +
                player.Id +
                " (" +
                (player.Username ?? "<unknown>") +
                ") code=" +
                decision.DenyCode +
                " reason=" +
                decision.Reason);

            ParticipantSession participant;

            if (_hostSecurityService != null &&
                _hostSecurityService.TryGetParticipant(
                    player,
                    out participant) &&
                participant != null &&
                !string.IsNullOrWhiteSpace(
                    participant.IdentityKey))
            {
                if (_challengeService != null)
                {
                    _challengeService.CancelParticipant(
                        participant.IdentityKey);
                }
            }

            RemovePendingConnection(
                player.Id);

            _hostSecurityService.MarkParticipantRejected(
                player,
                decision.DenyCode,
                decision.Reason);

            MirrorParticipantRejected(
                player,
                decision.DenyCode,
                decision.Reason);

            RecordParticipantSnapshot(
                player,
                report);

            List<ObservedViolation> violations =
                BuildObservedViolations(
                    player,
                    decision,
                    report);

            if (_violationStore != null)
            {
                foreach (ObservedViolation violation
                         in violations)
                {
                    if (violation == null)
                    {
                        continue;
                    }

                    _violationStore.Record(
                        violation);
                }
            }

            PublishRejectionEvent(
                player,
                decision,
                violations);

            if (sendDecision)
            {
                SendDecision(
                    player.Id,
                    decision);
            }

            Kick(
                player.Id,
                decision.Reason,
                decision.DenyCode);
        }

        private List<ObservedViolation>
            BuildObservedViolations(
                IServerPlayer player,
                SecurityDecision decision,
                SecurityReport report)
        {
            List<ObservedViolation> result =
                new List<ObservedViolation>();

            if (player == null ||
                decision == null)
            {
                return result;
            }

            SecuritySeverity severity =
                GetSeverity(
                    decision.DenyCode);

            DateTime nowUtc =
                DateTime.UtcNow;

            if (report != null &&
                report.UnknownFiles != null)
            {
                foreach (FileScanEntry file
                         in report.UnknownFiles)
                {
                    if (file == null)
                    {
                        continue;
                    }

                    ModArtifactScanEntry modArtifact =
                        FindModArtifact(
                            report,
                            file.Path,
                            file.ModId,
                            file.ArtifactId);

                    result.Add(
                        new ObservedViolation
                        {
                            SessionId =
                                _hostSecurityService.SessionId,

                            PlayerIdentityKey =
                                NormalizeIdentity(
                                    player.AuthKey),

                            DisplayName =
                                player.Username,

                            ModId =
                                FirstNonEmpty(
                                    file.ModId,
                                    modArtifact == null
                                        ? null
                                        : modArtifact.ModId),

                            ArtifactId =
                                FirstNonEmpty(
                                    file.ArtifactId,
                                    modArtifact == null
                                        ? null
                                        : modArtifact.ArtifactId),

                            FileName =
                                GetFileName(
                                    file.Path),

                            Path =
                                file.Path,

                            Version =
                                modArtifact == null
                                    ? null
                                    : modArtifact.Version,

                            AssemblyFullName =
                                modArtifact == null
                                    ? null
                                    : modArtifact.AssemblyFullName,

                            Sha256 =
                                file.Sha256,

                            ViolationType =
                                ViolationType.UnknownMod,

                            Severity =
                                severity,

                            FirstPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            LastPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            Notes =
                                BuildViolationNotes(
                                    decision,
                                    file.ExpectedSha256)
                        });
                }
            }

            if (report != null &&
                report.ForbiddenFiles != null)
            {
                foreach (FileScanEntry file
                         in report.ForbiddenFiles)
                {
                    if (file == null)
                    {
                        continue;
                    }

                    ModArtifactScanEntry modArtifact =
                        FindModArtifact(
                            report,
                            file.Path,
                            file.ModId,
                            file.ArtifactId);

                    result.Add(
                        new ObservedViolation
                        {
                            SessionId =
                                _hostSecurityService.SessionId,

                            PlayerIdentityKey =
                                NormalizeIdentity(
                                    player.AuthKey),

                            DisplayName =
                                player.Username,

                            ModId =
                                FirstNonEmpty(
                                    file.ModId,
                                    modArtifact == null
                                        ? null
                                        : modArtifact.ModId),

                            ArtifactId =
                                FirstNonEmpty(
                                    file.ArtifactId,
                                    modArtifact == null
                                        ? null
                                        : modArtifact.ArtifactId),

                            FileName =
                                GetFileName(
                                    file.Path),

                            Path =
                                file.Path,

                            Version =
                                modArtifact == null
                                    ? null
                                    : modArtifact.Version,

                            AssemblyFullName =
                                modArtifact == null
                                    ? null
                                    : modArtifact.AssemblyFullName,

                            Sha256 =
                                file.Sha256,

                            ViolationType =
                                ViolationType.ForbiddenMod,

                            Severity =
                                severity,

                            FirstPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            LastPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            Notes =
                                BuildViolationNotes(
                                    decision,
                                    file.ExpectedSha256)
                        });
                }
            }

            if (report != null &&
                report.UnknownAssemblies != null)
            {
                foreach (AssemblyScanEntry assembly
                         in report.UnknownAssemblies)
                {
                    if (assembly == null)
                    {
                        continue;
                    }

                    result.Add(
                        new ObservedViolation
                        {
                            SessionId =
                                _hostSecurityService.SessionId,

                            PlayerIdentityKey =
                                NormalizeIdentity(
                                    player.AuthKey),

                            DisplayName =
                                player.Username,

                            ModId =
                                assembly.ModId,

                            ArtifactId =
                                assembly.ArtifactId,

                            FileName =
                                GetFileName(
                                    assembly.Location),

                            Path =
                                assembly.Location,

                            Version =
                                FirstNonEmpty(
                                    assembly.AssemblyVersion,
                                    assembly.ManifestVersion),

                            AssemblyFullName =
                                assembly.FullName,

                            Sha256 =
                                assembly.Sha256,

                            ViolationType =
                                ViolationType.UnknownAssembly,

                            Severity =
                                severity,

                            FirstPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            LastPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            Notes =
                                BuildViolationNotes(
                                    decision,
                                    assembly.ExpectedSha256)
                        });
                }
            }

            if (report != null &&
                report.UnknownNativeModules != null)
            {
                foreach (NativeModuleScanEntry module
                         in report.UnknownNativeModules)
                {
                    if (module == null)
                    {
                        continue;
                    }

                    result.Add(
                        new ObservedViolation
                        {
                            SessionId =
                                _hostSecurityService.SessionId,

                            PlayerIdentityKey =
                                NormalizeIdentity(
                                    player.AuthKey),

                            DisplayName =
                                player.Username,

                            ModId =
                                module.ModId,

                            ArtifactId =
                                module.ArtifactId,

                            FileName =
                                GetFileName(
                                    module.Path),

                            Path =
                                module.Path,

                            Sha256 =
                                module.Sha256,

                            ViolationType =
                                ViolationType.UnknownNativeModule,

                            Severity =
                                severity,

                            FirstPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            LastPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            Notes =
                                BuildViolationNotes(
                                    decision,
                                    module.ExpectedSha256)
                        });
                }
            }

            if (report != null &&
                report.IntegrityFailures != null)
            {
                foreach (string failure
                         in report.IntegrityFailures)
                {
                    if (string.IsNullOrWhiteSpace(
                        failure))
                    {
                        continue;
                    }

                    result.Add(
                        new ObservedViolation
                        {
                            SessionId =
                                _hostSecurityService.SessionId,

                            PlayerIdentityKey =
                                NormalizeIdentity(
                                    player.AuthKey),

                            DisplayName =
                                player.Username,

                            ViolationType =
                                ViolationType.IntegrityFailure,

                            Severity =
                                severity,

                            FirstPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            LastPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            Notes =
                                Truncate(
                                    decision.DenyCode +
                                    ": " +
                                    failure,
                                    4000)
                        });
                }
            }

            if (report != null &&
                report.UnreadableFiles != null)
            {
                foreach (string unreadable
                         in report.UnreadableFiles)
                {
                    if (string.IsNullOrWhiteSpace(
                        unreadable))
                    {
                        continue;
                    }

                    result.Add(
                        new ObservedViolation
                        {
                            SessionId =
                                _hostSecurityService.SessionId,

                            PlayerIdentityKey =
                                NormalizeIdentity(
                                    player.AuthKey),

                            DisplayName =
                                player.Username,

                            FileName =
                                GetFileName(
                                    unreadable),

                            Path =
                                unreadable,

                            ViolationType =
                                ViolationType.Unreadable,

                            Severity =
                                severity,

                            FirstPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            LastPlayer =
                                NormalizeIdentity(
                                    player.AuthKey),

                            Notes =
                                Truncate(
                                    decision.DenyCode +
                                    ": " +
                                    decision.Reason,
                                    4000)
                        });
                }
            }

            if (result.Count == 0)
            {
                result.Add(
                    new ObservedViolation
                    {
                        SessionId =
                            _hostSecurityService.SessionId,

                        PlayerIdentityKey =
                            NormalizeIdentity(
                                player.AuthKey),

                        DisplayName =
                            player.Username,

                        ViolationType =
                            MapViolationType(
                                decision.DenyCode),

                        Severity =
                            severity,

                        FirstPlayer =
                            NormalizeIdentity(
                                player.AuthKey),

                        LastPlayer =
                            NormalizeIdentity(
                                player.AuthKey),

                        Notes =
                            Truncate(
                                decision.DenyCode +
                                ": " +
                                decision.Reason,
                                4000)
                    });
            }

            foreach (ObservedViolation violation
                     in result)
            {
                if (violation == null)
                {
                    continue;
                }

                violation.FirstSeenUtc =
                    nowUtc;

                violation.LastSeenUtc =
                    nowUtc;

                violation.SeenCount =
                    1;
            }

            return result;
        }

        private void PublishRejectionEvent(
            IServerPlayer player,
            SecurityDecision decision,
            List<ObservedViolation> violations)
        {
            if (_eventBus == null ||
                player == null ||
                decision == null)
            {
                return;
            }

            SecuritySeverity severity =
                GetSeverity(
                    decision.DenyCode);

            string identity =
                NormalizeIdentity(
                    player.AuthKey);

            string displayName =
                player.Username;

            string message =
                decision.DenyCode +
                ": " +
                Truncate(
                    decision.Reason,
                    3000);

            string evidenceSummary =
                BuildEvidenceSummary(
                    decision,
                    violations);

            SecurityEvent securityEvent;

            if (violations != null &&
                violations.Count > 0)
            {
                securityEvent =
                    SecurityEvent.CreateArtifactEvent(
                        SecurityEventType.PlayerRejected,
                        severity,
                        _hostSecurityService.SessionId,
                        identity,
                        displayName,
                        message,
                        evidenceSummary);
            }
            else
            {
                securityEvent =
                    SecurityEvent.CreatePlayerEvent(
                        SecurityEventType.PlayerRejected,
                        severity,
                        _hostSecurityService.SessionId,
                        identity,
                        displayName,
                        message);
            }

            securityEvent.SetProvider(
                "WhitelistServerAddon");

            _eventBus.Publish(
                securityEvent);
        }

        private void PublishHostSecurityEvent(
            SecurityEventType eventType,
            SecuritySeverity severity,
            string message)
        {
            if (_eventBus == null ||
                _hostSecurityService == null)
            {
                return;
            }

            SecurityEvent securityEvent =
                SecurityEvent.CreateHostEvent(
                    eventType,
                    _hostSecurityService.SessionId,
                    severity,
                    message);

            securityEvent.SetProvider(
                "WhitelistServerAddon");

            _eventBus.Publish(
                securityEvent);
        }

        private void PublishPlayerSecurityEvent(
            IServerPlayer player,
            SecurityEventType eventType,
            SecuritySeverity severity,
            string message)
        {
            if (_eventBus == null ||
                _hostSecurityService == null ||
                player == null)
            {
                return;
            }

            SecurityEvent securityEvent =
                SecurityEvent.CreatePlayerEvent(
                    eventType,
                    severity,
                    _hostSecurityService.SessionId,
                    NormalizeIdentity(
                        player.AuthKey),
                    player.Username,
                    message);

            securityEvent.SetProvider(
                "WhitelistServerAddon");

            _eventBus.Publish(
                securityEvent);
        }

        private void RecordParticipantSnapshot(
            IServerPlayer player,
            SecurityReport report)
        {
            if (_sessionAuditStore == null ||
                _hostSecurityService == null ||
                player == null)
            {
                return;
            }

            string identityKey =
                NormalizeIdentity(
                    player.AuthKey);

            ParticipantSession participant;

            if (!_hostSecurityService.TryGetParticipant(
                    identityKey,
                    out participant) ||
                participant == null)
            {
                return;
            }

            _sessionAuditStore.RecordParticipant(
                participant,
                report);
        }

        private static string BuildEvidenceSummary(
            SecurityDecision decision,
            List<ObservedViolation> violations)
        {
            try
            {
                List<ObservedViolation> limited =
                    violations == null
                        ? new List<ObservedViolation>()
                        : violations
                            .Take(16)
                            .ToList();

                string json =
                    JsonConvert.SerializeObject(
                        new
                        {
                            DenyCode =
                                decision == null
                                    ? null
                                    : decision.DenyCode,

                            Reason =
                                decision == null
                                    ? null
                                    : Truncate(
                                        decision.Reason,
                                        4000),

                            Violations =
                                limited
                        },
                        Formatting.None);

                return
                    Truncate(
                        json,
                        12000);
            }
            catch
            {
                return null;
            }
        }

        private static SecuritySeverity GetSeverity(
            string denyCode)
        {
            if (string.IsNullOrWhiteSpace(
                    denyCode))
            {
                return SecuritySeverity.High;
            }

            string value =
                denyCode.Trim();

            if (value.IndexOf(
                    "HOST",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "INTEGRITY",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "CORE",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "SELF",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "SESSION_INVALIDATED",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return SecuritySeverity.Critical;
            }

            if (value.IndexOf(
                    "CHALLENGE",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "UNKNOWN",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "FORBIDDEN",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "HASH",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "VERSION",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "ASSEMBLY",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "PATH",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "RUNTIME",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "PROTOCOL",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return SecuritySeverity.High;
            }

            return SecuritySeverity.Warning;
        }

        private static ViolationType MapViolationType(
            string denyCode)
        {
            if (string.IsNullOrWhiteSpace(
                    denyCode))
            {
                return ViolationType.ProtocolViolation;
            }

            string value =
                denyCode.Trim();

            if (value.IndexOf(
                    "UNKNOWN_NATIVE",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.UnknownNativeModule;
            }

            if (value.IndexOf(
                    "UNKNOWN_ASSEMBLY",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.UnknownAssembly;
            }

            if (value.IndexOf(
                    "UNKNOWN_FILE",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "UNKNOWN_MOD",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "MOD_NOT_IN_PRESET",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "MOD_NOT_PRESENT",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.UnknownMod;
            }

            if (value.IndexOf(
                    "FORBIDDEN",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.ForbiddenMod;
            }

            if (value.IndexOf(
                    "HASH",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.HashMismatch;
            }

            if (value.IndexOf(
                    "VERSION",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.VersionMismatch;
            }

            if (value.IndexOf(
                    "ASSEMBLY",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.AssemblyMismatch;
            }

            if (value.IndexOf(
                    "PATH",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.PathMismatch;
            }

            if (value.IndexOf(
                    "UNREADABLE",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.Unreadable;
            }

            if (value.IndexOf(
                    "RUNTIME",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.RuntimeArtifactAdded;
            }

            if (value.IndexOf(
                    "SAVE",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.SaveIntegrityViolation;
            }

            if (value.IndexOf(
                    "CHALLENGE",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.ChallengeFailure;
            }

            if (value.IndexOf(
                    "INTEGRITY",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.IntegrityFailure;
            }

            if (value.IndexOf(
                    "PROTOCOL",
                    StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf(
                    "MALFORMED",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.ProtocolViolation;
            }

            if (value.IndexOf(
                    "HOST",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return ViolationType.HostIntegrityChanged;
            }

            return ViolationType.UnknownMod;
        }

        private static string BuildViolationNotes(
            SecurityDecision decision,
            string expectedSha256)
        {
            string notes =
                decision == null
                    ? string.Empty
                    : (
                        decision.DenyCode +
                        ": " +
                        decision.Reason);

            if (!string.IsNullOrWhiteSpace(
                    expectedSha256))
            {
                notes +=
                    " ExpectedSHA256=" +
                    expectedSha256;
            }

            return
                Truncate(
                    notes,
                    4000);
        }

        private static ModArtifactScanEntry FindModArtifact(
            SecurityReport report,
            string path,
            string modId,
            string artifactId)
        {
            if (report == null ||
                report.ModArtifacts == null ||
                report.ModArtifacts.Count == 0)
            {
                return null;
            }

            foreach (ModArtifactScanEntry artifact
                     in report.ModArtifacts)
            {
                if (artifact == null)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(
                        artifactId) &&
                    string.Equals(
                        artifact.ArtifactId,
                        artifactId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return artifact;
                }

                if (!string.IsNullOrWhiteSpace(
                        modId) &&
                    string.Equals(
                        artifact.ModId,
                        modId,
                        StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(
                        artifact.Path,
                        path,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return artifact;
                }

                if (!string.IsNullOrWhiteSpace(
                        path) &&
                    string.Equals(
                        artifact.Path,
                        path,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return artifact;
                }
            }

            return null;
        }

        private void SendDecision(
            ushort playerId,
            SecurityDecision decision)
        {
            try
            {
                _sender.SendSingleData(
                    WhitelistClientPacketId.Decision,
                    new JsonPacket
                    {
                        Json =
                            JsonConvert.SerializeObject(
                                decision,
                                Formatting.None)
                    },
                    playerId);
            }
            catch (Exception ex)
            {
                LogServerError(
                    "Failed to send security decision to player " +
                    playerId +
                    ": " +
                    ex.GetType().Name);
            }
        }

        private void Kick(
            ushort playerId,
            string reason,
            string denyCode)
        {
            try
            {
                _api.ServerManager.SendMessage(
                    playerId,
                    "Whitelist: " +
                    Truncate(
                        reason,
                        2000) +
                    " [" +
                    (denyCode ??
                     "SECURITY_REJECTION") +
                    "]");
            }
            catch (Exception ex)
            {
                LogServerError(
                    "Failed to send rejection message to player " +
                    playerId +
                    ": " +
                    ex.GetType().Name);
            }

            Task.Run(
                async () =>
                {
                    await Task.Delay(
                        100)
                        .ConfigureAwait(false);

                    try
                    {
                        _api.ServerManager.DisconnectPlayer(
                            playerId,
                           DisconnectReason.Kicked);
                    }
                    catch (Exception ex)
                    {
                        LogServerError(
                            "Failed to disconnect rejected player " +
                            playerId +
                            ": " +
                            ex.GetType().Name);
                    }
                });
        }

        private bool IsPendingConnection(
            ushort playerId)
        {
            lock (_gate)
            {
                return _pendingConnections.ContainsKey(
                    playerId);
            }
        }

        private void RemovePendingConnection(
            ushort playerId)
        {
            lock (_gate)
            {
                _pendingConnections.Remove(
                    playerId);
            }
        }

        private void RemovePendingState(
            ushort playerId)
        {
            lock (_gate)
            {
                _pendingConnections.Remove(
                    playerId);
                _reportTransfers.Remove(
                    playerId);
                _baselineTransfers.Remove(
                    playerId);
            }
        }

        private static IPacketData InstantiatePacket(
            WhitelistServerPacketId packetId)
        {
            switch (packetId)
            {
                case WhitelistServerPacketId.SecurityReport:
                case WhitelistServerPacketId.ChallengeResponse:
                case WhitelistServerPacketId.RuntimeEvent:
                case WhitelistServerPacketId.SecurityHello:
                case WhitelistServerPacketId.HostBaselineChunkAck:
                    return new JsonPacket();

                default:
                    return null;
            }
        }

        private static void LogServerInfo(
            string message)
        {
            Modding.Logger.Log(
                "[HKMP.Whitelist] " +
                (message ?? "<info>"));
        }

        private static void LogServerError(
            string message)
        {
            Modding.Logger.LogError(
                "[HKMP.Whitelist] " +
                (message ?? "<error>"));
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

        private static string FirstNonEmpty(
            string first,
            string second)
        {
            if (!string.IsNullOrWhiteSpace(
                    first))
            {
                return first;
            }

            if (!string.IsNullOrWhiteSpace(
                    second))
            {
                return second;
            }

            return null;
        }

        private static string GetFileName(
            string path)
        {
            if (string.IsNullOrWhiteSpace(
                    path))
            {
                return null;
            }

            try
            {
                return Path.GetFileName(
                    path);
            }
            catch
            {
                return path;
            }
        }

        private static string Truncate(
            string value,
            int maximumLength)
        {
            if (string.IsNullOrEmpty(
                    value))
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

        private sealed class HostBaselinePacketData
        {
            public HostBaseline Baseline { get; set; }
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

            public int CurrentLength;

            public Dictionary<int, string> Chunks =
                new Dictionary<int, string>();
        }

        private sealed class HostBaselineTransferState
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

        private sealed class PendingConnection
        {
            public string ConnectionId;

            public DateTime CreatedUtc;
        }

        private sealed class RuntimeEventData
        {
            public int ProtocolVersion { get; set; }

            public string SessionId { get; set; }

            public string Type { get; set; }

            public string Details { get; set; }

            public DateTime TimestampUtc { get; set; }
        }
    }
}
