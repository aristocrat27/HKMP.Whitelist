using Hkmp.Api.Client;
using Hkmp.Api.Client.Networking;
using Hkmp.Networking.Packet;
using HKMP.Whitelist.Shared;
using Newtonsoft.Json;

namespace HKMP.Whitelist.Client
{
    public sealed class WhitelistClientAddon : ClientAddon
    {
        private WhitelistClientSecurityService _service;

        public override bool NeedsNetwork => true;

        protected override string Name =>
            "HKMP.Whitelist";

        protected override string Version =>
            "1.1.0.0";

        public override void Initialize(
            IClientApi clientApi)
        {
            _service =
                new WhitelistClientSecurityService(
                    this,
                    clientApi);

            clientApi.ClientManager.ConnectEvent +=
                OnConnect;

            var receiver =
                clientApi.NetClient.GetNetworkReceiver<WhitelistClientPacketId>(
                    this,
                    InstantiatePacket);

            receiver.RegisterPacketHandler<JsonPacket>(
                WhitelistClientPacketId.Manifest,
                packet =>
                    _service.HandleManifest(
                        packet.Json));

            receiver.RegisterPacketHandler<JsonPacket>(
                WhitelistClientPacketId.Challenge,
                packet =>
                    _service.HandleChallenge(
                        packet.Json));

            receiver.RegisterPacketHandler<JsonPacket>(
                WhitelistClientPacketId.Decision,
                packet =>
                    _service.HandleDecision(
                        packet.Json));

            receiver.RegisterPacketHandler<JsonPacket>(
                WhitelistClientPacketId.SecurityReportChunkAck,
                packet =>
                    _service.HandleSecurityReportChunkAck(
                        packet.Json));
        }

        private void OnConnect()
        {
            if (_service == null)
            {
                return;
            }

            _service.BeginHandshake();
        }

        private static IPacketData InstantiatePacket(
            WhitelistClientPacketId packetId)
        {
            switch (packetId)
            {
                case WhitelistClientPacketId.Manifest:
                case WhitelistClientPacketId.SecurityReportChunkAck:
                case WhitelistClientPacketId.Challenge:
                case WhitelistClientPacketId.Decision:
                    return new JsonPacket();

                default:
                    return null;
            }
        }
    }
}
