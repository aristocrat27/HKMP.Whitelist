using Hkmp.Networking.Packet;

namespace HKMP.Whitelist.Shared
{
    public enum WhitelistServerPacketId
    {
        SecurityReport,
        ChallengeResponse,
        RuntimeEvent,
        SecurityHello,
        HostBaselineChunkAck
    }

    public enum WhitelistClientPacketId
    {
        Manifest,
        Challenge,
        Decision,
        SecurityReportChunkAck
    }

    internal sealed class SecurityHelloData
    {
        public int ProtocolVersion { get; set; }
    }

    internal sealed class SecurityReportChunkPacketData
    {
        public int ProtocolVersion { get; set; }

        public string TransferId { get; set; }

        public string SessionId { get; set; }

        public string BaselineId { get; set; }

        public int ChunkIndex { get; set; }

        public int ChunkCount { get; set; }

        public int TotalLength { get; set; }

        public string Sha256 { get; set; }

        public string Data { get; set; }
    }

    internal sealed class HostBaselineChunkAckData
    {
        public int ProtocolVersion { get; set; }

        public string TransferId { get; set; }

        public string SessionId { get; set; }

        public string BaselineId { get; set; }

        public int ChunkIndex { get; set; }
    }

    internal sealed class SecurityReportChunkAckData
    {
        public int ProtocolVersion { get; set; }

        public string TransferId { get; set; }

        public string SessionId { get; set; }

        public string BaselineId { get; set; }

        public int ChunkIndex { get; set; }
    }

    internal sealed class HostBaselineChunkPacketData
    {
        public int ProtocolVersion { get; set; }

        public string TransferId { get; set; }

        public string SessionId { get; set; }

        public string BaselineId { get; set; }

        public int ChunkIndex { get; set; }

        public int ChunkCount { get; set; }

        public int TotalLength { get; set; }

        public string Sha256 { get; set; }

        public string Data { get; set; }
    }

    public sealed class JsonPacket : IPacketData
    {
        public string Json { get; set; } = "{}";

        public bool IsReliable
        {
            get { return true; }
        }

        public bool DropReliableDataIfNewerExists
        {
            get { return false; }
        }

        public void WriteData(
            IPacket packet)
        {
            packet.Write(
                Json ?? "{}");
        }

        public void ReadData(
            IPacket packet)
        {
            Json =
                packet.ReadString(
                    65535);
        }
    }
}
