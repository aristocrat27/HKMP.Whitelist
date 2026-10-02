using System;
using System.Text;

namespace HKMP.Whitelist.Shared
{
    public static class ChallengeProofBuilder
    {
        public static byte[] BuildMessage(
            ChallengeRequest request,
            byte[] localArtifactBytes)
        {
            if (request == null ||
                localArtifactBytes == null ||
                localArtifactBytes.Length == 0)
            {
                return null;
            }

            string header =
                (request.ProtocolVersion.ToString() ?? "0") + "|" +
                (request.SessionId ?? "") + "|" +
                (request.ChallengeId ?? "") + "|" +
                request.SecurityGeneration.ToString() + "|" +
                request.SequenceNumber.ToString() + "|" +
                (request.NonceBase64 ?? "");

            byte[] headerBytes =
                Encoding.UTF8.GetBytes(
                    header);

            byte[] result =
                new byte[
                    headerBytes.Length +
                    1 +
                    localArtifactBytes.Length];

            Buffer.BlockCopy(
                headerBytes,
                0,
                result,
                0,
                headerBytes.Length);

            result[headerBytes.Length] =
                (byte)'|';

            Buffer.BlockCopy(
                localArtifactBytes,
                0,
                result,
                headerBytes.Length + 1,
                localArtifactBytes.Length);

            return result;
        }
    }
}
