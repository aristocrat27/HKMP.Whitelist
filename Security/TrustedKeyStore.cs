using System;
using System.Collections.Generic;

namespace HKMP.Whitelist.Security
{
    internal static class TrustedKeyStore
    {
        private static readonly Dictionary<
            string,
            string> TrustedPublicKeys =
            new Dictionary<
                string,
                string>(
                StringComparer.Ordinal);

        public static bool TryGetPublicKey(
            string keyId,
            out byte[] publicKey)
        {
            publicKey = null;

            if (string.IsNullOrWhiteSpace(
                    keyId))
            {
                return false;
            }

            string encodedKey;

            if (!TrustedPublicKeys.TryGetValue(
                    keyId.Trim(),
                    out encodedKey))
            {
                return false;
            }

            try
            {
                publicKey =
                    Convert.FromBase64String(
                        encodedKey);

                return
                    publicKey != null &&
                    publicKey.Length == 32;
            }
            catch
            {
                publicKey = null;

                return false;
            }
        }

        public static bool IsTrustedPublicKey(
            string keyId,
            byte[] publicKey)
        {
            if (publicKey == null ||
                publicKey.Length != 32)
            {
                return false;
            }

            byte[] trustedKey;

            if (!TryGetPublicKey(
                    keyId,
                    out trustedKey))
            {
                return false;
            }

            return FixedTimeEquals(
                trustedKey,
                publicKey);
        }

        private static bool FixedTimeEquals(
            byte[] first,
            byte[] second)
        {
            if (first == null ||
                second == null ||
                first.Length != second.Length)
            {
                return false;
            }

            int difference = 0;

            for (int i = 0;
                 i < first.Length;
                 i++)
            {
                difference |=
                    first[i] ^
                    second[i];
            }

            return difference == 0;
        }
    }
}