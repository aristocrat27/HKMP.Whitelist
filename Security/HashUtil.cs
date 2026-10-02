using System;
using System.IO;
using System.Security.Cryptography;

namespace HKMP.Whitelist.Security
{
    internal static class HashUtil
    {
        public static string Sha256File(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path) ||
                !File.Exists(path))
            {
                return null;
            }

            using (SHA256 sha =
                   SHA256.Create())
            using (FileStream stream =
                   new FileStream(
                       path,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.ReadWrite | FileShare.Delete,
                       8192,
                       FileOptions.SequentialScan))
            {
                byte[] hash =
                    sha.ComputeHash(stream);

                return ToLowerHex(hash);
            }
        }

        public static string HmacSha256(
            byte[] key,
            byte[] data)
        {
            if (key == null ||
                key.Length == 0 ||
                data == null)
            {
                return null;
            }

            using (HMACSHA256 hmac =
                   new HMACSHA256(key))
            {
                byte[] hash =
                    hmac.ComputeHash(data);

                return ToLowerHex(hash);
            }
        }

        public static byte[] ReadAllBytesShared(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path) ||
                !File.Exists(path))
            {
                return null;
            }

            using (FileStream stream =
                   new FileStream(
                       path,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.ReadWrite | FileShare.Delete,
                       8192,
                       FileOptions.SequentialScan))
            using (MemoryStream memory =
                   new MemoryStream())
            {
                stream.CopyTo(memory);
                return memory.ToArray();
            }
        }

        public static bool IsSha256(
            string value)
        {
            if (string.IsNullOrEmpty(value) ||
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

                bool hex =
                    (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F');

                if (!hex)
                {
                    return false;
                }
            }

            return true;
        }

        public static bool FixedTimeEquals(
            string first,
            string second)
        {
            if (first == null ||
                second == null)
            {
                return false;
            }

            if (first.Length != second.Length)
            {
                return false;
            }

            int difference = 0;

            for (int i = 0;
                 i < first.Length;
                 i++)
            {
                difference |=
                    first[i] ^ second[i];
            }

            return difference == 0;
        }

        private static string ToLowerHex(
            byte[] bytes)
        {
            if (bytes == null)
            {
                return null;
            }

            char[] chars =
                new char[
                    bytes.Length * 2];

            const string hex =
                "0123456789abcdef";

            for (int i = 0;
                 i < bytes.Length;
                 i++)
            {
                chars[i * 2] =
                    hex[bytes[i] >> 4];

                chars[i * 2 + 1] =
                    hex[bytes[i] & 0x0F];
            }

            return new string(chars);
        }
    }
}