
using HKMP.Whitelist.Shared;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace HKMP.Whitelist.Server
{
    internal static class PresetLoader
    {
        private const string PresetFileName =
        "preset.json";

        private const string ManifestFileName =
            "manifest.json";

        private const int MaximumManifestBytes =
            4 * 1024 * 1024;

        private const int MaximumPresetBytes =
            1024 * 1024;

        public static PresetConfig Load(
            string directory)
        {
            PresetConfig fallback =
                CreateDenyAllPreset();

            if (string.IsNullOrWhiteSpace(
                    directory))
            {
                return fallback;
            }

            string path;

            try
            {
                path =
                    Path.Combine(
                        directory,
                        PresetFileName);
            }
            catch
            {
                return fallback;
            }

            if (!File.Exists(
                    path))
            {
                return fallback;
            }

            try
            {
                FileInfo info =
                    new FileInfo(
                        path);

                if (info.Length <= 0 ||
                    info.Length > MaximumPresetBytes)
                {
                    return fallback;
                }

                string json =
                    File.ReadAllText(
                        path);

                if (string.IsNullOrWhiteSpace(
                        json))
                {
                    return fallback;
                }

                PresetConfig preset =
                    JsonConvert.DeserializeObject<PresetConfig>(
                        json,
                        CreateJsonSettings());

                if (preset == null)
                {
                    return fallback;
                }

                NormalizePreset(
                    preset);

                return preset;
            }
            catch
            {
                return fallback;
            }
        }

        public static TrustedManifest LoadManifest(
            string directory)
        {
            TrustedManifest manifest;
            string reason;

            if (!TryLoadManifest(
                    directory,
                    out manifest,
                    out reason))
            {
                return null;
            }

            return manifest;
        }

        public static bool TryLoadManifest(
            string directory,
            out TrustedManifest manifest,
            out string reason)
        {
            manifest = null;
            reason = null;

            if (string.IsNullOrWhiteSpace(
                    directory))
            {
                reason =
                    "MANIFEST_DIRECTORY_INVALID";

                return false;
            }

            string path;

            try
            {
                path =
                    Path.Combine(
                        directory,
                        ManifestFileName);
            }
            catch
            {
                reason =
                    "MANIFEST_PATH_INVALID";

                return false;
            }

            if (!File.Exists(
                    path))
            {
                reason =
                    "MANIFEST_FILE_NOT_FOUND";

                return false;
            }

            try
            {
                FileInfo info =
                    new FileInfo(
                        path);

                if (info.Length <= 0)
                {
                    reason =
                        "MANIFEST_FILE_EMPTY";

                    return false;
                }

                if (info.Length >
                    MaximumManifestBytes)
                {
                    reason =
                        "MANIFEST_FILE_TOO_LARGE";

                    return false;
                }

                string json =
                    File.ReadAllText(
                        path);

                if (string.IsNullOrWhiteSpace(
                        json))
                {
                    reason =
                        "MANIFEST_JSON_EMPTY";

                    return false;
                }

                manifest =
                    JsonConvert.DeserializeObject<TrustedManifest>(
                        json,
                        CreateJsonSettings());

                if (manifest == null)
                {
                    reason =
                        "MANIFEST_DESERIALIZATION_FAILED";

                    return false;
                }

                return true;
            }
            catch (JsonSerializationException)
            {
                manifest = null;

                reason =
                    "MANIFEST_JSON_INVALID";

                return false;
            }
            catch (IOException)
            {
                manifest = null;

                reason =
                    "MANIFEST_FILE_READ_FAILED";

                return false;
            }
            catch (UnauthorizedAccessException)
            {
                manifest = null;

                reason =
                    "MANIFEST_FILE_ACCESS_DENIED";

                return false;
            }
            catch
            {
                manifest = null;

                reason =
                    "MANIFEST_LOAD_FAILED";

                return false;
            }
        }

        private static JsonSerializerSettings CreateJsonSettings()
        {
            return
                new JsonSerializerSettings
                {
                    Culture =
                        CultureInfo.InvariantCulture,

                    DateParseHandling =
                        DateParseHandling.DateTime,

                    DateTimeZoneHandling =
                        DateTimeZoneHandling.Utc,

                    MissingMemberHandling =
                        MissingMemberHandling.Error,

                    NullValueHandling =
                        NullValueHandling.Include,

                    DefaultValueHandling =
                        DefaultValueHandling.Include,

                    TypeNameHandling =
                        TypeNameHandling.None,

                    MetadataPropertyHandling =
                        MetadataPropertyHandling.Ignore
                };
        }

        private static PresetConfig CreateDenyAllPreset()
        {
            return
                new PresetConfig
                {
                    PresetName =
                        "Default Deny All",

                    SecurityMode =
                        SecurityMode.Maximum,

                    UnknownPolicyDeny =
                        true,

                    RequireCompleteScan =
                        true,

                    CheckCoreIntegrity =
                        true,

                    CheckSelfIntegrity =
                        true,

                    RuntimeMonitoringEnabled =
                        true,

                    RuntimeScanIntervalSeconds =
                        30,

                    ChallengeEnabled =
                        true,

                    ChallengeTimeoutMs =
                        3000,

                    RequiredMods =
                        new List<string>(),

                    AllowedMods =
                        new List<string>(),

                    IgnoredMods =
                        new List<string>(),

                    ForbiddenMods =
                        new List<string>()
                };
        }

        private static void NormalizePreset(
            PresetConfig preset)
        {
            if (preset == null)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(
                    preset.PresetName))
            {
                preset.PresetName =
                    "Default Deny All";
            }

            ModPolicyResolver.Normalize(
                preset);

            if (preset.RuntimeScanIntervalSeconds < 1)
            {
                preset.RuntimeScanIntervalSeconds =
                    30;
            }

            if (preset.RuntimeScanIntervalSeconds > 3600)
            {
                preset.RuntimeScanIntervalSeconds =
                    3600;
            }

            if (preset.ChallengeTimeoutMs < 250)
            {
                preset.ChallengeTimeoutMs =
                    250;
            }

            if (preset.ChallengeTimeoutMs > 30000)
            {
                preset.ChallengeTimeoutMs =
                    30000;
            }
        }

    }
}
