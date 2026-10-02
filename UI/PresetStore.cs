using HKMP.Whitelist.Shared;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace HKMP.Whitelist.UI
{
    internal static class PresetStore
    {
        private static PresetConfig _activePreset;
        private static PresetConfig _editingPreset;
        private static string _editingPresetName;

        public static event Action PolicyChanged;

        public static PresetConfig Get()
        {
            return GetActive();
        }

        public static PresetConfig GetActive()
        {
            if (_activePreset != null)
            {
                return _activePreset;
            }

            LoadActive();

            return _activePreset;
        }

        public static PresetConfig GetEditing()
        {
            if (_editingPreset != null)
            {
                return _editingPreset;
            }

            string activeName =
                GetActivePresetName();

            if (!string.IsNullOrWhiteSpace(activeName))
            {
                if (BeginEditing(activeName))
                {
                    return _editingPreset;
                }

                PresetConfig active =
                    GetActive();

                if (active != null)
                {
                    _editingPreset =
                        Clone(active);

                    _editingPresetName =
                        activeName;

                    return _editingPreset;
                }
            }

            return null;
        }

        public static PresetConfig GetEditingOrActive()
        {
            PresetConfig editing =
                GetEditing();

            return editing ?? GetActive();
        }

        public static bool IsEditing
        {
            get
            {
                return _editingPreset != null;
            }
        }

        public static string EditingPresetName
        {
            get
            {
                return _editingPresetName ?? "";
            }
        }

        public static void Set(
            PresetConfig preset)
        {
            _activePreset =
                preset;

            if (_activePreset != null)
            {
                EnsureLists(
                    _activePreset);
                ModPolicyResolver.Normalize(
                    _activePreset);
            }
        }

        public static string GetActivePresetName()
        {
            if (WhitelistMod.GlobalSettings == null)
            {
                return "";
            }

            return
                WhitelistMod.GlobalSettings.ActivePresetName ??
                "";
        }

        public static bool BeginEditing(
            string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                ClearEditing();
                return false;
            }

            string path =
                GetPresetPath(name);

            try
            {
                if (!File.Exists(path))
                {
                    ClearEditing();
                    return false;
                }

                PresetConfig preset =
                    JsonConvert.DeserializeObject<PresetConfig>(
                        File.ReadAllText(path));

                if (preset == null)
                {
                    ClearEditing();
                    return false;
                }

                preset.PresetName =
                    name;

                EnsureLists(
                    preset);
                ModPolicyResolver.Normalize(
                    preset);

                _editingPreset =
                    preset;

                _editingPresetName =
                    name;

                return true;
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Failed to begin profile editing:\n" +
                    ex);

                ClearEditing();

                return false;
            }
        }

        public static void SetEditing(
            PresetConfig preset,
            string name)
        {
            _editingPreset =
                preset;

            _editingPresetName =
                name ??
                (
                    preset == null
                        ? ""
                        : preset.PresetName);

            if (_editingPreset != null)
            {
                EnsureLists(
                    _editingPreset);
                ModPolicyResolver.Normalize(
                    _editingPreset);
            }
        }

        public static void ClearEditing()
        {
            _editingPreset =
                null;

            _editingPresetName =
                "";
        }

        public static void ActivateEditing(
            string name,
            string directory,
            WhitelistMenu menu)
        {
            if (_editingPreset == null)
            {
                if (!BeginEditing(name))
                {
                    return;
                }
            }

            if (!string.IsNullOrWhiteSpace(name))
            {
                _editingPreset.PresetName =
                    name;

                _editingPresetName =
                    name;
            }

            EnsureLists(
                _editingPreset);
            ModPolicyResolver.Normalize(
                _editingPreset);

            _activePreset =
                Clone(
                    _editingPreset);

            WhitelistGlobalSettings settings =
                WhitelistMod.GlobalSettings;

            if (settings != null)
            {
                settings.ActivePresetName =
                    _editingPresetName;
            }

            WritePresetFiles(
                directory,
                _editingPreset,
                true);

            if (menu != null)
            {
                menu.MarkSaved();
            }

            NotifyPolicyChanged();
        }

        public static void ClearActive(
            string directory,
            WhitelistMenu menu)
        {
            _activePreset =
                null;

            if (WhitelistMod.GlobalSettings != null)
            {
                WhitelistMod.GlobalSettings.ActivePresetName =
                    "";
            }

            try
            {
                string activePath =
                    Path.Combine(
                        directory,
                        "preset.json");

                if (File.Exists(activePath))
                {
                    File.Delete(
                        activePath);
                }
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Failed to clear active profile:\n" +
                    ex);
            }

            if (menu != null)
            {
                menu.MarkSaved();
            }
        }

        public static void Save(
            string directory,
            WhitelistMenu menu)
        {
            if (_editingPreset != null)
            {
                SaveEditing(
                    directory,
                    menu);

                return;
            }

            SaveActive(
                directory,
                menu);
        }

        public static bool SaveEditing(
            string directory,
            WhitelistMenu menu)
        {
            if (_editingPreset == null)
            {
                return false;
            }

            try
            {
                EnsureLists(
                    _editingPreset);
                ModPolicyResolver.Normalize(
                    _editingPreset);

                bool isActive =
                    string.Equals(
                        _editingPresetName,
                        GetActivePresetName(),
                        StringComparison.OrdinalIgnoreCase);

                if (isActive)
                {
                    _activePreset =
                        Clone(
                            _editingPreset);
                }

                WritePresetFiles(
                    directory,
                    _editingPreset,
                    isActive);

                if (menu != null)
                {
                    menu.MarkSaved();
                }

                return true;
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Profile save failed:\n" +
                    ex);

                return false;
            }
        }

        public static void NotifyPolicyChanged()
        {
            Action handler =
                PolicyChanged;

            if (handler == null)
            {
                return;
            }

            foreach (Action callback in
                     handler.GetInvocationList())
            {
                try
                {
                    callback();
                }
                catch (Exception ex)
                {
                    Modding.Logger.LogError(
                        "[Whitelist] PolicyChanged handler failed:\n" +
                        ex);
                }
            }
        }

        private static void SaveActive(
            string directory,
            WhitelistMenu menu)
        {
            PresetConfig preset =
                GetActive();

            if (preset == null)
            {
                return;
            }

            try
            {
                EnsureLists(
                    preset);
                ModPolicyResolver.Normalize(
                    preset);

                WritePresetFiles(
                    directory,
                    preset,
                    true);

                if (menu != null)
                {
                    menu.MarkSaved();
                }
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Active profile save failed:\n" +
                    ex);
            }
        }

        public static PresetConfig CreateDefaultPreset(
            string name)
        {
            return new PresetConfig
            {
                PresetName =
                    string.IsNullOrWhiteSpace(name)
                        ? "Default Deny All"
                        : name,

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

        public static string SanitizeFileName(
            string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "Preset";
            }

            char[] invalid =
                Path.GetInvalidFileNameChars();

            return
                new string(
                    value
                        .Select(
                            c =>
                                invalid.Contains(c)
                                    ? '_'
                                    : c)
                        .ToArray());
        }

        private static void LoadActive()
        {
            string activeName =
                GetActivePresetName();

            if (string.IsNullOrWhiteSpace(activeName))
            {
                _activePreset =
                    null;

                return;
            }

            try
            {
                string assemblyPath =
                    typeof(WhitelistMod)
                        .Assembly
                        .Location;

                string directory =
                    Path.GetDirectoryName(
                        assemblyPath);

                string presetsPath =
                    GetPresetPathFromDirectory(
                        directory,
                        activeName);

                if (File.Exists(presetsPath))
                {
                    _activePreset =
                        JsonConvert.DeserializeObject<PresetConfig>(
                            File.ReadAllText(presetsPath));
                }
                else
                {
                    string activePath =
                        Path.Combine(
                            directory,
                            "preset.json");

                    if (File.Exists(activePath))
                    {
                        _activePreset =
                            JsonConvert.DeserializeObject<PresetConfig>(
                                File.ReadAllText(activePath));
                    }
                }

                if (_activePreset != null)
                {
                    _activePreset.PresetName =
                        activeName;

                    EnsureLists(
                        _activePreset);
                    ModPolicyResolver.Normalize(
                        _activePreset);
                }
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Failed to load active profile:\n" +
                    ex);

                _activePreset =
                    null;
            }
        }

        private static void WritePresetFiles(
            string directory,
            PresetConfig preset,
            bool writeActive)
        {
            if (preset == null ||
                string.IsNullOrWhiteSpace(
                    preset.PresetName))
            {
                return;
            }

            string json =
                JsonConvert.SerializeObject(
                    preset,
                    Formatting.Indented);

            string presetsDirectory =
                Path.Combine(
                    directory,
                    "presets");

            Directory.CreateDirectory(
                presetsDirectory);

            string profilePath =
                GetPresetPathFromDirectory(
                    directory,
                    preset.PresetName);

            File.WriteAllText(
                profilePath,
                json);

            if (writeActive)
            {
                File.WriteAllText(
                    Path.Combine(
                        directory,
                        "preset.json"),
                    json);
            }
        }

        private static string GetPresetPath(
            string name)
        {
            string assemblyPath =
                typeof(WhitelistMod)
                    .Assembly
                    .Location;

            string directory =
                Path.GetDirectoryName(
                    assemblyPath);

            return
                GetPresetPathFromDirectory(
                    directory,
                    name);
        }

        private static string GetPresetPathFromDirectory(
            string directory,
            string name)
        {
            string presetsDirectory =
                Path.Combine(
                    directory,
                    "presets");

            Directory.CreateDirectory(
                presetsDirectory);

            return
                Path.Combine(
                    presetsDirectory,
                    SanitizeFileName(name) +
                    ".json");
        }

        private static PresetConfig Clone(
            PresetConfig source)
        {
            if (source == null)
            {
                return null;
            }

            PresetConfig clone =
                JsonConvert.DeserializeObject<PresetConfig>(
                    JsonConvert.SerializeObject(
                        source));

            if (clone != null)
            {
                EnsureLists(
                    clone);
                ModPolicyResolver.Normalize(
                    clone);
            }

            return clone;
        }

        private static void EnsureLists(
            PresetConfig preset)
        {
            if (preset == null)
            {
                return;
            }

            if (preset.RequiredMods == null)
            {
                preset.RequiredMods =
                    new List<string>();
            }

            if (preset.AllowedMods == null)
            {
                preset.AllowedMods =
                    new List<string>();
            }

            if (preset.IgnoredMods == null)
            {
                preset.IgnoredMods =
                    new List<string>();
            }

            if (preset.ForbiddenMods == null)
            {
                preset.ForbiddenMods =
                    new List<string>();
            }
        }
    }
}
