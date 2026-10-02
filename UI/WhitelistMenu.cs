using Satchel.BetterMenus;
using System.IO;
using UnityEngine;

namespace HKMP.Whitelist.UI
{
    public sealed class WhitelistMenu
    {
        private readonly string _modDirectory;

        private readonly ModBrowserMenu _mods;
        private readonly PresetMenu _presets;
        private readonly SecurityMenu _security;
        private readonly DiagnosticsMenu _diagnostics;

        private Menu _mainMenu;
        private MenuScreen _modListParent;

        private TextPanel _presetText;

        private bool _dirty;

        public WhitelistMenu()
        {
            string assemblyPath =
                typeof(WhitelistMenu)
                    .Assembly
                    .Location;

            _modDirectory =
                string.IsNullOrWhiteSpace(
                    assemblyPath)
                    ? Application.dataPath
                    : Path.GetDirectoryName(
                        assemblyPath);

            _mods =
                new ModBrowserMenu(this);

            _presets =
                new PresetMenu(this);

            _security =
                new SecurityMenu(this);

            _diagnostics =
                new DiagnosticsMenu(this);

            PresetStore.PolicyChanged +=
                OnPolicyChanged;
        }

        private void OnPolicyChanged()
        {
            UpdateMainSummary();
        }

        public string ModDirectory
        {
            get { return _modDirectory; }
        }

        public bool IsDirty
        {
            get { return _dirty; }
        }

        public void MarkDirty()
        {
            _dirty = true;
            UpdateMainSummary();
        }

        public void MarkSaved()
        {
            _dirty = false;
            UpdateMainSummary();
        }

        public MenuScreen GetMenuScreen(
            MenuScreen modListMenu)
        {
            _modListParent =
                modListMenu;

            EnsureMainMenu();

            return
                _mainMenu.GetMenuScreen(
                    modListMenu);
        }

        public void OpenMods(
            MenuScreen parent)
        {
            MenuScreen target =
                parent ??
                _modListParent;

            _mods.Open(
                target);
        }

        public void OpenSecurity(
            MenuScreen parent)
        {
            _security.Open(parent);
        }

        public void OpenPresets(
            MenuScreen parent)
        {
            _presets.Open(parent);
        }

        public void OpenDiagnostics(
            MenuScreen parent)
        {
            _diagnostics.Open(parent);
        }

        public void GoTo(
            Menu menu)
        {
            GoTo(
                menu,
                _mainMenu == null
                    ? _modListParent
                    : _mainMenu.menuScreen);
        }

        public void GoTo(
            Menu menu,
            MenuScreen parent)
        {
            if (menu == null)
            {
                return;
            }

            if (parent == null)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Cannot open menu because the parent MenuScreen is null.");

                return;
            }

            MenuScreen screen =
                menu.GetMenuScreen(parent);

            Satchel.BetterMenus.Utils.GoToMenuScreen(
                screen);
        }

        private void EnsureMainMenu()
        {
            if (_mainMenu != null)
            {
                UpdateMainSummary();
                return;
            }

            _presetText =
                new TextPanel(
                    "",
                    fontSize:
                        WhitelistUiStyle.MainPreset,
                    Id:
                        "PresetText");

            _mainMenu =
                new Menu(
                    "WHITELIST",
                    new Element[]
                    {
                        new TextPanel(
                            "WHITELIST",
                            fontSize:
                                WhitelistUiStyle.Title,
                            Id:
                                "Title"),

                        _presetText,

                        new MenuButton(
                            "MODS",
                            "Browse installed mods and set policy",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                OpenMods(
                                    _mainMenu.menuScreen ??
                                    _modListParent);
                            },
                            true,
                            "Mods"),

                        new MenuButton(
                            "PRESETS",
                            "Manage security profiles",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                OpenPresets(
                                    _mainMenu.menuScreen);
                            },
                            true,
                            "Presets"),

                        new MenuButton(
                            "SECURITY",
                            "Verification and integrity settings",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                OpenSecurity(
                                    _mainMenu.menuScreen);
                            },
                            true,
                            "Security"),

                        new MenuButton(
                            "DIAGNOSTICS",
                            "Security state and local diagnostics",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                OpenDiagnostics(
                                    _mainMenu.menuScreen);
                            },
                            true,
                            "Diagnostics")
                    });

            UpdateMainSummary();
        }

        private void UpdateMainSummary()
        {
            if (_presetText == null)
            {
                return;
            }

            string activeName =
                PresetStore.GetActivePresetName();

            _presetText.Name =
                string.IsNullOrWhiteSpace(activeName)
                    ? "No active preset"
                    : "Preset  ·  " + activeName;

            try
            {
                _presetText.Update();
            }
            catch
            {
            }
        }
    }
}