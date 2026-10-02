using HKMP.Whitelist.Security;
using HKMP.Whitelist.Server;
using HKMP.Whitelist.Shared;
using Satchel.BetterMenus;
using System;

namespace HKMP.Whitelist.UI
{
    public sealed class ManifestMenu
    {
        private readonly WhitelistMenu _root;

        private Menu _menu;

        private TextPanel _status;
        private TextPanel _entries;
        private TextPanel _hash;

        private TrustedManifest _manifest;

        public ManifestMenu(
            WhitelistMenu root)
        {
            _root = root;
        }

        public void Open(
            MenuScreen parent)
        {
            EnsureMenu();

            _root.GoTo(
                _menu,
                parent);

            LoadManifest();
        }

        private void EnsureMenu()
        {
            if (_menu != null)
            {
                return;
            }

            _status =
                new TextPanel(
                    "",
                    fontSize:
                        WhitelistUiStyle.Body,
                    Id:
                        "Status");

            _entries =
                new TextPanel(
                    "",
                    fontSize:
                        WhitelistUiStyle.Body,
                    Id:
                        "Entries");

            _hash =
                new TextPanel(
                    "",
                    fontSize:
                        WhitelistUiStyle.Body,
                    Id:
                        "Hash");

            _menu =
                new Menu(
                    "HKMP.Whitelist - Manifest",
                    new Element[]
                    {
                        new TextPanel(
                            "MANIFEST",
                            fontSize:
                                WhitelistUiStyle.Title),

                        _status,
                        _entries,
                        _hash,

                        new MenuButton(
                            "Refresh",
                            "Reload manifest.json",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                LoadManifest();
                            },
                            false,
                            "Reload"),

                        new MenuButton(
                            "SHA-256",
                            "Calculate current Whitelist DLL hash",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                CalculateSelfHash();
                            },
                            false,
                            "SelfHash")
                    });
        }

        private void LoadManifest()
        {
            try
            {
                _manifest =
                    PresetLoader.LoadManifest(
                        _root.ModDirectory);
            }
            catch (Exception ex)
            {
                _manifest = null;

                Modding.Logger.LogError(
                    "[Whitelist] Manifest load failed:\n" +
                    ex);
            }

            RefreshText();
        }

        private void RefreshText()
        {
            _status.Name =
                _manifest == null
                    ? "Status: Not loaded"
                    : "Status: Loaded";

            _entries.Name =
                "Entries: " +
                (
                    _manifest == null ||
                    _manifest.Entries == null
                        ? 0
                        : _manifest.Entries.Count);

            _hash.Name =
                "Self SHA-256: Not calculated";

            try
            {
                _status.Update();
                _entries.Update();
                _hash.Update();

                _menu.Update();
            }
            catch
            {
            }
        }

        private void CalculateSelfHash()
        {
            try
            {
                string hash =
                    AntiTamperGuard.ComputeSelfHash();

                if (string.IsNullOrEmpty(hash))
                {
                    throw new InvalidOperationException(
                        "Unable to calculate Whitelist self hash.");
                }

                _hash.Name =
                    "Self SHA-256: " +
                    hash;

                _hash.Update();
                _menu.Update();

                Modding.Logger.Log(
                    "[Whitelist] Self SHA-256: " +
                    hash);
            }
            catch (Exception ex)
            {
                _hash.Name =
                    "Self SHA-256: Unavailable";

                try
                {
                    _hash.Update();
                    _menu.Update();
                }
                catch
                {
                }

                Modding.Logger.LogError(
                    "[Whitelist] Self hash failed:\n" +
                    ex);
            }
        }
    }
}